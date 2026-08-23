"""Alert grouping, throttling, deduplication, enrichment and dispatch.

Mission: one incident must not produce a thousand alerts.

Policies (all enforced by tests/test_alerts.py):

- Grouping: the group key comes from the alert itself. The first alert of a
  group emits immediately.
- Throttling: same-group alerts inside ``throttle_window_s`` of the last
  emission are suppressed. The window is evaluated lazily at the next
  submit (no timers, no threads). At expiry the next same-group alert
  emits with ``count``/``suppressed`` updated, so a burst collapses into
  one rolling summary while an ongoing incident stays visible.
- Escalation: an incoming severity ranked above the last emitted severity
  of its group emits immediately, even mid-window.
- Incident correlation: when the same template triggers two or more
  different detectors within 120 s, every involved payload carries
  ``incident``: ``"t<template_id>-<bucket>"`` where bucket is the cluster
  start epoch divided by 120 (integer floor), hence deterministic. The key
  is a documented nullable addition to schema ``logsift.alert/1``; it is
  None until a correlation exists, and it is filled in-place on retained
  payload objects once the second detector fires (consumers that kept the
  first payload see the same id).
- Identity: emitted ids are monotonic ``a-%06d`` across all groups.
- Evidence: ``evidence_lookup`` (when given) supplies ``examples`` and
  ``evidence_before`` at emission time; otherwise the alert's own lists
  pass through.
- Dispatch: hooks fire only for emitted payloads. Hook failures are
  captured into :class:`HookResult` and counted in ``stats()``
  (``hook_failures``); they never raise out of :meth:`AlertManager.submit`.
  Nothing is logged; the only stdout output is the dry-run preview.
- Injection safety: :class:`ExecHook` spawns the command with a list argv
  and ``shell=False`` and passes the payload verbatim on stdin, so hostile
  log content (backticks, quotes, semicolons, newlines, escapes) can never
  reach a shell. :class:`WebhookHook` posts the same JSON via urllib.
"""

from __future__ import annotations

import json
import math
import subprocess
import sys
import urllib.error
import urllib.request
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Protocol

from .events import SEVERITY_ORDER, Alert, iso_utc

_INCIDENT_WINDOW_S = 120.0
_INCIDENT_BUCKET_S = 120.0
_MAX_HITS_PER_TEMPLATE = 64
_PREVIEW_CHARS = 2000
_DETAIL_CHARS = 300
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITY_ORDER)}


def _short(text: str) -> str:
    return text if len(text) <= _DETAIL_CHARS else text[:_DETAIL_CHARS] + "..."


def _preview(header: str, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False)
    if len(body) > _PREVIEW_CHARS:
        body = body[:_PREVIEW_CHARS] + "...[truncated]"
    sys.stdout.write("[dry-run] " + header + "\n" + body + "\n")


class AlertSink(Protocol):
    def emit(self, payload: dict) -> None:
        ...


class JsonlSink:
    """Writes one JSON object per line and flushes; never coloured."""

    __slots__ = ("_stream",)

    def __init__(self, stream) -> None:
        self._stream = stream

    def emit(self, payload: dict) -> None:
        self._stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self._stream.flush()


@dataclass(frozen=True)
class HookResult:
    ok: bool
    detail: str


class ExecHook:
    """Delivers the payload on stdin to argv; never a shell, never a str cmd."""

    __slots__ = ("_argv", "_timeout_s", "_dry_run")

    def __init__(self, argv: list[str], timeout_s: float = 10.0, dry_run: bool = False) -> None:
        self._argv = list(argv)
        self._timeout_s = float(timeout_s)
        self._dry_run = bool(dry_run)

    def deliver(self, payload: dict) -> HookResult:
        if self._dry_run:
            _preview(f"exec argv={self._argv!r}", payload)
            return HookResult(ok=True, detail="dry-run")
        if not self._argv:
            return HookResult(ok=False, detail="exec: empty argv")
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        try:
            proc = subprocess.run(
                list(self._argv),
                shell=False,
                input=data,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self._timeout_s,
            )
        except subprocess.TimeoutExpired:
            return HookResult(ok=False, detail=f"exec: timeout after {self._timeout_s:g}s")
        except OSError as exc:
            return HookResult(ok=False, detail=_short(f"exec: {type(exc).__name__}: {exc}"))
        if proc.returncode == 0:
            return HookResult(ok=True, detail="exit 0")
        tail = proc.stderr.decode("utf-8", "replace").strip()
        detail = f"exit {proc.returncode}" + (f": {_short(tail)}" if tail else "")
        return HookResult(ok=False, detail=detail)


class WebhookHook:
    """POSTs the payload as JSON; dry-run prints a preview without network."""

    __slots__ = ("_url", "_headers", "_timeout_s", "_dry_run")

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout_s: float = 10.0,
        dry_run: bool = False,
    ) -> None:
        self._url = url
        self._headers = dict(headers or {})
        self._timeout_s = float(timeout_s)
        self._dry_run = bool(dry_run)

    def deliver(self, payload: dict) -> HookResult:
        if self._dry_run:
            _preview(f"webhook POST {self._url}", payload)
            return HookResult(ok=True, detail="dry-run")
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json", **self._headers}
        request = urllib.request.Request(self._url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_s) as response:
                status = getattr(response, "status", None) or response.getcode()
                return HookResult(ok=int(status) // 100 == 2, detail=f"http {status}")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return HookResult(ok=False, detail=_short(f"{type(exc).__name__}: {exc}"))


@dataclass(slots=True)
class _GroupState:
    total: int = 0
    suppressed_pending: int = 0
    first_ts: float = 0.0
    last_emit_ts: float = 0.0
    last_activity_ts: float = 0.0
    severity_rank: int = -1


@dataclass(slots=True)
class _TplHit:
    ts: float
    detector: str
    payload: dict | None


@dataclass(slots=True)
class _ActiveIncident:
    incident_id: str
    last_seen_ts: float


class AlertManager:
    """Groups, throttles, deduplicates, enriches and dispatches alerts.

    See the module docstring for the full policy list. ``submit`` returns the
    emitted payload dict, or None when the alert was suppressed. ``stats``
    reports ``emitted``, ``suppressed``, ``groups_active`` and
    ``hook_failures``.
    """

    __slots__ = (
        "_clock",
        "_sink",
        "_hooks",
        "_window",
        "_evidence_lookup",
        "_groups",
        "_tpl_hits",
        "_incidents",
        "_seq",
        "_emitted",
        "_suppressed",
        "_hook_failures",
        "_last_prune_ts",
    )

    def __init__(
        self,
        clock,
        sink: AlertSink | None = None,
        hooks: Sequence[ExecHook | WebhookHook] = (),
        throttle_window_s: float = 300.0,
        evidence_lookup: Callable[[Alert], tuple[list[str], list[str]]] | None = None,
    ) -> None:
        self._clock = clock
        self._sink = sink
        self._hooks = list(hooks)
        self._window = float(throttle_window_s)
        self._evidence_lookup = evidence_lookup
        self._groups: dict[str, _GroupState] = {}
        self._tpl_hits: dict[int, list[_TplHit]] = {}
        self._incidents: dict[int, _ActiveIncident] = {}
        self._seq = 0
        self._emitted = 0
        self._suppressed = 0
        self._hook_failures = 0
        self._last_prune_ts = -1.0

    def submit(self, alert: Alert) -> dict | None:
        # Grouping and throttling run on EVENT time so replay behaves exactly
        # like live ingestion and payloads stay deterministic; the injected
        # clock is only a fallback for alerts without any time.
        ts = float(
            alert.event_time
            if alert.event_time is not None and alert.event_time > 0
            else alert.window_end
        )
        if not math.isfinite(ts) or ts <= 0.0:
            ts = float(self._clock.now())
        self._prune(ts)
        group = self._groups.get(alert.group_key)
        if group is None:
            group = _GroupState(first_ts=ts, last_emit_ts=ts, last_activity_ts=ts)
            self._groups[alert.group_key] = group
        rank = _SEVERITY_RANK[alert.severity.value]
        escalated = group.severity_rank >= 0 and rank > group.severity_rank
        expired = (ts - group.last_emit_ts) >= self._window
        first = group.total == 0
        group.total += 1
        group.last_activity_ts = ts
        if not first and not escalated and not expired:
            group.suppressed_pending += 1
            self._suppressed += 1
            return None
        self._seq += 1
        payload = alert.to_json_dict()
        payload["id"] = f"a-{self._seq:06d}"
        payload["count"] = group.total
        payload["suppressed"] = group.suppressed_pending
        payload["first_seen"] = iso_utc(group.first_ts)
        if self._evidence_lookup is not None:
            examples, evidence = self._evidence_lookup(alert)
            payload["examples"] = list(examples)
            payload["evidence_before"] = list(evidence)
        payload["incident"] = self._correlate_incident(alert, ts, payload)
        group.last_emit_ts = ts
        group.severity_rank = rank
        group.suppressed_pending = 0
        self._emitted += 1
        self._dispatch(payload)
        return payload

    def stats(self) -> dict:
        return {
            "emitted": self._emitted,
            "suppressed": self._suppressed,
            "groups_active": len(self._groups),
            "hook_failures": self._hook_failures,
        }

    def _correlate_incident(self, alert: Alert, ts: float, payload: dict) -> str | None:
        tid = alert.template_id
        if tid is None:
            return None
        hits = self._tpl_hits.setdefault(tid, [])
        cutoff = ts - _INCIDENT_WINDOW_S
        while hits and hits[0].ts < cutoff:
            hits.pop(0)
        detectors = {h.detector for h in hits}
        detectors.add(alert.detector)
        if len(detectors) < 2:
            hits.append(_TplHit(ts=ts, detector=alert.detector, payload=payload))
            return None
        start_ts = hits[0].ts if hits else ts
        active = self._incidents.get(tid)
        if active is not None and (ts - active.last_seen_ts) < _INCIDENT_WINDOW_S:
            incident_id = active.incident_id
        else:
            incident_id = f"t{tid}-{int(start_ts // _INCIDENT_BUCKET_S)}"
            active = _ActiveIncident(incident_id=incident_id, last_seen_ts=ts)
            self._incidents[tid] = active
        active.last_seen_ts = ts
        for hit in hits:
            if hit.payload is not None:
                hit.payload["incident"] = incident_id
        hits.append(_TplHit(ts=ts, detector=alert.detector, payload=payload))
        excess = len(hits) - _MAX_HITS_PER_TEMPLATE
        if excess > 0:
            del hits[:excess]
        return incident_id

    def _dispatch(self, payload: dict) -> None:
        if self._sink is not None:
            self._sink.emit(payload)
        for hook in self._hooks:
            try:
                result = hook.deliver(payload)
            except Exception:
                self._hook_failures += 1
                continue
            if not result.ok:
                self._hook_failures += 1

    def _prune(self, ts: float) -> None:
        if self._last_prune_ts >= 0.0 and ts - self._last_prune_ts < min(self._window, 60.0):
            return
        self._last_prune_ts = ts
        keep = max(2.0 * self._window, 60.0)
        for key in [k for k, g in self._groups.items() if ts - g.last_activity_ts > keep]:
            del self._groups[key]
        for tid in [
            t
            for t, inc in self._incidents.items()
            if ts - inc.last_seen_ts >= _INCIDENT_WINDOW_S
        ]:
            del self._incidents[tid]
        for tid in [t for t, hits in self._tpl_hits.items() if not hits]:
            del self._tpl_hits[tid]

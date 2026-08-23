"""Per-template seasonal baselines with warm-up, persistence and exclusions.

Seasonality model: time is divided into 168 hour-of-week slots (slot =
``weekday() * 24 + hour`` in UTC, Monday = 0). A 03:00 trough is normal by
construction because each slot is compared only against its own history.

Keying policy: volume keys are opaque strings supplied by callers, by
convention ``"volume:<template text>"`` or ``"volume:__all__"``. Keys MUST be
derived from template text, never from template id - ids are reissued after
templater eviction while text identity survives.

Resource bounds (all enforced):
- per-key sample rings are capped at ``max_samples_per_slot`` per hour-of-week
  slot; numeric rings at ``2 * max_samples_per_slot``;
- total keys capped at ``max_keys``; when one more key is needed the victim is
  the entry least-recently OBSERVED (recency = last observation epoch), ties
  broken by smallest accumulated count, then by key string. Eviction drops the
  key's entire history permanently;
- error windows and exclusion windows have fixed caps (512 / 100), oldest
  dropped first;
- before every ``save()``, if the serialized state exceeds
  ``max_state_bytes``, samples are trimmed OLDEST-FIRST in a round-robin over
  keys in ascending key order (one sample per key per pass, then oldest error
  windows) until under the cap. The saved file therefore never exceeds the
  ceiling unless irreducible overhead alone exceeds it.

Exclusion semantics: windows are half-open ``[start, end)``. Observations
falling inside a marked window are never recorded, and marking (or loading a
state that contains exclusions) also purges already-stored samples inside
those windows, so an in-memory store and a save/load round trip converge to
identical state.

Warm-up: complete when the observed epoch span reaches ``warmup_seconds`` OR
at least 24 distinct hour-of-week slots have been seen. No system clock is
ever read; all recency and progress derive from the injected clock and the
epochs passed to observe methods.
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from logsift.statsutil import mad as _mad
from logsift.statsutil import median as _median

SCHEMA_BASELINE = "logsift.baseline/1"
_MAX_EXCLUSION_WINDOWS = 100
_MAX_ERROR_WINDOWS = 512
_SLOTS_PER_WEEK = 168
_WARMUP_SLOTS = 24


class BaselineError(Exception):
    """Baseline state file is unreadable or malformed; message names file and fix."""


@dataclass(frozen=True)
class VolumeBaseline:
    """Seasonal baseline for one template key and one hour-of-week slot."""

    median: float
    mad: float
    n: int


@dataclass(frozen=True)
class WarmupState:
    """Warm-up progress; ``eta_s`` is None once complete."""

    fraction: float
    eta_s: float | None
    complete: bool


class Clock(Protocol):
    def now(self) -> float: ...


class _Entry:
    __slots__ = ("kind", "slots", "ring", "weight", "last_observed")

    def __init__(self, kind: str, last_observed: float) -> None:
        self.kind = kind
        self.slots: dict[int, list[list[float]]] = {}
        self.ring: list[list[float]] = []
        self.weight = 0
        self.last_observed = last_observed


class BaselineStore:
    """Bounded, persistable seasonal baselines keyed on opaque strings."""

    __slots__ = (
        "_clock",
        "_path",
        "_max_samples_per_slot",
        "_max_keys",
        "_max_state_bytes",
        "_warmup_seconds",
        "_entries",
        "_error_windows",
        "_exclusions",
        "_first_epoch",
        "_last_epoch",
        "_slots_seen",
    )

    def __init__(
        self,
        clock: Clock,
        path: Path | str | None = None,
        max_samples_per_slot: int = 64,
        max_keys: int = 20000,
        max_state_bytes: int = 8 * 1024 * 1024,
        warmup_seconds: float = 3600.0,
    ) -> None:
        if max_samples_per_slot < 1 or max_keys < 1 or max_state_bytes < 1:
            raise ValueError("caps must be >= 1")
        self._clock = clock
        self._path = Path(path) if path is not None else None
        self._max_samples_per_slot = int(max_samples_per_slot)
        self._max_keys = int(max_keys)
        self._max_state_bytes = int(max_state_bytes)
        self._warmup_seconds = float(warmup_seconds)
        self._entries: dict[str, _Entry] = {}
        self._error_windows: list[list[float]] = []
        self._exclusions: list[list[float]] = []
        self._first_epoch: float | None = None
        self._last_epoch: float | None = None
        self._slots_seen: set[int] = set()

    # ---------------------------------------------------------------- slots

    @staticmethod
    def _slot(epoch: float) -> int | None:
        """Hour-of-week index 0..167, or None for out-of-range epochs."""
        try:
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        return dt.weekday() * 24 + dt.hour

    def _excluded(self, t: float) -> bool:
        return any(s <= t < e for s, e in self._exclusions)

    @staticmethod
    def _in_any(t: float, windows: list[list[float]]) -> bool:
        return any(s <= t < e for s, e in windows)

    def _touch(self, epoch: float) -> None:
        if self._first_epoch is None or epoch < self._first_epoch:
            self._first_epoch = epoch
        if self._last_epoch is None or epoch > self._last_epoch:
            self._last_epoch = epoch
        slot = self._slot(epoch)
        if slot is not None:
            self._slots_seen.add(slot)

    # ------------------------------------------------------------ observing

    def _entry(self, key: str, kind: str, now: float) -> _Entry:
        entry = self._entries.get(key)
        if entry is None:
            entry = _Entry(kind, now)
            self._entries[key] = entry
        return entry

    def _evict_over_capacity(self) -> None:
        while len(self._entries) > self._max_keys:
            victim = min(
                self._entries,
                key=lambda k: (
                    self._entries[k].last_observed,
                    self._entries[k].weight,
                    k,
                ),
            )
            del self._entries[victim]

    def observe_volume(self, key: str, bucket_epoch: float, count: int) -> None:
        """Record one hourly count for ``key`` into its hour-of-week slot.

        Observations inside an excluded window are silently dropped, as are
        non-finite epochs.
        """
        if not math.isfinite(bucket_epoch):
            return
        if self._excluded(bucket_epoch):
            return
        c = int(count)
        slot = self._slot(bucket_epoch)
        if slot is None:
            return
        entry = self._entry(key, "volume", bucket_epoch)
        ring = entry.slots.setdefault(slot, [])
        ring.append([bucket_epoch, c])
        while len(ring) > self._max_samples_per_slot:
            del ring[0]
        entry.weight += c
        entry.last_observed = max(entry.last_observed, bucket_epoch)
        self._touch(bucket_epoch)
        self._evict_over_capacity()

    def volume_baseline(self, key: str, bucket_epoch: float) -> VolumeBaseline | None:
        """Baseline for the slot containing ``bucket_epoch``; None when unlearned."""
        if not math.isfinite(bucket_epoch):
            return None
        entry = self._entries.get(key)
        if entry is None or entry.kind != "volume":
            return None
        slot = self._slot(bucket_epoch)
        samples = entry.slots.get(slot) if slot is not None else None
        if not samples:
            return None
        counts = [c for _, c in samples]
        med = _median(counts)
        spread = _mad(counts)
        if med is None or spread is None:
            return None
        return VolumeBaseline(median=med, mad=spread, n=len(counts))

    def observe_numeric(self, key: str, value: float) -> None:
        """Record one numeric sample (latency etc.) into a capped ring.

        The ring holds at most ``2 * max_samples_per_slot`` values, oldest
        first. Non-finite values are ignored; timestamps come from the clock.
        """
        v = float(value)
        if not math.isfinite(v):
            return
        now = float(self._clock.now())
        if self._excluded(now):
            return
        entry = self._entry(key, "numeric", now)
        entry.ring.append([now, v])
        while len(entry.ring) > 2 * self._max_samples_per_slot:
            del entry.ring[0]
        entry.weight += 1
        entry.last_observed = max(entry.last_observed, now)
        self._touch(now)
        self._evict_over_capacity()

    def numeric_sample(self, key: str) -> tuple[float, ...]:
        """Stored numeric samples for ``key``, oldest first; () when unknown."""
        entry = self._entries.get(key)
        if entry is None or entry.kind != "numeric":
            return ()
        return tuple(v for _, v in entry.ring)

    def observe_error_window(self, window_start_epoch: float, total: int, errors: int) -> None:
        """Append one rolling error-rate window; ring capped, oldest dropped."""
        if not math.isfinite(window_start_epoch):
            return
        if self._excluded(window_start_epoch):
            return
        start = float(window_start_epoch)
        idx = 0
        while idx < len(self._error_windows) and self._error_windows[idx][0] <= start:
            idx += 1
        self._error_windows.insert(idx, [start, int(total), int(errors)])
        while len(self._error_windows) > _MAX_ERROR_WINDOWS:
            del self._error_windows[0]
        self._touch(start)

    def error_windows(self) -> tuple[tuple[float, int, int], ...]:
        """Rolling windows chronologically; ((start, total, errors), ...)."""
        return tuple((s, t, e) for s, t, e in self._error_windows)

    # ----------------------------------------------------------- exclusions

    def mark_abnormal(self, start_epoch: float, end_epoch: float) -> None:
        """Exclude the half-open period ``[start, end)`` from learning.

        Future observations inside the window are dropped, and samples already
        stored inside it are removed immediately so that runtime state matches
        post-reload state exactly. Degenerate windows (end <= start,
        non-finite bounds) are ignored. At most 100 windows are kept; when the
        cap is exceeded the oldest window (smallest start) is dropped.
        """
        s, e = float(start_epoch), float(end_epoch)
        if not (math.isfinite(s) and math.isfinite(e)) or e <= s:
            return
        windows = [*self._exclusions, [s, e]]
        windows.sort()
        merged: list[list[float]] = [windows[0]]
        for ws, we in windows[1:]:
            if ws <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], we)
            else:
                merged.append([ws, we])
        self._exclusions = merged
        while len(self._exclusions) > _MAX_EXCLUSION_WINDOWS:
            del self._exclusions[0]
        self._apply_exclusions_to_samples()

    def exclusions(self) -> tuple[tuple[float, float], ...]:
        """Merged exclusion windows sorted by start."""
        return tuple((s, e) for s, e in self._exclusions)

    def _apply_exclusions_to_samples(self) -> None:
        if not self._exclusions:
            return
        for entry in self._entries.values():
            for slot in list(entry.slots):
                kept = [
                    p for p in entry.slots[slot] if not self._in_any(p[0], self._exclusions)
                ]
                if kept:
                    entry.slots[slot] = kept
                else:
                    del entry.slots[slot]
            kept_ring = [
                p for p in entry.ring if not self._in_any(p[0], self._exclusions)
            ]
            entry.ring = kept_ring
        self._error_windows = [
            w for w in self._error_windows if not self._in_any(w[0], self._exclusions)
        ]

    # -------------------------------------------------------------- warm-up

    def warmup(self) -> WarmupState:
        """Progress toward readiness.

        Fraction is the larger of observed-span/warmup_seconds and
        distinct-hour-slots/24, clamped to [0, 1]; complete when fraction
        reaches 1. ``eta_s`` estimates remaining seconds of observation span
        and is None once complete. A non-positive warmup_seconds disables
        warm-up entirely.
        """
        if self._warmup_seconds <= 0.0:
            return WarmupState(1.0, None, True)
        span = 0.0
        if self._first_epoch is not None and self._last_epoch is not None:
            span = max(0.0, self._last_epoch - self._first_epoch)
        frac_span = span / self._warmup_seconds
        frac_slots = min(len(self._slots_seen) / _WARMUP_SLOTS, 1.0)
        fraction = min(1.0, max(frac_span, frac_slots))
        complete = fraction >= 1.0
        eta = None if complete else max(0.0, self._warmup_seconds - span)
        return WarmupState(fraction, eta, complete)

    # ---------------------------------------------------------- persistence

    def _to_doc(self) -> dict:
        entries: dict[str, dict] = {}
        for key in sorted(self._entries):
            e = self._entries[key]
            body: dict = {
                "kind": e.kind,
                "weight": e.weight,
                "last_observed": e.last_observed,
            }
            if e.kind == "volume":
                body["slots"] = [[slot, e.slots[slot]] for slot in sorted(e.slots)]
            else:
                body["ring"] = [list(p) for p in e.ring]
            entries[key] = body
        return {
            "schema": SCHEMA_BASELINE,
            "warmup_seconds": self._warmup_seconds,
            "span": {
                "first_epoch": self._first_epoch,
                "last_epoch": self._last_epoch,
            },
            "slots_seen": sorted(self._slots_seen),
            "entries": entries,
            "error_windows": [list(w) for w in self._error_windows],
            "exclusions": [list(x) for x in self._exclusions],
        }

    def _serialize(self) -> bytes:
        return json.dumps(
            self._to_doc(), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")

    def state_bytes_estimate(self) -> int:
        """Exact byte length of the canonical serialized state."""
        return len(self._serialize())

    def _trim_to_disk_ceiling(self) -> None:
        """Drop oldest samples until the serialized state fits the ceiling.

        Drop order: one oldest sample per key per pass, cycling keys in
        ascending key order; then oldest error windows; exclusion windows are
        never trimmed here (they have their own 100 cap). Stops early when no
        trimmable sample remains - irreducible overhead may leave the state
        above the ceiling, and saving proceeds anyway.
        """
        while True:
            if self.state_bytes_estimate() <= self._max_state_bytes:
                return
            progressed = False
            for key in sorted(self._entries):
                if self.state_bytes_estimate() <= self._max_state_bytes:
                    break
                entry = self._entries[key]
                oldest_slot = min(
                    (s for s in entry.slots if entry.slots[s]),
                    key=lambda s: entry.slots[s][0][0],
                    default=None,
                )
                slot_ts = entry.slots[oldest_slot][0][0] if oldest_slot is not None else math.inf
                ring_ts = entry.ring[0][0] if entry.ring else math.inf
                if slot_ts is math.inf and ring_ts is math.inf:
                    continue
                progressed = True
                if slot_ts <= ring_ts:
                    del entry.slots[oldest_slot][0]
                    if not entry.slots[oldest_slot]:
                        del entry.slots[oldest_slot]
                else:
                    del entry.ring[0]
            if not progressed:
                if self._error_windows:
                    del self._error_windows[0]
                    continue
                return

    def save(self) -> None:
        """Atomically write state to ``path`` (tmp + os.replace).

        Persists nothing when no path was configured. Trims to
        ``max_state_bytes`` first; keys appear in sorted order in the JSON.
        """
        if self._path is None:
            return
        self._trim_to_disk_ceiling()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_name(self._path.name + ".tmp")
        payload = self._serialize()
        tmp.write_bytes(payload)
        os.replace(tmp, self._path)

    @staticmethod
    def _quarantine(path: Path) -> Path:
        corrupt = path.with_name(path.name + ".corrupt")
        try:
            os.replace(path, corrupt)
        except OSError:
            pass
        return corrupt

    def load(self) -> bool:
        """Load persisted state; True when a valid file was read.

        Returns False when no state file exists (fresh start). When a file
        exists but cannot be parsed or fails schema validation, raises
        :class:`BaselineError` after renaming the offender to
        ``<path>.corrupt`` - the next ``load()`` therefore finds no file,
        returns False, and the store starts fresh. In-memory state is only
        replaced after a file parses completely.
        """
        if self._path is None:
            return False
        try:
            raw = self._path.read_bytes()
        except FileNotFoundError:
            return False
        try:
            doc = json.loads(raw.decode("utf-8"))
            parsed = _parse_doc(doc)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
            corrupt = self._quarantine(self._path)
            raise BaselineError(
                f"baseline state at {self._path} is unreadable ({exc}); "
                f"a copy was moved to {corrupt}; delete it or restore a good "
                f"state file to recover"
            ) from exc
        (entries, error_windows, exclusions, first, last, slots_seen) = parsed
        self._entries = entries
        self._error_windows = error_windows
        self._exclusions = exclusions
        self._first_epoch = first
        self._last_epoch = last
        self._slots_seen = slots_seen
        if "warmup_seconds" in doc:
            self._warmup_seconds = float(doc["warmup_seconds"])
        self._apply_exclusions_to_samples()
        self._evict_over_capacity()
        return True


_ParsedDoc = tuple[
    dict[str, "_Entry"],
    list[list[float]],
    list[list[float]],
    float | None,
    float | None,
    set[int],
]


def _parse_doc(doc: object) -> _ParsedDoc:
    """Validate and convert a state document; raises ValueError/TypeError."""
    if not isinstance(doc, dict):
        raise ValueError("state is not a JSON object")
    if doc.get("schema") != SCHEMA_BASELINE:
        raise ValueError(f"unexpected schema {doc.get('schema')!r}")
    entries_doc = doc.get("entries")
    if not isinstance(entries_doc, dict):
        raise ValueError("entries must be an object")
    entries: dict[str, _Entry] = {}
    for key, body in entries_doc.items():
        if not isinstance(body, dict):
            raise TypeError(f"entry {key!r} must be an object")
        kind = body.get("kind")
        if kind not in ("volume", "numeric"):
            raise ValueError(f"entry {key!r} has invalid kind")
        entry = _Entry(str(kind), float(body.get("last_observed", 0.0)))
        entry.weight = int(body.get("weight", 0))
        if kind == "volume":
            slots = body.get("slots", [])
            if not isinstance(slots, list):
                raise ValueError(f"entry {key!r} slots must be a list")
            for pair in slots:
                slot, samples = pair
                if isinstance(slot, bool) or not 0 <= int(slot) < _SLOTS_PER_WEEK:
                    raise ValueError(f"entry {key!r} has out-of-range slot {slot!r}")
                parsed = [[float(ep), int(c)] for ep, c in samples]
                if any(not math.isfinite(ep) for ep, _ in parsed):
                    raise ValueError(f"entry {key!r} has non-finite sample epoch")
                entry.slots[int(slot)] = parsed
        else:
            ring = body.get("ring", [])
            if not isinstance(ring, list):
                raise ValueError(f"entry {key!r} ring must be a list")
            parsed = [[float(ep), float(v)] for ep, v in ring]
            if any(not math.isfinite(ep) or not math.isfinite(v) for ep, v in parsed):
                raise ValueError(f"entry {key!r} has non-finite sample")
            entry.ring = parsed
        entries[key] = entry
    error_windows = [[float(s), int(t), int(e)] for s, t, e in doc.get("error_windows", [])]
    exclusions = [[float(s), float(e)] for s, e in doc.get("exclusions", [])]
    span = doc.get("span") or {}
    if not isinstance(span, dict):
        raise ValueError("span must be an object")
    first = span.get("first_epoch")
    last = span.get("last_epoch")
    if isinstance(first, bool) or not isinstance(first, (int, float)):
        first = None
    else:
        first = float(first)
    if isinstance(last, bool) or not isinstance(last, (int, float)):
        last = None
    else:
        last = float(last)
    slots_seen = set()
    for raw in doc.get("slots_seen", []):
        idx = int(raw)
        if not 0 <= idx < _SLOTS_PER_WEEK:
            raise ValueError(f"slot index {raw!r} out of range")
        slots_seen.add(idx)
    return (entries, error_windows, exclusions, first, last, slots_seen)

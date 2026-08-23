"""Hourly per-template volume anomalies against seasonal hour-of-week baselines."""

from __future__ import annotations

import math
from collections import deque
from datetime import datetime, timezone

from ..events import Alert, Event, Severity
from ..statsutil import robust_z
from .base import BaseDetector, DetectorContext

_HOUR = 3600.0
_STALE_S = 7200.0
_MIN_BASELINE_SLOTS = 3
_GLOBAL_TEXT = "<all templates>"
_GLOBAL_KEY = "volume:__all__"


def _hhmm(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%H:%M")


def _slot_label(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%a %H:%M")


class VolumeDetector(BaseDetector):
    """Alerts when a closed hourly bucket breaks its hour-of-week baseline.

    Buckets are UTC hour floors of event time. When the newest event carries a
    newer bucket, the open bucket is closed: its per-template counts (plus the
    global ``__all__`` total) are fed into the baseline store, then each closed
    count is scored with a robust z against its own slot history. A bucket is
    never scored twice; late events for closed buckets are dropped. Quiet
    streams are handled by ``tick``, which closes buckets two hours stale, and
    ``flush``, which closes whatever remains.
    """

    id = "volume"

    def __init__(self, ctx: DetectorContext) -> None:
        super().__init__(ctx)
        self._cur_bucket: int | None = None
        self._last_closed: int | None = None
        self._counts: dict[str, int] = {}
        self._total: int = 0
        self._buf: list[Alert] = []
        self._hod: dict[str, dict[int, deque[int]]] = {}

    def _note_recent(self, key: str, count: int, total: int) -> None:
        self._note_hod(key, self._closed_start, count)

    def observe(self, ev: Event, now: float) -> None:
        ts = float(ev.ts)
        if not math.isfinite(ts):
            return
        bucket = math.floor(ts / _HOUR)
        if self._last_closed is not None and bucket <= self._last_closed:
            return
        if self._cur_bucket is not None and bucket > self._cur_bucket:
            self._buf.extend(self._close_current())
        if self._cur_bucket is None:
            self._cur_bucket = bucket
        text = ev.template_text if ev.template_text else "<no template>"
        self._counts[text] = self._counts.get(text, 0) + 1
        self._total += 1

    def tick(self, now: float) -> list[Alert]:
        if (
            self._cur_bucket is not None
            and (self._cur_bucket + 1) * _HOUR <= now - _STALE_S
        ):
            self._buf.extend(self._close_current())
        out, self._buf = self._buf, []
        return out

    def flush(self, now: float) -> list[Alert]:
        if self._cur_bucket is not None:
            self._buf.extend(self._close_current())
        return self.tick(now)

    def _close_current(self) -> list[Alert]:
        bucket = self._cur_bucket
        if bucket is None:
            return []
        self._cur_bucket = None
        self._last_closed = bucket
        counts, self._counts = self._counts, {}
        total, self._total = self._total, 0
        start = bucket * _HOUR
        self._closed_start = start
        out: list[Alert] = []
        # Score against strictly PRIOR history first, then record this
        # bucket - otherwise the spike becomes its own baseline.
        for text, count in counts.items():
            key = "volume:" + text
            alert = self._evaluate(text, key, count, start, total)
            self.ctx.baselines.observe_volume(key, start, count)
            self._note_recent(key, count, total)
            if alert is not None:
                out.append(alert)
        alert = self._evaluate(_GLOBAL_TEXT, _GLOBAL_KEY, total, start, total)
        self.ctx.baselines.observe_volume(_GLOBAL_KEY, start, total)
        self._note_recent(_GLOBAL_KEY, total, total)
        if alert is not None:
            out.append(alert)
        return out

    def _evaluate(self, text: str, key: str, count: int, start: float, total_now: int) -> Alert | None:
        cfg = self.ctx.config
        if key == _GLOBAL_KEY:
            baseline = self.ctx.baselines.volume_baseline(key, start)
            if baseline is None or baseline.n < _MIN_BASELINE_SLOTS:
                return None
            med = baseline.median
            mad = max(abs(baseline.mad), 0.05 * abs(baseline.median))
            return self._score(text, key, count, start, cfg, med, mad, f"median {med:g}/hr for slot {_slot_label(start)} over {baseline.n} weekly slots", f"{count / med:.1f}x median" if med > 0 else f"count {count}")
        # Ladder of baselines, most seasonal first; each states itself.
        baseline = self.ctx.baselines.volume_baseline(key, start)
        if baseline is not None and baseline.n >= _MIN_BASELINE_SLOTS:
            med = baseline.median
            mad = max(abs(baseline.mad), 0.05 * abs(baseline.median))
            desc = (
                f"median {med:g}/hr for slot {_slot_label(start)} "
                f"over {baseline.n} weekly slots"
            )
            return self._score(text, key, count, start, cfg, med, mad, desc, f"{count / med:.1f}x median")
        hod = self._hour_of_day_counts(key, start)
        if hod:
            ordered = sorted(hod)
            med = float(ordered[len(ordered) // 2])
            spread = max(med - ordered[(len(ordered) - 1) // 2], 0.5 * med)
            desc = (
                f"median {med:g}/hr at this hour of day over {len(ordered)} days "
                f"(weekly slot history still filling)"
            )
            return self._score(text, key, count, start, cfg, med, spread, desc, f"{count / med:.1f}x same-hour median")
        # First observation of this hour-of-day: record silently.
        return None

    def _hour_of_day_counts(self, key: str, start: float) -> list[int]:
        hod = int((start % 86400.0) // 3600.0)
        ring = self._hod.get(key)
        if not ring:
            return []
        return list(ring.get(hod, ()))

    def _note_hod(self, key: str, start: float, count: int) -> None:
        hod = int((start % 86400.0) // 3600.0)
        per_key = self._hod.setdefault(key, {})
        bucket = per_key.setdefault(hod, deque(maxlen=64))
        bucket.append(count)

    def _score(self, text, key, count, start, cfg, med, spread, desc, ratio_desc) -> Alert | None:
        if count < cfg.volume_min_count:
            return None
        # Spread floor: count noise is never smaller than Poisson sqrt(med),
        # and tiny historical counts need an absolute floor too.
        spread = max(spread, med ** 0.5 if med > 0 else 0.0, 2.0)
        z = robust_z(float(count), med, spread)
        if z < cfg.volume_elevated_z:
            return None
        severity = Severity.from_score_bands(
            z, cfg.volume_elevated_z, cfg.volume_anomalous_z, cfg.volume_critical_z
        )
        deviation = f"{ratio_desc} (robust z={z:.1f})"
        return self._build_alert(text, count, start, med, desc, deviation, z, severity, cfg, key)

    def _build_alert(
        self,
        text: str,
        count: int,
        start: float,
        med: float,
        desc: str,
        deviation: str,
        z: float,
        severity: Severity,
        cfg,
        key: str = "",
    ) -> Alert:
        return Alert(
            detector=self.id,
            severity=severity,
            template_id=None,
            template_text=text,
            baseline_desc=desc,
            baseline_value=med,
            observed_desc=(
                f"{count} events in {_hhmm(start)}-{_hhmm(start + _HOUR)} bucket"
            ),
            observed_value=float(count),
            deviation_desc=deviation,
            z=z,
            threshold_desc=f"robust z >= {cfg.volume_elevated_z:g} (elevated band)",
            threshold_value=cfg.volume_elevated_z,
            window_start=start,
            window_end=start + _HOUR,
            group_key=key or ("volume:" + text),
            event_time=start + _HOUR,
        )

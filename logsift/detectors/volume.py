"""Hourly per-template volume anomalies against seasonal hour-of-week baselines."""

from __future__ import annotations

import math
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
        out: list[Alert] = []
        for text, count in counts.items():
            self.ctx.baselines.observe_volume("volume:" + text, start, count)
            alert = self._evaluate(text, "volume:" + text, count, start)
            if alert is not None:
                out.append(alert)
        self.ctx.baselines.observe_volume(_GLOBAL_KEY, start, total)
        alert = self._evaluate(_GLOBAL_TEXT, _GLOBAL_KEY, total, start)
        if alert is not None:
            out.append(alert)
        return out

    def _evaluate(self, text: str, key: str, count: int, start: float) -> Alert | None:
        cfg = self.ctx.config
        baseline = self.ctx.baselines.volume_baseline(key, start)
        if baseline is None or baseline.n < _MIN_BASELINE_SLOTS:
            return None
        if count < cfg.volume_min_count:
            return None
        z = robust_z(float(count), baseline.median, baseline.mad)
        if z < cfg.volume_elevated_z:
            return None
        severity = Severity.from_score_bands(
            z, cfg.volume_elevated_z, cfg.volume_anomalous_z, cfg.volume_critical_z
        )
        med = baseline.median
        if med > 0:
            deviation = f"{count / med:.1f}x median (robust z={z:.1f})"
        else:
            deviation = f"count {count} vs median 0 (robust z={z:.1f})"
        return Alert(
            detector=self.id,
            severity=severity,
            template_id=None,
            template_text=text,
            baseline_desc=(
                f"median {med:g}/hr for slot {_slot_label(start)} "
                f"over {baseline.n} slots"
            ),
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
            group_key=key,
            event_time=start + _HOUR,
        )

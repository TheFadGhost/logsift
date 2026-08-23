"""Stopped-template detector: templates that stopped appearing.

Scoring semantics: the score is the silence ratio ``gap / expected_interval``
where ``expected_interval`` is derived from the template's hourly volume
baseline (median events/hr -> seconds between events), falling back to the
template's overall observed mean rate while it was alive. Severity bands via
``Severity.from_score_bands``: elevated 10x, anomalous 25x, critical 50x.

Firing rules, evaluated on tick() but at most once per
``config.stopped_check_interval_s``: a tracked template with all-time count
>= ``stopped_min_history`` whose current gap exceeds
``gap_factor * expected_interval`` AND for which the baseline predicts at
least ``stopped_min_expected`` missed occurrences fires ONCE per silence
episode; the episode re-arms when the template recurs, so a later stop can
fire again.

Tracking state is a bounded LRU capped at ``track_cap`` (default 5000);
evicted templates lose their history and start tracking from scratch.
"""

from __future__ import annotations

import math
from collections import OrderedDict

from ..events import Alert, Event, Severity
from .base import BaseDetector


class _Track:
    __slots__ = ("count", "first_seen", "last_seen", "last_id", "fired")

    def __init__(self, ts: float) -> None:
        self.count = 0
        self.first_seen = ts
        self.last_seen = ts
        self.last_id: int | None = None
        self.fired = False


def _fmt_dur(seconds: float) -> str:
    if seconds >= 5400.0:
        return f"{seconds / 3600.0:.1f}h"
    if seconds >= 90.0:
        return f"{seconds / 60.0:.0f}m"
    return f"{seconds:.0f}s"


class StoppedTemplateDetector(BaseDetector):
    """Fires when a well-established template goes silent for too long."""

    id = "stopped_template"

    def __init__(self, ctx: object, track_cap: int = 5000) -> None:
        super().__init__(ctx)
        self._cap = max(1, int(track_cap))
        self._tracks: OrderedDict[str, _Track] = OrderedDict()
        self._next_check: float | None = None

    def observe(self, ev: Event, now: float) -> None:
        text = ev.template_text
        if not text:
            return
        tr = self._tracks.get(text)
        if tr is None:
            tr = _Track(now)
            self._tracks[text] = tr
            while len(self._tracks) > self._cap:
                self._tracks.popitem(last=False)
        else:
            self._tracks.move_to_end(text)
        tr.count += 1
        ts = ev.ts if ev.ts > 0 else now
        if ts > tr.last_seen:
            tr.last_seen = ts
        tr.first_seen = min(tr.first_seen, ts)
        tr.last_id = ev.template_id
        tr.fired = False

    def tick(self, now: float) -> list[Alert]:
        cfg = self.ctx.config
        if self._next_check is not None and now < self._next_check:
            return []
        self._next_check = now + cfg.stopped_check_interval_s
        alerts: list[Alert] = []
        for text, tr in list(self._tracks.items()):
            if tr.fired or tr.count < cfg.stopped_min_history:
                continue
            gap = now - tr.last_seen
            if gap <= 0.0:
                continue
            rate_hr, source = self._rate_hr(text, tr)
            if rate_hr is None or rate_hr <= 0.0 or not math.isfinite(rate_hr):
                continue
            interval_s = 3600.0 / rate_hr
            expected_count = rate_hr * gap / 3600.0
            if gap <= interval_s * cfg.stopped_gap_factor:
                continue
            if expected_count < cfg.stopped_min_expected:
                continue
            tr.fired = True
            ratio = gap / interval_s
            severity = Severity.from_score_bands(ratio, 10.0, 25.0, 50.0)
            alerts.append(
                Alert(
                    detector=self.id,
                    severity=severity,
                    template_id=tr.last_id,
                    template_text=text,
                    baseline_desc=(
                        f"expected >={int(cfg.stopped_min_expected)} occurrences in "
                        f"gap {_fmt_dur(gap)} based on {source} {rate_hr:g}/hr"
                    ),
                    baseline_value=expected_count,
                    observed_desc=f"0 occurrences for {_fmt_dur(gap)}",
                    observed_value=0.0,
                    deviation_desc=f"silent for {ratio:.1f}x expected interval",
                    z=None,
                    threshold_desc=(
                        f"gap > {cfg.stopped_gap_factor:g}x expected interval "
                        f"({_fmt_dur(interval_s)})"
                    ),
                    threshold_value=interval_s * cfg.stopped_gap_factor,
                    window_start=tr.last_seen,
                    window_end=now,
                    group_key=f"stopped_template:{text}",
                    examples=[],
                )
            )
        return alerts

    def _rate_hr(self, text: str, tr: _Track) -> tuple[float | None, str]:
        key = f"volume:{text}"
        base = self.ctx.baselines.volume_baseline(key, self.ctx.clock.now())
        if base is None or base.median <= 0.0:
            base = self.ctx.baselines.volume_baseline(key, tr.last_seen)
        if base is not None and base.median > 0.0:
            return float(base.median), "median"
        span_s = tr.last_seen - tr.first_seen
        if span_s <= 0.0:
            return None, ""
        return tr.count / (span_s / 3600.0), "observed mean"

"""Numeric field distribution-shift detection via Mann-Whitney U on sample windows."""

from __future__ import annotations

import math
from collections import OrderedDict, deque

from ..events import Alert, Event, Severity
from ..statsutil import mann_whitney_u, median
from .base import BaseDetector, DetectorContext

_MAX_SAMPLES = 2000
_PRIOR_MULTIPLE = 3
_REBOUND_WINDOW_S = 7200.0


class _Series:
    __slots__ = ("vals", "seen_since_eval", "last_alert", "last_direction")

    def __init__(self) -> None:
        self.vals: deque[tuple[float, float]] = deque(maxlen=_MAX_SAMPLES)
        self.seen_since_eval: int = 0
        self.last_alert: float = -math.inf
        self.last_direction: str = ""


class NumericShiftDetector(BaseDetector):
    """Alerts when a numeric field's recent samples shift against its prior.

    Comparisons are SAMPLE-count based so slow streams are still judged once
    enough evidence exists: the last ``numeric_min_samples`` values are tested
    against up to ``3x`` that many preceding values (own ring first, then the
    persistent mirror in the baseline store). Samples are mirrored into the
    store keyed by template text and field name so history survives restarts.
    A field cools down for one window's worth of event time after each alert;
    direction is reported with both medians. Bounded memory: at most 2000
    samples per field, at most ``numeric_max_fields_per_template`` fields per
    template (least-recently-seen evicted).
    """

    id = "numeric_shift"

    def __init__(self, ctx: DetectorContext) -> None:
        super().__init__(ctx)
        self._templates: dict[str, OrderedDict[str, _Series]] = {}
        self._buf: list[Alert] = []

    def observe(self, ev: Event, now: float) -> None:
        if not ev.numeric:
            return
        ts = float(ev.ts)
        if not math.isfinite(ts):
            return
        text = ev.template_text if ev.template_text else "<no template>"
        fields = self._templates.get(text)
        if fields is None:
            fields = self._templates[text] = OrderedDict()
        cfg = self.ctx.config
        for name, raw in ev.numeric.items():
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                continue
            value = float(raw)
            if not math.isfinite(value):
                continue
            series = fields.get(name)
            if series is None:
                series = _Series()
                fields[name] = series
            fields.move_to_end(name)
            while len(fields) > cfg.numeric_max_fields_per_template:
                fields.popitem(last=False)
            series.vals.append((ts, value))
            series.seen_since_eval += 1
            key = f"numeric:{text}:{name}"
            self.ctx.baselines.observe_numeric(key, value, epoch=ts)
            if series.seen_since_eval >= cfg.numeric_min_samples:
                series.seen_since_eval = 0
                alert = self._compare(text, name, key, series, ts, cfg)
                if alert is not None:
                    series.last_alert = ts
                    series.last_direction = alert.deviation_desc.split(":")[0]
                    self._buf.append(alert)

    def tick(self, now: float) -> list[Alert]:
        out, self._buf = self._buf, []
        return out

    def _compare(
        self,
        text: str,
        name: str,
        key: str,
        series: _Series,
        now_ts: float,
        cfg,
    ) -> Alert | None:
        k = cfg.numeric_min_samples
        vals = list(series.vals)
        if len(vals) < k:
            return None
        recent = [v for _ts, v in vals[-k:]]
        prior = [v for _ts, v in vals[-(k * (_PRIOR_MULTIPLE + 1)) : -k]]
        if len(prior) < k:
            prior = [float(v) for v in self.ctx.baselines.numeric_sample(key)]
            prior = prior[:-k] if len(prior) > k else prior
        if len(prior) < k:
            return None
        result = mann_whitney_u(recent, prior)
        if result is None:
            return None
        _, z = result
        if abs(z) < cfg.numeric_elevated_z:
            return None
        if now_ts - series.last_alert < cfg.numeric_window_s:
            return None
        med_r = median(recent)
        med_p = median(prior)
        if med_r is None or med_p is None:
            return None
        direction = "increase" if z > 0 else "decrease"
        # Rebound suppression: when a shift REVERTS within two hours of the
        # original alert, that is the incident closing, not a new anomaly.
        if (
            series.last_direction
            and direction != series.last_direction
            and now_ts - series.last_alert < _REBOUND_WINDOW_S
        ):
            return None
        if med_p != 0:
            pct = f"{(med_r - med_p) / abs(med_p) * 100.0:+.0f}%"
        else:
            pct = f"{med_r - med_p:+g} abs"
        severity = Severity.from_score_bands(
            abs(z),
            cfg.numeric_elevated_z,
            cfg.numeric_anomalous_z,
            cfg.numeric_critical_z,
        )
        window_start = vals[-k][0]
        return Alert(
            detector=self.id,
            severity=severity,
            template_id=None,
            template_text=text,
            baseline_desc=(
                f"median {name} {med_p:g} over prior {len(prior)} samples"
            ),
            baseline_value=med_p,
            observed_desc=(
                f"median {name} {med_r:g} over last {len(recent)} samples"
            ),
            observed_value=med_r,
            deviation_desc=(
                f"{direction}: median {name} {med_r:g} vs {med_p:g} "
                f"({pct}, MW-U z={z:.1f})"
            ),
            z=z,
            threshold_desc=(
                f"|MW-U z| >= {cfg.numeric_elevated_z:g} (elevated band)"
            ),
            threshold_value=cfg.numeric_elevated_z,
            window_start=window_start,
            window_end=now_ts,
            group_key=f"numeric_shift:{text}:{name}",
            event_time=now_ts,
        )

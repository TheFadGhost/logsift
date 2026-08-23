"""Numeric field distribution-shift detection via Mann-Whitney U on sliding windows."""

from __future__ import annotations

import math
from collections import OrderedDict, deque

from ..events import Alert, Event, Severity
from ..statsutil import mann_whitney_u, median
from .base import BaseDetector, DetectorContext

_MAX_SAMPLES = 2000


class _Series:
    __slots__ = ("vals", "last_eval", "last_alert")

    def __init__(self) -> None:
        self.vals: deque[tuple[float, float]] = deque(maxlen=_MAX_SAMPLES)
        self.last_eval: float = -math.inf
        self.last_alert: float = -math.inf


class NumericShiftDetector(BaseDetector):
    """Alerts when a numeric field's recent window shifts against its prior.

    Per (template text, field) a bounded ring of ``(ts, value)`` samples is
    kept (at most 2000 per field, at most ``numeric_max_fields_per_template``
    most-recently-seen fields per template). Once per ``numeric_window_s`` the
    last window is compared with the preceding ``numeric_baseline_s`` via
    ``mann_whitney_u``; when the own prior window is still thin, the seeded
    mirror in the baseline store backs it up. Samples are also mirrored into
    the store so history survives restarts. Alerts cool down for one window
    per field; direction is reported with the medians.
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
        w = float(cfg.numeric_window_s)
        span = float(cfg.numeric_baseline_s)
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
            key = f"numeric:{text}:{name}"
            self.ctx.baselines.observe_numeric(key, value)
            if now - series.last_eval >= w:
                series.last_eval = now
                alert = self._compare(text, name, key, series, now, w, span)
                if alert is not None:
                    series.last_alert = now
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
        now: float,
        w: float,
        span: float,
    ) -> Alert | None:
        cfg = self.ctx.config
        t1 = now - w
        t0 = t1 - span
        recent: list[float] = []
        prior: list[float] = []
        for ts, v in series.vals:
            if ts >= t1:
                recent.append(v)
            elif ts >= t0:
                prior.append(v)
        if len(recent) < cfg.numeric_min_samples:
            return None
        if len(prior) < cfg.numeric_min_samples:
            prior = [float(v) for v in self.ctx.baselines.numeric_sample(key)]
            if len(prior) < cfg.numeric_min_samples:
                return None
        result = mann_whitney_u(recent, prior)
        if result is None:
            return None
        _, z = result
        if abs(z) < cfg.numeric_elevated_z:
            return None
        if now - series.last_alert < w:
            return None
        med_r = median(recent)
        med_p = median(prior)
        if med_r is None or med_p is None:
            return None
        direction = "increase" if z > 0 else "decrease"
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
        return Alert(
            detector=self.id,
            severity=severity,
            template_id=None,
            template_text=text,
            baseline_desc=(
                f"median {name} {med_p:g} over prior {span:g}s "
                f"(n={len(prior)} samples)"
            ),
            baseline_value=med_p,
            observed_desc=(
                f"median {name} {med_r:g} over last {w:g}s "
                f"(n={len(recent)} samples)"
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
            window_start=now - w,
            window_end=now,
            group_key=f"numeric_shift:{text}:{name}",
            event_time=now,
        )

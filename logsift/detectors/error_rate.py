"""Streaming error-rate shift detection via the pooled two-proportion z-test."""

from __future__ import annotations

import math

from ..events import Alert, Event, Severity
from ..statsutil import two_proportion_ztest
from .base import BaseDetector, DetectorContext

_ERROR_LEVELS = frozenset({"error", "critical"})
_ALL_TEXT = "<all templates>"
_GROUP_KEY = "error_rate:__all__"


class ErrorRateDetector(BaseDetector):
    """Alerts when the recent error proportion jumps above its own history.

    Events are accumulated on an absolute grid of ``error_window_s`` buckets.
    Each closed window is stored in the baseline store, then scored against
    the aggregate of stored windows covering the preceding ``error_baseline_s``
    (the store's persisted ring is part of that aggregate, so history survives
    restarts). The current partial window is also scored on every tick so a
    surge surfaces within one window. At most one alert fires per window;
    negative shifts are ignored.
    """

    id = "error_rate"

    def __init__(self, ctx: DetectorContext) -> None:
        super().__init__(ctx)
        self._w = float(ctx.config.error_window_s)
        self._win: int | None = None
        self._total: int = 0
        self._errors: int = 0
        self._fired_win: int | None = None
        self._last_partial_eval: float = -math.inf
        self._buf: list[Alert] = []

    def observe(self, ev: Event, now: float) -> None:
        ts = float(ev.ts)
        if not math.isfinite(ts):
            return
        idx = math.floor(ts / self._w)
        if self._win is None:
            self._win = idx
        elif idx < self._win:
            return
        while self._win < idx:
            self._buf.extend(self._roll(self._win))
            self._win += 1
        self._total += 1
        lvl = ev.level
        if lvl is not None and lvl in _ERROR_LEVELS:
            self._errors += 1

    def tick(self, now: float) -> list[Alert]:
        if self._win is not None:
            cur = math.floor(now / self._w)
            while self._win < cur:
                self._buf.extend(self._roll(self._win))
                self._win += 1
            # Partial-window scoring is throttled: a full scan of baseline
            # windows per tick is wasted work while the window is young.
            if now - self._last_partial_eval >= 5.0:
                self._last_partial_eval = now
                start = self._win * self._w
                end = now if now > start else start
                base_errors, base_total, n_windows = self._baseline_before(start)
                alert = self._evaluate(
                    self._win,
                    start,
                    end,
                    self._total,
                    self._errors,
                    base_errors,
                    base_total,
                    n_windows,
                )
                if alert is not None:
                    self._buf.append(alert)
        out, self._buf = self._buf, []
        return out

    def _roll(self, idx: int) -> list[Alert]:
        start = idx * self._w
        total, self._total = self._total, 0
        errors, self._errors = self._errors, 0
        self.ctx.baselines.observe_error_window(start, total, errors)
        base_errors, base_total, n_windows = self._baseline_before(start)
        alert = self._evaluate(
            idx, start, start + self._w, total, errors, base_errors, base_total, n_windows
        )
        return [alert] if alert is not None else []

    def _baseline_before(self, start: float) -> tuple[int, int, int]:
        lo = start - float(self.ctx.config.error_baseline_s)
        base_total = 0
        base_errors = 0
        n_windows = 0
        for ws, wt, we in self.ctx.baselines.error_windows():
            if start > ws >= lo:
                base_total += wt
                base_errors += we
                n_windows += 1
        return base_errors, base_total, n_windows

    def _evaluate(
        self,
        win_idx: int,
        start: float,
        end: float,
        total: int,
        errors: int,
        base_errors: int,
        base_total: int,
        n_windows: int,
    ) -> Alert | None:
        cfg = self.ctx.config
        if self._fired_win == win_idx:
            return None
        if total < cfg.error_min_events or base_total < cfg.error_min_events:
            return None
        if base_errors < 3:
            # With fewer than 3 baseline errors the proportion test is
            # degenerate (zero-variance baseline); staying silent here is a
            # documented limitation, not a tuned threshold.
            return None
        z = two_proportion_ztest(errors, total, base_errors, base_total)
        if z is None or z < cfg.error_elevated_z:
            return None
        self._fired_win = win_idx
        recent_pct = errors / total * 100.0
        base_pct = base_errors / base_total * 100.0
        severity = Severity.from_score_bands(
            z, cfg.error_elevated_z, cfg.error_anomalous_z, cfg.error_critical_z
        )
        return Alert(
            detector=self.id,
            severity=severity,
            template_id=None,
            template_text=_ALL_TEXT,
            baseline_desc=(
                f"{base_pct:.1f}% errors ({base_errors}/{base_total} events) "
                f"across {n_windows} windows in preceding "
                f"{cfg.error_baseline_s:g}s"
            ),
            baseline_value=base_pct,
            observed_desc=(
                f"{recent_pct:.1f}% errors ({errors}/{total} events) in "
                f"{cfg.error_window_s:g}s window"
            ),
            observed_value=recent_pct,
            deviation_desc=(
                f"{recent_pct:.1f}% vs {base_pct:.1f}% baseline (z={z:.1f})"
            ),
            z=z,
            threshold_desc=(
                f"two-proportion z >= {cfg.error_elevated_z:g} (elevated band)"
            ),
            threshold_value=cfg.error_elevated_z,
            window_start=start,
            window_end=end,
            group_key=_GROUP_KEY,
            event_time=end,
        )

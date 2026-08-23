"""New-template detector: first sighting of an unseen template after warm-up.

Scoring semantics: the score is the number of occurrences of the template
text within ``ASSESS_S`` (60 s) of its first post-warm-up sighting.
Severity bands via ``Severity.from_score_bands``: elevated band = 1.0
(every alert is at least ELEVATED), anomalous band = ``BURST_THRESHOLD``
(20 - a burst of brand-new messages), critical band = inf (unreachable).

Alerts are emitted from tick()/flush() once the 60 s assessment window
closes, or early from tick() when the burst threshold is crossed; the
engine must therefore tick regularly. Each unseen text fires exactly once.

Grace: when ``config.new_template_grace_s > 0``, templates first seen within
that many seconds after warm-up completion are absorbed silently (marked
seen, never alerted) so settling noise right after warm-up does not page.

The seen-set is a bounded LRU capped at ``lru_cap`` (default 5000). When an
ancient template resurfaces after eviction it MAY legitimately re-fire -
documented behaviour: eviction forgets history by design.
"""

from __future__ import annotations

import math
from collections import OrderedDict

from ..events import Alert, Event, Severity, iso_utc
from .base import BaseDetector


class NewTemplateDetector(BaseDetector):
    """Fires once per unseen template text after warm-up completes."""

    id = "new_template"
    ASSESS_S = 60.0
    BURST_THRESHOLD = 20.0
    _PENDING_CAP = 10000

    def __init__(self, ctx: object, lru_cap: int = 5000) -> None:
        super().__init__(ctx)
        self._cap = max(1, int(lru_cap))
        self._seen: OrderedDict[str, None] = OrderedDict()
        self._pending: OrderedDict[str, list[object]] = OrderedDict()
        self._warm = False
        self._warm_ts: float | None = None

    def observe(self, ev: Event, now: float) -> None:
        text = ev.template_text
        if not text:
            return
        warm = self.ctx.warmup_complete()
        if warm and not self._warm:
            self._warm = True
            self._warm_ts = now
        is_new = text not in self._seen
        if is_new:
            self._seen[text] = None
            while len(self._seen) > self._cap:
                self._seen.popitem(last=False)
        else:
            self._seen.move_to_end(text)
        pend = self._pending.get(text)
        if pend is not None:
            if now - float(pend[0]) <= self.ASSESS_S:
                pend[1] += 1  # type: ignore[operator]
            return
        if not warm or not is_new:
            return
        grace = self.ctx.config.new_template_grace_s
        if grace > 0 and self._warm_ts is not None and now - self._warm_ts <= grace:
            return
        first_ts = ev.ts if ev.ts > 0 else now
        self._pending[text] = [first_ts, 1, ev.template_id]
        while len(self._pending) > self._PENDING_CAP:
            self._pending.popitem(last=False)

    def tick(self, now: float) -> list[Alert]:
        alerts: list[Alert] = []
        for text in list(self._pending.keys()):
            pend = self._pending[text]
            age = now - float(pend[0])
            if int(pend[1]) >= self.BURST_THRESHOLD or age >= self.ASSESS_S:
                del self._pending[text]
                alerts.append(self._emit(text, pend, now))
        return alerts

    def _emit(self, text: str, pend: list[object], now: float) -> Alert:
        first_ts = float(pend[0])
        count = int(pend[1])
        severity = Severity.from_score_bands(
            float(count), 1.0, self.BURST_THRESHOLD, math.inf
        )
        return Alert(
            detector=self.id,
            severity=severity,
            template_id=int(pend[2]) if pend[2] is not None else None,
            template_text=text,
            baseline_desc="not present in baseline history",
            baseline_value=None,
            observed_desc=f"first occurrence at {iso_utc(first_ts)} (count {count} since)",
            observed_value=float(count),
            deviation_desc="new template",
            z=None,
            threshold_desc="warm-up complete + not seen in baseline",
            threshold_value=None,
            window_start=first_ts,
            window_end=now,
            group_key=f"new_template:{text}",
            examples=[],
        )

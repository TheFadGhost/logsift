"""Rare-sequence detector: unusual orderings of template ids.

Maintains a sliding n-gram (``config.sequence_ngram_n``, default 3) over the
order of template_id arrival. During warm-up, n-gram counts accumulate in a
bounded LRU map (``config.sequence_max_ngrams``, least-recently-seen evicted
first); after warm-up the counts are frozen as the baseline.

After warm-up: an n-gram whose baseline count is <=
``config.sequence_max_baseline_count`` (counts absent from the map count as
0 - never-seen orderings are the rarest kind) and that occurs at least
``config.sequence_min_observed`` times within a 10-minute window fires once,
then stays silent for ``config.sequence_cooldown_s`` per n-gram.

Scoring semantics: the score is k, the number of qualifying occurrences of
the n-gram inside the 10-minute window. Bands via
``Severity.from_score_bands``: elevated 1.0, anomalous = min_observed,
critical = inf - so every alert lands ANOMALOUS by construction; an unusual
ordering IS the signal, there is no softer or harder grade.

Known blind spots, stated honestly:
- long-range drift is invisible: only orderings of exactly n consecutive
  template ids are compared;
- permutations longer than n are not modelled - a pattern whose signature
  spans more than n events decomposes into unrelated short grams;
- cold-start after eviction: once an n-gram falls out of the bounded
  learning map its count reads as 0, so historically common orderings can
  re-fire as if rare; likewise patterns genuinely absent from a short
  learning phase fire readily.
"""

from __future__ import annotations

import math
from collections import OrderedDict, deque

from ..events import Alert, Event, Severity
from .base import BaseDetector

OBS_WINDOW_S = 600.0


class RareSequenceDetector(BaseDetector):
    """Fires when a rare n-gram of template ids repeats after warm-up."""

    id = "rare_sequence"

    def __init__(self, ctx: object) -> None:
        super().__init__(ctx)
        cfg = self.ctx.config
        self._n = max(1, int(cfg.sequence_ngram_n))
        self._cap = max(1, int(cfg.sequence_max_ngrams))
        self._base: OrderedDict[tuple[int, ...], int] = OrderedDict()
        self._learn: deque[int] = deque(maxlen=self._n)
        self._tail: deque[int] = deque(maxlen=self._n)
        self._obs: OrderedDict[tuple[int, ...], deque[float]] = OrderedDict()
        self._fired_at: dict[tuple[int, ...], float] = {}
        self._texts: OrderedDict[int, str] = OrderedDict()
        self._outbox: list[Alert] = []

    def observe(self, ev: Event, now: float) -> None:
        tid = ev.template_id
        if tid is None:
            return
        if ev.template_text:
            self._remember_text(tid, ev.template_text)
        if not self.ctx.warmup_complete():
            self._learn.append(tid)
            if len(self._learn) == self._n:
                gram = tuple(self._learn)
                self._base[gram] = self._base.get(gram, 0) + 1
                self._base.move_to_end(gram)
                while len(self._base) > self._cap:
                    self._base.popitem(last=False)
            return
        self._tail.append(tid)
        if len(self._tail) < self._n:
            return
        gram = tuple(self._tail)
        cnt = self._base.get(gram)
        if cnt is not None and cnt > self.ctx.config.sequence_max_baseline_count:
            return
        dq = self._obs.get(gram)
        if dq is None:
            dq = deque()
            self._obs[gram] = dq
            while len(self._obs) > self._cap:
                self._obs.popitem(last=False)
        else:
            self._obs.move_to_end(gram)
        dq.append(float(now))
        horizon = now - OBS_WINDOW_S
        while dq and dq[0] < horizon:
            dq.popleft()
        min_obs = self.ctx.config.sequence_min_observed
        if len(dq) < min_obs:
            return
        last = self._fired_at.get(gram)
        if last is not None and now - last < self.ctx.config.sequence_cooldown_s:
            return
        self._fired_at[gram] = now
        oldest = dq[0]
        k = len(dq)
        dq.clear()
        self._outbox.append(self._emit(gram, cnt, k, oldest, now))

    def tick(self, now: float) -> list[Alert]:
        out = self._outbox
        self._outbox = []
        return out

    def _remember_text(self, tid: int, text: str) -> None:
        self._texts[tid] = text
        self._texts.move_to_end(tid)
        while len(self._texts) > 8192:
            self._texts.popitem(last=False)

    def _emit(
        self,
        gram: tuple[int, ...],
        baseline_cnt: int | None,
        k: int,
        oldest: float,
        now: float,
    ) -> Alert:
        cfg = self.ctx.config
        seen = float(baseline_cnt) if baseline_cnt is not None else 0.0
        label = "->".join(str(i) for i in gram)
        severity = Severity.from_score_bands(
            float(k), 1.0, float(cfg.sequence_min_observed), math.inf
        )
        return Alert(
            detector=self.id,
            severity=severity,
            template_id=gram[-1],
            template_text=self._texts.get(gram[-1], ""),
            baseline_desc=(
                f"seen {int(seen)} times during learning (n-gram {label})"
            ),
            baseline_value=seen,
            observed_desc=f"{k} times in 10m",
            observed_value=float(k),
            deviation_desc="rare ordering",
            z=None,
            threshold_desc=(
                f"baseline<={cfg.sequence_max_baseline_count} and "
                f"k>={cfg.sequence_min_observed} in 10m"
            ),
            threshold_value=float(cfg.sequence_min_observed),
            window_start=oldest,
            window_end=now,
            group_key=f"rare_sequence:{gram}",
            examples=[],
        )

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
        self._min_component = max(1, int(cfg.sequence_min_component_count))
        self._hour_cap = max(1, int(cfg.sequence_max_alerts_per_hour))
        self._base: OrderedDict[tuple[int, ...], int] = OrderedDict()
        self._pairs: dict[tuple[int, int], int] = {}
        self._learn_counts: dict[int, int] = {}
        self._learn: deque[int] = deque(maxlen=self._n)
        self._tail: deque[int] = deque(maxlen=self._n)
        self._obs: OrderedDict[tuple[int, ...], deque[float]] = OrderedDict()
        self._fired_at: dict[tuple[int, ...], float] = {}
        self._alert_times: deque[float] = deque(maxlen=256)
        self._recent: deque[tuple[float, int]] = deque(maxlen=4096)
        self.suppressed_overflow = 0
        self._last_event_ts: float | None = None
        self._texts: OrderedDict[int, str] = OrderedDict()
        self._outbox: list[Alert] = []

    def _flood_dominates(self, now: float) -> bool:
        """True when a single template holds most of the recent stream."""
        share_limit = float(
            getattr(self.ctx.config, "sequence_max_dominant_share", 0.6)
        )
        horizon = now - OBS_WINDOW_S
        while self._recent and self._recent[0][0] < horizon:
            self._recent.popleft()
        counts: dict[int, int] = {}
        for _ts, tid in self._recent:
            counts[tid] = counts.get(tid, 0) + 1
        if not counts:
            return False
        top = max(counts.values())
        return (top / len(self._recent)) > share_limit

    def observe(self, ev: Event, now: float) -> None:
        tid = ev.template_id
        if tid is None:
            return
        if ev.template_text:
            self._remember_text(tid, ev.template_text)
        # Component familiarity is judged on ROLLING totals: a low-traffic
        # template may be absent from a short learning window yet be a
        # well-established part of the stream by the time it appears in an
        # unusual ordering.
        self._learn_counts[tid] = self._learn_counts.get(tid, 0) + 1
        if not self.ctx.warmup_complete():
            self._learn.append(tid)
            if len(self._learn) == self._n:
                gram = tuple(self._learn)
                self._base[gram] = self._base.get(gram, 0) + 1
                self._base.move_to_end(gram)
                while len(self._base) > self._cap:
                    self._base.popitem(last=False)
                if self._n >= 2:
                    for i in range(self._n - 1):
                        pair = (gram[i], gram[i + 1])
                        self._pairs[pair] = self._pairs.get(pair, 0) + 1
            return
        # A "sequence" is a temporally contiguous run of events: when the gap
        # since the previous event exceeds sequence_gap_s, the ordering
        # context resets. The n-gram therefore means "these events happened
        # back-to-back", which survives tight bursts and ignores
        # coincidences spread over minutes.
        gap_limit = float(getattr(self.ctx.config, "sequence_gap_s", 2.0))
        if self._last_event_ts is not None and now - self._last_event_ts > gap_limit:
            self._tail.clear()
        self._last_event_ts = now
        self._tail.append(tid)
        self._recent.append((float(now), tid))
        if len(self._tail) < self._n:
            return
        gram = tuple(self._tail)
        if len(set(gram)) < len(gram):
            # Orderings that repeat a template are density phenomena
            # (self-runs, alternating pairs); the volume detector owns them.
            # Rare sequences mean an unusual ordering of DISTINCT events.
            return
        if not self._components_known(gram):
            return
        cnt = self._base.get(gram)
        if cnt is not None and cnt > self.ctx.config.sequence_max_baseline_count:
            return
        if not self._pairs_rare(gram):
            return
        if self._flood_dominates(now):
            # During a flood one template dominates the stream and adjacency
            # patterns are its shadow, not a signal; volume owns that story.
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
        required = min_obs
        if len(dq) < required:
            return
        last = self._fired_at.get(gram)
        if last is not None and now - last < self.ctx.config.sequence_cooldown_s:
            return
        self._fired_at[gram] = now
        oldest = dq[0]
        k = len(dq)
        dq.clear()
        if not self._under_hourly_cap(now):
            self.suppressed_overflow += 1
            return
        self._outbox.append(self._emit(gram, cnt, k, oldest, now, required))

    def _components_known(self, gram: tuple[int, ...]) -> bool:
        return all(
            self._learn_counts.get(t, 0) >= self._min_component for t in gram
        )

    def _pairs_rare(self, gram: tuple[int, ...]) -> bool:
        """A qualifying triple must not merely be unseen - every adjacent pair
        must also have been rare during learning. Random co-occurrences of
        common templates usually contain at least one everyday adjacency and
        are filtered here."""
        if self._n < 2:
            return True
        max_cnt = self.ctx.config.sequence_max_baseline_count
        for i in range(self._n - 1):
            if self._pairs.get((gram[i], gram[i + 1]), 0) > max_cnt:
                return False
        return True

    def _under_hourly_cap(self, now: float) -> bool:
        horizon = now - 3600.0
        while self._alert_times and self._alert_times[0] < horizon:
            self._alert_times.popleft()
        if len(self._alert_times) >= self._hour_cap:
            return False
        self._alert_times.append(now)
        return True

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
        required: int,
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
                f"k>={required} in 10m"
            ),
            threshold_value=float(required),
            window_start=oldest,
            window_end=now,
            group_key=f"rare_sequence:{gram}",
            examples=[],
        )

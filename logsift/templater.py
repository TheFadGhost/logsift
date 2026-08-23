"""Drain-style streaming log templater.

Messages are tokenised on whitespace and clustered by token count. A message
joins the first candidate template (scanned in ascending template id order,
so ties resolve to the lowest id) whose tokens disagree with the message's
masked tokens in fewer than half of all positions; every disagreeing position
becomes a slot rendered as ``<*>``. Tokens containing digits are masked to
``<*>`` before matching, which keeps high-cardinality values (ids, addresses,
latencies) from fragmenting clusters while their original spellings are
returned as params.

State policy:
- Template ids are sequential integers starting at 1 in first-appearance
  order; identical input sequences therefore yield identical templates and
  ids.
- When storing one more template would exceed ``max_templates``, the least
  recently seen template is evicted, breaking ties by lowest count and then
  lowest template id.
- An evicted template's text reappearing later receives a NEW id. Downstream
  baselines must key on ``Template.text``, never on ``template_id``.
- ``stats()["merges"]`` counts messages absorbed by an existing template,
  whether or not slots widened.

Complexity: process() is O(c * t), c candidates sharing the token count and
t that count; eviction is O(n) over live templates and runs only when the
cap is exceeded. Memory is bounded by max_templates plus up to three sample
lines per template.
"""

from __future__ import annotations

from dataclasses import dataclass

from logsift.clock import Clock
from logsift.events import Template

SLOT = "<*>"
_SAMPLE_CAP = 3


@dataclass(frozen=True, slots=True)
class TemplateMatch:
    """One message's cluster: the template it belongs to and this message's slot values."""

    template: Template
    params: tuple[str, ...]


def _has_digit(token: str) -> bool:
    return any(ch.isdigit() for ch in token)


def _mask(tokens: tuple[str, ...], mask_digits: bool) -> tuple[str, ...]:
    if not mask_digits:
        return tokens
    return tuple(SLOT if _has_digit(tok) or tok == SLOT else tok for tok in tokens)


class Templater:
    """Streaming clusterer turning raw messages into templates and params."""

    __slots__ = (
        "_clock",
        "_mask_digits",
        "_groups",
        "_by_id",
        "_max_templates",
        "_next_id",
        "_total_messages",
        "_merges",
    )

    def __init__(self, clock: Clock, max_templates: int = 5000, mask_digits: bool = True) -> None:
        if max_templates < 1:
            raise ValueError("max_templates must be >= 1")
        self._clock = clock
        self._mask_digits = mask_digits
        self._groups: dict[int, list[Template]] = {}
        self._by_id: dict[int, Template] = {}
        self._max_templates = max_templates
        self._next_id = 1
        self._total_messages = 0
        self._merges = 0

    def process(self, message: str) -> TemplateMatch:
        """Template one message and update the matched template's counters."""
        raw = tuple(message.split())
        masked = _mask(raw, self._mask_digits)
        now = self._clock.now()
        self._total_messages += 1
        group = self._groups.setdefault(len(masked), [])
        for candidate in group:
            merged = _try_merge(candidate.tokens, masked)
            if merged is None:
                continue
            if merged != candidate.tokens:
                candidate.tokens = merged
            candidate.count += 1
            candidate.last_seen = now
            self._merges += 1
            if len(candidate.sample_values) < _SAMPLE_CAP:
                candidate.sample_values.append(message)
            return TemplateMatch(candidate, _params(raw, merged))
        return TemplateMatch(self._create(group, masked, now, message), _params(raw, masked))

    def get(self, template_id: int) -> Template | None:
        return self._by_id.get(template_id)

    def templates(self) -> list[Template]:
        return sorted(self._by_id.values(), key=lambda t: t.template_id)

    def stats(self) -> dict[str, int]:
        return {
            "total_messages": self._total_messages,
            "template_count": len(self._by_id),
            "merges": self._merges,
        }

    def _create(
        self,
        group: list[Template],
        masked: tuple[str, ...],
        now: float,
        message: str,
    ) -> Template:
        if len(self._by_id) >= self._max_templates:
            self._evict()
        template = Template(
            template_id=self._next_id,
            tokens=masked,
            count=1,
            first_seen=now,
            last_seen=now,
        )
        template.sample_values.append(message)
        self._next_id += 1
        group.append(template)
        self._by_id[template.template_id] = template
        return template

    def _evict(self) -> None:
        victim = min(
            self._by_id.values(),
            key=lambda t: (t.last_seen, t.count, t.template_id),
        )
        del self._by_id[victim.template_id]
        self._groups[len(victim.tokens)].remove(victim)


def _try_merge(candidate: tuple[str, ...], masked: tuple[str, ...]) -> tuple[str, ...] | None:
    if candidate == masked:
        return candidate
    mismatches = [i for i, (c, m) in enumerate(zip(candidate, masked)) if c != m]
    if len(mismatches) * 2 >= len(masked):
        return None
    widened = list(candidate)
    for i in mismatches:
        widened[i] = SLOT
    return tuple(widened)


def _params(raw: tuple[str, ...], tokens: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(raw[i] for i, tok in enumerate(tokens) if tok == SLOT)

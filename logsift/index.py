"""Bounded in-memory index over the live event stream.

Storage policy:
- Rows live in a fixed-capacity deque ring; ``add`` is O(1) and evicts the
  oldest row once ``max_events`` is reached. Nothing here reads the clock -
  all time comes from the events themselves.
- ``message`` and ``raw`` are capped at 512 characters on storage; ``fields``
  is capped at 16 entries with 512-character values, keeping per-row memory
  bounded regardless of input size.
- ``template_stats`` counts every event ever added (aligned to this index's
  lifetime). When a template's rows rotate out of the ring its stat entry is
  retained and its count simply stops growing - it is never decremented.
  Distinct template texts are bounded by the templater's own template cap
  (an evicted template text reappearing reuses the same text key).
- ``minute_counts`` holds at most 60 per-minute buckets aligned to
  floor(ts / 60); buckets are consecutive *observed* minutes that contained
  at least one event - idle gaps collapse. Sparkline consumers wanting true
  wall-clock alignment should bucket on their own axis instead.

``iter_rows`` iterates over a snapshot taken at call time, so adding or
evicting during iteration never distorts or truncates the walk.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Iterator

from logsift.events import Event, ParseStatus

MESSAGE_CAP = 512
RAW_CAP = 512
FIELD_VALUE_CAP = 512
FIELDS_CAP = 16
_MINUTE = 60
_MINUTE_BUCKETS = 60


@dataclass(slots=True)
class EventRow:
    """One indexed event; immutable-by-convention snapshot of the stream."""

    ts: float
    level: str | None
    template_id: int | None
    template_text: str
    message: str          # capped at MESSAGE_CAP chars
    fields: dict[str, str]  # capped at FIELDS_CAP entries, values capped
    source: str
    parse_status: str     # "ok" | "unparsed"
    raw: str              # capped at RAW_CAP chars


@dataclass(slots=True)
class TemplateStat:
    """All-time stats for one template text since index creation."""

    template_id: int
    text: str
    count: int
    last_seen: float
    minute_counts: deque  # per-minute totals, last 60 observed buckets (ints)


@dataclass(frozen=True)
class Totals:
    lines_total: int
    unparsed_total: int
    levels: dict[str, int]
    first_ts: float | None
    last_ts: float | None
    evicted_count: int


@dataclass(slots=True)
class _Stat:
    text: str
    tid: int
    count: int = 0
    last_seen: float = 0.0
    minutes: deque = field(default_factory=lambda: deque(maxlen=_MINUTE_BUCKETS))


def _cap_fields(fields: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for k, v in list(fields.items())[:FIELDS_CAP]:
        out[k[:FIELD_VALUE_CAP]] = v[:FIELD_VALUE_CAP]
    return out


def _status_text(status: object) -> str:
    if isinstance(status, ParseStatus):
        return status.value
    return str(status)


class StreamingIndex:
    """Fixed-capacity ring of EventRows with O(1) add and lifetime aggregates."""

    __slots__ = ("_rows", "_max_events", "_lines_total", "_unparsed_total",
                 "_levels", "_first_ts", "_last_ts", "_evicted", "_stats")

    def __init__(self, max_events: int = 100_000) -> None:
        if max_events < 1:
            raise ValueError("max_events must be >= 1")
        self._max_events = max_events
        self._rows: deque[EventRow] = deque(maxlen=max_events)
        self._lines_total = 0
        self._unparsed_total = 0
        self._levels: dict[str, int] = {}
        self._first_ts: float | None = None
        self._last_ts: float | None = None
        self._evicted = 0
        self._stats: dict[str, _Stat] = {}

    def add(self, event: Event) -> None:
        """Index one event. O(1); evicts the oldest row beyond max_events."""
        row = EventRow(
            ts=event.ts,
            level=event.level,
            template_id=event.template_id,
            template_text=event.template_text or "",
            message=event.message[:MESSAGE_CAP],
            fields=_cap_fields(event.fields),
            source=event.source,
            parse_status=_status_text(event.parse_status),
            raw=event.raw_line[:RAW_CAP],
        )
        if len(self._rows) == self._max_events:
            self._evicted += 1
        self._rows.append(row)
        self._lines_total += 1
        if row.parse_status == ParseStatus.UNPARSED.value:
            self._unparsed_total += 1
        if row.level is not None:
            self._levels[row.level] = self._levels.get(row.level, 0) + 1
        if self._first_ts is None:
            self._first_ts = event.ts
        self._last_ts = event.ts
        if row.template_text:
            self._touch_stats(row)

    def _touch_stats(self, row: EventRow) -> None:
        st = self._stats.get(row.template_text)
        if st is None:
            st = _Stat(text=row.template_text, tid=row.template_id or 0)
            self._stats[row.template_text] = st
        st.count += 1
        st.last_seen = row.ts
        if row.template_id is not None:
            st.tid = row.template_id
        bucket = int(row.ts // _MINUTE)
        minutes = st.minutes
        if minutes and minutes[-1][0] == bucket:
            minutes[-1][1] += 1
        else:
            minutes.append([bucket, 1])

    def __len__(self) -> int:
        return len(self._rows)

    def iter_rows(self, reverse: bool = False) -> Iterator[EventRow]:
        """Iterate a point-in-time snapshot; safe against concurrent adds/evictions."""
        snapshot = tuple(self._rows)
        if reverse:
            snapshot = tuple(reversed(snapshot))
        yield from snapshot

    def template_stats(self) -> dict[str, TemplateStat]:
        """Stats keyed by template TEXT; returned copies are safe to keep."""
        return {
            st.text: TemplateStat(
                template_id=st.tid,
                text=st.text,
                count=st.count,
                last_seen=st.last_seen,
                minute_counts=deque((count for _, count in st.minutes)),
            )
            for st in self._stats.values()
        }

    def totals(self) -> Totals:
        """Lifetime totals; first/last ts cover every event ever added."""
        return Totals(
            lines_total=self._lines_total,
            unparsed_total=self._unparsed_total,
            levels=dict(self._levels),
            first_ts=self._first_ts,
            last_ts=self._last_ts,
            evicted_count=self._evicted,
        )

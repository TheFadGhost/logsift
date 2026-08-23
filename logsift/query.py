"""Query layer over StreamingIndex: filter, aggregate, top-N, histogram, render.

Semantics:
- Time window is ``since <= ts < until`` (since inclusive, until exclusive).
- ``level`` matches case-insensitively against the row level.
- ``field_key`` / ``field_value``: key alone requires presence; value alone
  requires any field holding that value; both require the exact pair.
- ``free_text`` is a case-insensitive substring over message and raw.
- ``aggregate`` supports exactly ``level``, ``template``, ``source`` - rows do
  not expose arbitrary field lookups by design (bounded memory). Missing
  values aggregate under the literal key ``(none)``.
- ``histogram`` buckets are contiguous and include empty buckets; bucket i
  covers ``[start + i*b, start + (i+1)*b)`` except the final bucket, which is
  closed on the right so ``end`` itself lands in it (numpy convention).
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Mapping

from logsift.index import EventRow, StreamingIndex

_MAX_BUCKETS = 100_000

_AGG_FIELDS = ("level", "template", "source")
_MISSING = "(none)"
_EIGHTHS = ("▏", "▎", "▍", "▌", "▋", "▊", "▉")
_FULL_BLOCK = "█"


class QueryError(ValueError):
    """Invalid query. Carries a machine-readable kind and a hint-bearing message."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind


@dataclass(frozen=True)
class QuerySpec:
    since: float | None = None            # epoch seconds, inclusive
    until: float | None = None            # epoch seconds, exclusive
    level: str | None = None              # canonical (lowercase) level match
    template_id: int | None = None
    template_contains: str | None = None  # substring on template text
    field_key: str | None = None
    field_value: str | None = None
    free_text: str | None = None          # case-insensitive substring on message+raw


@dataclass(frozen=True)
class QueryResult:
    rows: tuple[EventRow, ...]
    matched: int
    scanned: int


def parse_query(params: Mapping[str, str]) -> QuerySpec:
    """Build a QuerySpec from raw string params; raises QueryError on bad input."""
    numeric = {"since": float, "until": float, "template_id": int}
    strings = ("level", "template_contains", "field_key", "field_value", "free_text")
    kwargs: dict[str, object] = {}
    for key, raw in params.items():
        value = str(raw).strip()
        if key in numeric:
            convert = numeric[key]
            try:
                kwargs[key] = convert(value)
            except ValueError:
                kind_word = "an integer" if convert is int else "an epoch-seconds number"
                raise QueryError(
                    "bad_value",
                    f"invalid {key} {raw!r}: must be {kind_word}"
                    f"; try {key}=1767225600",
                ) from None
        elif key in strings:
            if value:
                kwargs[key] = value.lower() if key == "level" else value
        else:
            valid = sorted((*numeric, *strings))
            raise QueryError(
                "unknown_param",
                f"unknown query parameter {key!r}; try one of {', '.join(valid)}",
            )
    return QuerySpec(**kwargs)


def execute(index: StreamingIndex, q: QuerySpec) -> QueryResult:
    """Filter the index snapshot; scanned counts rows examined, matched rows returned."""
    level = q.level.strip().lower() if q.level is not None else None
    free = q.free_text.lower() if q.free_text is not None else None
    has_field_pred = q.field_key is not None or q.field_value is not None
    rows: list[EventRow] = []
    scanned = 0
    for row in index.iter_rows():
        scanned += 1
        if q.since is not None and row.ts < q.since:
            continue
        if q.until is not None and row.ts >= q.until:
            continue
        if level is not None and (row.level is None or row.level.lower() != level):
            continue
        if q.template_id is not None and row.template_id != q.template_id:
            continue
        if q.template_contains is not None and q.template_contains not in row.template_text:
            continue
        if has_field_pred and not _field_match(row.fields, q.field_key, q.field_value):
            continue
        if free is not None and free not in row.message.lower() and free not in row.raw.lower():
            continue
        rows.append(row)
    return QueryResult(rows=tuple(rows), matched=len(rows), scanned=scanned)


def _field_match(fields: dict[str, str], key: str | None, value: str | None) -> bool:
    if key is not None and value is not None:
        return fields.get(key) == value
    if key is not None:
        return key in fields
    return value in fields.values()


def aggregate(rows: Iterable[EventRow], field: str) -> Counter:
    """Count rows by 'level', 'template' or 'source'; unknown fields are rejected."""
    if field not in _AGG_FIELDS:
        raise QueryError(
            "unknown_field",
            f"cannot aggregate by {field!r}: only {', '.join(_AGG_FIELDS)} are indexed"
            "; try level, template or source",
        )
    counter: Counter = Counter()
    for row in rows:
        if field == "level":
            key = row.level if row.level else _MISSING
        elif field == "template":
            key = row.template_text if row.template_text else _MISSING
        else:
            key = row.source if row.source else _MISSING
        counter[key] += 1
    return counter


def top_n(counter: Counter, n: int) -> list[tuple[str, int]]:
    """Deterministic top-N: count descending, ties alphabetical ascending."""
    ordered = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))
    return ordered[: max(n, 0)]


def histogram(
    rows: Iterable[EventRow],
    bucket_seconds: float,
    start: float | None = None,
    end: float | None = None,
) -> list[tuple[float, int]]:
    """Contiguous time buckets covering [start, end]; empty buckets included."""
    if bucket_seconds <= 0:
        raise QueryError(
            "bad_bucket",
            f"invalid bucket_seconds {bucket_seconds!r}: must be > 0"
            "; try 60 for minute buckets",
        )
    materialised = list(rows)
    lo = start
    hi = end
    if lo is None or hi is None:
        if not materialised:
            return []
        timestamps = [r.ts for r in materialised]
        if lo is None:
            lo = min(timestamps)
        if hi is None:
            hi = max(timestamps)
    if hi < lo:
        return []
    nbuckets = max(1, int(math.ceil((hi - lo) / bucket_seconds)))
    if nbuckets > _MAX_BUCKETS:
        raise QueryError(
            "too_many_buckets",
            f"{nbuckets} buckets exceed the {_MAX_BUCKETS} cap:"
            f" span {hi - lo:.0f}s at {bucket_seconds!r}s per bucket"
            "; try a larger bucket_seconds",
        )
    counts = [0] * nbuckets
    last = nbuckets - 1
    for row in materialised:
        if row.ts < lo or row.ts > hi:
            continue
        idx = int(math.floor((row.ts - lo) / bucket_seconds))
        counts[min(idx, last)] += 1  # right edge closes the final bucket
    return [(lo + i * bucket_seconds, c) for i, c in enumerate(counts)]


def format_histogram(buckets: list[tuple[float, int]], width_chars: int = 40) -> list[str]:
    """Render buckets as lines: ISO minute label, proportional bar, right-aligned count.

    Bars use full blocks terminated by an eighth-fraction block (DESIGN.md s4);
    zero counts render an empty bar and a bare 0.
    """
    if width_chars < 1:
        raise ValueError("width_chars must be >= 1")
    if not buckets:
        return []
    peak = max(count for _, count in buckets)
    count_width = max(len(str(peak)), 1)
    scale = width_chars * 8
    lines: list[str] = []
    for epoch, count in buckets:
        label = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
        bar = ""
        if peak > 0 and count > 0:
            units = (count * scale * 2 + peak) // (2 * peak)
            full, frac = divmod(units, 8)
            bar = _FULL_BLOCK * full + (_EIGHTHS[frac - 1] if frac else "")
        lines.append(f"{label} {bar:<{width_chars}} {count:>{count_width}}")
    return lines

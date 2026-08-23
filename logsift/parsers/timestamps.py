"""Shared parsing primitives and timestamp handling.

ParseResult and Parser live here because every parser module depends on
them and this is the leaf of the parsers package (no internal imports).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

MONTHS: dict[str, int] = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

LEVEL_ALIASES: dict[str, str] = {
    "trace": "trace",
    "debug": "debug",
    "dbg": "debug",
    "info": "info",
    "information": "info",
    "notice": "notice",
    "warn": "warning",
    "warning": "warning",
    "error": "error",
    "err": "error",
    "critical": "critical",
    "crit": "critical",
    "fatal": "critical",
    "emerg": "critical",
    "emergency": "critical",
    "alert": "critical",
    "panic": "critical",
}


@dataclass(slots=True)
class ParseResult:
    ok: bool
    ts: float | None
    level: str | None
    message: str
    fields: dict[str, str] = field(default_factory=dict)
    numeric: dict[str, float] = field(default_factory=dict)
    parser: str = ""
    error: str | None = None


class Parser(Protocol):
    name: str

    def try_parse(self, line: str) -> ParseResult | None:
        """Return a result for this line, or None when definitely not this format."""
        ...


def canon_level(raw: object) -> str | None:
    if raw is None:
        return None
    text = str(raw).strip().lower()
    return LEVEL_ALIASES.get(text)


def to_epoch(dt: datetime) -> float:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def parse_iso(text: str) -> float | None:
    """ISO-8601-ish strings. Offsets/Z/fractional seconds honored; naive means UTC."""
    cleaned = text.strip()
    if not cleaned:
        return None
    if cleaned.endswith(("z", "Z")):
        cleaned = cleaned[:-1] + "+00:00"
    cleaned = cleaned.replace(",", ".")
    try:
        dt = datetime.fromisoformat(cleaned)
    except ValueError:
        return None
    return to_epoch(dt)


def parse_with_formats(text: str, formats: list[str] | tuple[str, ...]) -> float | None:
    cleaned = text.strip()
    for fmt in formats:
        try:
            dt = datetime.strptime(cleaned, fmt)
        except ValueError:
            continue
        return to_epoch(dt)
    return None


def parse_auto(text: str) -> float | None:
    """Best-effort timestamp from a string: ISO first, then common layouts."""
    value = parse_iso(text)
    if value is not None:
        return value
    cleaned = text.strip()
    if cleaned.isdigit() and 9 <= len(cleaned) <= 13:
        epoch = float(cleaned)
        if len(cleaned) >= 13:
            epoch /= 1000.0
        return epoch
    return parse_with_formats(
        cleaned,
        ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d-%m-%Y %H:%M:%S", "%m-%d-%Y %H:%M:%S"),
    )


def parse_syslog_time(
    month_name: str, day_text: str, clock_text: str, year: int
) -> float | None:
    """RFC3164 'Mmm d HH:MM:SS' plus an externally supplied year."""
    month = MONTHS.get(month_name.lower())
    if month is None:
        return None
    parts = clock_text.split(":")
    if len(parts) != 3:
        return None
    try:
        day = int(day_text)
        hour = int(parts[0])
        minute = int(parts[1])
        second = int(parts[2])
        dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except ValueError:
        return None
    return dt.timestamp()


def parse_utc_offset(text: str) -> timezone | None:
    """'+0200', '-0530', '+02' style offsets from access/syslog stamps."""
    sign = 1 if text.startswith("+") else -1
    digits = text[1:]
    try:
        if len(digits) == 4:
            hours, minutes = int(digits[:2]), int(digits[2:])
        elif len(digits) == 2:
            hours, minutes = int(digits), 0
        else:
            return None
    except ValueError:
        return None
    if hours > 23 or minutes > 59:
        return None
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def year_of(epoch: float) -> int:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).year

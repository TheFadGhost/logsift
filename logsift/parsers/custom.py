"""User-supplied regex parser with named capture groups."""

from __future__ import annotations

import re
from typing import Sequence

from .timestamps import ParseResult, canon_level, parse_auto, parse_with_formats

_TS_GROUP_NAMES = ("ts", "time", "timestamp")
_LEVEL_GROUP_NAMES = ("level", "severity", "lvl")
_MSG_GROUP_NAMES = ("message", "msg", "event", "text")


class CustomParser:
    name = "custom"

    def __init__(
        self,
        pattern: str,
        time_formats: Sequence[str] = (),
    ) -> None:
        try:
            self._regex = re.compile(pattern)
        except re.error as exc:
            raise ValueError(
                f"invalid custom pattern ({exc}); hint: use named groups like "
                "(?P<ts>...), (?P<level>...), (?P<message>.*)"
            ) from exc
        self._time_formats: tuple[str, ...] = tuple(time_formats)
        if not self._regex.groupindex:
            raise ValueError(
                "custom pattern has no named groups; hint: add (?P<ts>...) or "
                "(?P<message>...) so fields can be extracted"
            )

    def try_parse(self, line: str) -> ParseResult | None:
        match = self._regex.search(line)
        if match is None:
            return None

        ts: float | None = None
        level: str | None = None
        message_value: str | None = None
        fields: dict[str, str] = {}
        numeric: dict[str, float] = {}

        for group_name in self._regex.groupindex:
            value = match.group(group_name)
            if value is None:
                continue
            lowered = group_name.lower()
            if lowered in _TS_GROUP_NAMES:
                parsed = (
                    parse_with_formats(value, self._time_formats)
                    if self._time_formats
                    else None
                )
                if parsed is None and not self._time_formats:
                    parsed = parse_auto(value)
                ts = parsed
                continue
            if lowered in _LEVEL_GROUP_NAMES:
                level = canon_level(value)
                continue
            if lowered in _MSG_GROUP_NAMES:
                message_value = value
                continue
            fields[group_name] = value
            try:
                numeric[group_name] = float(value)
            except ValueError:
                continue

        return ParseResult(
            ok=True,
            ts=ts,
            level=level,
            message=line if message_value is None else message_value,
            fields=fields,
            numeric=numeric,
            parser=self.name,
        )

    def score(self, line: str) -> float:
        return 0.99 if self._regex.search(line) is not None else 0.0

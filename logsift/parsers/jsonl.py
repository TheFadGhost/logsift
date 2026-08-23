"""JSON lines parser plus the escape-aware continuation probe."""

from __future__ import annotations

import json

from .timestamps import ParseResult, canon_level, parse_auto

TS_KEYS = ("timestamp", "time", "ts", "@timestamp", "date", "datetime", "eventtime")
LEVEL_KEYS = ("level", "severity", "lvl")
MSG_KEYS = ("message", "msg", "event", "text")


def needs_continuation(line: str) -> bool:
    """True while `line` ends inside an unterminated JSON string or object/array.

    Escape-aware: backslash escapes the next character inside strings, so
    \\\" does not close a quote and braces inside strings are ignored.
    """
    in_string = False
    escaped = False
    depth = 0
    for ch in line:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        else:
            if ch == '"':
                in_string = True
            elif ch in "{[":
                depth += 1
            elif ch in "}]":
                depth = max(0, depth - 1)
    return in_string or depth > 0


class JsonParser:
    name = "json"

    def try_parse(self, line: str) -> ParseResult | None:
        stripped = line.strip()
        if not stripped.startswith("{"):
            return None
        try:
            data = json.loads(stripped)
        except (json.JSONDecodeError, ValueError, RecursionError):
            return ParseResult(
                ok=False,
                ts=None,
                level=None,
                message=line,
                parser=self.name,
                error=(
                    "invalid JSON after leading '{': the line looks like JSON but "
                    "does not decode; hint: check for truncation or stray characters"
                ),
            )
        if not isinstance(data, dict):
            return None
        return _build_result(line, data, self.name)

    def score(self, line: str) -> float:
        stripped = line.strip()
        if not stripped.startswith("{"):
            return 0.0
        try:
            data = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            return 0.15 if not needs_continuation(stripped) else 0.05
        if not isinstance(data, dict):
            return 0.0
        return 0.95 if _has_known_keys(data) else 0.6


def _has_known_keys(data: dict) -> bool:
    lowered = {str(k).lower() for k in data}
    return bool(
        lowered.intersection(TS_KEYS) or lowered.intersection(LEVEL_KEYS)
        or lowered.intersection(MSG_KEYS)
    )


def _build_result(raw_line: str, data: dict, parser_name: str) -> ParseResult:
    ts_value = _first_key(data, TS_KEYS)
    ts = _parse_ts_value(ts_value)

    level_raw = _first_key(data, LEVEL_KEYS)
    level = canon_level(level_raw)

    msg_value = _first_key(data, MSG_KEYS)
    message = raw_line if msg_value is None else str(msg_value)

    fields: dict[str, str] = {}
    numeric: dict[str, float] = {}
    lowered_consumed = set()
    for key in TS_KEYS + LEVEL_KEYS + MSG_KEYS:
        lowered_consumed.add(key)
    for key in data:
        key_str = str(key)
        if key_str.lower() in lowered_consumed:
            continue
        value = data[key]
        _collect(key_str, value, fields, numeric)

    return ParseResult(
        ok=True,
        ts=ts,
        level=level,
        message=message,
        fields=fields,
        numeric=numeric,
        parser=parser_name,
    )


def _first_key(data: dict, names: tuple[str, ...]) -> object | None:
    for name in names:
        for key in data:
            if str(key).lower() == name:
                return data[key]
    return None


def _parse_ts_value(value: object) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        epoch = float(value)
        if 0.0 < epoch < 4.0e12:
            return epoch
        return None
    return parse_auto(str(value))


def _scalar_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def _collect(
    key: str,
    value: object,
    fields: dict[str, str],
    numeric: dict[str, float],
) -> None:
    if isinstance(value, dict):
        for inner_key in value:
            inner_value = value[inner_key]
            dotted = f"{key}.{inner_key}"
            text = _scalar_text(inner_value)
            if text is None:
                continue
            fields[dotted] = text
            if isinstance(inner_value, (int, float)) and not isinstance(inner_value, bool):
                numeric[dotted] = float(inner_value)
        return
    text = _scalar_text(value)
    if text is None:
        return
    fields[key] = text
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        numeric[key] = float(value)

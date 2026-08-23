"""logfmt parser: key=value pairs, quoted values with escapes."""

from __future__ import annotations

import re

from .timestamps import ParseResult, canon_level, parse_auto

_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]*")

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "'": "'", "\\": "\\"}

_TS_KEYS = ("timestamp", "time", "ts", "@timestamp", "date", "datetime", "eventtime")
_LEVEL_KEYS = ("level", "severity", "lvl")
_MSG_KEYS = ("message", "msg", "event", "text")


def _split_tokens(line: str) -> list[tuple[bool, str]]:
    """Split on spaces outside quotes; returns (ended_unquoted?, token) pairs."""
    tokens: list[tuple[bool, str]] = []
    buf: list[str] = []
    quote: str | None = None
    i = 0
    n = len(line)
    while i < n:
        ch = line[i]
        if quote is not None:
            buf.append(ch)
            if ch == "\\" and i + 1 < n:
                buf.append(line[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ('"', "'"):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch in (" ", "\t"):
            if buf:
                tokens.append((False, "".join(buf)))
                buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        tokens.append((quote is not None, "".join(buf)))
    return tokens


def _unquote(token: str) -> tuple[str, bool]:
    """Strip surrounding quotes and resolve escapes. Returns (value, well_formed)."""
    if len(token) >= 2 and token[0] == token[-1] and token[0] in ('"', "'"):
        body = token[1:-1]
        out: list[str] = []
        i = 0
        while i < len(body):
            ch = body[i]
            if ch == "\\" and i + 1 < len(body):
                out.append(_ESCAPES.get(body[i + 1], body[i + 1]))
                i += 2
                continue
            if ch == "\\":
                return "".join(out), False
            out.append(ch)
            i += 1
        return "".join(out), True
    if token and token[0] in ('"', "'"):
        return token, False
    return token, True


class LogfmtParser:
    name = "logfmt"

    def try_parse(self, line: str) -> ParseResult | None:
        pairs: dict[str, str] = {}
        malformed = 0
        saw_equals = False
        for _quoted, token in _split_tokens(line):
            eq = _find_equals(token)
            if eq is None:
                continue
            saw_equals = True
            key = token[:eq]
            value_token = token[eq + 1 :]
            if _KEY_RE.fullmatch(key) is None:
                malformed += 1
                continue
            value, well_formed = _unquote(value_token)
            if not well_formed:
                malformed += 1
            pairs[key] = value
        if not pairs:
            if saw_equals or "=" in line:
                hint = (
                    "expected key=value pairs; hint: keys must start with a letter "
                    "or underscore and values may be double- or single-quoted"
                )
                return ParseResult(
                    ok=False,
                    ts=None,
                    level=None,
                    message=line,
                    parser=self.name,
                    error=f"no parsable key=value tokens in logfmt-like line ({hint})",
                )
            return None

        ts = _lookup_ts(pairs)
        level = canon_level(_lookup_first(pairs, _LEVEL_KEYS))
        msg_value = _lookup_first(pairs, _MSG_KEYS)
        message = line if msg_value is None else msg_value

        fields: dict[str, str] = {}
        numeric: dict[str, float] = {}
        consumed = set()
        for names in (_TS_KEYS, _LEVEL_KEYS, _MSG_KEYS):
            consumed.update(names)
        for key, value in pairs.items():
            if key.lower() in consumed:
                continue
            fields[key] = value
            try:
                numeric[key] = float(value)
            except ValueError:
                continue

        return ParseResult(
            ok=True,
            ts=ts,
            level=level,
            message=message,
            fields=fields,
            numeric=numeric,
            parser=self.name,
        )

    def score(self, line: str) -> float:
        total = 0
        good = 0
        for _quoted, token in _split_tokens(line):
            eq = _find_equals(token)
            if eq is None:
                total += 1
                continue
            key = token[:eq]
            if _KEY_RE.fullmatch(key) is None:
                total += 1
                continue
            value, well_formed = _unquote(token[eq + 1 :])
            total += 1
            if well_formed:
                good += 1
        if total == 0 or good == 0:
            return 0.0
        fraction = good / total
        base = 0.5 + 0.4 * fraction
        lowered_keys = {
            t[: _find_equals(t)].lower()
            for _q, t in _split_tokens(line)
            if _find_equals(t) is not None
        }
        if lowered_keys.intersection(_TS_KEYS + _LEVEL_KEYS + _MSG_KEYS):
            base = max(base, 0.9)
        return min(base, 0.92)


def _find_equals(token: str) -> int | None:
    """First '=' outside quotes."""
    quote: str | None = None
    i = 0
    while i < len(token):
        ch = token[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
        elif ch == "=":
            return i
        i += 1
    return None


def _lookup_first(pairs: dict[str, str], names: tuple[str, ...]) -> str | None:
    for name in names:
        for key in pairs:
            if key.lower() == name:
                return pairs[key]
    return None


def _lookup_ts(pairs: dict[str, str]) -> float | None:
    raw = _lookup_first(pairs, _TS_KEYS)
    if raw is None:
        return None
    return parse_auto(raw)

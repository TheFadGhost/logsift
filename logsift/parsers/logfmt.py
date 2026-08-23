"""logfmt parser: key=value pairs, quoted values with escapes."""

from __future__ import annotations

import re

from .timestamps import ParseResult, canon_level, parse_auto

_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.\-]*")

_key_ok_cache: dict[str, bool] = {}


def _key_bad(key: str) -> bool:
    cached = _key_ok_cache.get(key)
    if cached is None:
        cached = _KEY_RE.fullmatch(key) is not None
        if len(_key_ok_cache) < 4096:
            _key_ok_cache[key] = cached
        return not cached
    return not cached

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "'": "'", "\\": "\\"}

_TS_KEYS = ("timestamp", "time", "ts", "@timestamp", "date", "datetime", "eventtime")
_LEVEL_KEYS = ("level", "severity", "lvl")
_MSG_KEYS = ("message", "msg", "event", "text")

_CONSUMED = frozenset(_TS_KEYS + _LEVEL_KEYS + _MSG_KEYS)

_TS_KEYS_SET = frozenset(_TS_KEYS)
_LEVEL_KEYS_SET = frozenset(_LEVEL_KEYS)
_MSG_KEYS_SET = frozenset(_MSG_KEYS)

_ROLE_CACHE: dict[str, str] = {}

# One C-level pass extracts key=value pairs; quoted values may contain
# spaces and escaped quotes. Keys share the logfmt key grammar and must
# start at a token boundary.
_PAIR_RE = re.compile(
    r"(?:^|(?<=\s))([A-Za-z_][A-Za-z0-9_.\-]*)="
    r"(\"(?:[^\"\\]|\\.)*\"?|'(?:[^'\\]|\\.)*'?|[^\s]+)"
)


_TOKEN_RE = None  # replaced by jump-based scanner below


def _odd_backslashes_before(line: str, start: int, end: int) -> bool:
    """True when an odd run of backslashes immediately precedes end."""
    k = end - 1
    count = 0
    while k >= start and line[k] == "\\":
        count += 1
        k -= 1
    return count % 2 == 1


def _split_tokens(line: str) -> list[tuple[bool, str]]:
    """Split on spaces outside quotes; returns (ended_unquoted?, token) pairs."""
    if '"' not in line and "'" not in line:
        return [(False, tok) for tok in line.split()]
    out: list[tuple[bool, str]] = []
    i = 0
    n = len(line)
    while True:
        while i < n and line[i] in " \t":
            i += 1
        if i >= n:
            break
        start = i
        quote_open = False
        end = n
        while i < n:
            sp = line.find(" ", i)
            tab = line.find("\t", i)
            dq = line.find('"', i)
            sq = line.find("'", i)
            candidates = [x for x in (sp, tab, dq, sq) if x != -1]
            if not candidates:
                i = n
                break
            nxt = min(candidates)
            if line[nxt] not in "\"'":
                i = nxt + 1
                end = nxt
                break
            # Jump over a quoted span, honouring escaped quotes.
            q = line[nxt]
            j = nxt + 1
            close = -1
            while True:
                close = line.find(q, j)
                if close == -1:
                    i = n
                    quote_open = True
                    break
                if not _odd_backslashes_before(line, nxt + 1, close):
                    i = close + 1
                    break
                j = close + 1
            if quote_open:
                end = n
                break
        out.append((quote_open and i >= n and end == n, line[start:end]))
    return out


def _unquote(token: str) -> tuple[str, bool]:
    """Strip surrounding quotes and resolve escapes. Returns (value, well_formed)."""
    first = token[0] if token else ""
    if first in ('"', "'"):
        if len(token) < 2 or token[-1] != first:
            return token, False
        body = token[1:-1]
        if "\\" not in body:
            return body, True
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
    return token, True


class LogfmtParser:
    name = "logfmt"

    def try_parse(self, line: str) -> ParseResult | None:
        fields: dict[str, str] = {}
        numeric: dict[str, float] = {}
        ts_raw: str | None = None
        level_raw: str | None = None
        msg_raw: str | None = None
        matched_any = False
        for m in _PAIR_RE.finditer(line):
            matched_any = True
            key = m.group(1)
            v = m.group(2)
            if v[:1] in "\"'":
                v, well_formed = _unquote(v)
                if not well_formed:
                    continue
            low = _ROLE_CACHE.get(key)
            if low is None:
                low = key.lower()
                if len(_ROLE_CACHE) < 4096:
                    _ROLE_CACHE[key] = low
            if low in _TS_KEYS_SET:
                if ts_raw is None:
                    ts_raw = v
                continue
            if low in _LEVEL_KEYS_SET:
                if level_raw is None:
                    level_raw = v
                continue
            if low in _MSG_KEYS_SET:
                if msg_raw is None:
                    msg_raw = v
                continue
            fields[key] = v
            last = v[-1:] if v else ""
            if last.isdigit() or last in ".eE+-":
                try:
                    numeric[key] = float(v)
                except ValueError:
                    continue

        if not matched_any:
            if "=" in line:
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

        return ParseResult(
            ok=True,
            ts=parse_auto(ts_raw) if ts_raw is not None else None,
            level=canon_level(level_raw),
            message=line if msg_raw is None else msg_raw,
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
    q = len(token)
    dq = token.find('"')
    if dq >= 0:
        q = dq
    sq = token.find("'")
    if 0 <= sq < q:
        q = sq
    idx = token.find("=", 0, q)
    return idx if idx >= 0 else None


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

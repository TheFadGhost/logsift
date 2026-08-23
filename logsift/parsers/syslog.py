"""syslog parser: RFC3164 and RFC5424."""

from __future__ import annotations

import re

from ..clock import Clock
from .timestamps import ParseResult, parse_iso, parse_syslog_time, year_of

_RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<program>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<msg>.*)$"
)

_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d{1,2})\s+"
    r"(?P<ts>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?P<sd>\[.*?\]|-)"
    r"(?:\s(?P<msg>.*))?$"
)

_PRI_SEVERITY: dict[int, str] = {
    0: "critical",
    1: "critical",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}


def _level_from_pri(pri_text: str | None) -> str | None:
    if pri_text is None:
        return None
    try:
        pri = int(pri_text)
    except ValueError:
        return None
    if not 0 <= pri <= 191:
        return None
    return _PRI_SEVERITY[pri % 8]


class SyslogParser:
    name = "syslog"

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    def try_parse(self, line: str) -> ParseResult | None:
        stripped = line.strip()
        if stripped.startswith("<"):
            match = _RFC5424_RE.match(stripped)
            if match is not None:
                return self._result_5424(match)
            has_pri = re.match(r"^<\d{1,3}>", stripped) is not None
            match = _RFC3164_RE.match(stripped)
            if has_pri and match is not None:
                return self._result_3164(match, had_pri=True)
            if has_pri:
                return ParseResult(
                    ok=False,
                    ts=None,
                    level=None,
                    message=line,
                    parser=self.name,
                    error=(
                        "looks like RFC5424 (starts with <PRI>) but the header does "
                        "not match '<PRI>version timestamp host app procid msgid "
                        "structured-data message'; hint: check the ISO8601 stamp"
                    ),
                )
            return None

        match = _RFC3164_RE.match(stripped)
        if match is None:
            if re.match(
                r"^[A-Za-z]{3}\s+\d{1,2}\s", stripped
            ) is not None or re.match(r"^[A-Za-z]{3}\s+\d{1,2}$", stripped) is not None:
                hint = (
                    "expected 'Mmm dd HH:MM:SS host proc[pid]: msg'; "
                    "hint: check the time-of-day and host fields"
                )
                return ParseResult(
                    ok=False,
                    ts=None,
                    level=None,
                    message=line,
                    parser=self.name,
                    error=f"classic syslog-shaped line failed to parse ({hint})",
                )
            return None
        return self._result_3164(match, stripped.startswith("<"))

    def _result_5424(self, match: re.Match[str]) -> ParseResult:
        groups = match.groupdict()
        stamp = groups["ts"]
        ts = parse_iso(stamp) if stamp != "-" else None
        level = _level_from_pri(groups["pri"])
        msg = groups["msg"] or ""
        fields = {
            "hostname": groups["host"],
            "program": groups["app"],
        }
        numeric: dict[str, float] = {}
        if groups["procid"] not in ("-", "") and groups["procid"].isdigit():
            numeric["pid"] = float(groups["procid"])
            fields["pid"] = groups["procid"]
        return ParseResult(
            ok=True,
            ts=ts,
            level=level,
            message=msg,
            fields=fields,
            numeric=numeric,
            parser=self.name,
        )

    def _result_3164(self, match: re.Match[str], had_pri: bool) -> ParseResult:
        groups = match.groupdict()
        now = self._clock.now()
        year = year_of(now)
        ts = parse_syslog_time(groups["mon"], groups["day"], groups["clock"], year)
        if ts is None:
            return ParseResult(
                ok=False,
                ts=None,
                level=None,
                message=match.group(0),
                parser=self.name,
                error=(
                    f"syslog timestamp '{groups['mon']} {groups['day']} "
                    f"{groups['clock']}' is invalid; "
                    "hint: expected 'Mmm d HH:MM:SS' with a real month/day/time"
                ),
            )
        level = _level_from_pri(groups["pri"]) if had_pri else None
        fields = {
            "hostname": groups["host"],
            "program": groups["program"],
        }
        pid = groups.get("pid")
        if pid is not None:
            fields["pid"] = pid
        return ParseResult(
            ok=True,
            ts=ts,
            level=level,
            message=groups["msg"],
            fields=fields,
            parser=self.name,
        )

    def score(self, line: str) -> float:
        stripped = line.strip()
        if stripped.startswith("<"):
            if _RFC5424_RE.match(stripped) is not None:
                return 0.95
            has_pri = re.match(r"^<\d{1,3}>", stripped) is not None
            if _RFC3164_RE.match(stripped) is not None and has_pri:
                return 0.95
            if re.match(r"^<\d{1,3}>\d", stripped) is not None:
                return 0.4
            return 0.0
        if _RFC3164_RE.match(stripped) is not None:
            return 0.95
        if re.match(r"^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}", stripped) is not None:
            return 0.5
        return 0.0

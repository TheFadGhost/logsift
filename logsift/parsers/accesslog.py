"""Apache/Nginx access log parser: common and combined formats."""

from __future__ import annotations

import re
from datetime import datetime

from .timestamps import (
    MONTHS,
    ParseResult,
    parse_utc_offset,
)

_ACCESS_RE = re.compile(
    r"^(?P<remote_host>\S+) (?P<ident>\S+) (?P<authuser>\S+) "
    r"\[(?P<day>\d{1,2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2}) (?P<tz>[+-]\d{4})\] "
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<bytes>\d+|-)'
    r'(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
    r"(?: (?P<request_time>[\d.]+|-))?\s*$"
)


def _parse_access_ts(
    day: str, mon: str, year: str, hh: str, mm: str, ss: str, tz_text: str
) -> float | None:
    month = MONTHS.get(mon.lower())
    tz = parse_utc_offset(tz_text)
    if month is None or tz is None:
        return None
    try:
        dt = datetime(
            int(year), month, int(day), int(hh), int(mm), int(ss), tzinfo=tz
        )
    except ValueError:
        return None
    return dt.timestamp()


class AccessLogParser:
    name = "access_combined"

    def try_parse(self, line: str) -> ParseResult | None:
        match = _ACCESS_RE.match(line.strip())
        if match is None:
            if '"' in line:
                return ParseResult(
                    ok=False,
                    ts=None,
                    level=None,
                    message=line,
                    parser=self.name,
                    error=(
                        "looks like an access log (quoted request) but does not match "
                        "common/combined layout "
                        "'host ident authuser [dd/Mon/yyyy:HH:mm:ss +zzzz] \"METHOD path "
                        "proto\" status bytes'; hint: check the bracketed timestamp and "
                        "the quoted request field"
                    ),
                )
            return None

        groups = match.groupdict()
        ts = _parse_access_ts(
            groups["day"],
            groups["mon"],
            groups["year"],
            groups["hh"],
            groups["mm"],
            groups["ss"],
            groups["tz"],
        )
        if ts is None:
            return ParseResult(
                ok=False,
                ts=None,
                level=None,
                message=line,
                parser=self.name,
                error=(
                    "access log timestamp is invalid; "
                    "hint: expected dd/Mon/yyyy:HH:mm:ss +zzzz inside brackets"
                ),
            )

        request = groups["request"]
        parts = request.split(" ")
        if len(parts) == 3:
            method, path, protocol = parts
        else:
            method, path, protocol = "-", request, "-"

        fields: dict[str, str] = {
            "method": method,
            "path": path,
            "protocol": protocol,
            "remote_host": groups["remote_host"],
            "ident": groups["ident"],
            "authuser": groups["authuser"],
            "status": groups["status"],
            "bytes": groups["bytes"],
            "referer": groups.get("referer") or "-",
            "user_agent": groups.get("user_agent") or "-",
        }
        numeric: dict[str, float] = {"status": float(groups["status"])}
        if groups["bytes"] != "-":
            numeric["bytes"] = float(groups["bytes"])
        if groups.get("request_time") not in (None, "-"):
            numeric["duration_ms"] = float(groups["request_time"]) * 1000.0

        level = None
        status_code = int(groups["status"])
        if status_code >= 500:
            level = "error"
        elif status_code >= 400:
            level = "warning"

        return ParseResult(
            ok=True,
            ts=ts,
            level=level,
            message=request,
            fields=fields,
            numeric=numeric,
            parser=self.name,
        )

    def score(self, line: str) -> float:
        stripped = line.strip()
        if _ACCESS_RE.match(stripped) is not None:
            return 0.98
        if '"' in stripped and re.search(r"\s\d{3}\s", stripped) is not None:
            return 0.2
        return 0.0

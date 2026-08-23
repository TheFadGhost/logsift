"""Format parsers: detection, parsing, honest failure reporting.

Public surface: ParseResult, Parser, ParserRegistry, DetectionReport,
needs_continuation, plus one class per supported format.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..clock import Clock
from ..textwidth import sanitize_for_display, truncate_end
from .accesslog import AccessLogParser
from .custom import CustomParser
from .jsonl import JsonParser, needs_continuation
from .logfmt import LogfmtParser
from .syslog import SyslogParser
from .timestamps import ParseResult, Parser

_EXCERPT_WIDTH = 120
_LOW_CONFIDENCE_HINT = (
    "line matched no known format; try a --format override or a custom pattern "
    "with named groups like (?P<ts>...) (?P<level>...) (?P<message>.*)"
)


@dataclass(frozen=True)
class DetectionReport:
    parser_name: str
    confidence: float
    scores: dict[str, float]
    sample_size: int


class ParserRegistry:
    _BASE_ORDER: tuple[type, ...] = (JsonParser, LogfmtParser, AccessLogParser, SyslogParser)

    def __init__(self, clock: Clock, custom_pattern: str | None = None) -> None:
        self._clock = clock
        self._parsers: list[Parser] = []
        if custom_pattern is not None:
            self._parsers.append(CustomParser(custom_pattern))
        for cls in self._BASE_ORDER:
            if cls is SyslogParser:
                self._parsers.append(SyslogParser(clock))
            else:
                self._parsers.append(cls())
        self._locked: str | None = None
        self._locked_parser: Parser | None = None
        self._ordered: list[Parser] = list(self._parsers)

    @property
    def parser_names(self) -> tuple[str, ...]:
        return tuple(p.name for p in self._parsers)

    def detect(self, sample_lines: list[str]) -> DetectionReport:
        scores: dict[str, float] = {p.name: 0.0 for p in self._parsers}
        if not sample_lines:
            return DetectionReport(parser_name="", confidence=0.0, scores=scores, sample_size=0)
        for parser in self._parsers:
            scorer = getattr(parser, "score", None)
            per_line = [
                round(float(scorer(line)), 4) if callable(scorer) else 0.0
                for line in sample_lines
            ]
            scores[parser.name] = round(sum(per_line) / len(per_line), 4)
        best_name = ""
        best_score = 0.0
        for parser in self._parsers:
            score = scores[parser.name]
            if score > best_score:
                best_score = score
                best_name = parser.name
        return DetectionReport(
            parser_name=best_name,
            confidence=best_score,
            scores=dict(scores),
            sample_size=len(sample_lines),
        )

    def lock(self, parser_name: str) -> None:
        valid = self.parser_names
        if parser_name not in valid:
            raise ValueError(
                f"unknown parser {parser_name!r}; available: {', '.join(valid)}"
            )
        self._locked = parser_name
        self._locked_parser = next(p for p in self._parsers if p.name == parser_name)

    @property
    def locked(self) -> str | None:
        return self._locked

    def parse_line(self, line: str) -> ParseResult:
        ordered = self._ordered
        if self._locked is not None:
            locked_result = self._locked_parser.try_parse(line)
            if locked_result is not None:
                return locked_result
        else:
            for parser in ordered:
                result = parser.try_parse(line)
                if result is not None and result.ok:
                    return result
            # fall through to failure reporting below
            return self._all_fail(line, ordered)
        for parser in ordered:
            if parser is self._locked_parser:
                continue
            result = parser.try_parse(line)
            if result is not None and result.ok:
                return result
        return self._all_fail(line, [self._locked_parser, *ordered])

    def _all_fail(self, line: str, tried: list) -> ParseResult:
        first_failure: ParseResult | None = None
        for parser in tried:
            result = parser.try_parse(line)
            if result is not None and not result.ok and first_failure is None:
                first_failure = result
        if first_failure is not None:
            return first_failure
        return self._unparsed_result(line)

    def _unparsed_result(self, line: str) -> ParseResult:
        excerpt = truncate_end(sanitize_for_display(line), _EXCERPT_WIDTH)
        scores: dict[str, float] = {}
        best_name = ""
        best_score = 0.0
        for parser in self._parsers:
            scorer = getattr(parser, "score", None)
            value = round(float(scorer(line)), 4) if callable(scorer) else 0.0
            scores[parser.name] = value
            if value > best_score:
                best_score = value
                best_name = parser.name
        if best_score > 0.0:
            closest = f"closest format looks like {best_name} (confidence {best_score:.2f})"
        else:
            closest = "no format resembles it"
        hint = _LOW_CONFIDENCE_HINT
        if best_score == 0.0 and needs_continuation(line):
            hint = (
                "the line ends inside an unterminated JSON object or string; "
                "it may be truncated mid-write or need multiline continuation"
            )
        error = (
            f"no parser accepted this line (tried: {', '.join(self.parser_names)}); "
            f"line: '{excerpt}' ({closest}); try {hint}"
        )
        return ParseResult(
            ok=False,
            ts=None,
            level=None,
            message=line,
            fields={},
            numeric={},
            parser="",
            error=error,
        )


__all__ = [
    "AccessLogParser",
    "CustomParser",
    "DetectionReport",
    "JsonParser",
    "LogfmtParser",
    "ParseResult",
    "Parser",
    "ParserRegistry",
    "SyslogParser",
    "needs_continuation",
]

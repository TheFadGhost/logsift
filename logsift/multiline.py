"""Multi-line event assembly: stack traces and pretty-printed objects become one event."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class ContinuationRule:
    """Predicate deciding whether a raw line continues the currently open event."""

    name: str
    matches: Callable[[str], bool]


_STACK_FRAME_RE = re.compile(
    r"^(?:"
    r"[ \t]+at\s\S"                                     # java/js frame
    r"|[ \t]*Caused by:"                                # java cause chain
    r"|[ \t]*\.\.\.[ \t]+\d+[ \t]+more\b"               # java "... N more"
    r"|Traceback \(most recent call last\):"            # python traceback header
    r"|[ \t]+File \"[^\"]+\", line \d+"                 # python frame
    r"|[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception)\b"    # exception summary line
    r")"
)

_JSON_CLOSE_RE = re.compile(r"\s*[}\]][\s}\],]*")


def _is_indented(line: str) -> bool:
    return line.startswith((" ", "\t"))


def _is_stack_frame(line: str) -> bool:
    return _STACK_FRAME_RE.match(line) is not None


def _json_continues(line: str) -> bool:
    """True while the stream is still inside one JSON document.

    Degrades to False whenever logsift.parsers.jsonl cannot be imported, so
    the rule is inert until that module exists.
    """
    try:
        from logsift.parsers.jsonl import needs_continuation
    except Exception:
        return False
    if needs_continuation(line):
        return True
    # A line made only of closers/commas ends the document but still belongs to it.
    return _JSON_CLOSE_RE.fullmatch(line) is not None


def default_rules() -> list[ContinuationRule]:
    """Fresh list each call; callers may reorder or extend freely."""
    return [
        ContinuationRule("indented", _is_indented),
        ContinuationRule("stack_frame", _is_stack_frame),
        ContinuationRule("json_partial", _json_continues),
    ]


class MultilineAssembler:
    """Assembles raw lines into completed multi-line event texts.

    Contract:
    - Lines are terminator-stripped input from the reader, joined with "\\n".
    - A line matching no rule completes the open event and starts a new one;
      a matching line appends. A matching line arriving with no open event
      opens one, so data is never dropped mid-trace at stream start.
    - Bounded memory: appending past ``max_event_lines`` or ``max_event_bytes``
      force-completes the event immediately and the overflowing line begins
      the next event (split rather than grow unbounded). A single line larger
      than ``max_event_bytes`` is emitted as its own singleton event.
    - Order-driven only; no clock involvement. Deterministic per input.
    """

    __slots__ = ("_rules", "_max_lines", "_max_bytes", "_parts", "_encoded")

    def __init__(
        self,
        rules: list[ContinuationRule] | None = None,
        max_event_lines: int = 512,
        max_event_bytes: int = 262144,
    ) -> None:
        if max_event_lines < 1:
            raise ValueError("max_event_lines must be >= 1")
        if max_event_bytes < 1:
            raise ValueError("max_event_bytes must be >= 1")
        self._rules = default_rules() if rules is None else list(rules)
        self._max_lines = max_event_lines
        self._max_bytes = max_event_bytes
        self._parts: list[str] = []
        self._encoded = 0

    def feed(self, line: str) -> list[str]:
        """Feed one raw line; returns 0..1 completed event texts."""
        completed: list[str] = []
        encoded = len(line.encode("utf-8", "replace"))
        if any(rule.matches(line) for rule in self._rules):
            if self._parts and (
                len(self._parts) + 1 > self._max_lines
                or self._encoded + encoded + len(self._parts) > self._max_bytes
            ):
                completed.append(self._take())
        elif self._parts:
            completed.append(self._take())
        self._parts.append(line)
        self._encoded += encoded
        return completed

    def flush(self) -> list[str]:
        """At EOF: emit an unterminated tail as one event, exactly once."""
        if not self._parts:
            return []
        return [self._take()]

    def _take(self) -> str:
        text = "\n".join(self._parts)
        self._parts.clear()
        self._encoded = 0
        return text

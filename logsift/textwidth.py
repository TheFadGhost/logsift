"""Display-width-aware text handling. All truncation/padding goes through here."""

from __future__ import annotations

import re
import sys

_ZERO_WIDTH = re.compile(
    "[\u0300-\u036f\u0483-\u0489\u0591-\u05bd\u064b-\u065f\u06d6-\u06dc"
    "\u200b-\u200f\u2060-\u2064\ufeff]"
)

_WIDE_RANGES = (
    (0x1100, 0x115F),
    (0x2E80, 0x303E),
    (0x3041, 0x33FF),
    (0x3400, 0x4DBF),
    (0x4E00, 0x9FFF),
    (0xA000, 0xA4CF),
    (0xAC00, 0xD7A3),
    (0xF900, 0xFAFF),
    (0xFE10, 0xFE19),
    (0xFE30, 0xFE6F),
    (0xFF00, 0xFF60),
    (0xFFE0, 0xFFE6),
    (0x1F300, 0x1F64F),
    (0x1F900, 0x1F9FF),
    (0x20000, 0x2FFFD),
    (0x30000, 0x3FFFD),
)

_CONTROL_ESCAPES = {
    "\n": "\\n",
    "\r": "\\r",
    "\t": "    ",
}


def char_width(ch: str) -> int:
    cp = ord(ch)
    if cp == 0:
        return 0
    if 0x0300 <= cp <= 0x036F or cp in (0x200B, 0x200C, 0x200D, 0xFEFF):
        return 0
    for lo, hi in _WIDE_RANGES:
        if lo <= cp <= hi:
            return 2
    return 1


def display_width(text: str) -> int:
    text = _ZERO_WIDTH.sub("", text)
    total = 0
    for ch in text:
        total += char_width(ch)
    return total


def sanitize_for_display(text: str) -> str:
    out: list[str] = []
    for ch in text:
        cat = _CONTROL_ESCAPES.get(ch)
        if cat is not None:
            out.append(cat)
            continue
        cp = ord(ch)
        if cp < 0x20 or cp == 0x7F or 0x80 <= cp <= 0x9F:
            out.append(f"\\x{cp:02x}")
        else:
            out.append(ch)
    return "".join(out)


def truncate_middle(text: str, max_width: int) -> str:
    """Truncate to display width keeping head and tail, joined by `...`."""
    if max_width <= 3:
        return text[:max_width]
    if display_width(text) <= max_width:
        return text
    ellipsis = "..."
    budget = max_width - len(ellipsis)
    head_budget = (budget * 3) // 10
    tail_budget = budget - head_budget
    head = _fit_prefix(text, head_budget)
    tail = _fit_suffix(text, tail_budget)
    return f"{head}{ellipsis}{tail}"


def truncate_end(text: str, max_width: int) -> str:
    if display_width(text) <= max_width:
        return text
    if max_width <= 1:
        return _fit_prefix(text, max_width)
    return _fit_prefix(text, max_width - 1) + ">"


def _fit_prefix(text: str, width: int) -> str:
    acc = 0
    for i, ch in enumerate(text):
        w = char_width(ch)
        if acc + w > width:
            return text[:i]
        acc += w
    return text


def _fit_suffix(text: str, width: int) -> str:
    acc = 0
    out: list[str] = []
    for ch in reversed(text):
        w = char_width(ch)
        if acc + w > width:
            break
        out.append(ch)
        acc += w
    return "".join(reversed(out))


def pad_to(text: str, width: int) -> str:
    gap = width - display_width(text)
    return text + " " * gap if gap > 0 else text


def rjust_width(text: str, width: int) -> str:
    gap = width - display_width(text)
    return " " * gap + text if gap > 0 else text


def strip_ansi_len(text: str) -> int:
    plain = ANSI_RE.sub("", text)
    return display_width(plain)


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def eprint(*args) -> None:  # pragma: no cover
    print(*args, file=sys.stderr)

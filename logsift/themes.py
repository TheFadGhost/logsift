"""Semantic colour tokens, four themes, capability detection.

Rendering code never writes raw SGR codes; it asks a Theme for a token.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass

from .events import Severity


class Token:
    NORMAL = "normal"
    ELEVATED = "elevated"
    ANOMALOUS = "anomalous"
    CRITICAL = "critical"
    DIM = "dim"
    BORDER = "border"
    ACCENT = "accent"


TOKENS = (
    Token.NORMAL,
    Token.ELEVATED,
    Token.ANOMALOUS,
    Token.CRITICAL,
    Token.DIM,
    Token.BORDER,
    Token.ACCENT,
)

SEVERITY_TOKEN = {
    Severity.NORMAL: Token.NORMAL,
    Severity.ELEVATED: Token.ELEVATED,
    Severity.ANOMALOUS: Token.ANOMALOUS,
    Severity.CRITICAL: Token.CRITICAL,
}


class Mode:
    OFF = "off"
    COLOR16 = "color16"
    TRUECOLOR = "truecolor"


# token -> (r, g, b)
_PALETTES_TRUECOLOR = {
    "dark": {
        Token.NORMAL: (201, 209, 217),
        Token.ELEVATED: (210, 153, 34),
        Token.ANOMALOUS: (244, 111, 61),
        Token.CRITICAL: (248, 81, 73),
        Token.DIM: (110, 118, 129),
        Token.BORDER: (48, 54, 61),
        Token.ACCENT: (121, 192, 255),
    },
    "light": {
        Token.NORMAL: (36, 41, 47),
        Token.ELEVATED: (154, 103, 0),
        Token.ANOMALOUS: (188, 76, 0),
        Token.CRITICAL: (207, 34, 46),
        Token.DIM: (110, 119, 129),
        Token.BORDER: (208, 215, 222),
        Token.ACCENT: (9, 105, 218),
    },
    # Blue/orange ramp on the preserved blue-yellow axis; luminance-separated.
    "high_contrast": {
        Token.NORMAL: (158, 173, 189),
        Token.ELEVATED: (232, 197, 71),
        Token.ANOMALOUS: (255, 140, 66),
        Token.CRITICAL: (255, 255, 255),
        Token.DIM: (108, 122, 137),
        Token.BORDER: (62, 74, 87),
        Token.ACCENT: (102, 178, 255),
    },
}

# token -> 16-colour ANSI fg code (30-37 / 90-97); critical adds bold+red bg
_PALETTES_16 = {
    "dark": {
        Token.NORMAL: 37,
        Token.ELEVATED: 93,
        Token.ANOMALOUS: 91,
        Token.CRITICAL: 97,
        Token.DIM: 90,
        Token.BORDER: 90,
        Token.ACCENT: 96,
    },
    "light": {
        Token.NORMAL: 30,
        Token.ELEVATED: 33,
        Token.ANOMALOUS: 31,
        Token.CRITICAL: 91,
        Token.DIM: 90,
        Token.BORDER: 37,
        Token.ACCENT: 34,
    },
    "high_contrast": {
        Token.NORMAL: 37,
        Token.ELEVATED: 93,
        Token.ANOMALOUS: 91,
        Token.CRITICAL: 97,
        Token.DIM: 90,
        Token.BORDER: 90,
        Token.ACCENT: 96,
    },
}

THEMES = ("dark", "light", "high_contrast", "term16")


@dataclass(frozen=True)
class Theme:
    name: str
    mode: str

    def style(self, token: str) -> str:
        if self.mode == Mode.OFF:
            return ""
        if self.name == "term16" or self.mode == Mode.COLOR16:
            return _style16(token, self.name if self.name != "term16" else "dark")
        rgb = _PALETTES_TRUECOLOR[self.name][token]
        if token == Token.CRITICAL:
            return f"\x1b[1m\x1b[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"
        return f"\x1b[38;2;{rgb[0]};{rgb[1]};{rgb[2]}m"

    def reset(self) -> str:
        return "\x1b[0m" if self.mode != Mode.OFF else ""

    def paint(self, token: str, text: str) -> str:
        return f"{self.style(token)}{text}{self.reset()}"


def _style16(token: str, palette_name: str) -> str:
    code = _PALETTES_16[palette_name][token]
    prefix = "1;" if token == Token.CRITICAL else ""
    return f"\x1b[{prefix}{code}m"


def detect_mode(stream=None, env: dict[str, str] | None = None) -> str:
    env = dict(os.environ if env is None else env)
    stream = sys.stdout if stream is None else stream
    if env.get("NO_COLOR"):
        return Mode.OFF
    if env.get("TERM") == "dumb":
        return Mode.OFF
    if not hasattr(stream, "isatty") or not stream.isatty():
        return Mode.OFF
    colorterm = env.get("COLORTERM", "")
    if colorterm in ("truecolor", "24bit"):
        return Mode.TRUECOLOR
    term = env.get("TERM", "")
    if "256color" in term or os.name == "nt":
        return Mode.TRUECOLOR
    return Mode.COLOR16


def get_theme(name: str = "dark", mode: str | None = None, stream=None) -> Theme:
    if name not in THEMES:
        raise ValueError(
            f"unknown theme {name!r}; expected one of {', '.join(THEMES)}"
        )
    resolved_mode = detect_mode(stream=stream) if mode is None else mode
    return Theme(name=name, mode=resolved_mode)


def severity_token(sev: Severity) -> str:
    return SEVERITY_TOKEN[sev]

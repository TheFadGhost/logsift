"""Theme accessibility: deuteranopia simulation, 16-colour mapping, NO_COLOR."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logsift.events import Severity
from logsift.themes import (
    _PALETTES_16,
    _PALETTES_TRUECOLOR,
    Mode,
    Token,
    detect_mode,
    get_theme,
    severity_token,
)


def _srgb_to_lin(c: float) -> float:
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _rgb_to_lab(rgb: tuple[int, int, int]):
    r, g, b = [_srgb_to_lin(v / 255.0) for v in rgb]

    def f(t: float) -> float:
        return t ** (1 / 3) if t > 0.008856 else 7.787 * t + 16 / 116

    x = f(0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.9505
    y = f(0.2126 * r + 0.7152 * g + 0.0722 * b)
    z = f(0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.089
    return (116 * y - 16, 500 * (x - y), 200 * (y - z))


def _lab_dist(a, b) -> float:
    return sum((x - y) ** 2 for x, y in zip(a, b)) ** 0.5


def _deutan_project(rgb: tuple[int, int, int]) -> tuple[int, int, int]:
    """Vienot-style deuteranopia simulation via LMS reduction."""
    r, g, b = [v / 255.0 for v in rgb]
    l = 0.31399 * r + 0.63947 * g + 0.04654 * b
    m = 0.15537 * r + 0.75789 * g + 0.08670 * b
    s = 0.01775 * r + 0.10944 * g + 0.87262 * b
    # Remove M-cone response, rebuild from L and S.
    l_new = 0.0 * l + 1.0 * m + 0.0 * s
    m_new = m
    s_new = s
    rr = 5.47221206 * l_new - 4.6419601 * m_new + 0.16963708 * s_new
    gg = -1.12524190 * l_new + 2.29317094 * m_new - 0.16789520 * s_new
    bb = 0.02980165 * l_new - 0.19318073 * m_new + 1.16364776 * s_new
    return (
        max(0, min(255, round(rr * 255))),
        max(0, min(255, round(gg * 255))),
        max(0, min(255, round(bb * 255))),
    )


def test_high_contrast_severities_survive_deuteranopia():
    palette = _PALETTES_TRUECOLOR["high_contrast"]
    severities = [
        palette[severity_token(sev)] for sev in
        (Severity.NORMAL, Severity.ELEVATED, Severity.ANOMALOUS, Severity.CRITICAL)
    ]
    simulated = [_deutan_project(rgb) for rgb in severities]
    labs = [_rgb_to_lab(rgb) for rgb in simulated]
    floor = 18.0
    for i in range(len(labs)):
        for j in range(i + 1, len(labs)):
            d = _lab_dist(labs[i], labs[j])
            assert d >= floor, (
                f"severity {i} vs {j} too close under deuteranopia: dE={d:.1f}"
            )


def test_all_themes_define_every_token():
    all_tokens = (
        Token.NORMAL, Token.ELEVATED, Token.ANOMALOUS, Token.CRITICAL,
        Token.DIM, Token.BORDER, Token.ACCENT,
    )
    for theme_name in ("dark", "light", "high_contrast"):
        for token in all_tokens:
            assert token in _PALETTES_TRUECOLOR[theme_name]
            assert token in _PALETTES_16.get(theme_name, _PALETTES_16["dark"])


def test_theme_paint_modes():
    dark = get_theme("dark", mode=Mode.TRUECOLOR)
    painted = dark.paint(Token.CRITICAL, "!!")
    assert painted.startswith("\x1b[") and "38;2;" in painted
    term16 = get_theme("dark", mode=Mode.COLOR16)
    p16 = term16.paint(Token.ELEVATED, "+")
    assert ";5;" not in p16 and "38;2;" not in p16
    off = get_theme("dark", mode=Mode.OFF)
    assert off.paint(Token.ANOMALOUS, "!") == "!"


def test_no_color_env_disables_colour():
    assert detect_mode(env={"NO_COLOR": "1"}, stream=_FakeTTY()) == Mode.OFF


def test_non_tty_stream_disables_colour():
    import io

    assert detect_mode(stream=io.StringIO()) == Mode.OFF


class _FakeTTY:
    def isatty(self) -> bool:
        return True

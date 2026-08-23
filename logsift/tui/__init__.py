"""Logsift TUI: flicker-free diff-rendered terminal interface."""

from .app import Actions, TuiApp
from .input import InputReader
from .renderer import (
    Frame,
    FrameRenderer,
    DiffRenderer,
    alt_enter,
    alt_exit,
    clear_screen,
    cursor_hide,
    cursor_show,
    enable_windows_vt,
    fmt_count,
    fmt_duration,
    fmt_pct,
    fmt_rate,
    hbar,
    render_template,
    restore_windows_vt,
    sparkline,
    sparkline_with_stats,
)

__all__ = [
    "Actions",
    "DiffRenderer",
    "Frame",
    "FrameRenderer",
    "InputReader",
    "TuiApp",
    "alt_enter",
    "alt_exit",
    "clear_screen",
    "cursor_hide",
    "cursor_show",
    "enable_windows_vt",
    "fmt_count",
    "fmt_duration",
    "fmt_pct",
    "fmt_rate",
    "hbar",
    "render_template",
    "restore_windows_vt",
    "sparkline",
    "sparkline_with_stats",
]

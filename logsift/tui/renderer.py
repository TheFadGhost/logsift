"""Frame building, layout, and diff emission for the Logsift TUI.

FrameRenderer builds whole-screen frames (rows of styled segments) from
immutable Snapshot objects. DiffRenderer emits only changed rows via cursor
positioning. No raw SGR codes outside theme.paint/style; no system clock.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone

from ..events import DETECTORS, Alert
from ..snapshot import Snapshot
from ..textwidth import (
    char_width,
    display_width,
    rjust_width,
    sanitize_for_display,
    strip_ansi_len,
    truncate_end,
    truncate_middle,
)
from ..themes import Mode, Theme, Token, severity_token
from ..textwidth import ANSI_RE

COUNT_W = 7
RATE_W = 11
PCT_W = 7
DUR_W = 7
SLOT_MAX_W = 24
MAX_FPS = 10.0

BOX_TL, BOX_TR, BOX_BL, BOX_BR = "\u250c", "\u2510", "\u2514", "\u2518"
BOX_H, BOX_V = "\u2500", "\u2502"
BLOCKS_V = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"
EIGHTHS = "\u258f\u258e\u258d\u258c\u258b\u258a\u2589"
FULL_BLOCK = "\u2588"

SEV_WORD_W = 9
DET_W = 16
TID_W = 4
TIME_W = 8

ALT_ENTER = "\x1b[?1049h"
ALT_EXIT = "\x1b[?1049l"
CURSOR_HIDE = "\x1b[?25l"
CURSOR_SHOW = "\x1b[?25h"
CLEAR_SCREEN = "\x1b[2J"
CLEAR_EOL = "\x1b[K"

_STD_OUTPUT_HANDLE = -11
_ENABLE_VT = 0x0004
_saved_console_mode: int | None = None


def goto(row: int, col: int = 1) -> str:
    return f"\x1b[{row};{col}H"


def alt_enter() -> str:
    return ALT_ENTER + CLEAR_SCREEN + CURSOR_HIDE


def alt_exit() -> str:
    return CURSOR_SHOW + ALT_EXIT


def clear_screen() -> str:
    return CLEAR_SCREEN


def cursor_hide() -> str:
    return CURSOR_HIDE


def cursor_show() -> str:
    return CURSOR_SHOW


def enable_windows_vt() -> bool:
    """Enable VT processing on the Windows console. Returns success."""
    global _saved_console_mode
    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(_STD_OUTPUT_HANDLE)
        if not handle or handle == -1:
            return False
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        _saved_console_mode = mode.value
        return bool(kernel32.SetConsoleMode(handle, mode.value | _ENABLE_VT))
    except Exception:
        return False


def restore_windows_vt() -> bool:
    """Restore the console mode saved by enable_windows_vt, if any."""
    global _saved_console_mode
    if os.name != "nt" or _saved_console_mode is None:
        return False
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(_STD_OUTPUT_HANDLE)
        if not handle or handle == -1:
            return False
        return bool(kernel32.SetConsoleMode(handle, _saved_console_mode))
    except Exception:
        return False
    finally:
        _saved_console_mode = None


def fmt_count(value: float) -> str:
    v = max(0.0, float(value))
    if v < 10_000:
        return f"{v:.0f}"
    if v < 10_000_000:
        s = f"{v / 1e3:.1f}k"
        if display_width(s) <= COUNT_W:
            return s
    s = f"{v / 1e6:.2f}M"
    if display_width(s) <= COUNT_W:
        return s
    return truncate_end(f"{v / 1e9:.2f}G", COUNT_W)


def fmt_rate(lps: float) -> str:
    core = fmt_count(lps)
    out = f"{core} l/s"
    if display_width(out) > RATE_W:
        out = truncate_end(core, RATE_W - 4) + " l/s"
    return out


def fmt_pct(pct: float) -> str:
    v = max(0.0, float(pct))
    s = f"{v:.1f}%"
    if display_width(s) > PCT_W:
        s = truncate_end(f"{v:.0f}%", PCT_W)
    return s


def fmt_duration(seconds: float) -> str:
    s = max(0.0, float(seconds))
    if s < 1.0:
        if s < 0.001:
            us = s * 1e6
            out = f"{us:.0f}us"
            return out if display_width(out) <= DUR_W else "9999us"
        ms = s * 1e3
        out = f"{ms:.1f}ms"
        if display_width(out) <= DUR_W:
            return out
    if s < 1000.0:
        out = f"{s:.2f}s"
        if display_width(out) <= DUR_W:
            return out
    mins = int(s // 60)
    secs = int(s % 60)
    if mins > 9999:
        mins, secs = 9999, 59
    out = f"{mins}:{secs:02d}"
    if display_width(out) <= DUR_W:
        return out
    return truncate_end(f"{s / 3600.0:.1f}h", DUR_W)


def sparkline(values: "tuple[int, ...] | list[int]", cells: int) -> str:
    vals = [max(0, int(v)) for v in values]
    if cells <= 0:
        return ""
    vals = vals[-cells:]
    vmax = max(vals) if vals else 0
    out: list[str] = []
    for v in vals:
        if vmax <= 0 or v <= 0:
            out.append(" ")
            continue
        level = min(8, max(1, int(v * 8 / vmax + 0.5)))
        out.append(BLOCKS_V[level - 1])
    return "".join(out)


def sparkline_with_stats(values: "tuple[int, ...] | list[int]", cells: int) -> str:
    bars = sparkline(values, cells)
    vmin = min(values) if values else 0
    vmax = max(values) if values else 0
    return f"{bars} min {vmin} max {vmax}"


def hbar(value: float, max_value: float, width: int) -> str:
    if width <= 0:
        return ""
    frac = 0.0 if max_value <= 0 else max(0.0, min(1.0, value / max_value))
    eighths = int(frac * width * 8 + 0.5)
    full = min(width, eighths // 8)
    rem = eighths % 8 if full < width else 0
    out = FULL_BLOCK * full
    if rem > 0:
        out += EIGHTHS[rem - 1]
    return out


def split_template_slots(text: str) -> list[tuple[str, bool]]:
    parts: list[tuple[str, bool]] = []
    rest = text
    while True:
        idx = rest.find("<*>")
        if idx < 0:
            parts.append((rest, False))
            break
        parts.append((rest[:idx], False))
        parts.append(("<*>", True))
        rest = rest[idx + 3 :]
    return [(t, slot) for t, slot in parts if t or slot]


def render_template(theme: Theme, text: str) -> str:
    out: list[str] = []
    for piece, is_slot in split_template_slots(sanitize_for_display(text)):
        shown = "{*}" if is_slot else piece
        token = Token.ACCENT if is_slot else Token.NORMAL
        out.append(theme.paint(token, shown))
    return "".join(out)


def render_template_clipped(theme: Theme, text: str, budget: int) -> str:
    if budget <= 0:
        return ""
    out: list[str] = []
    used = 0
    for piece, is_slot in split_template_slots(sanitize_for_display(text)):
        shown = "{*}" if is_slot else piece
        pw = display_width(shown)
        if used + pw <= budget:
            token = Token.ACCENT if is_slot else Token.NORMAL
            out.append(theme.paint(token, shown))
            used += pw
            continue
        remaining = budget - used
        if remaining >= 2:
            token = Token.ACCENT if is_slot else Token.NORMAL
            out.append(theme.paint(token, truncate_end(shown, remaining)))
        break
    return "".join(out)


def wrap_hang(text: str, width: int, indent: int = 2, max_lines: int = 2) -> list[str]:
    text = " ".join(sanitize_for_display(text).split())
    if width <= indent + 4 or not text:
        return [truncate_end(text, width)]
    limits = [width] + [width - indent] * (max_lines - 1)
    words = text.split(" ")
    lines: list[str] = []
    for lim in limits:
        cur = ""
        while words and display_width(cur + " " + words[0] if cur else words[0]) <= lim:
            cur = f"{cur} {words.pop(0)}" if cur else words.pop(0)
        if not cur and words:
            cur = truncate_end(words.pop(0), lim)
        lines.append(cur)
        if not words:
            break
    if words:
        lines[-1] = truncate_end(
            lines[-1] + " " + " ".join(words[:2]), limits[min(len(lines), max_lines) - 1]
        )
    return lines


def anatomy_line1(alert: Alert) -> str:
    tid = "-" if alert.template_id is None else f"t{alert.template_id}"
    marker = alert.severity.marker
    word = alert.severity.value
    det = truncate_end(alert.detector, DET_W)
    return f"{marker} {word:<{SEV_WORD_W}} {det:<{DET_W}} {tid:>{TID_W}}"


def anatomy_line2(alert: Alert) -> str:
    thr = f" (thr {alert.threshold_desc})" if alert.threshold_desc else ""
    dev = f" {alert.deviation_desc}" if alert.deviation_desc else ""
    return (
        f"baseline {alert.baseline_desc} -> observed {alert.observed_desc}"
        f"{dev}{thr}"
    )


def clock_hms(epoch: float | None) -> str:
    if epoch is None or epoch <= 0:
        return "--:--:--"
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%H:%M:%S")


@dataclass
class Frame:
    rows: list[str]


class Screen:
    """Cell grid with token per cell; materializes to styled rows of exact width."""

    __slots__ = ("w", "h", "chars", "tokens")

    def __init__(self, cols: int, rows: int) -> None:
        self.w = cols
        self.h = rows
        self.chars: list[list[str]] = [[" "] * cols for _ in range(rows)]
        self.tokens: list[list[str | None]] = [[None] * cols for _ in range(rows)]

    def write(self, x: int, y: int, text: str, token: str | None = None) -> int:
        if y < 0 or y >= self.h or not text:
            return max(0, min(x, self.w))
        col = max(0, x)
        for ch in text:
            cw = char_width(ch)
            if cw == 0:
                continue
            if col + cw > self.w:
                break
            self.chars[y][col] = ch
            self.tokens[y][col] = token
            if cw == 2 and col + 1 < self.w:
                self.chars[y][col + 1] = ""
                self.tokens[y][col + 1] = token
            col += cw
        return col

    def hline(self, x: int, y: int, width: int, token: str | None) -> None:
        if y < 0 or y >= self.h:
            return
        for xx in range(max(0, x), min(x + width, self.w)):
            self.chars[y][xx] = BOX_H
            self.tokens[y][xx] = token

    def box(self, x: int, y: int, w: int, h: int, title: str = "", title_token: str | None = None) -> None:
        if w < 2 or h < 2:
            return
        top, bot = y, y + h - 1
        left, right = x, x + w - 1
        for xx in range(left, right + 1):
            self.chars[top][xx] = BOX_H
            self.tokens[top][xx] = Token.BORDER
            self.chars[bot][xx] = BOX_H
            self.tokens[bot][xx] = Token.BORDER
        for yy in range(top, bot + 1):
            self.chars[yy][left] = BOX_V
            self.tokens[yy][left] = Token.BORDER
            self.chars[yy][right] = BOX_V
            self.tokens[yy][right] = Token.BORDER
        self.chars[top][left], self.tokens[top][left] = BOX_TL, Token.BORDER
        self.chars[top][right], self.tokens[top][right] = BOX_TR, Token.BORDER
        self.chars[bot][left], self.tokens[bot][left] = BOX_BL, Token.BORDER
        self.chars[bot][right], self.tokens[bot][right] = BOX_BR, Token.BORDER
        if title:
            self.write(left + 2, top, f" {title} ", title_token or Token.DIM)

    def materialize(self, theme: Theme) -> list[str]:
        rows: list[str] = []
        for yy in range(self.h):
            parts: list[str] = []
            cur_tok: str | None = None
            buf: list[str] = []
            started = False
            for xx in range(self.w):
                tok = self.tokens[yy][xx]
                ch = self.chars[yy][xx]
                if started and tok == cur_tok:
                    buf.append(ch)
                    continue
                if buf:
                    parts.append(self._emit(theme, cur_tok, "".join(buf)))
                cur_tok = tok
                buf = [ch]
                started = True
            if buf:
                parts.append(self._emit(theme, cur_tok, "".join(buf)))
            rows.append("".join(parts))
        return rows

    @staticmethod
    def _emit(theme: Theme, tok: str | None, text: str) -> str:
        return theme.paint(tok, text) if tok is not None else text


@dataclass
class Layout:
    cls: str
    header_h: int
    body_y: int
    body_h: int
    status_y: int
    templates_rect: tuple[int, int, int, int]
    feed_rect: tuple[int, int, int, int]


class FrameRenderer:
    def __init__(self, theme: Theme) -> None:
        self.theme = theme

    def render(
        self,
        snap: Snapshot | None,
        cols: int,
        rows: int,
        *,
        overlay_open: bool = False,
        focus: str = "feed",
        selected_feed: int = -1,
        selected_template_id: int | None = None,
        disconnected_retries: int | None = None,
        local_paused: bool = False,
    ) -> Frame:
        scr = Screen(cols, rows)
        if snap is None:
            self._draw_waiting(scr, 0, "stdin")
            return Frame(scr.materialize(self.theme))
        if snap.total_events == 0:
            self._draw_waiting(scr, snap.total_events, snap.source_name)
            return Frame(scr.materialize(self.theme))
        if rows < 8 or cols < 24 or rows - (3 if cols >= 80 else 2) - 2 < 4:
            self._draw_too_small(scr)
            return Frame(scr.materialize(self.theme))
        layout = self._layout(cols, rows)
        self._draw_header(scr, snap, layout.header_h)
        self._draw_templates_panel(scr, snap, layout.templates_rect, focus == "templates", selected_template_id)
        self._draw_feed_panel(
            scr, snap, layout.feed_rect, focus == "feed", selected_feed, overlay_open
        )
        self._draw_status(
            scr, snap, layout.status_y, disconnected_retries, local_paused, overlay_open
        )
        if overlay_open:
            self._draw_overlay(scr, snap, focus, selected_feed, selected_template_id)
        return Frame(scr.materialize(self.theme))

    def _layout(self, cols: int, rows: int) -> Layout:
        narrow = cols < 80
        header_h = 2 if narrow else 3
        status_h = 2
        body_y = header_h
        body_h = rows - header_h - status_h
        status_y = rows - status_h
        if cols >= 120:
            left_w = max(20, int(cols * 0.38))
            return Layout(
                "wide", header_h, body_y, body_h, status_y,
                templates_rect=(0, body_y, left_w, body_h),
                feed_rect=(left_w, body_y, cols - left_w, body_h),
            )
        if narrow:
            feed_h = max(3, int(body_h * 0.70))
            tmpl_h = body_h - feed_h
            if tmpl_h < 3:
                return Layout(
                    "narrow", header_h, body_y, body_h, status_y,
                    templates_rect=(0, body_y, cols, 0),
                    feed_rect=(0, body_y, cols, body_h),
                )
            return Layout(
                "narrow", header_h, body_y, body_h, status_y,
                templates_rect=(0, body_y, cols, tmpl_h),
                feed_rect=(0, body_y + tmpl_h, cols, feed_h),
            )
        tmpl_h = max(3, int(body_h * 0.40))
        return Layout(
            "standard", header_h, body_y, body_h, status_y,
            templates_rect=(0, body_y, cols, tmpl_h),
            feed_rect=(0, body_y + tmpl_h, cols, body_h - tmpl_h),
        )

    def _draw_waiting(self, scr: Screen, count: int, source: str) -> None:
        src = truncate_end(sanitize_for_display(source), 16)
        msg = f"waiting for input - {src} ({count} lines received)"
        row = scr.h // 2
        x = max(0, (scr.w - display_width(msg)) // 2)
        scr.write(x, row, msg, Token.DIM)

    def _draw_too_small(self, scr: Screen) -> None:
        msg = "terminal too small"
        x = max(0, (scr.w - len(msg)) // 2)
        scr.write(x, scr.h // 2, msg, Token.DIM)

    def _warm_or_uptime(self, snap: Snapshot) -> tuple[str, str]:
        if snap.warmup_fraction is not None:
            pct = int(round(max(0.0, min(1.0, snap.warmup_fraction)) * 100))
            text = f"baseline warming up {pct}%"
            if snap.warmup_eta_s is not None:
                text += f" (eta {fmt_duration(snap.warmup_eta_s)})"
            return text, Token.ELEVATED
        return f"up {fmt_duration(snap.uptime_s)}", Token.DIM

    def _draw_header(self, scr: Screen, snap: Snapshot, header_h: int) -> None:
        cols = scr.w
        name = truncate_end(sanitize_for_display(snap.source_name), 16)
        x = scr.write(0, 0, "logsift", Token.NORMAL)
        x = scr.write(x + 1, 0, "src", Token.DIM)
        scr.write(x + 1, 0, name, Token.ACCENT)
        right, rtoken = self._warm_or_uptime(snap)
        scr.write(cols - display_width(right), 0, right, rtoken)
        if header_h == 3:
            self._slots_row(scr, 1, snap)
            scr.hline(0, 2, cols, Token.BORDER)
        else:
            self._slots_row_compact(scr, 1, snap)

    def _slots_row(self, scr: Screen, y: int, snap: Snapshot) -> None:
        x = scr.write(0, y, "in", Token.DIM)
        x = scr.write(x + 1, y, rjust_width(fmt_rate(snap.ingest_rate_lps), RATE_W), Token.NORMAL)
        x = scr.write(x + 2, y, "win", Token.DIM)
        x = scr.write(x + 1, y, rjust_width(fmt_rate(snap.window_rate_lps), RATE_W), Token.NORMAL)
        x = scr.write(x + 2, y, "err", Token.DIM)
        x = scr.write(x + 1, y, rjust_width(fmt_pct(snap.error_rate_pct), PCT_W), Token.ELEVATED)
        unparsed = f"{rjust_width(str(snap.unparsed_count), COUNT_W)} ({fmt_pct(snap.unparsed_pct)})"
        x = scr.write(x + 2, y, "unparsed", Token.DIM)
        x = scr.write(x + 1, y, unparsed, Token.NORMAL)
        x = scr.write(x + 2, y, "events", Token.DIM)
        scr.write(x + 1, y, rjust_width(fmt_count(snap.total_events), COUNT_W), Token.NORMAL)

    def _slots_row_compact(self, scr: Screen, y: int, snap: Snapshot) -> None:
        x = scr.write(0, y, "in", Token.DIM)
        x = scr.write(x + 1, y, rjust_width(fmt_rate(snap.ingest_rate_lps), RATE_W), Token.NORMAL)
        x = scr.write(x + 2, y, "err", Token.DIM)
        x = scr.write(x + 1, y, rjust_width(fmt_pct(snap.error_rate_pct), PCT_W), Token.ELEVATED)
        x = scr.write(x + 2, y, "unp", Token.DIM)
        x = scr.write(x + 1, y, rjust_width(str(snap.unparsed_count), COUNT_W), Token.NORMAL)
        x = scr.write(x + 2, y, "ev", Token.DIM)
        scr.write(x + 1, y, rjust_width(fmt_count(snap.total_events), COUNT_W), Token.NORMAL)

    def _draw_templates_panel(
        self,
        scr: Screen,
        snap: Snapshot,
        rect: tuple[int, int, int, int],
        focus_active: bool,
        selected_tid: int | None,
    ) -> None:
        x, y, w, h = rect
        if h < 2 or w < 4:
            return
        scr.box(x, y, w, h, "top templates", Token.DIM)
        self._templates_content(scr, snap, rect, focus_active, selected_tid)

    def _draw_feed_panel(
        self,
        scr: Screen,
        snap: Snapshot,
        rect: tuple[int, int, int, int],
        focus_active: bool,
        selected_feed: int,
        overlay_open: bool,
    ) -> None:
        x, y, w, h = rect
        if h < 2 or w < 4:
            return
        scr.box(x, y, w, h, "anomaly feed", Token.NORMAL if focus_active else Token.DIM)
        self._feed_content(scr, snap, rect, focus_active, selected_feed, overlay_open)

    def _templates_content(
        self,
        scr: Screen,
        snap: Snapshot,
        rect: tuple[int, int, int, int],
        focus_active: bool,
        selected_tid: int | None,
    ) -> None:
        x, y, w, h = rect
        if h < 3:
            return
        inner_w = w - 4
        items = sorted(snap.top_templates, key=lambda t: (-t.count, t.template_id))
        vmax = max((t.count for t in items), default=0)
        bar_w = max(3, min(12, inner_w // 4)) if inner_w >= 30 else 0
        fixed = 1 + 1 + 5 + 1 + COUNT_W + 1 + PCT_W + 1
        tmpl_w = max(6, inner_w - fixed - bar_w - 1)
        row = y + 1
        for item in items[: h - 2]:
            sel = focus_active and selected_tid is not None and item.template_id == selected_tid
            cx = scr.write(x + 2, row, ">" if sel else " ", Token.ACCENT)
            cx = scr.write(cx + 1, row, rjust_width(f"t{item.template_id}", 5), Token.DIM)
            cx = scr.write(cx + 1, row, rjust_width(fmt_count(item.count), COUNT_W), Token.NORMAL)
            cx = scr.write(cx + 1, row, rjust_width(fmt_pct(item.share * 100), PCT_W), Token.DIM)
            cx += 1
            if bar_w:
                cx = scr.write(cx, row, hbar(item.count, vmax, bar_w), Token.NORMAL)
                cx += 1
            scr.write(cx, row, render_template_clipped(self.theme, item.text, tmpl_w))
            row += 1
        if not items:
            scr.write(x + 2, row, "no templates yet", Token.DIM)

    def _feed_content(
        self,
        scr: Screen,
        snap: Snapshot,
        rect: tuple[int, int, int, int],
        focus_active: bool,
        selected_feed: int,
        overlay_open: bool,
    ) -> None:
        x, y, w, h = rect
        inner_w = w - 4
        if snap.paused or snap.source_state == "paused":
            note = "paused - press p to resume"
            scr.write(x + 2, y + 1, note, Token.ELEVATED)
            return
        if snap.warmup_fraction is not None:
            scr.write(x + 2, y + 1, "detectors suppressed until warm-up completes", Token.DIM)
            return
        alerts: tuple[Alert, ...] = tuple(reversed(snap.alerts))
        if not alerts:
            msg = "no anomalies - stream looked normal"
            scr.write(x + 2, y + 1, msg, Token.DIM)
            return
        prefix_w = 1 + 1 + SEV_WORD_W + 1 + DET_W + 1 + TID_W + 1
        tmpl_w = max(6, inner_w - prefix_w - TIME_W - 1)
        row = y + 1
        bottom = y + h - 1
        for idx, alert in enumerate(alerts):
            if row + 1 > bottom:
                break
            sel = focus_active and not overlay_open and idx == selected_feed
            head = ">" if sel else " "
            l1 = anatomy_line1(alert)
            tid = "-" if alert.template_id is None else f"t{alert.template_id}"
            sev_tok = severity_token(alert.severity)
            cx = scr.write(x + 1, row, head + " ", Token.ACCENT if sel else Token.DIM)
            cx = scr.write(
                cx, row, f"{alert.severity.marker} {alert.severity.value:<{SEV_WORD_W}}", sev_tok
            )
            cx = scr.write(cx + 1, row, truncate_end(alert.detector, DET_W).ljust(DET_W), Token.DIM)
            cx = scr.write(cx + 1, row, rjust_width(tid, TID_W), Token.DIM)
            cx += 1
            cx = scr.write(cx, row, render_template_clipped(self.theme, alert.template_text, tmpl_w))
            when = clock_hms(alert.event_time or alert.window_end)
            scr.write(x + 1 + inner_w - TIME_W, row, rjust_width(when, TIME_W), Token.DIM)
            row += 1
            for line in wrap_hang(anatomy_line2(alert), inner_w - 2)[:2]:
                if row > bottom:
                    break
                scr.write(x + 3, row, line, Token.DIM)
                row += 1

    def _state_word(self, state: str, retries: int | None) -> tuple[str, str]:
        if state == "disconnected":
            suffix = "" if retries is None else f" - retry {retries}"
            return "disconnected" + suffix, Token.CRITICAL
        if state == "eof":
            return "eof", Token.DIM
        if state in ("paused",):
            return "paused", Token.ELEVATED
        if state == "no_data":
            return "no data", Token.ELEVATED
        return "connected", Token.NORMAL

    def _draw_status(
        self,
        scr: Screen,
        snap: Snapshot,
        status_y: int,
        retries: int | None,
        local_paused: bool,
        overlay_open: bool,
    ) -> None:
        cols = scr.w
        hints = "tab panels / enter detail / p pause / q quit"
        hw = display_width(hints)
        scr.write(cols - hw - 1, status_y, hints, Token.DIM)
        state = snap.source_state
        word, tok = self._state_word(state, retries)
        x = scr.write(1, status_y, word, tok)
        dets = " ".join(DETECTORS)
        dw = display_width(dets)
        dx = max(x + 2, (cols - hw - 1 - dw) // 2)
        if dx + dw <= cols - hw - 1:
            scr.write(dx, status_y, dets, Token.DIM)
        notes_y = status_y + 1
        paused_now = snap.paused or local_paused or state == "paused"
        if paused_now:
            x = scr.write(1, notes_y, "paused - press p to resume", Token.ELEVATED)
        if state == "no_data":
            x = scr.write(x + 2 if paused_now else 1, notes_y, "no data - check source", Token.ELEVATED)
        if overlay_open:
            scr.write(cols - hw - 1, notes_y, "esc close detail", Token.DIM)

    def _detail_alert(self, snap: Snapshot, focus: str, selected_feed: int, selected_tid: int | None) -> Alert | None:
        alerts: tuple[Alert, ...] = tuple(reversed(snap.alerts))
        if focus != "feed" and selected_tid is not None:
            for a in alerts:
                if a.template_id == selected_tid:
                    return a
        if focus == "feed" and 0 <= selected_feed < len(alerts):
            return alerts[selected_feed]
        return alerts[0] if alerts else None

    def _draw_overlay(
        self,
        scr: Screen,
        snap: Snapshot,
        focus: str,
        selected_feed: int,
        selected_tid: int | None,
    ) -> None:
        cols, rows = scr.w, scr.h
        ow = max(40, int(cols * 0.80))
        oh = max(10, int(rows * 0.80))
        ow = min(ow, cols)
        oh = min(oh, rows)
        ox = (cols - ow) // 2
        oy = (rows - oh) // 2
        for yy in range(oy, oy + oh):
            for xx in range(ox, ox + ow):
                scr.chars[yy][xx] = " "
                scr.tokens[yy][xx] = None
        alert = self._detail_alert(snap, focus, selected_feed, selected_tid)
        title = "detail"
        if alert is not None:
            tid = "-" if alert.template_id is None else f"t{alert.template_id}"
            title = f"detail {tid} {alert.severity.value}"
        scr.box(ox, oy, ow, oh, title, Token.ACCENT)
        inner_w = ow - 4
        row = oy + 1
        bottom = oy + oh - 2
        if alert is None:
            scr.write(ox + 2, row, "no selection available", Token.DIM)
            return
        sev_tok = severity_token(alert.severity)
        cx = scr.write(
            ox + 2,
            row,
            f"{alert.severity.marker} {alert.severity.value}",
            sev_tok,
        )
        cx = scr.write(cx + 1, row, f"[{alert.detector}]", Token.DIM)
        scr.write(cx + 1, row, render_template_clipped(self.theme, alert.template_text, inner_w - (cx - ox + 3)), Token.NORMAL)
        row += 1
        for line in wrap_hang(anatomy_line2(alert), inner_w, max_lines=3):
            if row > bottom:
                break
            scr.write(ox + 3, row, line, Token.DIM)
            row += 1
        if alert.threshold_desc and row <= bottom:
            scr.write(ox + 3, row, f"threshold {alert.threshold_desc}", Token.NORMAL)
            row += 1
        if row <= bottom:
            ws = datetime.fromtimestamp(alert.window_start, tz=timezone.utc).strftime("%H:%M:%S")
            we = datetime.fromtimestamp(alert.window_end, tz=timezone.utc).strftime("%H:%M:%S")
            scr.write(ox + 3, row, f"window {ws} .. {we}  count {alert.count} suppressed {alert.suppressed}", Token.NORMAL)
            row += 1
        if row < bottom:
            scr.hline(ox + 2, row, inner_w, Token.BORDER)
            row += 1
        history = snap.selected_template_history
        if row <= bottom:
            label = "history"
            cells = max(6, inner_w - 24)
            if history:
                text = sparkline_with_stats(history, cells)
                scr.write(ox + 2, row, label, Token.DIM)
                scr.write(ox + 11, row, text[: inner_w - 10], Token.NORMAL)
            else:
                scr.write(ox + 2, row, f"{label} unavailable", Token.DIM)
            row += 1
        examples = snap.selected_template_examples or tuple(alert.examples) or ()
        if examples and row <= bottom:
            scr.write(ox + 2, row, "examples", Token.DIM)
            row += 1
            for ex in examples[:3]:
                if row > bottom:
                    break
                scr.write(ox + 4, row, truncate_middle(sanitize_for_display(ex), inner_w - 4), Token.NORMAL)
                row += 1
        context = tuple(alert.evidence_before)[:2]
        if context and row <= bottom:
            scr.write(ox + 2, row, "context", Token.DIM)
            row += 1
            for c in context:
                if row > bottom:
                    break
                scr.write(ox + 4, row, truncate_middle(sanitize_for_display(c), inner_w - 4), Token.DIM)
                row += 1
        hint = "esc close"
        scr.write(ox + ow - 2 - len(hint), oy + oh - 2, hint, Token.DIM)


class DiffRenderer:
    """Emits only changed rows; full repaint on invalidate().

    When the active theme runs with colour off (NO_COLOR, non-TTY), output
    degrades to completely escape-free plain text: rows joined by newlines.
    """

    def __init__(self, theme=None) -> None:
        self._theme = theme
        self._prev: list[str] | None = None
        self._force = True

    def invalidate(self) -> None:
        self._force = True

    @property
    def needs_full_repaint(self) -> bool:
        return self._force

    def emit(self, frame: Frame) -> str:
        rows = frame.rows
        if self._theme is not None and getattr(self._theme, "mode", None) == Mode.OFF:
            self._prev = list(rows)
            self._force = False
            plain = [ANSI_RE.sub("", row) for row in rows]
            return "\n".join(plain)
        out: list[str] = []
        prev = None if self._force else self._prev
        if prev is None or len(prev) != len(rows):
            out.append(CLEAR_SCREEN)
            for i, row in enumerate(rows):
                out.append(goto(i + 1))
                out.append(row)
                out.append(CLEAR_EOL)
        else:
            for i, row in enumerate(rows):
                old = prev[i]
                if old == row:
                    continue
                out.append(goto(i + 1))
                out.append(row)
                if strip_ansi_len(row) < strip_ansi_len(old):
                    out.append(CLEAR_EOL)
        self._prev = list(rows)
        self._force = False
        return "".join(out)


def feed_order(snap: Snapshot) -> tuple[Alert, ...]:
    return tuple(reversed(snap.alerts))

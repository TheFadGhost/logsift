"""Headless TUI tests: diffing, layout stability, fixed slots, states, bans."""

from __future__ import annotations

import io
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logsift.clock import FakeClock
from logsift.events import Alert, Severity
from logsift.snapshot import Snapshot, SnapshotProvider, TemplateSummary
from logsift.textwidth import ANSI_RE, display_width, rjust_width, strip_ansi_len
from logsift.themes import Mode, Theme, get_theme
from logsift.tui.app import TuiApp
from logsift.tui.renderer import (
    COUNT_W,
    DiffRenderer,
    Frame,
    FrameRenderer,
    fmt_count,
    fmt_duration,
    fmt_pct,
    fmt_rate,
)

COLS, ROWS = 120, 30

EMOJI_RE = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF\u2b00-\u2bff]"
)
POS_RE = re.compile(r"\x1b\[\d+;1H")


def off_theme() -> Theme:
    return Theme(name="dark", mode=Mode.OFF)


def mk_alert(sev: Severity = Severity.ANOMALOUS, tid: int = 42, **over) -> Alert:
    fields = dict(
        detector="volume",
        severity=sev,
        template_id=tid,
        template_text="user <*> login failed",
        baseline_desc="12/hr (slot Mon 03:00, n=26)",
        baseline_value=12.0,
        observed_desc="310/hr",
        observed_value=310.0,
        deviation_desc="25.8x",
        z=14.2,
        threshold_desc="z > 6",
        threshold_value=6.0,
        window_start=100.0,
        window_end=160.0,
        group_key=f"volume:t{tid}",
        event_time=157.0,
        examples=["Aug 22 03:13:58 user 4821 login failed"],
        evidence_before=["Aug 22 03:13:57 service started"],
    )
    fields.update(over)
    return Alert(**fields)


def mk_snap(**over) -> Snapshot:
    templates = (
        TemplateSummary(42, "user <*> login failed", 310, 5.2, 0.0, 0.61),
        TemplateSummary(7, "GET /api/orders <*> <*>", 120, 2.0, 0.0, 0.24),
        TemplateSummary(9, "payment <*> settled in <*>", 60, 1.0, 0.0, 0.12),
    )
    alerts = (mk_alert(Severity.ANOMALOUS, 42),)
    fields = dict(
        generated_mono=10.0,
        uptime_s=125.0,
        source_name="stdin",
        source_state="connected",
        ingest_rate_lps=120.4,
        window_rate_lps=90.2,
        error_rate_pct=1.2,
        unparsed_pct=0.4,
        unparsed_count=3,
        total_events=5000,
        warmup_fraction=None,
        warmup_eta_s=None,
        paused=False,
        top_templates=templates,
        alerts=alerts,
        volume_series=(3, 8, 2, 310, 40),
        selected_template_history=(1, 2, 3, 8, 5),
        selected_template_examples=("user 4821 login failed",),
    )
    fields.update(over)
    return Snapshot(**fields)


def render(snap, theme=None, cols=COLS, rows=ROWS, **kw):
    fr = FrameRenderer(theme if theme is not None else off_theme())
    return fr.render(snap, cols, rows, **kw)


def plain(frame) -> str:
    return ANSI_RE.sub("", "\n".join(frame.rows))


def plain_rows(frame) -> list[str]:
    return [ANSI_RE.sub("", r) for r in frame.rows]


class TestDiffRendering:
    def test_identical_snapshots_produce_no_row_rewrites(self):
        snap = mk_snap()
        f1 = render(snap)
        f2 = render(snap)
        diff = DiffRenderer()
        first = diff.emit(f1)
        assert first != ""
        second = diff.emit(f2)
        assert POS_RE.search(second) is None
        assert second == ""

    def test_changed_number_rewrites_exactly_one_row(self):
        s1 = mk_snap(total_events=5000)
        s2 = mk_snap(total_events=5042)
        f1 = render(s1)
        f2 = render(s2)
        diff = DiffRenderer()
        diff.emit(f1)
        out = diff.emit(f2)
        hits = POS_RE.findall(out)
        assert len(hits) == 1
        assert "5042" in ANSI_RE.sub("", out)

    def test_shorter_row_gets_clear_to_eol(self):
        fr = FrameRenderer(off_theme())
        wide = Frame(["a" * 30])
        narrow = Frame(["a" * 10])
        diff = DiffRenderer()
        diff.emit(wide)
        out = diff.emit(narrow)
        assert "\x1b[K" in out


class TestLayoutStability:
    def test_constant_width_across_volatile_values(self):
        sizes = [(120, 30), (119, 28), (80, 24), (79, 22)]
        snaps = [
            mk_snap(
                ingest_rate_lps=r,
                window_rate_lps=w,
                total_events=t,
                unparsed_pct=p,
                error_rate_pct=e,
                top_templates=(
                    TemplateSummary(
                        42,
                        "\u30e6\u30fc\u30b6\u30fc <*> \u30ed\u30b0\u30a4\u30f3\u5931\u6557"
                        " \u3057\u307e\u3057\u305f \u3042\u3042\u3042\u3042\u3042",
                        t,
                        r / 60.0,
                        0.0,
                        p / 100.0,
                    ),
                ),
            )
            for r, w, t, p, e in [
                (0.0, 0.0, 0, 0.0, 0.0),
                (99999.9, 12345.6, 12345678, 99.9, 88.8),
                (1.0, 2.0, 7, 0.1, 0.2),
                (5000.0, 4000.0, 999999, 50.0, 12.5),
            ]
        ]
        for cols, rows in sizes:
            widths_per_frame = []
            for snap in snaps:
                frame = render(snap, cols=cols, rows=rows)
                assert len(frame.rows) == rows
                for row in frame.rows:
                    assert strip_ansi_len(row) == cols, (
                        f"row width {strip_ansi_len(row)} != {cols}"
                    )
                widths_per_frame.append([strip_ansi_len(r) for r in frame.rows])
            for other in widths_per_frame[1:]:
                assert other == widths_per_frame[0]

    def test_cjk_never_exceeds_budget(self):
        long_cjk = "\u63a5\u7d9c" * 40
        snap = mk_snap(
            top_templates=(
                TemplateSummary(42, long_cjk + " <*> tail", 900, 5.0, 0.0, 0.9),
            ),
            source_name="\u65e5\u672c\u8a9e\u30bd\u30fc\u30b9\u540d\u306f\u306a\u304c\u3044",
        )
        for cols, rows in [(80, 24), (120, 30), (70, 20)]:
            frame = render(snap, cols=cols, rows=rows)
            for row in frame.rows:
                assert strip_ansi_len(row) <= cols


class TestFixedWidthNumbers:
    def test_fmt_count_rules(self):
        assert fmt_count(9_999) == "9999"
        padded = rjust_width(fmt_count(9_999), COUNT_W)
        assert padded == "   9999"
        assert fmt_count(12_345) == "12.3k"
        assert fmt_count(12_345_678) == "12.35M"
        assert fmt_count(0) == "0"

    def test_slot_widths_constant_across_magnitudes(self):
        counts = [0, 7, 999, 9_999, 10_000, 99_999, 999_999, 9_999_499,
                  9_999_500, 12_345_678, 987_654_321]
        for v in counts:
            assert display_width(fmt_count(v)) <= COUNT_W, v
            assert strip_ansi_len(rjust_width(fmt_count(v), COUNT_W)) == COUNT_W
        rates = [0.0, 1.5, 310.4, 9_999.0, 12_345.6, 9_999_999.0]
        for v in rates:
            assert display_width(fmt_rate(v)) <= 11, v
        pcts = [0.0, 1.25, 45.67, 99.99, 100.0]
        for v in pcts:
            assert display_width(fmt_pct(v)) <= 7, v
        durs = [0.0004, 0.02, 0.5, 38.0, 125.0, 3661.0, 100_000.0]
        for v in durs:
            assert display_width(fmt_duration(v)) <= 7, v

    def test_duration_units(self):
        assert fmt_duration(0.00092).endswith("us")
        assert fmt_duration(0.0124).endswith("ms")
        assert fmt_duration(3.2) == "3.20s"
        assert ":" in fmt_duration(3661.0)


class TestSeverity:
    def test_marker_and_word_present_in_feed(self):
        snap = mk_snap(
            alerts=(
                mk_alert(Severity.ANOMALOUS, 42),
                mk_alert(Severity.CRITICAL, 43),
            )
        )
        text = plain(render(snap))
        assert "! anomalous" in text
        assert "!! critical" in text

    def test_marker_and_word_survive_colour_off(self):
        snap = mk_snap(alerts=(mk_alert(Severity.ELEVATED, 5),))
        text_off = plain(render(snap, theme=Theme(name="dark", mode=Mode.OFF)))
        assert "+ elevated" in text_off
        frame_color = render(
            snap, theme=Theme(name="dark", mode=Mode.TRUECOLOR)
        )
        text_color = plain(frame_color)
        assert "+ elevated" in text_color


class TestColourOff:
    def test_no_ansi_anywhere_in_frame(self):
        theme = Theme(name="dark", mode=Mode.OFF)
        frames = [
            render(None, theme=theme),
            render(mk_snap(), theme=theme),
            render(mk_snap(warmup_fraction=0.62), theme=theme, overlay_open=True),
        ]
        for frame in frames:
            joined = "".join(frame.rows)
            assert "\x1b[" not in joined


class TestUnicodeAndBans:
    def _all_frames(self, theme):
        return [
            render(None, theme=theme),
            render(mk_snap(), theme=theme),
            render(mk_snap(source_state="disconnected"), theme=theme),
            render(mk_snap(warmup_fraction=0.62, warmup_eta_s=38.0), theme=theme),
            render(mk_snap(), theme=theme, overlay_open=True),
        ]

    def test_banned_patterns_absent(self):
        theme = Theme(name="dark", mode=Mode.TRUECOLOR)
        raw = ""
        for frame in self._all_frames(theme):
            raw += "\n".join(frame.rows) + "\n"
        assert EMOJI_RE.search(raw) is None
        assert "+---+" not in raw
        assert "\x1b[5m" not in raw

    def test_real_box_characters_used(self):
        frame = render(mk_snap(), theme=Theme(name="dark", mode=Mode.OFF))
        text = "\n".join(frame.rows)
        assert "\u250c" in text and "\u2502" in text and "\u2500" in text


class TestOverlayRepaint:
    def test_overlay_toggle_full_repaint_once_then_diff_resumes(self):
        snap = mk_snap()
        base = render(snap)
        overlay = render(snap, overlay_open=True)
        overlay_again = render(snap, overlay_open=True)
        diff = DiffRenderer()
        diff.emit(base)
        diff.invalidate()
        out_open = diff.emit(overlay)
        assert "\x1b[2J" in out_open
        assert len(POS_RE.findall(out_open)) == len(base.rows)
        out_steady = diff.emit(overlay_again)
        assert out_steady == ""
        closed = render(snap)
        diff.invalidate()
        out_close = diff.emit(closed)
        assert "\x1b[2J" in out_close
        after = diff.emit(closed)
        assert after == ""

    def test_app_overlay_lifecycle_forces_full_repaint(self):
        provider = SnapshotProvider()
        provider.publish(mk_snap())
        stream = io.StringIO()
        app = TuiApp(
            provider,
            get_theme("dark", mode=Mode.TRUECOLOR),
            FakeClock(),
            sleeper=lambda s: None,
            stream=stream,
            size_provider=lambda: (120, 30),
            keyboard=False,
        )
        app.render_once()
        app.on_open_detail()
        opened = app.render_once()
        assert "\x1b[2J" in opened
        steady = app.render_once()
        assert POS_RE.search(steady) is None
        app.on_close_detail()
        closed_out = app.render_once()
        assert "\x1b[2J" in closed_out
        final = app.render_once()
        assert final == ""


class TestStates:
    def test_waiting_for_input_when_no_snapshot(self):
        text = plain(render(None))
        assert "waiting for input - stdin (0 lines received)" in text

    def test_warming_shows_percent_and_eta_and_suppression(self):
        snap = mk_snap(warmup_fraction=0.62, warmup_eta_s=38.0)
        frame = render(snap)
        text = plain(frame)
        assert "warming up 62%" in text
        assert "(eta 38.00s)" in text
        assert "detectors suppressed until warm-up completes" in text

    def test_disconnected_word_in_status_bar(self):
        snap = mk_snap(source_state="disconnected")
        frame = render(snap, disconnected_retries=3)
        status_rows = frame.rows[-2:]
        text = ANSI_RE.sub("", "\n".join(status_rows))
        assert "disconnected" in text
        assert "retry 3" in text

    def test_paused_state_word(self):
        snap = mk_snap(paused=True)
        text = plain(render(snap))
        assert "paused" in text

    def test_no_data_state_word(self):
        snap = mk_snap(source_state="no_data")
        text = plain(render(snap))
        assert "no data" in text

    def test_eof_state_word(self):
        snap = mk_snap(source_state="eof")
        text = plain(render(snap))
        assert "eof" in text


class TestSparklineAndSlots:
    def test_sparkline_blocks_and_stats(self):
        from logsift.tui.renderer import sparkline_with_stats

        out = sparkline_with_stats((3, 310, 155), 5)
        assert "min 3 max 310" in out
        assert "\u2588" in out or any("\u2581" <= ch <= "\u2588" for ch in out)

    def test_template_slots_render_accent_braces(self):
        from logsift.tui.renderer import render_template

        theme = Theme(name="dark", mode=Mode.TRUECOLOR)
        out = render_template(theme, "user <*> login failed")
        stripped = ANSI_RE.sub("", out)
        assert stripped.count("{*}") == 1
        assert "user" in stripped and "login failed" in stripped

    def test_feed_line_contains_time_and_detector(self):
        snap = mk_snap()
        text = plain(render(snap))
        assert "volume" in text
        assert "t42" in text
        assert "baseline 12/hr" in text

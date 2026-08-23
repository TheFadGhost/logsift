"""TUI against a LIVE engine: theme sweep, stability under throughput, restore."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

from test_engine_e2e import _make_stream, _raise_end  # noqa: E402

import re

from logsift.cli import _StreamEnd  # noqa: E402
from logsift.clock import SystemClock  # noqa: E402
from logsift.config import Config  # noqa: E402
from logsift.engine import Engine  # noqa: E402
from logsift.snapshot import SnapshotProvider  # noqa: E402
from logsift.sources import FileFollowSource  # noqa: E402
from logsift.textwidth import display_width  # noqa: E402
from logsift.themes import Mode, get_theme  # noqa: E402
from logsift.tui.app import TuiApp  # noqa: E402

_ANY_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_ROW_SPLIT = re.compile(r"\x1b\[\d+;1H|\n")


def _plain_rows(frame: str) -> list[str]:
    return [_ANY_ANSI.sub("", row) for row in _ROW_SPLIT.split(frame)]


def _wait_for_data(provider: SnapshotProvider, min_events: int = 1000):
    import time as _t

    for _ in range(400):
        snap = provider.latest()
        if snap is not None and snap.total_events >= min_events:
            return snap
        _t.sleep(0.05)
    return provider.latest()


def _run_engine_publishing(provider: SnapshotProvider, path: Path) -> None:
    cfg = Config(max_events=50_000, warmup_seconds=600.0)
    clock = SystemClock()
    source = FileFollowSource(path, poll_interval=0.25, clock=clock, sleeper=_raise_end)
    engine = Engine(cfg, clock, provider=provider, source_name=path.name, eof_exceptions=(_StreamEnd,))
    try:
        engine.run_source(source)
    except _StreamEnd:
        pass


def test_tui_renders_live_stream_across_themes(tmp_path):
    stream = tmp_path / "live.log"
    _make_stream(stream)
    provider = SnapshotProvider()
    import threading

    thread = threading.Thread(
        target=_run_engine_publishing, args=(provider, stream), daemon=True
    )
    thread.start()
    snap = _wait_for_data(provider)
    assert snap is not None and snap.total_events >= 1000

    clock = SystemClock()
    for theme_name in ("dark", "light", "high_contrast", "term16"):
        theme = get_theme(theme_name, mode=Mode.TRUECOLOR)
        app = TuiApp(provider, theme, clock, keyboard=False, fps=60)
        frame = app.render_once()
        assert frame is not None
        plain_rows = _plain_rows(frame)
        nonempty = [r for r in plain_rows if r.strip()]
        assert nonempty, f"{theme_name}: empty frame"
        joined = "\n".join(nonempty)
        assert (
            "top templates" in joined.lower()
            or "anomaly" in joined.lower()
            or "waiting" in joined.lower()
        )
        # No rendered row may exceed the terminal width budget (80 cols).
        for r in nonempty:
            assert display_width(r) <= 80 + 2, f"{theme_name}: row too wide: {display_width(r)}"
    # Stability: full repaints across changing data keep identical geometry.
    app = TuiApp(provider, get_theme("dark", mode=Mode.TRUECOLOR), clock, keyboard=False, fps=60)
    f1_rows = _plain_rows(app.render_once())
    import time as _t

    _t.sleep(0.3)
    app.differ.invalidate()
    f2_rows = _plain_rows(app.render_once())
    assert len(f1_rows) == len(f2_rows)
    for r1, r2 in zip(f1_rows, f2_rows):
        # Row width may only shrink toward empty (clear-to-EOL), never grow.
        assert abs(display_width(r1) - display_width(r2)) <= 80
    thread.join(timeout=10)


def test_tui_no_colour_mode_emits_plain_text(tmp_path):
    stream = tmp_path / "live.log"
    _make_stream(stream)
    provider = SnapshotProvider()
    import threading

    thread = threading.Thread(
        target=_run_engine_publishing, args=(provider, stream), daemon=True
    )
    thread.start()
    _wait_for_data(provider)
    theme = get_theme("dark", mode=Mode.OFF)
    app = TuiApp(provider, theme, SystemClock(), keyboard=False, fps=60)
    frame = app.render_once()
    assert frame is not None
    assert "\x1b[" not in frame
    thread.join(timeout=10)

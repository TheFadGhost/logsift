"""TuiApp: render loop, selection model, overlay state, key wiring."""

from __future__ import annotations

import shutil
import sys
import time
from typing import Callable, Protocol

from ..clock import Clock
from ..snapshot import SnapshotProvider
from ..themes import Theme
from .input import InputReader
from .renderer import (
    ALT_ENTER,
    ALT_EXIT,
    CURSOR_HIDE,
    CURSOR_SHOW,
    DiffRenderer,
    FrameRenderer,
    MAX_FPS,
    enable_windows_vt,
    restore_windows_vt,
)


class Actions(Protocol):
    def on_pause_toggle(self) -> None: ...
    def on_quit(self) -> None: ...
    def on_select(self, index: int) -> None: ...
    def on_open_detail(self) -> None: ...
    def on_close_detail(self) -> None: ...
    def on_cycle_panel(self) -> None: ...


def _default_size() -> tuple[int, int]:
    size = shutil.get_terminal_size(fallback=(80, 24))
    return size.columns, size.lines


class TuiApp:
    """Consumes provider.latest() at <=10 fps; never blocks ingestion."""

    def __init__(
        self,
        provider: SnapshotProvider,
        theme: Theme,
        clock: Clock,
        sleeper: Callable[[float], None] = time.sleep,
        actions: Actions | None = None,
        stream=None,
        size_provider=None,
        fps: float = MAX_FPS,
        keyboard: bool = True,
    ) -> None:
        self.provider = provider
        self.theme = theme
        self.clock = clock
        self.sleeper = sleeper
        self.actions = actions
        self.stream = sys.stdout if stream is None else stream
        self.size_provider = size_provider or _default_size
        self.fps = max(1.0, min(MAX_FPS, float(fps)))
        self.keyboard = keyboard
        self.renderer = FrameRenderer(theme)
        self.differ = DiffRenderer(theme=theme)
        self._running = True
        self._overlay_open = False
        self._focus = "feed"
        self._sel_feed = -1
        self._sel_tid: int | None = None
        self._last_size: tuple[int, int] | None = None
        self._prev_state: str | None = None
        self._dc_episodes = 0
        self._local_paused = False

    @property
    def overlay_open(self) -> bool:
        return self._overlay_open

    @property
    def focus(self) -> str:
        return self._focus

    def request_quit(self) -> None:
        self._running = False

    def render_once(self) -> str:
        cols, rows = self.size_provider()
        if (cols, rows) != self._last_size:
            self.differ.invalidate()
            self._last_size = (cols, rows)
        snap = self.provider.latest()
        self._track_state(snap.source_state if snap is not None else None)
        frame = self.renderer.render(
            snap,
            cols,
            rows,
            overlay_open=self._overlay_open,
            focus=self._focus,
            selected_feed=self._sel_feed,
            selected_template_id=self._sel_tid,
            disconnected_retries=self._dc_episodes or None,
            local_paused=self._local_paused,
        )
        return self.differ.emit(frame)

    def run(self, max_frames: int | None = None) -> None:
        stream = self.stream
        vt_enabled = enable_windows_vt()
        reader: InputReader | None = None
        try:
            stream.write(ALT_ENTER)
            stream.write(CURSOR_HIDE)
            stream.flush()
            if self.keyboard:
                reader = InputReader(self.actions if self.actions is not None else self)
                reader.start()
            period = 1.0 / self.fps
            frames = 0
            while self._running:
                start = self.clock.monotonic()
                stream.write(self.render_once())
                stream.flush()
                frames += 1
                if max_frames is not None and frames >= max_frames:
                    break
                elapsed = self.clock.monotonic() - start
                self.sleeper(max(0.0, period - elapsed))
        except KeyboardInterrupt:
            pass
        finally:
            if reader is not None:
                reader.stop()
            stream.write(CURSOR_SHOW)
            stream.write(ALT_EXIT)
            stream.flush()
            restore_windows_vt()

    def _track_state(self, state: str | None) -> None:
        if state == self._prev_state:
            return
        if state == "disconnected":
            self._dc_episodes += 1
        elif state == "connected":
            self._dc_episodes = 0
        self._prev_state = state

    def on_pause_toggle(self) -> None:
        self._local_paused = not self._local_paused
        if self.actions is not None:
            self.actions.on_pause_toggle()

    def on_select(self, index: int) -> None:
        snap = self.provider.latest()
        if snap is None:
            return
        if self._focus == "templates":
            items = snap.top_templates
            if items:
                ids = [t.template_id for t in sorted(items, key=lambda t: (-t.count, t.template_id))]
                cur = ids.index(self._sel_tid) if self._sel_tid in ids else 0
                nxt = max(0, min(len(ids) - 1, cur + index))
                self._sel_tid = ids[nxt]
        else:
            alerts = snap.alerts
            if alerts:
                cur = 0 if not 0 <= self._sel_feed < len(alerts) else self._sel_feed
                self._sel_feed = max(0, min(len(alerts) - 1, cur + index))
        if self.actions is not None:
            self.actions.on_select(index)

    def on_open_detail(self) -> None:
        snap = self.provider.latest()
        if snap is None or not snap.alerts:
            return
        if not 0 <= self._sel_feed < len(snap.alerts):
            self._sel_feed = 0
        if not self._overlay_open:
            self._overlay_open = True
            self.differ.invalidate()
        if self.actions is not None:
            self.actions.on_open_detail()

    def on_close_detail(self) -> None:
        if self._overlay_open:
            self._overlay_open = False
            self.differ.invalidate()
        if self.actions is not None:
            self.actions.on_close_detail()

    def on_cycle_panel(self) -> None:
        self._focus = "templates" if self._focus == "feed" else "feed"
        if self.actions is not None:
            self.actions.on_cycle_panel()

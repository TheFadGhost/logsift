"""Portable single-key input reader.

Reads keys on a daemon thread: msvcrt on Windows, termios+tty cbreak on
POSIX. Degrades to keyboard-less on unsupported platforms; never raises
into the caller.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    from .app import Actions


_WIN_CHAR_KEYS = {
    "q": "q",
    "p": "p",
    "\t": "tab",
    "\r": "enter",
    "\n": "enter",
    "\x1b": "esc",
    "\x03": "q",
}

_POSIX_BYTE_KEYS = {b"q", b"p", b"\t", b"\r", b"\n", b"\x1b", b"\x03"}

_WIN_PREFIX_KEYS = {"H": "up", "P": "down"}
_POSIX_ARROW = {b"A": "up", b"B": "down"}


def _map_char(ch: str) -> str | None:
    return _WIN_CHAR_KEYS.get(ch)


class InputReader:
    """Maps q/p/tab/enter/esc/up/down to the Actions protocol callbacks."""

    def __init__(self, actions: "Actions") -> None:
        self._actions = actions
        self._stop_evt = threading.Event()
        self._thread: threading.Thread | None = None
        self._kind: str | None = None
        self._saved_attrs: object | None = None
        self._fd = -1

    @property
    def keyboard_available(self) -> bool:
        return self._kind is not None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="logsift-input", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_evt.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=1.5)
        self._thread = None

    def _dispatch(self, key: str | None) -> None:
        if key is None:
            return
        actions = self._actions
        try:
            if key == "up":
                actions.on_select(-1)
            elif key == "down":
                actions.on_select(1)
            elif key == "tab":
                actions.on_cycle_panel()
            elif key == "enter":
                actions.on_open_detail()
            elif key == "esc":
                actions.on_close_detail()
            elif key == "q":
                actions.on_quit()
            elif key == "p":
                actions.on_pause_toggle()
        except Exception:
            pass

    def _loop(self) -> None:
        try:
            self._setup()
        except Exception:
            self._kind = None
            return
        try:
            while not self._stop_evt.is_set():
                key = self._poll()
                if key is not None:
                    self._dispatch(key)
        except Exception:
            pass
        finally:
            try:
                self._teardown()
            except Exception:
                pass

    def _setup(self) -> None:
        try:
            import msvcrt  # noqa: F401

            self._kind = "win"
            return
        except ImportError:
            pass
        try:
            import sys
            import termios
            import tty

            fd = sys.stdin.fileno()
            self._saved_attrs = termios.tcgetattr(fd)
            tty.setcbreak(fd)
            self._fd = fd
            self._kind = "posix"
        except Exception:
            self._kind = None

    def _teardown(self) -> None:
        if self._kind != "posix" or self._saved_attrs is None or self._fd < 0:
            return
        try:
            import termios

            termios.tcsetattr(self._fd, termios.TCSADRAIN, self._saved_attrs)
        except Exception:
            pass

    def _poll(self) -> str | None:
        if self._kind == "win":
            return self._poll_win()
        if self._kind == "posix":
            return self._poll_posix()
        self._stop_evt.wait(0.05)
        return None

    def _poll_win(self) -> str | None:
        import msvcrt

        while not self._stop_evt.is_set() and not msvcrt.kbhit():
            self._stop_evt.wait(0.02)
        if self._stop_evt.is_set() or not msvcrt.kbhit():
            return None
        ch = msvcrt.getwch()
        if ch in ("\x00", "\xe0"):
            nxt = msvcrt.getwch()
            return _WIN_PREFIX_KEYS.get(nxt)
        return _map_char(ch)

    def _poll_posix(self) -> str | None:
        import os
        import select
        import sys

        fd = sys.stdin.fileno()
        ready, _, _ = select.select([fd], [], [], 0.05)
        if not ready:
            return None
        data = os.read(fd, 1)
        if not data:
            self._stop_evt.set()
            return None
        if data in _POSIX_BYTE_KEYS:
            return _map_char(data.decode("ascii", errors="replace"))
        if data == b"\x1b":
            follow, _, _ = select.select([fd], [], [], 0.02)
            if not follow:
                return "esc"
            seq = os.read(fd, 2)
            if len(seq) == 2 and seq[0:1] == b"[":
                return _POSIX_ARROW.get(seq[1:2])
            return "esc"
        return None

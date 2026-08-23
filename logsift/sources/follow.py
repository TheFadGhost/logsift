"""File following with rotation, truncation and replacement handling."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Callable, Iterator

from logsift.clock import Clock
from logsift.sources import LogSource, RawLine, Sleeper, _CHUNK, _LineAssembler


class FileFollowSource(LogSource):
    """Follows one path through appends and rotation, like tail -F.

    Every poll cycle the current file is drained to EOF before any switch is
    considered. Identity is (st_dev, st_ino) from os.stat plus a size check:

    - identity changed (rename rotation or whole-file replacement): the old
      file's unterminated tail is flushed as its own line, then the new file
      now at the path is read from offset 0.
    - same identity but size shrank (copytruncate): the pending partial is
      dropped because it belonged to overwritten content, and reading
      restarts at offset 0.

    Appends reaching a renamed-away old file after its final drain are not
    seen; that window is inherent to path-based following without inotify.
    A final partial line waits for its newline and is emitted once when
    iteration ends via stop().
    """

    def __init__(
        self,
        path: str | Path,
        poll_interval: float = 0.25,
        *,
        clock: Clock,
        sleeper: Sleeper = time.sleep,
    ) -> None:
        self._path = Path(path)
        self.name = str(self._path)
        self._interval = float(poll_interval)
        self._clock = clock
        self._sleeper = sleeper
        self._stop = threading.Event()
        self._lines = _LineAssembler(self.name)
        self._identity: tuple[int, int] | None = None
        self._offset = 0

    def describe(self) -> str:
        return f"follow:{self._path}"

    def stop(self) -> None:
        self._stop.set()

    def __iter__(self) -> Iterator[RawLine]:
        return self._follow()

    def _follow(self) -> Iterator[RawLine]:
        try:
            while not self._stop.is_set():
                progressed = False
                try:
                    stat = self._path.stat()
                except OSError:
                    stat = None
                if stat is not None:
                    ident = (stat.st_dev, stat.st_ino)
                    if self._identity is None:
                        self._identity = ident
                        self._offset = 0
                    elif ident != self._identity:
                        # Rotation or replacement: emit the old file's
                        # unterminated tail, then start the new file at 0.
                        for line in self._lines.flush_boundary():
                            yield line
                        self._identity = ident
                        self._offset = 0
                    elif stat.st_size < self._offset:
                        # Copytruncate: pending partial belonged to overwritten
                        # content; drop it and replay the new content.
                        self._lines.drop_pending()
                        self._offset = 0
                    if stat.st_size > self._offset:
                        try:
                            with open(self._path, "rb") as fh:
                                fh.seek(self._offset)
                                while True:
                                    chunk = fh.read(_CHUNK)
                                    if not chunk:
                                        break
                                    self._offset += len(chunk)
                                    progressed = True
                                    for line in self._lines.feed(chunk):
                                        yield line
                        except OSError:
                            pass
                if not progressed:
                    self._nap(self._stop, self._interval, self._sleeper)
            for line in self._lines.finish():
                yield line
        finally:
            self._stop.set()

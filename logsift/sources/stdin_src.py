"""Stdin ingestion source."""

from __future__ import annotations

import sys
import threading
import time
from typing import IO, Callable, Iterator

from logsift.clock import Clock
from logsift.sources import LogSource, RawLine, Sleeper, _CHUNK, _LineAssembler


class StdinSource(LogSource):
    """Reads newline-delimited bytes from a binary stream; ends on EOF.

    stop() takes effect between reads; a read blocked on an interactive
    stdin with no input and no EOF cannot be interrupted portably.
    """

    def __init__(
        self,
        name: str = "stdin",
        stream: IO[bytes] | None = None,
        *,
        clock: Clock,
        sleeper: Sleeper = time.sleep,
    ) -> None:
        self.name = name
        self._clock = clock
        self._sleeper = sleeper
        self._stop = threading.Event()
        self._stream = stream if stream is not None else sys.stdin.buffer

    def describe(self) -> str:
        return f"stdin:{getattr(self._stream, 'name', 'stream')}"

    def stop(self) -> None:
        self._stop.set()

    def __iter__(self) -> Iterator[RawLine]:
        return self._pump()

    def _read_chunk(self) -> bytes:
        reader = getattr(self._stream, "read1", None)
        if reader is not None:
            return reader(_CHUNK)
        return self._stream.read(_CHUNK)

    def _pump(self) -> Iterator[RawLine]:
        lines = _LineAssembler(self.name)
        try:
            while not self._stop.is_set():
                try:
                    data = self._read_chunk()
                except OSError:
                    break
                if not data:
                    break
                for line in lines.feed(data):
                    yield line
            for line in lines.finish():
                yield line
        finally:
            self._stop.set()

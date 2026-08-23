"""Directory ingestion: rotated and gzipped log files, discovered by pattern."""

from __future__ import annotations

import fnmatch
import gzip
import threading
import time
from pathlib import Path
from typing import Callable, Iterator

from logsift.clock import Clock
from logsift.sources import LogSource, RawLine, Sleeper, _CHUNK, _LineAssembler


class _Cursor:
    """Per-file ingest state: identity, byte/decompressed offset, assembler."""

    __slots__ = ("path", "rel", "identity", "offset", "lines", "progress")

    def __init__(self, path: Path) -> None:
        self.path = path
        self.rel = path.name
        self.identity: tuple[int, int] | None = None
        self.offset = 0
        self.lines = _LineAssembler(self.rel)
        self.progress = False


class DirectorySource(LogSource):
    """Streams every file matching a pattern under one directory.

    Files are discovered sorted by name; files appearing later are appended
    to the processing order. Each cycle every known file is drained from its
    saved offset while it grows. Names ending in .gz are decompressed
    transparently; offsets count decompressed bytes and a growing gzip file
    is re-decoded from its last clean point, so poll cost is proportional to
    accumulated size. Identity changes or shrinks reset a file's offset
    exactly like FileFollowSource.

    Policy: a final partial line without a newline waits until the newline
    arrives, the file vanishes, or stop() - then it is flushed exactly once.
    RawLine.source_name is the file name, not the directory.
    """

    def __init__(
        self,
        dirpath: str | Path,
        pattern: str = "*.log*",
        include_gz: bool = True,
        poll_interval: float = 0.5,
        *,
        clock: Clock,
        sleeper: Sleeper = time.sleep,
    ) -> None:
        self._dir = Path(dirpath)
        self._pattern = pattern
        self._include_gz = include_gz
        self._interval = float(poll_interval)
        self._clock = clock
        self._sleeper = sleeper
        self._stop = threading.Event()
        self.name = str(self._dir)
        self._order: list[_Cursor] = []
        self._by_rel: dict[str, _Cursor] = {}

    def describe(self) -> str:
        return f"dir:{self._dir} pattern={self._pattern}"

    def stop(self) -> None:
        self._stop.set()

    def __iter__(self) -> Iterator[RawLine]:
        return self._walk()

    def _walk(self) -> Iterator[RawLine]:
        try:
            while not self._stop.is_set():
                progressed = False
                picked, ok = self._scan()
                if ok:
                    for line in self._reconcile(picked):
                        yield line
                for cur in list(self._order):
                    for line in self._pump(cur):
                        yield line
                    if cur.progress:
                        cur.progress = False
                        progressed = True
                if not progressed:
                    self._nap(self._stop, self._interval, self._sleeper)
            for cur in list(self._order):
                for line in cur.lines.finish():
                    yield line
        finally:
            self._stop.set()

    def _scan(self) -> tuple[list[Path], bool]:
        try:
            entries = list(self._dir.iterdir())
        except OSError:
            return [], False
        picked: list[Path] = []
        for p in entries:
            try:
                if not p.is_file():
                    continue
            except OSError:
                continue
            fname = p.name
            if not fnmatch.fnmatch(fname, self._pattern):
                continue
            if fname.endswith(".gz") and not self._include_gz:
                continue
            picked.append(p)
        picked.sort(key=lambda p: p.name)
        return picked, True

    def _reconcile(self, picked: list[Path]) -> Iterator[RawLine]:
        alive = {p.name for p in picked}
        for p in picked:
            if p.name not in self._by_rel:
                cur = _Cursor(p)
                self._by_rel[p.name] = cur
                self._order.append(cur)
        for cur in list(self._order):
            if cur.rel not in alive:
                # The stream ended permanently with an unterminated tail.
                for line in cur.lines.finish():
                    yield line
                self._by_rel.pop(cur.rel, None)
                self._order.remove(cur)

    def _pump(self, cur: _Cursor) -> Iterator[RawLine]:
        try:
            stat = cur.path.stat()
        except OSError:
            return
        ident = (stat.st_dev, stat.st_ino)
        if cur.identity is None:
            cur.identity = ident
            cur.offset = 0
        elif ident != cur.identity:
            # Replaced under the same name: emit the tail, start over.
            for line in cur.lines.flush_boundary():
                yield line
            cur.identity = ident
            cur.offset = 0
        elif stat.st_size < cur.offset:
            cur.lines.drop_pending()
            cur.offset = 0
        if stat.st_size <= cur.offset:
            return
        chunks = (
            self._gz_chunks(cur)
            if cur.rel.endswith(".gz")
            else self._plain_chunks(cur.path, cur.offset)
        )
        try:
            for chunk in chunks:
                cur.offset += len(chunk)
                cur.progress = True
                for line in cur.lines.feed(chunk):
                    yield line
        except (OSError, EOFError):
            return

    def _plain_chunks(self, path: Path, offset: int) -> Iterator[bytes]:
        with open(path, "rb") as fh:
            fh.seek(offset)
            while True:
                chunk = fh.read(_CHUNK)
                if not chunk:
                    return
                yield chunk

    def _gz_chunks(self, cur: _Cursor) -> Iterator[bytes]:
        with gzip.open(cur.path, "rb") as fh:
            skip = cur.offset
            while skip > 0:
                got = fh.read(min(_CHUNK, skip))
                if not got:
                    return
                skip -= len(got)
            while True:
                try:
                    chunk = fh.read(_CHUNK)
                except (EOFError, OSError):
                    return
                if not chunk:
                    return
                yield chunk

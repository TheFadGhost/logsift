"""Ingestion sources: one streaming interface over stdin, files, directories, TCP."""

from __future__ import annotations

import codecs
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Callable, Iterator

from logsift.events import FLAG_INVALID_UTF8, FLAG_TRUNCATED, MAX_LINE_BYTES

__all__ = [
    "RawLine",
    "LogSource",
    "StdinSource",
    "FileFollowSource",
    "DirectorySource",
    "TcpSource",
]

Sleeper = Callable[[float], None]

_CHUNK = 65536


@dataclass(slots=True)
class RawLine:
    """One decoded line as delivered by a LogSource."""

    text: str
    source_name: str
    valid_utf8: bool
    flags: int = 0


class LogSource(ABC):
    """A blocking stream of RawLine objects; ends at permanent EOF or stop()."""

    name: str

    @abstractmethod
    def __iter__(self) -> Iterator[RawLine]:
        ...

    @abstractmethod
    def stop(self) -> None:
        """Thread-safe, idempotent; unblocks iteration promptly."""

    @abstractmethod
    def describe(self) -> str:
        ...

    @staticmethod
    def _nap(stop: threading.Event, seconds: float, sleeper: Sleeper) -> None:
        if sleeper is time.sleep:
            stop.wait(seconds)
        else:
            sleeper(seconds)


class _PieceAssembler:
    """Byte stream in, newline-delimited pieces out, each capped at max bytes.

    A piece longer than the cap is emitted early with truncated=True and the
    remainder starts a new piece. Cuts back off from inside a UTF-8 sequence.
    """

    def __init__(self, max_bytes: int) -> None:
        self._max = max_bytes
        self._buf = bytearray()
        self._overflow = False

    def feed(self, data: bytes) -> list[tuple[bytes, bool]]:
        self._buf.extend(data)
        out: list[tuple[bytes, bool]] = []
        while self._buf:
            nl = self._buf.find(b"\n")
            if 0 <= nl <= self._max:
                out.append((bytes(self._buf[:nl]), self._overflow))
                del self._buf[: nl + 1]
                self._overflow = False
                continue
            if len(self._buf) > self._max:
                cut = self._safe_cut()
                out.append((bytes(self._buf[:cut]), True))
                del self._buf[:cut]
                self._overflow = True
                continue
            break
        return out

    def has_partial(self) -> bool:
        return bool(self._buf)

    def drop_partial(self) -> None:
        self._buf.clear()
        self._overflow = False

    def take_partial(self) -> tuple[bytes, bool] | None:
        if not self._buf:
            return None
        piece = (bytes(self._buf), self._overflow)
        self._buf.clear()
        self._overflow = False
        return piece

    def _safe_cut(self) -> int:
        cut = self._max
        i = cut - 1
        floor = cut - 4
        while i >= floor and (self._buf[i] & 0xC0) == 0x80:
            i -= 1
        if i >= floor:
            lead = self._buf[i]
            if lead >= 0xC0:
                need = 2 if lead < 0xE0 else 3 if lead < 0xF0 else 4
                if cut - i < need:
                    cut = i
        return cut if cut > 0 else 1


class _LineAssembler:
    """Byte stream to RawLine stream: cap enforcement plus the utf-8 policy.

    Decoding uses an incremental errors="replace" decoder; valid_utf8 is False
    exactly when U+FFFD appears in decoded output. The pending partial buffer
    is bounded by MAX_LINE_BYTES.
    """

    def __init__(self, source_name: str) -> None:
        self._name = source_name
        self._pieces = _PieceAssembler(MAX_LINE_BYTES)
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def feed(self, data: bytes) -> list[RawLine]:
        return [self._decode(piece, trunc) for piece, trunc in self._pieces.feed(data)]

    def has_pending(self) -> bool:
        return self._pieces.has_partial()

    def drop_pending(self) -> None:
        """Discard the unterminated line (used when content is overwritten)."""
        self._pieces.drop_partial()
        self._reset_decoder()

    def flush_boundary(self) -> list[RawLine]:
        """Emit any unterminated line; for switching to a different file."""
        got = self._pieces.take_partial()
        piece, trunc = got if got is not None else (b"", False)
        text = self._decoder.decode(piece, final=True)
        self._reset_decoder()
        if not text:
            return []
        return [self._build(text, trunc)]

    def finish(self) -> list[RawLine]:
        """Terminal flush of the unterminated line; the assembler is spent."""
        return self.flush_boundary()

    def _reset_decoder(self) -> None:
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def _decode(self, piece: bytes, trunc: bool) -> RawLine:
        text = self._decoder.decode(piece)
        return self._build(text, trunc)

    def _build(self, text: str, trunc: bool) -> RawLine:
        if text.endswith("\r"):
            text = text[:-1]
        valid = "\ufffd" not in text
        flags = 0
        if trunc:
            flags |= FLAG_TRUNCATED
        if not valid:
            flags |= FLAG_INVALID_UTF8
        return RawLine(text=text, source_name=self._name, valid_utf8=valid, flags=flags)


def _stat_identity(path) -> tuple[int, int] | None:
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


from .dirsource import DirectorySource  # noqa: E402
from .follow import FileFollowSource  # noqa: E402
from .stdin_src import StdinSource  # noqa: E402
from .tcp import TcpSource  # noqa: E402

"""TCP ingestion: newline-delimited frames from any number of clients."""

from __future__ import annotations

import selectors
import socket
import threading
import time
from collections import deque
from typing import Callable, Iterator

from logsift.clock import Clock
from logsift.sources import LogSource, RawLine, Sleeper, _CHUNK, _LineAssembler

_MAX_RECVS_PER_ROUND = 64


class TcpSource(LogSource):
    """A server socket emitting one RawLine per newline-terminated frame.

    Accepts sequential and concurrent clients; each client gets its own
    bounded assembler, so an oversized frame is flagged FLAG_TRUNCATED and
    split, never buffered unbounded. A graceful disconnect or an abrupt
    reset ends only that client: complete lines already delivered are kept,
    the client's unterminated partial is discarded, and the server keeps
    listening. Partials still pending when stop() arrives are flushed.
    """

    def __init__(
        self,
        host: str,
        port: int,
        *,
        clock: Clock,
        sleeper: Sleeper = time.sleep,
    ) -> None:
        self._clock = clock
        self._sleeper = sleeper
        self._stop = threading.Event()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind((host, port))
        self._srv.listen(16)
        self._srv.settimeout(0.1)
        self.port: int = self._srv.getsockname()[1]
        self.name = f"tcp:{host}:{self.port}"

    def describe(self) -> str:
        return self.name

    def stop(self) -> None:
        self._stop.set()

    def __iter__(self) -> Iterator[RawLine]:
        return self._serve()

    def _serve(self) -> Iterator[RawLine]:
        sel = selectors.DefaultSelector()
        conns: dict[socket.socket, _LineAssembler] = {}
        ready: deque[RawLine] = deque()
        sel.register(self._srv, selectors.EVENT_READ)
        try:
            while not self._stop.is_set():
                for key, _mask in sel.select(timeout=0.1):
                    if key.fileobj is self._srv:
                        self._accept(conns, sel)
                    else:
                        self._drain(key.fileobj, conns, ready, sel)
                while ready:
                    yield ready.popleft()
            for sock, asm in list(conns.items()):
                try:
                    sel.unregister(sock)
                except (KeyError, ValueError):
                    pass
                sock.close()
                del conns[sock]
                for line in asm.finish():
                    yield line
        finally:
            sel.close()
            self._srv.close()
            for sock in conns:
                sock.close()

    def _accept(self, conns: dict[socket.socket, _LineAssembler], sel) -> None:
        try:
            client, addr = self._srv.accept()
        except OSError:
            return
        client.setblocking(False)
        conns[client] = _LineAssembler(f"{addr[0]}:{addr[1]}")
        sel.register(client, selectors.EVENT_READ)

    def _drain(
        self,
        sock: socket.socket,
        conns: dict[socket.socket, _LineAssembler],
        ready: deque[RawLine],
        sel,
    ) -> None:
        asm = conns.get(sock)
        if asm is None:
            return
        dead = False
        for _ in range(_MAX_RECVS_PER_ROUND):
            try:
                data = sock.recv(_CHUNK)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                # Includes ConnectionResetError: abrupt client reset.
                dead = True
                break
            if not data:
                dead = True
                break
            ready.extend(asm.feed(data))
        if dead:
            # The peer ended mid-frame; a half line is not a line. Complete
            # lines were already emitted; drop the partial and move on.
            asm.drop_pending()
            try:
                sel.unregister(sock)
            except (KeyError, ValueError):
                pass
            sock.close()
            conns.pop(sock, None)

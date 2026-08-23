"""Sources: stdin, follow rotation/truncation, directory, TCP, caps, stopping."""

from __future__ import annotations

import gzip
import io
import os
import socket
import struct
import threading
from pathlib import Path
from typing import Callable

import pytest

from logsift.clock import Clock, FakeClock
from logsift.events import FLAG_INVALID_UTF8, FLAG_TRUNCATED, MAX_LINE_BYTES
from logsift.sources import (
    DirectorySource,
    FileFollowSource,
    LogSource,
    RawLine,
    StdinSource,
    TcpSource,
)


def fake_sleeper(clock: Clock, pause: float = 0.001) -> Callable[[float], None]:
    def _sleep(seconds: float) -> None:
        clock.advance(seconds)
        if pause > 0:
            threading.Event().wait(pause)

    return _sleep


def _spawn(source: LogSource):
    got: list[RawLine] = []
    done = threading.Event()

    def run() -> None:
        try:
            for line in source:
                got.append(line)
        finally:
            done.set()

    th = threading.Thread(target=run, daemon=True)
    th.start()
    return got, done, th


def _wait(got: list[RawLine], done: threading.Event, n: int, budget: int = 500) -> None:
    spins = 0
    while len(got) < n and spins < budget:
        threading.Event().wait(0.01)
        spins += 1
    assert len(got) >= n, f"only {len(got)}/{n} lines, stopped={done.is_set()}"


def _join(th: threading.Thread, budget: int = 300) -> None:
    spins = 0
    while th.is_alive() and spins < budget:
        threading.Event().wait(0.01)
        spins += 1
    assert not th.is_alive(), "iteration did not end after stop()"


def _retry(op: Callable[[], None], tries: int = 200) -> None:
    last: Exception | None = None
    for _ in range(tries):
        try:
            op()
            return
        except PermissionError as exc:
            last = exc
            threading.Event().wait(0.005)
    raise AssertionError(f"filesystem operation kept failing: {last}")


def _pipe_source(payload: bytes, name: str = "t") -> list[RawLine]:
    r, w = os.pipe()
    src = StdinSource(name=name, stream=os.fdopen(r, "rb"), clock=FakeClock())

    def feed() -> None:
        try:
            os.write(w, payload)
        finally:
            os.close(w)

    writer = threading.Thread(target=feed, daemon=True)
    writer.start()
    try:
        return list(src)
    finally:
        src.stop()
        writer.join(5)


def test_logsource_is_abstract_and_rawline_defaults():
    with pytest.raises(TypeError):
        LogSource()
    rl = RawLine(text="x", source_name="s", valid_utf8=True)
    assert rl.flags == 0


def test_stdin_decodes_lines_and_flags_invalid_utf8():
    lines = _pipe_source(b"alpha\n\xff\xfebet\n")
    assert [ln.text for ln in lines] == ["alpha", "\ufffd\ufffdbet"]
    first, second = lines
    assert first.source_name == "t"
    assert first.valid_utf8 is True
    assert first.flags == 0
    assert second.valid_utf8 is False
    assert second.flags & FLAG_INVALID_UTF8


def test_stdin_oversized_line_truncated_and_split():
    payload = b"H" * (MAX_LINE_BYTES + 40) + b"TAIL\n"
    lines = _pipe_source(payload)
    assert len(lines) >= 2
    joined = "".join(ln.text for ln in lines)
    assert joined == "H" * (MAX_LINE_BYTES + 40) + "TAIL"
    assert all(ln.flags & FLAG_TRUNCATED for ln in lines)
    assert len(lines[0].text.encode()) <= MAX_LINE_BYTES
    assert lines[0].text == "H" * MAX_LINE_BYTES
    assert lines[1].text == "H" * 40 + "TAIL"


def test_stdin_multibyte_boundary_cut_stays_valid():
    head = b"x" * (MAX_LINE_BYTES - 1)
    euro = "\u20ac".encode()
    lines = _pipe_source(head + euro + b"z" * 20 + b"\n")
    joined = "".join(ln.text for ln in lines)
    assert joined == head.decode() + "\u20ac" + "z" * 20
    assert lines[0].flags & FLAG_TRUNCATED
    assert all(ln.valid_utf8 for ln in lines)


def test_stdin_bytestream_contract():
    src = StdinSource(name="mem", stream=io.BytesIO(b"a\nb"), clock=FakeClock())
    assert src.describe()
    lines = list(src)
    assert [ln.text for ln in lines] == ["a", "b"]
    src.stop()
    src.stop()
    assert list(src) == []


def test_follow_append_rotation_copytruncate_replacement(tmp_path: Path):
    p = tmp_path / "app.log"
    clock = FakeClock()
    src = FileFollowSource(
        p, poll_interval=0.01, clock=clock, sleeper=fake_sleeper(clock)
    )
    got, done, th = _spawn(src)

    p.write_bytes(b"one\ntwo\n")
    _wait(got, done, 2)

    rotated = tmp_path / "app.log.1"
    _retry(lambda: os.rename(p, rotated))
    p.write_bytes(b"three\nfour\n")
    _wait(got, done, 4)

    with p.open("ab") as fh:
        fh.write(b"five\nsix\n")
    _wait(got, done, 6)

    p.write_bytes(b"seven\n")
    _wait(got, done, 7)

    _retry(lambda: os.remove(p))
    p.write_bytes(b"eight\n")
    _wait(got, done, 8)

    src.stop()
    _join(th)
    texts = [ln.text for ln in got]
    assert texts == ["one", "two", "three", "four", "five", "six", "seven", "eight"]
    assert len(set(texts)) == len(texts)
    assert all(ln.valid_utf8 for ln in got)


def test_follow_flushes_partial_line_exactly_once_at_stop(tmp_path: Path):
    p = tmp_path / "tail.log"
    clock = FakeClock()
    src = FileFollowSource(
        p, poll_interval=0.01, clock=clock, sleeper=fake_sleeper(clock)
    )
    got, done, th = _spawn(src)
    p.write_bytes(b"alpha\nbeta")
    _wait(got, done, 1)
    threading.Event().wait(0.2)
    assert [ln.text for ln in got] == ["alpha"]
    src.stop()
    _join(th)
    texts = [ln.text for ln in got]
    assert texts == ["alpha", "beta"]
    assert sum(1 for ln in got if ln.text == "beta") == 1


def test_follow_file_created_after_start(tmp_path: Path):
    p = tmp_path / "late.log"
    clock = FakeClock()
    src = FileFollowSource(
        p, poll_interval=0.01, clock=clock, sleeper=fake_sleeper(clock)
    )
    got, done, th = _spawn(src)
    threading.Event().wait(0.1)
    assert got == []
    p.write_bytes(b"late\nlines\n")
    _wait(got, done, 2)
    src.stop()
    _join(th)
    assert [ln.text for ln in got] == ["late", "lines"]


def test_follow_stop_unblocks_blocked_iteration_promptly(tmp_path: Path):
    p = tmp_path / "quiet.log"
    p.write_bytes(b"")
    src = FileFollowSource(p, poll_interval=0.05, clock=FakeClock())
    got, done, th = _spawn(src)
    threading.Event().wait(0.25)
    assert not done.is_set()
    src.stop()
    _join(th, budget=200)
    assert got == []


def test_directory_sorted_then_new_gzip_picked_up_and_partial_policy(tmp_path: Path):
    (tmp_path / "b.log").write_bytes(b"b1\n")
    (tmp_path / "a.log").write_bytes(b"a1\na2\n")
    clock = FakeClock()
    src = DirectorySource(
        tmp_path, poll_interval=0.01, clock=clock, sleeper=fake_sleeper(clock)
    )
    got, done, th = _spawn(src)

    _wait(got, done, 3)
    assert [ln.text for ln in got[:3]] == ["a1", "a2", "b1"]
    assert got[0].source_name == "a.log"

    (tmp_path / "m.log.gz").write_bytes(gzip.compress(b"g1\ng2\n"))
    _wait(got, done, 5)
    assert [ln.text for ln in got[3:]] == ["g1", "g2"]
    assert got[3].source_name == "m.log.gz"

    (tmp_path / "z.log").write_bytes(b"part")
    threading.Event().wait(0.3)
    assert len(got) == 5

    src.stop()
    _join(th)
    texts = [ln.text for ln in got]
    assert texts == ["a1", "a2", "b1", "g1", "g2", "part"]
    assert sum(1 for ln in got if ln.text == "part") == 1


def test_directory_include_gz_false_skips_gzip(tmp_path: Path):
    (tmp_path / "a.log").write_bytes(b"a1\n")
    (tmp_path / "x.log.gz").write_bytes(gzip.compress(b"g1\n"))
    clock = FakeClock()
    src = DirectorySource(
        tmp_path,
        include_gz=False,
        poll_interval=0.01,
        clock=clock,
        sleeper=fake_sleeper(clock),
    )
    got, done, th = _spawn(src)
    _wait(got, done, 1)
    threading.Event().wait(0.2)
    assert len(got) == 1
    src.stop()
    _join(th)
    assert [ln.text for ln in got] == ["a1"]


def _connect(port: int) -> socket.socket:
    return socket.create_connection(("127.0.0.1", port), timeout=2)


def test_tcp_clients_reset_partial_discard_and_stop():
    clock = FakeClock()
    src = TcpSource("127.0.0.1", 0, clock=clock)
    got, done, th = _spawn(src)

    c1 = _connect(src.port)
    c1.sendall(b"a\nbb\n")
    c1.close()
    _wait(got, done, 2)

    c2 = _connect(src.port)
    c2.sendall(b"cc\n")
    c2.close()
    _wait(got, done, 3)

    rst = _connect(src.port)
    rst.sendall(b"mid-frame-no-newline")
    rst.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    rst.close()
    threading.Event().wait(0.15)

    c4 = _connect(src.port)
    c4.sendall(b"dd\n")
    c4.close()
    _wait(got, done, 4)

    c5 = _connect(src.port)
    c5.sendall(b"orphan")
    c5.close()
    threading.Event().wait(0.5)
    assert len(got) == 4

    src.stop()
    _join(th)
    texts = [ln.text for ln in got]
    assert texts == ["a", "bb", "cc", "dd"]
    assert all(ln.valid_utf8 for ln in got)
    assert str(src.port) in src.describe()


def test_tcp_oversized_frame_flagged_and_next_client_ok():
    clock = FakeClock()
    src = TcpSource("127.0.0.1", 0, clock=clock)
    got, done, th = _spawn(src)
    probe = _connect(src.port)
    probe.close()

    big = _connect(src.port)
    big.sendall(b"B" * (MAX_LINE_BYTES + 10) + b"\nend\n")
    big.close()
    _wait(got, done, 2)

    nxt = _connect(src.port)
    nxt.sendall(b"after\n")
    nxt.close()
    _wait(got, done, 4)

    src.stop()
    _join(th)
    assert got[0].flags & FLAG_TRUNCATED
    assert "".join(ln.text for ln in got[:2]) == "B" * (MAX_LINE_BYTES + 10)
    assert got[2].text == "end"
    assert got[3].text == "after"


def test_tcp_stop_unblocks_promptly():
    clock = FakeClock()
    src = TcpSource("127.0.0.1", 0, clock=clock)
    got, done, th = _spawn(src)
    listening = False
    for _ in range(200):
        try:
            s = _connect(src.port)
            s.close()
            listening = True
            break
        except OSError:
            threading.Event().wait(0.01)
    assert listening
    src.stop()
    _join(th, budget=200)

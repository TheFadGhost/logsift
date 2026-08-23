"""Bounded-memory ingestion: measured, asserted, never eyeballed."""

from __future__ import annotations

import ctypes
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

from logsift.cli import _StreamEnd  # noqa: E402
from logsift.config import Config  # noqa: E402
from logsift.engine import Engine  # noqa: E402
from logsift.clock import SystemClock  # noqa: E402
from logsift.sources import FileFollowSource  # noqa: E402
from mem_check import peak_rss_during_run  # noqa: E402


def _raise_end(_seconds: float) -> None:
    raise _StreamEnd


def _write_logfmt_stream(path: Path, n_lines: int, base_epoch: float) -> None:
    """Synthetic deterministic logfmt stream - no real data, ever."""
    rng_seed = 12345
    state = rng_seed
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        step = 3600.0 * 24 * 7 / n_lines
        for i in range(n_lines):
            state = (state * 1103515245 + 12345) % 2147483648
            fam = state % 8
            dur = 50 + (state >> 3) % 900
            user = f"u-{(state >> 5) % 9973:04d}"
            ts = base_epoch + i * step
            hh = int(ts % 86400 // 3600)
            mm = int(ts % 3600 // 60)
            ss = int(ts % 60)
            msg = (
                f"worker w{fam} heartbeat lane lane-{fam} lag {dur} ms "
                f"user {user} batch {i}"
            )
            fh.write(
                f"timestamp=2026-03-01T{hh:02d}:{mm:02d}:{ss:02d}Z level=info "
                f"service=synth-{fam} duration_ms={dur} {msg}\n"
            )


def test_large_stream_memory_bounded_and_ring_enforced(tmp_path):
    stream = tmp_path / "big.log"
    n = 150_000
    max_events = 20_000
    _write_logfmt_stream(stream, n, base_epoch=1782950400.0)
    ceiling_bytes = 400 * 1024 * 1024
    peak_bytes, info = peak_rss_during_run(
        stream,
        max_events=max_events,
        warmup_seconds=600.0,
    )
    assert info["lines"] == n
    assert info["unparsed"] == 0
    # The ring is hard: exactly max_events retained, everything else evicted.
    assert info["index_retained"] == max_events
    assert info["evicted"] == n - max_events
    # Memory stays far below any plausible unbounded growth for 150k events;
    # an unbounded index here would hold 150k rows and their strings.
    assert 0 < peak_bytes < ceiling_bytes, (
        f"peak RSS {peak_bytes / 1048576:.1f} MB exceeded {ceiling_bytes / 1048576:.0f} MB"
    )


def test_index_eviction_keeps_newest_data(tmp_path):
    """Eviction drops the OLDEST rows; recent data must remain queryable."""
    from logsift.index import StreamingIndex

    idx = StreamingIndex(max_events=500)

    class _FakeEvent:
        pass

    import logging

    from logsift.events import Event, ParseStatus

    base = 1782950400.0
    for i in range(800):
        ev = Event(
            ts=base + i,
            message=f"m{i}",
            template_id=i % 7 + 1,
            template_text=f"t{i % 7}",
            parse_status=ParseStatus.OK,
        )
        idx.add(ev)
    totals = idx.totals()
    assert len(idx) == 500
    assert totals.evicted_count == 300
    rows = list(idx.iter_rows())
    assert rows[0].ts == base + 300  # oldest retained is i=300
    assert rows[-1].ts == base + 799

"""Measure peak memory of a full ingestion run against a configured ceiling.

Method: feeds the file through the real pipeline (source reader -> multiline
assembler -> parser registry -> templater -> six detectors -> bounded index)
in-process and samples the process working set (via GetProcessMemoryInfo on
Windows, resource.getrusage maxrss elsewhere) after every N lines. Peak is the
max sample. The ceiling comparison uses that peak honestly; no sampling means
no claim.
"""

from __future__ import annotations

import argparse
import ctypes
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

if sys.platform == "win32":

    class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_uint32),
            ("PageFaultCount", ctypes.c_uint32),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    def _rss_bytes() -> int:
        psapi = ctypes.windll.psapi
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetCurrentProcess()
        counters = _PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(_PROCESS_MEMORY_COUNTERS)
        if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
            return 0
        return int(counters.WorkingSetSize)

else:
    import resource

    def _rss_bytes() -> int:
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024


def _raise_end(_seconds: float) -> None:
    raise _StreamEndSentinel


class _StreamEndSentinel(Exception):
    """Raised by the sleeper when a finite file reaches EOF under follow."""


def peak_rss_during_run(path: Path, max_events: int, warmup_seconds: float) -> tuple[int, dict]:
    """Runs the real pipeline and returns (peak_rss_bytes, stats)."""
    import threading

    from logsift.cli import _StreamEnd
    from logsift.config import Config
    from logsift.engine import Engine
    from logsift.clock import SystemClock
    from logsift.sources import FileFollowSource

    cfg = Config(max_events=max_events, warmup_seconds=warmup_seconds)
    clock = SystemClock()
    source = FileFollowSource(
        path, poll_interval=cfg.poll_interval_s, clock=clock, sleeper=_raise_end
    )
    engine = Engine(cfg, clock, provider=None, source_name=path.name, eof_exceptions=(_StreamEndSentinel,))
    stop = threading.Event()
    peak = {"rss": _rss_bytes()}

    def sampler() -> None:
        local_peak = peak["rss"]
        while not stop.wait(0.05):
            rss = _rss_bytes()
            if rss > local_peak:
                local_peak = rss
        peak["rss"] = max(local_peak, _rss_bytes())

    thread = threading.Thread(target=sampler, daemon=True)
    thread.start()
    try:
        try:
            engine.run_source(source)
        except _StreamEndSentinel:
            pass
    finally:
        source.stop()
        stop.set()
        thread.join(timeout=2.0)
        peak["rss"] = max(peak["rss"], _rss_bytes())
    s = engine.stats
    info = {
        "lines": s.lines_total,
        "events": s.events_assembled,
        "unparsed": s.unparsed,
        "templates": len(engine.index.template_stats()),
        "index_retained": len(engine.index),
        "evicted": engine.index.totals().evicted_count,
        "alerts": s.alerts_emitted,
    }
    return peak["rss"], info


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="measure ingestion memory under load")
    ap.add_argument("--input", required=True)
    ap.add_argument("--ceiling-mb", type=float, default=512.0)
    ap.add_argument("--max-events", type=int, default=100_000)
    ap.add_argument("--warmup", type=float, default=3600.0)
    ns = ap.parse_args(argv)
    path = Path(ns.input)
    if not path.exists():
        print(f"mem-check: no such file: {path}", file=sys.stderr)
        return 2
    peak_bytes, info = peak_rss_during_run(path, ns.max_events, ns.warmup)
    peak_mb = peak_bytes / (1024 * 1024)
    verdict = "OK" if peak_mb <= ns.ceiling_mb else "OVER CEILING"
    print(f"lines={info['lines']} events={info['events']} unparsed={info['unparsed']} "
          f"templates={info['templates']} retained={info['index_retained']} "
          f"evicted={info['evicted']} alerts={info['alerts']}")
    print(f"peak working set: {peak_mb:.1f} MB (ceiling {ns.ceiling_mb:.0f} MB) - {verdict}")
    return 0 if peak_mb <= ns.ceiling_mb else 1


if __name__ == "__main__":
    raise SystemExit(main())



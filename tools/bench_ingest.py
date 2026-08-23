"""End-to-end ingestion throughput benchmark over the real Logsift pipeline.

Composes the shipped stages exactly as each module documents them:

    source reader (FileFollowSource) -> MultilineAssembler -> ParserRegistry
    -> Templater -> StreamingIndex.add

Everything reported is measured live in this process; no number is assumed,
cached or extrapolated. If a pipeline stage cannot be imported the missing
stage is named and the tool exits nonzero.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if (ROOT / "logsift").is_dir():
    sys.path.insert(0, str(ROOT))

METHOD_STATEMENT = (
    "measured by feeding FILE through the full parse-template-index path "
    "in-process; timing via clock.monotonic deltas around the loop"
)

_STAGE_IMPORTS = (
    ("source reader", "from logsift.sources import FileFollowSource"),
    ("multiline assembler", "from logsift.multiline import MultilineAssembler"),
    ("parser registry", "from logsift.parsers import ParserRegistry"),
    ("templater", "from logsift.templater import Templater"),
    ("index.add", "from logsift.index import StreamingIndex"),
    ("event contract", "from logsift.events import Event, ParseStatus"),
    ("injected clock", "from logsift.clock import SystemClock"),
)


class _StreamEnd(Exception):
    """Raised by the sleeper when a finite file reaches EOF under follow."""


def _stream_end(_seconds: float) -> None:
    raise _StreamEnd


def _load_stages() -> tuple[dict, list[tuple[str, str]]]:
    namespace: dict = {}
    missing: list[tuple[str, str]] = []
    for label, statement in _STAGE_IMPORTS:
        try:
            exec(statement, namespace)
        except ImportError as exc:
            missing.append((label, str(exc)))
    return namespace, missing


def _detect_format(registry_cls, clock, path: Path, sample_size: int = 200) -> tuple[str, float]:
    sample: list[str] = []
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            sample.append(line.rstrip("\r\n"))
            if len(sample) >= sample_size:
                break
    report = registry_cls(clock).detect(sample)
    return report.parser_name, report.confidence


def _run_once(namespace: dict, path: Path) -> tuple[int, int, float]:
    clock = namespace["SystemClock"]()
    source = namespace["FileFollowSource"](
        path, poll_interval=0.25, clock=clock, sleeper=_stream_end
    )
    assembler = namespace["MultilineAssembler"]()
    registry = namespace["ParserRegistry"](clock)
    templater = namespace["Templater"](clock)
    index = namespace["StreamingIndex"]()
    lines = 0
    events = 0

    def absorb(text: str) -> None:
        nonlocal events
        events += 1
        result = registry.parse_line(text)
        event = namespace["Event"](
            ts=result.ts if result.ts is not None else 0.0,
            message=result.message,
            level=result.level,
            fields=dict(result.fields),
            numeric=dict(result.numeric),
            source=source.name,
            parse_status=namespace["ParseStatus"].OK if result.ok else namespace["ParseStatus"].UNPARSED,
            parser=result.parser,
            raw_line=text,
        )
        match = templater.process(event.message)
        event.template_id = match.template.template_id
        event.template_text = match.template.text
        index.add(event)

    start = clock.monotonic()
    try:
        for raw_line in source:
            lines += 1
            for text in assembler.feed(raw_line.text):
                absorb(text)
    except _StreamEnd:
        pass
    finally:
        source.stop()
    for text in assembler.flush():
        absorb(text)
    elapsed = clock.monotonic() - start
    return lines, events, elapsed


def _stdev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    return math.sqrt(sum((v - mean) ** 2 for v in values) / len(values))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark end-to-end log ingestion through the real Logsift pipeline."
    )
    parser.add_argument("--input", required=True, help="log file to feed through the pipeline")
    parser.add_argument("--runs", type=int, default=3, help="repetitions (default 3)")
    parser.add_argument("--json", dest="json_out", default=None, help="optional JSON report path")
    args = parser.parse_args(argv)

    if args.runs < 1:
        print("bench_ingest: --runs must be >= 1", file=sys.stderr)
        return 2
    path = Path(args.input)
    if not path.is_file():
        print(f"bench_ingest: input not found: {path}", file=sys.stderr)
        return 2

    namespace, missing = _load_stages()
    if missing:
        for label, error in missing:
            print(f"bench_ingest: stage import failed: {label} ({error})", file=sys.stderr)
        print(
            "hint: run from the repository root so the logsift package resolves, "
            "or install it with 'pip install -e .'",
            file=sys.stderr,
        )
        return 2

    total_bytes = path.stat().st_size
    clock = namespace["SystemClock"]()
    detected_name, detected_confidence = _detect_format(namespace["ParserRegistry"], clock, path)

    hardware = {
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
    }

    rows: list[dict] = []
    for run_no in range(1, args.runs + 1):
        lines, events, elapsed = _run_once(namespace, path)
        lps = lines / elapsed if elapsed > 0 else 0.0
        mbs = (total_bytes / 1e6) / elapsed if elapsed > 0 else 0.0
        rows.append({
            "run": run_no,
            "elapsed_s": elapsed,
            "lines": lines,
            "events": events,
            "lines_per_s": lps,
            "mb_per_s": mbs,
        })

    rates = [row["lines_per_s"] for row in rows]
    mean_rate = sum(rates) / len(rates)
    spread = _stdev(rates)
    bench_lines = rows[-1]["lines"]
    avg_line_bytes = total_bytes / max(1, bench_lines)

    print("logsift ingestion benchmark")
    print(f"method: {METHOD_STATEMENT}")
    print(f"input: {path} ({total_bytes} bytes, avg line {avg_line_bytes:.1f} B)")
    print(
        f"format detected: {detected_name} (confidence {detected_confidence:.3f}, "
        f"200-line sample)"
    )
    print(
        f"hardware: {hardware['platform']}; cpus={hardware['cpu_count']}; "
        f"python {hardware['python']}"
    )
    print()
    print("run  elapsed_s      lines   lines/s     MB/s")
    for row in rows:
        print(
            f"{row['run']:>3}  {row['elapsed_s']:>9.3f}  {row['lines']:>8}  "
            f"{row['lines_per_s']:>12.1f}  {row['mb_per_s']:>8.2f}"
        )
    cv = (spread / mean_rate * 100.0) if mean_rate > 0 else 0.0
    print(
        f"mean lines/s {mean_rate:,.1f}  stdev {spread:,.1f} (cv {cv:.1f}%)  "
        f"over {len(rows)} run(s)"
    )

    if args.json_out:
        report = {
            "schema": "logsift.bench/1",
            "input": str(path),
            "bytes": total_bytes,
            "lines_last_run": bench_lines,
            "avg_line_bytes": avg_line_bytes,
            "detected_format": {"name": detected_name, "confidence": detected_confidence},
            "runs": rows,
            "mean_lines_per_s": mean_rate,
            "stdev_lines_per_s": spread,
            "cv_pct": cv,
            "hardware": hardware,
            "python": platform.python_version(),
            "method": METHOD_STATEMENT,
        }
        Path(args.json_out).write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

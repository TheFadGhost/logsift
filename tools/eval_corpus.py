"""Evaluate detection quality on the labelled corpus: precision/recall per detector.

Matching rule: an alert matches a label when its detector maps to the label
kind AND the alert's event time falls inside [start - 30min, end + 30min].
A label is recalled if >=1 of its alerts matched; precision counts alerts that
matched any label. Unmatched alerts are false positives.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logsift.cli import EXIT_RUNTIME_ERROR, _StreamEnd  # noqa: E402
from logsift.config import Config  # noqa: E402
from logsift.engine import Engine  # noqa: E402
from logsift.sources import FileFollowSource  # noqa: E402

KIND_TO_DETECTOR = {
    "volume_spike": "volume",
    "new_template": "new_template",
    "stopped_template": "stopped_template",
    "error_rate_surge": "error_rate",
    "latency_shift": "numeric_shift",
    "rare_sequence": "rare_sequence",
}

TOLERANCE_S = 1800.0


def run_replay(corpus: Path, cfg: Config) -> list[dict]:
    from logsift.clock import SystemClock

    clock = SystemClock()
    source = FileFollowSource(
        corpus,
        poll_interval=cfg.poll_interval_s,
        clock=clock,
        sleeper=_raise_stream_end,
    )
    engine = Engine(
        cfg, clock, provider=None, source_name=corpus.name, eof_exceptions=(_StreamEnd,)
    )
    try:
        engine.run_source(source)
    except _StreamEnd:
        pass
    finally:
        source.stop()
    return engine.recent_alerts()


def _raise_stream_end(_seconds: float) -> None:
    raise _StreamEnd


def _alert_time(alert: dict) -> float:
    raw = alert.get("time") or alert.get("window", {}).get("end")
    try:
        dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return dt.timestamp()
    except (ValueError, TypeError):
        return 0.0


def evaluate(alerts: list[dict], labels: dict) -> dict:
    anomalies = labels["anomalies"]
    matched_labels: set[int] = set()
    tp_by_det: defaultdict[str, int] = defaultdict(int)
    fp_by_det: defaultdict[str, int] = defaultdict(int)
    labels_by_kind: defaultdict[str, int] = defaultdict(int)
    for lab in anomalies:
        labels_by_kind[lab["kind"]] += 1
    for alert in alerts:
        det = alert.get("detector", "")
        t = _alert_time(alert)
        hit = None
        for i, lab in enumerate(anomalies):
            if KIND_TO_DETECTOR.get(lab["kind"]) != det:
                continue
            if lab["start_epoch"] - TOLERANCE_S <= t <= lab["end_epoch"] + TOLERANCE_S:
                hit = i
                break
        if hit is None:
            fp_by_det[det] += 1
        else:
            matched_labels.add(hit)
            tp_by_det[det] += 1
    report: dict[str, dict[str, float]] = {}
    for kind, detector in KIND_TO_DETECTOR.items():
        n_labels = labels_by_kind.get(kind, 0)
        recalled = sum(
            1 for i in matched_labels if anomalies[i]["kind"] == kind
        )
        tp = min(tp_by_det.get(detector, 0), n_labels)
        fp = fp_by_det.get(detector, 0)
        precision = tp / max(1, tp + fp)
        recall = recalled / max(1, n_labels)
        report[detector] = {
            "labels": n_labels,
            "true_positives": tp,
            "false_positives": fp,
            "missed": n_labels - recalled,
            "precision": round(precision, 3),
            "recall": round(recall, 3),
        }
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="precision/recall of Logsift detectors on the labelled corpus"
    )
    ap.add_argument("--corpus-dir", default="generated/demo")
    ap.add_argument("--warmup", type=float, default=3600.0)
    ap.add_argument("--json-out", default=None)
    ns = ap.parse_args(argv)

    corpus_dir = Path(ns.corpus_dir)
    corpus = corpus_dir / "corpus.jsonl"
    labels_path = corpus_dir / "labels.json"
    if not corpus.exists() or not labels_path.exists():
        print(
            f"eval: missing {corpus} or {labels_path}; run tools/gen_corpus.py first",
            file=sys.stderr,
        )
        return EXIT_RUNTIME_ERROR
    labels = json.loads(labels_path.read_text(encoding="utf-8"))

    cfg = Config(warmup_seconds=ns.warmup)
    alerts = run_replay(corpus, cfg)
    report = evaluate(alerts, labels)

    print(f"alerts emitted: {len(alerts)} over {len(labels['anomalies'])} injected anomalies")
    header = f"{'detector':<18}{'labels':>7}{'tp':>5}{'fp':>5}{'missed':>8}{'prec':>7}{'recall':>8}"
    print(header)
    for detector in KIND_TO_DETECTOR.values():
        r = report[detector]
        print(
            f"{detector:<18}{r['labels']:>7}{r['true_positives']:>5}{r['false_positives']:>5}"
            f"{r['missed']:>8}{r['precision']:>7.3f}{r['recall']:>8.3f}"
        )
    if ns.json_out:
        Path(ns.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Tests for tools/gen_corpus.py: corpus shape, label schema, synthetic hygiene."""

from __future__ import annotations

import json
import random
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

import gen_corpus  # noqa: E402

LABEL_KINDS = {
    "volume_spike",
    "new_template",
    "stopped_template",
    "error_rate_surge",
    "latency_shift",
    "rare_sequence",
}

IPv4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOC_PREFIXES = ("192.0.2.", "198.51.100.", "203.0.113.")
DOTTED_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9-]*(?:\.[A-Za-z0-9-]+)+")

ACCESS_SHAPE_RE = re.compile(
    r"^\d{1,3}(?:\.\d{1,3}){3} \S+ \S+ "
    r"\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} \+0000\] "
    r'"[A-Z]+ \S+ HTTP/(?:[12]\.\d|2)" \d{3} (?:\d+|-) "[^"]*" "[^"]*"$'
)
SYSLOG_SHAPE_RE = re.compile(
    r"^(?:<\d{1,3}>)?[A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2} \S+ [a-z]+\[\d+\]: .+$"
)
LOGFMT_TOKEN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\-]*=")


def _split_logfmt(line: str) -> list[str]:
    tokens: list[str] = []
    buf: list[str] = []
    in_quotes = False
    for ch in line:
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
        elif ch == " " and not in_quotes:
            if buf:
                tokens.append("".join(buf))
                buf = []
        else:
            buf.append(ch)
    if buf:
        tokens.append("".join(buf))
    return tokens


def _generate(tmp_path: Path, lines: int = 2600, seed: int = 7) -> Path:
    out = tmp_path / "fixture"
    rc = gen_corpus.main(["--out", str(out), "--lines", str(lines), "--seed", str(seed)])
    assert rc == 0
    return out


def test_corpus_exists_nonempty_and_valid_line_records(tmp_path: Path) -> None:
    out = _generate(tmp_path)
    corpus = out / "corpus.jsonl"
    assert corpus.is_file()
    text = corpus.read_text(encoding="utf-8")
    lines_out = text.splitlines()
    assert len(lines_out) == 2600
    assert all(line.strip() for line in lines_out)
    json_lines = [line for line in lines_out if line.startswith("{")]
    assert len(json_lines) > len(lines_out) * 0.35
    for line in json_lines:
        obj = json.loads(line)
        assert isinstance(obj, dict)
    assert any(line.startswith("timestamp=") for line in lines_out), "logfmt missing"
    assert any(ACCESS_SHAPE_RE.match(line) for line in lines_out), "access-combined missing"
    assert any(SYSLOG_SHAPE_RE.match(line) for line in lines_out), "syslog missing"


def test_all_six_label_kinds_with_required_fields(tmp_path: Path) -> None:
    out = _generate(tmp_path)
    labels = json.loads((out / "labels.json").read_text(encoding="utf-8"))
    kinds = {entry["kind"] for entry in labels["anomalies"]}
    assert kinds == LABEL_KINDS
    for entry in labels["anomalies"]:
        assert {"kind", "start_epoch", "end_epoch", "template_hint", "note"} <= set(entry)
        start, end = entry["start_epoch"], entry["end_epoch"]
        assert gen_corpus.BASE_EPOCH <= start < end <= gen_corpus.BASE_EPOCH + gen_corpus.HORIZON_SECONDS


def test_timestamps_inside_simulated_range(tmp_path: Path) -> None:
    out = _generate(tmp_path)
    lo = gen_corpus.BASE_EPOCH
    hi = gen_corpus.BASE_EPOCH + gen_corpus.HORIZON_SECONDS
    checked = 0
    for line in (out / "corpus.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.startswith("{"):
            continue
        stamp = json.loads(line)["timestamp"]
        epoch = datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
        assert lo <= epoch < hi
        checked += 1
    assert checked >= 500
    labels = json.loads((out / "labels.json").read_text(encoding="utf-8"))
    start = labels["timeline"]["start_epoch"]
    end = labels["timeline"]["end_epoch"]
    assert lo <= start < end <= hi


def test_normal_ranges_are_exact_complement_of_anomaly_windows(tmp_path: Path) -> None:
    out = _generate(tmp_path, lines=400, seed=11)
    labels = json.loads((out / "labels.json").read_text(encoding="utf-8"))
    base = gen_corpus.BASE_EPOCH
    horizon = gen_corpus.HORIZON_SECONDS
    windows = sorted(
        (a["start_epoch"] - base, a["end_epoch"] - base) for a in labels["anomalies"]
    )
    expected: list[list[float]] = []
    cursor = 0.0
    for start, end in windows:
        if start > cursor:
            expected.append([base + cursor, base + start])
        cursor = max(cursor, end)
    if cursor < horizon:
        expected.append([base + cursor, base + horizon])
    assert labels["normal_ranges"] == expected


def test_ips_come_only_from_documentation_ranges(tmp_path: Path) -> None:
    out = _generate(tmp_path)
    text = (out / "corpus.jsonl").read_text(encoding="utf-8")
    found = IPv4_RE.findall(text)
    assert len(found) >= 30
    prefixes = set()
    for ip in found:
        octets = ip.split(".")
        assert all(o.isdigit() and int(o) <= 255 for o in octets)
        prefix = ".".join(octets[:3]) + "."
        assert prefix in DOC_PREFIXES, f"non-documentation IP {ip}"
        prefixes.add(prefix)
    assert len(prefixes) >= 2


def test_dotted_names_within_invented_allowlist(tmp_path: Path) -> None:
    out = _generate(tmp_path)
    text = (out / "corpus.jsonl").read_text(encoding="utf-8")
    candidates = {m.lower() for m in DOTTED_TOKEN_RE.findall(text)}
    allowed = {h.lower() for h in gen_corpus.ALLOWED_DOT_TOKENS}
    stray = candidates - allowed
    assert not stray, f"dotted names outside the invented allowlist: {sorted(stray)}"
    assert candidates & allowed


def test_two_runs_same_seed_are_byte_identical(tmp_path: Path) -> None:
    one = _generate(tmp_path / "a", lines=1200, seed=42)
    two = tmp_path / "b" / "fixture"
    rc = gen_corpus.main(["--out", str(two), "--lines", "1200", "--seed", "42"])
    assert rc == 0
    for name in ("corpus.jsonl", "labels.json"):
        assert (one / name).read_bytes() == (two / name).read_bytes(), name


def test_different_seed_changes_output(tmp_path: Path) -> None:
    one = _generate(tmp_path / "s1", lines=800, seed=1)
    two = _generate(tmp_path / "s2", lines=800, seed=2)
    assert (one / "corpus.jsonl").read_bytes() != (two / "corpus.jsonl").read_bytes()


def test_rejects_lines_below_reserved_budget(tmp_path: Path) -> None:
    rc = gen_corpus.main(["--out", str(tmp_path / "tiny"), "--lines", "10"])
    assert rc == 2


def test_line_emitters_format_correctness() -> None:
    rng = random.Random(99)
    ts = gen_corpus.BASE_EPOCH + 40_000
    for fam in gen_corpus.APP_FAMILIES + (gen_corpus.FAM_PURGE,):
        for level in ("info", "error"):
            json_line = gen_corpus.emit_app(fam, ts, level, "json", rng,
                                            gen_corpus.NORMAL_DURATION_MS)
            obj = json.loads(json_line)
            assert obj["timestamp"].endswith("Z")
            assert obj["level"] == level
            assert obj["service"] == fam.service
            assert isinstance(obj["message"], str) and obj["message"]
            logfmt_line = gen_corpus.emit_app(fam, ts, level, "logfmt", rng,
                                              gen_corpus.NORMAL_DURATION_MS)
            tokens = _split_logfmt(logfmt_line)
            assert all(LOGFMT_TOKEN_RE.match(tok) or tok.startswith('msg="')
                       for tok in tokens)
            head = dict(tok.split("=", 1) for tok in tokens[:4])
            assert set(head) == {"timestamp", "level", "service", "msg"}
            assert head["service"] == fam.service and head["level"] == level
    for fam in gen_corpus.ACCESS_FAMILIES:
        line = gen_corpus.emit_access(fam, ts, rng)
        assert ACCESS_SHAPE_RE.match(line), line
        assert IPv4_RE.match(line).group(0).startswith(DOC_PREFIXES)
    for fam in gen_corpus.SYSLOG_FAMILIES:
        line = gen_corpus.emit_syslog(fam, ts, rng)
        assert SYSLOG_SHAPE_RE.match(line), line
        host = line.split(" ")[3]
        assert host in gen_corpus.HOSTS


def test_rare_sequence_families_are_established_and_distinct() -> None:
    specials = {id(gen_corpus.FAM_SPIKE), id(gen_corpus.FAM_STOPPED)}
    trio = (gen_corpus.FAM_SEQ_A, gen_corpus.FAM_SEQ_B, gen_corpus.FAM_SEQ_C)
    assert len({f.fid for f in trio}) == 3
    for f in trio:
        assert f in gen_corpus.APP_FAMILIES
        assert id(f) not in specials

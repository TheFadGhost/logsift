"""CLI end-to-end: run headless, query, summary, config validate, hooks test."""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logsift.cli import EXIT_CONFIG_INVALID, EXIT_OK, main


def _write_stream(path: Path) -> None:
    base = 1772323200.0
    lines = []
    for i in range(4000):
        ts = base + i * 6.0
        hh = int(ts % 86400 // 3600)
        mm = int(ts % 3600 // 60)
        ss = int(ts % 60)
        iso = f"2026-03-01T{hh:02d}:{mm:02d}:{ss:02d}Z"
        if i < 2000:
            lines.append(f"timestamp={iso} level=info service=auth msg=\"login ok user u-{i % 50}\"")
        elif i < 3000:
            lines.append(f"timestamp={iso} level=error service=auth msg=\"login refused user u-{i % 50}\"")
        else:
            surge = "error" if (i - 3000) < 60 else "info"
            lines.append(
                f'{{"timestamp":"{iso}","level":"{surge}","service":"pay",'
                f'"message":"charge captured order od-{i} amount {i % 9 + 1} eur"}}'
            )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_headless_run_emits_jsonl_alerts(tmp_path, capsys, monkeypatch):
    stream = tmp_path / "s.log"
    _write_stream(stream)
    rc = main(["run", str(stream), "--headless", "--exit-on-eof", "--warmup", "120"])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    payloads = [json.loads(line) for line in out.splitlines() if line.strip()]
    assert payloads, "expected at least one JSONL alert"
    for p in payloads:
        assert p["schema"] == "logsift.alert/1"
        assert "\x1b[" not in out  # never coloured


def test_query_aggregate_and_filter(tmp_path, capsys):
    stream = tmp_path / "s.log"
    _write_stream(stream)
    rc = main(["query", str(stream), "--aggregate", "level"])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "info" in out and "error" in out
    capsys.readouterr()
    rc = main(["query", str(stream), "--level", "error", "--limit", "5"])
    assert rc == EXIT_OK
    lines = [l for l in capsys.readouterr().out.splitlines() if l.strip()]
    assert lines[0].startswith("matched")
    assert len(lines) <= 7


def test_query_histogram_runs(tmp_path, capsys):
    stream = tmp_path / "s.log"
    _write_stream(stream)
    rc = main(["query", str(stream), "--histogram", "--bucket-seconds", "3600"])
    assert rc == EXIT_OK
    assert capsys.readouterr().out.count("\n") > 3


def test_summary_reports_counts_and_alerts(tmp_path, capsys):
    stream = tmp_path / "s.log"
    _write_stream(stream)
    rc = main(["summary", str(stream)])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "Logsift summary" in out
    assert "lines:" in out
    assert "alerts in window:" in out


def test_config_validate_rejects_bad_theme(tmp_path, capsys):
    cfg_path = tmp_path / "logsift.toml"
    cfg_path.write_text('theme = "neon"\n', encoding="utf-8")
    rc = main(["config", "validate", "--file", str(cfg_path)])
    assert rc == EXIT_CONFIG_INVALID
    assert "theme" in capsys.readouterr().err


def test_config_validate_accepts_good_file(tmp_path, capsys):
    cfg_path = tmp_path / "logsift.toml"
    cfg_path.write_text(
        'theme = "dark"\nwarmup_seconds = 600\n[detectors]\nvolume_anomalous_z = 6.0\n',
        encoding="utf-8",
    )
    rc = main(["config", "validate", "--file", str(cfg_path)])
    assert rc == EXIT_OK
    assert "valid" in capsys.readouterr().out


def test_hooks_test_dry_run_with_exec_hook(tmp_path, capsys):
    cfg_path = tmp_path / "hooks.toml"
    receiver = tmp_path / "recv.py"
    receiver.write_text(
        "import sys\nsys.stdout.write(sys.stdin.read())\n",
        encoding="utf-8",
    )
    quoted = json.dumps(str(receiver))
    cfg_path.write_text(
        "[[hooks]]\ntype = \"exec\"\nargv = [" + quoted.replace("\\", "\\\\") + ", \"x\"]\ndry_run = true\n",
        encoding="utf-8",
    )
    rc = main(["hooks", "test", "--config", str(cfg_path)])
    assert rc == EXIT_OK
    assert "dry-run" in capsys.readouterr().out


def test_missing_input_file_is_actionable():
    rc = main(["replay", "Z:/no/such/file.log"])
    assert rc == 1


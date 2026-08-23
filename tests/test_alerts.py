"""AlertManager, sinks and hooks: throttling, escalation, incidents, safety."""

from __future__ import annotations

import io
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from logsift.alerts import (
    AlertManager,
    ExecHook,
    HookResult,
    JsonlSink,
    WebhookHook,
)
from logsift.clock import FakeClock
from logsift.events import Alert, Severity, iso_utc

T0 = FakeClock.DEFAULT_START
INCIDENT_RE = re.compile(r"t\d+-\d+")


def _alert(
    ts: float = T0,
    detector: str = "volume",
    severity: Severity = Severity.CRITICAL,
    template_id: int | None = 42,
    group_key: str | None = None,
    template_text: str = "user <*> login failed",
) -> Alert:
    return Alert(
        detector=detector,
        severity=severity,
        template_id=template_id,
        template_text=template_text,
        baseline_desc="median 12/hr for slot Mon 03:00 over 26 slots",
        baseline_value=12.0,
        observed_desc="310 events in bucket 03:00-04:00",
        observed_value=310.0,
        deviation_desc="25.8x baseline",
        z=14.2,
        threshold_desc="robust z > 6.0 and observed >= 5",
        threshold_value=6.0,
        window_start=ts - 3600.0,
        window_end=ts,
        group_key=group_key or f"{detector}:t{template_id}",
        event_time=ts,
    )


class RecordingSink:
    def __init__(self) -> None:
        self.payloads: list[dict] = []

    def emit(self, payload: dict) -> None:
        self.payloads.append(payload)


class CountingStream:
    def __init__(self) -> None:
        self._buf = io.StringIO()
        self.flushes = 0

    def write(self, text: str) -> int:
        return self._buf.write(text)

    def flush(self) -> None:
        self.flushes += 1
        self._buf.flush()

    def value(self) -> str:
        return self._buf.getvalue()


class RecordingHook:
    def __init__(self, ok: bool = True, detail: str = "ok") -> None:
        self.calls: list[dict] = []
        self._ok = ok
        self._detail = detail

    def deliver(self, payload: dict) -> HookResult:
        self.calls.append(payload)
        return HookResult(ok=self._ok, detail=self._detail)


ECHO_STDIN_SCRIPT = """\
import sys
with open(sys.argv[1], "w", encoding="utf-8") as marker:
    marker.write("ran")
data = sys.stdin.buffer.read()
with open(sys.argv[2], "wb") as out:
    out.write(data)
sys.stdout.buffer.write(data)
"""

HOSTILE_TEMPLATE = (
    'user `id` $(whoami); rm -rf / && echo "pwned" || \'quoted\' ; '
    "%PATH% | & \nsecond line\ttabbed \x1b[31mansi\x1b[0m end"
)


# --- burst / throttle ---------------------------------------------------------


def test_burst_of_1000_emits_once_then_summary_after_window():
    clock = FakeClock()
    sink = RecordingSink()
    mgr = AlertManager(clock, sink=sink)

    payloads = [mgr.submit(_alert(ts=clock.now())) for _ in range(1000)]
    assert sum(p is not None for p in payloads) == 1
    first = payloads[0]
    assert first is not None
    assert first["count"] == 1
    assert first["suppressed"] == 0
    assert mgr.stats() == {
        "emitted": 1,
        "suppressed": 999,
        "groups_active": 1,
        "hook_failures": 0,
    }

    clock.advance(300.5)
    summary = mgr.submit(_alert(ts=clock.now()))
    assert summary is not None
    assert summary["count"] == 1001
    assert summary["suppressed"] == 999
    assert summary["first_seen"] == first["first_seen"]
    stats = mgr.stats()
    assert stats["emitted"] == 2
    assert stats["suppressed"] == 999
    assert stats["groups_active"] == 1

    clock.advance(10.0)
    assert mgr.submit(_alert(ts=clock.now())) is None
    stats = mgr.stats()
    assert stats["suppressed"] == 1000


def test_throttle_window_boundary_is_lazy_at_next_submit():
    clock = FakeClock()
    sink = RecordingSink()
    mgr = AlertManager(clock, sink=sink)
    first = mgr.submit(_alert(ts=T0))
    assert first is not None

    clock.advance(290.0)
    assert mgr.submit(_alert(ts=clock.now())) is None
    clock.advance(9.9)
    assert mgr.submit(_alert(ts=clock.now())) is None
    clock.advance(0.1)
    at_expiry = mgr.submit(_alert(ts=clock.now()))
    assert at_expiry is not None
    assert at_expiry["count"] == 4
    assert at_expiry["suppressed"] == 2
    assert len(sink.payloads) == 2


def test_first_alert_of_each_group_emits_with_monotonic_ids():
    clock = FakeClock()
    sink = RecordingSink()
    mgr = AlertManager(clock, sink=sink)
    p1 = mgr.submit(_alert(detector="volume", template_id=1))
    p2 = mgr.submit(_alert(detector="error_rate", template_id=1))
    p3 = mgr.submit(_alert(detector="volume", template_id=2))
    assert p1 is not None and p2 is not None and p3 is not None
    assert [p["id"] for p in sink.payloads] == ["a-000001", "a-000002", "a-000003"]
    assert mgr.stats()["groups_active"] == 3


# --- escalation ----------------------------------------------------------------


def test_severity_escalation_mid_window_emits_immediately():
    clock = FakeClock()
    sink = RecordingSink()
    mgr = AlertManager(clock, sink=sink)

    seq = [
        (Severity.ELEVATED, True),
        (Severity.ANOMALOUS, True),
        (Severity.ANOMALOUS, False),
        (Severity.CRITICAL, True),
        (Severity.CRITICAL, False),
        (Severity.NORMAL, False),
    ]
    for offset, (severity, should_emit) in enumerate(seq):
        clock.advance(10.0)
        payload = mgr.submit(_alert(ts=clock.now(), severity=severity))
        assert (payload is not None) == should_emit, f"step {offset} ({severity.value})"
        if payload is not None:
            assert payload["severity"] == severity.value

    stats = mgr.stats()
    assert stats["emitted"] == 3
    assert stats["suppressed"] == 3
    assert [p["severity"] for p in sink.payloads] == ["elevated", "anomalous", "critical"]


# --- incident correlation --------------------------------------------------------


def test_incident_same_template_two_detectors_share_id():
    clock = FakeClock()
    mgr = AlertManager(clock)

    p1 = mgr.submit(_alert(ts=T0, detector="volume", template_id=7))
    assert p1 is not None
    assert p1["incident"] is None

    clock.advance(30.0)
    p2 = mgr.submit(_alert(ts=clock.now(), detector="error_rate", template_id=7))
    assert p2 is not None
    assert p2["incident"] is not None
    assert INCIDENT_RE.fullmatch(p2["incident"])
    assert p1["incident"] == p2["incident"]

    clock.advance(30.0)
    p3 = mgr.submit(_alert(ts=clock.now(), detector="rare_sequence", template_id=7))
    assert p3 is not None
    assert p3["incident"] == p2["incident"]

    other = mgr.submit(_alert(ts=clock.now(), detector="volume", template_id=8))
    assert other is not None
    assert other["incident"] is None


def test_incident_suppressed_alerts_still_correlate():
    clock = FakeClock()
    sink = RecordingSink()
    mgr = AlertManager(clock, sink=sink)

    p1 = mgr.submit(_alert(ts=T0, detector="volume", template_id=9))
    assert p1 is not None
    for _ in range(50):
        clock.advance(1.0)
        assert mgr.submit(_alert(ts=clock.now(), detector="volume", template_id=9)) is None

    clock.advance(9.0)
    p2 = mgr.submit(_alert(ts=clock.now(), detector="numeric_shift", template_id=9))
    assert p2 is not None
    assert p2["incident"] is not None
    assert p1["incident"] == p2["incident"]
    assert all(p["incident"] == p2["incident"] for p in sink.payloads)


def test_incident_new_cluster_after_silence_gets_fresh_deterministic_id():
    clock = FakeClock()
    mgr = AlertManager(clock)

    a1 = mgr.submit(_alert(ts=T0, detector="volume", template_id=11))
    clock.advance(60.0)
    b1 = mgr.submit(_alert(ts=clock.now(), detector="new_template", template_id=11))
    assert a1 is not None and b1 is not None
    old_incident = b1["incident"]
    assert old_incident is not None
    assert a1["incident"] == old_incident
    assert old_incident == f"t11-{int(T0 // 120)}"

    clock.advance(250.0)
    c1 = mgr.submit(_alert(ts=clock.now(), detector="volume", template_id=11))
    clock.advance(10.0)
    c2 = mgr.submit(_alert(ts=clock.now(), detector="stopped_template", template_id=11))
    assert c1 is not None and c2 is not None
    assert c2["incident"] is not None
    assert c2["incident"] != old_incident
    assert c1["incident"] == c2["incident"]
    assert c2["incident"] == f"t11-{int((T0 + 310.0) // 120)}"


def test_alert_without_template_id_never_gets_incident():
    clock = FakeClock()
    mgr = AlertManager(clock)
    p1 = mgr.submit(_alert(ts=T0, detector="volume", template_id=None))
    p2 = mgr.submit(_alert(ts=T0 + 1.0, detector="error_rate", template_id=None))
    assert p1 is not None and p2 is not None
    assert p1["incident"] is None and p2["incident"] is None


# --- evidence enrichment ----------------------------------------------------------


def test_evidence_lookup_enriches_emitted_payloads_only():
    clock = FakeClock()
    calls: list[Alert] = []

    def lookup(alert: Alert) -> tuple[list[str], list[str]]:
        calls.append(alert)
        return ([f"example of {alert.detector}"], ["raw line before"])

    mgr = AlertManager(clock, evidence_lookup=lookup)
    p1 = mgr.submit(_alert(ts=T0, template_id=21))
    assert mgr.submit(_alert(ts=T0 + 1.0, template_id=21)) is None
    assert p1 is not None
    assert p1["examples"] == ["example of volume"]
    assert p1["evidence_before"] == ["raw line before"]
    assert len(calls) == 1


# --- JsonlSink --------------------------------------------------------------------


def test_jsonl_sink_parses_matches_schema_plus_added_keys_never_coloured():
    clock = FakeClock()
    stream = CountingStream()
    mgr = AlertManager(clock, sink=JsonlSink(stream))

    a1 = _alert(ts=T0, detector="volume", template_id=31)
    p1 = mgr.submit(a1)
    assert mgr.submit(_alert(ts=T0 + 1.0, detector="volume", template_id=31)) is None
    p2 = mgr.submit(_alert(ts=T0 + 2.0, detector="error_rate", template_id=32))
    clock.advance(400.0)
    p3 = mgr.submit(_alert(ts=clock.now(), detector="volume", template_id=31))

    raw = stream.value()
    assert "\x1b" not in raw
    lines = raw.splitlines()
    assert len(lines) == 3
    assert stream.flushes == 3
    parsed = [json.loads(line) for line in lines]
    assert parsed == [p1, p2, p3]
    assert [p["id"] for p in parsed] == ["a-000001", "a-000002", "a-000003"]

    base_keys = set(a1.to_json_dict().keys())
    for got in parsed:
        assert base_keys <= set(got.keys())
        assert "incident" in got

    third = parsed[2]
    assert third["count"] == 3
    assert third["suppressed"] == 1
    assert third["first_seen"] == iso_utc(T0)
    for key in ("schema", "severity", "marker", "detector", "template", "group_key"):
        assert third[key] == a1.to_json_dict()[key]


# --- exec hook: injection safety -----------------------------------------------------


def test_exec_hook_passes_hostile_payload_verbatim_via_stdin(tmp_path: Path):
    script = tmp_path / "echo_stdin.py"
    script.write_text(ECHO_STDIN_SCRIPT, encoding="utf-8")
    marker = tmp_path / "marker.txt"
    outfile = tmp_path / "stdin_copy.bin"

    hook = ExecHook([sys.executable, str(script), str(marker), str(outfile)], timeout_s=30.0)
    mgr = AlertManager(FakeClock(), hooks=[hook])
    alert = _alert(template_text=HOSTILE_TEMPLATE, template_id=13)
    payload = mgr.submit(alert)

    assert payload is not None
    assert payload["template"] == HOSTILE_TEMPLATE
    assert marker.read_text(encoding="utf-8") == "ran"
    expected = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    assert outfile.read_bytes() == expected
    assert json.loads(outfile.read_bytes().decode("utf-8")) == payload
    assert mgr.stats()["hook_failures"] == 0


# --- exec hook: failures and dry-run --------------------------------------------------


def test_exec_hook_nonzero_exit_and_missing_command_reported_not_raised():
    exit3 = ExecHook([sys.executable, "-c", "import sys; sys.exit(3)"], timeout_s=30.0)
    res = exit3.deliver({"probe": True})
    assert res.ok is False
    assert "exit 3" in res.detail

    missing = ExecHook(["logsift-no-such-command-xyz"], timeout_s=30.0)
    res = missing.deliver({"probe": True})
    assert res.ok is False
    assert res.detail.startswith("exec:")


def test_exec_hook_dry_run_prints_truncated_preview_and_never_executes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    script = tmp_path / "echo_stdin.py"
    script.write_text(ECHO_STDIN_SCRIPT, encoding="utf-8")
    marker = tmp_path / "marker.txt"
    outfile = tmp_path / "stdin_copy.bin"
    hook = ExecHook([sys.executable, str(script), str(marker), str(outfile)], dry_run=True)

    payload = _alert(template_text="A" * 3000, template_id=14).to_json_dict()
    result = hook.deliver(payload)

    assert result.ok is True
    assert result.detail == "dry-run"
    out = capsys.readouterr().out
    assert "[dry-run]" in out
    assert "A" * 1500 in out
    assert "A" * 2500 not in out
    assert not marker.exists()
    assert not outfile.exists()


# --- webhook hook ----------------------------------------------------------------------


def test_webhook_dry_run_prints_preview_and_performs_no_network_call(
    capsys: pytest.CaptureFixture[str], monkeypatch
):
    def explode(*args, **kwargs):
        raise AssertionError("network call attempted")

    monkeypatch.setattr(urllib.request, "urlopen", explode)
    hook = WebhookHook("http://127.0.0.1:9/hooks/logsift", dry_run=True)
    payload = _alert(ts=T0).to_json_dict()
    result = hook.deliver(payload)

    assert result.ok is True
    assert result.detail == "dry-run"
    out = capsys.readouterr().out
    assert "http://127.0.0.1:9/hooks/logsift" in out
    assert '"severity": "critical"' in out
    assert "[dry-run]" in out


def test_hook_failures_captured_in_stats_and_submit_unbroken(monkeypatch):
    def refuse(*args, **kwargs):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    clock = FakeClock()
    sink = RecordingSink()
    failing_exec = ExecHook([sys.executable, "-c", "import sys; sys.exit(7)"], timeout_s=30.0)
    bad_url = WebhookHook("http://logsift.invalid/hook")
    quiet = RecordingHook()

    mgr = AlertManager(clock, sink=sink, hooks=[failing_exec, bad_url, quiet])

    payload = mgr.submit(_alert(ts=T0))
    assert payload is not None
    assert len(sink.payloads) == 1
    assert quiet.calls and quiet.calls[0] is payload
    stats = mgr.stats()
    assert stats["emitted"] == 1
    assert stats["hook_failures"] == 2

    suppressed = mgr.submit(_alert(ts=T0 + 1.0))
    assert suppressed is None
    assert len(quiet.calls) == 1
    stats = mgr.stats()
    assert stats["suppressed"] == 1
    assert stats["hook_failures"] == 2


def test_exception_inside_hook_deliver_is_swallowed_by_manager():
    class ExplodingHook:
        def deliver(self, payload: dict) -> HookResult:
            raise RuntimeError("boom")

    sink = RecordingSink()
    mgr = AlertManager(FakeClock(), sink=sink, hooks=[ExplodingHook()])
    payload = mgr.submit(_alert(ts=T0))
    assert payload is not None
    assert len(sink.payloads) == 1
    assert mgr.stats()["hook_failures"] == 1

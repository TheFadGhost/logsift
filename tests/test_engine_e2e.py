"""End-to-end engine properties: replay determinism, alert schema conformance."""

from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from logsift.cli import _StreamEnd  # noqa: E402
from logsift.config import Config  # noqa: E402
from logsift.engine import Engine  # noqa: E402
from logsift.clock import SystemClock  # noqa: E402
from logsift.events import DETECTORS, SEVERITY_ORDER  # noqa: E402
from logsift.sources import FileFollowSource  # noqa: E402


def _raise_end(_seconds: float) -> None:
    raise _StreamEnd


def _replay(path: Path, warmup: float = 600.0) -> tuple[list[dict], Engine]:
    cfg = Config(max_events=50_000, warmup_seconds=warmup)
    clock = SystemClock()
    source = FileFollowSource(
        path, poll_interval=cfg.poll_interval_s, clock=clock, sleeper=_raise_end
    )
    engine = Engine(cfg, clock, provider=None, source_name=path.name, eof_exceptions=(_StreamEnd,))
    try:
        engine.run_source(source)
    except _StreamEnd:
        pass
    return [a.to_json_dict() for a in engine.recent_alerts()], engine


def _make_stream(path: Path) -> None:
    """Deterministic mixed stream with one injected volume spike."""
    lines = []
    base = 1772323200.0  # 2026-03-01T00:00:00Z
    months = {59: "Feb", 60: "Mar", 61: "Mar", 90: "Mar", 91: "Apr"}
    for i in range(30_000):
        ts = base + i * 6.0
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        iso = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        yday = dt.timetuple().tm_yday
        month = months.get(yday, dt.strftime("%b"))
        day = dt.day
        fam = i % 5
        if 24000 <= i < 24300:
            # Volume surge on an ESTABLISHED template: 300 extra charge
            # events inside one hour against a flat baseline.
            lines.append(
                f'{{"timestamp":"{iso}","level":"info","service":"pay",'
                f'"message":"charge captured order od-{100000 + i} amount {i % 80 + 1} eur"}}'
            )
            lines.append(
                f'{{"timestamp":"{iso}","level":"info","service":"pay",'
                f'"message":"charge captured order od-{200000 + i} amount {i % 80 + 1} eur"}}'
            )
            continue
        if fam == 0:
            lines.append(f"timestamp={iso} level=info service=auth msg=\"login ok user u-{i % 991}\"")
        elif fam == 1:
            lines.append(
                f'{{"timestamp":"{iso}","level":"info","service":"pay",'
                f'"message":"charge captured order od-{i % 997} amount {i % 80 + 1} eur"}}'
            )
        elif fam == 2:
            lines.append(
                f"{month} {day:02d} {dt.strftime('%H:%M:%S')} host-alpha workerd[77]: "
                f"job {i % 313} finished in {30 + i % 70} ms exit 0"
            )
        elif fam == 3:
            lines.append(
                f'192.0.2.{i % 250} - - [{day_stamp(ts)}] "GET /api/items/{i % 89} HTTP/1.1" 200 {100 + i % 900}'
            )
        else:
            lines.append(f"timestamp={iso} level=error service=auth msg=\"login refused user u-{i % 991}\"")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def day_stamp(ts: float) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return (
        f"{dt.day:02d}/{dt.strftime('%b')}/{dt.year}:"
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"
    )


def day_stamp_month(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%b")


def test_replay_is_deterministic(tmp_path):
    stream = tmp_path / "stream.log"
    _make_stream(stream)
    alerts_a, _ = _replay(stream)
    alerts_b, _ = _replay(stream)
    assert len(alerts_a) == len(alerts_b)
    for a, b in zip(alerts_a, alerts_b):
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


_REQUIRED_KEYS = {
    "schema",
    "id",
    "time",
    "severity",
    "marker",
    "detector",
    "template_id",
    "template",
    "baseline",
    "observed",
    "deviation",
    "threshold",
    "window",
    "group_key",
    "count",
    "suppressed",
    "first_seen",
    "examples",
    "evidence_before",
}

_ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")
_MARKERS = {"normal": ".", "elevated": "+", "anomalous": "!", "critical": "!!"}


def test_alert_payloads_conform_to_documented_schema(tmp_path):
    stream = tmp_path / "stream.log"
    _make_stream(stream)
    alerts, _ = _replay(stream)
    assert alerts, "expected at least one alert from the injected spike"
    seen_detectors = set()
    for alert in alerts:
        missing = _REQUIRED_KEYS - set(alert)
        assert not missing, f"missing keys {missing}"
        extra = set(alert) - _REQUIRED_KEYS - {"incident"}
        assert not extra, f"undocumented keys {extra}"
        assert alert["schema"] == "logsift.alert/1"
        assert alert["severity"] in SEVERITY_ORDER
        assert alert["marker"] == _MARKERS[alert["severity"]]
        assert alert["detector"] in DETECTORS
        assert _ISO_RE.match(alert["time"]), alert["time"]
        assert _ISO_RE.match(alert["window"]["start"])
        assert _ISO_RE.match(alert["window"]["end"])
        assert isinstance(alert["count"], int) and alert["count"] >= 1
        assert isinstance(alert["suppressed"], int) and alert["suppressed"] >= 0
        for section in ("baseline", "observed", "threshold"):
            assert isinstance(alert[section]["desc"], str) and alert[section]["desc"]
        assert isinstance(alert["examples"], list)
        seen_detectors.add(alert["detector"])
    # The injected spike must be caught by the volume detector with a full explanation.
    volume = [a for a in alerts if a["detector"] == "volume"]
    assert volume, "volume detector missed the injected spike"
    v = volume[0]
    assert v["baseline"]["value"] is not None
    assert v["observed"]["value"] is not None
    assert v["deviation"]["z"] is not None
    assert "z" in v["threshold"]["desc"] or "robust" in v["threshold"]["desc"]




"""Discrete detectors: new_template, stopped_template, rare_sequence.

FakeClock only; hand-built Events with explicit template ids/texts and a real
BaselineStore for context.
"""

from __future__ import annotations

from typing import Callable

from logsift.baselines import BaselineStore
from logsift.clock import Clock, FakeClock
from logsift.detectors.base import BaseDetector, DetectorConfig, DetectorContext
from logsift.detectors.new_template import NewTemplateDetector
from logsift.detectors.rare_sequence import RareSequenceDetector
from logsift.detectors.stopped_template import StoppedTemplateDetector
from logsift.events import Alert, Event, Severity

HOUR = 3600.0
WEEK = 168 * HOUR
START = FakeClock.DEFAULT_START  # 2026-01-01T00:00:00Z, a Thursday


class _Gate:
    def __init__(self) -> None:
        self.done = False

    def __call__(self) -> bool:
        return self.done


def _ctx(
    clock: Clock, store: BaselineStore, gate: _Gate, cfg: DetectorConfig | None = None
) -> DetectorContext:
    return DetectorContext(
        clock=clock,
        baselines=store,
        warmup_complete=gate.__call__,
        config=cfg if cfg is not None else DetectorConfig(),
    )


def _ev(ts: float, tid: int, text: str) -> Event:
    return Event(ts=ts, message=text, template_id=tid, template_text=text)


def _check_schema(alerts: list[Alert], det_id: str) -> None:
    assert alerts, f"expected alerts from {det_id}"
    for a in alerts:
        assert a.detector == det_id
        assert a.severity.value in ("normal", "elevated", "anomalous", "critical")
        assert isinstance(a.baseline_desc, str) and a.baseline_desc
        assert isinstance(a.observed_desc, str) and a.observed_desc
        assert isinstance(a.deviation_desc, str) and a.deviation_desc
        assert isinstance(a.threshold_desc, str) and a.threshold_desc
        assert a.template_text
        assert a.group_key.startswith(det_id + ":")
        assert a.window_start <= a.window_end
        assert a.examples == []


def _drain(det: BaseDetector, clock: FakeClock) -> list[Alert]:
    return det.tick(clock.now())


# --------------------------------------------------------------------------- new


def test_new_template_silent_during_warmup_then_fires_once() -> None:
    clock = FakeClock()
    gate = _Gate()
    det = NewTemplateDetector(_ctx(clock, BaselineStore(clock), gate))
    for i in range(5):
        det.observe(_ev(clock.now(), 1, "boot ok"), clock.now())
        clock.advance(1.0)
    gate.done = True
    det.observe(_ev(clock.now(), 2, "quantum flux engaged"), clock.now())
    assert _drain(det, clock) == []
    clock.advance(61.0)
    alerts = _drain(det, clock)
    _check_schema(alerts, "new_template")
    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity is Severity.ELEVATED
    assert a.template_id == 2
    assert a.group_key == "new_template:quantum flux engaged"
    assert "not present in baseline history" in a.baseline_desc
    for _ in range(3):
        det.observe(_ev(clock.now(), 2, "quantum flux engaged"), clock.now())
        clock.advance(1.0)
    clock.advance(61.0)
    assert _drain(det, clock) == []
    det.observe(_ev(clock.now(), 3, "second novel line"), clock.now())
    clock.advance(61.0)
    again = _drain(det, clock)
    _check_schema(again, "new_template")
    assert len(again) == 1
    assert again[0].template_text == "second novel line"


def test_new_template_burst_becomes_anomalous() -> None:
    clock = FakeClock()
    gate = _Gate()
    gate.done = True
    det = NewTemplateDetector(_ctx(clock, BaselineStore(clock), gate))
    for i in range(20):
        det.observe(_ev(clock.now(), 9, "flood line"), clock.now())
        clock.advance(1.0)
    alerts = _drain(det, clock)
    _check_schema(alerts, "new_template")
    assert len(alerts) == 1
    assert alerts[0].severity is Severity.ANOMALOUS
    assert alerts[0].observed_value == 20.0


def test_new_template_lru_eviction_allows_refire() -> None:
    clock = FakeClock()
    gate = _Gate()
    gate.done = True
    det = NewTemplateDetector(_ctx(clock, BaselineStore(clock), gate), lru_cap=2)
    seen_texts: list[str] = []
    for text in ["alpha", "beta", "gamma", "alpha", "gamma"]:
        det.observe(_ev(clock.now(), 1, text), clock.now())
        clock.advance(61.0)
        for a in _drain(det, clock):
            seen_texts.append(a.template_text)
    assert seen_texts == ["alpha", "beta", "gamma", "alpha"]


def test_new_template_grace_absorbs_settling_noise() -> None:
    clock = FakeClock()
    gate = _Gate()
    cfg = DetectorConfig(new_template_grace_s=30.0)
    det = NewTemplateDetector(_ctx(clock, BaselineStore(clock), gate, cfg))
    det.observe(_ev(clock.now(), 1, "warm noise"), clock.now())
    clock.advance(1.0)
    gate.done = True
    det.observe(_ev(clock.now(), 4, "grace ghost"), clock.now())
    clock.advance(40.0)
    det.observe(_ev(clock.now(), 5, "real newcomer"), clock.now())
    clock.advance(61.0)
    alerts = _drain(det, clock)
    _check_schema(alerts, "new_template")
    assert len(alerts) == 1
    assert alerts[0].template_text == "real newcomer"
    clock.advance(200.0)
    assert _drain(det, clock) == []


# ----------------------------------------------------------------------- stopped


def _feed_beats(
    det: StoppedTemplateDetector, clock: FakeClock, beats: int, text: str, tid: int
) -> None:
    for i in range(beats):
        if i:
            clock.advance(60.0)
        det.observe(_ev(clock.now(), tid, text), clock.now())


def test_stopped_template_fires_after_gap_and_rearms() -> None:
    q = START + 27 * HOUR  # Friday 03:00
    last_seen = q - 1800.0  # Friday 02:30
    first = last_seen - 239 * 60.0
    clock = FakeClock(start=first)
    store = BaselineStore(clock)
    gate = _Gate()
    gate.done = True
    det = StoppedTemplateDetector(_ctx(clock, store, gate))
    text = "heartbeat ok"
    key = f"volume:{text}"
    for base in (q, last_seen):
        for wk in (1, 2, 3):
            store.observe_volume(key, base - wk * WEEK, 120)
    for i in range(240):
        if i:
            clock.advance(60.0)
        det.observe(_ev(clock.now(), 7, text), clock.now())
        if i < 5:
            det.observe(_ev(clock.now(), 8, "chatter"), clock.now())
    assert clock.now() == last_seen
    clock.advance(400.0)
    assert _drain(det, clock) == []
    clock.advance(1400.0)
    assert clock.now() == q
    alerts = _drain(det, clock)
    _check_schema(alerts, "stopped_template")
    assert len(alerts) == 1
    a = alerts[0]
    assert abs((a.baseline_value or 0.0) - 60.0) < 1e-9
    assert abs((a.threshold_value or 0.0) - 300.0) < 1e-9
    assert a.severity is Severity.CRITICAL
    assert a.window_start == last_seen
    assert a.group_key == f"stopped_template:{text}"
    assert "0 occurrences" in a.observed_desc
    clock.advance(30.0)
    assert _drain(det, clock) == []
    clock.advance(60.0)
    det.observe(_ev(clock.now(), 7, text), clock.now())
    clock.advance(1800.0)
    resumed = _drain(det, clock)
    _check_schema(resumed, "stopped_template")
    assert len(resumed) == 1
    clock.advance(3600.0)
    assert _drain(det, clock) == []


def test_stopped_template_low_count_never_fires_and_fallback_rate_used() -> None:
    clock = FakeClock()
    store = BaselineStore(clock)
    gate = _Gate()
    gate.done = True
    cfg = DetectorConfig(
        stopped_min_history=6,
        stopped_gap_factor=3.0,
        stopped_min_expected=1,
    )
    det = StoppedTemplateDetector(_ctx(clock, store, gate, cfg))
    _feed_beats(det, clock, 12, "chatty trace", 3)
    _feed_beats(det, clock, 5, "lonely whisper", 4)
    clock.advance(100000.0)
    alerts = _drain(det, clock)
    assert all(a.template_text != "lonely whisper" for a in alerts)


def test_stopped_template_uses_observed_mean_when_no_baseline() -> None:
    clock = FakeClock()
    store = BaselineStore(clock)
    gate = _Gate()
    gate.done = True
    cfg = DetectorConfig(
        stopped_min_history=6,
        stopped_gap_factor=3.0,
        stopped_min_expected=1,
    )
    det = StoppedTemplateDetector(_ctx(clock, store, gate, cfg))
    _feed_beats(det, clock, 12, "orphan rhythm", 5)
    clock.advance(300.0)
    alerts = _drain(det, clock)
    _check_schema(alerts, "stopped_template")
    assert len(alerts) == 1
    assert "observed mean" in alerts[0].baseline_desc


# ------------------------------------------------------------------ rare_sequence


def _cycle(
    det: RareSequenceDetector,
    clock: FakeClock,
    ids: list[int],
    repeats: int,
    dt: float = 0.1,
) -> None:
    for _ in range(repeats):
        for tid in ids:
            clock.advance(dt)
            det.observe(_ev(clock.now(), tid, f"text {tid}"), clock.now())


def test_rare_sequence_learns_common_loops_and_fires_on_novel_repeat() -> None:
    clock = FakeClock()
    store = BaselineStore(clock)
    gate = _Gate()
    cfg = DetectorConfig()
    det = RareSequenceDetector(_ctx(clock, store, gate, cfg))
    _cycle(det, clock, [1, 2, 3], 300)
    gate.done = True
    _cycle(det, clock, [4, 5, 6], 3)
    alerts = _drain(det, clock)
    _check_schema(alerts, "rare_sequence")
    assert len(alerts) == 1
    a = alerts[0]
    assert a.severity is Severity.ANOMALOUS
    assert a.group_key == "rare_sequence:(4, 5, 6)"
    assert "seen 0 times during learning" in a.baseline_desc
    assert "(n-gram 4->5->6)" in a.baseline_desc
    assert a.observed_value == 3.0
    _cycle(det, clock, [1, 2, 3], 5)
    assert _drain(det, clock) == []
    clock.advance(700.0)
    _cycle(det, clock, [4, 5, 6], 3)
    again = _drain(det, clock)
    _check_schema(again, "rare_sequence")
    assert len(again) == 1
    total = alerts + again
    assert len(total) == 2


def test_rare_sequence_common_triples_never_fire() -> None:
    clock = FakeClock()
    store = BaselineStore(clock)
    gate = _Gate()
    det = RareSequenceDetector(_ctx(clock, store, gate))
    _cycle(det, clock, [1, 2, 3], 500)
    gate.done = True
    _cycle(det, clock, [1, 2, 3], 50)
    assert _drain(det, clock) == []


def test_rare_sequence_cooldown_suppresses_immediate_refire() -> None:
    clock = FakeClock()
    store = BaselineStore(clock)
    gate = _Gate()
    cfg = DetectorConfig(sequence_cooldown_s=1200.0)
    det = RareSequenceDetector(_ctx(clock, store, gate, cfg))
    _cycle(det, clock, [7, 8], 300, dt=0.05)
    gate.done = True
    _cycle(det, clock, [4, 5, 6], 3)
    first = _drain(det, clock)
    _check_schema(first, "rare_sequence")
    assert len(first) == 1
    assert first[0].group_key == "rare_sequence:(4, 5, 6)"
    clock.advance(700.0)
    _cycle(det, clock, [4, 5, 6], 3)
    mid = _drain(det, clock)
    assert {a.group_key for a in mid} == {
        "rare_sequence:(5, 6, 4)",
        "rare_sequence:(6, 4, 5)",
    }
    clock.advance(600.0)
    _cycle(det, clock, [4, 5, 6], 3)
    second = _drain(det, clock)
    _check_schema(second, "rare_sequence")
    assert len(second) == 1
    assert second[0].group_key == "rare_sequence:(4, 5, 6)"

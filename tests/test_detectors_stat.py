"""Statistical detectors: seasonal volume, error-rate shift, numeric shift.

FakeClock only; every alert is schema-checked for the mandatory explanation
fields, severity words and exact detector ids.
"""

from __future__ import annotations

import math

from logsift.baselines import BaselineStore
from logsift.clock import FakeClock
from logsift.detectors.base import DetectorConfig, DetectorContext
from logsift.detectors.error_rate import ErrorRateDetector
from logsift.detectors.numeric_shift import NumericShiftDetector
from logsift.detectors.volume import VolumeDetector
from logsift.events import Alert, Event, Severity

HOUR = 3600.0
START = FakeClock.DEFAULT_START  # 2026-01-01T00:00:00Z, a Thursday

TPL_A = "user <*> login failed"
TPL_B = "GET /health check"
TPL_N = "POST /api/submit completed"

SEV_WORDS = {"normal", "elevated", "anomalous", "critical"}
DETECTOR_IDS = {"volume", "error_rate", "numeric_shift"}


def _ctx(clock: FakeClock | None = None) -> DetectorContext:
    clock = clock if clock is not None else FakeClock()
    return DetectorContext(
        clock=clock,
        baselines=BaselineStore(clock),
        warmup_complete=lambda: True,
        config=DetectorConfig(),
    )


def _schema_check(alerts: list[Alert]) -> None:
    for a in alerts:
        for field in (
            a.detector,
            a.template_text,
            a.baseline_desc,
            a.observed_desc,
            a.deviation_desc,
            a.threshold_desc,
            a.group_key,
        ):
            assert isinstance(field, str) and field.strip(), f"empty field: {a!r}"
        assert a.detector in DETECTOR_IDS, a.detector
        assert a.severity.value in SEV_WORDS, a.severity
        assert a.severity.marker in {".", "+", "!", "!!"}
        assert a.window_end > a.window_start, a


def _jitter(seed: int, span: float) -> int:
    """Deterministic pseudo-noise in [-span, +span]."""
    r = (seed * 2654435761 + 0x9E3779B9) % 1999999
    frac = r / 1999998.0 * 2.0 - 1.0
    return round(span * frac)


# --------------------------------------------------------------------- volume


def _count_a(hour_index: int) -> int:
    """Strong daily sinusoid: trough 90 at 03:00, peak 350 at 15:00."""
    base = 220.0 + 130.0 * math.cos(2 * math.pi * ((hour_index % 24) - 15) / 24.0)
    return max(1, int(round(base)) + _jitter(hour_index, 0.10 * base))


def _count_b(hour_index: int) -> int:
    """Flat low-volume template, 2..4 events/hr."""
    return max(1, 3 + _jitter(hour_index * 7 + 1, 1.0))


def _feed_hour(det: VolumeDetector, hour_index: int, count_b: int | None = None) -> None:
    ca = _count_a(hour_index)
    cb = _count_b(hour_index) if count_b is None else count_b
    base = START + hour_index * HOUR
    events = [Event(ts=base + (k + 0.5) * HOUR / ca, message="login failed",
                    level="info", template_text=TPL_A) for k in range(ca)]
    events += [Event(ts=base + (k + 0.5) * HOUR / cb, message="health ok",
                     level="info", template_text=TPL_B) for k in range(cb)]
    events.sort(key=lambda e: e.ts)
    for ev in events:
        det.observe(ev, ev.ts)


def _feed_hours(
    det: VolumeDetector, h0: int, h1: int, spike_hour: int | None = None
) -> list[Alert]:
    alerts: list[Alert] = []
    for h in range(h0, h1):
        _feed_hour(det, h, count_b=60 if h == spike_hour else None)
        alerts.extend(det.tick(START + (h + 1) * HOUR))
    return alerts


def test_volume_seasonal_stream_never_alerts_then_spike_fires_exactly_once():
    # Hour-of-week slots only accumulate history from the same weekday, so
    # scoring starts once a slot has seen three weeks (day 14 onward); every
    # nightly trough from then on is genuinely scored against its own slot.
    det = VolumeDetector(_ctx(FakeClock()))
    alerts = _feed_hours(det, 0, 519)
    _schema_check(alerts)
    assert alerts == [], [a.explain() for a in alerts]
    troughs = {START + d * 24 * HOUR + 3 * HOUR for d in range(22)}
    assert not [a for a in alerts if a.window_start in troughs]

    # Inject a 20x spike on TPL_B (~3/hr) at the day-21 15:00 peak hour; its
    # slot history is days 0, 7 and 14 (all Thursdays).
    alerts += _feed_hours(det, 519, 528, spike_hour=519)
    alerts.extend(det.flush(START + 528 * HOUR))
    _schema_check(alerts)
    assert len(alerts) == 1, [a.explain() for a in alerts]
    a = alerts[0]
    assert a.detector == "volume"
    assert a.template_text == TPL_B
    assert a.group_key == f"volume:{TPL_B}"
    assert a.window_start == START + 519 * HOUR
    assert a.window_end == START + 520 * HOUR
    assert a.observed_value == 60.0
    assert a.baseline_value is not None and a.baseline_value <= 4.0
    assert "over 3 weekly slots" in a.baseline_desc
    assert "x median" in a.deviation_desc and "robust z=" in a.deviation_desc
    assert a.threshold_value == 4.0
    assert a.severity in (Severity.ANOMALOUS, Severity.CRITICAL)


def test_volume_tick_closes_stale_bucket_on_quiet_stream():
    clock = FakeClock()
    det = VolumeDetector(_ctx(clock))
    _feed_hour(det, 0)
    out = det.tick(clock.now())
    assert out == []  # bucket only minutes old, not stale yet
    clock.advance(3 * HOUR)
    out = det.tick(clock.now())  # >= 2h stale: closed into baselines, n<3 so silent
    assert out == []
    assert det.tick(clock.now()) == []


# ----------------------------------------------------------------- error rate


def _run_error_seconds(
    det: ErrorRateDetector, clock: FakeClock, start_s: float, seconds: int, is_error
) -> list[Alert]:
    alerts: list[Alert] = []
    for i in range(seconds):
        t = start_s + i
        level = "error" if is_error(i) else "info"
        det.observe(
            Event(ts=START + t, message="handled request", level=level,
                  template_text="req"),
            t,
        )
        clock.advance(1.0)
        alerts.extend(det.tick(clock.now()))
    return alerts


def test_error_rate_quiet_stream_is_silent_then_surge_fires_then_recover():
    clock = FakeClock()
    det = ErrorRateDetector(_ctx(clock))
    baseline_err = lambda i: i % 97 == 13  # noqa: E731 - about 1%

    quiet = _run_error_seconds(det, clock, 0, 600, baseline_err)
    _schema_check(quiet)
    assert quiet == []

    surge = _run_error_seconds(det, clock, 600, 60, lambda i: i % 20 < 3)  # 15%
    _schema_check(surge)
    assert len(surge) >= 1, "surge must fire within one window"
    for a in surge:
        assert a.detector == "error_rate"
        assert a.group_key == "error_rate:__all__"
        assert a.template_id is None and a.template_text == "<all templates>"
        assert START + 600 <= a.window_start < START + 660
        assert a.z is not None and a.z >= 3.0
        assert "%" in a.deviation_desc and "z=" in a.deviation_desc
        assert a.baseline_value is not None and a.baseline_value < 5.0

    recovery = _run_error_seconds(det, clock, 660, 300, baseline_err)
    _schema_check(recovery)
    assert recovery == []


# -------------------------------------------------------------------- numeric


def _num_feed(det: NumericShiftDetector, t: float, duration_ms: float) -> None:
    det.observe(
        Event(ts=START + t, message="submit ok",
              numeric={"duration_ms": duration_ms}, template_text=TPL_N),
        START + t,
    )


def test_numeric_shift_fires_on_latency_jump_and_stays_quiet_when_identical():
    clock = FakeClock()
    det = NumericShiftDetector(_ctx(clock))
    steady: list[Alert] = []
    for i in range(600):  # 15 min of ~100ms latency, identical distributions
        t = i * 1.5
        _num_feed(det, t, 100.0 + _jitter(i, 5.0))
        clock.advance(1.5)
        steady.extend(det.tick(clock.now()))
    _schema_check(steady)
    assert steady == []

    shifted: list[Alert] = []
    for i in range(600, 760):  # step to ~300ms
        t = i * 1.5
        _num_feed(det, t, 300.0 + _jitter(i, 5.0))
        clock.advance(1.5)
        shifted.extend(det.tick(clock.now()))
    _schema_check(shifted)
    fires = [a for a in shifted if a.group_key == f"numeric_shift:{TPL_N}:duration_ms"]
    assert len(fires) >= 1, "latency jump 100 -> 300 must fire"
    first = fires[0]
    assert first.detector == "numeric_shift"
    assert first.template_text == TPL_N
    assert 0.0 < first.window_end - first.window_start <= 60.0 * 2
    assert first.baseline_value is not None and 85.0 <= first.baseline_value <= 115.0
    assert first.observed_value is not None and 285.0 <= first.observed_value <= 315.0
    assert "increase" in first.deviation_desc
    assert "+" in first.deviation_desc and "MW-U z=" in first.deviation_desc
    times = [a.event_time for a in fires]
    assert all(b - a >= 55.0 for a, b in zip(times, times[1:])), "cooldown violated"


def test_numeric_high_cardinality_noise_is_memory_bounded():
    det = NumericShiftDetector(_ctx(FakeClock()))
    names = [f"field_{i}" for i in range(64)]
    for i in range(4000):
        det.observe(
            Event(ts=START + i, message="m",
                  numeric={names[i % 64]: float(i % 997)}, template_text="svc"),
            START + float(i),
        )
    fields = det._templates["svc"]
    cap = det.ctx.config.numeric_max_fields_per_template
    assert len(fields) <= cap
    for i in range(4000, 9000):  # hammer one field far past the ring cap
        det.observe(
            Event(ts=START + i, message="m", numeric={"hot": float(i % 13)},
                  template_text="svc2"),
            START + float(i),
        )
    assert len(det._templates["svc2"]["hot"].vals) <= 2000



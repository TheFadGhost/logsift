"""Baselines: seasonality, persistence, exclusions, caps, warm-up. FakeClock only."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from logsift.baselines import (
    BaselineError,
    BaselineStore,
    SCHEMA_BASELINE,
)
from logsift.clock import FakeClock

HOUR = 3600.0
DAY = 24 * HOUR
START = FakeClock.DEFAULT_START  # 2026-01-01T00:00:00Z, a Thursday


def _daily_count(hour: int) -> int:
    """Daily sinusoid: trough at 03:00 (50), peak at 12:00 (350)."""
    return int(200 + 150 * math.sin(2 * math.pi * (hour - 9) / 24))


def _observe_days(store: BaselineStore, key: str, days: int) -> None:
    for day in range(days):
        for hour in range(24):
            store.observe_volume(key, START + day * DAY + hour * HOUR, _daily_count(hour))


def test_seasonality_low_trough_vs_midday_peak():
    store = BaselineStore(FakeClock())
    key = "volume:__all__"
    _observe_days(store, key, days=21)
    at_03 = store.volume_baseline(key, START + 3 * HOUR)
    at_12 = store.volume_baseline(key, START + 12 * HOUR)
    assert at_03 is not None and at_12 is not None
    assert at_03.n == 3
    assert at_12.n == 3
    assert at_03.median == _daily_count(3)
    assert at_12.median == _daily_count(12)
    assert at_03.median < 100 < 300 < at_12.median
    assert at_03.mad <= at_03.median


def test_unknown_key_or_slot_returns_none():
    store = BaselineStore(FakeClock())
    assert store.volume_baseline("volume:missing", START) is None
    store.observe_volume("volume:k", START, 5)
    assert store.volume_baseline("volume:k", START + 5 * HOUR) is None
    assert store.numeric_sample("volume:k") == ()
    assert store.volume_baseline("volume:k", float("nan")) is None


def test_restart_equivalence(tmp_path: Path):
    path = tmp_path / "baselines.json"
    clock = FakeClock()
    a = BaselineStore(clock, path=path)
    c = BaselineStore(clock)
    excluded = (START + 2 * DAY, START + 2 * DAY + 6 * HOUR)
    probe = []
    for day in range(3):
        for hour in range(24):
            epoch = START + day * DAY + hour * HOUR
            probe.append(epoch)
            count1, count2 = 10 + hour % 5, 100 + hour
            a.observe_volume("volume:login failed", epoch, count1)
            a.observe_volume("volume:__all__", epoch, count2)
            if not excluded[0] <= epoch < excluded[1]:
                c.observe_volume("volume:login failed", epoch, count1)
                c.observe_volume("volume:__all__", epoch, count2)
    clock.advance(DAY)
    for i in range(5):
        a.observe_numeric("numeric:latency", 10.0 + i)
        c.observe_numeric("numeric:latency", 10.0 + i)
        clock.advance(60.0)
    for i in range(7):
        a.observe_error_window(START + i * HOUR, total=100, errors=i)
        c.observe_error_window(START + i * HOUR, total=100, errors=i)
    a.mark_abnormal(*excluded)
    a.save()

    b = BaselineStore(clock, path=path)
    assert b.load() is True

    for key in ("volume:login failed", "volume:__all__"):
        for epoch in probe:
            ba = a.volume_baseline(key, epoch)
            bb = b.volume_baseline(key, epoch)
            bc = c.volume_baseline(key, epoch)
            assert (ba is None) == (bb is None) == (bc is None)
            if ba is not None:
                assert (ba.median, ba.mad, ba.n) == (bb.median, bb.mad, bb.n)
                assert (ba.median, ba.mad, ba.n) == (bc.median, bc.mad, bc.n)
    assert b.error_windows() == a.error_windows() == c.error_windows()
    assert len(b.error_windows()) == 7
    assert b.exclusions() == a.exclusions()
    assert b.numeric_sample("numeric:latency") == (10.0, 11.0, 12.0, 13.0, 14.0)
    wa, wb = a.warmup(), b.warmup()
    assert (wb.fraction, wb.complete) == (wa.fraction, wa.complete)


def test_exclusion_removes_samples_and_blocks_future(tmp_path: Path):
    path = tmp_path / "baselines.json"
    store = BaselineStore(FakeClock(), path=path)
    key = "volume:t"
    for week in range(2):
        for day in range(7):
            for hour in range(24):
                store.observe_volume(key, START + (week * 7 + day) * DAY + hour * HOUR, 10)
    bad_day = 10
    bad_start = START + bad_day * DAY
    store.mark_abnormal(bad_start, bad_start + DAY)
    slot_epoch = bad_start + 5 * HOUR
    before = store.volume_baseline(key, slot_epoch)
    assert before is not None and before.n == 1
    store.observe_volume(key, slot_epoch, 999)
    still = store.volume_baseline(key, slot_epoch)
    assert still is not None and still.n == 1 and still.median == 10
    post_window = bad_start + 14 * DAY + 5 * HOUR
    store.observe_volume(key, post_window, 10)
    later = store.volume_baseline(key, post_window)
    assert later is not None and later.n == 2
    assert store.exclusions() == ((bad_start, bad_start + DAY),)
    store.save()

    reloaded = BaselineStore(FakeClock(), path=path)
    assert reloaded.load() is True
    assert reloaded.exclusions() == ((bad_start, bad_start + DAY),)
    after = reloaded.volume_baseline(key, slot_epoch)
    assert after is not None and after.n == 2
    reloaded.observe_volume(key, slot_epoch, 999)
    guarded = reloaded.volume_baseline(key, slot_epoch)
    assert guarded is not None and guarded.n == 2


def test_exclusion_merges_overlaps_and_caps_at_100():
    store = BaselineStore(FakeClock())
    base = START
    store.mark_abnormal(base, base + HOUR)
    store.mark_abnormal(base + HOUR, base + 2 * HOUR)
    store.mark_abnormal(base + 3 * HOUR, base + 4 * HOUR)
    assert store.exclusions() == ((base, base + 2 * HOUR), (base + 3 * HOUR, base + 4 * HOUR))
    for i in range(120):
        store.mark_abnormal(base + DAY * (i + 1), base + DAY * (i + 1) + HOUR)
    windows = store.exclusions()
    assert len(windows) == 100
    assert min(w[0] for w in windows) >= base + DAY * 21
    degenerate = BaselineStore(FakeClock())
    degenerate.mark_abnormal(base + 5 * HOUR, base + 5 * HOUR)
    degenerate.mark_abnormal(float("nan"), base)
    assert degenerate.exclusions() == ()


def test_malformed_state_file_quarantined_then_fresh(tmp_path: Path):
    path = tmp_path / "baselines.json"
    path.write_bytes(b"\xff\xfe not json at all")
    store = BaselineStore(FakeClock(), path=path)
    with pytest.raises(BaselineError) as excinfo:
        store.load()
    message = str(excinfo.value)
    assert "baselines.json" in message and ".corrupt" in message
    corrupt = tmp_path / "baselines.json.corrupt"
    assert corrupt.exists()
    assert not path.exists()
    assert store.load() is False
    assert store.volume_baseline("volume:x", START) is None


def test_wrong_schema_is_baseline_error(tmp_path: Path):
    path = tmp_path / "baselines.json"
    path.write_text(json.dumps({"schema": "something/else", "entries": {}}))
    store = BaselineStore(FakeClock(), path=path)
    with pytest.raises(BaselineError):
        store.load()
    assert (tmp_path / "baselines.json.corrupt").exists()


def test_load_false_then_save_then_true(tmp_path: Path):
    path = tmp_path / "baselines.json"
    store = BaselineStore(FakeClock(), path=path)
    assert store.load() is False
    store.observe_volume("volume:boot", START, 4)
    store.save()
    other = BaselineStore(FakeClock(), path=path)
    assert other.load() is True
    loaded = other.volume_baseline("volume:boot", START)
    assert loaded is not None and loaded.median == 4.0
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["schema"] == SCHEMA_BASELINE


def test_disk_ceiling_trims_oldest_first(tmp_path: Path):
    path = tmp_path / "baselines.json"
    store = BaselineStore(FakeClock(), path=path, max_state_bytes=900)
    key = "volume:trim"
    n_samples = 50
    for i in range(n_samples):
        store.observe_volume(key, START + i * HOUR, 10 + i)
    store.save()
    size = path.stat().st_size
    assert size <= 900
    assert store.state_bytes_estimate() <= 900
    kept = BaselineStore(FakeClock(), path=path)
    assert kept.load() is True
    present = [
        i
        for i in range(n_samples)
        if kept.volume_baseline(key, START + i * HOUR) is not None
    ]
    assert 0 < len(present) < n_samples
    assert present == list(range(present[0], n_samples))
    assert present[0] > 0


def test_error_window_ring_cap():
    store = BaselineStore(FakeClock())
    for i in range(600):
        store.observe_error_window(START + i * 60.0, total=100, errors=i % 7)
    windows = store.error_windows()
    assert len(windows) == 512
    assert windows[0] == (START + 88 * 60.0, 100, 88 % 7)
    assert windows[-1][0] == START + 599 * 60.0


def test_volume_slot_ring_cap():
    store = BaselineStore(FakeClock(), max_samples_per_slot=8)
    key = "volume:cap"
    for week in range(30):
        store.observe_volume(key, START + week * 7 * DAY, week)
    store.observe_volume(key, START + 7 * DAY, 999)
    baseline = store.volume_baseline(key, START)
    assert baseline is not None and baseline.n == 8


def test_numeric_ring_cap():
    clock = FakeClock()
    store = BaselineStore(clock, max_samples_per_slot=8)
    for i in range(25):
        store.observe_numeric("numeric:n", float(i))
        clock.advance(1.0)
    values = store.numeric_sample("numeric:n")
    assert len(values) == 16
    assert values == tuple(float(x) for x in range(9, 25))
    store.observe_numeric("numeric:n", float("nan"))
    store.observe_numeric("numeric:n", float("inf"))
    assert len(store.numeric_sample("numeric:n")) == 16


def test_key_eviction_least_recently_observed():
    clock = FakeClock()
    store = BaselineStore(clock, max_keys=3, max_samples_per_slot=2)
    store.observe_volume("k_a", clock.now(), 10)
    clock.advance(60.0)
    store.observe_volume("k_b", clock.now(), 10)
    clock.advance(60.0)
    store.observe_volume("k_c", clock.now(), 10)
    clock.advance(60.0)
    store.observe_volume("k_a", clock.now(), 1)
    clock.advance(60.0)
    store.observe_volume("k_d", clock.now(), 10)
    assert store.volume_baseline("k_b", clock.now()) is None
    assert store.volume_baseline("k_a", clock.now()) is not None
    assert store.volume_baseline("k_c", clock.now()) is not None
    assert store.volume_baseline("k_d", clock.now()) is not None


def test_key_eviction_tie_breaks_on_smallest_count_then_name():
    clock = FakeClock()
    store = BaselineStore(clock, max_keys=2)
    store.observe_volume("z_big", clock.now(), 9)
    store.observe_volume("y_small", clock.now(), 1)
    clock.advance(60.0)
    store.observe_volume("x_new", clock.now(), 5)
    assert store.volume_baseline("y_small", clock.now()) is None
    assert store.volume_baseline("z_big", clock.now()) is not None
    tie = BaselineStore(clock, max_keys=2)
    tie.observe_volume("b_two", clock.now(), 3)
    tie.observe_volume("a_two", clock.now(), 3)
    clock.advance(60.0)
    tie.observe_volume("c_new", clock.now(), 3)
    assert tie.volume_baseline("a_two", clock.now()) is None
    assert tie.volume_baseline("b_two", clock.now()) is not None


def test_warmup_span_progress_with_clock_advance():
    clock = FakeClock()
    store = BaselineStore(clock, warmup_seconds=3600.0)
    state = store.warmup()
    assert state.fraction == 0.0 and state.complete is False
    assert state.eta_s == pytest.approx(3600.0)
    store.observe_volume("volume:w", clock.now(), 1)
    state = store.warmup()
    assert state.fraction == pytest.approx(1 / 24)
    clock.advance(1800.0)
    store.observe_volume("volume:w", clock.now(), 1)
    state = store.warmup()
    assert state.fraction == pytest.approx(0.5)
    assert state.eta_s == pytest.approx(1800.0)
    assert state.complete is False
    clock.advance(1800.0)
    store.observe_volume("volume:w", clock.now(), 1)
    state = store.warmup()
    assert state.complete is True
    assert state.fraction == 1.0
    assert state.eta_s is None


def test_warmup_completes_via_distinct_slots():
    clock = FakeClock()
    store = BaselineStore(clock, warmup_seconds=200000.0)
    for hour in range(24):
        store.observe_volume("volume:s", clock.now(), 1)
        clock.advance(HOUR)
    state = store.warmup()
    assert state.complete is True
    assert state.eta_s is None
    short = BaselineStore(FakeClock(), warmup_seconds=0.0)
    assert short.warmup().complete is True


def test_excluded_observations_do_not_advance_warmup():
    clock = FakeClock()
    store = BaselineStore(clock, warmup_seconds=3600.0)
    store.observe_volume("volume:e", clock.now(), 1)
    span_before = store.warmup().fraction
    store.mark_abnormal(clock.now() + 600.0, clock.now() + 1200.0)
    store.observe_volume("volume:e", clock.now() + 900.0, 1)
    assert store.warmup().fraction == span_before

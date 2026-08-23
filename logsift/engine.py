"""Ingestion engine: source -> assembler -> parser -> templater -> detectors -> index.

One worker thread consumes the bounded line queue; a timer thread publishes UI
snapshots and requests detector ticks. Detector ticks execute on the worker
thread so alerts stay single-threaded end to end.
"""

from __future__ import annotations

import queue
import sys
import threading
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from .alerts import AlertManager, ExecHook, WebhookHook
from .baselines import BaselineStore
from .clock import Clock
from .config import Config, HookSpec
from .detectors.base import BaseDetector, DetectorContext
from .detectors.error_rate import ErrorRateDetector
from .detectors.new_template import NewTemplateDetector
from .detectors.numeric_shift import NumericShiftDetector
from .detectors.rare_sequence import RareSequenceDetector
from .detectors.stopped_template import StoppedTemplateDetector
from .detectors.volume import VolumeDetector
from .events import (
    FLAG_INVALID_UTF8,
    FLAG_TRUNCATED,
    MAX_LINE_BYTES,
    Event,
    ParseStatus,
)
from .index import StreamingIndex
from .multiline import MultilineAssembler
from .parsers import ParserRegistry
from .snapshot import Snapshot, SnapshotProvider, TemplateSummary
from .sources import LogSource, RawLine
from .templater import Templater

QUEUE_SIZE = 10_000
TICK_INTERVAL_S = 1.0
BASELINE_SAVE_INTERVAL_S = 300.0


@dataclass(slots=True)
class EngineStats:
    lines_total: int = 0
    parsed_ok: int = 0
    unparsed: int = 0
    events_assembled: int = 0
    invalid_utf8_lines: int = 0
    truncated_lines: int = 0
    error_level_events: int = 0
    alerts_emitted: int = 0
    alerts_suppressed: int = 0
    first_ts: float | None = None
    last_ts: float | None = None


def build_hooks(specs: list[HookSpec]) -> list[ExecHook | WebhookHook]:
    out: list[ExecHook | WebhookHook] = []
    for spec in specs:
        if spec.type == "exec":
            out.append(ExecHook(argv=spec.argv, timeout_s=spec.timeout_s, dry_run=spec.dry_run))
        else:
            out.append(
                WebhookHook(
                    url=spec.url,
                    headers=spec.headers or None,
                    timeout_s=spec.timeout_s,
                    dry_run=spec.dry_run,
                )
            )
    return out


class _RateCounter:
    """Per-second ingest ring for rate display."""

    __slots__ = ("per_second", "_bucket", "_count")

    def __init__(self) -> None:
        self.per_second: deque[int] = deque(maxlen=120)
        self._bucket = -1.0
        self._count = 0

    def add(self, mono: float) -> None:
        sec = float(int(mono))
        if sec != self._bucket:
            if self._bucket >= 0:
                self.per_second.append(self._count)
            self._bucket = sec
            self._count = 1
        else:
            self._count += 1

    def rate_lps(self) -> float:
        n = len(self.per_second)
        return sum(self.per_second) / n if n else 0.0


class Engine:
    """Runs one source to completion."""

    def __init__(
        self,
        cfg: Config,
        clock: Clock,
        provider: SnapshotProvider | None = None,
        alert_sink=None,
        source_name: str = "input",
        verbose: bool = False,
        eof_exceptions: tuple[type[BaseException], ...] = (),
    ) -> None:
        self.cfg = cfg
        self.clock = clock
        self.provider = provider
        self.source_name = source_name
        self.verbose = verbose
        self.eof_exceptions = eof_exceptions
        self.stats = EngineStats()
        self.index = StreamingIndex(max_events=cfg.max_events)
        baseline_path = Path(cfg.baseline_path) if cfg.baseline_path else None
        self.baselines = BaselineStore(
            clock,
            path=baseline_path,
            max_state_bytes=cfg.baseline_max_state_bytes,
            warmup_seconds=cfg.warmup_seconds,
        )
        if baseline_path is not None and baseline_path.exists():
            try:
                self.baselines.load()
            except Exception as exc:
                self._notify(f"baseline load failed ({exc}); starting fresh")
                self.baselines = BaselineStore(
                    clock,
                    path=baseline_path,
                    max_state_bytes=cfg.baseline_max_state_bytes,
                    warmup_seconds=cfg.warmup_seconds,
                )
        self.templater = Templater(clock, max_templates=cfg.max_templates)
        self._registry = ParserRegistry(clock, custom_pattern=cfg.custom_pattern)
        self._sample_window: deque[str] = deque(maxlen=200)

        ctx = DetectorContext(
            clock=clock,
            baselines=self.baselines,
            warmup_complete=lambda: self.baselines.warmup().complete,
            config=cfg.detectors,
        )
        self.detectors: list[BaseDetector] = [
            VolumeDetector(ctx),
            ErrorRateDetector(ctx),
            NumericShiftDetector(ctx),
            NewTemplateDetector(ctx),
            StoppedTemplateDetector(ctx),
            RareSequenceDetector(ctx),
        ]

        self.alert_manager = AlertManager(
            clock,
            sink=alert_sink,
            hooks=build_hooks(cfg.hooks),
            throttle_window_s=cfg.throttle_window_s,
            evidence_lookup=self._evidence_lookup,
        )

        self.assembler = MultilineAssembler()
        self._queue: queue.Queue[RawLine | None] = queue.Queue(maxsize=QUEUE_SIZE)
        self._tick_queue: queue.Queue[float] = queue.Queue(maxsize=64)
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._source_done = threading.Event()
        self._source_failed = False
        self._source_error: str | None = None
        self._rate = _RateCounter()
        self._minute_ring: deque[tuple[float, int]] = deque(maxlen=180)
        self._recent_alerts: deque[dict] = deque(maxlen=200)
        self._last_line_mono: float | None = None
        self._start_mono = clock.monotonic()
        self._last_baseline_save_mono = clock.monotonic()
        self._last_event_tick_ts: float | None = None

    # ------------------------------------------------------------------ run

    def run_source(self, source: LogSource) -> EngineStats:
        reader = threading.Thread(target=self._read_loop, args=(source,), daemon=True)
        timer = threading.Thread(target=self._timer_loop, daemon=True)
        reader.start()
        timer.start()
        try:
            self._process_loop()
        finally:
            self.request_stop()
            self._final_flush()
            self._save_baseline()
        self._source_done.wait(timeout=5.0)
        return self.stats

    def request_pause_toggle(self) -> None:
        if self._pause_event.is_set():
            self._pause_event.clear()
        else:
            self._pause_event.set()

    def request_stop(self) -> None:
        self._stop_event.set()

    def _notify(self, message: str) -> None:
        sys.stderr.write(f"logsift: {message}\n")
        sys.stderr.flush()

    @property
    def source_error(self) -> str | None:
        return self._source_error

    def recent_alerts(self) -> tuple[dict, ...]:
        return tuple(self._recent_alerts)

    # -------------------------------------------------------------- threads

    def _read_loop(self, source: LogSource) -> None:
        try:
            for raw in source:
                if self._stop_event.is_set():
                    break
                while not self._stop_event.is_set():
                    try:
                        self._queue.put(raw, timeout=0.25)
                        break
                    except queue.Full:
                        continue
        except self.eof_exceptions:
            pass
        except Exception as exc:
            self._source_failed = True
            self._source_error = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                self._queue.put(None, timeout=1.0)
            except queue.Full:
                pass
            self._source_done.set()

    def _timer_loop(self) -> None:
        next_tick = self.clock.monotonic() + TICK_INTERVAL_S
        while not self._stop_event.is_set():
            mono = self.clock.monotonic()
            if mono >= next_tick:
                try:
                    self._tick_queue.put_nowait(mono)
                except queue.Full:
                    pass
                next_tick = mono + TICK_INTERVAL_S
            if self.provider is not None:
                self._publish_snapshot(mono)
            self._stop_event.wait(0.2)

    # ------------------------------------------------------------- pipeline

    def _process_loop(self) -> None:
        while not self._stop_event.is_set():
            if self._pause_event.is_set():
                self._drain_tick()
                self._stop_event.wait(0.2)
                continue
            try:
                raw = self._queue.get(timeout=0.25)
            except queue.Empty:
                self._drain_tick()
                if self._source_done.is_set():
                    break
                continue
            if raw is None:
                break
            self._process_raw(raw, self.clock.monotonic())
            self._drain_tick()
            if self.stats.last_ts is not None:
                self._maybe_event_time_tick(self.stats.last_ts)

    def _event_time_now(self) -> float:
        """Detector 'now' follows event time so replay matches live behaviour."""
        if self.stats.last_ts is not None:
            return self.stats.last_ts
        return self.clock.now()

    def _drain_tick(self) -> None:
        try:
            mono = self._tick_queue.get_nowait()
        except queue.Empty:
            return
        self._run_ticks(mono)

    def _maybe_event_time_tick(self, event_ts: float) -> None:
        """Drive periodic detector ticks by EVENT time so replay at full speed
        behaves like a live stream; the monotonic timer only covers idle gaps."""
        if (
            self._last_event_tick_ts is None
            or event_ts - self._last_event_tick_ts >= TICK_INTERVAL_S
        ):
            self._run_ticks(self.clock.monotonic())

    def _run_ticks(self, mono: float) -> None:
        now = self._event_time_now()
        if self.stats.last_ts is not None:
            self._last_event_tick_ts = now
        alerts: list = []
        for det in self.detectors:
            alerts.extend(det.tick(now))
        self._submit_alerts(alerts)
        if mono - self._last_baseline_save_mono > BASELINE_SAVE_INTERVAL_S:
            self._save_baseline()

    def _process_raw(self, raw: RawLine, now_mono: float) -> None:
        s = self.stats
        s.lines_total += 1
        self._rate.add(now_mono)
        self._last_line_mono = now_mono
        flags = 0
        if not raw.valid_utf8:
            flags |= FLAG_INVALID_UTF8
            s.invalid_utf8_lines += 1
        if raw.flags & FLAG_TRUNCATED:
            flags |= FLAG_TRUNCATED
            s.truncated_lines += 1

        if not self._registry.locked and len(self._sample_window) < 200:
            self._sample_window.append(raw.text)
            if len(self._sample_window) >= 50:
                report = self._registry.detect(list(self._sample_window))
                if report.parser_name:
                    self._registry.lock(report.parser_name)

        for assembled in self.assembler.feed(raw.text):
            self._handle_assembled(assembled, raw.source_name, flags)

    def _handle_assembled(self, text: str, source_name: str, flags: int) -> None:
        s = self.stats
        result = self._registry.parse_line(text)
        event_ts = result.ts if (result.ok and result.ts is not None) else self.clock.now()
        if result.ok:
            s.parsed_ok += 1
            match = self.templater.process(result.message)
            ev = Event(
                ts=event_ts,
                message=result.message,
                level=result.level,
                fields=dict(result.fields),
                numeric=dict(result.numeric),
                template_id=match.template.template_id,
                template_text=match.template.text,
                source=source_name,
                parse_status=ParseStatus.OK,
                parser=result.parser,
                raw_line=text[:2048],
                ingest_ts=self.clock.now(),
                flags=flags,
            )
            if ev.level in ("error", "critical"):
                s.error_level_events += 1
            for det in self.detectors:
                det.observe(ev, ev.ts)
            self.index.add(ev)
        else:
            s.unparsed += 1
            ev = Event(
                ts=event_ts,
                message=text[:512],
                source=source_name,
                parse_status=ParseStatus.UNPARSED,
                parser="",
                raw_line=text[:2048],
                ingest_ts=self.clock.now(),
                flags=flags,
            )
            self.index.add(ev)
        s.events_assembled += 1
        if s.first_ts is None or event_ts < s.first_ts:
            s.first_ts = event_ts
        if s.last_ts is None or event_ts > s.last_ts:
            s.last_ts = event_ts
        minute = float(int(event_ts // 60))
        if self._minute_ring and self._minute_ring[-1][0] == minute:
            start, count = self._minute_ring[-1]
            self._minute_ring[-1] = (start, count + 1)
        elif not self._minute_ring or minute > self._minute_ring[-1][0]:
            self._minute_ring.append((minute, 1))

    def _final_flush(self) -> None:
        now = self._event_time_now()
        for assembled in self.assembler.flush():
            self._handle_assembled(assembled, self.source_name, 0)
        alerts: list = []
        for det in self.detectors:
            alerts.extend(det.flush(now))
        self._submit_alerts(alerts)
        self._publish_snapshot(self.clock.monotonic())

    def _submit_alerts(self, alerts) -> None:
        for alert in alerts:
            payload = self.alert_manager.submit(alert)
            if payload is not None:
                self.stats.alerts_emitted += 1
                self._recent_alerts.append(payload)
            else:
                self.stats.alerts_suppressed += 1

    def _save_baseline(self) -> None:
        if not self.cfg.baseline_path:
            return
        try:
            self.baselines.save()
            self._last_baseline_save_mono = self.clock.monotonic()
        except OSError as exc:
            self._notify(f"baseline save failed ({exc}); continuing without persisting")

    # ------------------------------------------------------------ snapshots

    def _publish_snapshot(self, mono: float) -> None:
        if self.provider is None:
            return
        totals = self.index.totals()
        tstats = self.index.template_stats()
        top = sorted(tstats.values(), key=lambda t: (-t.count, t.text))[:12]
        summaries = tuple(
            TemplateSummary(
                template_id=t.template_id,
                text=t.text,
                count=t.count,
                last_seen=t.last_seen,
                rate_per_min=(t.minute_counts[-1] if t.minute_counts else 0),
                share=(t.count / max(1, totals.lines_total)),
            )
            for t in top
        )
        volume = tuple(c for _m, c in sorted(self._minute_ring)[-120:])
        warmup = self.baselines.warmup()
        snap = Snapshot(
            generated_mono=mono,
            uptime_s=max(0.0, mono - self._start_mono),
            source_name=self.source_name,
            source_state=self._source_state(),
            ingest_rate_lps=self._rate.rate_lps(),
            window_rate_lps=self._rate.rate_lps(),
            error_rate_pct=(100.0 * self.stats.error_level_events / max(1, self.stats.parsed_ok)),
            unparsed_pct=(100.0 * self.stats.unparsed / max(1, self.stats.lines_total)),
            unparsed_count=self.stats.unparsed,
            total_events=self.stats.events_assembled,
            warmup_fraction=(None if warmup.complete else warmup.fraction),
            warmup_eta_s=warmup.eta_s,
            paused=self._pause_event.is_set(),
            top_templates=summaries,
            alerts=tuple(dict(a) for a in self._recent_alerts),
            volume_series=volume,
        )
        self.provider.publish(snap)

    def _source_state(self) -> str:
        if self._pause_event.is_set():
            return "paused"
        if self._source_failed:
            return "disconnected"
        if self._source_done.is_set():
            return "eof"
        if self._last_line_mono is not None and self.clock.monotonic() - self._last_line_mono > 30.0:
            return "no_data"
        return "connected"

    # ------------------------------------------------------------- evidence

    def _evidence_lookup(self, alert):
        rows = list(self.index.iter_rows(reverse=True))[:4000]
        examples: list[str] = []
        before: list[str] = []
        matched_idx: int | None = None
        for i, row in enumerate(rows):
            if alert.template_id is not None and row.template_id == alert.template_id:
                if len(examples) < 3:
                    examples.append(row.raw[:240])
                if matched_idx is None:
                    matched_idx = i
        if matched_idx is not None:
            before = [r.raw[:200] for r in rows[matched_idx : matched_idx + 5]]
        return examples, before


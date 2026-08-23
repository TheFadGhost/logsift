"""Immutable snapshots handed from the ingestion engine to the TUI.

The engine publishes a new Snapshot through an atomic reference swap; the UI
thread reads whatever reference is current and never blocks ingestion.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .events import Alert


@dataclass(frozen=True, slots=True)
class TemplateSummary:
    template_id: int
    text: str
    count: int
    rate_per_min: float
    last_seen: float
    share: float


SOURCE_STATES = ("connected", "disconnected", "eof", "paused", "no_data")


@dataclass(frozen=True, slots=True)
class Snapshot:
    generated_mono: float
    uptime_s: float
    source_name: str
    source_state: str
    ingest_rate_lps: float
    window_rate_lps: float
    error_rate_pct: float
    unparsed_pct: float
    unparsed_count: int
    total_events: int
    warmup_fraction: float | None
    warmup_eta_s: float | None
    paused: bool
    top_templates: tuple[TemplateSummary, ...]
    alerts: tuple[Alert, ...]
    volume_series: tuple[int, ...]
    selected_template_history: tuple[int, ...] | None = None
    selected_template_examples: tuple[str, ...] | None = None


class SnapshotProvider:
    """Single-writer, many-reader holder with atomic reference swap."""

    __slots__ = ("_snap",)

    def __init__(self) -> None:
        self._snap: Snapshot | None = None

    def publish(self, snap: Snapshot) -> None:
        self._snap = snap

    def latest(self) -> Snapshot | None:
        return self._snap

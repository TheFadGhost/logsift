"""Detector contract. Every alert carries its full explanation - no bare scores."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from ..events import Alert, Event

if TYPE_CHECKING:
    from ..baselines import BaselineStore


@dataclass(slots=True)
class DetectorConfig:
    # volume
    volume_elevated_z: float = 4.0
    volume_anomalous_z: float = 6.0
    volume_critical_z: float = 10.0
    volume_min_count: int = 5
    # error rate
    error_window_s: float = 60.0
    error_baseline_s: float = 300.0
    error_elevated_z: float = 3.0
    error_anomalous_z: float = 4.0
    error_critical_z: float = 8.0
    error_min_events: int = 20
    # numeric distribution shift
    numeric_window_s: float = 60.0
    numeric_baseline_s: float = 600.0
    numeric_elevated_z: float = 3.5
    numeric_anomalous_z: float = 5.0
    numeric_critical_z: float = 9.0
    numeric_min_samples: int = 30
    numeric_max_fields_per_template: int = 8
    # new templates
    new_template_grace_s: float = 0.0
    new_template_min_count: int = 2
    # stopped templates
    stopped_check_interval_s: float = 30.0
    stopped_gap_factor: float = 10.0
    stopped_min_expected: int = 50
    stopped_min_history: int = 200
    # rare sequences
    sequence_ngram_n: int = 3
    sequence_gap_s: float = 2.0
    sequence_max_baseline_count: int = 2
    sequence_min_observed: int = 4
    sequence_cooldown_s: float = 900.0
    sequence_max_ngrams: int = 50000
    sequence_min_component_count: int = 5
    sequence_max_alerts_per_hour: int = 3
    sequence_max_dominant_share: float = 0.6


@dataclass(slots=True)
class DetectorContext:
    """Shared services a detector may use. Detectors own no global state."""

    clock: object                      # Clock
    baselines: "BaselineStore"
    warmup_complete: Callable[[], bool]
    config: DetectorConfig


class BaseDetector(ABC):
    """observe() per event; tick() periodically; both return alerts via tick/flush."""

    id: str = ""

    def __init__(self, ctx: DetectorContext) -> None:
        self.ctx = ctx

    @abstractmethod
    def observe(self, ev: Event, now: float) -> None:
        """Consume one event. Must not raise on hostile content."""

    def tick(self, now: float) -> list[Alert]:
        """Called ~every second of engine time and once at shutdown flush."""
        return []

    def flush(self, now: float) -> list[Alert]:
        return self.tick(now)


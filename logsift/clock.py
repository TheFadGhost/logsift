"""Injected clocks. No module other than this one may read the system time."""

from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float:
        """Wall-clock time as UTC epoch seconds."""
        ...

    def monotonic(self) -> float:
        """Monotonic seconds, for measuring intervals."""
        ...

    def advance(self, seconds: float) -> None:  # pragma: no cover - protocol
        ...


class SystemClock:
    __slots__ = ()

    def now(self) -> float:
        return time.time()

    def monotonic(self) -> float:
        return time.monotonic()

    def advance(self, seconds: float) -> None:
        raise TypeError("SystemClock cannot be advanced; inject a FakeClock in tests")


class FakeClock:
    """Deterministic clock for tests. Start epoch defaults to 2026-01-01 UTC."""

    __slots__ = ("_now", "_mono")

    DEFAULT_START = 1767225600.0

    def __init__(self, start: float | None = None) -> None:
        self._now = self.DEFAULT_START if start is None else float(start)
        self._mono = 0.0

    def now(self) -> float:
        return self._now

    def monotonic(self) -> float:
        return self._mono

    def advance(self, seconds: float) -> None:
        self._now += seconds
        self._mono += seconds

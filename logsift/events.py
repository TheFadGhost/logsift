"""Core data contracts: events, templates, alerts. Every module builds on these."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

SCHEMA_ALERT = "logsift.alert/1"

SEVERITY_ORDER = ("normal", "elevated", "anomalous", "critical")
MARKERS = {"normal": ".", "elevated": "+", "anomalous": "!", "critical": "!!"}

DETECTORS = (
    "volume",
    "new_template",
    "stopped_template",
    "error_rate",
    "numeric_shift",
    "rare_sequence",
)

MAX_LINE_BYTES = 32768

FLAG_TRUNCATED = 1
FLAG_INVALID_UTF8 = 2


class Severity(str, Enum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    ANOMALOUS = "anomalous"
    CRITICAL = "critical"

    @property
    def marker(self) -> str:
        return MARKERS[self.value]

    @classmethod
    def from_score_bands(
        cls, score: float, elevated: float, anomalous: float, critical: float
    ) -> "Severity":
        if score >= critical:
            return cls.CRITICAL
        if score >= anomalous:
            return cls.ANOMALOUS
        if score >= elevated:
            return cls.ELEVATED
        return cls.NORMAL


class ParseStatus(str, Enum):
    OK = "ok"
    UNPARSED = "unparsed"


def iso_utc(epoch: float) -> str:
    dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


@dataclass(slots=True)
class Event:
    """One assembled log event flowing down the pipeline.

    A 40-line stack trace is one Event; the assembler guarantees that.
    """

    ts: float
    message: str
    level: str | None = None
    fields: dict[str, str] = field(default_factory=dict)
    numeric: dict[str, float] = field(default_factory=dict)
    template_id: int | None = None
    template_text: str | None = None
    source: str = ""
    parse_status: ParseStatus = ParseStatus.OK
    parser: str = ""
    raw_line: str = ""
    ingest_ts: float = 0.0
    flags: int = 0


@dataclass(slots=True)
class Template:
    template_id: int
    tokens: tuple[str, ...]
    count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    sample_values: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return " ".join(self.tokens)

    def render(self, params: list[str] | None = None) -> str:
        out: list[str] = []
        i = 0
        for tok in self.tokens:
            if tok == "<*>":
                val = params[i] if params and i < len(params) else "*"
                out.append("{" + val + "}")
                i += 1
            else:
                out.append(tok)
        return " ".join(out)


@dataclass(slots=True)
class Alert:
    """An anomaly. The explanation fields are mandatory, never optional colouring."""

    detector: str
    severity: Severity
    template_id: int | None
    template_text: str
    baseline_desc: str
    baseline_value: float | None
    observed_desc: str
    observed_value: float | None
    deviation_desc: str
    z: float | None
    threshold_desc: str
    threshold_value: float | None
    window_start: float
    window_end: float
    group_key: str
    event_time: float | None = None

    id: str = ""
    count: int = 1
    suppressed: int = 0
    first_seen: float = 0.0
    examples: list[str] = field(default_factory=list)
    evidence_before: list[str] = field(default_factory=list)

    def explain(self) -> str:
        parts = [
            f"{self.severity.value} [{self.detector}] template {self.template_text!r}",
            f"baseline: {self.baseline_desc}",
            f"observed: {self.observed_desc}",
            f"deviation: {self.deviation_desc}",
            f"threshold: {self.threshold_desc}",
            f"window: {iso_utc(self.window_start)} .. {iso_utc(self.window_end)}",
        ]
        if self.examples:
            parts.append("examples:")
            parts.extend(f"  {line}" for line in self.examples[:3])
        return "\n".join(parts)

    def to_json_dict(self) -> dict:
        d = {
            "schema": SCHEMA_ALERT,
            "id": self.id,
            "time": iso_utc(self.event_time or self.window_end),
            "severity": self.severity.value,
            "marker": self.severity.marker,
            "detector": self.detector,
            "template_id": self.template_id,
            "template": self.template_text,
            "baseline": {"desc": self.baseline_desc, "value": self.baseline_value},
            "observed": {"desc": self.observed_desc, "value": self.observed_value},
            "deviation": {"desc": self.deviation_desc, "z": self.z},
            "threshold": {"desc": self.threshold_desc, "value": self.threshold_value},
            "window": {
                "start": iso_utc(self.window_start),
                "end": iso_utc(self.window_end),
            },
            "group_key": self.group_key,
            "count": self.count,
            "suppressed": self.suppressed,
            "first_seen": iso_utc(self.first_seen),
            "examples": list(self.examples),
            "evidence_before": list(self.evidence_before),
        }
        return json.loads(json.dumps(d))

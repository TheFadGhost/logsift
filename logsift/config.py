"""TOML configuration with validation and helpful errors."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

from .detectors.base import DetectorConfig
from .themes import THEMES


class ConfigError(ValueError):
    """Invalid configuration. Message names the key, the problem, and the fix."""


_HOOK_TYPES = {"exec": {"argv", "timeout_s", "dry_run"}, "webhook": {"url", "headers", "timeout_s", "dry_run"}}

TOP_KEYS = {
    "theme",
    "warmup_seconds",
    "max_events",
    "max_templates",
    "baseline_path",
    "baseline_max_state_bytes",
    "throttle_window_s",
    "poll_interval_s",
    "custom_pattern",
    "hooks",
    "detectors",
}


@dataclass(slots=True)
class HookSpec:
    type: str                 # "exec" | "webhook"
    argv: list[str] = field(default_factory=list)
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    timeout_s: float = 10.0
    dry_run: bool = False

    def validate(self, where: str) -> None:
        if self.type == "exec":
            if not self.argv:
                raise ConfigError(f"{where}: exec hook needs a non-empty 'argv' list; e.g. argv = [\"python\", \"handler.py\"]")
        elif self.type == "webhook":
            if not self.url.startswith(("http://", "https://")):
                raise ConfigError(f"{where}: webhook 'url' must start with http:// or https://, got {self.url!r}")
        else:
            raise ConfigError(f"{where}: hook.type must be \"exec\" or \"webhook\", got {self.type!r}")
        if self.timeout_s <= 0:
            raise ConfigError(f"{where}: hook timeout_s must be > 0")


@dataclass(slots=True)
class Config:
    theme: str = "dark"
    warmup_seconds: float = 3600.0
    max_events: int = 100_000
    max_templates: int = 5000
    baseline_path: str | None = None
    baseline_max_state_bytes: int = 8 * 1024 * 1024
    throttle_window_s: float = 300.0
    poll_interval_s: float = 0.25
    custom_pattern: str | None = None
    hooks: list[HookSpec] = field(default_factory=list)
    detectors: DetectorConfig = field(default_factory=DetectorConfig)

    def validate(self) -> None:
        if self.theme not in THEMES:
            raise ConfigError(
                f"theme must be one of {', '.join(THEMES)}, got {self.theme!r}"
            )
        for name in (
            "warmup_seconds",
            "throttle_window_s",
            "poll_interval_s",
        ):
            if getattr(self, name) < 0:
                raise ConfigError(f"{name} must be >= 0, got {getattr(self, name)}")
        if self.max_events < 100:
            raise ConfigError("max_events must be >= 100 (the index needs room to detect anything)")
        if self.max_templates < 10:
            raise ConfigError("max_templates must be >= 10")
        for i, hook in enumerate(self.hooks):
            hook.validate(f"hooks[{i}]")

        if self.detectors.error_window_s <= 0 or self.detectors.numeric_window_s <= 0:
            raise ConfigError("detector window sizes must be > 0")


def _coerce_int(key: str, value: object, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key} must be an integer, got {value!r}")
    if minimum is not None and value < minimum:
        raise ConfigError(f"{key} must be >= {minimum}, got {value}")
    return value


def _coerce_float(key: str, value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{key} must be a number, got {value!r}")
    return float(value)


def _parse_hooks(raw: object) -> list[HookSpec]:
    if not isinstance(raw, list):
        raise ConfigError("hooks must be an array of tables: [[hooks]] type=\"exec\" argv=[...]")
    out: list[HookSpec] = []
    for i, item in enumerate(raw):
        where = f"hooks[{i}]"
        if not isinstance(item, dict):
            raise ConfigError(f"{where} must be a table")
        unknown = set(item) - {"type", "argv", "url", "headers", "timeout_s", "dry_run"}
        if unknown:
            known = "type, argv, url, headers, timeout_s, dry_run"
            raise ConfigError(f"{where}: unknown keys {sorted(unknown)}; valid keys are: {known}")
        htype = item.get("type")
        if htype not in _HOOK_TYPES:
            raise ConfigError(f"{where}: type must be \"exec\" or \"webhook\", got {htype!r}")
        allowed = _HOOK_TYPES[htype] | {"type"}
        bad = set(item) - allowed
        if bad:
            raise ConfigError(f"{where}: keys {sorted(bad)} do not apply to a {htype} hook")
        argv = item.get("argv", [])
        if not isinstance(argv, list) or any(not isinstance(a, str) for a in argv):
            raise ConfigError(f"{where}: argv must be an array of strings")
        headers = item.get("headers", {})
        if not isinstance(headers, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items()
        ):
            raise ConfigError(f"{where}: headers must be a string-to-string table")
        out.append(
            HookSpec(
                type=htype,
                argv=argv,
                url=str(item.get("url", "")),
                headers=headers,
                timeout_s=_coerce_float(f"{where}.timeout_s", item.get("timeout_s", 10.0)),
                dry_run=bool(item.get("dry_run", False)),
            )
        )
    return out


def _apply_detector(cfg: DetectorConfig, raw: dict) -> None:
    valid = {f.name for f in fields(DetectorConfig)}
    unknown = set(raw) - valid
    if unknown:
        sample = ", ".join(sorted(valid)[:6])
        raise ConfigError(
            f"detectors.{sorted(unknown)[0]}: unknown detector option; "
            f"valid options include {sample}, ... (see README config reference)"
        )
    ints = {
        "volume_min_count",
        "error_min_events",
        "numeric_min_samples",
        "numeric_max_fields_per_template",
    }
    for k, v in raw.items():
        if k in ints:
            setattr(cfg, k, _coerce_int(f"detectors.{k}", v, minimum=1))
        else:
            setattr(cfg, k, _coerce_float(f"detectors.{k}", v))


def config_from_dict(raw: dict, origin: str = "<defaults>") -> Config:
    cfg = Config()
    unknown = set(raw) - TOP_KEYS
    if unknown:
        raise ConfigError(
            f"{origin}: unknown config key {sorted(unknown)[0]}; "
            f"valid top-level keys are: {', '.join(sorted(TOP_KEYS))}"
        )
    if "theme" in raw:
        cfg.theme = str(raw["theme"])
    if "warmup_seconds" in raw:
        cfg.warmup_seconds = _coerce_float("warmup_seconds", raw["warmup_seconds"])
    if "max_events" in raw:
        cfg.max_events = _coerce_int("max_events", raw["max_events"], minimum=100)
    if "max_templates" in raw:
        cfg.max_templates = _coerce_int("max_templates", raw["max_templates"], minimum=10)
    if "baseline_path" in raw:
        bp = raw["baseline_path"]
        if bp is not None and not isinstance(bp, str):
            raise ConfigError("baseline_path must be a string path or null")
        cfg.baseline_path = bp
    if "baseline_max_state_bytes" in raw:
        cfg.baseline_max_state_bytes = _coerce_int(
            "baseline_max_state_bytes", raw["baseline_max_state_bytes"], minimum=1024
        )
    if "throttle_window_s" in raw:
        cfg.throttle_window_s = _coerce_float("throttle_window_s", raw["throttle_window_s"])
    if "poll_interval_s" in raw:
        cfg.poll_interval_s = _coerce_float("poll_interval_s", raw["poll_interval_s"])
    if "custom_pattern" in raw:
        cp = raw["custom_pattern"]
        if cp is not None and not isinstance(cp, str):
            raise ConfigError("custom_pattern must be a regex string with named groups or null")
        cfg.custom_pattern = cp
    if "hooks" in raw:
        cfg.hooks = _parse_hooks(raw["hooks"])
    if "detectors" in raw:
        d = raw["detectors"]
        if not isinstance(d, dict):
            raise ConfigError("detectors must be a table of detector options")
        _apply_detector(cfg.detectors, d)
    cfg.validate()
    return cfg


def load_config(path: Path | None) -> tuple[Config, str]:
    """Returns (config, description). Missing file yields defaults."""
    if path is None:
        return Config(), "<defaults>"
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"config file not found: {p}; create one or pass --config explicitly")
    try:
        raw = tomllib.loads(p.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{p}: invalid TOML ({exc}); check quotes and brackets near the error position") from exc
    return config_from_dict(raw, str(p)), str(p)


def validate_config_file(path: Path) -> list[str]:
    """For `logsift config validate`. Returns human-readable problems; empty means valid."""
    try:
        load_config(path)
    except ConfigError as exc:
        return [str(exc)]
    except OSError as exc:
        return [f"{path}: cannot read file ({exc})"]
    return []

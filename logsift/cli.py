"""Logsift CLI: run, replay, query, summary, config validate, hooks test."""

from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path

from .alerts import ExecHook, JsonlSink, WebhookHook
from .clock import Clock, SystemClock
from .config import Config, ConfigError, load_config, validate_config_file
from .engine import Engine
from .events import iso_utc
from .query import (
    QueryError,
    aggregate,
    execute,
    format_histogram,
    histogram,
    parse_query,
    top_n,
)
from .snapshot import SnapshotProvider
from .sources import DirectorySource, FileFollowSource, StdinSource, TcpSource

EXIT_OK = 0
EXIT_RUNTIME_ERROR = 1
EXIT_USAGE = 2
EXIT_CONFIG_INVALID = 3


class _StreamEnd(Exception):
    """Raised by the injected sleeper when a finite file hits EOF under follow."""


def _finite_sleeper(_seconds: float) -> None:
    raise _StreamEnd


def _fail(message: str) -> int:
    print(f"logsift: {message}", file=sys.stderr)
    return EXIT_RUNTIME_ERROR


def _parse_target(target: str) -> tuple[str, str]:
    """Returns (kind, value): stdin | file | dir | tcp."""
    if target in ("-", "stdin"):
        return "stdin", ""
    if target.startswith("dir:"):
        return "dir", target[4:]
    if target.startswith("tcp:"):
        return "tcp", target[4:]
    return "file", target


def _make_source(kind: str, value: str, cfg: Config, clock: Clock, finite: bool):
    poll = cfg.poll_interval_s
    sleeper = _finite_sleeper if finite else None
    kwargs = {"clock": clock}
    if kind == "stdin":
        source = StdinSource(**kwargs)
    elif kind == "file":
        path = Path(value)
        if not path.exists():
            raise FileNotFoundError(f"no such file: {path}")
        extra = {"sleeper": sleeper} if sleeper else {}
        source = FileFollowSource(path, poll_interval=poll, **kwargs, **extra)
    elif kind == "dir":
        path = Path(value)
        if not path.is_dir():
            raise NotADirectoryError(f"not a directory: {path}")
        extra = {"sleeper": sleeper} if sleeper else {}
        source = DirectorySource(path, poll_interval=max(poll, 0.25), **kwargs, **extra)
    elif kind == "tcp":
        host, _, port_s = value.rpartition(":")
        try:
            port = int(port_s)
        except ValueError as exc:
            raise ValueError(f"tcp target needs host:port, got {value!r}") from exc
        source = TcpSource(host or "127.0.0.1", port, **kwargs)
    else:  # pragma: no cover
        raise ValueError(f"unknown source kind {kind!r}")
    return source


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", type=str, default=None, help="TOML config file")
    parser.add_argument("--theme", type=str, default=None, help="dark|light|high_contrast|term16")
    parser.add_argument("--baseline", type=str, default=None, help="baseline state file path")
    parser.add_argument("--warmup", type=float, default=None, help="warm-up seconds")
    parser.add_argument(
        "--max-events", type=int, default=None, help="in-memory ring size (memory ceiling)"
    )
    parser.add_argument("--verbose", action="store_true", help="diagnostics to stderr")


def _apply_overrides(cfg: Config, ns: argparse.Namespace) -> Config:
    if ns.theme:
        cfg.theme = ns.theme
    if ns.baseline:
        cfg.baseline_path = ns.baseline
    if ns.warmup is not None:
        cfg.warmup_seconds = ns.warmup
    if ns.max_events is not None:
        cfg.max_events = ns.max_events
    cfg.validate()
    return cfg


def _load(ns: argparse.Namespace) -> Config:
    cfg, _desc = load_config(Path(ns.config) if ns.config else None)
    return _apply_overrides(cfg, ns)


# ------------------------------------------------------------------- run


def cmd_run(ns: argparse.Namespace) -> int:
    cfg = _load(ns)
    target = ns.target or "-"
    kind, value = _parse_target(target)
    clock = SystemClock()
    headless = ns.headless or not sys.stdout.isatty()
    finite = bool(getattr(ns, "exit_on_eof", False))

    provider = SnapshotProvider()
    sink = None
    jsonl_target = ns.jsonl
    if headless and jsonl_target is None:
        jsonl_target = "-"
    if jsonl_target == "-":
        sink = JsonlSink(sys.stdout)
    elif jsonl_target:
        handle = open(jsonl_target, "a", encoding="utf-8")
        sink = JsonlSink(handle)

    source = _make_source(kind, value, cfg, clock, finite=finite)
    engine = Engine(
        cfg,
        clock,
        provider=provider,
        alert_sink=sink,
        source_name=source.describe(),
        verbose=ns.verbose,
        eof_exceptions=((_StreamEnd,) if finite else ()),
    )

    if headless:
        try:
            engine.run_source(source)
        finally:
            if sink is not None and getattr(sink, "_stream", None) not in (None, sys.stdout):
                sink._stream.close()
        _print_engine_summary(engine, sys.stderr)
        return EXIT_OK

    from .tui.app import TuiApp
    from .tui.renderer import get_theme

    theme = get_theme(cfg.theme)

    class _Actions:
        def on_pause_toggle(self) -> None:
            engine.request_pause_toggle()

        def on_quit(self) -> None:
            engine.request_stop()

        def on_select(self, index: int) -> None:
            pass

        def on_open_detail(self) -> None:
            pass

        def on_close_detail(self) -> None:
            pass

        def on_cycle_panel(self) -> None:
            pass

    app = TuiApp(provider, theme, clock, actions=_Actions())
    worker = threading.Thread(target=engine.run_source, args=(source,), daemon=True)
    worker.start()
    app.run()
    engine.request_stop()
    worker.join(timeout=5.0)
    _print_engine_summary(engine, sys.stderr)
    if sink is not None and getattr(sink, "_stream", None) not in (None, sys.stdout):
        sink._stream.close()
    return EXIT_OK


def _print_engine_summary(engine: Engine, stream) -> None:
    s = engine.stats
    tstat_count = len(engine.index.template_stats())
    print(
        f"ingested {s.lines_total} lines -> {s.events_assembled} events "
        f"({s.unparsed} unparsed); {tstat_count} templates; "
        f"alerts {s.alerts_emitted} emitted / {s.alerts_suppressed} suppressed",
        file=stream,
    )
    if engine.source_error:
        print(f"source ended abnormally: {engine.source_error}", file=stream)


# ---------------------------------------------------------------- replay


def cmd_replay(ns: argparse.Namespace) -> int:
    cfg = _load(ns)
    clock = SystemClock()
    sink = None
    if ns.jsonl:
        handle = open(ns.jsonl, "w", encoding="utf-8")
        sink = JsonlSink(handle)
    all_alerts: list[dict] = []
    total_lines = 0
    span_lo: float | None = None
    span_hi: float | None = None

    for file_path in ns.files:
        path = Path(file_path)
        if not path.exists():
            return _fail(f"no such file: {path}")
        source = FileFollowSource(
            path, poll_interval=cfg.poll_interval_s, clock=clock, sleeper=_finite_sleeper
        )
        engine = Engine(cfg, clock, provider=None, alert_sink=sink, source_name=path.name, eof_exceptions=(_StreamEnd,))
        try:
            try:
                engine.run_source(source)
            except _StreamEnd:
                pass
            total_lines += engine.stats.lines_total
            if engine.stats.first_ts is not None and (span_lo is None or engine.stats.first_ts < span_lo):
                span_lo = engine.stats.first_ts
            if engine.stats.last_ts is not None and (span_hi is None or engine.stats.last_ts > span_hi):
                span_hi = engine.stats.last_ts
            all_alerts.extend(a.to_json_dict() for a in engine.recent_alerts())
            _print_engine_summary(engine, sys.stderr)
        finally:
            source.stop()
    if sink is not None:
        sink._stream.close()

    print(f"replay complete: {total_lines} lines, {len(all_alerts)} alerts", file=sys.stderr)
    for alert in all_alerts[:20]:
        marker = alert.get("marker", "!")
        sev = str(alert.get("severity", "")).upper()
        print(
            f"  {marker} {sev} [{alert.get('detector')}] {alert.get('template', '')[:60]} "
            f"@ {alert.get('time', '')}",
            file=sys.stderr,
        )
    if ns.suggest is not None:
        _print_threshold_suggestions(all_alerts, ns.suggest, span_lo, span_hi, sys.stderr)
    return EXIT_OK


def _print_threshold_suggestions(
    alerts: list[dict], target_per_hour: float, span_lo: float | None, span_hi: float | None, stream
) -> None:
    if span_lo is None or span_hi is None or span_hi <= span_lo:
        print("threshold suggestions: no timed data observed; cannot suggest", file=stream)
        return
    span_hours = max(1e-6, (span_hi - span_lo) / 3600.0)
    current_rate = len(alerts) / span_hours
    print("threshold suggestions (heuristic starting point - validate with another replay):", file=stream)
    if not alerts:
        print(f"  no alerts fired; to catch MORE, lower detector bands in config (current target {target_per_hour}/h)", file=stream)
        return
    scale = (current_rate / max(target_per_hour, 0.01)) ** 0.5
    scale = min(4.0, max(0.5, scale))
    print(f"  current alert rate ~{current_rate:.2f}/h, target {target_per_hour:.2f}/h", file=stream)
    print(f"  suggested: multiply z-band thresholds by {scale:.2f}", file=stream)
    print("  [detectors]", file=stream)
    print(f"  volume_anomalous_z = {6.0 * scale:.1f}", file=stream)
    print(f"  error_anomalous_z = {4.0 * scale:.1f}", file=stream)
    print(f"  numeric_anomalous_z = {5.0 * scale:.1f}", file=stream)


# ----------------------------------------------------------------- query


def cmd_query(ns: argparse.Namespace) -> int:
    cfg = _load(ns)
    clock = SystemClock()
    engine = Engine(cfg, clock, provider=None, source_name="query", eof_exceptions=(_StreamEnd,))
    params = {
        k: v
        for k, v in {
            "since": ns.since,
            "until": ns.until,
            "level": ns.level,
            "template_id": ns.template_id,
            "template_contains": ns.template_contains,
            "field_key": ns.field_key,
            "field_value": ns.field_value,
            "free_text": ns.text,
        }.items()
        if v is not None
    }
    try:
        spec = parse_query(params)
    except QueryError as exc:
        print(f"logsift: {exc.message}", file=sys.stderr)
        return EXIT_USAGE

    for file_path in ns.files:
        path = Path(file_path)
        if not path.exists():
            return _fail(f"no such file: {path}")
        source = FileFollowSource(
            path, poll_interval=cfg.poll_interval_s, clock=clock, sleeper=_finite_sleeper
        )
        engine.source_name = path.name
        try:
            engine.run_source(source)
        except _StreamEnd:
            pass
        finally:
            source.stop()

    result = execute(engine.index, spec)
    print(f"matched {result.matched} of {result.scanned} indexed events")
    if ns.aggregate:
        try:
            counter = aggregate(result.rows, ns.aggregate)
        except QueryError as exc:
            print(f"logsift: {exc.message}", file=sys.stderr)
            return EXIT_USAGE
        for key, count in counter.most_common(20):
            print(f"{key}: {count}")
    elif ns.histogram:
        buckets = histogram(result.rows, ns.bucket_seconds)
        for line in format_histogram(buckets, width_chars=ns.hist_width):
            print(line)
    else:
        shown = result.rows[-ns.limit :] if ns.limit else result.rows
        for row in shown:
            ts = iso_utc(row.ts)[11:19]
            lvl = row.level or "-"
            tpl = row.template_text[:80]
            print(f"{ts} {lvl:<8} {tpl}")
        if result.matched > len(shown):
            print(f"... {result.matched - len(shown)} older matches evicted or truncated")
    return EXIT_OK


# --------------------------------------------------------------- summary


def cmd_summary(ns: argparse.Namespace) -> int:
    cfg = _load(ns)
    clock = SystemClock()
    since = ns.since
    until = ns.until
    engine = Engine(cfg, clock, provider=None, source_name="summary", eof_exceptions=(_StreamEnd,))

    for file_path in ns.files:
        path = Path(file_path)
        if not path.exists():
            return _fail(f"no such file: {path}")
        source = FileFollowSource(
            path, poll_interval=cfg.poll_interval_s, clock=clock, sleeper=_finite_sleeper
        )
        engine.source_name = path.name
        try:
            engine.run_source(source)
        except _StreamEnd:
            pass
        finally:
            source.stop()

    s = engine.stats
    tstats = engine.index.template_stats()
    alerts = [
        a
        for a in (x.to_json_dict() for x in engine.recent_alerts())
        if (since is None or _iso_to_epoch(a.get("time")) >= since)
        and (until is None or _iso_to_epoch(a.get("time")) < until)
    ]
    print("=== Logsift summary ===")
    print(f"lines: {s.lines_total}  events: {s.events_assembled}  unparsed: {s.unparsed} ({100.0 * s.unparsed / max(1, s.lines_total):.1f}%)")
    err_pct = 100.0 * s.error_level_events / max(1, s.parsed_ok)
    print(f"error-level share: {err_pct:.2f}%   distinct templates: {len(tstats)}")
    if since or until:
        print(f"window: {since or 'start'} .. {until or 'end'}")
    print(f"alerts in window: {len(alerts)} (emitted {s.alerts_emitted}, suppressed {s.alerts_suppressed})")
    for a in alerts[:30]:
        print(
            f"  {a.get('marker')} {str(a.get('severity')).upper():<9} [{a.get('detector')}] "
            f"{str(a.get('template'))[:56]} @ {a.get('time')}"
        )
        print(f"      baseline {a.get('baseline', {}).get('desc', '')}; observed {a.get('observed', {}).get('desc', '')}")
    top = sorted(tstats.values(), key=lambda t: -t.count)[:10]
    print("top templates:")
    for t in top:
        pct = 100.0 * t.count / max(1, s.parsed_ok)
        print(f"  {t.count:>8}  {pct:5.1f}%  {t.text[:64]}")
    return EXIT_OK


def _iso_to_epoch(value: object) -> float:
    # Alerts carry ISO strings; compare lexically is wrong across years, parse properly.
    from datetime import datetime, timezone

    if isinstance(value, (int, float)):
        return float(value)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return dt.timestamp() if dt.tzinfo else dt.replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return 0.0


# ---------------------------------------------------------------- config


def cmd_config(ns: argparse.Namespace) -> int:
    path = Path(ns.file) if ns.file else Path("logsift.toml")
    problems = validate_config_file(path)
    if not path.exists() and ns.file is None:
        print("no config file found (defaults active); nothing to validate")
        return EXIT_OK
    if problems:
        for p in problems:
            print(f"INVALID: {p}", file=sys.stderr)
        return EXIT_CONFIG_INVALID
    print(f"{path}: valid")
    return EXIT_OK


def cmd_hooks_test(ns: argparse.Namespace) -> int:
    cfg, _ = load_config(Path(ns.config) if ns.config else None)
    if not cfg.hooks:
        print("no hooks configured; add [[hooks]] entries to your config (see README)")
        return EXIT_OK
    payload = {
        "schema": "logsift.alert/1",
        "id": "a-test000",
        "time": iso_utc(SystemClock().now()),
        "severity": "anomalous",
        "marker": "!",
        "detector": "volume",
        "template_id": 0,
        "template": "synthetic hooks-test payload",
        "baseline": {"desc": "n/a", "value": None},
        "observed": {"desc": "n/a", "value": None},
        "deviation": {"desc": "n/a", "z": None},
        "threshold": {"desc": "n/a", "value": None},
        "window": {"start": iso_utc(0), "end": iso_utc(0)},
        "group_key": "hooks-test",
        "count": 1,
        "suppressed": 0,
        "first_seen": iso_utc(0),
        "examples": [],
        "evidence_before": [],
    }
    failures = 0
    for spec in cfg.hooks:
        hook: ExecHook | WebhookHook
        if spec.type == "exec":
            hook = ExecHook(argv=spec.argv, timeout_s=spec.timeout_s, dry_run=True)
        else:
            hook = WebhookHook(url=spec.url, headers=spec.headers or None, timeout_s=spec.timeout_s, dry_run=True)
        result = hook.deliver(payload)
        status = "ok" if result.ok else "FAILED"
        if not result.ok:
            failures += 1
        print(f"{spec.type} hook ({spec.url or ' '.join(spec.argv)}): {status} - {result.detail}")
    return EXIT_RUNTIME_ERROR if failures else EXIT_OK


# ------------------------------------------------------------------ main


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="logsift",
        description="Streaming log analyzer with explainable anomaly detection.",
    )
    ap.add_argument("--version", action="version", version=f"logsift {_get_version()}")
    sub = ap.add_subparsers(dest="command")

    p_run = sub.add_parser("run", help="analyse a live stream (TUI on a terminal)")
    p_run.add_argument("target", nargs="?", default="-", help='"-", a file path, dir:PATH, or tcp:host:port')
    p_run.add_argument("--headless", action="store_true", help="JSONL alerts to stdout instead of TUI")
    p_run.add_argument("--exit-on-eof", dest="exit_on_eof", action="store_true", help="stop when a file source reaches EOF instead of following")
    p_run.add_argument("--jsonl", type=str, default=None, help='alert JSONL destination ("-": stdout)')
    _add_common(p_run)
    p_run.set_defaults(func=cmd_run)

    p_rep = sub.add_parser("replay", help="run detection over historical files at speed")
    p_rep.add_argument("files", nargs="+")
    p_rep.add_argument("--jsonl", type=str, default=None, help="write alert JSONL here")
    p_rep.add_argument("--suggest", type=float, default=None, metavar="PER_HOUR", help="suggest thresholds toward this alert rate")
    _add_common(p_rep)
    p_rep.set_defaults(func=cmd_replay)

    p_q = sub.add_parser("query", help="filter/aggregate/histogram over an input")
    p_q.add_argument("files", nargs="+")
    p_q.add_argument("--since", type=float, default=None, help="epoch seconds (inclusive)")
    p_q.add_argument("--until", type=float, default=None, help="epoch seconds (exclusive)")
    p_q.add_argument("--level", type=str, default=None)
    p_q.add_argument("--template-id", dest="template_id", type=str, default=None)
    p_q.add_argument("--template-contains", dest="template_contains", type=str, default=None)
    p_q.add_argument("--field-key", dest="field_key", type=str, default=None)
    p_q.add_argument("--field-value", dest="field_value", type=str, default=None)
    p_q.add_argument("--text", type=str, default=None)
    p_q.add_argument("--aggregate", type=str, default=None, help="level|template|source")
    p_q.add_argument("--top", type=int, default=20)
    p_q.add_argument("--histogram", action="store_true")
    p_q.add_argument("--bucket-seconds", dest="bucket_seconds", type=float, default=60.0)
    p_q.add_argument("--hist-width", dest="hist_width", type=int, default=40)
    p_q.add_argument("--limit", type=int, default=50)
    _add_common(p_q)
    p_q.set_defaults(func=cmd_query)

    p_sum = sub.add_parser("summary", help="summary report for a time range")
    p_sum.add_argument("files", nargs="+")
    p_sum.add_argument("--since", type=float, default=None)
    p_sum.add_argument("--until", type=float, default=None)
    _add_common(p_sum)
    p_sum.set_defaults(func=cmd_summary)

    p_cfg = sub.add_parser("config", help="configuration utilities")
    cfg_sub = p_cfg.add_subparsers(dest="config_command")
    p_val = cfg_sub.add_parser("validate", help="validate a config file")
    p_val.add_argument("--file", type=str, default=None)
    p_cfg.set_defaults(func=cmd_config)

    p_hooks = sub.add_parser("hooks", help="hook utilities")
    hooks_sub = p_hooks.add_subparsers(dest="hooks_command")
    p_ht = hooks_sub.add_parser("test", help="dry-run configured hooks with a synthetic payload")
    p_ht.add_argument("--config", type=str, default=None)
    p_ht.set_defaults(func=cmd_hooks_test)

    return ap


def _get_version() -> str:
    from . import __version__

    return __version__


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    ns = parser.parse_args(argv)
    if not getattr(ns, "func", None):
        parser.print_help(sys.stderr)
        return EXIT_USAGE
    try:
        return ns.func(ns)
    except ConfigError as exc:
        print(f"logsift: invalid config: {exc}", file=sys.stderr)
        return EXIT_CONFIG_INVALID
    except FileNotFoundError as exc:
        return _fail(str(exc))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_OK
    except BrokenPipeError:
        return EXIT_OK
    except Exception as exc:  # noqa: BLE001 - last-resort guard reports honestly
        import traceback

        traceback.print_exc(file=sys.stderr)
        return _fail(f"unexpected failure: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    sys.exit(main())



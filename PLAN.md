# Logsift — Feature Plan

Judged against three tests: (A) serves the core purpose of surfacing the unusual
thing in a log stream; (B) can be finished to the same quality bar as the rest
of the tool; (C) stays inside scope — log storage/search platforms, distributed
collection fleets, metrics/tracing systems, and incident-management workflows
are second products and are out.

## Core features (the mission)

| # | Feature | Status |
|---|---------|--------|
| 1 | Streaming ingestion: stdin, file-follow with rotation/truncation handling, directory of rotated/compressed files, TCP socket — one source interface, bounded memory | core |
| 2 | Formats: JSON lines, logfmt, access logs (common+combined), syslog, user-supplied named-capture pattern; auto-detection with stated confidence; unparseable lines reported, never silently dropped | core |
| 3 | Multi-line event assembly by configurable continuation rules | core |
| 4 | Log templating: Drain-style variable-token clustering ("user 4821 not found" and "user 9134 not found" → one template + parameters). Proper algorithm, not a regex list | core |
| 5 | Detectors, each explainable: volume vs per-template seasonal baseline; newly-appearing templates; stopped templates; error-rate shift; numeric-field distribution shift (Mann–Whitney U on trailing windows); rare sequence (n-gram rarity). Every alert names detector, baseline, observed value, deviation, threshold, window, examples | core |
| 6 | Baseline learning: warm-up period, persistence between runs, exclusion marking for abnormal periods | core |
| 7 | Query interface: filter by time/level/field/template/free text; aggregate by any field; top-N; time-bucketed histogram — over the streaming index | core |
| 8 | Live TUI (throughput, error rate, top templates, anomaly feed, template detail view) + headless JSON alert mode for piping | core |
| 9 | Alert throttling/dedup/grouping; webhook and exec hooks | core |
| 10 | Retention/bounded resources: enforced memory and disk ceilings with a stated drop policy | core |
| 11 | Replay mode over historical files at speed, same code path as live ingestion | core |

## Ideation round — ACCEPTED

- **Zero-config sensible defaults** — no flags, no config: all six detectors on
  with conservative thresholds, works on the first run. Accepted: the difference
  between used-once and used-daily.
- **Config file + `logsift config validate`** — TOML config with exact
  file/line diagnostics for invalid fields. Accepted: cheap, high-leverage trust.
- **Actionable input diagnostics** — unmatched pattern prints offending line,
  format guess, fix hint; unreadable file states cause and continues or exits
  deliberately. Accepted: silent partial ingestion is the worst failure mode.
- **`--explain` / explainable alerts** — baseline, observed, deviation,
  threshold in every alert (TUI and JSON). Accepted: an alert without a why is noise.
- **Replay-driven threshold suggestions** — after replay, table of suggested
  thresholds toward a target alert rate; user copies into config. Accepted:
  arithmetic over data replay already computes; no auto-tuning service.
- **Alert evidence pack** — bounded ring buffer of preceding raw lines plus up
  to 3 sample lines of the anomalous template attached to each alert.
  Accepted: anomalies are only interpretable with their neighbors.
- **Summary report for a time range** (`logsift summary`) — alerts fired, top
  new/stopped templates, volume curve as text. Accepted: closes the loop from
  live flagging to postmortem review.
- **Hook dry-run (`logsift hooks test`)** — fires each hook with a synthetic
  payload, prints status/latency. Accepted: a broken hook is a silently missed alert.
- **TUI keyboard triage, tightly scoped** — pause/resume, select alert/template,
  detail view with evidence pack. No general-purpose log browsing pager.
  Accepted with the scope fence.

## Ideation round — REJECTED

- **Shell completion scripts** — zero effect on finding anomalies at 3am;
  polish, wrong priority for v1. Revisit post-1.0 if ever.
- **Persistent searchable log archive** — full-text indexed storage with
  retention policies is explicitly the storage-platform second product; the
  query interface already covers recent windows within bounded memory.
- **Managed notification integrations** (Slack/PagerDuty/email/on-call routing)
  — generic webhook/exec hooks cover transport; everything past that is
  incident-management workflow, someone else's product.
- **Semantic template labeling** ("nginx upstream timeout" style names) —
  heuristic coverage is an endless tail; a wrong label destroys trust faster
  than no label. Ship verbatim sample lines instead.
- **Secrets/PII redaction engine** — regex coverage promises we cannot keep;
  false confidence is worse than none. Documented risk instead.

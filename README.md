# Logsift

> **built with ox alpha**
>
> most of this was written in august 2026 during the free preview window of
> [ox alpha](https://openrouter.ai/stealth/ox-alpha), an anonymous stealth model
> that turned up on openrouter for about a week. i set the direction and reviewed
> what came back. the tests are real and they pass — clone it and run them.

Logsift is a streaming log analyzer that learns the normal shapes of your log
messages and flags anomalies as they happen - built for engineers who need to
find the unusual thing in millions of lines without knowing in advance what
they are looking for.

No account, no agent fleet, no index server: one process reads a stream,
clusters messages into templates, keeps seasonal baselines, and tells you -
with evidence - when something breaks the pattern.

## Install

Requires Python 3.11+. No third-party dependencies.

```bash
git clone https://github.com/TheFadGhost/logsift.git
cd logsift
pip install .          # installs the `logsift` command
```

Run the test suite (245+ tests):

```bash
python -m pytest tests -p no:cacheprovider
```

## 30-second demo

Generate a synthetic 120k-line corpus (mixed formats, daily seasonality, six
labelled anomalies injected) and run detection over it:

```bash
python tools/gen_corpus.py --out generated/demo --lines 120000 --seed 7
logsift replay generated/demo/corpus.jsonl --warmup 3600
```

Watch it live in the TUI:

```bash
logsift run generated/demo/corpus.jsonl        # follows; Ctrl+C or q to quit
logsift run -                                  # stdin
logsift run tcp:0.0.0.0:5140                   # TCP listener
logsift run dir:C:/logs/myapp                  # rotated + gzipped directory (any OS path)
```

Headless JSON alerts for piping:

```bash
logsift run /var/log/app.log --headless | jq .detector
```

The TUI (plain-text capture from a live run over the demo corpus):

`````text
logsift src corpus.jsonl                                                                              up 1.44s
in   14.1k l/s  win   14.1k l/s  err    0.7%  unparsed       0 (0.0%)  events   21.4k                         
──────────────────────────────────────────────────────────────────────────────────────────────────────────────
┌─ top templates ────────────────────────────────────────────────────────────────────────────────────────────┐
│      t7    3012   14.1% ████████████ {*} {*} {*}                                                           │
│      t2    2411   11.2% █████████▋ request routed to upstream {*} status {*} in {*} ms                     │
│      t3    1749    8.2% ███████ login succeeded for user {*}                                               │
│     t16    1130    5.3% ████▌ charge captured for order {*} amount {*} {*}                                 │
│     t11    1059    4.9% ████▎ job {*} finished in {*} ms exit {*}                                          │
│     t28     964    4.5% ███▉ query plan cache hit ratio {*} for cohort {*}                                 │
│      t8     884    4.1% ███▌ session token rotated for user {*}                                            │
│      t9     844    3.9% ███▍ accepted public key for user {*} from {*} port {*}                            │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
┌─ anomaly feed ─────────────────────────────────────────────────────────────────────────────────────────────┐
│  ! anomalous rare_sequence      t2 request routed to upstream {*} status {*} in {*} ms           12:11:38  │
│  baseline seen 0 times during learning (n-gram 3->7->2) -> observed 4 times in 10m rare ordering (thr      │
│  baseline<=2 and k>=4 in 10m)                                                                              │
│  + elevated  new_template      t40 purge plan {*} committed across {*} regions                   09:46:00  │
│  baseline not present in baseline history -> observed first occurrence at 2026-06-01T09:45:00.006Z (count  │
│  12 since) new template (thr warm-up complete + not seen in baseline)                                      │
│  ! anomalous rare_sequence     t33 job {*} parked in dead letter after {*} attempts              03:04:30  │
│  baseline seen 0 times during learning (n-gram 17->27->33) -> observed 4 times in 10m rare ordering (thr   │
│  baseline<=2 and k>=4 in 10m)                                                                              │
│  + elevated  new_template      t36 compaction merged {*} segments on volume {*}                  00:33:10  │
│  baseline not present in baseline history -> observed first occurrence at 2026-06-01T00:32:06.440Z (count  │
│  2 since) new template (thr warm-up complete + not seen in baseline)                                       │
│                                                                                                            │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
 connected                                                       tab panels / enter detail / p pause / q quit 
                                                                                                              `````

## Supported input formats

| Format | Notes |
|--------|-------|
| JSON lines | `timestamp`/`time`/`ts`/`@timestamp` keys; nested objects flattened one level |
| logfmt | `key=value`, quoted values with escapes |
| Access logs | Apache common + combined; status maps to level (5xx = error) |
| syslog | RFC3164 and RFC5424; RFC3164 year inferred from ingest date |
| Custom | Your regex with named groups (`ts`, `level`, `message` special-cased) |

Format auto-detection samples up to the first 200 lines and locks the best format with a stated confidence.
Unparseable lines are never silently dropped: they are counted, shown in the
header (`unparsed N (x.y%)`), listed in the detail view with the reason, and
reported at exit. Invalid UTF-8 decodes losslessly with U+FFFD and is flagged.

Multi-line events: stack traces and continuation lines are assembled into ONE
event by configurable rules (indentation, Java/Python frame patterns,
unterminated JSON objects). A 40-line stack trace is one event, so downstream
statistics stay meaningful. Oversized events split at configurable caps rather
than growing without bound.

## How templating works

Messages are tokenised on whitespace; tokens containing digits are masked to
`<*>` before matching (so `od-81234`, IPs, UUIDs and latencies cannot fragment
clusters). A message joins the first template with the same token count whose
positions disagree in fewer than half of all positions; disagreements become
slots. `"user 4821 login failed"` and `"user 9134 login failed"` become one
template `user <*> login failed` with per-event parameters. The template table
is bounded (`max_templates`, default 5000) with least-recently-seen eviction;
baselines key on template TEXT so ids can be reissued safely.

## Detectors

All six run by default after warm-up. Every alert states: detector name, the
template, the baseline (what was expected), the observed value, the deviation,
the threshold that fired, the time window, and example lines - in the TUI and
in every JSON payload. No bare scores.

| Detector | Catches | Misses (stated honestly) |
|----------|---------|--------------------------|
| `volume` | Hourly count spikes vs hour-of-week baselines (robust z on median/MAD). Falls back to hour-of-day history in the first week; first observation of an hour learns silently. | Slow ramps within normal range; brand-new templates (that is `new_template`'s job); outages shorter than one bucket. |
| `new_template` | Message shapes never seen during warm-up, especially bursts. One-off oddities are suppressed (default: needs 2 occurrences in 60s) - that is where most noise lives. | Genuine one-line-only novel messages; templates evicted and relearned fire again once. |
| `stopped_template` | Established templates going silent (gap > factor x expected interval, expected volume above floor). Suppressed while many peers are silent too (systemic events belong to `volume`). | Low-volume templates; stops shorter than gap_factor x interval. |
| `error_rate` | Error-level share jumps via pooled two-proportion z-test on a 60s window vs trailing 300s. Silent when the baseline holds <3 errors (degenerate test) or windows are too thin. | Slow error creep below the z-band; error bursts inside windows thinner than `error_min_events`. |
| `numeric_shift` | Distribution shifts of numeric fields (`duration_ms`, `bytes`, ...) via Mann-Whitney U: last 30 samples vs prior 90. Sample-based, so slow streams still get judged once enough evidence exists. | Variance changes without a median shift; fields that appear only after eviction from the bounded ring. |
| `rare_sequence` | Unusual ORDERINGS: temporally contiguous n-grams (default 3 events within 2s) unseen in learning, with rare adjacent pairs, repeated 4+ times in 10 minutes. Suppressed when one template floods >60% of recent traffic (that is a volume story) and rate-capped at 3/hour. | Orderings spread over minutes; anything involving fewer than min-component occurrences; long-range patterns beyond n=3. |

Severity bands (elevated/anomalous/critical) come from each detector's score:
robust z, two-proportion z, MW-U z, occurrence counts, or silence ratios - all
declared in config, restated in every alert.

## Detection quality (measured, not claimed)

Corpus: `tools/gen_corpus.py --lines 120000 --seed 7` - 120k synthetic lines
(JSON/logfmt/access/syslog mix) across a simulated 72 hours with daily
seasonality, plus exactly one injected anomaly of each kind at documented,
non-overlapping times (`generated/demo/labels.json`). Evaluation:
`tools/eval_corpus.py` matches alerts to labels by detector kind and time
window (+/- 30 min); unmatched alerts are false positives.

Result with default thresholds and `--warmup 3600`:

```
detector           labels   tp   fp  missed   prec  recall
volume                  1    1    0       0  1.000   1.000
new_template            1    1    0       0  1.000   1.000
stopped_template        1    1    0       0  1.000   1.000
error_rate              1    1    0       0  1.000   1.000
numeric_shift           1    1    0       0  1.000   1.000
rare_sequence           1    1    0       0  1.000   1.000
```

Read this correctly: eight alerts fired for six injections (repeat detections
inside anomaly windows are counted once per label). Perfect scores on ONE
seeded corpus with SIX injections mean the pipeline finds these classes of
anomaly with zero noise on this corpus - not that false positives are
impossible in production. The corpus generator is committed; regenerate with
other seeds and judge for yourself before trusting any threshold.

Replay is deterministic: identical input files produce byte-identical alert
sequences (asserted by test), because detection runs on event time end to end.

## Throughput and resource ceilings

Method: `tools/bench_ingest.py --input FILE --runs N` feeds the file through
the real pipeline in-process and times with monotonic clock deltas. Hardware
for the numbers below: Windows 10 (build 26200), 28 CPUs, Python 3.11.9;
input `generated/demo/corpus.jsonl` (18.4 MB, avg line 153 B, mixed JSON/
logfmt/access/syslog).

- Parse + template + index (no detectors): **~25,700 lines/s** (fresh process).
- Full pipeline with all six detectors: **~7,900 lines/s** (fresh process,
  logfmt-heavy synthetic stream, `tools/mem_check.py`).

Memory ceiling: the streaming index is a hard ring (`max_events`, default
100,000 rows; oldest dropped first). Measured peak working set for a
5,000,000-line run (763 MB file): **151.8 MB**, with exactly 100,000 rows
retained and 4,900,000 evicted - `tools/mem_check.py --ceiling-mb 600`.
Template table capped at `max_templates` (LRU); baseline sample rings capped
per key; disk state capped at `baseline_max_state_bytes` (oldest samples
dropped first, round-robin across keys, then oldest error windows; exclusion
windows are never trimmed). When ceilings hit, data is dropped oldest-first
and counted - nothing silently grows.

## Baselines between runs

```bash
logsift replay day1.log --baseline logsift.state
logsift run - --baseline logsift.state      # resumes learning
```

Warm-up (default 3600s of observed span or 24 distinct hour slots) suppresses
all detectors until a baseline exists. Mark a bad period so it never poisons
the baseline:

```python
store.mark_abnormal(start_epoch, end_epoch)   # persisted, filtered at load
```

After a replay, `--suggest ALERTS_PER_HOUR` prints heuristic threshold
adjustments toward a target alert rate - a starting point to copy into config
and validate with another replay, not auto-tuning.

## Config reference (`logsift.toml`)

```toml
theme = "dark"                # dark | light | high_contrast | term16
warmup_seconds = 3600.0
max_events = 100000           # in-memory ring size
max_templates = 5000
baseline_path = "logsift.state"
baseline_max_state_bytes = 8388608
throttle_window_s = 300.0     # same-group alert suppression window
poll_interval_s = 0.25
# custom_pattern = '(?P<ts>\\S+) (?P<level>\\w+) (?P<message>.*)'

[[hooks]]
type = "exec"                 # payload arrives on STDIN, never via shell
argv = ["python", "C:/opt/oncall.py"]   # any executable + script
timeout_s = 10.0
# dry_run = true              # print instead of executing

[[hooks]]
type = "webhook"              # POST alert JSON to your endpoint
url = "https://alerts.example.test/hook"
headers = { Authorization = "Bearer ..." }
dry_run = true

[detectors]                   # all keys optional; every default lives in logsift/detectors/base.py
volume_elevated_z = 4.0
volume_anomalous_z = 6.0
volume_critical_z = 10.0
error_anomalous_z = 4.0
numeric_anomalous_z = 5.0
sequence_min_observed = 4
sequence_max_alerts_per_hour = 3
sequence_max_dominant_share = 0.6
```

Validate with exact diagnostics:

```bash
logsift config validate --file logsift.toml
```

Test hooks without firing them at anyone:

```bash
logsift hooks test --config logsift.toml
```

Exit codes: 0 success, 1 runtime error, 2 usage, 3 invalid config.

## Query interface

Over any input, using the same ingestion path:

```bash
logsift query app.log --level error --since 1772323200 --limit 20
logsift query app.log --aggregate service --top 10
logsift query app.log --histogram --bucket-seconds 3600
logsift summary app.log --since 1772409600
```

## Alert JSON schema (`logsift.alert/1`)

One alert per line, machine-formatted, never coloured:

```json
{
  "schema": "logsift.alert/1",
  "id": "a-000001",
  "time": "2026-06-02T14:00:00.000Z",
  "severity": "critical",
  "marker": "!!",
  "detector": "volume",
  "template_id": 14,
  "template": "worker <*> heartbeat lane <*> lag <*> s",
  "baseline": {"desc": "...", "value": 109.0},
  "observed": {"desc": "...", "value": 1075.0},
  "deviation": {"desc": "...", "z": 11.9},
  "threshold": {"desc": "...", "value": 4.0},
  "window": {"start": "...", "end": "..."},
  "group_key": "volume:<template text>",
  "count": 1,
  "suppressed": 0,
  "first_seen": "...",
  "examples": ["...raw lines..."],
  "evidence_before": ["...preceding raw lines..."],
  "incident": null
}
```

`incident` is an optional correlation id when multiple detectors fire on the
same template within 120s. Hooks receive this exact payload on stdin (exec) or
as the POST body (webhook) - log content is hostile input and never touches a
shell argument.

## Architecture note

Ingestion pipeline: source reader thread -> bounded queue (backpressure, no
unbounded buffering) -> multiline assembler -> parser registry (auto-detected
and locked) -> Drain templater -> six detectors -> bounded ring index ->
snapshot publisher -> TUI (diff-rendered, <=10 fps) or JSONL sink. Detector
ticks follow EVENT time, so replaying historical files behaves identically to
live tailing. All timing flows through an injected clock; the suite enforces
this by grep and by construction. Colour goes through one semantic token table
(seven tokens, four themes including a deuteranopia-verified high-contrast
theme and a 16-colour theme); `NO_COLOR`, non-TTY output and dumb terminals
get plain text automatically.

## License

MIT - see LICENSE.
# Logsift Design

## Point of view

Logsift is a precise instrument that reports honestly and never cries wolf. It
is built for the engineer who, at 3am, must decide in two seconds whether an
alert deserves action; every design choice serves that decision. An alert that
cannot state its own evidence - what was expected, what arrived, by how much it
exceeded expectation, against what threshold - does not ship. Layouts do not
move, numbers do not change width, severity is always carried by a word and a
marker and never by colour alone, and nothing blinks. When Logsift is quiet,
that means something: the stream looked normal. Trust is the product; the TUI
is just its face.

## 1. TUI layout

Three fixed width classes. Panel proportions are fixed per class and never
change between refreshes.

```
wide      (cols >= 120)
+ header ---------------------------------------------------------------+ 3 rows
| rates / error% / unparsed% / totals / uptime                           |
+------------------------------+-----------------------------------------+
| TOP TEMPLATES        38%     | ANOMALY FEED                     62%    | body
+------------------------------+-----------------------------------------+
| status bar                                                             | 2 rows

standard  (80 <= cols < 120): stacked vertically - header 3 rows,
TOP TEMPLATES 40% of remaining body height, ANOMALY FEED 60%, status 2 rows.
narrow    (cols < 80): header 2 rows (compact fields), ANOMALY FEED takes
70% of body, TOP TEMPLATES reachable by Tab toggle, status bar 2 rows.
```

Rule for what earns space: the anomaly feed always holds the largest share of
body height in every width class; the template detail view opens as an overlay
covering about 80% of the terminal, centred, closed with Esc. Panels are drawn
at identical coordinates every frame; a panel changes position only when the
terminal is resized across a width-class boundary or the data structure itself
changes (overlay opened/closed).

Header fields, left to right, fixed-width slots: source name (truncated to 16),
ingest rate, window rate, error rate, unparsed rate, event total, warm-up
progress or uptime. Every numeric slot has a constant rendered width (section
5) so nothing shifts.

Status bar, left: source state (`connected`, `disconnected - retry 3`, `eof`,
`paused`); centre: detector enable states; right: key hints
(`tab panels / enter detail / p pause / q quit`) - hints dim, never animated.

## 2. Anatomy of an anomaly alert

Every alert - TUI feed entry, detail view, and JSON - carries the same eight
facts. The feed entry answers "why did this fire" with no drilling:

```
!! CRITICAL  volume   t42  user {4821} login failed                03:14:07
   baseline 12/hr (slot Mon 03:00, n=26) -> observed 310/hr  25.8x  z=14.2 (thr z>6)
```

Line 1: severity marker + word, detector name, template id, rendered template
(variable slots per section 3), event time. Line 2: baseline description and
value, observed value, ratio/deviation, named statistic with threshold. Long
forms wrap under line 2 with a two-space hang indent; nothing hides behind
interaction. Detail view adds: sparkline of the template's history (section 4),
the evidence pack (up to 3 sample lines of the template plus bounded context
lines around the triggering event), and the same numbers verbatim.

Detector ids are fixed: `volume`, `new_template`, `stopped_template`,
`error_rate`, `numeric_shift`, `rare_sequence`.

Severity mapping - word + marker + token always together:
`normal` marker `.`, `elevated` `+`, `anomalous` `!`, `critical` `!!`.
Each detector emits a numeric score; severity comes from fixed bands declared
in config defaults and restated in every explanation.

## 3. Template rendering

A template is fixed text interleaved with variable slots. Slots render in the
accent token wrapped in braces: message `user 4821 login failed` against
template `user <*> login failed` renders as `user ` + accent(`{4821}`) +
` login failed`. In monochrome mode the braces alone carry the distinction.
A slot value longer than 24 display columns truncates width-aware to
`{4821...}`. Slot boundaries are semantic (Drain positions) and adjacent slots
are never merged for display.

Long messages truncate to the panel width preserving both ends: keep the first
30% and last 60% of available display columns joined by `...` (counted as
width 3), because log messages carry identity at the front and consequence at
the end ("connection to db-primary:5432 timed out"). Truncation is computed on
display width (section 7), never byte or rune count.

## 4. Sparklines and histograms

Vertical sparklines (template history): Unicode blocks U+2581-U+2588
(`▁▂▃▄▅▆▇█`) with space for zero - nine states per cell. Sub-cell resolution
is defined as: values normalise to the cell maximum and quantise to these nine
levels (nearest, ties up); quantisation loss is compensated by printing the
numeric min and max beside every sparkline (`min 3 max 310`), so magnitude
information is stated numerically rather than faked with finer glyphs.

Horizontal bars (top-N lists, histograms): full blocks repeated, terminated by
an eighth-fraction block from `▏▎▍▌▋▊▉` chosen by the remainder - genuine
sub-cell horizontal resolution. Bar length maps linearly to the panel maximum;
the numeric value always sits right of the bar in fixed-width form.

Time-bucketed histograms show bucket start time dim on the left, horizontal
bar centre, count fixed-width on the right.

## 5. Numbers, durations, rates

Fixed once, used everywhere in the TUI (JSON is machine-formatted separately
with full precision):

| Kind     | Rule                                                     | Fixed width     |
|----------|----------------------------------------------------------|-----------------|
| count    | < 10000: integer; >= 10k: `12.3k`; >= 10M: `1.23M`       | 7, right-aligned |
| rate     | counts per second, same numeric rule + ` l/s` label      | 11              |
| percent  | one decimal (`  1.2%`)                                   | 7               |
| duration | < 1ms: `920us`; < 1000s: `12.4ms` / `3.20s`; else m:ss   | 7               |

All numbers render right-aligned into constant-width slots. A value that grows
past its slot width never widens the slot; it steps to the next unit rule
above. No number anywhere in the TUI changes cell width between refreshes.

## 6. Colour tokens and themes

Exactly seven semantic tokens. Rendering code never touches raw colour codes;
it requests tokens from a theme object. One token table, four themes.

| Token     | Meaning                                | Severity word |
|-----------|----------------------------------------|---------------|
| normal    | healthy / info-level text              | normal        |
| elevated  | worth noticing                         | elevated      |
| anomalous | an anomaly fired                       | anomalous     |
| critical  | severe anomaly / source failure        | critical      |
| dim       | secondary metadata, hints, old entries | -             |
| border    | panel borders, separators              | -             |
| accent    | template variable slots, selection     | -             |

Themes, selected in config as `theme = "dark" | "light" | "high_contrast" |
"term16"`: dark is the default; light for bright terminals; high_contrast uses
a blue/orange severity ramp chosen to survive deuteranopia (verified by a
colour-simulation test, not by inspecting the table); term16 maps every token
to the classic 16 ANSI colours with no truecolor sequences.

Capability detection order: `NO_COLOR` env set -> all colour off; stdout not a
TTY -> off; `TERM=dumb` -> off; `COLORTERM=truecolor|24bit` or Windows VT
enabled -> theme truecolor palette; otherwise the theme 16-colour mapping.
JSON output is never coloured under any setting.

Severity is never conveyed by colour alone: every alert carries its marker
(`.` `+` `!` `!!`), its word (`elevated`, ...), and level names are text.
The four severities stay pairwise distinguishable in the high_contrast theme
under simulated deuteranopia (asserted in tests via a Vienot-style LMS
projection and a CIE76 distance floor).

## 7. Log line rendering and width handling

Log lines render with: timestamp dim; level coloured by its token (DEBUG dim,
INFO normal, WARN elevated, ERROR anomalous, CRITICAL critical) with the level
word itself always visible; field names dim and field values normal; template
fixed text normal; variable slots accent per section 3.

Every ingested line is untrusted input. Before rendering: control characters
(C0/C1 except tab) are replaced with backslash-x escapes; tab renders as four
spaces; invalid UTF-8 bytes decode to U+FFFD and the line is flagged unparsed.
Display width uses a local wcwidth implementation covering East Asian Wide and
Fullwidth ranges; truncation and padding are computed on display width so wide
characters cannot corrupt alignment.

## 8. States

- Empty (source attached, zero lines): centred dim text `waiting for input -
  stdin (0 lines received)`. Static, no animation.
- Warming up: header shows `baseline warming up 62% (eta 38s)`; anomaly feed
  shows one dim line `detectors suppressed until warm-up completes`; alerts do
  not fire during warm-up.
- No data after connect: after 30s without a line the status bar shows
  `no data for 30s` in elevated token with the word; it stays (no flashing).
- Parse failures: header carries a permanent `unparsed N (x.y%)` slot; the
  detail view lists the most recent unparsed lines verbatim (sanitised), each
  tagged with the parser that rejected it and the detected format confidence.
- Source disconnected: status bar left shows `disconnected - retry 3` in
  critical token with the word; reconnect uses exponential backoff capped at
  30s; the rest of the UI keeps rendering stale data clearly labelled by the
  disconnected state.

## 9. CLI and machine output

Subcommands: `run` (live analyse; TUI default on a TTY, JSONL alerts with
`--headless`), `replay FILE...` (offline detection over files at full speed,
same pipeline as live), `query` (filter/aggregate/histogram over an input),
`summary` (time-range report), `config validate`, `hooks test`, `bench`,
`gen-corpus`. Exit codes: 0 success, 1 runtime error, 2 usage error, 3 invalid
config. Errors go to stderr as one line: `logsift: <what> (<cause>); try
<hint>` - e.g. an unmatched user pattern prints the offending line, the closest
detected format and its confidence, and the fix hint.

Alert JSONL schema (`schema` field pins it; documented in README, validated by
a conformance test):

```json
{
  "schema": "logsift.alert/1",
  "id": "a-000123",
  "time": "2026-08-22T03:14:07.512Z",
  "severity": "critical",
  "marker": "!!",
  "detector": "volume",
  "template_id": 42,
  "template": "user <*> login failed",
  "baseline": {"desc": "median 12/hr for slot Mon 03:00 over 26 slots", "value": 12.0},
  "observed": {"desc": "310 events in bucket 03:00-04:00", "value": 310},
  "deviation": {"desc": "25.8x baseline", "z": 14.2},
  "threshold": {"desc": "robust z > 6.0 and observed >= 5", "value": 6.0},
  "window": {"start": "2026-08-22T03:00:00Z", "end": "2026-08-22T04:00:00Z"},
  "group_key": "volume:t42",
  "count": 3,
  "suppressed": 297,
  "first_seen": "2026-08-22T03:14:07.512Z",
  "examples": ["Aug 22 03:13:58 ..."],
  "evidence_before": ["...up to 5 preceding raw lines..."]
}
```

The tool's own diagnostics log (stderr, `--verbose`) is:
`ISO8601 LEVEL MODULE message`, level padded to five, module in brackets.
Colour roles on stderr follow section 6; non-TTY stderr is plain.

## 10. Rendering architecture (audited requirements)

Ingestion runs on worker thread(s) publishing immutable snapshots through an
atomic reference swap; the UI thread renders at most 10 fps from the latest
snapshot. Rendering never blocks ingestion and ingestion never blocks
rendering; there is no shared lock across the boundary. The renderer keeps the
previous frame's cell buffer and emits only changed rows via cursor
positioning - no flicker, no full clears except on resize or overlay
open/close. The terminal state (console modes, buffer) is saved at startup and
restored in a finally block that also runs on SIGINT and on unexpected
exceptions; the alternate screen is left cleanly.

## 11. Banned

Emoji anywhere; ALL-CAPS alert banners; decorative colour; flashing or
blinking; rainbow palettes where three severities suffice; panels jumping
between refreshes; number widths that change; `+---+` box drawing when real box
characters exist; anomaly scores presented bare without explanation.

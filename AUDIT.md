# Logsift Audit — pre-v1.0.0

Audits were performed by sub-agents that did not write the code under review:
a UI/design audit (72 rendered frames: 4 themes x 3 modes x 3 widths x 2
heights, driven through a live Engine), and a stranger-style README walkthrough
that executed every documented command from a clean state. Findings below were
fixed on main and re-verified; the final re-check found zero open defects.

## Round 1 findings (design audit)

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| 1 | critical | `logsift run` on a real TTY crashed at startup: `cli.py` imported `get_theme` from `.tui.renderer`, where it does not exist | import moved to `logsift.themes`; verified `run` path imports cleanly |
| 2 | high | painted template strings (raw SGR) written into the per-character cell grid split escape sequences around later writes (right-aligned clock), corrupting colours/borders in every coloured frame | new `template_segments()` + `Screen.write_segments()`; cells only ever receive plain text + token. Re-scan of all theme x mode frames shows zero malformed SGR fragments |
| 3 | high | detail-view history sparkline could never appear: engine never populated `selected_template_history/examples` | CLI actions bridge records the selected template; snapshot publisher fills history from the index minute ring plus up to 3 example lines |
| 4 | high | feed explanation lines truncated head-only, dropping the threshold clause | `wrap_hang` overflow now truncates both ends; threshold survives |
| 5 | medium | template column kept only the head when over budget | middle truncation keeps both ends (DESIGN section 3) |
| 6 | medium | unparsed-count header slot used raw `str()`, growing past its fixed width | routed through `fmt_count` like every other count |
| 7 | medium | feed prefix width undercounted by 2; template collided with the clock column | prefix constant corrected |
| 8 | low | OFF/NO_COLOR mode still emitted alt-screen/cursor control escapes | escapes gated off for plain mode; frames are fully escape-free |

## Round 1 findings (README stranger walkthrough)

| # | Severity | Finding | Resolution |
|---|----------|---------|------------|
| B1 | blocker | committed evaluation tool crashed (`AttributeError` on Alert objects) after the engine API changed | `eval_corpus.py` serialises via `Alert.to_json_dict()`; README table reproduced exactly |
| B2 | major | one numeric_shift alert outside label tolerance counted as FP (post-incident rebound detection) | rebound suppression: an opposite-direction shift within 2h of an alert on the same key is treated as the incident closing, not a new anomaly; documented in the detector docstring |
| B3 | major | headless runs printed a timer-thread traceback: `deque mutated during iteration` between ingest thread and snapshot publisher | `StreamingIndex.template_stats()` now copies minute rings under a lock shared with `_touch_stats` |
| B4 | minor | README pointed to `docs/` for detector defaults | corrected pointer to `logsift/detectors/base.py` |
| B5 | minor | corpus size quoted as 17.6 MB vs actual 18.4 MB | corrected |
| B6 | minor | detection wording said "first 50 lines" | corrected to "samples up to first 200 lines" |
| B7 | minor | POSIX-only hook/path examples | neutralised with portable examples |

## Checked and fine (both audits)

- Layout proportions per width class; borders intact; states render
  (connected/eof/disconnected/no data/paused); waiting/warm-up states verbatim.
- Every alert carries severity word+marker, detector id, template, time,
  baseline desc/value, observed value, deviation incl. z, threshold - no
  drilling required.
- Slot braces distinct from fixed text; CJK content renders without breaking
  alignment; sparklines use the defined glyph set with min/max annotation;
  histogram bars use eighth-fraction blocks.
- Fixed-width number slots hold across magnitude changes.
- NO_COLOR/OFF emits zero escapes; term16 never emits truecolor SGR; JSONL is
  byte-clean of escapes under COLORTERM=truecolor.
- Banned list scan clean: no emoji, no blink SGR, no +-box drawing, no bare
  scores, no ALL-CAPS banners beyond severity words.
- Terminal restore (alt screen, cursor, Windows VT console mode) fires on
  normal exit, KeyboardInterrupt, and unexpected exceptions.
- Injection safety: exec hooks pass payloads on stdin with shell=False;
  hostile templates round-trip byte-exact.
- Determinism: two replays produce byte-identical alert sequences.
- Memory: 5M-line run peaks at 151.8 MB with the ring holding exactly its
  configured 100k rows.

## Final re-audit

Re-ran the frame-malformation scan (4 themes x 2 colour modes): 0 defective
frames. Full test suite green. Detection quality on the labelled corpus:
precision 1.000 / recall 1.000 per detector, zero false positives.

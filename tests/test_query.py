"""Index + query: predicates, boundaries, aggregation, histogram, eviction, caps."""

from __future__ import annotations

from collections import Counter, deque

import pytest

from logsift.clock import FakeClock
from logsift.events import Event, ParseStatus
from logsift.index import MESSAGE_CAP, RAW_CAP, EventRow, StreamingIndex
from logsift.query import (
    QueryError,
    QuerySpec,
    aggregate,
    execute,
    format_histogram,
    histogram,
    parse_query,
    top_n,
)

T0 = FakeClock.DEFAULT_START  # 2026-01-01 UTC, minute-aligned


def _ev(
    clock: FakeClock,
    message: str = "line",
    *,
    level: str | None = None,
    template_id: int | None = None,
    template_text: str | None = None,
    source: str = "",
    parse_status: ParseStatus = ParseStatus.OK,
    raw_line: str | None = None,
    fields: dict[str, str] | None = None,
) -> Event:
    return Event(
        ts=clock.now(),
        message=message,
        level=level,
        fields=fields or {},
        template_id=template_id,
        template_text=template_text,
        source=source,
        parse_status=parse_status,
        raw_line=message if raw_line is None else raw_line,
    )


def _fixture_index() -> StreamingIndex:
    """Five events spanning 120s: info/error auth templates plus an unparsed line."""
    clock = FakeClock()
    idx = StreamingIndex()
    idx.add(_ev(clock, "user 4821 login failed", level="INFO",
                template_id=1, template_text="user <*> login failed",
                source="auth", fields={"user": "4821"}))
    clock.advance(30)
    idx.add(_ev(clock, "user 9134 login failed", level="ERROR",
                template_id=1, template_text="user <*> login failed",
                source="auth", fields={"user": "9134"},
                raw_line="src=web token=SECRET user 9134 login failed"))
    clock.advance(30)
    idx.add(_ev(clock, "<<<garbage>>>", parse_status=ParseStatus.UNPARSED))
    clock.advance(30)
    idx.add(_ev(clock, "GET /healthz 200 3ms", level="INFO",
                template_id=2, template_text="GET /healthz <*> <*>",
                source="web"))
    clock.advance(30)
    idx.add(_ev(clock, "payment 9001 settled", level="ERROR",
                template_id=3, template_text="payment <*> settled",
                source="pay", fields={"amount": "9001"}))
    return idx


# ---------------------------------------------------------------- filtering


def test_filter_since_inclusive_until_exclusive():
    idx = _fixture_index()
    r = execute(idx, QuerySpec(since=T0 + 30))
    assert r.matched == 4  # the ts == T0+30 row is included
    assert all(row.ts >= T0 + 30 for row in r.rows)
    r = execute(idx, QuerySpec(until=T0 + 30))
    assert [row.ts for row in r.rows] == [T0]  # the ts == T0+30 row is excluded
    assert execute(idx, QuerySpec(since=T0 + 30, until=T0 + 30)).rows == ()
    r = execute(idx, QuerySpec(since=T0 + 31, until=T0 + 90))
    assert [row.ts for row in r.rows] == [T0 + 60]


def test_each_predicate_alone():
    idx = _fixture_index()
    levels = [row.level for row in execute(idx, QuerySpec(level="error")).rows]
    assert levels == ["ERROR", "ERROR"]  # canonical match is case-insensitive
    assert execute(idx, QuerySpec(level="ERROR")).matched == 2
    assert execute(idx, QuerySpec(template_id=1)).matched == 2
    texts = {row.template_text for row in execute(idx, QuerySpec(template_contains="login")).rows}
    assert texts == {"user <*> login failed"}
    sources = {row.source for row in execute(idx, QuerySpec(field_key="user")).rows}
    assert sources == {"auth"}
    amounts = execute(idx, QuerySpec(field_value="9001")).rows
    assert len(amounts) == 1 and amounts[0].fields.get("amount") == "9001"
    pair = execute(idx, QuerySpec(field_key="user", field_value="4821")).rows
    assert len(pair) == 1 and pair[0].message == "user 4821 login failed"
    miss = execute(idx, QuerySpec(field_key="user", field_value="9001")).rows
    assert miss == ()


def test_combined_predicates():
    idx = _fixture_index()
    rows = execute(idx, QuerySpec(level="error", template_id=1)).rows
    assert [row.message for row in rows] == ["user 9134 login failed"]
    rows = execute(idx, QuerySpec(since=T0 + 90, template_contains="settled")).rows
    assert [row.source for row in rows] == ["pay"]


def test_free_text_case_insensitive_across_message_and_raw():
    idx = _fixture_index()
    hits = execute(idx, QuerySpec(free_text="LOGIN FAILED")).rows
    assert len(hits) == 2  # matches both messages
    secret = execute(idx, QuerySpec(free_text="secret")).rows
    assert len(secret) == 1  # present only in the second row's RAW line
    assert secret[0].message == "user 9134 login failed"


def test_scanned_counts_all_rows_not_matches():
    idx = _fixture_index()
    r = execute(idx, QuerySpec(free_text="nomatch-anywhere"))
    assert (r.matched, r.scanned) == (0, 5)


# --------------------------------------------------------------- aggregates


def test_aggregate_by_level_template_source_and_missing_values():
    idx = _fixture_index()
    rows = execute(idx, QuerySpec()).rows
    assert aggregate(rows, "level") == {"INFO": 2, "ERROR": 2, "(none)": 1}
    assert aggregate(rows, "template")["user <*> login failed"] == 2
    assert aggregate(rows, "template")["(none)"] == 1
    assert aggregate(rows, "source")["auth"] == 2


def test_aggregate_unknown_field_raises_with_hint():
    with pytest.raises(QueryError) as ei:
        aggregate([], "user")
    assert "user" in str(ei.value) and "try" in str(ei.value)


def test_top_n_descending_with_alphabetical_ties():
    single = aggregate([EventRow(T0, None, None, "", "m", {}, "", "ok", "")], "level")
    assert top_n(single, 5) == [("(none)", 1)]
    tied = Counter({"b": 2, "a": 2, "c": 7, "d": 2})
    assert top_n(tied, 3) == [("c", 7), ("a", 2), ("b", 2)]
    assert top_n(tied, 0) == []
    assert top_n(tied, -1) == []


# ---------------------------------------------------------------- histogram

def _rows_at(*times: float) -> list[EventRow]:
    return [EventRow(t, None, None, "", "m", {}, "", "ok", "") for t in times]


def test_histogram_contiguous_including_empty_buckets():
    buckets = histogram(_rows_at(0.0, 300.0), 60.0)
    assert [t for t, _ in buckets] == [0.0, 60.0, 120.0, 180.0, 240.0]
    assert [c for _, c in buckets] == [1, 0, 0, 0, 1]  # max ts closes the last bucket


def test_histogram_custom_start_end_and_out_of_span_rows_dropped():
    rows = _rows_at(-50.0, 1.0, 9.0, 10.0, 11.0)
    buckets = dict(histogram(rows, 2.5, start=0.0, end=10.0))
    assert list(buckets) == [0.0, 2.5, 5.0, 7.5]
    assert buckets[7.5] == 2  # ts == end lands in the final, right-closed bucket
    assert buckets[0.0] == 1 and buckets[2.5] == 0  # empty middle bucket present


def test_histogram_single_row_empty_input_and_explicit_bounds_no_rows():
    assert histogram(_rows_at(42.0), 10.0) == [(42.0, 1)]
    assert histogram([], 60.0) == []
    zeros = [(t, 0) for t in (0.0, 60.0, 120.0)]  # [0,180] at 60s -> three buckets
    assert histogram([], 60.0, start=0.0, end=180.0) == zeros


def test_histogram_non_positive_bucket_raises_with_hint():
    with pytest.raises(QueryError) as ei:
        histogram(_rows_at(0.0), 0)
    assert "bucket_seconds" in str(ei.value)


# --------------------------------------------------------- histogram render

_LABEL_LEN = len("1970-01-01 00:00")


def _parts(line: str, width: int) -> tuple[str, str, str]:
    """Line layout: label SP bar(width, space-padded) SP count."""
    return (
        line[:_LABEL_LEN],
        line[_LABEL_LEN + 1:_LABEL_LEN + 1 + width],
        line[_LABEL_LEN + 2 + width:],
    )


def _bar(line: str, width: int) -> str:
    return _parts(line, width)[1].rstrip()


def test_format_histogram_bar_proportional_and_padded_to_width():
    buckets = [(0.0, 40), (60.0, 20), (120.0, 0)]
    lines = format_histogram(buckets, width_chars=40)
    assert len(lines) == 3
    label, bar, count = _parts(lines[0], 40)
    assert label == "1970-01-01 00:00"
    assert bar == "\u2588" * 40  # peak fills the full width
    assert count == "40"
    assert len(lines[0]) == len(lines[1]) == len(lines[2])
    assert _bar(lines[1], 40) == "\u2588" * 20  # half the peak, half the bar
    zero_label, zero_bar, zero_count = _parts(lines[2], 40)
    assert zero_bar.strip() == "" and zero_count.strip() == "0"
    assert zero_label == "1970-01-01 00:02"


def test_format_histogram_eighth_fraction_block_by_remainder():
    width = 10
    cases = {
        80: "\u2588" * 10,
        41: "\u2588" * 5 + "\u258f",  # 41/80 of the width: 5 fulls plus one eighth
        9: "\u2588" + "\u258f",  # 9 eighths of a column
        79: "\u2588" * 9 + "\u2589",
    }
    buckets = [(float(i * 60), v) for i, v in enumerate(cases)]
    for want, line in zip(cases.values(), format_histogram(buckets, width)):
        assert _bar(line, width) == want


def test_format_histogram_count_right_alignment_and_empty_input():
    lines = format_histogram([(0.0, 5), (60.0, 123)], width_chars=4)
    assert [_parts(line, 4)[2] for line in lines] == ["  5", "123"]
    assert len(lines[0]) == len(lines[1])
    assert format_histogram([], 40) == []


# -------------------------------------------------------------------- index


def test_eviction_keeps_newest_max_events_and_counts_evictions():
    clock = FakeClock()
    idx = StreamingIndex(max_events=1000)
    for i in range(1500):
        idx.add(_ev(clock, f"event {i}"))
        clock.advance(1)
    assert len(idx) == 1000
    totals = idx.totals()
    assert totals.evicted_count == 500
    assert totals.lines_total == 1500
    rows = list(idx.iter_rows())
    assert rows[0].ts == pytest.approx(T0 + 500)  # oldest 500 rotated out
    assert rows[-1].ts == pytest.approx(T0 + 1499)
    assert totals.first_ts == pytest.approx(T0)
    assert totals.last_ts == pytest.approx(T0 + 1499)


def test_message_raw_and_fields_capped_on_storage():
    clock = FakeClock()
    idx = StreamingIndex()
    idx.add(_ev(clock, "x" * 600, raw_line="r" * 600,
                fields={f"k{i}": "v" * 600 for i in range(20)}))
    row = next(iter(idx.iter_rows()))
    assert len(row.message) <= MESSAGE_CAP == 512
    assert len(row.raw) <= RAW_CAP == 512
    assert len(row.fields) == 16
    assert all(len(v) <= 512 for v in row.fields.values())


def test_totals_track_levels_unparsed_and_lifetime_bounds():
    idx = _fixture_index()
    totals = idx.totals()
    assert totals.lines_total == 5 and totals.unparsed_total == 1
    assert totals.levels == {"INFO": 2, "ERROR": 2}
    assert totals.evicted_count == 0
    assert totals.first_ts == pytest.approx(T0)
    assert totals.last_ts == pytest.approx(T0 + 120)


def test_template_stats_keyed_by_text_with_minute_buckets_capped_at_60():
    clock = FakeClock(start=T0 - T0 % 60)  # align to a minute boundary
    idx = StreamingIndex()
    first_minute = int(clock.now() // 60)
    for minute in range(70):
        idx.add(_ev(clock, "user 4821 login failed", level="INFO", template_id=7,
                    template_text="user <*> login failed"))
        idx.add(_ev(clock, "user 9134 login failed", level="INFO", template_id=7,
                    template_text="user <*> login failed"))
        clock.advance(60)
    stats = idx.template_stats()
    stat = stats["user <*> login failed"]
    assert set(stats) == {"user <*> login failed"}
    assert stat.count == 140  # all-time count; rows rotate out but counts persist
    assert stat.last_seen == pytest.approx(clock.now() - 60)
    assert len(stat.minute_counts) == 60  # only the last 60 observed minutes kept
    assert stat.minute_counts[0] == 2  # each observed minute held exactly two events
    assert stat.minute_counts[-1] == 2
    assert stat.minute_counts == deque([2] * 60)
    assert int(stat.last_seen // 60) - first_minute == 69


def test_template_stats_returned_copies_are_decoupled_from_index():
    clock = FakeClock()
    idx = StreamingIndex()
    idx.add(_ev(clock, "m", template_id=4, template_text="t"))
    stat = idx.template_stats()["t"]
    stat.count = 999
    stat.minute_counts.append(42)
    assert idx.template_stats()["t"].count == 1
    assert len(idx.template_stats()["t"].minute_counts) == 1


def test_iter_rows_reverse_and_snapshot_isolation():
    clock = FakeClock()
    idx = StreamingIndex()
    for i in range(3):
        idx.add(_ev(clock, f"m{i}"))
        clock.advance(1)
    forward = [row.message for row in idx.iter_rows()]
    backward = [row.message for row in idx.iter_rows(reverse=True)]
    assert forward == ["m0", "m1", "m2"]
    assert backward == ["m2", "m1", "m0"]
    it = idx.iter_rows()
    first = next(it)
    idx.add(_ev(clock, "m3"))  # mutate the index before draining the iterator
    drained = [first.message] + [row.message for row in it]
    assert drained == ["m0", "m1", "m2"]


# -------------------------------------------------------------- parse_query


def test_parse_query_good_params_types_and_canonicalisation():
    q = parse_query({
        "since": "1767225600",
        "until": " 1767225660 ",
        "level": " ERROR ",
        "template_id": "42",
        "template_contains": "login",
        "field_key": "user",
        "field_value": "4821",
        "free_text": "time out",
    })
    assert q.since == 1767225600.0 and isinstance(q.since, float)
    assert q.until == 1767225660.0
    assert q.level == "error"
    assert q.template_id == 42 and isinstance(q.template_id, int)
    assert (q.template_contains, q.field_key, q.field_value, q.free_text) == (
        "login", "user", "4821", "time out")
    empty = parse_query({"level": "", "free_text": "   "})
    assert empty.level is None and empty.free_text is None
    assert parse_query({}) == QuerySpec()


def _expect_error(params: dict[str, str], needle: str) -> None:
    with pytest.raises(QueryError) as ei:
        parse_query(params)
    message = str(ei.value)
    assert needle in message, message
    assert "try" in message.lower(), message
    assert ei.value.kind


def test_parse_query_invalid_since_names_param_and_hints():
    _expect_error({"since": "abc"}, "since")


def test_parse_query_invalid_until_names_param_and_hints():
    _expect_error({"until": ""}, "until")


def test_parse_query_invalid_template_id_names_param_and_hints():
    _expect_error({"template_id": "12.5"}, "template_id")


def test_parse_query_unknown_param_rejected_with_valid_list():
    with pytest.raises(QueryError) as ei:
        parse_query({"colour": "red"})
    message = str(ei.value)
    assert "'colour'" in message and "since" in message and "free_text" in message

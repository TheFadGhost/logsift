"""Tests for logsift.parsers: formats, detection, honest failures."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from logsift.clock import FakeClock
from logsift.parsers import (
    AccessLogParser,
    CustomParser,
    JsonParser,
    LogfmtParser,
    ParserRegistry,
    SyslogParser,
    needs_continuation,
)

UTC = timezone.utc


def epoch(y, mo, d, h=0, mi=0, s=0, us=0):
    return datetime(y, mo, d, h, mi, s, us, tzinfo=UTC).timestamp()


class TestJsonParser:
    def test_full_fixture(self):
        line = (
            '{"timestamp":"2026-08-22T03:14:07.512Z","level":"WARN",'
            '"msg":"user login failed","user_id":4821,"duration_ms":123.5,'
            '"req":{"id":7,"path":"/api/v1"},"ok":true,"tag":null}'
        )
        result = JsonParser().try_parse(line)
        assert result is not None
        assert result.ok
        assert result.ts == epoch(2026, 8, 22, 3, 14, 7, 512000)
        assert result.level == "warning"
        assert result.message == "user login failed"
        assert result.parser == "json"
        assert result.fields == {
            "user_id": "4821",
            "duration_ms": "123.5",
            "req.id": "7",
            "req.path": "/api/v1",
            "ok": "true",
        }
        assert result.numeric == {
            "user_id": 4821.0,
            "duration_ms": 123.5,
            "req.id": 7.0,
        }
        assert "tag" not in result.fields

    def test_minimal_object_without_known_keys(self):
        line = '{"a": 1, "b": "two"}'
        result = JsonParser().try_parse(line)
        assert result is not None and result.ok
        assert result.ts is None
        assert result.level is None
        assert result.message == line

    def test_truncated_returns_ok_false_not_none(self):
        result = JsonParser().try_parse('{ "a": "b')
        assert result is not None
        assert not result.ok
        assert result.error
        assert "json" in result.error.lower()

    def test_non_object_json_is_none(self):
        assert JsonParser().try_parse("[1, 2, 3]") is None
        assert JsonParser().try_parse('"bare string"') is None

    def test_offset_and_naive_timestamps(self):
        offset_line = '{"time":"2026-08-22T05:14:07+02:00"}'
        result = JsonParser().try_parse(offset_line)
        assert result is not None and result.ok
        assert result.ts == epoch(2026, 8, 22, 3, 14, 7)
        naive_line = '{"time":"2026-08-22 03:14:07"}'
        result = JsonParser().try_parse(naive_line)
        assert result is not None and result.ok
        assert result.ts == epoch(2026, 8, 22, 3, 14, 7)


class TestLogfmtParser:
    def test_full_fixture(self):
        line = (
            'time=2026-08-22T03:14:07Z level=error msg="db timeout \\"users\\" '
            'retrying now" host=db-primary retries=3'
        )
        result = LogfmtParser().try_parse(line)
        assert result is not None
        assert result.ok
        assert result.ts == epoch(2026, 8, 22, 3, 14, 7)
        assert result.level == "error"
        assert result.message == 'db timeout "users" retrying now'
        assert result.fields == {"host": "db-primary", "retries": "3"}
        assert result.numeric == {"retries": 3.0}

    def test_message_falls_back_to_raw_line(self):
        result = LogfmtParser().try_parse("host=a count=2")
        assert result is not None and result.ok
        assert result.message == "host=a count=2"

    def test_single_quoted_and_escapes(self):
        result = LogfmtParser().try_parse("a='it\\'s' b=\"x\\ty\"")
        assert result is not None and result.ok
        assert result.fields["a"] == "it's"
        assert result.fields["b"] == "x\ty"

    def test_plain_text_is_none(self):
        assert LogfmtParser().try_parse("just some words here") is None

    def test_equals_but_no_pairs_is_ok_false(self):
        result = LogfmtParser().try_parse('9bad=oops "unterminated')
        assert result is not None
        assert not result.ok
        assert result.error


class TestAccessLogParser:
    COMBINED = (
        "203.0.113.42 - alice [22/Aug/2026:03:14:07 +0000] "
        '"GET /api/users?id=7 HTTP/1.1" 503 1024 '
        '"https://ref.example/" "curl/8.0" 0.042'
    )

    def test_combined_with_duration(self):
        result = AccessLogParser().try_parse(self.COMBINED)
        assert result is not None
        assert result.ok
        assert result.ts == epoch(2026, 8, 22, 3, 14, 7)
        assert result.parser == "access_combined"
        assert result.fields == {
            "method": "GET",
            "path": "/api/users?id=7",
            "protocol": "HTTP/1.1",
            "remote_host": "203.0.113.42",
            "ident": "-",
            "authuser": "alice",
            "status": "503",
            "bytes": "1024",
            "referer": "https://ref.example/",
            "user_agent": "curl/8.0",
        }
        assert result.numeric == {
            "status": 503.0,
            "bytes": 1024.0,
            "duration_ms": pytest.approx(42.0),
        }
        assert result.level == "error"
        assert result.message == "GET /api/users?id=7 HTTP/1.1"

    def test_common_without_referer_agent(self):
        line = '10.0.0.9 - - [01/Jan/2026:00:00:01 +0200] "POST /login HTTP/2.0" 404 -'
        result = AccessLogParser().try_parse(line)
        assert result is not None and result.ok
        assert result.ts == epoch(2025, 12, 31, 22, 0, 1)
        assert result.numeric == {"status": 404.0}
        assert result.fields["referer"] == "-"
        assert result.fields["user_agent"] == "-"
        assert result.level == "warning"

    def test_malformed_quoted_line_is_ok_false(self):
        result = AccessLogParser().try_parse('"GET /only-request" 200')
        assert result is not None
        assert not result.ok
        assert result.error

    def test_no_quote_is_none(self):
        assert AccessLogParser().try_parse("plain words only") is None


class TestSyslogParser:
    def test_rfc3164_year_inference_matches_clock(self):
        clock = FakeClock()
        parser = SyslogParser(clock)
        result = parser.try_parse(
            "Oct  5 03:14:15 db-primary sshd[2891]: Accepted publickey for root"
        )
        assert result is not None
        assert result.ok
        assert result.ts == epoch(2026, 10, 5, 3, 14, 15)
        assert result.level is None
        assert result.message == "Accepted publickey for root"
        assert result.fields == {
            "hostname": "db-primary",
            "program": "sshd",
            "pid": "2891",
        }

    def test_rfc3164_year_follows_advanced_clock(self):
        clock = FakeClock(start=epoch(2019, 6, 1))
        parser = SyslogParser(clock)
        result = parser.try_parse("Dec 31 23:59:59 web-7 kernel: disk full")
        assert result is not None and result.ok
        assert result.ts == epoch(2019, 12, 31, 23, 59, 59)

    def test_rfc3164_with_pri_prefix_maps_severity(self):
        clock = FakeClock()
        result = SyslogParser(clock).try_parse("<34>Oct  5 03:14:15 h proc[1]: boom")
        assert result is not None and result.ok
        assert result.level == "critical"

    def test_rfc3164_invalid_time_is_ok_false(self):
        clock = FakeClock()
        result = SyslogParser(clock).try_parse("Oct 99 25:00:00 h p[1]: m")
        assert result is not None
        assert not result.ok
        assert result.error

    def test_rfc5424_full(self):
        line = "<34>1 2026-08-22T03:14:15.003Z web-1 myapp 8811 ID47 - Backend failure"
        result = SyslogParser(FakeClock()).try_parse(line)
        assert result is not None
        assert result.ok
        assert result.ts == epoch(2026, 8, 22, 3, 14, 15, 3000)
        assert result.level == "critical"
        assert result.message == "Backend failure"
        assert result.fields == {"hostname": "web-1", "program": "myapp", "pid": "8811"}
        assert result.numeric == {"pid": 8811.0}

    def test_rfc5424_offset_timestamp(self):
        line = "<13>1 2026-08-22T05:14:07+02:00 host app - - - hello"
        result = SyslogParser(FakeClock()).try_parse(line)
        assert result is not None and result.ok
        assert result.ts == epoch(2026, 8, 22, 3, 14, 7)
        assert result.level == "notice"
        assert result.fields == {"hostname": "host", "program": "app"}

    def test_rfc5424_shaped_but_broken_is_ok_false(self):
        result = SyslogParser(FakeClock()).try_parse("<123>1 notatime")
        assert result is not None
        assert not result.ok
        assert result.error

    def test_unrelated_line_is_none(self):
        assert SyslogParser(FakeClock()).try_parse("nothing here at all") is None


class TestCustomParser:
    PATTERN = (
        r"\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] "
        r"(?P<level>INFO|ERROR) (?P<component>\w+): (?P<message>.*)"
    )

    def test_match(self):
        parser = CustomParser(self.PATTERN)
        line = "[2026-08-22 03:14:07] ERROR payment: card declined"
        result = parser.try_parse(line)
        assert result is not None and result.ok
        assert result.parser == "custom"
        assert result.ts == epoch(2026, 8, 22, 3, 14, 7)
        assert result.level == "error"
        assert result.fields == {"component": "payment"}
        assert result.numeric == {}
        assert result.message == "card declined"

    def test_explicit_time_formats(self):
        parser = CustomParser(
            r"(?P<ts>[^ ]+ [^ ]+) (?P<message>.*)",
            time_formats=("%d.%m.%Y %H:%M:%S",),
        )
        result = parser.try_parse("22.08.2026 03:14:07 ready")
        assert result is not None and result.ok
        assert result.ts == epoch(2026, 8, 22, 3, 14, 7)
        assert result.message == "ready"

    def test_mismatch_is_none(self):
        assert CustomParser(self.PATTERN).try_parse("no brackets here") is None

    def test_invalid_pattern_raises_value_error_with_hint(self):
        with pytest.raises(ValueError) as excinfo:
            CustomParser("(?P<ts>[unclosed")
        assert "hint" in str(excinfo.value)

    def test_pattern_without_named_groups_rejected(self):
        with pytest.raises(ValueError):
            CustomParser(r"\d+ words")


class TestNeedsContinuation:
    @pytest.mark.parametrize(
        "line,expected",
        [
            ("", False),
            ("plain text", False),
            ('{"a": 1}', False),
            ('{"a": 1', True),
            ('{ "a": "b', True),
            ('{"a": {"b": [1, 2]}', True),
            ('{"a": {"b": [1, 2]}}', False),
            ('{"s": "}"}', False),
            ('{"s": "\\\\"}', False),
            ('{"s": "\\"', True),
            ("[]", False),
            ("{} extra", False),
            ("}{", True),
        ],
    )
    def test_cases(self, line, expected):
        assert needs_continuation(line) is expected

    def test_escape_aware_quote_does_not_close(self):
        assert needs_continuation('{"a": "b\\"c"}') is False
        assert needs_continuation('{"a": "b\\\\"c"}') is True


class TestRegistryDetection:
    JSON_SAMPLES = [
        '{"timestamp":"2026-01-02T03:04:05Z","level":"info","msg":"one","n":1}',
        '{"timestamp":"2026-01-02T03:04:06Z","level":"error","msg":"two","n":2}',
        '{"timestamp":"2026-01-02T03:04:07Z","level":"debug","msg":"three"}',
    ]
    LOGFMT_SAMPLES = [
        "time=2026-01-02T03:04:05Z level=info msg=alpha n=1",
        "time=2026-01-02T03:04:06Z level=warn msg=beta n=2",
        "time=2026-01-02T03:04:07Z level=error msg=gamma",
    ]
    ACCESS_SAMPLES = [
        '1.2.3.4 - - [02/Jan/2026:03:04:05 +0000] "GET /a HTTP/1.1" 200 10 "-" "ua"',
        '1.2.3.4 - - [02/Jan/2026:03:04:06 +0000] "GET /b HTTP/1.1" 404 20 "-" "ua"',
        '1.2.3.4 - - [02/Jan/2026:03:04:07 +0000] "GET /c HTTP/1.1" 500 30',
    ]
    SYSLOG_SAMPLES = [
        "Jan  2 03:04:05 host-a proc[1]: alpha message",
        "Jan  2 03:04:06 host-b proc[2]: beta message",
        "<13>1 2026-01-02T03:04:07Z host-c proc 3 ID - gamma message",
    ]

    def test_detect_each_format(self):
        registry = ParserRegistry(FakeClock())
        for samples, expected in [
            (self.JSON_SAMPLES, "json"),
            (self.LOGFMT_SAMPLES, "logfmt"),
            (self.ACCESS_SAMPLES, "access_combined"),
            (self.SYSLOG_SAMPLES, "syslog"),
        ]:
            report = registry.detect(samples)
            assert report.parser_name == expected, report
            assert report.confidence >= 0.6
            assert report.sample_size == len(samples)
            assert set(report.scores) == set(registry.parser_names)

    def test_detect_custom_wins_when_configured(self):
        registry = ParserRegistry(
            FakeClock(), custom_pattern=r"^(?P<level>\w+) (?P<message>.*)$"
        )
        report = registry.detect(["ERROR things fell over", "INFO all good"])
        assert report.parser_name == "custom"
        assert report.confidence == pytest.approx(0.99)

    def test_garbage_reports_low_confidence(self):
        registry = ParserRegistry(FakeClock())
        report = registry.detect(["hello world", "the quick brown fox jumps"])
        assert report.confidence <= 0.2
        assert report.sample_size == 2

    def test_empty_samples(self):
        report = ParserRegistry(FakeClock()).detect([])
        assert report.parser_name == ""
        assert report.confidence == 0.0
        assert report.sample_size == 0

    def test_report_is_frozen(self):
        from dataclasses import FrozenInstanceError

        report = ParserRegistry(FakeClock()).detect(['{"a":1}'])
        with pytest.raises(FrozenInstanceError):
            report.parser_name = "x"


class TestRegistryParseLine:
    def test_mixed_stream_never_drops(self):
        lines = [
            '{"timestamp":"2026-01-02T03:04:05Z","level":"info","msg":"json one"}',
            "time=2026-01-02T03:04:06Z level=error msg=logfmt two",
            "Jan  2 03:04:07 host-c proc[3]: syslog three",
            '{"timestamp":"2026-01-02T03:04:08Z","level":"warn","msg":"json four"}',
            "time=2026-01-02T03:04:09Z level=debug msg=logfmt five",
            "Jan  2 03:04:10 host-f proc[6]: syslog six",
        ]
        expected = ["json", "logfmt", "syslog"] * 2
        registry = ParserRegistry(FakeClock())
        for line, want in zip(lines, expected):
            result = registry.parse_line(line)
            assert result.ok, result.error
            assert result.parser == want
            assert result.ts is not None

    def test_truncated_final_json_reported_not_crash(self):
        registry = ParserRegistry(FakeClock())
        result = registry.parse_line('{ "a": "b')
        assert result is not None
        assert not result.ok
        assert result.error
        assert result.parser == "json"

    def test_garbage_gets_closest_format_and_excerpt(self):
        registry = ParserRegistry(FakeClock())
        long_garbage = "zzz unparseable " * 30
        result = registry.parse_line(long_garbage)
        assert not result.ok
        assert result.message == long_garbage
        assert len(result.error) < len(long_garbage)
        assert "line:" in result.error

    def test_lock_pins_parser_and_falls_through_on_none(self):
        registry = ParserRegistry(FakeClock())
        registry.lock("logfmt")
        result = registry.parse_line("k=v note")
        assert result.ok and result.parser == "logfmt"

    def test_lock_changes_outcome_for_ambiguous_line(self):
        line = '{"a":"x", "b": 42} status=200'
        unlocked = ParserRegistry(FakeClock())
        ok_result = unlocked.parse_line(line)
        assert ok_result.ok and ok_result.parser == "logfmt"
        locked = ParserRegistry(FakeClock())
        locked.lock("json")
        pinned = locked.parse_line(line)
        assert not pinned.ok
        assert pinned.parser == "json"

    def test_lock_unknown_name_raises(self):
        registry = ParserRegistry(FakeClock())
        with pytest.raises(ValueError):
            registry.lock("nope")

    def test_custom_pattern_via_registry_and_helpful_mismatch(self):
        pattern = (
            r"\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] "
            r"(?P<level>\w+) (?P<message>.*)"
        )
        registry = ParserRegistry(FakeClock(), custom_pattern=pattern)
        good = registry.parse_line("[2026-08-22 03:14:07] ERROR payment failed")
        assert good.ok and good.parser == "custom"
        assert good.ts == epoch(2026, 8, 22, 3, 14, 7)

        miss = ParserRegistry(FakeClock()).parse_line(
            "[2026-08-22 03:14:07] ERROR payment failed"
        )
        assert not miss.ok
        assert miss.error
        assert "custom pattern" in miss.error or "tried:" in miss.error


class TestTimestampHelpers:
    def test_naive_is_utc(self):
        from logsift.parsers.timestamps import parse_auto

        assert parse_auto("2026-08-22T03:14:07") == epoch(2026, 8, 22, 3, 14, 7)

    def test_epoch_string(self):
        from logsift.parsers.timestamps import parse_auto

        assert parse_auto("1767225600") == FakeClock.DEFAULT_START
        assert parse_auto("1767225600000") == FakeClock.DEFAULT_START

    def test_bad_inputs_are_none(self):
        from logsift.parsers.timestamps import parse_auto

        assert parse_auto("") is None
        assert parse_auto("not a time") is None
        assert parse_auto("2026-99-99") is None


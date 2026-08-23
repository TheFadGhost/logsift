"""MultilineAssembler: trace assembly, boundaries, caps, determinism."""

from __future__ import annotations

import sys

import pytest

from logsift.multiline import ContinuationRule, MultilineAssembler, default_rules


JAVA_TRACE = [
    "java.net.ConnectException: Connection refused to db-primary:5432",
    "\tat com.example.db.Pool.connect(Pool.java:88)",
    "\tat com.example.db.Pool.tryConnect(Pool.java:61)",
    "\tat com.example.db.Pool$Heartbeat.run(Pool.java:203)",
    "\tat java.base/java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:572)",
    "\tat java.base/java.util.concurrent.FutureTask.runAndReset(FutureTask.java:305)",
    "\tat java.base/java.util.concurrent.ScheduledThreadPoolExecutor$ScheduledFutureTask.run(ScheduledThreadPoolExecutor.java:305)",
    "\tat java.base/java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:637)",
    "\tat java.base/java.lang.Thread.run(Thread.java:1583)",
    "\tat com.example.scheduler.Loop.tick(Loop.java:44)",
    "Caused by: java.net.SocketTimeoutException: connect timed out",
    "\tat java.base/java.net.PlainSocketImpl.waitForConnect(Native Method)",
    "\t... 9 more",
]
AFTER_JAVA = "2026-08-22T03:14:09 INFO pool recovered, retrying in 5s"

PYTHON_TRACE = [
    "Traceback (most recent call last):",
    '  File "app.py", line 10, in handle',
    "    payload = decode(raw)",
    '  File "app.py", line 6, in decode',
    "    return int(raw) / len(items)",
    "ZeroDivisionError: division by zero",
]
AFTER_PYTHON = "2026-08-22T03:15:00 INFO request handled"

JSON_OBJECT = [
    "{",
    '  "service": "auth",',
    '  "pid": 4211',
    "}",
]
AFTER_JSON = "2026-08-22T03:16:00 INFO next request"


def _feed_all(asm: MultilineAssembler, lines: list[str]) -> list[str]:
    out: list[str] = []
    for line in lines:
        out.extend(asm.feed(line))
    return out


def _jsonl_available() -> bool:
    try:
        import logsift.parsers.jsonl  # noqa: F401
    except Exception:
        return False
    return True


def test_default_rules_names():
    assert [rule.name for rule in default_rules()] == [
        "indented",
        "stack_frame",
        "json_partial",
    ]


def test_java_trace_assembles_to_two_events():
    asm = MultilineAssembler()
    events = _feed_all(asm, JAVA_TRACE + [AFTER_JAVA])
    events += asm.flush()
    assert len(events) == 2
    trace, normal = events
    assert trace == "\n".join(JAVA_TRACE)
    assert trace.startswith("java.net.ConnectException:")
    assert "Caused by:" in trace
    assert sum(1 for ln in trace.split("\n") if ln.lstrip().startswith("at ")) == 10
    assert normal == AFTER_JAVA


def test_python_traceback_one_event_then_new_event():
    asm = MultilineAssembler()
    events = _feed_all(asm, PYTHON_TRACE + [AFTER_PYTHON])
    events += asm.flush()
    assert events == ["\n".join(PYTHON_TRACE), AFTER_PYTHON]


def test_incremental_and_batched_feeding_are_identical():
    stream = JAVA_TRACE + [AFTER_JAVA] + PYTHON_TRACE + [AFTER_PYTHON]

    batched = MultilineAssembler()
    expected = _feed_all(batched, stream)
    expected += batched.flush()

    one_by_one = MultilineAssembler()
    actual: list[str] = []
    for line in stream:
        actual.extend(one_by_one.feed(line))
    actual += one_by_one.flush()

    chunky = MultilineAssembler()
    actual_chunks: list[str] = []
    for i in range(0, len(stream), 3):
        for line in stream[i : i + 3]:
            actual_chunks.extend(chunky.feed(line))
    actual_chunks += chunky.flush()

    assert actual == expected
    assert actual_chunks == expected


def test_unterminated_trace_flushed_exactly_once():
    asm = MultilineAssembler()
    during_feed: list[str] = []
    for line in JAVA_TRACE:
        during_feed.extend(asm.feed(line))
    assert during_feed == []
    first = asm.flush()
    assert first == ["\n".join(JAVA_TRACE)]
    assert asm.flush() == []


def test_json_partial_pretty_object_is_one_event():
    if not _jsonl_available():
        pytest.skip("logsift.parsers.jsonl is not implemented yet")
    rules = {rule.name: rule for rule in default_rules()}
    json_rule = rules["json_partial"]
    assert json_rule.matches("{") is True
    assert json_rule.matches("}") is True
    assert json_rule.matches('{"complete": true}') is False

    asm = MultilineAssembler()
    events = _feed_all(asm, JSON_OBJECT + [AFTER_JSON])
    events += asm.flush()
    assert events == ["\n".join(JSON_OBJECT), AFTER_JSON]


def test_json_rule_degrades_to_false_when_parser_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "logsift.parsers.jsonl", None)
    rules = {rule.name: rule for rule in default_rules()}
    assert rules["json_partial"].matches("{") is False
    assert rules["json_partial"].matches("}") is False
    assert rules["json_partial"].matches("anything at all") is False


def test_line_cap_splits_deterministically():
    asm = MultilineAssembler(max_event_lines=4)
    lines = [f"    frame {i}" for i in range(10)]
    events = _feed_all(asm, lines)
    events += asm.flush()
    assert events == [
        "\n".join(lines[0:4]),
        "\n".join(lines[4:8]),
        "\n".join(lines[8:10]),
    ]


def test_byte_cap_splits_deterministically():
    asm = MultilineAssembler(max_event_bytes=50)
    long_line = "x" * 30
    events: list[str] = []
    for _ in range(3):
        events.extend(asm.feed(long_line))
    events += asm.flush()
    assert len(events) == 3
    assert events == [long_line, long_line, long_line]


def test_blank_lines_do_not_corrupt_state():
    asm = MultilineAssembler()
    events: list[str] = []
    events.extend(asm.feed("first line"))
    events.extend(asm.feed(""))
    events.extend(asm.feed("\t\t"))
    events.extend(asm.feed("second line"))
    events.extend(asm.feed("   "))
    events.extend(asm.feed("third line"))
    events += asm.flush()
    assert events == ["first line", "\n\t\t", "second line\n   ", "third line"]


def test_orphan_continuation_at_stream_start_opens_event():
    asm = MultilineAssembler()
    assert asm.feed("\tat deeper.stack.Frame(Frame.java:1)") == []
    tail = asm.flush()
    assert tail == ["\tat deeper.stack.Frame(Frame.java:1)"]


def test_determinism_same_input_same_output():
    stream = JAVA_TRACE + [AFTER_JAVA] + JSON_OBJECT + [AFTER_JSON] + PYTHON_TRACE

    def run() -> list[str]:
        asm = MultilineAssembler()
        events = _feed_all(asm, stream)
        return events + asm.flush()

    assert run() == run()


def test_constructor_validates_caps():
    with pytest.raises(ValueError):
        MultilineAssembler(max_event_lines=0)
    with pytest.raises(ValueError):
        MultilineAssembler(max_event_bytes=0)


def test_custom_rule_only():
    def is_arrow(line: str) -> bool:
        return line.startswith("->")

    rule = ContinuationRule("arrow", is_arrow)
    asm = MultilineAssembler(rules=[rule])
    events: list[str] = []
    assert events == []
    events.extend(asm.feed("wrapped message"))
    assert asm.feed("-> part one") == []
    events.extend(asm.feed("tail"))
    events += asm.flush()
    assert events == ["wrapped message\n-> part one", "tail"]

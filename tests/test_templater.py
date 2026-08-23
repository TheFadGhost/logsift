"""Templater: clustering, masking, params, determinism, eviction, edges."""

from __future__ import annotations

from logsift.clock import FakeClock
from logsift.templater import Templater


def test_user_not_found_clusters_into_one_template():
    t = Templater(FakeClock())
    m1 = t.process("user 4821 not found")
    m2 = t.process("user 9134 not found")
    assert m1.template is m2.template
    assert m1.template.tokens == ("user", "<*>", "not", "found")
    assert m1.params == ("4821",)
    assert m2.params == ("9134",)
    assert m1.template.count == 2
    assert t.stats() == {"total_messages": 2, "template_count": 1, "merges": 1}


def test_get_variants_cluster_with_digit_masking():
    t = Templater(FakeClock())
    lines = [
        ("GET /api/users 200 12ms", ("200", "12ms")),
        ("GET /api/users 404 8ms", ("404", "8ms")),
        ("GET /api/users 200 130ms", ("200", "130ms")),
    ]
    seen = [t.process(line) for line, _ in lines]
    assert all(m.template is seen[0].template for m in seen)
    assert seen[0].template.text == "GET /api/users <*> <*>"
    assert [m.params for m in seen] == [want for _, want in lines]
    assert t.stats()["template_count"] == 1


def _mixed_stream_30() -> list[str]:
    f1 = ["user 4821 login failed", "user 9134 login failed", "user 17231 login failed", "user 4821 login failed"]
    f2 = ["user admin login failed", "user root login failed", "user admin login failed"]
    f3 = ["GET /api/orders 200 34ms", "GET /api/orders 503 210ms", "GET /api/orders 200 5ms", "GET /api/orders 301 11ms"]
    f4 = ["POST /api/orders 201 9ms", "POST /api/orders 202 11ms", "POST /api/orders 201 9ms"]
    f5 = ["payment 9001 settled in 45ms", "payment 9002 settled in 60ms", "payment 9003 settled in 88ms", "payment 9004 settled in 52ms"]
    f6 = ["disk sda1 usage at 42%", "disk sda2 usage at 57%", "disk sda15 usage at 61%", "disk sdb1 usage at 38%"]
    f7 = ["connection to db-1 timed out", "connection to db-2 timed out", "connection to db-3 timed out", "connection to db-7 timed out"]
    f8 = ["connection to db-primary timed out", "connection to db-replica timed out", "connection to db-primary timed out", "connection to db-backup timed out"]
    return [*f1, *f2, *f3, *f4, *f5, *f6, *f7, *f8]


def test_labelled_fixture_thirty_messages_eight_families_five_templates():
    t = Templater(FakeClock())
    matches = [t.process(line) for line in _mixed_stream_30()]
    templates = t.templates()
    assert len(templates) == 5
    texts = {tpl.text for tpl in templates}
    assert texts == {
        "user <*> login failed",
        "<*> /api/orders <*> <*>",
        "payment <*> settled in <*>",
        "disk <*> usage at <*>",
        "connection to <*> timed out",
    }
    by_text = {tpl.text: tpl for tpl in templates}
    assert by_text["user <*> login failed"].count == 7
    http = next(tpl for tpl in templates if tpl.text.endswith("/api/orders <*> <*>"))
    assert http.count == 7
    assert by_text["payment <*> settled in <*>"].count == 4
    assert by_text["disk <*> usage at <*>"].count == 4
    assert by_text["connection to <*> timed out"].count == 8
    assert sum(tpl.count for tpl in templates) == 30
    st = t.stats()
    assert st["total_messages"] == 30
    assert st["template_count"] == 5
    assert st["merges"] == 25
    assert matches[3].params == ("4821",)
    post_match = matches[12]
    assert post_match.params == ("POST", "202", "11ms")


def test_identical_sequence_two_fresh_templaters_same_ids_and_texts():
    stream = _mixed_stream_30()

    def run() -> tuple[list[tuple[int, str]], list[tuple[str, ...]]]:
        clk = FakeClock()
        t = Templater(clk)
        ids_texts: list[tuple[int, str]] = []
        params: list[tuple[str, ...]] = []
        for i, line in enumerate(stream):
            clk.advance(0.5)
            m = t.process(line)
            ids_texts.append((m.template.template_id, m.template.text))
            params.append(m.params)
        return ids_texts, params

    first_ids, first_params = run()
    second_ids, second_params = run()
    assert first_ids == second_ids
    assert first_params == second_params


def test_high_cardinality_five_thousand_unique_lines_one_template():
    t = Templater(FakeClock())
    match = None
    for i in range(5000):
        match = t.process(f"payment {100000 + i} settled in {(i * 7) % 997}ms")
    assert match is not None
    assert t.stats()["template_count"] == 1
    assert match.template.text == "payment <*> settled in <*>"
    assert match.template.count == 5000
    assert t.stats()["total_messages"] == 5000
    assert t.stats()["merges"] == 4999


def test_eviction_respects_cap_and_evicts_least_recently_seen_smallest_count():
    clk = FakeClock()
    t = Templater(clk, max_templates=3)
    t.process("alpha beta gamma delta epsilon")
    clk.advance(1.0)
    two = t.process("foxtrot golf hotel india juliet kilo")
    clk.advance(1.0)
    three = t.process("kilo lima mike november oscar papa")
    clk.advance(1.0)
    one_again = t.process("alpha beta gamma delta epsilon")
    assert one_again.template.template_id == 1
    assert one_again.template.count == 2
    clk.advance(1.0)
    four = t.process("quebec romeo sierra tango uniform victor")
    assert len(t.templates()) == 3
    assert t.get(two.template.template_id) is None
    assert t.get(three.template.template_id) is not None
    assert t.get(one_again.template.template_id) is not None
    assert t.get(four.template.template_id) is not None
    reborn = t.process("foxtrot golf hotel india juliet kilo")
    assert reborn.template.template_id != two.template.template_id
    assert reborn.template.text == two.template.text
    assert len(t.templates()) == 3
    assert {tpl.template_id for tpl in t.templates()} == {
        one_again.template.template_id,
        four.template.template_id,
        reborn.template.template_id,
    }


def test_eviction_tie_breaks_on_lowest_template_id():
    t = Templater(FakeClock(), max_templates=2)
    t.process("aa bb cc")
    t.process("dd ee ff")
    t.process("gg hh ii")
    assert [tpl.template_id for tpl in t.templates()] == [2, 3]


def test_adjacent_slots_stay_adjacent():
    t = Templater(FakeClock())
    m1 = t.process("a 1 b 2 c")
    m2 = t.process("a 9 b 8 c")
    assert m1.template is m2.template
    assert m1.template.tokens == ("a", "<*>", "b", "<*>", "c")
    assert m1.params == ("1", "2")
    assert m2.params == ("9", "8")
    assert sum(1 for tok in m1.template.tokens if tok == "<*>") == 2


def test_distinct_short_messages_do_not_merge():
    t = Templater(FakeClock())
    a = t.process("login ok")
    b = t.process("disk full")
    c = t.process("login ok")
    assert a.template is not b.template
    assert a.template is c.template
    assert b.template.tokens == ("disk", "full")
    assert t.stats()["template_count"] == 2


def test_empty_and_whitespace_only_share_one_empty_template():
    t = Templater(FakeClock())
    e1 = t.process("")
    e2 = t.process("   ")
    e3 = t.process("\t\n  ")
    assert e1.template is e2.template is e3.template
    assert e1.template.tokens == ()
    assert e1.template.text == ""
    assert e1.params == ()
    assert e1.template.count == 3
    assert t.stats()["total_messages"] == 3
    assert t.stats()["template_count"] == 1
    normal = t.process("real event here")
    assert normal.template.text == "real event here"
    assert t.stats()["template_count"] == 2


def test_mask_digits_off_merges_by_minority_rule_only():
    t = Templater(FakeClock(), mask_digits=False)
    m1 = t.process("user 4821 not found")
    assert m1.template.tokens == ("user", "4821", "not", "found")
    assert m1.params == ()
    m2 = t.process("user 9134 not found")
    assert m2.template is m1.template
    assert m1.template.tokens == ("user", "<*>", "not", "found")
    assert m2.params == ("9134",)
    m3 = t.process("node alpha down")
    m4 = t.process("node beta down")
    assert m4.template is m3.template
    assert m3.template.tokens == ("node", "<*>", "down")
    assert m4.params == ("beta",)


def test_get_templates_sorted_and_unknown_id_none():
    t = Templater(FakeClock())
    t.process("x 1 y")
    t.process("p q r s")
    t.process("z 2 w")
    assert [tpl.template_id for tpl in t.templates()] == sorted(
        tpl.template_id for tpl in t.templates()
    )
    assert t.get(999) is None
    assert t.get(2) is not None and t.get(2).text == "p q r s"


def test_clock_drives_first_seen_last_seen_and_count():
    clk = FakeClock()
    start = clk.now()
    t = Templater(clk)
    m1 = t.process("tick 1 tock")
    clk.advance(5.0)
    m2 = t.process("tick 2 tock")
    assert m1.template.first_seen == start
    assert m1.template.last_seen == start + 5.0
    assert m1.template.count == 2


def test_sample_values_bounded_at_three():
    t = Templater(FakeClock())
    for i in range(10):
        t.process(f"evt {i} done")
    assert len(t.templates()[0].sample_values) == 3
    assert t.templates()[0].sample_values == ["evt 0 done", "evt 1 done", "evt 2 done"]


def test_max_templates_must_be_positive():
    try:
        Templater(FakeClock(), max_templates=0)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for max_templates=0")

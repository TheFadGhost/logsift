"""Repo-wide hygiene gates: injected clock only, no stubs, no emoji, no bare except."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "logsift"
TESTS = ROOT / "tests"

EMOJI_RE = re.compile(
    "[\U0001F000-\U0001FAFF\U00002600-\U000027BF\U0001F1E6-\U0001F1FF\u2b00-\u2bff]"
)
STUB_RE = re.compile(r"\b(TODO|FIXME|XXX|HACK)\b")
STUB_ALLOW = {Path(__file__)}
BARE_EXCEPT_RE = re.compile(r"except\s*:")
CLOCK_RE = re.compile(
    r"time\.time\(|time\.monotonic\(|datetime\.now\(|datetime\.utcnow\("
    r"|perf_counter\("
)

ALLOW_PRINT = {PKGF := PKG / "cli.py", PKG / "tui"}


def _py_files(base: Path):
    for p in sorted(base.rglob("*.py")):
        yield p


def _check(paths, regexes, message, allow=()):
    offenders = []
    for p in paths:
        if p in allow:
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        for i, line in enumerate(text.splitlines(), 1):
            for rx in regexes:
                if rx.search(line):
                    offenders.append(f"{p.relative_to(ROOT)}:{i}: {message}: {line.strip()}")
    return offenders


def test_no_real_clock_outside_clock_module():
    src = list(_py_files(PKG))
    bad = _check(src, [CLOCK_RE], "direct system clock access", allow={PKG / "clock.py"})
    assert not bad, "\n" + "\n".join(bad)


def test_no_real_clock_in_tests():
    bad = _check(list(_py_files(TESTS)), [CLOCK_RE], "tests must not touch the system clock")
    assert not bad, "\n" + "\n".join(bad)


def test_no_stubs():
    bad = _check(
        list(_py_files(PKG)) + list(_py_files(TESTS)),
        [STUB_RE],
        "stub marker",
        allow=STUB_ALLOW,
    )
    assert not bad, "\n" + "\n".join(bad)


def test_no_emoji_anywhere():
    files = list(_py_files(PKG)) + list(_py_files(TESTS))
    files += [
        p
        for p in ROOT.glob("*.md")
        if p.name not in ("AUDIT.md", "BLOCKERS.md")
    ]
    bad = _check(files, [EMOJI_RE], "emoji found")
    assert not bad, "\n" + "\n".join(bad)


def test_no_bare_except():
    bad = _check(list(_py_files(PKG)), [BARE_EXCEPT_RE], "bare except swallows failures")
    assert not bad, "\n" + "\n".join(bad)


def test_print_only_in_cli_or_tui():
    print_re = re.compile(r"(?<![\w.])print\(")
    src = [p for p in _py_files(PKG) if "tui" not in p.parts and p.name != "cli.py"]
    bad = _check(src, [print_re], "print() outside CLI/TUI layer", allow=ALLOW_PRINT)
    assert not bad, "\n" + "\n".join(bad)

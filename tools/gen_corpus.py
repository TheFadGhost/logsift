"""Synthetic mixed-format log corpus generator for Logsift fixtures.

Every emitted byte is invented for this project: documentation-only IP ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), .example.test hostnames,
u-NNNN principals, fabricated object ids and original message wording. No
real log data is read or reproduced. Output is deterministic under --seed;
the system clock is never consulted (fixed BASE_EPOCH constant instead).

Usage:
    python tools/gen_corpus.py --out DIR [--lines N] [--seed S] [--big]

Outputs:
    DIR/corpus.jsonl   mixed-format synthetic log lines over a 72 h timeline
    DIR/labels.json    machine-readable injected-anomaly description
    DIR/stream_big.log (--big) 5,000,000 logfmt lines, no labels
    DIR/README.txt     factual generation record
"""

from __future__ import annotations

import argparse
import bisect
import json
import math
import random
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

BASE_EPOCH = 1780272000.0  # 2026-06-01T00:00:00Z; fixed constant, never time.time()
HORIZON_SECONDS = 72 * 3600
DEFAULT_LINES = 120_000
DEFAULT_SEED = 20260601
MIN_LINES = 300

DOC_NETS = ("192.0.2.", "198.51.100.", "203.0.113.")
HOSTS = (
    "host-alpha",
    "host-beta",
    "web-01.example.test",
    "web-02.example.test",
    "db-01.example.test",
    "cache-03.example.test",
)
MAIL_DOMAINS = ("inbox.example.test", "lists.example.test", "corp-mail.example.test")
ASSET_FILES = frozenset(f"app-{i:02d}.js" for i in range(1, 40))
ALLOWED_DOT_TOKENS = (
    frozenset(HOSTS) | frozenset(MAIL_DOMAINS) | ASSET_FILES | {"index.html"}
)
ORIGINS = ("origin-eu-1", "origin-us-2", "edge-far-3")
UPSTREAMS = ("app-pool-a", "app-pool-b", "legacy-shim")
AGENTS = ("SynthClient/1.4", "CorpPatchBot/2.0", "FieldAgent/0.9", "QueueProbe/3.1")
REFERERS = ("/v1/cart/items", "/v1/search/results", "/assets/index.html")

FORMAT_WEIGHTS: tuple[tuple[str, float], ...] = (
    ("json", 0.50),
    ("logfmt", 0.20),
    ("access", 0.15),
    ("syslog", 0.15),
)
FORMAT_NAMES = tuple(name for name, _ in FORMAT_WEIGHTS)

NORMAL_DURATION_MS = (60, 171)
SHIFT_DURATION_MS = (330, 481)
SURGE_ERROR_PROB = 0.15

NEW_TEMPLATE_COUNT = 40
RARE_TRIPLES = 8
RARE_GAP_SECONDS = 90
RESERVED_LINES = NEW_TEMPLATE_COUNT + RARE_TRIPLES * 3

RARE_START = 3 * 3600
RARE_END = RARE_START + (RARE_TRIPLES - 1) * RARE_GAP_SECONDS + 5
NEW_T_START = int(9.75 * 3600)
NEW_T_END = NEW_T_START + 300
SURGE_START = 15 * 3600
SURGE_END = SURGE_START + 900
SHIFT_START = 21 * 3600
SHIFT_END = SHIFT_START + 1800
STOP_START = 30 * 3600
STOP_END = 36 * 3600
SPIKE_START = 38 * 3600
SPIKE_END = SPIKE_START + 1800

BIG_LINES = 5_000_000


def _uid(rng: random.Random) -> str:
    return "u-%04d" % rng.randrange(1, 9999)


def _doc_ip(rng: random.Random) -> str:
    return DOC_NETS[rng.randrange(len(DOC_NETS))] + str(rng.randrange(1, 255))


def _oid(rng: random.Random) -> str:
    return "od-%05d" % rng.randrange(10000, 99999)


def _jid(rng: random.Random) -> str:
    return "jb-%06d" % rng.randrange(100000, 999999)


@dataclass(frozen=True)
class AppFamily:
    fid: str
    service: str
    weight: float
    p_warn: float
    p_err: float
    render: Callable[[random.Random, tuple[int, int]], tuple[str, dict]]
    render_error: Callable[[random.Random, tuple[int, int]], tuple[str, dict]]


def _app(
    fid: str,
    service: str,
    weight: float,
    p_warn: float,
    p_err: float,
    render: Callable[[random.Random, tuple[int, int]], tuple[str, dict]],
    render_error: Callable[[random.Random, tuple[int, int]], tuple[str, dict]] | None = None,
) -> AppFamily:
    if render_error is None:
        def render_error(rng: random.Random, _dur: tuple[int, int]) -> tuple[str, dict]:
            ms = rng.randrange(40, 900)
            return f"{service} operation aborted after {ms} ms", {"duration_ms": ms}
    return AppFamily(fid, service, weight, p_warn, p_err, render, render_error)


def _f_auth_login_ok(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    uid = _uid(rng)
    return f"login succeeded for user {uid}", {"user_id": uid}


def _f_auth_token(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    uid = _uid(rng)
    return f"session token rotated for user {uid}", {"user_id": uid}


def _f_auth_fail(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    uid = _uid(rng)
    return f"login refused: credentials not recognised for user {uid}", {"user_id": uid}


def _f_auth_mfa(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    uid = _uid(rng)
    dev = "dv-%04x" % rng.randrange(0x10000)
    return f"mfa challenge dispatched to device {dev} for user {uid}", {
        "device_id": dev, "user_id": uid,
    }


def _f_auth_key(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    pid = "svc-%02d" % rng.randrange(1, 40)
    return f"api key expired for principal {pid}", {"principal": pid}


def _e_auth_key(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    pid = "svc-%02d" % rng.randrange(1, 40)
    return f"api key rejected: principal {pid} past validity", {"principal": pid}


def _f_pay_charge(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    oid = _oid(rng)
    minor = rng.randrange(100, 99000)
    cur = ("eur", "usd", "gbp")[rng.randrange(3)]
    return f"charge captured for order {oid} amount {minor} {cur}", {
        "order_id": oid, "amount_minor": minor, "currency": cur,
    }


def _e_pay_charge(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    oid = _oid(rng)
    return f"capture aborted: issuer unreachable for order {oid}", {"order_id": oid}


def _f_pay_refund(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    oid = _oid(rng)
    return f"refund queued for order {oid}", {"order_id": oid}


def _f_pay_declined(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    oid = _oid(rng)
    rc = ("insufficient_funds", "do_not_honor", "expired_card")[rng.randrange(3)]
    return f"issuer declined authorization for order {oid} reason {rc}", {
        "order_id": oid, "decline_code": rc,
    }


def _f_pay_payout(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    mid = "m-%03d" % rng.randrange(1, 400)
    wh = "w%02d" % rng.randrange(1, 53)
    return f"payout scheduled for merchant {mid} window {wh}", {
        "merchant_id": mid, "window": wh,
    }


def _f_pay_recon(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    bid = "rb-%04d" % rng.randrange(10000)
    n = rng.randrange(40, 4000)
    return f"reconciliation batch {bid} closed with {n} entries", {
        "batch_id": bid, "entries": n,
    }


def _f_gw_routed(rng: random.Random, dur: tuple[int, int]) -> tuple[str, dict]:
    up = UPSTREAMS[rng.randrange(len(UPSTREAMS))]
    sc = (200, 201, 204, 301)[rng.randrange(4)]
    ms = rng.randrange(*dur)
    return f"request routed to upstream {up} status {sc} in {ms} ms", {
        "upstream": up, "status_code": sc, "duration_ms": ms,
    }


def _e_gw_routed(rng: random.Random, dur: tuple[int, int]) -> tuple[str, dict]:
    up = UPSTREAMS[rng.randrange(len(UPSTREAMS))]
    ms = rng.randrange(*dur)
    return f"upstream timeout after {ms} ms on route {up}", {
        "upstream": up, "duration_ms": ms,
    }


def _f_gw_limit(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    pid = "svc-%02d" % rng.randrange(1, 40)
    scope = ("tenant", "global", "endpoint")[rng.randrange(3)]
    return f"rate limit engaged for principal {pid} scope {scope}", {
        "principal": pid, "scope": scope,
    }


def _f_gw_miss(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    key = "obj-%05d" % rng.randrange(10000)
    origin = ORIGINS[rng.randrange(len(ORIGINS))]
    return f"object {key} fetched from origin {origin}", {
        "object_key": key, "origin": origin,
    }


def _f_gw_ws(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    ch = "chan-%03d" % rng.randrange(100, 900)
    proto = ("ws-json", "ws-msgpack")[rng.randrange(2)]
    return f"stream session opened channel {ch} protocol {proto}", {
        "channel": ch, "protocol": proto,
    }


def _f_q_hb(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    wid = "wk-%02d" % rng.randrange(1, 60)
    lane = ("lane-a", "lane-b", "lane-c")[rng.randrange(3)]
    lag = rng.randrange(0, 15)
    return f"worker {wid} heartbeat lane {lane} lag {lag} s", {
        "worker_id": wid, "lane": lane, "lag_s": lag,
    }


def _f_q_done(rng: random.Random, dur: tuple[int, int]) -> tuple[str, dict]:
    jid = _jid(rng)
    ms = rng.randrange(*dur)
    ex = rng.randrange(0, 3)
    return f"job {jid} finished in {ms} ms exit {ex}", {
        "job_id": jid, "duration_ms": ms, "exit_code": ex,
    }


def _e_q_done(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    jid = _jid(rng)
    ex = rng.randrange(10, 40)
    return f"job {jid} failed with code {ex}", {"job_id": jid, "exit_code": ex}


def _f_q_retry(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    jid = _jid(rng)
    r = rng.randrange(1, 4)
    dly = (5, 30, 120)[r - 1]
    return f"job {jid} retry {r}/3 scheduled delay {dly} s", {
        "job_id": jid, "attempt": r, "delay_s": dly,
    }


def _f_q_dead(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    jid = _jid(rng)
    return f"job {jid} parked in dead letter after 3 attempts", {"job_id": jid}


def _f_st_snap(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    vol = "vol-%s" % ("abcd", "efgh", "ijkl")[rng.randrange(3)]
    seg = rng.randrange(1, 500)
    return f"snapshot of volume {vol} sealed segment {seg}", {
        "volume": vol, "segment": seg,
    }


def _f_st_compact(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    vol = "vol-%s" % ("abcd", "efgh", "ijkl")[rng.randrange(3)]
    n = rng.randrange(2, 40)
    return f"compaction merged {n} segments on volume {vol}", {
        "volume": vol, "merged": n,
    }


def _f_st_lag(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    rid = "replica-%d" % rng.randrange(1, 6)
    lag = rng.randrange(0, 40)
    return f"replica {rid} replay lag {lag} s", {"replica_id": rid, "lag_s": lag}


def _f_se_shard(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    sh = "shard-%02d" % rng.randrange(1, 30)
    node = "node-%d" % rng.randrange(1, 9)
    return f"shard {sh} promoted to leader on node {node}", {
        "shard": sh, "node": node,
    }


def _f_se_plan(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    ratio = round(rng.uniform(0.82, 0.99), 3)
    coh = "ch-%s%d" % (("alpha", "beta", "gamma")[rng.randrange(3)], rng.randrange(1, 9))
    return f"query plan cache hit ratio {ratio} for cohort {coh}", {
        "hit_ratio": ratio, "cohort_id": coh,
    }


def _e_se_plan(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    coh = "ch-%s%d" % (("alpha", "beta", "gamma")[rng.randrange(3)], rng.randrange(1, 9))
    return f"plan cache corrupt; rebuilding cohort {coh}", {"cohort_id": coh}


def _f_se_slow(rng: random.Random, dur: tuple[int, int]) -> tuple[str, dict]:
    qid = "q-%05d" % rng.randrange(10000)
    n = rng.randrange(200, 90000)
    ms = rng.randrange(*dur)
    return f"query {qid} examined {n} postings in {ms} ms", {
        "query_id": qid, "postings": n, "duration_ms": ms,
    }


def _f_ml_queue(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    mid = "msg-%06d" % rng.randrange(100000)
    dom = MAIL_DOMAINS[rng.randrange(len(MAIL_DOMAINS))]
    return f"message {mid} queued to tenant domain {dom}", {
        "message_id": mid, "tenant_domain": dom,
    }


def _f_ml_bounce(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    mid = "msg-%06d" % rng.randrange(100000)
    rc = ("mailbox_full", "bad_domain", "policy_reject")[rng.randrange(3)]
    return f"message {mid} bounced reason {rc}", {"message_id": mid, "bounce_code": rc}


_APP_SPEC = (
    _app("auth.login.ok", "auth", 6.0, 0.02, 0.0005, _f_auth_login_ok, _f_auth_fail),
    _app("auth.token.rotate", "auth", 3.0, 0.01, 0.0, _f_auth_token),
    _app("auth.login.fail", "auth", 1.2, 0.80, 0.04, _f_auth_fail),
    _app("auth.mfa.sent", "auth", 1.5, 0.03, 0.001, _f_auth_mfa),
    _app("auth.apikey.expired", "auth", 0.8, 0.55, 0.10, _f_auth_key, _e_auth_key),
    _app("pay.charge.captured", "payments", 4.0, 0.02, 0.002, _f_pay_charge, _e_pay_charge),
    _app("pay.refund.queued", "payments", 1.4, 0.03, 0.002, _f_pay_refund),
    _app("pay.auth.declined", "payments", 1.0, 0.62, 0.06, _f_pay_declined),
    _app("pay.payout.scheduled", "payments", 0.9, 0.02, 0.001, _f_pay_payout),
    _app("pay.recon.batch", "payments", 0.7, 0.02, 0.002, _f_pay_recon),
    _app("gw.routed", "api-gateway", 8.0, 0.03, 0.002, _f_gw_routed, _e_gw_routed),
    _app("gw.rate.limit", "api-gateway", 1.0, 0.68, 0.02, _f_gw_limit),
    _app("gw.cache.miss", "api-gateway", 2.2, 0.04, 0.001, _f_gw_miss),
    _app("gw.ws.open", "api-gateway", 1.1, 0.02, 0.001, _f_gw_ws),
    # Baseline share of this family is exactly 5 percent of the app pool so a
    # full-window reassignment yields a 20x burst (see volume_spike note).
    _app("q.worker.hb", "worker-queue", 47.8 * 0.05 / 0.95, 0.01, 0.0005, _f_q_hb),
    _app("q.job.done", "worker-queue", 3.5, 0.03, 0.002, _f_q_done, _e_q_done),
    _app("q.job.retry", "worker-queue", 0.9, 0.60, 0.02, _f_q_retry),
    _app("q.job.dead", "worker-queue", 0.4, 0.45, 0.18, _f_q_dead),
    _app("store.snapshot", "storage", 1.3, 0.02, 0.001, _f_st_snap),
    _app("store.compact", "storage", 0.8, 0.03, 0.001, _f_st_compact),
    _app("store.replica.lag", "storage", 0.9, 0.46, 0.02, _f_st_lag),
    _app("search.shard.promote", "search", 0.9, 0.04, 0.001, _f_se_shard),
    _app("search.plan.cache", "search", 3.0, 0.02, 0.001, _f_se_plan, _e_se_plan),
    _app("search.slow.query", "search", 1.2, 0.10, 0.005, _f_se_slow),
    _app("mail.queued", "mailer", 1.6, 0.02, 0.001, _f_ml_queue),
    _app("mail.bounce", "mailer", 0.5, 0.52, 0.08, _f_ml_bounce),
)
APP_FAMILIES: tuple[AppFamily, ...] = _APP_SPEC
FAM_SPIKE = APP_FAMILIES[14]
FAM_SHIFT = APP_FAMILIES[10]
FAM_STOPPED = APP_FAMILIES[22]

def _f_purge(rng: random.Random, _d: tuple[int, int]) -> tuple[str, dict]:
    pid = "pl-%04d" % rng.randrange(10000)
    regions = rng.randrange(2, 13)
    return f"purge plan {pid} committed across {regions} regions", {
        "plan_id": pid, "regions": regions,
    }



FAM_PURGE = _app("edge.purge.plan", "edge-cache", 0.0, 0.0, 0.0, _f_purge)
FAM_SEQ_A = APP_FAMILIES[2]
FAM_SEQ_B = APP_FAMILIES[9]
FAM_SEQ_C = APP_FAMILIES[17]


@dataclass(frozen=True)
class AccessFamily:
    fid: str
    weight: float
    method: str
    path_fn: Callable[[random.Random], str]
    statuses: tuple[tuple[int, float], ...]


BYTES_BY_STATUS = {
    200: (700, 24000), 201: (64, 600), 204: (0, 64), 301: (180, 420),
    304: (0, 480), 401: (120, 300), 404: (220, 520), 500: (320, 900),
}


def _p_account(rng: random.Random) -> str:
    return "/v1/accounts/ac-%05d/summary" % rng.randrange(10000)


def _p_cart(_rng: random.Random) -> str:
    return "/v1/cart/items"


def _p_asset(rng: random.Random) -> str:
    return "/assets/app-%02d.js" % rng.randrange(1, 40)


def _p_search(rng: random.Random) -> str:
    term = ("logsift-docs", "queue-lag", "template-drift")[rng.randrange(3)]
    return f"/v1/search/results?q={term}"


def _p_health(_rng: random.Random) -> str:
    return "/health/live"


def _p_receipt(rng: random.Random) -> str:
    return f"/v1/orders/{_oid(rng)}/receipt"


def _p_sessions(_rng: random.Random) -> str:
    return "/v1/sessions"


ACCESS_FAMILIES: tuple[AccessFamily, ...] = (
    AccessFamily("acc.account.summary", 5.0, "GET", _p_account, ((200, 0.92), (404, 0.08))),
    AccessFamily("acc.cart.post", 3.5, "POST", _p_cart, ((201, 0.9), (500, 0.02), (200, 0.08))),
    AccessFamily("acc.asset.get", 4.0, "GET", _p_asset, ((200, 0.55), (304, 0.45))),
    AccessFamily("acc.search.get", 2.5, "GET", _p_search, ((200, 0.96), (500, 0.04))),
    AccessFamily("acc.health.live", 1.5, "GET", _p_health, ((200, 1.0),)),
    AccessFamily("acc.receipt.get", 1.2, "GET", _p_receipt, ((200, 0.85), (404, 0.15))),
    AccessFamily("acc.sessions.post", 1.8, "POST", _p_sessions, ((200, 0.88), (401, 0.12))),
)


@dataclass(frozen=True)
class SyslogFamily:
    fid: str
    weight: float
    program: str
    pid: int
    pri: int
    msg_fn: Callable[[random.Random], str]


def _s_auth_accept(rng: random.Random) -> str:
    uid = _uid(rng)
    ip = _doc_ip(rng)
    port = rng.randrange(1024, 65000)
    return f"accepted public key for user {uid} from {ip} port {port}"


def _s_auth_fail(rng: random.Random) -> str:
    uid = _uid(rng)
    return f"credential check failed for user {uid} from {_doc_ip(rng)}"


def _s_sched_sweep(rng: random.Random) -> str:
    return f"scheduled sweep of expired sessions removed {rng.randrange(0, 900)} entries"


def _s_net_probe(rng: random.Random) -> str:
    ip = _doc_ip(rng)
    ms = rng.randrange(1, 90)
    return f"probe to {ip} answered in {ms} ms"


def _s_net_flap(rng: random.Random) -> str:
    port = "eth%d" % rng.randrange(0, 8)
    state = ("up", "down")[rng.randrange(2)]
    return f"carrier state changed on port {port}: {state}"


def _s_pkg_current(_rng: random.Random) -> str:
    return "package inventory already current"


def _s_batch_drain(rng: random.Random) -> str:
    return f"drain pass moved {rng.randrange(10, 5000)} items to archive"



SYSLOG_FAMILIES: tuple[SyslogFamily, ...] = (
    SyslogFamily("sy.auth.accept", 3.0, "authd", 812, 38, _s_auth_accept),
    SyslogFamily("sy.auth.fail", 1.0, "authd", 812, 36, _s_auth_fail),
    SyslogFamily("sy.sched.sweep", 1.2, "schedd", 204, 38, _s_sched_sweep),
    SyslogFamily("sy.net.probe", 2.0, "netwatch", 533, 38, _s_net_probe),
    SyslogFamily("sy.net.flap", 0.6, "netwatch", 533, 36, _s_net_flap),
    SyslogFamily("sy.pkg.current", 1.4, "pkgupd", 87, 38, _s_pkg_current),
    SyslogFamily("sy.batch.drain", 1.8, "batchrun", 961, 38, _s_batch_drain),
)


def _cumulative(weights: list[float]) -> tuple[list[float], float]:
    bounds: list[float] = []
    acc = 0.0
    for w in weights:
        acc += w
        bounds.append(acc)
    return bounds, acc


APP_BOUNDS, APP_TOTAL = _cumulative([f.weight for f in APP_FAMILIES])
ACCESS_BOUNDS, ACCESS_TOTAL = _cumulative([f.weight for f in ACCESS_FAMILIES])
SYSLOG_BOUNDS, SYSLOG_TOTAL = _cumulative([f.weight for f in SYSLOG_FAMILIES])
FMT_BOUNDS, FMT_TOTAL = _cumulative([w for _, w in FORMAT_WEIGHTS])


def _pick(bounds: list[float], total: float, rng: random.Random) -> int:
    target = rng.random() * total
    idx = bisect.bisect_left(bounds, target)
    return idx if idx < len(bounds) else len(bounds) - 1


_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _iso(ts: float) -> str:
    dt = _utc(ts)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _escape_quoted(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _seasonal(hour: float) -> float:
    day = math.exp(-((hour - 13.0) ** 2) / (2 * 3.2 ** 2))
    evening = math.exp(-((hour - 20.5) ** 2) / (2 * 1.8 ** 2))
    return 0.22 + day + 0.55 * evening


HOUR_WEIGHTS = [_seasonal(float(h)) for h in range(24)]


def _apportion(total: int, weights: list[float]) -> list[int]:
    n = len(weights)
    if total <= 0:
        return [0] * n
    scale = sum(weights)
    raw = [total * w / scale for w in weights]
    counts = [int(math.floor(x)) for x in raw]
    remaining = total - sum(counts)
    order = sorted(range(n), key=lambda j: (-(raw[j] - counts[j]), j))
    for j in order[:remaining]:
        counts[j] += 1
    return counts


def _draw_level(fam: AppFamily, rng: random.Random) -> str:
    r = rng.random()
    if r < fam.p_err:
        return "error"
    if r < fam.p_err + fam.p_warn:
        return "warning"
    return "info"


def emit_app(
    fam: AppFamily,
    ts: float,
    level: str,
    fmt: str,
    rng: random.Random,
    dur_range: tuple[int, int],
) -> str:
    renderer = fam.render_error if level == "error" else fam.render
    message, extras = renderer(rng, dur_range)
    iso = _iso(ts)
    if fmt == "json":
        payload = {"timestamp": iso, "level": level, "service": fam.service, "message": message}
        payload.update(extras)
        return json.dumps(payload, separators=(",", ":"))
    tokens = [
        "timestamp=" + iso,
        "level=" + level,
        "service=" + fam.service,
        'msg="' + _escape_quoted(message) + '"',
    ]
    tokens.extend(f"{key}={value}" for key, value in extras.items())
    return " ".join(tokens)


def emit_access(fam: AccessFamily, ts: float, rng: random.Random) -> str:
    status_bounds, status_total = _cumulative([w for _, w in fam.statuses])
    status = fam.statuses[_pick(status_bounds, status_total, rng)][0]
    lo, hi = BYTES_BY_STATUS[status]
    nbytes = rng.randrange(lo, hi + 1)
    user = _uid(rng) if rng.random() < 0.30 else "-"
    path = fam.path_fn(rng)
    proto = "HTTP/1.1" if rng.random() < 0.7 else "HTTP/2"
    referer = REFERERS[rng.randrange(len(REFERERS))] if rng.random() < 0.3 else "-"
    agent = AGENTS[rng.randrange(len(AGENTS))]
    dt = _utc(ts)
    stamp = (
        f"{dt.day:02d}/{_MONTHS[dt.month - 1]}/{dt.year:d}:"
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"
    )
    return (
        f'{_doc_ip(rng)} - {user} [{stamp}] "{fam.method} {path} {proto}" '
        f'{status} {nbytes} "{referer}" "{agent}"'
    )


def emit_syslog(fam: SyslogFamily, ts: float, rng: random.Random) -> str:
    host = HOSTS[rng.randrange(len(HOSTS))]
    message = fam.msg_fn(rng)
    dt = _utc(ts)
    head = (
        f"{_MONTHS[dt.month - 1]} {dt.day:02d} "
        f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
    )
    pri = f"<{fam.pri}>" if rng.random() < 0.5 else ""
    return f"{pri}{head} {host} {fam.program}[{fam.pid}]: {message}"


_ANOMALY_TABLE = (
    ("rare_sequence", RARE_START, RARE_END,
     "auth.login.fail -> pay.recon.batch -> q.job.dead (ordered triple)",
     "three established low-traffic families emitted back-to-back in an order "
     f"never seen naturally, repeated {RARE_TRIPLES} times at {RARE_GAP_SECONDS} s spacing"),
    ("new_template", NEW_T_START, NEW_T_END,
     "purge plan <*> committed across <*> regions",
     f"a family seen nowhere else in the timeline appears {NEW_TEMPLATE_COUNT} times "
     "inside this 5 minute window"),
    ("error_rate_surge", SURGE_START, SURGE_END,
     "(mixed) error-level variants of existing json/logfmt families",
     "share of error-level app lines forced to about 15 percent; the natural "
     "baseline outside this window stays under 1 percent"),
    ("latency_shift", SHIFT_START, SHIFT_END,
     "request routed to upstream <*> status <*> in <*> ms",
     "duration_ms moves from the 60-170 ms band to the 330-480 ms band for "
     "this one family"),
    ("stopped_template", STOP_START, STOP_END,
     "query plan cache hit ratio <*> for cohort <*>",
     "this normally frequent family emits zero lines for the whole 6 hour window"),
    ("volume_spike", SPIKE_START, SPIKE_END,
     "worker <*> heartbeat lane <*> lag <*> s",
     "every json/logfmt line in the window is reassigned to this family; its "
     "baseline share of the app pool is exactly 5 percent, so its rate in the "
     "window is 20x its own baseline"),
)


def _normal_ranges() -> list[list[float]]:
    cursor = 0.0
    spans: list[list[float]] = []
    for _kind, start, end, _hint, _note in _ANOMALY_TABLE:
        if start > cursor:
            spans.append([BASE_EPOCH + cursor, BASE_EPOCH + start])
        cursor = max(cursor, float(end))
    if cursor < HORIZON_SECONDS:
        spans.append([BASE_EPOCH + cursor, BASE_EPOCH + HORIZON_SECONDS])
    return spans


def _build_labels(seed: int, requested: int, written: int) -> dict:
    placement = "; ".join(
        f"{kind} {start / 3600:.3f}h..{end / 3600:.3f}h"
        for kind, start, end, _hint, _note in _ANOMALY_TABLE
    )
    anomalies = [
        {
            "kind": kind,
            "start_epoch": BASE_EPOCH + start,
            "end_epoch": BASE_EPOCH + end,
            "template_hint": hint,
            "note": note,
        }
        for kind, start, end, hint, note in _ANOMALY_TABLE
    ]
    return {
        "schema": "logsift.corpus.labels/1",
        "generator": "tools/gen_corpus.py",
        "seed": seed,
        "requested_lines": requested,
        "written_lines": written,
        "timeline": {"start_epoch": BASE_EPOCH, "end_epoch": BASE_EPOCH + HORIZON_SECONDS},
        "meta": {
            "placement_hours_from_base_epoch": placement,
            "minimum_separation_between_windows": "2.0 h",
            "seasonality": "gaussian midday and evening peaks, overnight trough near 0.22x",
            "format_mix": dict(FORMAT_WEIGHTS),
            "provenance": "fully synthetic; documentation-only IPs; invented hosts and ids",
        },
        "anomalies": anomalies,
        "normal_ranges": _normal_ranges(),
    }


def _generate_records(lines: int, seed: int) -> list[tuple[float, int, str]]:
    rng = random.Random(seed)
    base_count = lines - RESERVED_LINES
    alloc = _apportion(base_count, [HOUR_WEIGHTS[h % 24] for h in range(HORIZON_SECONDS // 3600)])
    records: list[tuple[float, int, str]] = []
    seq = 0
    for hour, count in enumerate(alloc):
        if count == 0:
            continue
        hour_start = hour * 3600
        slot = 3600.0 / count
        for i in range(count):
            offset = hour_start + (i + rng.random()) * slot
            ts = BASE_EPOCH + offset
            fmt = FORMAT_NAMES[_pick(FMT_BOUNDS, FMT_TOTAL, rng)]
            if fmt in ("json", "logfmt"):
                fam = APP_FAMILIES[_pick(APP_BOUNDS, APP_TOTAL, rng)]
                if STOP_START <= offset < STOP_END and fam is FAM_STOPPED:
                    while fam is FAM_STOPPED:
                        fam = APP_FAMILIES[_pick(APP_BOUNDS, APP_TOTAL, rng)]
                if SPIKE_START <= offset < SPIKE_END:
                    fam = FAM_SPIKE
                level = _draw_level(fam, rng)
                if SURGE_START <= offset < SURGE_END and rng.random() < SURGE_ERROR_PROB:
                    level = "error"
                dur = SHIFT_DURATION_MS if SHIFT_START <= offset < SHIFT_END else NORMAL_DURATION_MS
                line = emit_app(fam, ts, level, fmt, rng, dur)
            elif fmt == "access":
                line = emit_access(ACCESS_FAMILIES[_pick(ACCESS_BOUNDS, ACCESS_TOTAL, rng)], ts, rng)
            else:
                line = emit_syslog(SYSLOG_FAMILIES[_pick(SYSLOG_BOUNDS, SYSLOG_TOTAL, rng)], ts, rng)
            records.append((ts, seq, line))
            seq += 1
    for _ in range(NEW_TEMPLATE_COUNT):
        ts = BASE_EPOCH + NEW_T_START + rng.random() * (NEW_T_END - NEW_T_START)
        records.append((ts, seq, emit_app(FAM_PURGE, ts, "info", "json", rng, NORMAL_DURATION_MS)))
        seq += 1
    for k in range(RARE_TRIPLES):
        base_t = BASE_EPOCH + RARE_START + k * RARE_GAP_SECONDS
        ta = base_t
        tb = ta + 0.15
        tc = tb + 0.20
        records.append((ta, seq, emit_app(FAM_SEQ_A, ta, "info", "json", rng, NORMAL_DURATION_MS)))
        seq += 1
        records.append((tb, seq, emit_app(FAM_SEQ_B, tb, "info", "logfmt", rng, NORMAL_DURATION_MS)))
        seq += 1
        records.append((tc, seq, emit_app(FAM_SEQ_C, tc, "info", "json", rng, NORMAL_DURATION_MS)))
        seq += 1
    records.sort(key=lambda rec: (rec[0], rec[1]))
    return records


def _write_big_stream(path: Path, seed: int) -> int:
    rng = random.Random((seed << 1) ^ 0x5EED)
    step = HORIZON_SECONDS / BIG_LINES
    chunk: list[str] = []
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for i in range(BIG_LINES):
            ts = BASE_EPOCH + i * step
            fam = APP_FAMILIES[_pick(APP_BOUNDS, APP_TOTAL, rng)]
            level = _draw_level(fam, rng)
            chunk.append(emit_app(fam, ts, level, "logfmt", rng, NORMAL_DURATION_MS))
            if len(chunk) >= 20000:
                fh.write("\n".join(chunk) + "\n")
                chunk.clear()
        if chunk:
            fh.write("\n".join(chunk) + "\n")
    return BIG_LINES


def generate(out_dir: Path, lines: int, seed: int, big: bool) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    records = _generate_records(lines, seed)
    corpus_path = out_dir / "corpus.jsonl"
    with open(corpus_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.writelines(line + "\n" for _ts, _seq, line in records)
    labels = _build_labels(seed, lines, len(records))
    labels_path = out_dir / "labels.json"
    with open(labels_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(labels, sort_keys=True, indent=2) + "\n")
    big_note = "none"
    if big:
        big_path = out_dir / "stream_big.log"
        big_lines = _write_big_stream(big_path, seed)
        big_note = f"stream_big.log {big_lines} lines ({big_path.stat().st_size} bytes)"
    readme_path = out_dir / "README.txt"
    argv_text = " ".join(sys.argv)
    command = (
        f"python tools/gen_corpus.py --out {out_dir} --lines {lines} --seed {seed}"
        + (" --big" if big else "")
    )
    readme = "\n".join([
        "logsift synthetic fixture corpus",
        "",
        f"command: {command}",
        f"argv: {argv_text}",
        f"seed: {seed}",
        f"requested_lines: {lines}",
        f"corpus_lines_written: {len(records)} (includes {RESERVED_LINES} injected anomaly lines)",
        f"timeline_start_utc: {_iso(BASE_EPOCH)}",
        f"timeline_end_utc: {_iso(BASE_EPOCH + HORIZON_SECONDS)}",
        f"files:",
        f"  corpus.jsonl {corpus_path.stat().st_size} bytes",
        f"  labels.json {labels_path.stat().st_size} bytes",
        f"  {big_note}",
        "anomaly_windows: documented in labels.json (anomalies + normal_ranges + meta)",
        "provenance: fully synthetic; documentation-only IP ranges (192.0.2.0/24, "
        "198.51.100.0/24, 203.0.113.0/24); invented .example.test hostnames and "
        "host-alpha/host-beta; fabricated u-NNNN and object ids; original wording; "
        "no real log data",
        "",
    ])
    with open(readme_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(readme)
    return {
        "corpus": str(corpus_path),
        "labels": str(labels_path),
        "lines": len(records),
        "corpus_bytes": corpus_path.stat().st_size,
        "big": big_note,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic synthetic mixed-format log corpus."
    )
    parser.add_argument("--out", required=True, help="output directory (created if missing)")
    parser.add_argument("--lines", type=int, default=DEFAULT_LINES,
                        help=f"total corpus lines including injected anomalies (default {DEFAULT_LINES})")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED,
                        help=f"deterministic seed (default {DEFAULT_SEED})")
    parser.add_argument("--big", action="store_true",
                        help=f"also write stream_big.log with {BIG_LINES} logfmt lines")
    args = parser.parse_args(argv)
    if args.lines < MIN_LINES:
        print(f"gen_corpus: --lines must be >= {MIN_LINES} "
              f"({RESERVED_LINES} lines are reserved for injected anomalies)", file=sys.stderr)
        return 2
    stats = generate(Path(args.out), args.lines, args.seed, args.big)
    print(f"corpus: {stats['corpus']} ({stats['lines']} lines, {stats['corpus_bytes']} bytes)")
    print(f"labels: {stats['labels']}")
    print(f"big: {stats['big']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


"""Deterministic statistics primitives for baseline learning.

Pure functions only: no clock access, no I/O, no global state. Every function
accepts degenerate input (empty lists, zero denominators, constant samples)
and returns ``None`` or a neutral value instead of raising; the exact contract
is documented per function and asserted in tests.
"""

from __future__ import annotations

import math
from collections import Counter

MAD_TO_SIGMA = 1.4826  # consistency constant: MAD of a normal distribution -> sigma
_Z_EPS = 1e-9


def median(values: list[float]) -> float | None:
    """Median of ``values``; ``None`` when the list is empty."""
    if not values:
        return None
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def mad(values: list[float]) -> float | None:
    """Median absolute deviation about the median.

    Returns ``None`` for an empty list and ``0.0`` for a single sample or any
    constant sample (all deviations are zero).
    """
    med = median(values)
    if med is None:
        return None
    return median([abs(v - med) for v in values])


def robust_z(x: float, med: float, spread: float) -> float:
    """Robust z-score ``(x - med) / (1.4826 * spread)``.

    The divisor is floored at 1e-9 so a zero MAD can never divide by zero:
    ``x == med`` yields exactly ``0.0``, any other ``x`` yields a large but
    finite score proportional to the raw offset. Negative spreads are treated
    as their absolute value. Inputs are assumed finite.
    """
    scale = max(MAD_TO_SIGMA * abs(float(spread)), _Z_EPS)
    return (float(x) - float(med)) / scale


def two_proportion_ztest(k1: int, n1: int, k2: int, n2: int) -> float | None:
    """Pooled two-proportion z statistic; positive means group 1 rate higher.

    Returns ``None`` when either trial count is non-positive (nothing to
    compare). Returns ``0.0`` when the pooled variance is degenerate (both
    groups are all-success or all-failure), since the rates are then equal by
    construction and no shift is observable.
    """
    if n1 <= 0 or n2 <= 0:
        return None
    p1 = k1 / n1
    p2 = k2 / n2
    pooled = (k1 + k2) / (n1 + n2)
    var = pooled * (1.0 - pooled) * (1.0 / n1 + 1.0 / n2)
    if var <= 0.0:
        return 0.0
    return (p1 - p2) / math.sqrt(var)


def mann_whitney_u(a: list[float], b: list[float]) -> tuple[float, float] | None:
    """Mann-Whitney U of sample ``a`` against ``b`` with normal approximation.

    Returns ``(u, z)`` where ``u`` is U for sample ``a`` (rank-sum based,
    tie-corrected average ranks) and ``z`` the tie-corrected normal score;
    negative z means ``a`` is stochastically smaller than ``b``.

    Returns ``None`` when either sample is empty. When every pooled value is
    identical the variance is zero and ``z`` is defined as ``0.0``. Values are
    assumed finite (NaN ordering is undefined).
    """
    na, nb = len(a), len(b)
    if na == 0 or nb == 0:
        return None
    pool = list(a) + list(b)
    ranks = _average_ranks(pool)
    r_a = math.fsum(ranks[:na])
    u_a = r_a - na * (na + 1) / 2.0
    n = na + nb
    mu_u = na * nb / 2.0
    tie_term = sum(t**3 - t for t in Counter(pool).values())
    sigma_sq = (na * nb / 12.0) * ((n + 1) - tie_term / (n * (n - 1)))
    if sigma_sq <= 0.0:
        return (u_a, 0.0)
    return (u_a, (u_a - mu_u) / math.sqrt(sigma_sq))


def _average_ranks(values: list[float]) -> list[float]:
    """One-based ranks with ties assigned their average rank."""
    order = sorted(range(len(values)), key=lambda i: values[i])
    ranks = [0.0] * len(values)
    i = 0
    while i < len(order):
        j = i
        while j + 1 < len(order) and values[order[j + 1]] == values[order[i]]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[order[k]] = avg
        i = j + 1
    return ranks

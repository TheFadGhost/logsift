"""Statsutil: known-value checks, scaling, sanity, degenerate input safety."""

from __future__ import annotations

import math

from logsift.statsutil import (
    mad,
    mann_whitney_u,
    median,
    robust_z,
    two_proportion_ztest,
)


def test_median_known_values():
    assert median([]) is None
    assert median([5]) == 5.0
    assert median([1, 3, 2]) == 2.0
    assert median([4, 1, 3, 2]) == 2.5
    assert median([7.5, 2.5]) == 5.0


def test_mad_known_values():
    assert mad([]) is None
    assert mad([7]) == 0.0
    assert mad([4, 4, 4]) == 0.0
    assert mad([1, 2, 3, 4, 5]) == 1.0
    assert mad([1, 2, 3, 100]) == 1.0


def test_robust_z_scaling():
    z = robust_z(13, 10, 1.0)
    assert math.isclose(z, 3 / 1.4826)
    assert robust_z(10, 10, 1.0) == 0.0
    assert math.isclose(robust_z(7, 10, 2.0), -3 / (1.4826 * 2.0))


def test_robust_z_zero_mad_epsilon_floor():
    assert robust_z(10, 10, 0.0) == 0.0
    big = robust_z(10.001, 10.0, 0.0)
    assert math.isfinite(big) and big > 9e5
    assert robust_z(10, 10, -3.0) == 0.0


def test_two_proportion_ztest_sanity():
    assert two_proportion_ztest(50, 100, 25, 50) == 0.0
    z = two_proportion_ztest(90, 100, 10, 100)
    assert z is not None and abs(z) > 9 and z > 0
    rev = two_proportion_ztest(10, 100, 90, 100)
    assert rev is not None and rev == -z


def test_two_proportion_ztest_degenerate():
    assert two_proportion_ztest(1, 0, 1, 10) is None
    assert two_proportion_ztest(1, 10, 1, 0) is None
    assert two_proportion_ztest(-1, 10, 1, 10) is not None
    assert two_proportion_ztest(0, 5, 0, 5) == 0.0
    assert two_proportion_ztest(5, 5, 5, 5) == 0.0


def test_mann_whitney_detects_shift():
    a = [float(x) for x in range(20)]
    b = [float(x) + 100.0 for x in range(20)]
    u, z = mann_whitney_u(a, b)
    assert u == 0.0
    assert z < -4.0
    _, z_rev = mann_whitney_u(b, a)
    assert z_rev > 4.0


def test_mann_whitney_identical_samples_zero():
    u, z = mann_whitney_u([1.0, 2.0, 3.0], [1.0, 2.0, 3.0])
    assert u == 4.5
    assert z == 0.0


def test_mann_whitney_ties_handled():
    u, z = mann_whitney_u([1.0, 1.0, 2.0], [1.0, 2.0, 2.0])
    assert math.isfinite(u) and math.isfinite(z)
    assert z < 0
    expected_sigma = math.sqrt((9 / 12.0) * (7 - 48 / 30))
    assert math.isclose(abs(z), 1.5 / expected_sigma)


def test_mann_whitney_degenerate_inputs():
    assert mann_whitney_u([], [1.0]) is None
    assert mann_whitney_u([1.0], []) is None
    assert mann_whitney_u([], []) is None
    u, z = mann_whitney_u([1.0], [2.0])
    assert (u, z) == (0.0, -1.0)
    u2, z2 = mann_whitney_u([5.0], [5.0])
    assert u2 == 0.5
    assert z2 == 0.0


def test_median_mad_do_not_mutate_input():
    values = [3, 1, 2]
    median(values)
    mad(values)
    assert values == [3, 1, 2]

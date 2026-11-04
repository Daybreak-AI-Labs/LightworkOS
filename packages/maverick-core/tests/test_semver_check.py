"""semver_check: version-constraint satisfaction."""
from __future__ import annotations

from maverick.tools.semver_check import semver_check


def _c(version, constraint):
    return semver_check().fn({"op": "check", "version": version, "constraint": constraint})


def test_comparator_range_satisfied():
    out = _c("1.5.0", ">=1.2.0,<2.0.0")
    assert out.startswith("SATISFIED")


def test_comparator_range_unsatisfied():
    out = _c("2.0.0", ">=1.2.0,<2.0.0")
    assert out.startswith("UNSATISFIED")
    assert "fails <2.0.0" in out


def test_caret_major():
    assert _c("1.9.9", "^1.2.3").startswith("SATISFIED")
    assert _c("2.0.0", "^1.2.3").startswith("UNSATISFIED")
    assert _c("1.2.2", "^1.2.3").startswith("UNSATISFIED")


def test_caret_zero_minor():
    # ^0.2.3 -> >=0.2.3 <0.3.0
    assert _c("0.2.5", "^0.2.3").startswith("SATISFIED")
    assert _c("0.3.0", "^0.2.3").startswith("UNSATISFIED")


def test_tilde():
    # ~1.2.3 -> >=1.2.3 <1.3.0
    assert _c("1.2.9", "~1.2.3").startswith("SATISFIED")
    assert _c("1.3.0", "~1.2.3").startswith("UNSATISFIED")


def test_exact_and_star():
    assert _c("1.2.3", "1.2.3").startswith("SATISFIED")
    assert _c("1.2.4", "=1.2.3").startswith("UNSATISFIED")
    assert _c("9.9.9", "*").startswith("SATISFIED")


def test_prerelease_ordering():
    # prerelease is lower than the release when the bound explicitly names it
    assert _c("1.0.0-rc.1", "<1.0.0-rc.2").startswith("SATISFIED")
    assert _c("1.0.0", ">1.0.0-rc.1").startswith("SATISFIED")


def test_prerelease_excluded_at_final_release_upper_bound():
    assert _c("2.0.0-rc.1", "^1.2.3").startswith("UNSATISFIED")
    assert _c("1.3.0-beta", "~1.2.3").startswith("UNSATISFIED")
    assert _c("2.0.0-rc.1", ">=1.2.0,<2.0.0").startswith("UNSATISFIED")


def test_prerelease_allowed_before_explicit_prerelease_upper_bound():
    assert _c("2.0.0-beta.1", ">=1.2.0,<2.0.0-rc.1").startswith("SATISFIED")


def test_partial_version_padding():
    # constraint and version may omit trailing components
    assert _c("1.2", ">=1.0").startswith("SATISFIED")


def test_errors():
    t = semver_check()
    assert t.fn({"op": "check", "version": "", "constraint": "*"}).startswith("ERROR")
    assert t.fn({"op": "check", "version": "notsemver", "constraint": "*"}).startswith("ERROR")
    assert t.fn({"op": "check", "version": "1.0.0", "constraint": ">=bad"}).startswith("ERROR")
    assert t.fn({"op": "nope", "version": "1.0.0", "constraint": "*"}).startswith("ERROR")


def test_registered():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        workdir = "."

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "semver_check" in names


def test_huge_numeric_components_do_not_crash():
    # Regression: int() on an unbounded \d+ run tripped CPython's
    # int_max_str_digits ValueError on a model-supplied version/constraint.
    t = semver_check()
    big = "1" * 5000
    assert t.fn({"op": "check", "version": big, "constraint": ">=1.0.0"}).startswith("ERROR")
    assert t.fn({"op": "check", "version": "1.0.0", "constraint": ">=" + big}).startswith("ERROR")
    # huge numeric prerelease identifier compares without int()
    out = t.fn({"op": "check", "version": "1.0.0-" + big, "constraint": ">=1.0.0-1"})
    assert out.startswith(("SATISFIED", "UNSATISFIED"))


def test_numeric_prerelease_ordering():
    t = semver_check()
    # 2 < 10 numerically (longer digit run = larger), not lexically
    assert t.fn({"op": "check", "version": "1.0.0-2", "constraint": "<1.0.0-10"}).startswith("SATISFIED")
    assert t.fn({"op": "check", "version": "1.0.0-10", "constraint": ">1.0.0-2"}).startswith("SATISFIED")

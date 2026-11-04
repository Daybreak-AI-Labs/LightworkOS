"""supply_chain_pin: flag unpinned/unhashed/range dependencies."""
from __future__ import annotations

from maverick.tools.supply_chain_pin import supply_chain_pin


def _run(**kw):
    return supply_chain_pin().fn({"op": "check", **kw})


def test_ok_all_pinned_and_hashed():
    out = _run(deps=[
        {"name": "requests", "version": "2.31.0", "hash": "sha256:aaa"},
        {"name": "rich", "version": "13.7.1", "hash": "sha256:bbb"},
    ])
    assert out.startswith("OK") and "2 package(s) pinned and hashed" in out


def test_unpinned_flagged():
    out = _run(deps=[{"name": "lodash", "hash": "sha256:x"}])
    assert out.startswith("VIOLATIONS")
    assert "lodash: unpinned" in out


def test_version_range_flagged():
    out = _run(deps=[{"name": "react", "version": "^18.2.0", "hash": "sha256:x"}])
    assert out.startswith("VIOLATIONS")
    assert "version range" in out and "react" in out


def test_unhashed_flagged_by_default():
    out = _run(deps=[{"name": "flask", "version": "3.0.0"}])
    assert out.startswith("VIOLATIONS")
    assert "flask: unhashed" in out


def test_hash_not_required_when_policy_off():
    out = _run(deps=[{"name": "flask", "version": "3.0.0"}],
               policy={"require_hash": False})
    assert out.startswith("OK") and "1 package(s) pinned" in out
    assert "hashed" not in out


def test_multiple_violations_counted():
    out = _run(deps=[
        {"name": "a", "version": "~1.0"},
        {"name": "b"},
    ])
    assert out.startswith("VIOLATIONS")
    # a: range + unhashed, b: unpinned + unhashed => 4 issues
    assert "4 issue(s)" in out


def test_exact_pin_with_letter_x_not_flagged():
    # An exact pin that merely CONTAINS the letter 'x' is a real pin, not a
    # wildcard -- only a standalone 'x'/'X' version component is a range.
    out = _run(deps=[{"name": "torch", "version": "2.0.0+cuxa", "hash": "sha256:z"}])
    assert out.startswith("OK"), out


def test_wildcard_x_component_flagged():
    out = _run(deps=[{"name": "react", "version": "18.x", "hash": "sha256:z"}])
    assert out.startswith("VIOLATIONS")
    assert "version range" in out and "react" in out


def test_errors():
    t = supply_chain_pin()
    assert t.fn({"op": "check"}).startswith("ERROR")
    assert t.fn({"op": "nope", "deps": []}).startswith("ERROR")

"""data_residency: per-jurisdiction data residency routing."""
from __future__ import annotations

from maverick.tools.data_residency import data_residency


def _run(**kw):
    return data_residency().fn({"op": "route", **kw})


def test_direct_region_allow():
    out = _run(region="DE", policy={"DE": ["DE", "FR"]})
    assert out.startswith("ALLOW DE")
    assert "permitted storage region(s): DE, FR" in out


def test_group_key_matches_member():
    # EU policy key should match a member country DE.
    out = _run(region="DE", policy={"EU": ["EEA"]})
    assert out.startswith("ALLOW DE")
    assert "matched EU" in out
    # EEA storage target expands to include FR, IS, etc.
    assert "FR" in out and "IS" in out


def test_no_policy_for_region_denies():
    out = _run(region="US", policy={"DE": ["DE"]})
    assert out.startswith("DENY US")
    assert "no residency policy" in out


def test_empty_allowed_denies():
    out = _run(region="DE", policy={"DE": []})
    assert out.startswith("DENY DE")
    assert "permits no storage region" in out


def test_case_insensitive_region():
    out = _run(region="de", policy={"DE": ["de"]})
    assert out.startswith("ALLOW DE")


def test_errors_and_unknown_op():
    t = data_residency()
    assert t.fn({"op": "route", "policy": {"DE": ["DE"]}}).startswith("ERROR")
    assert t.fn({"op": "route", "region": "DE"}).startswith("ERROR")
    assert t.fn({"op": "route", "region": "DE", "policy": {}}).startswith("ERROR")
    assert t.fn({"op": "nope", "region": "DE", "policy": {"DE": ["DE"]}}).startswith("ERROR")


def test_factory_identity():
    t = data_residency()
    assert t.name == "data_residency"
    assert t.parallel_safe is True

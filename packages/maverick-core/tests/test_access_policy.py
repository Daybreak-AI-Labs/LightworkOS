"""Purpose/attribute-based access control (PBAC/ABAC)."""
from __future__ import annotations

import pytest
from maverick.access_policy import (
    AccessDenied,
    AccessPolicy,
    AccessRequest,
    check,
    decide,
    enforce,
    purpose_scope,
)


def test_decide_allows_matching_purpose_and_attributes():
    pol = AccessPolicy(purposes=["audit"], required_attributes=["finance-cleared"])
    ok = decide(AccessRequest("audit", ["finance-cleared", "extra"]), pol)
    assert ok.allowed


def test_decide_denies_wrong_purpose():
    pol = AccessPolicy(purposes=["audit"])
    d = decide(AccessRequest("marketing"), pol)
    assert not d.allowed and "purpose" in d.reason


def test_decide_denies_missing_attribute():
    pol = AccessPolicy(purposes=["audit"], required_attributes=["pii-cleared"])
    d = decide(AccessRequest("audit"), pol)
    assert not d.allowed and "pii-cleared" in d.reason


def test_unrestricted_policy_allows_anything():
    pol = AccessPolicy()
    assert pol.unrestricted
    assert decide(AccessRequest("whatever"), pol).allowed
    assert check(pol).allowed  # even with no purpose declared


def test_restricted_resource_with_no_purpose_is_denied():
    # Default behaviour with no active purpose: unrestricted ok, restricted denied.
    assert not check(AccessPolicy(purposes=["audit"])).allowed


def test_purpose_scope_satisfies_check_and_enforce():
    pol = AccessPolicy(purposes=["audit"], required_attributes=["finance-cleared"])
    with purpose_scope("audit", ["finance-cleared"]):
        assert check(pol).allowed
        enforce(pol)  # does not raise
    # outside the scope, the restricted resource is denied again
    assert not check(pol).allowed


def test_enforce_raises_on_denied():
    with pytest.raises(AccessDenied, match="purpose"):
        with purpose_scope("marketing"):
            enforce(AccessPolicy(purposes=["audit"]))


def test_env_declares_purpose(monkeypatch):
    monkeypatch.setenv("MAVERICK_PURPOSE", "audit")
    monkeypatch.setenv("MAVERICK_PURPOSE_ATTRS", "finance-cleared, pii-cleared")
    assert check(AccessPolicy(purposes=["audit"],
                              required_attributes=["finance-cleared"])).allowed

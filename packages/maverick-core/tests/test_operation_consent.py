"""Hostile tests for exact, one-use operation consent permits."""
from __future__ import annotations

import copy
import time

import pytest
from maverick.approval_cards import ApprovalCardError
from maverick.safety import consent


@pytest.fixture
def authority(monkeypatch):
    state = {
        "authority": {
            "actor": "user:alice",
            "workspace": "tenant-a",
            "role": "operator",
            "versions": {
                "principal_sha256": "a" * 64,
                "role_permissions_sha256": "b" * 64,
                "budget_authority_sha256": "c" * 64,
            },
        },
        "runtime_budget": {
            "currency": "USD",
            "external_effect_cost": "unmeasured",
            "authority_sha256": "c" * 64,
        },
    }

    def runtime_authority(*, actor_hint=None):
        del actor_hint
        return (
            copy.deepcopy(state["authority"]),
            copy.deepcopy(state["runtime_budget"]),
            True,
        )

    monkeypatch.setattr(consent, "_runtime_approval_authority", runtime_authority)
    monkeypatch.setattr(
        consent,
        "require_consent",
        lambda *_args, **_kwargs: consent.ConsentDecision(
            True, "prompt", "high", time.time(), actor="user:reviewer",
        ),
    )
    return state


def _permit(
    state,
    *,
    action="test.write",
    scope="record:7",
    detail="Update the reviewed record.",
    provenance="test",
    **kwargs,
):
    return consent.require_operation_consent(
        action,
        risk="high",
        scope=scope,
        detail=detail,
        provenance=provenance,
        target=copy.deepcopy(state["target"]),
        parameters=copy.deepcopy(state["parameters"]),
        parameter_summary=["Set the committed value."],
        known_effects=["Changes one test record."],
        unresolved_assumptions=[],
        before="The record has its original value.",
        after="The record has the reviewed value.",
        irreversible=False,
        target_provider=lambda: copy.deepcopy(state["target"]),
        parameters_provider=lambda: copy.deepcopy(state["parameters"]),
        input_versions_provider=lambda: copy.deepcopy(state["inputs"]),
        credential_versions_provider=lambda: copy.deepcopy(state["credentials"]),
        budget_provider=lambda: copy.deepcopy(state["budget"]),
        **kwargs,
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda state, authority: state["target"].update({"id": 8}),
        lambda state, authority: state["parameters"].update({"value": "admin"}),
        lambda state, authority: state["inputs"].update({"revision": "r2"}),
        lambda state, authority: state["credentials"].update({"generation": "g2"}),
        lambda state, authority: state["budget"].update({"dollars": 11}),
        lambda state, authority: authority["authority"].update({"role": "viewer"}),
    ],
    ids=["target", "parameters", "inputs", "credentials", "budget", "actor-role"],
)
def test_permit_rejects_every_reviewed_dimension_drift(authority, mutate):
    state = {
        "target": {"id": 7},
        "parameters": {"value": "viewer"},
        "inputs": {"revision": "r1"},
        "credentials": {"generation": "g1"},
        "budget": {"dollars": 10},
    }
    permit = _permit(state)
    mutate(state, authority)

    with pytest.raises(ApprovalCardError, match="changed after approval"):
        with consent.consume_operation_consent(permit):
            pytest.fail("a stale permit reached the effect body")


def test_permit_is_single_use_and_carries_the_actual_decision(authority):
    state = {
        "target": {"id": 7},
        "parameters": {"value": "viewer"},
        "inputs": {"revision": "r1"},
        "credentials": {"generation": "g1"},
        "budget": {"dollars": 10},
    }
    permit = _permit(state)
    assert permit.decision.actor == "user:reviewer"
    with consent.consume_operation_consent(permit):
        pass
    with pytest.raises(ApprovalCardError, match="already consumed"):
        with consent.consume_operation_consent(permit):
            pass


def test_fresh_person_uses_exact_card_and_never_silent_consent(authority, monkeypatch):
    from maverick.approval_cards import digest

    state = {
        "target": {"task": 7, "tool": "write_file"},
        "parameters": {"path": "result.txt", "content": "approved text"},
        "inputs": {"revision": "r1"},
        "credentials": {"generation": "g1"},
        "budget": {"dollars": 10},
    }
    seen = []
    monkeypatch.setattr(consent, "require_consent", lambda *_a, **_kw: pytest.fail(
        "a fresh-person gate must not use silent consent"
    ))

    def person(_action, **kwargs):
        seen.append(kwargs)
        return consent.ConsentDecision(True, "dashboard", "high", time.time(), actor="user:reviewer")

    monkeypatch.setattr(consent, "require_person", person)
    permit = _permit(state, provenance="rehearsal", require_fresh_person=True)

    assert seen[0]["approval_card"]["parameters"]["sha256"] == digest(state["parameters"])
    assert seen[0]["provenance"] == "rehearsal"
    assert permit.decision.actor == "user:reviewer"
    with consent.consume_operation_consent(permit):
        pass


def test_expired_permit_cannot_reach_effect(authority):
    state = {
        "target": {"id": 7},
        "parameters": {"value": "viewer"},
        "inputs": {"revision": "r1"},
        "credentials": {"generation": "g1"},
        "budget": {"dollars": 10},
    }
    permit = _permit(state, ttl_seconds=0.01)
    time.sleep(0.03)

    with pytest.raises(ApprovalCardError, match="expired"):
        with consent.consume_operation_consent(permit):
            pytest.fail("an expired permit reached the effect body")


def test_bound_principal_must_be_present_at_consumption(monkeypatch, tmp_path):
    from maverick.connections import bind_principal

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        consent,
        "require_consent",
        lambda *_args, **_kwargs: consent.ConsentDecision(
            True, "prompt", "high", time.time(), actor="user:reviewer",
        ),
    )
    state = {
        "target": {"id": 7},
        "parameters": {"value": "viewer"},
        "inputs": {"revision": "r1"},
        "credentials": {"generation": "g1"},
        "budget": {"dollars": 10},
    }
    with bind_principal("user:alice"):
        permit = _permit(state)

    with pytest.raises(ApprovalCardError, match="actor is unavailable"):
        with consent.consume_operation_consent(permit):
            pytest.fail("a permit with a lost principal reached the effect body")


def test_bound_principal_must_match_at_consumption(monkeypatch, tmp_path):
    from maverick.connections import bind_principal

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        consent,
        "require_consent",
        lambda *_args, **_kwargs: consent.ConsentDecision(
            True, "prompt", "high", time.time(), actor="user:reviewer",
        ),
    )
    state = {
        "target": {"id": 7},
        "parameters": {"value": "viewer"},
        "inputs": {"revision": "r1"},
        "credentials": {"generation": "g1"},
        "budget": {"dollars": 10},
    }
    with bind_principal("user:alice"):
        permit = _permit(state)

    with bind_principal("user:bob"):
        with pytest.raises(ApprovalCardError, match="changed after approval"):
            with consent.consume_operation_consent(permit):
                pytest.fail("a permit used by another principal reached the effect body")


def test_principal_binding_and_authority_use_one_snapshot(monkeypatch, tmp_path):
    import maverick.connections as connections

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        consent,
        "require_consent",
        lambda *_args, **_kwargs: consent.ConsentDecision(
            True, "prompt", "high", time.time(), actor="user:reviewer",
        ),
    )
    principals = iter([None, "user:alice", None])
    monkeypatch.setattr(connections, "current_principal", lambda: next(principals))
    state = {
        "target": {"id": 7},
        "parameters": {"value": "viewer"},
        "inputs": {"revision": "r1"},
        "credentials": {"generation": "g1"},
        "budget": {"dollars": 10},
    }

    with pytest.raises(ApprovalCardError, match="changed after approval"):
        _permit(state)


def test_operation_consent_is_fresh_human_by_default(authority, monkeypatch):
    calls = []
    monkeypatch.setattr(
        consent,
        "require_consent",
        lambda *_args, **kwargs: (
            calls.append(kwargs)
            or consent.ConsentDecision(
                True, "prompt", "high", time.time(), actor="user:reviewer",
            )
        ),
    )
    state = {
        "target": {"id": 7},
        "parameters": {"value": "viewer"},
        "inputs": {"revision": "r1"},
        "credentials": {"generation": "g1"},
        "budget": {"dollars": 10},
    }

    _permit(state)

    assert calls[0]["allow_auto_approve"] is False
    assert calls[0]["consult_ledger"] is False


def test_operation_consent_redacts_every_visible_approval_label(
    authority, monkeypatch,
):
    calls = []

    def approve(action, **kwargs):
        calls.append((action, kwargs))
        return consent.ConsentDecision(
            True, "dashboard", "high", time.time(), actor="user:reviewer",
        )

    monkeypatch.setattr(consent, "require_consent", approve)
    token = "lw-rest-" + "Z" * 43
    state = {
        "target": {"id": 7},
        "parameters": {"value": "viewer"},
        "inputs": {"revision": "r1"},
        "credentials": {"generation": "g1"},
        "budget": {"dollars": 10},
    }

    permit = _permit(
        state,
        action=f"test.write.{token}",
        scope=f"record:7/{token}",
        detail=f"Update the reviewed record using {token}.",
        provenance=f"test:{token}",
    )

    visible = repr(calls) + repr(permit.card)
    assert token not in visible
    assert "REDACTED:lightwork_agent_token" in visible

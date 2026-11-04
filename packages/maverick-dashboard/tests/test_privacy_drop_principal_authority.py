from __future__ import annotations

from pathlib import Path

import pytest
from maverick.privacy_drop_management import DROPManagementConflict
from maverick_dashboard.privacy_drop_authority_proposals import (
    DROPAuthorityProposalStore,
)
from maverick_dashboard.privacy_drop_principal_authority import (
    DROPPrincipalKeyAuthority,
)

TENANT = "tenant-drop-keys"


def _authority(
    path: Path,
    *,
    dependencies: dict[int, int] | None = None,
) -> DROPPrincipalKeyAuthority:
    secrets = {
        "kms://drop/key-one": b"1" * 32,
        "kms://drop/key-two": b"2" * 32,
    }
    counts = dependencies if dependencies is not None else {}
    return DROPPrincipalKeyAuthority(
        path,
        tenant_id=TENANT,
        initial_key_ref="kms://drop/key-one",
        secret_resolver=lambda tenant, ref: secrets[ref] if tenant == TENANT else b"",
        dependency_counter=lambda revision: counts.get(revision, 0),
        config_gate=lambda: None,
        clock=lambda: 2_100_000_000.0,
    )


def test_rotation_keeps_previous_bindings_verifiable_without_exposing_key_material(
    tmp_path: Path,
) -> None:
    authority = _authority(tmp_path / "drop-keys.sqlite3")
    original = authority.bind(TENANT, "principal-one")

    rotated = authority.rotate(
        new_key_ref="kms://drop/key-two",
        expected_current_revision=1,
        actor_ref="key-operator",
        reviewer_ref="key-reviewer",
        idempotency_key="rotate-to-key-two",
    )
    current = authority.bind(TENANT, "principal-one")

    assert rotated.revision == 2
    assert current.key_revision == 2
    assert current.binding_sha256 != original.binding_sha256
    assert authority.verify(
        TENANT,
        "principal-one",
        original.key_revision,
        original.binding_sha256,
    ) is True
    assert authority.verify(TENANT, "principal-one", 999, original.binding_sha256) is False
    serialized = (tmp_path / "drop-keys.sqlite3").read_bytes()
    assert b"11111111111111111111111111111111" not in serialized
    assert b"22222222222222222222222222222222" not in serialized
    assert authority.verify_integrity() is True


def test_retirement_is_blocked_until_retained_dependencies_are_gone(
    tmp_path: Path,
) -> None:
    dependencies = {1: 3}
    authority = _authority(tmp_path / "drop-keys.sqlite3", dependencies=dependencies)
    authority.rotate(
        new_key_ref="kms://drop/key-two",
        expected_current_revision=1,
        actor_ref="key-operator",
        reviewer_ref="key-reviewer",
        idempotency_key="rotate-to-key-two",
    )

    with pytest.raises(DROPManagementConflict, match="retained DROP records"):
        authority.retire(
            1,
            expected_state="previous",
            actor_ref="key-operator",
            reviewer_ref="key-reviewer",
            idempotency_key="retire-key-one",
        )

    dependencies[1] = 0
    retired = authority.retire(
        1,
        expected_state="previous",
        actor_ref="key-operator",
        reviewer_ref="key-reviewer",
        idempotency_key="retire-key-one",
    )
    assert retired.state == "retired"
    assert authority.verify(TENANT, "principal-one", 1, "0" * 64) is False


def test_same_person_cannot_approve_rotation(tmp_path: Path) -> None:
    authority = _authority(tmp_path / "drop-keys.sqlite3")

    with pytest.raises(DROPManagementConflict, match="independent"):
        authority.rotate(
            new_key_ref="kms://drop/key-two",
            expected_current_revision=1,
            actor_ref="same-person",
            reviewer_ref="same-person",
            idempotency_key="same-person-rotation",
        )


def test_expired_proposal_dependencies_are_purged_only_by_maintenance(
    tmp_path: Path,
) -> None:
    now = [2_100_000_000.0]
    authority = DROPPrincipalKeyAuthority(
        tmp_path / "drop-keys.sqlite3",
        tenant_id=TENANT,
        initial_key_ref="kms://drop/key-one",
        secret_resolver=lambda tenant, ref: b"1" * 32,
        dependency_counter=lambda _revision: 0,
        config_gate=lambda: None,
        clock=lambda: now[0],
    )
    proposals = DROPAuthorityProposalStore(
        tmp_path / "drop-proposals.sqlite3",
        tenant_id=TENANT,
        principal_binding_resolver=authority.bind,
        principal_binding_verifier=authority.verify,
        retention_seconds=3_600,
        maintenance_authorizer=lambda: True,
        config_gate=lambda: None,
        clock=lambda: now[0],
    )
    proposals.propose(
        kind="rotate_key",
        payload={"new_key_ref": "kms://drop/key-two", "expected_current_revision": 1},
        proposer_ref="key-operator",
        idempotency_key="rotate-proposal",
    )
    assert proposals.retained_key_revision_counts() == {1: 1}

    now[0] += 3_601
    assert proposals.purge_expired(limit=10) == 1
    assert proposals.list_proposals() == ()
    assert proposals.retained_key_revision_counts() == {}
    assert proposals.verify_integrity() is True

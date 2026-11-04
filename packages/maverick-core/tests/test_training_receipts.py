from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from unittest.mock import patch

import pytest
from maverick.paths import tenant_scope
from maverick.training import receipts as tr

ed25519 = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    reason="cryptography required for signed training receipts",
)
from cryptography.hazmat.primitives import serialization  # noqa: E402, I001


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _keypair():
    private = ed25519.Ed25519PrivateKey.generate()
    public_hex = (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )
    key_id = hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:16]
    return private, public_hex, key_id


def _evidence(*, tenant_id: str = "alpha") -> tr.TrainingRunEvidence:
    return tr.TrainingRunEvidence(
        run_id="privacy-scorer-run-0001",
        tenant_id=tenant_id,
        started_at="2026-07-23T11:00:00Z",
        completed_at="2026-07-23T12:00:00Z",
        dataset_sha256=_digest("dataset"),
        environment_id="privacy-assessment",
        environment_version="1.0.0",
        environment_sha256=_digest("environment"),
        data_boundary=tr.DataBoundaryEvidence(
            data_scope="tenant_private",
            consent_scope="tenant_training",
            consent_record_id="consent-2026-0001",
            consent_evidence_sha256=_digest("consent"),
            boundary_policy_sha256=_digest("boundary-policy"),
            redaction_evidence_sha256=_digest("redaction-evidence"),
            retention_policy_sha256=_digest("retention-policy"),
        ),
        base_model=tr.BaseModelEvidence(
            model_id="Qwen/Qwen3.5-9B",
            revision=_digest("base-model")[:40],
            license_id="Apache-2.0",
            license_evidence_sha256=_digest("license"),
            artifact_sha256=_digest("base-model-artifact"),
            tokenizer_sha256=_digest("base-model-tokenizer"),
            artifact_format="safetensors",
            artifact_manifest_sha256=_digest("base-model-artifact-manifest"),
        ),
        training=tr.TrainingBackendEvidence(
            backend="prime-rl",
            backend_version="0.3.1",
            algorithm="dpo-lora",
            algorithm_version="1.0.0",
            hyperparameters={
                "batch_size": 16,
                "learning_rate": 0.00002,
                "lora_rank": 16,
                "optimizer": "adamw",
                "target_modules": ["q_proj", "v_proj"],
            },
            source_revision=_digest("training-source")[:40],
            dependency_lock_sha256=_digest("dependency-lock"),
            container_image_sha256=_digest("container-image"),
            hardware_profile_sha256=_digest("hardware-profile"),
            egress_policy_sha256=_digest("egress-policy"),
            config_sha256=_digest("training-config"),
            log_sha256=_digest("training-log"),
            final_checkpoint_sha256=_digest("final-training-checkpoint"),
            deterministic_seed=20260723,
        ),
        adapter=tr.AdapterEvidence(
            adapter_id="privacy-scorer-v1",
            artifact_format="safetensors",
            artifact_sha256=_digest("adapter"),
            runtime_compatibility_sha256=_digest("adapter-runtime-compatibility"),
            checkpoint_sha256=_digest("adapter-checkpoint"),
        ),
        evaluation=tr.EvaluationEvidence(
            protocol_sha256=_digest("evaluation-protocol"),
            run_sha256=_digest("evaluation-run"),
            sealed_holdout_sha256=_digest("sealed-holdout"),
            qualification_evidence_sha256=_digest("qualification-evidence"),
            qualification_policy_sha256=_digest("qualification-policy"),
            baseline_metrics={
                "citation_precision": 0.91,
                "schema_pass_rate": 0.94,
            },
            candidate_metrics={
                "citation_precision": 0.97,
                "schema_pass_rate": 0.99,
            },
            holdout_metrics={
                "citation_precision": 0.95,
                "schema_pass_rate": 0.98,
            },
        ),
    )


def _approval(
    evidence: tr.TrainingRunEvidence,
    private,
    key_id: str,
) -> tr.HumanApprovalEvidence:
    request = tr.approval_request(evidence)
    approver_id = "human:assurance-officer"
    decision = "approved"
    approved_at = "2026-07-23T12:30:00Z"
    return tr.HumanApprovalEvidence(
        approver_id=approver_id,
        approver_key_id=key_id,
        decision=decision,
        approved_at=approved_at,
        subject_sha256=request.subject_sha256,
        signature=private.sign(
            request.message(
                approver_id=approver_id,
                approver_key_id=key_id,
                decision=decision,
                approved_at=approved_at,
            ),
        ).hex(),
    )


def _issue():
    approver_private, approver_public, approver_key_id = _keypair()
    evidence = _evidence()
    approval = _approval(evidence, approver_private, approver_key_id)
    with patch.object(
        tr,
        "_server_training_approver_registry",
        return_value={approver_key_id: approver_public},
    ):
        issued = tr.issue_training_receipt(evidence, approval)
    receipt_key_id = issued.receipt["key_id"]
    return issued, {
        "receipt": {receipt_key_id: issued.signing_public_key},
        "approval": {approver_key_id: approver_public},
    }


def test_issues_complete_tenant_private_receipt_and_verifies():
    with tenant_scope(tenant="alpha"):
        issued, trust = _issue()
        receipt = issued.receipt

        assert receipt["schema"] == "lightwork.training-receipt.v2"
        assert tr.APPROVAL_MESSAGE_VERSION == "lightwork-training-approval-v2"
        assert tr.verify_training_receipt(
            receipt,
            trusted_receipt_pubkeys=trust["receipt"],
            trusted_approver_pubkeys=trust["approval"],
        )
        assert tr.read_training_receipt(receipt["receipt_id"]) == receipt
        assert "tenants" in str(tr.receipts_path())
        assert receipt["evidence"]["dataset_sha256"] == _digest("dataset")
        assert receipt["evidence"]["environment_sha256"] == _digest("environment")
        assert receipt["evidence"]["data_boundary"]["redaction_evidence_sha256"] == _digest(
            "redaction-evidence"
        )
        assert receipt["evidence"]["data_boundary"]["retention_policy_sha256"] == _digest(
            "retention-policy"
        )
        assert receipt["evidence"]["base_model"] == {
            "model_id": "Qwen/Qwen3.5-9B",
            "revision": _digest("base-model")[:40],
            "license_id": "Apache-2.0",
            "license_evidence_sha256": _digest("license"),
            "artifact_sha256": _digest("base-model-artifact"),
            "tokenizer_sha256": _digest("base-model-tokenizer"),
            "artifact_format": "safetensors",
            "artifact_manifest_sha256": _digest("base-model-artifact-manifest"),
        }
        assert receipt["evidence"]["training"]["source_revision"] == _digest("training-source")[:40]
        assert receipt["evidence"]["training"]["dependency_lock_sha256"] == _digest(
            "dependency-lock"
        )
        assert receipt["evidence"]["training"]["container_image_sha256"] == _digest(
            "container-image"
        )
        assert receipt["evidence"]["training"]["hardware_profile_sha256"] == _digest(
            "hardware-profile"
        )
        assert receipt["evidence"]["training"]["egress_policy_sha256"] == _digest("egress-policy")
        assert receipt["evidence"]["training"]["config_sha256"] == _digest(
            "training-config",
        )
        assert receipt["evidence"]["training"]["log_sha256"] == _digest(
            "training-log",
        )
        assert receipt["evidence"]["training"]["final_checkpoint_sha256"] == _digest(
            "final-training-checkpoint"
        )
        assert receipt["evidence"]["training"]["deterministic_seed"] == 20260723
        assert receipt["evidence"]["adapter"]["artifact_sha256"] == _digest("adapter")
        assert receipt["evidence"]["adapter"]["runtime_compatibility_sha256"] == _digest(
            "adapter-runtime-compatibility"
        )
        assert receipt["evidence"]["adapter"]["checkpoint_sha256"] == _digest(
            "adapter-checkpoint",
        )
        assert set(receipt["evidence"]["evaluation"]) == {
                "protocol_sha256",
                "run_sha256",
                "sealed_holdout_sha256",
                "qualification_evidence_sha256",
                "qualification_policy_sha256",
                "baseline_metrics",
            "candidate_metrics",
            "holdout_metrics",
        }
        assert receipt["evidence"]["evaluation"]["run_sha256"] == _digest(
            "evaluation-run",
        )
        assert receipt["evidence"]["evaluation"]["sealed_holdout_sha256"] == _digest(
            "sealed-holdout"
        )
        assert receipt["approval"]["decision"] == "approved"
        assert "public_key" not in receipt
        assert "public_key" not in receipt["approval"]


def test_tampering_with_evidence_or_signature_is_rejected():
    with tenant_scope(tenant="alpha"):
        issued, trust = _issue()
        changed = copy.deepcopy(issued.receipt)
        changed["evidence"]["evaluation"]["holdout_metrics"]["schema_pass_rate"] = 1.0
        assert not tr.verify_training_receipt(
            changed,
            trusted_receipt_pubkeys=trust["receipt"],
            trusted_approver_pubkeys=trust["approval"],
        )

        changed = copy.deepcopy(issued.receipt)
        changed["evidence"]["base_model"]["artifact_sha256"] = _digest("swapped")
        assert not tr.verify_training_receipt(
            changed,
            trusted_receipt_pubkeys=trust["receipt"],
            trusted_approver_pubkeys=trust["approval"],
        )

        changed = copy.deepcopy(issued.receipt)
        changed["sig"] = "00" * 64
        assert not tr.verify_training_receipt(
            changed,
            trusted_receipt_pubkeys=trust["receipt"],
            trusted_approver_pubkeys=trust["approval"],
        )


@pytest.mark.parametrize(
    "path",
    [
        ("data_boundary", "redaction_evidence_sha256"),
        ("base_model", "artifact_manifest_sha256"),
        ("training", "dependency_lock_sha256"),
        ("adapter", "runtime_compatibility_sha256"),
        ("evaluation", "sealed_holdout_sha256"),
    ],
)
def test_verification_fails_closed_when_reproducibility_evidence_is_missing(path):
    with tenant_scope(tenant="alpha"):
        issued, trust = _issue()
        changed = copy.deepcopy(issued.receipt)
        del changed["evidence"][path[0]][path[1]]
        assert not tr.verify_training_receipt(
            changed,
            trusted_receipt_pubkeys=trust["receipt"],
            trusted_approver_pubkeys=trust["approval"],
        )


def test_self_disclosed_and_untrusted_keys_never_establish_trust():
    with tenant_scope(tenant="alpha"):
        issued, trust = _issue()
        receipt = issued.receipt
        assert not tr.verify_training_receipt(
            receipt,
            trusted_receipt_pubkeys={},
            trusted_approver_pubkeys=trust["approval"],
        )
        assert not tr.verify_training_receipt(
            receipt,
            trusted_receipt_pubkeys=trust["receipt"],
            trusted_approver_pubkeys={},
        )

        self_disclosed = copy.deepcopy(receipt)
        self_disclosed["public_key"] = issued.signing_public_key
        assert not tr.verify_training_receipt(
            self_disclosed,
            trusted_receipt_pubkeys={},
            trusted_approver_pubkeys=trust["approval"],
        )
        assert not tr.verify_training_receipt(
            self_disclosed,
            trusted_receipt_pubkeys=trust["receipt"],
            trusted_approver_pubkeys=trust["approval"],
        )

        nested_key = copy.deepcopy(receipt)
        nested_key["evidence"]["base_model"]["public_key"] = issued.signing_public_key
        assert not tr.verify_training_receipt(
            nested_key,
            trusted_receipt_pubkeys=trust["receipt"],
            trusted_approver_pubkeys=trust["approval"],
        )

        _wrong_private, wrong_public, _wrong_key_id = _keypair()
        assert not tr.verify_training_receipt(
            receipt,
            trusted_receipt_pubkeys={receipt["key_id"]: wrong_public},
            trusted_approver_pubkeys=trust["approval"],
        )


def test_tenant_isolation_blocks_cross_tenant_read_and_verification():
    with tenant_scope(tenant="alpha"):
        issued, trust = _issue()
        receipt_id = issued.receipt["receipt_id"]
        assert tr.verify_training_receipt(
            issued.receipt,
            trusted_receipt_pubkeys=trust["receipt"],
            trusted_approver_pubkeys=trust["approval"],
        )

    assert tr.verify_training_receipt(
        issued.receipt,
        trusted_receipt_pubkeys=trust["receipt"],
        trusted_approver_pubkeys=trust["approval"],
        expected_tenant_id="alpha",
    )
    with tenant_scope(tenant="beta"):
        with pytest.raises(tr.TrainingReceiptError, match="could not be recovered"):
            tr.read_training_receipt(receipt_id)
        assert not tr.verify_training_receipt(
            issued.receipt,
            trusted_receipt_pubkeys=trust["receipt"],
            trusted_approver_pubkeys=trust["approval"],
        )
        assert not tr.verify_training_receipt(
            issued.receipt,
            trusted_receipt_pubkeys=trust["receipt"],
            trusted_approver_pubkeys=trust["approval"],
            expected_tenant_id="alpha",
        )


def test_issuance_refuses_an_unscoped_shared_store():
    private, public, key_id = _keypair()
    evidence = _evidence()
    approval = _approval(evidence, private, key_id)
    with pytest.raises(tr.TrainingReceiptError, match="explicit tenant"):
        with patch.object(
            tr,
            "_server_training_approver_registry",
            return_value={key_id: public},
        ):
            tr.issue_training_receipt(evidence, approval)


def test_human_approval_is_bound_to_run_and_requires_external_trust():
    trusted_private, trusted_public, trusted_key_id = _keypair()
    untrusted_private, _untrusted_public, untrusted_key_id = _keypair()
    evidence = _evidence()
    untrusted = _approval(evidence, untrusted_private, untrusted_key_id)

    with tenant_scope(tenant="alpha"):
        with pytest.raises(ValueError, match="trusted approver"):
            with patch.object(
                tr,
                "_server_training_approver_registry",
                return_value={trusted_key_id: trusted_public},
            ):
                tr.issue_training_receipt(evidence, untrusted)

        trusted = _approval(evidence, trusted_private, trusted_key_id)
        relabeled = replace(trusted, approver_id="human:different-officer")
        with pytest.raises(ValueError, match="trusted approver"):
            with patch.object(
                tr,
                "_server_training_approver_registry",
                return_value={trusted_key_id: trusted_public},
            ):
                tr.issue_training_receipt(evidence, relabeled)

        swapped = replace(evidence, dataset_sha256=_digest("different-dataset"))
        with pytest.raises(ValueError, match="not bound"):
            with patch.object(
                tr,
                "_server_training_approver_registry",
                return_value={trusted_key_id: trusted_public},
            ):
                tr.issue_training_receipt(swapped, trusted)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda evidence: replace(
                evidence,
                base_model=replace(evidence.base_model, revision="main"),
            ),
            "immutable",
        ),
        (
            lambda evidence: replace(
                evidence,
                data_boundary=replace(evidence.data_boundary, cross_tenant_data=True),
            ),
            "cross-tenant",
        ),
        (
            lambda evidence: replace(
                evidence,
                data_boundary=replace(evidence.data_boundary, hosted_training=True),
            ),
            "hosted_training consent",
        ),
        (
            lambda evidence: replace(
                evidence,
                data_boundary=replace(
                    evidence.data_boundary,
                    raw_training_data_exported=True,
                ),
            ),
            "raw training-data export",
        ),
        (
            lambda evidence: replace(
                evidence,
                training=replace(
                    evidence.training,
                    hyperparameters={"system_prompt": "secret"},
                ),
            ),
            "raw prompts",
        ),
    ],
)
def test_refuses_mutable_or_content_bearing_evidence(mutate, message):
    with pytest.raises(ValueError, match=message):
        tr.approval_request(mutate(_evidence()))


@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    [
        (
            "data_boundary",
            "redaction_evidence_sha256",
            _digest("different-redaction-evidence"),
        ),
        (
            "data_boundary",
            "retention_policy_sha256",
            _digest("different-retention-policy"),
        ),
        ("base_model", "tokenizer_sha256", _digest("different-tokenizer")),
        ("base_model", "artifact_format", "gguf"),
        (
            "base_model",
            "artifact_manifest_sha256",
            _digest("different-base-manifest"),
        ),
        (
            "training",
            "source_revision",
            _digest("different-training-source")[:40],
        ),
        (
            "training",
            "dependency_lock_sha256",
            _digest("different-dependency-lock"),
        ),
        (
            "training",
            "container_image_sha256",
            _digest("different-container-image"),
        ),
        (
            "training",
            "hardware_profile_sha256",
            _digest("different-hardware-profile"),
        ),
        (
            "training",
            "egress_policy_sha256",
            _digest("different-egress-policy"),
        ),
        ("training", "config_sha256", _digest("different-training-config")),
        ("training", "log_sha256", _digest("different-training-log")),
        (
            "training",
            "final_checkpoint_sha256",
            _digest("different-final-checkpoint"),
        ),
        ("training", "deterministic_seed", 7),
        (
            "adapter",
            "runtime_compatibility_sha256",
            _digest("different-runtime-compatibility"),
        ),
        ("adapter", "checkpoint_sha256", _digest("different-adapter-checkpoint")),
        ("evaluation", "run_sha256", _digest("different-evaluation-run")),
        (
            "evaluation",
            "sealed_holdout_sha256",
            _digest("different-sealed-holdout"),
        ),
    ],
)
def test_reproducibility_evidence_is_bound_by_approval_and_public_commitment(
    section,
    field,
    replacement,
):
    original = _evidence()
    changed = replace(
        original,
        **{
            section: replace(
                getattr(original, section),
                **{field: replacement},
            ),
        },
    )
    original_request = tr.approval_request(original)
    changed_request = tr.approval_request(changed)
    assert changed_request.subject_sha256 != original_request.subject_sha256

    private, public, key_id = _keypair()
    approval = _approval(changed, private, key_id)
    with tenant_scope(tenant="alpha"):
        with patch.object(
            tr,
            "_server_training_approver_registry",
            return_value={key_id: public},
        ):
            issued = tr.issue_training_receipt(changed, approval)
    assert issued.receipt["evidence"][section][field] == replacement
    assert issued.public_commitment["approval_subject_sha256"] == changed_request.subject_sha256
    assert (
        issued.public_commitment["receipt_payload_sha256"]
        == issued.receipt["receipt_payload_sha256"]
    )


@pytest.mark.parametrize(
    ("section", "field", "invalid", "message"),
    [
        (
            "data_boundary",
            "redaction_evidence_sha256",
            "not-a-digest",
            "redaction_evidence_sha256",
        ),
        (
            "data_boundary",
            "retention_policy_sha256",
            "not-a-digest",
            "retention_policy_sha256",
        ),
        (
            "base_model",
            "tokenizer_sha256",
            "not-a-digest",
            "tokenizer_sha256",
        ),
        (
            "base_model",
            "artifact_format",
            "raw format",
            "artifact_format",
        ),
        (
            "base_model",
            "artifact_manifest_sha256",
            "not-a-digest",
            "artifact_manifest_sha256",
        ),
        (
            "training",
            "source_revision",
            "main",
            "source_revision",
        ),
        (
            "training",
            "dependency_lock_sha256",
            "not-a-digest",
            "dependency_lock_sha256",
        ),
        (
            "training",
            "container_image_sha256",
            "not-a-digest",
            "container_image_sha256",
        ),
        (
            "training",
            "hardware_profile_sha256",
            "not-a-digest",
            "hardware_profile_sha256",
        ),
        (
            "training",
            "egress_policy_sha256",
            "not-a-digest",
            "egress_policy_sha256",
        ),
        ("training", "config_sha256", "not-a-digest", "config_sha256"),
        ("training", "log_sha256", "not-a-digest", "log_sha256"),
        (
            "training",
            "final_checkpoint_sha256",
            "not-a-digest",
            "final_checkpoint_sha256",
        ),
        (
            "training",
            "deterministic_seed",
            True,
            "must be an integer",
        ),
        (
            "training",
            "deterministic_seed",
            1.5,
            "must be an integer",
        ),
        (
            "training",
            "deterministic_seed",
            -1,
            "between 0 and 2\\^63 - 1",
        ),
        (
            "training",
            "deterministic_seed",
            2**63,
            "between 0 and 2\\^63 - 1",
        ),
        (
            "adapter",
            "runtime_compatibility_sha256",
            "not-a-digest",
            "runtime_compatibility_sha256",
        ),
        (
            "adapter",
            "checkpoint_sha256",
            "not-a-digest",
            "checkpoint_sha256",
        ),
        (
            "evaluation",
            "run_sha256",
            "not-a-digest",
            "run_sha256",
        ),
        (
            "evaluation",
            "sealed_holdout_sha256",
            "not-a-digest",
            "sealed_holdout_sha256",
        ),
    ],
)
def test_reproducibility_evidence_requires_exact_content_free_values(
    section,
    field,
    invalid,
    message,
):
    evidence = _evidence()
    malformed = replace(
        evidence,
        **{
            section: replace(
                getattr(evidence, section),
                **{field: invalid},
            ),
        },
    )
    with pytest.raises(ValueError, match=message):
        tr.approval_request(malformed)


def test_receipt_never_contains_raw_prompts_outputs_or_examples():
    secret = "DO-NOT-PERSIST-RAW-INTERACTION"
    evidence = _evidence()
    private, public, key_id = _keypair()
    approval = _approval(evidence, private, key_id)
    with tenant_scope(tenant="alpha"):
        with patch.object(
            tr,
            "_server_training_approver_registry",
            return_value={key_id: public},
        ):
            issued = tr.issue_training_receipt(evidence, approval)
    serialized = json.dumps(issued.receipt)
    assert secret not in serialized
    assert public not in serialized
    assert issued.signing_public_key not in serialized
    forbidden = {
        "prompt",
        "output",
        "completion",
        "transcript",
        "example",
        "public_key",
        "signing_public_key",
    }

    def walk(value):
        if isinstance(value, dict):
            for key, item in value.items():
                assert key.lower() not in forbidden
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(issued.receipt)


def test_verified_read_proves_membership_in_the_complete_receipt_chain():
    with tenant_scope(tenant="alpha"):
        first, first_trust = _issue()
        second, second_trust = _issue()
        receipt_trust = {
            **first_trust["receipt"],
            **second_trust["receipt"],
        }
        approver_trust = {
            **first_trust["approval"],
            **second_trust["approval"],
        }

        selected = tr.read_verified_training_receipt(
            second.receipt["receipt_id"],
            trusted_receipt_pubkeys=receipt_trust,
            trusted_approver_pubkeys=approver_trust,
        )

        assert selected == second.receipt
        assert first.receipt["hash"] == second.receipt["prev_hash"]


def test_server_training_trust_uses_only_protected_global_registries(
    monkeypatch,
):
    from maverick import approval_signing
    from maverick.audit import signing

    _private, receipt_public, receipt_key_id = _keypair()
    _private, approver_public, approver_key_id = _keypair()
    monkeypatch.setattr(
        signing,
        "trusted_audit_public_keys",
        lambda: {receipt_key_id: receipt_public},
    )
    monkeypatch.setattr(
        approval_signing,
        "trusted_global_approver_keys",
        lambda: [approver_public],
    )

    assert tr.server_training_trust_registries() == (
        {receipt_key_id: receipt_public},
        {approver_key_id: approver_public},
    )


def test_server_training_trust_fails_closed_when_a_registry_is_empty(
    monkeypatch,
):
    from maverick import approval_signing
    from maverick.audit import signing

    monkeypatch.setattr(signing, "trusted_audit_public_keys", dict)
    monkeypatch.setattr(
        approval_signing,
        "trusted_global_approver_keys",
        list,
    )

    with pytest.raises(tr.TrainingReceiptError, match="registry is empty"):
        tr.server_training_trust_registries()


@pytest.mark.parametrize("tamper", ["change_earlier_row", "drop_genesis"])
def test_verified_read_refuses_a_valid_row_detached_from_its_chain(tamper):
    with tenant_scope(tenant="alpha"):
        _first, first_trust = _issue()
        second, second_trust = _issue()
        receipt_trust = {
            **first_trust["receipt"],
            **second_trust["receipt"],
        }
        approver_trust = {
            **first_trust["approval"],
            **second_trust["approval"],
        }
        path = tr.receipts_path()
        lines = path.read_text(encoding="utf-8").splitlines()
        if tamper == "change_earlier_row":
            earlier = json.loads(lines[0])
            earlier["evidence"]["dataset_sha256"] = _digest("forged-earlier")
            lines[0] = json.dumps(earlier, sort_keys=True)
        else:
            lines = lines[1:]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        with pytest.raises(tr.TrainingReceiptError, match="chain"):
            tr.read_verified_training_receipt(
                second.receipt["receipt_id"],
                trusted_receipt_pubkeys=receipt_trust,
                trusted_approver_pubkeys=approver_trust,
            )


def test_public_commitment_is_verified_and_disclosure_minimal():
    with tenant_scope(tenant="alpha"):
        issued, trust = _issue()
        commitment = tr.public_transparency_commitment(
            issued.receipt,
            trusted_receipt_pubkeys=trust["receipt"],
            trusted_approver_pubkeys=trust["approval"],
        )
        assert commitment == issued.public_commitment
        assert commitment["schema"] == "lightwork.training-transparency-commitment.v1"
        assert set(commitment) == {
            "schema",
            "dataset_sha256",
            "environment_sha256",
            "base_model_artifact_sha256",
            "adapter_sha256",
            "approval_subject_sha256",
            "receipt_payload_sha256",
            "event_hash",
            "key_id",
        }
        public_json = json.dumps(commitment)
        for private_value in (
            "alpha",
            "Qwen/Qwen3.5-9B",
            "privacy-scorer-run-0001",
            "human:assurance-officer",
            "citation_precision",
            _digest("redaction-evidence"),
            _digest("retention-policy"),
            _digest("base-model-tokenizer"),
            _digest("base-model-artifact-manifest"),
            _digest("dependency-lock"),
            _digest("container-image"),
            _digest("hardware-profile"),
            _digest("egress-policy"),
            _digest("training-config"),
            _digest("training-log"),
            _digest("final-training-checkpoint"),
            _digest("adapter-runtime-compatibility"),
            _digest("adapter-checkpoint"),
            _digest("evaluation-run"),
            _digest("sealed-holdout"),
        ):
            assert private_value not in public_json

        changed = copy.deepcopy(issued.receipt)
        changed["evidence"]["dataset_sha256"] = _digest("forged")
        with pytest.raises(ValueError, match="unverified"):
            tr.public_transparency_commitment(
                changed,
                trusted_receipt_pubkeys=trust["receipt"],
                trusted_approver_pubkeys=trust["approval"],
            )

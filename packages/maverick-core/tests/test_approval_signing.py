"""Cryptographic approval gate for high-blast-radius self-changes.

The governed ladder gates ``code``/``weights`` behind a human. A self-settable
boolean is not a real control for a self-modifying agent, so these tests pin
that (a) a valid Ed25519 signature over (candidate, rung, payload) authorises,
(b) the signature is bound to the payload (an approval can't be replayed onto a
swapped one), and (c) forgery or absence fails closed.
"""
from __future__ import annotations

import os

import pytest
from maverick import approval_signing as ap
from maverick import self_improvement as si

ed25519 = pytest.importorskip(
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    reason="cryptography required for approval signing",
)
from cryptography.hazmat.primitives import serialization  # noqa: E402


def _keypair():
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ).hex()
    pub_hex = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    return priv_hex, pub_hex


def _candidate(**kw):
    base = dict(rung="code", summary="s", baseline_score=0.5, candidate_score=0.9,
                samples=20, payload={"diff": "x"}, capability_widens=False,
                rollback="snap-1")
    base.update(kw)
    return si.Candidate(**base)


class TestSignVerify:
    def test_valid_signature_identifies_approver(self):
        priv, pub = _keypair()
        cand = _candidate()
        req = ap.ApprovalRequest.for_candidate(cand)
        sig = ap.sign_request(req, priv)
        assert ap.verify(req, sig, [pub]) == ap.key_id(pub)

    def test_wrong_key_does_not_verify(self):
        priv, _pub = _keypair()
        _priv2, pub2 = _keypair()
        req = ap.ApprovalRequest.for_candidate(_candidate())
        sig = ap.sign_request(req, priv)
        assert ap.verify(req, sig, [pub2]) is None

    def test_signature_bound_to_payload_toctou(self):
        # Approve a benign payload, then swap the payload: signature must break.
        priv, pub = _keypair()
        benign = _candidate(payload={"diff": "benign"})
        sig = ap.sign_request(ap.ApprovalRequest.for_candidate(benign), priv)
        malicious = _candidate(id=benign.id, payload={"diff": "rm -rf /"})
        req_mal = ap.ApprovalRequest.for_candidate(malicious)
        assert ap.verify(req_mal, sig, [pub]) is None

    def test_signature_bound_to_rung(self):
        priv, pub = _keypair()
        cand = _candidate(rung="code")
        sig = ap.sign_request(ap.ApprovalRequest.for_candidate(cand), priv)
        weights = _candidate(id=cand.id, rung="weights", payload=cand.payload)
        assert ap.verify(ap.ApprovalRequest.for_candidate(weights), sig, [pub]) is None

    def test_empty_signature_is_none(self):
        _priv, pub = _keypair()
        assert ap.verify(ap.ApprovalRequest.for_candidate(_candidate()), "", [pub]) is None

    def test_self_reported_digest_cannot_override_the_real_payload(self):
        # Regression for the substitution attack: the request digest is bound to
        # the ACTUAL payload, never to the self-settable payload_sha256 field. A
        # candidate that carries a digest for some OTHER payload must still be
        # signed over its own payload's digest -- the stale field is ignored.
        other = ap.payload_digest({"canonical": "form"})
        cand = _candidate(payload={"anything": 1}, payload_sha256=other)
        req = ap.ApprovalRequest.for_candidate(cand)
        assert req.payload_sha256 == ap.payload_digest({"anything": 1})
        assert req.payload_sha256 != other

    def test_swapped_payload_cannot_inherit_prior_signature(self):
        # The exact TOCTOU/substitution the module exists to prevent: an approver
        # signs a BENIGN candidate; an agent then swaps in a malicious payload but
        # KEEPS the benign payload_sha256 and the benign signature, hoping the
        # gate binds to the (unchanged) self-reported digest. It must not verify.
        priv, pub = _keypair()
        benign = _candidate(payload={"diff": "benign"})
        benign_digest = ap.payload_digest(benign.payload)
        sig = ap.sign_request(ap.ApprovalRequest.for_candidate(benign), priv)
        # Attacker keeps benign id + benign digest + benign signature, swaps payload.
        swapped = _candidate(id=benign.id, payload={"diff": "rm -rf /"},
                             payload_sha256=benign_digest)
        swapped.approval_signature = sig
        assert ap.verify_candidate(swapped) is None          # refused
        # And the request it builds is bound to the malicious bytes, not the digest.
        assert ap.ApprovalRequest.for_candidate(swapped).payload_sha256 != benign_digest

    def test_string_payload_digest_matches_raw_sha256(self):
        # payload_digest of a str/bytes payload hashes the raw bytes, so it equals
        # the sha256(patch.encode()) the creation sites record --
        # keeping sign, ledger, and the independent auditor consistent.
        import hashlib
        patch = "diff --git a/x b/x\n-old\n+new\n"
        assert ap.payload_digest(patch) == hashlib.sha256(patch.encode()).hexdigest()
        assert ap.payload_digest(patch.encode()) == hashlib.sha256(patch.encode()).hexdigest()


class TestEnforcement:
    def test_global_trust_roots_ignore_tenant_merged_configuration(
        self,
        monkeypatch,
    ):
        from maverick import config

        _priv, global_pub = _keypair()
        _priv, tenant_pub = _keypair()
        monkeypatch.setattr("maverick._STARTUP_APPROVER_KEYS", global_pub)
        monkeypatch.delenv("MAVERICK_APPROVER_KEYS_DIR", raising=False)
        monkeypatch.setattr(
            config,
            "load_global_config",
            lambda: {"self_improvement": {"approver_keys": [global_pub]}},
        )
        monkeypatch.setattr(
            config,
            "load_config",
            lambda: {"self_improvement": {"approver_keys": [tenant_pub]}},
        )
        monkeypatch.setattr(config, "config_source_errors", dict)

        assert ap.trusted_global_approver_keys() == [global_pub]

        # A same-uid writer can alter either config layer, but cannot add a
        # trusted key without changing the supervisor's startup environment.
        monkeypatch.setattr("maverick._STARTUP_APPROVER_KEYS", "")
        assert ap.trusted_global_approver_keys() == []
        monkeypatch.setattr(ap, "_config_approval", lambda: {"approver_keys": [tenant_pub]})
        assert ap.trusted_approver_keys() == []

    def test_global_trust_roots_reject_malformed_keys(self, monkeypatch):
        from maverick import config

        monkeypatch.delenv("MAVERICK_APPROVER_KEYS", raising=False)
        monkeypatch.delenv("MAVERICK_APPROVER_KEYS_DIR", raising=False)
        monkeypatch.setattr(
            config,
            "load_global_config",
            lambda: {"self_improvement": {"approver_keys": ["not-a-key"]}},
        )
        monkeypatch.setattr(config, "config_source_errors", dict)

        with pytest.raises(RuntimeError, match="malformed key"):
            ap.trusted_global_approver_keys()

    def test_signatures_required_without_keys(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_APPROVER_KEYS", raising=False)
        monkeypatch.delenv("MAVERICK_APPROVER_KEYS_DIR", raising=False)
        monkeypatch.delenv("MAVERICK_REQUIRE_SIGNED_APPROVAL", raising=False)
        monkeypatch.setattr(ap, "_config_approval", dict)
        assert ap.signing_enforced() is True

    def test_writable_wizard_env_cannot_set_trust_roots_or_disable_signatures(self, tmp_path, monkeypatch):
        from maverick import config

        _private, attacker = _keypair()
        path = tmp_path / ".env"
        path.write_text(f"MAVERICK_APPROVER_KEYS={attacker}\nMAVERICK_REQUIRE_SIGNED_APPROVAL=0\n")
        monkeypatch.setattr("maverick._STARTUP_APPROVER_KEYS", "")
        monkeypatch.delenv("MAVERICK_APPROVER_KEYS", raising=False)
        monkeypatch.delenv("MAVERICK_REQUIRE_SIGNED_APPROVAL", raising=False)
        monkeypatch.setattr(ap, "_config_approval", dict)
        config._load_env_file(path)
        assert "MAVERICK_APPROVER_KEYS" not in os.environ
        assert "MAVERICK_REQUIRE_SIGNED_APPROVAL" not in os.environ
        assert ap.trusted_approver_keys() == []
        assert ap.signing_enforced() is True

    def test_startup_roots_survive_later_environment_and_file_changes(self, tmp_path):
        import subprocess
        import sys

        env = os.environ.copy()
        env["MAVERICK_HOME"] = str(tmp_path)
        env["MAVERICK_CONFIG"] = str(tmp_path / "config.toml")
        env["MAVERICK_APPROVER_KEYS"] = "11" * 32
        script = '''
import os
from pathlib import Path
import maverick
from maverick import approval_signing, config
os.environ["MAVERICK_APPROVER_KEYS"] = "22" * 32
Path(os.environ["MAVERICK_HOME"], ".env").write_text("MAVERICK_APPROVER_KEYS=" + "33" * 32)
config.reset_config_cache()
assert approval_signing.trusted_approver_keys() == ["11" * 32]
assert approval_signing.trusted_global_approver_keys() == ["11" * 32]
assert approval_signing.signing_enforced()
'''
        result = subprocess.run([sys.executable, "-c", script], env=env,
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr

    def test_enforced_with_env_keys(self, monkeypatch):
        _priv, pub = _keypair()
        monkeypatch.setattr("maverick._STARTUP_APPROVER_KEYS", pub)
        monkeypatch.setattr(ap, "_config_approval", dict)
        assert ap.signing_enforced() is True
        assert pub in ap.trusted_approver_keys()

    def test_require_flag_enforces_even_without_keys(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_APPROVER_KEYS", raising=False)
        monkeypatch.delenv("MAVERICK_APPROVER_KEYS_DIR", raising=False)
        monkeypatch.setenv("MAVERICK_REQUIRE_SIGNED_APPROVAL", "1")
        monkeypatch.setattr(ap, "_config_approval", dict)
        assert ap.signing_enforced() is True

    def test_writable_directory_cannot_create_approver_trust(self, tmp_path, monkeypatch):
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_hex = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ).hex()
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        (tmp_path / "approver.pub").write_bytes(pub_bytes)      # raw 32 bytes
        (tmp_path / "not-a-key.pub").write_bytes(b"too short")  # skipped
        monkeypatch.delenv("MAVERICK_APPROVER_KEYS", raising=False)
        monkeypatch.setenv("MAVERICK_APPROVER_KEYS_DIR", str(tmp_path))
        monkeypatch.setattr(ap, "_config_approval", dict)

        keys = ap.trusted_approver_keys()
        assert keys == []
        assert ap.signing_enforced() is True
        cand = _candidate()
        cand.approval_signature = ap.sign_request(
            ap.ApprovalRequest.for_candidate(cand), priv_hex)
        assert ap.verify_candidate(cand) is None
        monkeypatch.setattr("maverick._STARTUP_APPROVER_KEYS", pub_bytes.hex())
        assert ap.verify_candidate(cand) == ap.key_id(pub_bytes.hex())

    def test_untrusted_directory_still_enforces_signatures(
        self, tmp_path, monkeypatch
    ):
        # A configured directory signals enforcement intent, even when its
        # contents are not independently trusted.
        _priv, pub = _keypair()
        (tmp_path / "approver.pub").write_text(pub, encoding="ascii")
        monkeypatch.delenv("MAVERICK_APPROVER_KEYS", raising=False)
        monkeypatch.setenv("MAVERICK_APPROVER_KEYS_DIR", str(tmp_path))
        monkeypatch.setattr(ap, "_config_approval", dict)

        assert ap.trusted_approver_keys() == []
        assert ap.signing_enforced() is True

    @pytest.mark.parametrize(
        "policy",
        [
            {"approver_keys": "not-a-list"},
            {"approver_keys": [123]},
            {"approver_keys_dir": 123},
            {"require_signed_approval": "false"},
        ],
    )
    def test_malformed_configured_approval_policy_is_not_unsigned(
        self, monkeypatch, policy,
    ):
        from maverick import config

        monkeypatch.delenv("MAVERICK_APPROVER_KEYS", raising=False)
        monkeypatch.delenv("MAVERICK_APPROVER_KEYS_DIR", raising=False)
        monkeypatch.delenv("MAVERICK_REQUIRE_SIGNED_APPROVAL", raising=False)
        monkeypatch.setattr(
            config,
            "load_config",
            lambda: {"self_improvement": policy},
        )
        monkeypatch.setattr(config, "config_source_errors", dict)

        with pytest.raises(RuntimeError, match="unavailable or invalid"):
            ap.signing_enforced()
        with pytest.raises(RuntimeError, match="unavailable or invalid"):
            ap.trusted_approver_keys()


class TestGateIntegration:
    """The controller's human-approval gate under enforcement."""

    def _controller(self):
        # Enabled, honest verifier, no ledger; humans required at code rung.
        return si.SelfImprovementController(
            min_improvement=0.0, max_auto_rung="policy",
            frozen_fn=lambda: False, audit_fn=lambda **k: None,
        )

    def test_boolean_ignored_when_signing_enforced(self, monkeypatch):
        _priv, pub = _keypair()
        monkeypatch.setattr(ap, "signing_enforced", lambda: True)
        monkeypatch.setattr(ap, "trusted_approver_keys", lambda: [pub])
        ctrl = self._controller()
        # approved=True but NO signature -> gate must still refuse.
        cand = _candidate(approved=True, approval_signature=None)
        verdict = ctrl.evaluate(cand)
        human = [g for g in verdict.gates if g.gate == "human_approval"][0]
        assert human.ok is False
        assert "signature" in human.reason

    def test_valid_signature_passes_gate_and_records_approver(self, monkeypatch):
        priv, pub = _keypair()
        monkeypatch.setattr(ap, "signing_enforced", lambda: True)
        monkeypatch.setattr(ap, "trusted_approver_keys", lambda: [pub])
        ctrl = self._controller()
        cand = _candidate(approved=False)  # Candidate is a mutable dataclass
        cand.approval_signature = ap.sign_request(ap.ApprovalRequest.for_candidate(cand), priv)
        verdict = ctrl.evaluate(cand)
        human = [g for g in verdict.gates if g.gate == "human_approval"][0]
        assert human.ok is True, verdict.blocking_reason
        assert verdict.approver_id == ap.key_id(pub)
        assert verdict.promote is True

    def test_forged_signature_fails_gate(self, monkeypatch):
        priv, _pub = _keypair()
        _priv2, pub2 = _keypair()          # controller trusts pub2 only
        monkeypatch.setattr(ap, "signing_enforced", lambda: True)
        monkeypatch.setattr(ap, "trusted_approver_keys", lambda: [pub2])
        ctrl = self._controller()
        cand = _candidate(approved=False)
        cand.approval_signature = ap.sign_request(  # signed by an untrusted key
            ap.ApprovalRequest.for_candidate(cand), priv)
        verdict = ctrl.evaluate(cand)
        human = [g for g in verdict.gates if g.gate == "human_approval"][0]
        assert human.ok is False
        assert verdict.promote is False

    def test_boolean_cannot_bypass_signature_requirement(self, monkeypatch):
        monkeypatch.setattr(ap, "signing_enforced", lambda: False)
        ctrl = self._controller()
        approved = ctrl.evaluate(_candidate(approved=True))
        refused = ctrl.evaluate(_candidate(approved=False))
        h_ok = [g for g in approved.gates if g.gate == "human_approval"][0]
        h_no = [g for g in refused.gates if g.gate == "human_approval"][0]
        assert h_ok.ok is False and h_no.ok is False

    @pytest.mark.parametrize("source_outage", [False, True])
    def test_signed_code_candidate_is_refused_when_policy_is_untrusted(
        self, monkeypatch, source_outage,
    ):
        from maverick import config

        priv, pub = _keypair()
        candidate = _candidate(approved=True)
        candidate.approval_signature = ap.sign_request(
            ap.ApprovalRequest.for_candidate(candidate), priv,
        )
        policy = {} if source_outage else {"approver_keys": [pub, 123]}
        monkeypatch.delenv("MAVERICK_APPROVER_KEYS", raising=False)
        monkeypatch.delenv("MAVERICK_APPROVER_KEYS_DIR", raising=False)
        monkeypatch.delenv("MAVERICK_REQUIRE_SIGNED_APPROVAL", raising=False)
        monkeypatch.setattr(
            config,
            "load_config",
            lambda: {"self_improvement": policy},
        )
        monkeypatch.setattr(
            config,
            "config_source_errors",
            lambda: ({"config.toml": "unreadable"} if source_outage else {}),
        )

        verdict = self._controller().evaluate(candidate)
        human = [g for g in verdict.gates if g.gate == "human_approval"][0]
        assert verdict.promote is False
        assert human.ok is False
        assert "policy is unavailable" in human.reason


def test_startup_pinned_operator_can_sign_exact_promotion_in_new_process(tmp_path):
    """A separately held test key authorizes only the exact recorded payload."""
    import json
    import subprocess
    import sys

    private, public = _keypair()
    wrong_private, _ = _keypair()
    candidate = _candidate(id="startup-signed-test")
    request = ap.ApprovalRequest.for_candidate(candidate)
    signature = ap.sign_request(request, private)
    wrong_signature = ap.sign_request(request, wrong_private)
    env = os.environ.copy()
    env.update({
        "MAVERICK_HOME": str(tmp_path),
        "MAVERICK_CONFIG": str(tmp_path / "config.toml"),
        "MAVERICK_APPROVER_KEYS": public,
        "MAVERICK_SELF_IMPROVEMENT": "1",
    })
    env.pop("MAVERICK_APPROVER_KEYS_DIR", None)
    script = '''
import json
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from maverick import approval_signing as ap
from maverick import self_improvement as si

data = json.load(sys.stdin)
base = dict(id="startup-signed-test", rung="code", summary="s", baseline_score=0.5,
            candidate_score=0.9, samples=20, payload={"diff": "x"},
            capability_widens=False, rollback="snap-1")
ledger = si.PromotionLedger(path=Path(data["ledger"]))
controller = si.SelfImprovementController(
    ledger=ledger, frozen_fn=lambda: False, audit_fn=lambda **kw: None,
    model_risk_verifier=lambda **kw: (True, ""))
for change in ({"payload": {"diff": "changed"}, "approval_signature": data["signature"]},
               {"approval_signature": data["wrong_signature"]}):
    verdict = controller.promote(si.Candidate(**(base | change)))
    assert not verdict.promote, verdict
    assert not ledger.all()
candidate = si.Candidate(**(base | {"approval_signature": data["signature"],
                                  "payload_sha256": data["payload_sha256"]}))
verdict = controller.promote(candidate)
assert verdict.promote, verdict
records = ledger.all()
assert len(records) == 1
record = records[0]
request = ap.ApprovalRequest.for_candidate(candidate)
assert record.id == candidate.id
assert record.payload_sha256 == request.payload_sha256
assert record.approval_signature == data["signature"]
assert record.approver_id == ap.key_id(data["public"])
Ed25519PublicKey.from_public_bytes(bytes.fromhex(data["public"])).verify(
    bytes.fromhex(record.approval_signature), request.message())
'''
    result = subprocess.run(
        [sys.executable, "-c", script],
        input=json.dumps({"signature": signature, "wrong_signature": wrong_signature,
                          "public": public, "payload_sha256": request.payload_sha256,
                          "ledger": str(tmp_path / "ledger.json")}),
        env=env, capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr

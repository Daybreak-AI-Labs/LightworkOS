"""Adversarial tests for the standing-consent authorization ledger."""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap

import pytest
from maverick import client
from maverick.connections import bind_principal
from maverick.file_lock import private_path_is_restricted
from maverick.safety import consent


def test_corrupt_client_binding_cannot_use_legacy_ledger_override(
    monkeypatch, tmp_path,
):
    legacy = tmp_path / "legacy-consent.ledger"
    monkeypatch.setattr(consent, "CONSENT_LEDGER_PATH", legacy)
    monkeypatch.setattr(
        client,
        "_raw_client_id",
        lambda: (_ for _ in ()).throw(
            client.ClientBindingError("corrupt client binding")
        ),
    )

    with pytest.raises(client.ClientBindingError, match="corrupt client binding"):
        consent.consent_ledger_path()

    assert not legacy.exists()


def test_control_character_injection_is_rejected(tmp_path):
    path = tmp_path / "consent.ledger"

    with pytest.raises(ValueError, match="control characters"):
        consent.grant_persistent(
            "benign",
            "safe\n0|grant\trm-rf\t/",
            path=path,
        )

    assert consent._check_ledger("rm-rf", "/", path=path) is False
    assert not path.exists()


def test_tampered_record_invalidates_the_authority(tmp_path):
    path = tmp_path / "consent.ledger"
    consent.grant_persistent("force-push", "main", path=path)
    record = json.loads(path.read_text(encoding="utf-8"))
    record["action"] = "rm-rf"
    path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    assert consent._check_ledger("force-push", "main", path=path) is False
    assert consent._check_ledger("rm-rf", "main", path=path) is False
    assert consent.list_grants(path=path) == []


def test_non_ascii_tampered_signature_fails_closed(tmp_path):
    path = tmp_path / "consent.ledger"
    consent.grant_persistent("force-push", "main", path=path)
    record = json.loads(path.read_text(encoding="utf-8"))
    record["mac"] = "é" * 64
    path.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    assert consent._check_ledger("force-push", "main", path=path) is False
    with pytest.raises(consent.ConsentLedgerError, match="signature"):
        consent.grant_persistent("deploy", "prod", path=path)


def test_grant_is_bound_to_exact_principal(tmp_path):
    path = tmp_path / "consent.ledger"
    with bind_principal("user:alice"):
        consent.grant_persistent("deploy", "prod", path=path)
        assert consent._check_ledger("deploy", "prod", path=path)
    with bind_principal("user:bob"):
        assert not consent._check_ledger("deploy", "prod", path=path)
        assert consent.list_grants(path=path) == []


def test_unsigned_legacy_ledger_fails_closed(tmp_path):
    path = tmp_path / "consent.ledger"
    path.write_text("0|grant\trm-rf\t/\n", encoding="utf-8")

    assert consent._check_ledger("rm-rf", "/", path=path) is False
    with pytest.raises(consent.ConsentLedgerError, match="legacy"):
        consent.grant_persistent("safe", "scope", path=path)


def test_ledger_and_signing_key_are_private(tmp_path):
    path = tmp_path / "consent.ledger"
    consent.grant_persistent("deploy", "prod", path=path)

    assert private_path_is_restricted(path)
    assert private_path_is_restricted(path.with_name(path.name + ".key"))


def test_concurrent_grants_are_complete_and_chain_valid(tmp_path):
    path = tmp_path / "consent.ledger"
    start = tmp_path / "start"
    script = textwrap.dedent(
        """
        import sys
        import time
        from pathlib import Path
        from maverick.safety.consent import grant_persistent

        ledger, prefix, start = sys.argv[1:]
        deadline = time.monotonic() + 10
        while not Path(start).exists():
            if time.monotonic() >= deadline:
                raise TimeoutError("start barrier was not released")
            time.sleep(0.01)
        for index in range(5):
            grant_persistent(f"action-{prefix}-{index}", "scope", path=Path(ledger))
        """
    )
    workers = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(path), str(index), str(start)]
        )
        for index in range(4)
    ]
    start.touch()
    for worker in workers:
        assert worker.wait(timeout=30) == 0

    grants = consent.list_grants(path=path)
    assert len(grants) == 20
    assert all(consent._check_ledger(*grant, path=path) for grant in grants)


def test_historical_unscoped_grants_require_explicit_reauthorization(monkeypatch, tmp_path):
    path = tmp_path / "consent.ledger"
    # Recreate records from before the unscoped-generation change while using
    # the ordinary signed append path; keep a scoped record as a control.
    with monkeypatch.context() as old:
        old.setattr(consent, "_unscoped_policy_binding", lambda policy: policy)
        with bind_principal("user:alice"):
            consent.grant_persistent("send", path=path)
            consent.grant_persistent("deploy", "prod", path=path)
        with bind_principal("user:bob"):
            consent.grant_persistent("send", path=path)
    with bind_principal("user:alice"):
        assert not consent._check_ledger("send", None, path=path)
        assert consent._check_ledger("deploy", "prod", path=path)
        consent.grant_persistent("send", path=path)
        assert consent._check_ledger("send", None, path=path)
    with bind_principal("user:bob"):
        assert not consent._check_ledger("send", None, path=path)


def test_earned_autonomy_does_not_mint_or_revoke_manual_grants(monkeypatch, tmp_path):
    from maverick import earned_autonomy

    path = tmp_path / "consent.ledger"
    monkeypatch.setattr(consent, "CONSENT_LEDGER_PATH", path)
    consent.grant_persistent("send", path=path)
    earned_autonomy._default_grant_fn("send")
    earned_autonomy._default_revoke_fn("send")
    assert consent._check_ledger("send", None, path=path)
    assert not consent._check_ledger("other", None, path=path)

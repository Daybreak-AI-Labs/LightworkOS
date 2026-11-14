"""The Operating Record: decisions as a system of record + signed capsule."""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from maverick import operating_record as orec
from maverick.file_lock import private_path_is_restricted
from maverick.world_model import WorldModel


@pytest.fixture()
def world(tmp_path):
    w = WorldModel(tmp_path / "w.db")
    gid = w.create_goal("Reconcile the quarterly ledger", domain="finance_sox")
    eid = w.start_episode(gid)
    w.end_episode(eid, "done", "success")
    w.set_goal_status(gid, "done", result="tied out")
    aid = w.create_approval("bank_transfer", risk="high",
                            detail="Q3 vendor batch")
    w.decide_approval(aid, "approved", decided_by="user:cfo")
    return w


def test_assemble_threads_goals_and_approvals(world):
    records = orec.assemble(world)
    kinds = {r.kind for r in records}
    assert kinds == {"goal", "approval"}
    goal = next(r for r in records if r.kind == "goal")
    assert goal.department == "finance_sox" and goal.outcome == "done"
    approval = next(r for r in records if r.kind == "approval")
    assert approval.decided_by == "user:cfo"
    s = orec.stats(records)
    assert s.n_goals == 1 and s.n_approvals == 1 and s.n_human_decisions == 1
    assert s.departments == {"finance_sox": 1}


def test_approval_history_orders_equal_timestamps_before_limiting(tmp_path, monkeypatch):
    from maverick import world_model

    with WorldModel(tmp_path / "approval-order.db") as world:
        monkeypatch.setattr(world_model, "time", SimpleNamespace(time=lambda: 1_000.0))
        first = world.create_approval("first")
        second = world.create_approval("second")
        assert [row.id for row in world.list_approvals()] == [second, first]
        assert [row.id for row in world.list_approvals(limit=1)] == [second]


def test_query_finds_every_decision_that_touched_x(world):
    records = orec.assemble(world)
    assert len(orec.query(records, text="ledger")) == 1
    assert len(orec.query(records, actor="user:cfo")) == 1
    assert orec.query(records, department="legal_x") == []


def test_owner_scoped_approvals_overfetch_past_global_limit():
    """list_approvals has no owner SQL filter, so an owner-scoped assemble must
    over-fetch: alice's older approvals must not be dropped just because newer
    approvals by others fill the global top-``limit``."""
    class _Approval:
        def __init__(self, i, who):
            self.decided_at = float(i)
            self.requested_by = who
            self.claimed_by = None
            self.decided_by = who
            self.action = f"act-{i}"
            self.status = "approved"
            self.provenance = None

    class _FakeWorld:
        def __init__(self):
            # alice's one approval is the OLDEST; then 1000 by others (newest).
            self._rows = [_Approval(0, "alice")] + [
                _Approval(i, "bob") for i in range(1, 1001)
            ]

        def list_goals(self, **kw):
            return []

        def list_episodes(self, **kw):
            return []

        def list_approvals(self, *, limit):
            # Newest first, truncated to limit -- exactly the SQL behavior.
            return list(reversed(self._rows))[:limit]

    world = _FakeWorld()
    records = orec.assemble(world, limit=100, owner="alice")
    # Pre-fix: alice's lone (oldest) approval falls outside the newest-100 and
    # is dropped. Post-fix: the over-fetch recovers it.
    assert any(r.decided_by == "alice" for r in records)


def test_empty_owner_reads_unowned_approvals_only():
    def approval(i, requested_by):
        return SimpleNamespace(decided_at=float(i), requested_at=float(i), requested_by=requested_by,
                               claimed_by=None, decided_by="operator", action=f"act-{i}",
                               status="approved", provenance=None)

    class _FakeWorld:
        def list_goals(self, **kw):
            return []

        def list_episodes(self, **kw):
            return []

        def list_approvals(self, *, limit):
            return [approval(1, None), approval(2, "user:alice")]

    records = orec.assemble(_FakeWorld(), owner="")
    assert [r.subject for r in records] == ["act-1"]


def test_capsule_roundtrip_and_tamper_detection(world, tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    import maverick.audit.signing as signing
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    out_path = tmp_path / "mind.capsule.json"
    out_path.write_text("old private capsule", encoding="utf-8")
    out_path.chmod(0o600)
    old_umask = os.umask(0o022)
    try:
        out = orec.export_capsule(world, out_path, now=5.0)
    finally:
        os.umask(old_umask)
    ok, reason = orec.verify_capsule(out)
    assert ok, reason
    # Written atomically (temp + replace): no .tmp sibling left behind.
    assert not out.with_name(out.name + ".tmp").exists()
    assert private_path_is_restricted(out, 0o600)
    # Tamper with one decision: the capsule must fail verification.
    text = out.read_text(encoding="utf-8").replace(
        "Reconcile the quarterly ledger", "Reconcile the doctored ledger")
    out.write_text(text, encoding="utf-8")
    ok, reason = orec.verify_capsule(out)
    assert not ok and "FAILED" in reason


# -- origin: a capsule is trusted only when signed by a key the verifier trusts

def _forged_capsule(path, *, claimed_key_id="attacker-key"):
    """A capsule anyone can fabricate: a fresh key signs a record nobody made."""
    import json

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()
    body = {
        "schema_version": 1, "ts": 1.0, "learned": {},
        "records": [{"ts": 1.0, "kind": "approval", "actor": "user:cfo",
                     "subject": "FORGED: CFO approved $5M wire",
                     "outcome": "approved"}],
    }
    sig = priv.sign(orec._canonical(body)).hex()
    path.write_text(json.dumps(
        {**body, "pubkey": pub, "key_id": claimed_key_id, "sig": sig}),
        encoding="utf-8")
    return pub


@pytest.fixture()
def genuine(world, tmp_path, monkeypatch):
    """A capsule this installation really signed, plus its public key."""
    pytest.importorskip("cryptography")
    import json

    import maverick.audit.signing as signing
    monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
    path = orec.export_capsule(world, tmp_path / "genuine.json", now=5.0)
    return path, json.loads(path.read_text(encoding="utf-8"))["pubkey"]


def test_forged_capsule_signed_with_any_key_is_rejected_as_untrusted(genuine, tmp_path):
    forged = tmp_path / "forged.json"
    pub = _forged_capsule(forged)

    ok, reason = orec.verify_capsule(forged)

    assert not ok
    assert "untrusted key" in reason
    # The fingerprint shown is derived from the signing key itself, never the
    # capsule's own (unsigned, forgeable) key_id label.
    import hashlib
    assert hashlib.sha256(bytes.fromhex(pub)).hexdigest()[:16] in reason
    assert "attacker-key" not in reason


def test_capsule_signed_by_this_installations_audit_key_is_trusted_by_default(genuine):
    path, pub = genuine
    ok, reason = orec.verify_capsule(path)
    assert ok, reason
    import hashlib
    assert hashlib.sha256(bytes.fromhex(pub)).hexdigest()[:16] in reason


def test_explicit_trust_anchor_accepts_the_publishers_key_and_no_other(genuine, tmp_path):
    forged = tmp_path / "forged.json"
    attacker_pub = _forged_capsule(forged)
    path, own_pub = genuine

    # An auditor holding the firm's published key accepts the firm's capsule...
    assert orec.verify_capsule(path, trusted_pubkeys=[own_pub])[0]
    # ...and rejects the forgery even though it is internally consistent.
    ok, reason = orec.verify_capsule(forged, trusted_pubkeys=[own_pub])
    assert not ok and "untrusted key" in reason
    # Trust is exactly the key the verifier names, upper-case hex included.
    assert orec.verify_capsule(forged, trusted_pubkeys=[attacker_pub.upper()])[0]


def test_no_trust_anchor_fails_closed(genuine):
    path, _pub = genuine
    ok, reason = orec.verify_capsule(path, trusted_pubkeys=[])
    assert not ok and "no trusted key" in reason


def test_malformed_trust_anchor_fails_closed(genuine):
    path, _pub = genuine
    ok, reason = orec.verify_capsule(path, trusted_pubkeys=["not-a-key"])
    assert not ok and "64 hex" in reason


def test_a_tampered_capsule_still_fails_its_signature_first(genuine):
    path, pub = genuine
    path.write_text(path.read_text(encoding="utf-8").replace(
        "Reconcile the quarterly ledger", "Reconcile the doctored ledger"),
        encoding="utf-8")
    ok, reason = orec.verify_capsule(path, trusted_pubkeys=[pub])
    assert not ok and "FAILED" in reason


def test_integrity_check_alone_says_nothing_about_who_signed(genuine, tmp_path):
    forged = tmp_path / "forged.json"
    _forged_capsule(forged)
    ok, reason = orec.verify_capsule_integrity(forged)
    assert ok
    assert "integrity only" in reason and "who signed" in reason


def test_cli_record_verify_rejects_a_forged_capsule(genuine, tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main
    forged = tmp_path / "forged.json"
    _forged_capsule(forged)

    result = CliRunner().invoke(main, ["record", "verify", str(forged)])

    assert result.exit_code != 0
    assert "untrusted key" in result.output


def test_cli_record_verify_accepts_this_installations_capsule(genuine):
    from click.testing import CliRunner
    from maverick.cli import main
    path, _pub = genuine

    result = CliRunner().invoke(main, ["record", "verify", str(path)])

    assert result.exit_code == 0, result.output
    assert result.output.startswith("ok:")


def test_cli_record_export_still_passes_its_own_self_check(genuine, tmp_path):
    """``record export`` verifies what it just wrote; it signs with this
    installation's audit key, which is trusted by default, so the check holds."""
    from click.testing import CliRunner
    from maverick.cli import main
    out = tmp_path / "exported.json"

    result = CliRunner().invoke(
        main, ["--db", str(tmp_path / "cli.db"), "record", "export", str(out)])

    assert result.exit_code == 0, result.output
    assert "self-check: ok:" in result.output


def test_cli_record_verify_takes_a_published_key_or_a_key_file(genuine, tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main
    forged = tmp_path / "forged.json"
    attacker_pub = _forged_capsule(forged)
    _path, own_pub = genuine
    keys = tmp_path / "trusted.txt"
    keys.write_text(f"# the firm's published keys\n{own_pub}\n\n{attacker_pub}\n",
                    encoding="utf-8")
    run = CliRunner().invoke

    assert run(main, ["record", "verify", str(forged), "--pubkey", attacker_pub]).exit_code == 0
    assert run(main, ["record", "verify", str(forged), "--pubkey", own_pub]).exit_code != 0
    assert run(main, ["record", "verify", str(forged), "--trusted-keys", str(keys)]).exit_code == 0
    # An empty key file is an explicit "trust nobody", never a silent fallback
    # to the local keyring.
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n", encoding="utf-8")
    assert run(main, ["record", "verify", str(forged), "--trusted-keys", str(empty)]).exit_code != 0


def test_cli_record_verify_unreadable_key_file_is_a_clean_error(genuine, tmp_path):
    """A trusted-keys file that cannot be decoded is reported plainly and still
    fails closed -- never a Python traceback."""
    from click.testing import CliRunner
    from maverick.cli import main
    path, _pub = genuine
    binary = tmp_path / "trusted.bin"
    binary.write_bytes(b"\xff\xfe\x00\x80 not text")

    result = CliRunner().invoke(
        main, ["record", "verify", str(path), "--trusted-keys", str(binary)])

    assert result.exit_code != 0
    assert "trusted keys file" in result.output
    assert not isinstance(result.exception, UnicodeDecodeError), result.exception

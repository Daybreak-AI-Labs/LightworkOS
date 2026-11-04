"""Signed tax-constants channel: law changes arrive as governed content.

Locks the poisoning posture: fail-closed signatures, sanity validation
before anything can replace the tables, downgrade refusal, rollback, and
the prep CLI actually computing from an applied bundle.
"""
from __future__ import annotations

import json

import pytest
from maverick import tax_constants
from maverick.tax_prep import STATE_TY2025, TY2025


def _have_crypto() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
        return True
    except BaseException:
        return False


crypto = pytest.mark.skipif(not _have_crypto(), reason="cryptography unavailable")


def _payload(version: int = 1, **overrides) -> dict:
    """A valid bundle payload built from the shipped tables."""
    fed = {
        "standard_deduction": dict(TY2025["standard_deduction"]),
        "brackets": {s: [list(b) for b in TY2025["brackets"][s]]
                     for s in TY2025["brackets"]},
        "ctc_per_child": TY2025["ctc_per_child"],
        "ctc_phaseout_start": dict(TY2025["ctc_phaseout_start"]),
    }
    state = {
        "no_tax": sorted(STATE_TY2025["no_tax"]),
        "flat": {c: {"rate": f["rate"], "basis": f["basis"],
                     "deduction": dict(f["deduction"])}
                 for c, f in STATE_TY2025["flat"].items()},
    }
    p = {"schema_version": 1, "year": 2025, "version": version,
         "published": "2026-06-12", "federal": fed, "state": state}
    p.update(overrides)
    return p


def _sign(payload: dict):
    """Sign with a fresh publisher key; returns (envelope, pubkey_hex)."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    assert priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    sig = priv.sign(tax_constants._canonical_bytes(payload)).hex()
    return ({"schema_version": 1, "payload": payload,
             "publisher_key": pub, "publisher_key_id": pub[:8],
             "sig": sig}, pub)


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(tax_constants, "_store_dir", lambda: tmp_path)
    return tmp_path


class TestValidation:
    def test_shipped_tables_round_trip_as_a_valid_payload(self):
        assert tax_constants.validate_payload(_payload()) == []

    def test_insane_figures_are_refused(self):
        p = _payload()
        p["federal"]["brackets"]["single"][0][1] = 1.5   # 150% tax rate
        assert any("malformed" in e or "out of range" in e
                   for e in tax_constants.validate_payload(p))
        p2 = _payload()
        p2["state"]["flat"]["ZZ"] = p2["state"]["flat"]["PA"]
        assert any("unknown state" in e
                   for e in tax_constants.validate_payload(p2))
        p3 = _payload()
        p3["federal"]["brackets"]["mfj"] = [[10000, .1], [5000, .2], [None, .3]]
        assert any("ascending" in e
                   for e in tax_constants.validate_payload(p3))
        p4 = _payload()
        p4["federal"]["brackets"]["hoh"] = [[10000, .1], [20000, .2]]
        assert any("open-ended" in e
                   for e in tax_constants.validate_payload(p4))

    def test_graduated_state_table_validates(self):
        good = _payload()
        good["state"]["graduated"] = {"NY": {"basis": "agi",
            "brackets": [[20000, .04], [None, .06]],
            "deduction": {"single": 8000.0, "mfj": 16000.0, "hoh": 8000.0}}}
        assert tax_constants.validate_payload(good) == []
        # malformed graduated brackets are caught just like the federal ones
        bad = _payload()
        bad["state"]["graduated"] = {"NY": {"basis": "agi",
            "brackets": [[20000, .04], [10000, .06], [None, .08]],
            "deduction": {"single": 0.0, "mfj": 0.0, "hoh": 0.0}}}
        assert any("ascending" in e
                   for e in tax_constants.validate_payload(bad))
        unknown = _payload()
        unknown["state"]["graduated"] = {"ZZ": {"basis": "agi",
            "brackets": [[None, .05]],
            "deduction": {"single": 0.0, "mfj": 0.0, "hoh": 0.0}}}
        assert any("unknown state" in e
                   for e in tax_constants.validate_payload(unknown))


def _trust(monkeypatch, *pubs):
    """Configure the publisher keys the active bundle is re-verified against."""
    monkeypatch.setattr(tax_constants, "trusted_pubkeys", lambda: list(pubs))


@crypto
class TestApply:
    def test_signed_bundle_applies_and_wins_over_builtins(self, store, monkeypatch):
        p = _payload()
        p["federal"]["standard_deduction"]["single"] = 16000.0  # "new law"
        env, pub = _sign(p)
        _trust(monkeypatch, pub)
        ok, reason = tax_constants.apply_bundle(env, trusted=[pub])
        assert ok, reason
        federal, state, prov = tax_constants.active_constants()
        assert federal["standard_deduction"]["single"] == 16000.0
        assert state["flat"]["PA"]["rate"] == STATE_TY2025["flat"]["PA"]["rate"]
        assert "bundle v1" in prov
        assert tax_constants.active_version() == 1
        # A key no longer trusted today stops the retained bundle from applying.
        _trust(monkeypatch)
        assert tax_constants.active_version() == 0

    def test_fail_closed_no_anchors_untrusted_tampered(self, store):
        env, pub = _sign(_payload())
        ok, reason = tax_constants.apply_bundle(env, trusted=[])
        assert not ok and "no trusted publisher keys" in reason
        ok, reason = tax_constants.apply_bundle(env, trusted=["ab" * 32])
        assert not ok and "not currently trusted" in reason
        env["payload"]["federal"]["ctc_per_child"] = 99999.0  # tamper
        ok, reason = tax_constants.apply_bundle(env, trusted=[pub])
        assert not ok and "FAILED" in reason

    def test_invalid_payload_rejected_even_when_signed(self, store):
        p = _payload()
        p["state"]["flat"]["PA"]["rate"] = 1.5
        env, pub = _sign(p)
        ok, reason = tax_constants.apply_bundle(env, trusted=[pub])
        assert not ok and "sanity validation" in reason

    def test_downgrade_refused_and_rollback_restores(self, store, monkeypatch):
        env1, pub1 = _sign(_payload(version=1))
        env2, pub2 = _sign(_payload(version=2))
        _trust(monkeypatch, pub1, pub2)
        assert tax_constants.apply_bundle(env1, trusted=[pub1])[0]
        assert tax_constants.apply_bundle(env2, trusted=[pub2])[0]
        assert tax_constants.active_version() == 2
        ok, reason = tax_constants.apply_bundle(env1, trusted=[pub1])
        assert not ok and "not newer" in reason
        ok, reason = tax_constants.rollback()
        assert ok, reason
        assert tax_constants.active_version() == 1

    def test_corrupt_stored_bundle_falls_back_to_builtins(self, store):
        env, pub = _sign(_payload())
        assert tax_constants.apply_bundle(env, trusted=[pub])[0]
        tax_constants.bundle_path().write_text("{not json", encoding="utf-8")
        federal, _, prov = tax_constants.active_constants()
        assert federal == TY2025 and prov == "built-in defaults"

    def test_export_refuses_to_sign_garbage(self, tmp_path, monkeypatch):
        from maverick.audit import signing
        monkeypatch.setattr(signing, "KEY_DIR", tmp_path / "keys")
        p = _payload()
        p["federal"]["ctc_per_child"] = -1
        with pytest.raises(ValueError, match="invalid payload"):
            tax_constants.export_bundle(tmp_path / "b.json", p)
        good = tax_constants.export_bundle(tmp_path / "ok.json", _payload())
        env = json.loads(good.read_text(encoding="utf-8"))
        ok, reason = tax_constants.apply_bundle_file(
            good, trusted=[env["publisher_key"]],
            path=tmp_path / "applied.json")
        assert ok, reason


@crypto
class TestUpdateChannel:
    def test_throttle_skips_recent_checks(self, store, monkeypatch):
        from maverick import config as cfg_mod
        monkeypatch.setattr(cfg_mod, "load_config", lambda: {
            "tax": {"update_url": "https://updates.example/tax.json"}})
        (store / ".tax-constants-check").write_text(str(1e12))
        status, _ = tax_constants.check_for_update(now=1e12 + 60)
        assert status == "throttled"

    def test_no_url_is_disabled_not_an_error(self, store, monkeypatch):
        from maverick import config as cfg_mod
        monkeypatch.setattr(cfg_mod, "load_config", dict)
        assert tax_constants.check_for_update()[0] == "disabled"

    def test_prepare_computes_from_the_applied_bundle(self, store, tmp_path, monkeypatch):
        # The whole point: a published law change reaches the next prep run.
        from click.testing import CliRunner
        from maverick.cli import main
        p = _payload()
        p["federal"]["standard_deduction"]["single"] = 20000.0
        env, pub = _sign(p)
        _trust(monkeypatch, pub)
        assert tax_constants.apply_bundle(env, trusted=[pub])[0]
        docs = tmp_path / "docs"
        docs.mkdir()
        (docs / "w2.txt").write_text(
            "Form W-2 Wage and Tax Statement 2025\n"
            "Box 1 Wages, tips, other compensation: $85,000.00\n",
            encoding="utf-8")
        res = CliRunner().invoke(main, [
            "--db", str(tmp_path / "x.db"), "tax", "prepare", str(docs)])
        assert res.exit_code == 0, res.output
        assert "Standard deduction   : $20,000.00" in res.output
        assert "bundle v1" in res.output    # provenance on the package

    def test_update_cli_status_and_file_apply(self, store, tmp_path,
                                              monkeypatch):
        from click.testing import CliRunner
        from maverick import config as cfg_mod
        from maverick.cli import main
        env, pub = _sign(_payload())
        bundle = tmp_path / "bundle.json"
        bundle.write_text(json.dumps(env), encoding="utf-8")
        monkeypatch.setattr(cfg_mod, "load_config", lambda: {
            "tax": {"trusted_constants_pubkeys": [pub]}})
        res = CliRunner().invoke(main, [
            "--db", str(tmp_path / "x.db"), "tax", "update",
            "--file", str(bundle)])
        assert res.exit_code == 0, res.output
        assert "applied tax constants v1" in res.output
        res = CliRunner().invoke(main, [
            "--db", str(tmp_path / "x.db"), "tax", "update", "--status"])
        assert res.exit_code == 0 and "bundle v1" in res.output


def test_validate_payload_rejects_non_finite_numeric_header():
    # A JSON bundle with an out-of-range number (1e400) parses to float inf;
    # int(inf) raises OverflowError, which must be caught and reported as a
    # malformed header rather than escaping validate_payload.
    from maverick.tax_constants import validate_payload
    errs = validate_payload({"schema_version": float("inf"), "year": 2025, "version": 1})
    assert errs == ["malformed header fields"]


def test_concurrent_apply_preserves_rollback_copy(store, monkeypatch):
    """Two concurrent applies of newer bundles must not interleave the .prev
    backup + write: the bundle stays valid, a .prev rollback copy exists, and no
    fixed-".tmp" residue is left."""
    import threading

    env1, pub1 = _sign(_payload(version=1))
    assert tax_constants.apply_bundle(env1, trusted=[pub1])[0]  # seed v1

    env2, pub2 = _sign(_payload(version=2))
    env3, pub3 = _sign(_payload(version=3))
    _trust(monkeypatch, pub1, pub2, pub3)

    def apply(env, pub):
        tax_constants.apply_bundle(env, trusted=[pub])

    ts = [threading.Thread(target=apply, args=(env2, pub2)),
          threading.Thread(target=apply, args=(env3, pub3))]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    # The applied version is one of the two (whichever serialized last); the file
    # is a valid bundle and a .prev rollback copy survives, with no temp residue.
    assert tax_constants.active_version() in (2, 3)
    p = tax_constants.bundle_path()
    assert json.loads(p.read_text())  # valid JSON, not torn
    assert p.with_suffix(p.suffix + ".prev").exists()
    assert list(p.parent.glob("*.tmp")) == []

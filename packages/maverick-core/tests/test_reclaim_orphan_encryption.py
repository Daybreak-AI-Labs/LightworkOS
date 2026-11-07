"""reclaim_orphan_goals must not corrupt a sealed `goals.result`.

Bug: the startup orphan-reclaim ran
``result = COALESCE(result, '') || ' [process restarted mid-run]'`` in SQL.
With at-rest encryption on, ``result`` is sealed ciphertext, so the SQL
concatenation appends plaintext onto the ciphertext (unrecoverable on decrypt)
or, for a NULL result, writes bare plaintext into a sealed column (tripped as
tampering). The append must go through the seal layer instead.
"""
from __future__ import annotations

import importlib.util
import sqlite3

import pytest
from maverick import crypto_at_rest as car

requires_crypto = pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography extra is not installed",
)

_MARKER = " [process restarted mid-run]"


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    for v in ("MAVERICK_ENCRYPT_AT_REST", "MAVERICK_ENCRYPTION_KEY",
              "MAVERICK_ENTERPRISE", "MAVERICK_ENCRYPT_STRICT"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "keys" / "at_rest.key")


@requires_crypto
def test_reclaim_preserves_sealed_nonnull_result(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    from maverick.world_model import WorldModel
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    gid = wm.create_goal("g", "")
    # An active goal that already carries a (sealed) result.
    wm.set_goal_status(gid, "active", result="partial work so far")

    n = wm.reclaim_orphan_goals(max_age_seconds=0)
    assert n == 1

    g = wm.get_goal(gid)
    assert g.status == "blocked"
    # Decrypts cleanly (no ciphertext corruption) and carries both the prior
    # result and the restart marker.
    assert g.result == "partial work so far" + _MARKER

    # On disk it is still sealed, not plaintext.
    raw = sqlite3.connect(str(db)).execute(
        "SELECT result FROM goals WHERE id=?", (gid,)
    ).fetchone()[0]
    assert raw.startswith("MVKBND1:") and "partial work" not in raw


@requires_crypto
def test_reclaim_seals_marker_for_null_result(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    from maverick.world_model import WorldModel
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    gid = wm.create_goal("g", "")  # stays 'pending', result is NULL

    n = wm.reclaim_orphan_goals(max_age_seconds=0)
    assert n == 1

    # The marker round-trips and is stored sealed, never as bare plaintext in a
    # sealed column.
    assert wm.get_goal(gid).result == _MARKER
    raw = sqlite3.connect(str(db)).execute(
        "SELECT result FROM goals WHERE id=?", (gid,)
    ).fetchone()[0]
    assert raw.startswith("MVKBND1:")


@requires_crypto
def test_reclaim_under_strict_mode_preserves_legacy_plaintext_result(monkeypatch, tmp_path):
    """Regression: with strict mode on and a not-yet-migrated plaintext result,
    _dec_field returns the withheld sentinel and reclaim wrote it back sealed --
    permanently destroying the original. It must reclaim the status only and
    leave the stored result untouched."""
    from maverick.world_model import WorldModel
    db = tmp_path / "world.db"
    # Write phase: encryption EXPLICITLY off (under the secure default an
    # unset flag seals, which would break the legacy-plaintext premise).
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    wm = WorldModel(db)
    gid = wm.create_goal("g", "")
    wm.set_goal_status(gid, "active", result="IMPORTANT pre-encryption result")

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_STRICT", "1")
    n = wm.reclaim_orphan_goals(max_age_seconds=0)
    assert n == 1
    assert wm.get_goal(gid).status == "blocked"

    # The stored value is the untouched legacy plaintext -- recoverable via
    # `maverick encryption migrate` (or by lifting strict) -- not the sealed
    # withheld sentinel.
    raw = sqlite3.connect(str(db)).execute(
        "SELECT result FROM goals WHERE id=?", (gid,)
    ).fetchone()[0]
    assert raw == "IMPORTANT pre-encryption result"


def test_reclaim_plaintext_concat_unchanged_without_encryption(tmp_path, monkeypatch):
    """Encryption off: the fast SQL-concat path is preserved (marker appended)."""
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    from maverick.world_model import WorldModel
    wm = WorldModel(tmp_path / "world.db")
    gid = wm.create_goal("g", "")
    wm.set_goal_status(gid, "active", result="prior")

    n = wm.reclaim_orphan_goals(max_age_seconds=0)
    assert n == 1
    assert wm.get_goal(gid).result == "prior" + _MARKER


@requires_crypto
def test_a_withheld_fact_value_cannot_be_written_back_over_the_original(monkeypatch, tmp_path):
    """Strict mode withholds a legacy plaintext fact as a placeholder. Writing that
    placeholder back (the tag editor round-trips ``fact_record``'s value) would seal
    it over the real value and destroy it."""
    from maverick.world_model import _UNSEALED_WITHHELD, WorldModel
    db = tmp_path / "world.db"
    # Write the legacy row with at-rest off explicitly: the production posture
    # (MAVERICK_TEST_SECURE_DEFAULT=1) turns encryption on by default.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    wm = WorldModel(db)
    wm.upsert_fact("policy:retention", "keep invoices for seven years")  # at-rest off: plaintext
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_STRICT", "1")

    item = wm.fact_record("policy:retention")
    assert item["value"] == _UNSEALED_WITHHELD
    with pytest.raises(ValueError, match="encryption migrate"):
        wm.upsert_fact("policy:retention", item["value"], tags=["finance"], expected_revision=item["revision"])

    raw = sqlite3.connect(str(db)).execute(
        "SELECT value FROM facts WHERE key=?", ("policy:retention",)).fetchone()[0]
    assert raw == "keep invoices for seven years"
    # A real value still writes (and is sealed) as before.
    wm.upsert_fact("policy:retention", "keep invoices for ten years")
    assert wm.fact_record("policy:retention")["value"] == "keep invoices for ten years"

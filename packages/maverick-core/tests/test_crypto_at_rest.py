"""Encryption at rest: AES-256-GCM seal/unseal + key management."""
from __future__ import annotations

import base64
import importlib.util

import pytest
from maverick import crypto_at_rest as car
from maverick import file_lock

# AES-GCM needs the optional 'cryptography' extra; skip only the tests that
# exercise encryption where it is absent, matching the audit-signing tests
# (test_audit_anchor.py). Key-management tests still run without the extra.
requires_crypto = pytest.mark.skipif(
    importlib.util.find_spec("cryptography") is None,
    reason="cryptography extra is not installed",
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_ENCRYPT_AT_REST", raising=False)
    monkeypatch.delenv("MAVERICK_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_ENTERPRISE", raising=False)
    monkeypatch.delenv("MAVERICK_REPLICA_COUNT", raising=False)
    monkeypatch.delenv("MAVERICK_GOVERNED_RECORDS_BACKEND", raising=False)
    monkeypatch.delenv("MAVERICK_WORLD_BACKEND", raising=False)
    monkeypatch.setattr("maverick.config.load_config", lambda *a, **k: {})
    monkeypatch.setattr("maverick.config.load_governed_records_config", dict)
    monkeypatch.setattr(
        "maverick.config.governed_records_config_source_errors",
        dict,
    )
    # Keep the generated key out of the real ~/.maverick.
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "keys" / "at_rest.key")


def test_default_follows_the_posture():
    # Unset flag: sealed under the secure default, plaintext in legacy mode.
    from maverick.security_defaults import secure_by_default

    assert car.at_rest_enabled() is secure_by_default()


def test_enabled_by_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    assert car.at_rest_enabled() is True
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    assert car.at_rest_enabled() is False


def test_natural_truthy_tokens_enable_not_disable(monkeypatch):
    # Regression: a natural affirmative like 'on'/'yes'/'enabled'/'true' must
    # ENABLE at-rest encryption, not silently disable it (which stored plaintext).
    for tok in ("on", "yes", "enabled", "enable", "true", "y", "TRUE", " On "):
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", tok)
        assert car.at_rest_enabled() is True, f"{tok!r} should enable encryption"


def test_at_rest_floor_fails_safe_on_unrecognized_value(monkeypatch):
    # An unrecognised value must keep the security floor ON (fail-safe), never
    # silently downgrade to plaintext. Only an EXPLICIT false token disables.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "garbage")
    assert car.at_rest_enabled() is True
    for tok in ("0", "false", "off", "disabled", "no"):
        monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", tok)
        assert car.at_rest_enabled() is False, f"{tok!r} should disable encryption"


def test_implied_by_enterprise(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "1")
    assert car.at_rest_enabled() is True


def test_config_enables(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config", lambda *a, **k: {"encryption": {"at_rest": True}}
    )
    assert car.at_rest_enabled() is True


@requires_crypto
def test_seal_unseal_roundtrip():
    secret = b"patient SSN 123-45-6789"
    blob = car.seal(secret)
    assert car.is_sealed(blob)
    assert blob != secret  # actually encrypted
    assert b"123-45-6789" not in blob  # plaintext not present in ciphertext
    assert car.unseal(blob) == secret


@requires_crypto
def test_text_helpers():
    blob = car.seal_text("hello — é")
    assert car.unseal_to_text(blob) == "hello — é"


def test_unseal_passthrough_for_plaintext():
    # A blob without the magic header is legacy plaintext -> returned as-is.
    assert car.unseal(b"plain old note") == b"plain old note"
    assert car.is_sealed(b"plain old note") is False


@requires_crypto
def test_each_seal_uses_fresh_nonce():
    a, b = car.seal(b"same"), car.seal(b"same")
    assert a != b  # nonce randomization -> distinct ciphertexts
    assert car.unseal(a) == car.unseal(b) == b"same"


@requires_crypto
def test_tamper_is_detected():
    blob = bytearray(car.seal(b"important"))
    blob[-1] ^= 0x01  # flip a tag bit
    with pytest.raises(Exception):  # noqa: B017 - InvalidTag from the AEAD
        car.unseal(bytes(blob))


@requires_crypto
def test_injected_key_hex_and_base64(monkeypatch):
    key = bytes(range(32))
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", key.hex())
    blob = car.seal(b"x")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", base64.b64encode(key).decode())
    assert car.unseal(blob) == b"x"  # same key, different encoding -> opens


@requires_crypto
def test_injected_key_wrong_size_fails(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", "00" * 16)  # 16 bytes, not 32
    with pytest.raises(car.EncryptionUnavailable):
        car.seal(b"x")


@requires_crypto
def test_generated_key_persists_and_chmod(monkeypatch):
    blob = car.seal(b"persist me")
    assert car._KEY_PATH.exists()
    assert file_lock.private_path_is_restricted(car._KEY_PATH)
    assert file_lock.private_path_is_restricted(car._KEY_PATH.parent, 0o700)
    # A second seal reuses the same on-disk key, so unseal still works.
    assert car.unseal(blob) == b"persist me"


def test_generated_key_is_created_private_atomically(monkeypatch):
    original_create = file_lock.atomic_create_text
    observed = {}

    def checked_create(path, text, *, mode=0o600, encoding="utf-8"):
        observed["target_absent"] = not car._KEY_PATH.exists()
        observed["requested_mode"] = mode
        observed["parent_private_before_create"] = (
            file_lock.private_path_is_restricted(car._KEY_PATH.parent, 0o700)
        )
        return original_create(path, text, mode=mode, encoding=encoding)

    monkeypatch.setattr(file_lock, "atomic_create_text", checked_create)

    car._load_or_create_key()

    assert observed == {
        "target_absent": True,
        "requested_mode": 0o600,
        "parent_private_before_create": True,
    }
    assert file_lock.private_path_is_restricted(car._KEY_PATH)
    before = car._KEY_PATH.read_text(encoding="utf-8")
    monkeypatch.setattr(file_lock, "atomic_create_text", original_create)
    with pytest.raises(FileExistsError):
        car._write_new_key_file(b"z" * 32)
    assert car._KEY_PATH.read_text(encoding="utf-8") == before
    assert not list(car._KEY_PATH.parent.glob(".at_rest.key-*.tmp"))


def test_existing_key_permissions_are_repaired_before_read(monkeypatch):
    car._KEY_PATH.parent.mkdir(parents=True)
    car._KEY_PATH.write_text((b"k" * 32).hex(), encoding="utf-8")
    if car.os.name != "nt":
        car._KEY_PATH.parent.chmod(0o755)
        car._KEY_PATH.chmod(0o644)
    original_read_text = file_lock.atomic_read_text
    observed = {}

    def checked_read_text(path, *args, **kwargs):
        if path == car._KEY_PATH:
            observed["key_private_before_read"] = (
                file_lock.private_path_is_restricted(path)
            )
            observed["parent_private_before_read"] = (
                file_lock.private_path_is_restricted(path.parent, 0o700)
            )
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(file_lock, "atomic_read_text", checked_read_text)

    assert car._load_or_create_key() == b"k" * 32
    assert observed == {
        "key_private_before_read": True,
        "parent_private_before_read": True,
    }


@requires_crypto
def test_memory_tool_seals_on_disk(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_MEMORY_DIR", str(tmp_path / "mem"))
    from maverick.tools.memory import memory, memory_root_for

    tool = memory()
    out = tool.fn({"command": "create", "path": "notes.md",
                   "file_text": "patient SSN 123-45-6789"})
    assert "wrote" in out
    raw = (memory_root_for("") / "notes.md").read_bytes()
    assert not (tmp_path / "mem" / "notes.md").exists()  # no shared-root write
    assert car.is_sealed(raw)          # on-disk file is ciphertext
    assert b"123-45-6789" not in raw   # plaintext absent on disk
    view = tool.fn({"command": "view", "path": "notes.md"})
    assert "123-45-6789" in view       # view transparently decrypts


@requires_crypto
def test_memory_reads_legacy_plaintext_within_current_owned_scope(monkeypatch, tmp_path):
    memdir = tmp_path / "mem"
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_MEMORY_DIR", str(memdir))
    from maverick.tools.memory import memory, memory_root_for

    owned = memory_root_for("")
    owned.mkdir(parents=True)
    (owned / "old.md").write_text("legacy note", encoding="utf-8")  # pre-encryption
    (memdir / "other.md").write_text("unowned shared note", encoding="utf-8")

    view = memory().fn({"command": "view", "path": "old.md"})
    assert "legacy note" in view       # transparent plaintext fallback
    assert "not found" in memory().fn({"command": "view", "path": "other.md"})


@requires_crypto
def test_seal_to_str_roundtrip_and_passthrough():
    tok = car.seal_to_str("hello secret")
    assert tok.startswith("MVKAR1:")
    assert "hello secret" not in tok
    assert car.unseal_from_str(tok) == "hello secret"
    # Legacy plaintext (no marker) passes through unchanged.
    assert car.unseal_from_str("plain value") == "plain value"
    assert car.is_sealed_str(tok) and not car.is_sealed_str("plain value")


@requires_crypto
def test_unseal_many_from_str_reuses_one_key_resolution(monkeypatch):
    tokens = [car.seal_to_str(f"secret-{i}") for i in range(4)]
    original = car._load_or_create_key
    calls = 0

    def counted_load():
        nonlocal calls
        calls += 1
        return original()

    monkeypatch.setattr(car, "_load_or_create_key", counted_load)

    assert car.unseal_many_from_str([tokens[0], "legacy", *tokens[1:]]) == [
        "secret-0", "legacy", "secret-1", "secret-2", "secret-3",
    ]
    assert calls == 1


def test_unseal_from_str_treats_marker_collisions_as_plaintext():
    invalid_b64 = "MVKAR1:A"
    decoded_without_magic = "MVKAR1:" + base64.b64encode(b"Hello").decode("ascii")
    decoded_truncated_magic = "MVKAR1:" + base64.b64encode(car._MAGIC).decode("ascii")

    assert car.unseal_from_str(invalid_b64) == invalid_b64
    assert car.unseal_from_str(decoded_without_magic) == decoded_without_magic
    assert car.unseal_from_str(decoded_truncated_magic) == decoded_truncated_magic
    assert not car.is_sealed_str(invalid_b64)
    assert not car.is_sealed_str(decoded_without_magic)
    assert not car.is_sealed_str(decoded_truncated_magic)


@requires_crypto
def test_unseal_from_str_rejects_tampered_sealed_payload():
    blob = bytearray(car.seal(b"important"))
    blob[-1] ^= 0x01
    tok = "MVKAR1:" + base64.b64encode(bytes(blob)).decode("ascii")

    with pytest.raises(Exception):  # noqa: B017 - InvalidTag from the AEAD
        car.unseal_from_str(tok)


def test_world_db_reads_plaintext_marker_collisions(monkeypatch, tmp_path):
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    conv = wm.get_or_create_conversation("slack", "mallory")
    payloads = [
        "MVKAR1:A",
        "MVKAR1:" + base64.b64encode(b"Hello").decode("ascii"),
    ]
    wm.append_turn(conv.id, "user", payloads[0])
    wm.upsert_fact("user:mallory:note", payloads[1])

    assert wm.recent_turns(conv.id)[-1].content == payloads[0]
    assert wm.get_facts()["user:mallory:note"] == payloads[1]
    assert wm.get_fact("user:mallory:note") == payloads[1]
    assert wm.search_facts("user:mallory", "note")[0][1] == payloads[1]


@requires_crypto
def test_world_db_seals_turns_and_facts(monkeypatch, tmp_path):
    import sqlite3

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    conv = wm.get_or_create_conversation("slack", "alice")
    wm.append_turn(conv.id, "user", "my secret SSN 123-45-6789")
    wm.upsert_fact("user:alice:note", "card 4111111111111111")

    # The raw on-disk columns hold sealed tokens, not plaintext.
    raw_turn = sqlite3.connect(str(db)).execute("SELECT content FROM turns").fetchone()[0]
    raw_fact = sqlite3.connect(str(db)).execute("SELECT value FROM facts").fetchone()[0]
    assert raw_turn.startswith("MVKAR1:") and "123-45-6789" not in raw_turn
    assert raw_fact.startswith("MVKAR1:") and "4111111111111111" not in raw_fact

    # Reads transparently decrypt.
    assert wm.recent_turns(conv.id)[-1].content == "my secret SSN 123-45-6789"
    assert wm.get_facts()["user:alice:note"] == "card 4111111111111111"
    assert wm.get_fact("user:alice:note") == "card 4111111111111111"


def test_world_db_reads_legacy_plaintext(monkeypatch, tmp_path):
    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    # Write WITHOUT encryption (legacy rows; the fixture left at_rest off).
    wm = WorldModel(db)
    conv = wm.get_or_create_conversation("slack", "bob")
    wm.append_turn(conv.id, "user", "plain legacy turn")
    wm.upsert_fact("user:bob:n", "plain legacy fact")

    # Now turn encryption on; existing plaintext rows still read back fine.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    wm2 = WorldModel(db)
    assert wm2.recent_turns(conv.id)[-1].content == "plain legacy turn"
    assert wm2.get_fact("user:bob:n") == "plain legacy fact"


# --- per-tenant envelope encryption (opt-in) -------------------------------


def _per_tenant_env(monkeypatch, tmp_path, tenant="acme"):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)  # deterministic 32-byte KEK
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
    if tenant is not None:
        monkeypatch.setenv("MAVERICK_TENANT", tenant)
    else:
        monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    from maverick.tenant import kms as tenant_kms
    tenant_kms._clear_cache()


def test_per_tenant_off_by_default():
    assert car.per_tenant_at_rest() is False


def test_per_tenant_enabled_by_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
    assert car.per_tenant_at_rest() is True
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    assert car.per_tenant_at_rest() is False


def test_per_tenant_enabled_by_config(monkeypatch):
    monkeypatch.setattr(
        "maverick.config.load_config",
        lambda *a, **k: {"encryption": {"per_tenant": True}},
    )
    assert car.per_tenant_at_rest() is True


def test_tenant_magic_matches_tenant_kms():
    # The duplicated header constant must stay in lock-step with tenant_kms.
    from maverick.tenant import kms as tenant_kms
    assert car._TENANT_MAGIC == tenant_kms._SEAL_MAGIC


@requires_crypto
def test_per_tenant_seal_uses_tenant_envelope(monkeypatch, tmp_path):
    _per_tenant_env(monkeypatch, tmp_path, tenant="acme")
    blob = car.seal(b"tenant secret 42")
    assert blob[: len(car._TENANT_MAGIC)] == car._TENANT_MAGIC
    assert car.is_sealed(blob)
    assert b"tenant secret 42" not in blob
    assert car.unseal(blob) == b"tenant secret 42"


@requires_crypto
def test_per_tenant_seal_uses_raw_tenant_id_for_kms(monkeypatch, tmp_path):
    _per_tenant_env(monkeypatch, tmp_path, tenant="slack:alice")
    seen = {}

    def fake_seal_for_tenant(tenant_id, plaintext):
        seen["tenant_id"] = tenant_id
        seen["plaintext"] = plaintext
        return car._TENANT_MAGIC + b"fake"

    monkeypatch.setattr("maverick.tenant.kms.seal_for_tenant", fake_seal_for_tenant)
    assert car.seal(b"secret") == car._TENANT_MAGIC + b"fake"
    assert seen == {"tenant_id": "slack:alice", "plaintext": b"secret"}


@requires_crypto
def test_per_tenant_unseal_uses_raw_tenant_id_for_kms(monkeypatch, tmp_path):
    _per_tenant_env(monkeypatch, tmp_path, tenant="slack:alice")
    seen = {}

    def fake_unseal_for_tenant(tenant_id, blob):
        seen["tenant_id"] = tenant_id
        seen["blob"] = blob
        return b"secret"

    monkeypatch.setattr("maverick.tenant.kms.unseal_for_tenant", fake_unseal_for_tenant)
    blob = car._TENANT_MAGIC + b"fake"
    assert car.unseal(blob) == b"secret"
    assert seen == {"tenant_id": "slack:alice", "blob": blob}


@requires_crypto
def test_per_tenant_text_column_helpers(monkeypatch, tmp_path):
    _per_tenant_env(monkeypatch, tmp_path, tenant="acme")
    tok = car.seal_to_str("invoice total")
    assert tok.startswith("MVKAR1:")        # TEXT-column wrapper is unchanged
    assert "invoice total" not in tok
    assert car.is_sealed_str(tok)
    assert car.unseal_from_str(tok) == "invoice total"


@requires_crypto
def test_global_sealed_data_still_opens_after_per_tenant_on(monkeypatch, tmp_path):
    # Data sealed with the process-wide key (per-tenant OFF) must keep opening
    # once per-tenant mode is switched on — reads auto-detect by magic header.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", bytes(range(32)).hex())
    legacy = car.seal(b"sealed before the switch")
    assert legacy[: len(car._MAGIC)] == car._MAGIC

    monkeypatch.setenv("MAVERICK_KMS_KEK", "ab" * 32)
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "1")
    monkeypatch.setenv("MAVERICK_TENANT", "acme")
    from maverick.tenant import kms as tenant_kms
    tenant_kms._clear_cache()
    assert car.unseal(legacy) == b"sealed before the switch"


@requires_crypto
def test_one_tenant_cannot_open_anothers_data(monkeypatch, tmp_path):
    _per_tenant_env(monkeypatch, tmp_path, tenant="acme")
    blob = car.seal(b"acme only")
    from maverick.tenant import kms as tenant_kms
    # Re-pin to a different tenant; the GCM context no longer matches.
    monkeypatch.setenv("MAVERICK_TENANT", "beta")
    tenant_kms._clear_cache()
    with pytest.raises(car.EncryptionUnavailable):
        car.unseal(blob)


@requires_crypto
def test_world_db_seals_messages(monkeypatch, tmp_path):
    import sqlite3

    from maverick.world_model import WorldModel

    db = tmp_path / "world.db"
    wm = WorldModel(db)
    gid = wm.create_goal("g", "d")

    # A legacy plaintext message (encryption EXPLICITLY off — under the secure
    # default an unset flag means sealed) is stored as plaintext.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    wm.append_message(gid, "user", "findable plaintext token")
    raw_plain = sqlite3.connect(str(db)).execute(
        "SELECT content FROM messages WHERE role = 'user'"
    ).fetchone()[0]
    assert raw_plain == "findable plaintext token"

    # With encryption on, new message content is sealed on disk.
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    wm.append_message(gid, "assistant", "secret SSN 123-45-6789")
    raw = sqlite3.connect(str(db)).execute(
        "SELECT content FROM messages WHERE role = 'assistant'"
    ).fetchone()[0]
    assert raw.startswith("MVKAR1:") and "123-45-6789" not in raw


@requires_crypto
def test_world_db_seals_questions(monkeypatch, tmp_path):
    import sqlite3

    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    db = tmp_path / "world.db"
    wm = WorldModel(db)
    gid = wm.create_goal("g", "d")
    qid = wm.ask("secret question SSN 123-45-6789?", goal_id=gid)

    # The read path used by CLI / dashboard / MCP decrypts transparently.
    assert any("123-45-6789" in q.question for q in wm.open_questions(gid))

    wm.answer(qid, "secret answer 987-65-4321")

    # Raw on-disk columns are sealed.
    row = sqlite3.connect(str(db)).execute(
        "SELECT question, answer FROM questions"
    ).fetchone()
    assert row[0].startswith("MVKAR1:") and "123-45-6789" not in row[0]
    assert row[1].startswith("MVKAR1:") and "987-65-4321" not in row[1]

    # all_questions decrypts both fields.
    q = wm.all_questions(gid)[0]
    assert q.question == "secret question SSN 123-45-6789?"
    assert q.answer == "secret answer 987-65-4321"


def test_world_db_plaintext_marker_questions_do_not_crash_when_encryption_off(
    monkeypatch, tmp_path
):
    import base64

    from maverick.crypto_at_rest import _MAGIC, _NONCE_BYTES
    from maverick.world_model import WorldModel

    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    wm = WorldModel(tmp_path / "world.db")
    gid = wm.create_goal("g", "d")

    malformed_question = "MVKAR1:notbase64"
    qid = wm.ask(malformed_question, goal_id=gid)
    sealed_like_answer = "MVKAR1:" + base64.b64encode(
        _MAGIC + b"0" * (_NONCE_BYTES + 16)
    ).decode("ascii")
    assert wm.answer(qid, sealed_like_answer)

    q = wm.all_questions(gid)[0]
    assert q.question == malformed_question
    assert q.answer == sealed_like_answer


@requires_crypto
def test_unseal_wrong_key_or_tamper_raises_encryption_unavailable(monkeypatch, tmp_path):
    """unseal() honors its documented contract: a genuinely-sealed blob that
    can't be opened (tampered, wrong key, or truncated) raises
    EncryptionUnavailable, not a leaking cryptography InvalidTag / ValueError."""
    monkeypatch.setattr(car, "_KEY_PATH", tmp_path / "k.key")

    blob = car.seal(b"secret data")
    # Tampered GCM tag.
    bad = bytearray(blob)
    bad[-1] ^= 0xFF
    with pytest.raises(car.EncryptionUnavailable):
        car.unseal(bytes(bad))
    # Truncated (no room for nonce + tag).
    with pytest.raises(car.EncryptionUnavailable):
        car.unseal(car._MAGIC + b"short")
    # A clean round-trip still works.
    assert car.unseal(blob) == b"secret data"


# --- key rotation (additive keyring) ----------------------------------------

@requires_crypto
def test_no_keyring_keeps_v1_format():
    # With no keyring, seal() produces the legacy v1 header (no behaviour change).
    blob = car.seal(b"hello")
    assert blob[: len(car._MAGIC)] == car._MAGIC
    assert car.unseal(blob) == b"hello"


@requires_crypto
def test_rotation_keeps_old_data_readable(monkeypatch):
    # The data-safety guarantee: data sealed BEFORE rotation must still unseal
    # AFTER rotation (old key retained), and new writes use the new key (v2).
    old_blob = car.seal(b"pre-rotation secret")          # v1, under the legacy key
    assert old_blob[: len(car._MAGIC)] == car._MAGIC

    new_id = car.rotate_at_rest_key()
    assert len(new_id) == car._KEYID_BYTES * 2           # hex of the 8-byte id

    # Old v1 data still opens (legacy key is still resolvable).
    assert car.unseal(old_blob) == b"pre-rotation secret"

    # New writes are v2 under the rotated key, and round-trip.
    new_blob = car.seal(b"post-rotation secret")
    assert new_blob[: len(car._MAGIC_V2)] == car._MAGIC_V2
    assert car.unseal(new_blob) == b"post-rotation secret"


@requires_crypto
def test_named_rotation_recovers_original_key_without_another_change():
    old = car.seal(b"existing private work")
    reviewed = car.key_rotation_version()
    operation = "a" * 64
    identity = car.rotate_at_rest_key(operation_id=operation, expected_version=reviewed)
    assert car.rotation_receipt(operation) == identity
    assert car.rotate_at_rest_key(operation_id=operation, expected_version=reviewed) == identity
    assert len(list(car._keyring_dir().glob("*.key"))) == 1
    assert car.unseal(old) == b"existing private work"
    assert file_lock.private_path_is_restricted(car._rotation_intent(operation))
    with pytest.raises(car.EncryptionUnavailable, match="changed after review"):
        car.rotate_at_rest_key(operation_id="b" * 64, expected_version=reviewed)
    assert not car._rotation_intent("b" * 64).exists()


@requires_crypto
def test_a_key_rewritten_in_place_with_its_time_restored_changes_the_reviewed_version():
    # The review token is taken from stat facts only, and an in-place rewrite
    # that keeps the size and restores the modification time changes none of
    # them (on Windows st_ctime is the creation time, so it cannot show it either).
    import os

    car.seal(b"existing private work")  # the legacy key
    car.rotate_at_rest_key()
    key = next(car._keyring_dir().glob("*.key"))
    reviewed = car.key_rotation_version()
    before = os.stat(key)
    key.write_text("ab" * 32, encoding="utf-8")  # another key, the same size
    os.utime(key, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert car.key_rotation_version() != reviewed
    keys = sorted(car._keyring_dir().glob("*.key"))
    with pytest.raises(car.EncryptionUnavailable, match="changed after review"):
        car.rotate_at_rest_key(expected_version=reviewed)
    assert sorted(car._keyring_dir().glob("*.key")) == keys


def test_explicit_postgres_refuses_node_local_key_rotation(monkeypatch):
    monkeypatch.setenv("MAVERICK_GOVERNED_RECORDS_BACKEND", "postgres")
    monkeypatch.setenv("MAVERICK_REPLICA_COUNT", "1")
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")

    assert car.shared_authority_key_identity_required() is True
    with pytest.raises(car.EncryptionUnavailable, match="externally coordinated"):
        car.rotate_at_rest_key()


@requires_crypto
def test_two_rotations_all_generations_readable():
    import time

    car.rotate_at_rest_key()
    blob1 = car.seal(b"gen-1")
    time.sleep(0.01)  # ensure the second key is unambiguously newest (active)
    car.rotate_at_rest_key()
    blob2 = car.seal(b"gen-2")

    # Both generations decrypt -- each v2 blob names its own key-id, so a
    # superseded key still opens the data it sealed.
    assert car.unseal(blob1) == b"gen-1"
    assert car.unseal(blob2) == b"gen-2"


@requires_crypto
def test_v2_blob_with_unknown_keyid_fails_closed():
    car.rotate_at_rest_key()
    blob = car.seal(b"x")
    # Corrupt the embedded key-id so no key resolves -> fail closed.
    body = bytearray(blob)
    start = len(car._MAGIC_V2)
    for i in range(start, start + car._KEYID_BYTES):
        body[i] ^= 0xFF
    with pytest.raises(car.EncryptionUnavailable):
        car.unseal(bytes(body))


@requires_crypto
def test_rotated_key_file_is_private(monkeypatch):
    car.rotate_at_rest_key()
    for p in car._keyring_dir().glob("*.key"):
        assert file_lock.private_path_is_restricted(p), f"key is not private: {p}"


@requires_crypto
def test_rotation_secures_keyring_parent_with_permissive_umask():
    old_umask = car.os.umask(0)
    try:
        car.rotate_at_rest_key()
    finally:
        car.os.umask(old_umask)

    assert file_lock.private_path_is_restricted(car._KEY_PATH.parent, 0o700)
    assert file_lock.private_path_is_restricted(car._keyring_dir(), 0o700)


@requires_crypto
def test_rotation_repairs_existing_writable_keyring_parent():
    car._KEY_PATH.parent.mkdir(parents=True)
    car._KEY_PATH.parent.chmod(0o777)

    car.rotate_at_rest_key()

    assert file_lock.private_path_is_restricted(car._KEY_PATH.parent, 0o700)
    assert file_lock.private_path_is_restricted(car._keyring_dir(), 0o700)


# --- key durability: generation warning + escrow backup -----------------------

def test_keygen_logs_backup_warning(monkeypatch, caplog):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    import logging
    with caplog.at_level(logging.WARNING, logger="maverick.crypto_at_rest"):
        car._load_or_create_key()
    assert any("only way to decrypt" in r.message or "backup-key" in r.message
               for r in caplog.records)


def test_backup_key_material_copies_primary_and_keyring(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    car._load_or_create_key()              # create the primary key
    keyring_key = car._keyring_dir() / "rotation.key"
    keyring_key.parent.mkdir(parents=True)
    keyring_key.write_text((b"r" * 32).hex(), encoding="utf-8")
    keyring_key.chmod(0o600)
    dest = tmp_path / "escrow"
    written = car.backup_key_material(dest)
    names = sorted(p.name for p in written)
    assert "at_rest.key" in names
    assert any(n.endswith(".key") and n != "at_rest.key" for n in names)
    assert all(file_lock.private_path_is_restricted(p) for p in written)
    assert file_lock.private_path_is_restricted(dest, 0o700)
    # The escrowed primary key matches the live one (usable for recovery).
    assert (dest / "at_rest.key").read_text() == car._KEY_PATH.read_text()


def test_backup_key_material_refuses_existing_destination_file(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    car._load_or_create_key()
    dest = tmp_path / "escrow"
    dest.mkdir()
    existing = dest / "at_rest.key"
    existing.write_text("attacker controlled", encoding="utf-8")

    with pytest.raises(car.EncryptionUnavailable, match="cannot copy key"):
        car.backup_key_material(dest)

    assert existing.read_text(encoding="utf-8") == "attacker controlled"


def test_backup_key_material_refuses_destination_symlink(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    car._load_or_create_key()
    dest = tmp_path / "escrow"
    dest.mkdir()
    leaked = tmp_path / "leaked.key"
    leaked.write_text("attacker controlled", encoding="utf-8")
    try:
        (dest / "at_rest.key").symlink_to(leaked)
    except OSError as exc:
        if car.os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege is unavailable")
        raise

    with pytest.raises(car.EncryptionUnavailable, match="cannot copy key"):
        car.backup_key_material(dest)

    assert leaked.read_text(encoding="utf-8") == "attacker controlled"


def test_backup_key_material_refuses_directory_symlink(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    car._load_or_create_key()
    real_dest = tmp_path / "real-escrow"
    real_dest.mkdir()
    dest = tmp_path / "escrow-link"
    try:
        dest.symlink_to(real_dest, target_is_directory=True)
    except OSError as exc:
        if car.os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink privilege is unavailable")
        raise

    with pytest.raises(car.EncryptionUnavailable, match="cannot prepare key backup dir"):
        car.backup_key_material(dest)

    assert not (real_dest / "at_rest.key").exists()


def test_backup_key_material_errors_when_no_key(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    with pytest.raises(car.EncryptionUnavailable, match="no at-rest key material"):
        car.backup_key_material(tmp_path / "escrow")


# ---- the on-disk key path is resolved at call time, never at import ---------


def test_importing_the_module_does_not_resolve_the_data_dir():
    """Regression for the 2026-09-10 boot outage: a module-level
    ``data_dir(...)`` binding ran DURING import, re-entered config loading
    (tenant -> client id -> load_config -> unseal overlay -> import this
    module) and died on the half-initialised module. The path must be lazy."""
    import subprocess
    import sys

    probe = (
        "import maverick.crypto_at_rest as car\n"
        "assert car._KEY_PATH is None, car._KEY_PATH\n"
        "assert car._key_path().name == 'at_rest.key'\n"
    )
    r = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_key_path_is_deployment_wide_not_request_scoped(tmp_path, monkeypatch):
    """One key per deployment: a request bound to a workspace must seal with
    the same key every other scope reads with (a row sealed inside a
    tenant-bound request was unreadable to the owner-invite flow otherwise).
    MAVERICK_TENANT, a deployment-level binding, still picks the directory."""
    from maverick.paths import reset_tenant, set_tenant

    home = tmp_path / "home"
    monkeypatch.setenv("MAVERICK_HOME", str(home))
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_CLIENT_ID", raising=False)
    monkeypatch.setattr(car, "_KEY_PATH", None)   # the production default

    unbound = car._key_path()
    tok = set_tenant("tenant-a")
    try:
        path_a = car._key_path()
    finally:
        reset_tenant(tok)
    tok = set_tenant("tenant-b")
    try:
        path_b = car._key_path()
    finally:
        reset_tenant(tok)
    assert unbound == path_a == path_b == home / "keys" / "at_rest.key"

    monkeypatch.setenv("MAVERICK_TENANT", "tenant-env")
    bound = car._key_path()
    assert "tenant-env" in str(bound) and bound.name == "at_rest.key"
    tok = set_tenant("tenant-a")
    try:
        assert car._key_path() == bound
    finally:
        reset_tenant(tok)


def test_key_path_override_still_wins(tmp_path, monkeypatch):
    # The test-suite convention (and an operator escape hatch): a pinned
    # module attribute takes precedence over tenant resolution.
    pinned = tmp_path / "pinned" / "at_rest.key"
    monkeypatch.setattr(car, "_KEY_PATH", pinned)
    assert car._key_path() == pinned
    assert car._keyring_dir() == pinned.parent / "at_rest.d"

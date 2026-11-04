"""Migration governance: checksum immutability, head parity, additive-only.

The guard test (real ladders vs the committed lock) keeps migrations.lock.json
honest; the rest exercise the logic on synthetic ladders."""
from __future__ import annotations

import pytest
from maverick import migration_governance as mg

# ---- checksum -------------------------------------------------------------

def test_checksum_is_whitespace_stable_but_content_sensitive():
    a = ["ALTER TABLE goals ADD COLUMN x TEXT"]
    b = ["  ALTER   TABLE goals\n  ADD COLUMN x TEXT ;  "]  # reformatted, same SQL
    c = ["ALTER TABLE goals ADD COLUMN y TEXT"]            # different column
    assert mg.version_checksum(a) == mg.version_checksum(b)
    assert mg.version_checksum(a) != mg.version_checksum(c)


def test_checksum_is_order_significant():
    one = ["CREATE TABLE a (id int)", "CREATE TABLE b (id int)"]
    two = ["CREATE TABLE b (id int)", "CREATE TABLE a (id int)"]
    assert mg.version_checksum(one) != mg.version_checksum(two)


# ---- structural checks ----------------------------------------------------

def test_head_must_equal_declared_constant():
    # SQLite ladder maxing at v2 while the declared SCHEMA_VERSION is 23.
    lads = {"sqlite": {1: [], 2: []}, "postgres": {1: [], 2: []}}
    probs = mg.structural_problems(lads)
    assert any("declared SCHEMA_VERSION" in p for p in probs)


def test_cross_backend_head_mismatch_flagged():
    lads = {"sqlite": {1: [], 23: []}, "postgres": {1: [], 22: []}}
    probs = mg.structural_problems(lads)
    assert any("backend head mismatch" in p for p in probs)


def test_orphan_postgres_version_flagged_but_base_v1_exempt():
    # v9 exists only in PG -> flagged; v1 (base seed) is exempt.
    lads = {"sqlite": {1: [], 2: [], 23: []}, "postgres": {1: [], 9: [], 23: []}}
    probs = mg.structural_problems(lads)
    assert any("no sqlite counterpart" in p and "9" in p for p in probs)
    assert not any("[1]" in p for p in probs)


# ---- lock / immutability --------------------------------------------------

def _lock_from(lads):
    return mg.fingerprint(lads)


def test_editing_a_released_migration_fails():
    lads = {"sqlite": {1: ["CREATE TABLE a (id int)"]}, "postgres": {1: []}}
    lock = _lock_from(lads)
    lads["sqlite"][1] = ["CREATE TABLE a (id int, extra text)"]  # edit shipped v1
    probs = mg.lock_problems(lock, lads)
    assert any("checksum changed" in p for p in probs)


def test_removing_a_released_migration_fails():
    lads = {"sqlite": {1: [], 2: ["CREATE TABLE b (id int)"]}, "postgres": {1: []}}
    lock = _lock_from(lads)
    del lads["sqlite"][2]
    probs = mg.lock_problems(lock, lads)
    assert any("gone from the ladder" in p for p in probs)


def test_new_additive_version_prompts_regen_but_is_not_an_error():
    lads = {"sqlite": {1: []}, "postgres": {1: []}}
    lock = _lock_from(lads)
    lads["sqlite"][2] = ["ALTER TABLE goals ADD COLUMN z TEXT"]  # additive add
    probs = mg.lock_problems(lock, lads)
    assert any("run `--regen`" in p for p in probs)
    assert not any("destructive" in p or "checksum changed" in p for p in probs)


def test_new_destructive_version_is_rejected():
    lads = {"sqlite": {1: []}, "postgres": {1: []}}
    lock = _lock_from(lads)
    lads["sqlite"][2] = ["ALTER TABLE goals DROP COLUMN z"]  # non-additive
    probs = mg.lock_problems(lock, lads)
    assert any("destructive" in p for p in probs)


@pytest.mark.parametrize("stmt", [
    "ALTER TABLE goals DROP CONSTRAINT fk_parent",     # constraint drop
    'ALTER TABLE "my table" RENAME TO archived',       # quoted-identifier rename
    "DROP INDEX idx_goals_status",                     # index drop
    "DROP VIEW goal_summary",                           # view drop
    "drop   table   goals",                            # lowercase + extra spaces
])
def test_destructive_variants_are_caught(stmt):
    # Regression: these non-additive shapes slipped past the original regexes.
    lads = {"sqlite": {1: []}, "postgres": {1: []}}
    lock = _lock_from(lads)
    lads["sqlite"][2] = [stmt]
    probs = mg.lock_problems(lock, lads)
    assert any("destructive" in p for p in probs), f"missed destructive: {stmt!r}"


def test_additive_statements_are_not_false_positives():
    # Additive shapes must NOT trip the destructive gate.
    lads = {"sqlite": {1: []}, "postgres": {1: []}}
    lock = _lock_from(lads)
    lads["sqlite"][2] = [
        "ALTER TABLE goals ADD COLUMN note TEXT",
        "CREATE INDEX IF NOT EXISTS idx_x ON goals(status)",
        "CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY)",
    ]
    probs = mg.lock_problems(lock, lads)
    assert not any("destructive" in p for p in probs)


def test_clean_ladder_against_its_own_lock_has_no_problems():
    lads = {"sqlite": {1: [], 2: ["ALTER TABLE g ADD COLUMN c TEXT"]},
            "postgres": {1: []}}
    lock = _lock_from(lads)
    assert mg.lock_problems(lock, lads) == []


# ---- regen may not launder a destructive new version ----------------------

def test_regen_refuses_destructive_new_version():
    # The additive-only gate only inspects not-yet-locked versions, so --regen
    # must refuse to write a destructive NEW version into the lock (which would
    # grandfather it into immutability, never to be re-judged).
    lads = {"sqlite": {1: [], 2: ["ALTER TABLE g DROP COLUMN z"]}, "postgres": {1: []}}
    existing = mg.fingerprint({"sqlite": {1: []}, "postgres": {1: []}})  # v2 not locked
    blockers = mg.regen_blockers(lads, existing)
    assert any("destructive" in b and "v2" in b for b in blockers)


def test_regen_allows_additive_new_version():
    lads = {"sqlite": {1: [], 2: ["ALTER TABLE g ADD COLUMN z TEXT"]}, "postgres": {1: []}}
    existing = mg.fingerprint({"sqlite": {1: []}, "postgres": {1: []}})
    assert mg.regen_blockers(lads, existing) == []


def test_reviewed_learning_key_replacement_is_exactly_pinned():
    from maverick.learning_store_pg_schema import LEARNING_TENANT_MIGRATION

    existing = mg.fingerprint({"sqlite": {1: []}, "postgres": {1: []}})
    lads = {"sqlite": {1: [], 39: []}, "postgres": {1: [], 39: LEARNING_TENANT_MIGRATION}}
    assert mg._destructive_statements(LEARNING_TENANT_MIGRATION)
    assert mg.regen_blockers(lads, existing) == []
    assert all("destructive" not in item for item in mg.lock_problems(existing, lads))


@pytest.mark.parametrize("change", ["append_drop", "modify_sql", "different_version", "different_backend"])
def test_learning_key_exception_cannot_admit_other_destructive_ddl(change):
    from maverick.learning_store_pg_schema import LEARNING_TENANT_MIGRATION

    statements = list(LEARNING_TENANT_MIGRATION)
    backend, version = "postgres", 39
    if change == "append_drop":
        statements.append("DROP TABLE goals")
    elif change == "modify_sql":
        statements[-1] = statements[-1].replace("DROP CONSTRAINT", "DROP COLUMN")
    elif change == "different_version":
        version = 40
    else:
        backend = "sqlite"
    lads = {"sqlite": {1: []}, "postgres": {1: []}}
    existing = mg.fingerprint(lads)
    lads[backend][version] = statements
    assert any("destructive" in item for item in mg.regen_blockers(lads, existing))
    assert any("destructive" in item for item in mg.lock_problems(existing, lads))


def test_learning_key_exception_does_not_repin_an_existing_checksum(tmp_path, monkeypatch):
    from maverick.learning_store_pg_schema import LEARNING_TENANT_MIGRATION

    path = tmp_path / "migrations.lock.json"
    old = {"sqlite": {1: [], 39: []}, "postgres": {1: [], 39: ["SELECT 1"]}}
    import json

    path.write_text(json.dumps(mg.fingerprint(old)))
    before = path.read_bytes()
    current = {"sqlite": {1: [], 39: []}, "postgres": {1: [], 39: LEARNING_TENANT_MIGRATION}}
    monkeypatch.setattr(mg, "lock_path", lambda: path)
    monkeypatch.setattr(mg, "ladders", lambda: current)
    with pytest.raises(ValueError, match="silently re-pin"):
        mg.write_lock()
    assert path.read_bytes() == before


# ---- the base SCHEMA is governed by the ratchet ---------------------------

def test_base_schema_is_fingerprinted():
    lads = mg.ladders()
    assert mg._BASE_VERSION in lads["sqlite"]
    assert lads["sqlite"][mg._BASE_VERSION]          # the base SCHEMA string
    # and the committed lock pins it
    lock = mg.load_lock()
    assert str(mg._BASE_VERSION) in lock["checksums"]["sqlite"]


def test_editing_base_schema_is_caught_by_the_ratchet():
    # An edit to a base-schema table definition must change the v1 checksum and
    # fail the immutability check -- previously the base SCHEMA was never
    # fingerprinted, so those tables were ungoverned.
    lads = mg.ladders()
    lock = mg.load_lock()
    lads["sqlite"][mg._BASE_VERSION] = (
        list(lads["sqlite"][mg._BASE_VERSION]) + ["ALTER TABLE goals ADD COLUMN sneaky TEXT"])
    probs = mg.lock_problems(lock, lads)
    assert any("checksum changed" in p and "v1" in p for p in probs)


# ---- write_lock must not silently re-pin a released version -------

def test_write_lock_refuses_to_silently_repin_a_released_version(tmp_path, monkeypatch):
    # regen_blockers() only inspects versions ABSENT from the lock, so an
    # edit to an already-released migration followed by --regen used to
    # succeed and quietly rewrite that version's checksum into the lock --
    # lock_problems() flags the edit right up until the moment --regen
    # launders it, which is exactly the bypass the immutability rule exists
    # to prevent.
    fake_lock_path = tmp_path / "migrations.lock.json"
    monkeypatch.setattr(mg, "lock_path", lambda: fake_lock_path)
    lads = {"sqlite": {1: ["CREATE TABLE a (id int)"]}, "postgres": {1: []}}
    monkeypatch.setattr(mg, "ladders", lambda: lads)

    mg.write_lock()  # bootstrap the initial lock
    original = fake_lock_path.read_text()

    lads["sqlite"][1] = ["CREATE TABLE a (id int, extra text)"]  # edit shipped v1

    with pytest.raises(ValueError, match="silently re-pin"):
        mg.write_lock()
    assert fake_lock_path.read_text() == original  # lock file untouched


def test_write_lock_force_repin_requires_the_exact_token(tmp_path, monkeypatch):
    fake_lock_path = tmp_path / "migrations.lock.json"
    monkeypatch.setattr(mg, "lock_path", lambda: fake_lock_path)
    lads = {"sqlite": {1: ["CREATE TABLE a (id int)"]}, "postgres": {1: []}}
    monkeypatch.setattr(mg, "ladders", lambda: lads)
    mg.write_lock()

    lads["sqlite"][1] = ["CREATE TABLE a (id int, extra text)"]

    # A force_repin for the WRONG version must not let a different version's
    # re-pin through.
    with pytest.raises(ValueError, match="silently re-pin"):
        mg.write_lock(force_repin={"sqlite:2"})

    # The correct token is a deliberate, reviewable acknowledgment -- it
    # succeeds and actually updates the checksum.
    import json
    path = mg.write_lock(force_repin={"sqlite:1"})
    new_lock = json.loads(path.read_text())
    assert (new_lock["checksums"]["sqlite"]["1"]
            == mg.version_checksum(lads["sqlite"][1]))


def test_repin_blockers_empty_for_a_brand_new_additive_version():
    lads = {"sqlite": {1: [], 2: ["ALTER TABLE g ADD COLUMN z TEXT"]},
            "postgres": {1: []}}
    existing = mg.fingerprint({"sqlite": {1: []}, "postgres": {1: []}})
    assert mg.repin_blockers(lads, existing) == []


def test_repin_blockers_flags_an_edited_released_version():
    lads = {"sqlite": {1: ["CREATE TABLE a (id int)"]}, "postgres": {1: []}}
    existing = mg.fingerprint(lads)
    lads["sqlite"][1] = ["CREATE TABLE a (id int, extra text)"]
    blockers = mg.repin_blockers(lads, existing)
    assert any(b.startswith("sqlite:1 ") for b in blockers)


# ---- guard: real ladders match the committed lock -------------------------

def test_real_ladders_pass_governance():
    # If this fails, a migration was added/edited without regenerating the lock:
    #   python -m maverick.migration_governance --regen
    assert mg.validate() == [], mg.validate()

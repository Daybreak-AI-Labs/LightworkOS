"""Migration governance — the Alembic-grade ratchet over the world-model
migration ladders.

``schema_migrations.py`` lints a single ladder for online/offline safety. This
module governs the *integrity and evolution* of BOTH backend ladders together —
SQLite (``world_model.MIGRATIONS`` + ``SCHEMA_VERSION``) and Postgres
(``world_model_backends.postgres.MIGRATIONS`` + ``_PG_SCHEMA_VERSION``) — the way
Alembic governs a revision graph:

* **Immutability of released migrations.** Each version's statements are
  fingerprinted (sha256). A committed lock manifest (``migrations.lock.json``)
  pins those fingerprints. CI fails if an *already-released* version's checksum
  changes — editing a shipped migration silently diverges every DB that already
  applied the old text. Appending a NEW version is fine; it shows up as a
  reviewable lock diff (regenerate with ``--regen``).
* **Cross-backend head parity.** Both ladders must reach the same head and that
  head must equal each backend's declared ``SCHEMA_VERSION`` constant, so the
  two backends can never silently diverge in schema level.
* **Subset coherence.** The Postgres ladder folds the early SQLite versions into
  its consolidated base (v1), so every Postgres version must also exist in the
  SQLite ladder; a Postgres version with no SQLite counterpart is a drift bug.
* **Additive-only for new versions.** A version added since the lock may not
  carry a destructive statement (``DROP TABLE``/``DROP COLUMN``/``RENAME``):
  those break a rolling deploy where old replicas still read the old schema.
  Released versions are grandfathered (governed by the checksum, not re-judged).
  A reviewed v39 learning-key constraint replacement is pinned separately by
  backend, version and full SQL digest; it does not authorize other DDL.
  The v49 retirement of unused derived message-search objects is likewise
  pinned exactly; authoritative message/history tables are not retired.

Pure and offline (no DB). Surfaced as ``python -m maverick.migration_governance
--ci`` (CI gate) and ``--regen`` (rewrite the lock after an intentional add).
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

# Destructive shapes that must not appear in a NEW migration: they break a
# rolling deploy (old replicas still expect the column/table) and are
# non-additive. Grandfathered for already-released versions via the lock.
# The base-schema seed. SQLite applies its base CREATE at db creation and starts
# its MIGRATIONS dict at v2; Postgres carries the consolidated base as migration
# v1. So v1 legitimately exists in the PG ladder with no SQLite MIGRATIONS entry
# — exclude it from the cross-backend subset check (per-backend checksums still
# pin it independently).
_BASE_VERSION = 1

# Reviewed data-preserving exception: v39 replaces only validated global
# learning-table primary keys after tenant/null uniqueness is installed. The
# full normalized SQL digest pins the entire locked, fail-closed migration;
# neither arbitrary constraint drops nor a modified v39 inherit approval.
# See docs/operations/learning-store-tenant-keys.md. Released-lock immutability
# and explicit old-checksum repinning remain independent checks.
_REVIEWED_CONSTRAINT_REPLACEMENTS = {
    "postgres:39": "50f7c13c96f0f914267ccabc8dff7ba5e15be4cf5572c398fa3f570c39b0e9dc",  # pragma: allowlist secret - reviewed migration SQL digest
}

# No current reader uses these derived objects. The reviewed offline upgrade
# retires only their exact SQL, never authoritative messages/history or other
# objects. This is not an exception for rolling/custom-SQL compatibility.
_REVIEWED_DERIVED_SEARCH_RETIREMENTS = {
    "sqlite:49": "3dd39924baa912f21d0203217580cddb95ed900f979dfb690f76f94c557921d4",  # pragma: allowlist secret - reviewed migration SQL digest
    "postgres:49": "320d4e8e995ae87bd64053e0c104b47b2a8728c3838e6da283cec3044126d0ee",  # pragma: allowlist secret - reviewed migration SQL digest
}

_DESTRUCTIVE = (
    # DROP of any schema object an old replica may still depend on. CONSTRAINT
    # and the rebuildable objects (INDEX/VIEW/TRIGGER/SEQUENCE) are non-additive
    # in a rolling deploy and were missed before.
    re.compile(r"\bDROP\s+(TABLE|COLUMN|CONSTRAINT|INDEX|VIEW|TRIGGER|SEQUENCE)\b",
               re.IGNORECASE),
    # Any RENAME under ALTER TABLE. Match RENAME anywhere after ALTER TABLE
    # (not `ALTER TABLE \S+ RENAME`) so a quoted/bracketed identifier containing
    # a space -- ALTER TABLE "my table" RENAME TO y -- can't slip past \S+.
    re.compile(r"\bALTER\s+TABLE\b[^;]*\bRENAME\b", re.IGNORECASE | re.DOTALL),
    re.compile(r"\bRENAME\s+COLUMN\b", re.IGNORECASE),
)


def lock_path() -> Path:
    """The committed lock manifest, next to this module."""
    return Path(__file__).with_name("migrations.lock.json")


def _normalize(statement: str) -> str:
    """Whitespace-stable form of a statement so cosmetic reformatting (indent,
    trailing semicolon) does not move a checksum, but a real SQL change does."""
    return re.sub(r"\s+", " ", statement.strip().rstrip(";")).strip()


def version_checksum(statements: list[str]) -> str:
    """Stable sha256 (16 hex chars) over a version's normalized statements,
    order-significant."""
    joined = "\n".join(_normalize(s) for s in statements)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def _sqlite_ladder() -> dict[int, list[str]]:
    from .world_model import MIGRATIONS, SCHEMA
    # Fingerprint the base SCHEMA as version _BASE_VERSION so the ratchet governs
    # the tables it -- and only it -- creates (share_links, signoffs, artifacts,
    # projects, halt, provider_spend, harness_*, ...). The MIGRATIONS dict starts
    # at v2, so without this an edit to a base table definition changed the schema
    # with no checksum to catch it -- those tables were entirely ungoverned.
    ladder: dict[int, list[str]] = {_BASE_VERSION: [SCHEMA]}
    ladder.update({int(v): list(stmts) for v, stmts in MIGRATIONS.items()})
    return ladder


def _postgres_ladder() -> dict[int, list[str]]:
    from .world_model_backends.postgres import MIGRATIONS
    return {int(v): list(stmts) for v, stmts in MIGRATIONS}


def _declared_heads() -> dict[str, int]:
    from .world_model import SCHEMA_VERSION
    from .world_model_backends.postgres import _PG_SCHEMA_VERSION
    return {"sqlite": int(SCHEMA_VERSION), "postgres": int(_PG_SCHEMA_VERSION)}


def ladders() -> dict[str, dict[int, list[str]]]:
    return {"sqlite": _sqlite_ladder(), "postgres": _postgres_ladder()}


def fingerprint(lads: dict[str, dict[int, list[str]]] | None = None) -> dict:
    """``{"heads": {...}, "checksums": {backend: {version: cksum}}}`` — the
    canonical, JSON-stable description of both ladders."""
    lads = lads if lads is not None else ladders()
    checksums = {
        backend: {str(v): version_checksum(stmts) for v, stmts in sorted(steps.items())}
        for backend, steps in lads.items()
    }
    heads = {backend: max(steps) if steps else 0 for backend, steps in lads.items()}
    return {"heads": heads, "checksums": checksums}


def structural_problems(lads: dict[str, dict[int, list[str]]] | None = None) -> list[str]:
    """Backend-coherence checks that don't need the lock: head parity vs the
    declared constants, cross-backend head equality, and PG ⊆ SQLite."""
    lads = lads if lads is not None else ladders()
    problems: list[str] = []
    declared = _declared_heads()
    sqlite_v = set(lads["sqlite"])
    pg_v = set(lads["postgres"])

    for backend, steps in lads.items():
        if not steps:
            problems.append(f"{backend}: migration ladder is empty")
            continue
        head = max(steps)
        if head != declared[backend]:
            problems.append(
                f"{backend}: head migration v{head} != declared SCHEMA_VERSION "
                f"{declared[backend]} (bump the constant with the migration)")

    if lads["sqlite"] and lads["postgres"] and max(sqlite_v) != max(pg_v):
        problems.append(
            f"backend head mismatch: sqlite v{max(sqlite_v)} != postgres "
            f"v{max(pg_v)} (the two backends have diverged in schema level)")

    orphan_pg = sorted(pg_v - sqlite_v - {_BASE_VERSION})
    if orphan_pg:
        problems.append(
            f"postgres versions with no sqlite counterpart: {orphan_pg} "
            "(every PG migration needs a matching SQLite ladder entry)")
    return problems


def _destructive_statements(statements: list[str]) -> list[str]:
    hits = []
    for stmt in statements:
        if any(p.search(stmt) for p in _DESTRUCTIVE):
            hits.append(_normalize(stmt)[:70])
    return hits


def _reviewed_destructive_migration(backend: str, version: str, statements: list[str]) -> bool:
    key = f"{backend}:{version}"
    expected = (_REVIEWED_CONSTRAINT_REPLACEMENTS.get(key)
                or _REVIEWED_DERIVED_SEARCH_RETIREMENTS.get(key))
    if expected is None:
        return False
    actual = hashlib.sha256("\n".join(_normalize(s) for s in statements).encode("utf-8")).hexdigest()
    return actual == expected


def lock_problems(
    lock: dict | None, lads: dict[str, dict[int, list[str]]] | None = None,
) -> list[str]:
    """Immutability + additive-only checks against the committed lock.

    A changed checksum on a version present in the lock = an edit to a released
    migration (hard fail). A version absent from the lock is *new*: allowed, but
    it must be additive (no destructive statement) and the operator must
    regenerate the lock so the add is reviewed.
    """
    lads = lads if lads is not None else ladders()
    fp = fingerprint(lads)
    if not lock:
        return ["no migrations.lock.json — run `--regen` to create the baseline"]
    locked = lock.get("checksums", {})
    problems: list[str] = []
    pending_regen = False

    for backend, current in fp["checksums"].items():
        prior = locked.get(backend, {})
        for version, cksum in current.items():
            if version in prior:
                if prior[version] != cksum:
                    problems.append(
                        f"{backend}: migration v{version} checksum changed "
                        f"({prior[version]} -> {cksum}) — a released migration was "
                        "edited; released migrations are immutable, add a new "
                        "version instead")
            else:
                pending_regen = True
                destructive = _destructive_statements(lads[backend][int(version)])
                if destructive and not _reviewed_destructive_migration(backend, version, lads[backend][int(version)]):
                    problems.append(
                        f"{backend}: new migration v{version} has destructive "
                        f"statement(s) {destructive}; new migrations must be "
                        "additive (old replicas still read the old schema)")
        for version in prior:
            if version not in current:
                problems.append(
                    f"{backend}: migration v{version} is in the lock but gone "
                    "from the ladder — released migrations may not be removed")
    if pending_regen and not problems:
        problems.append(
            "new migration version(s) detected — run `--regen` and commit "
            "migrations.lock.json so the addition is reviewed")
    return problems


def validate() -> list[str]:
    lads = ladders()
    return structural_problems(lads) + lock_problems(load_lock(), lads)


def load_lock() -> dict | None:
    try:
        return json.loads(lock_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def regen_blockers(
    lads: dict[str, dict[int, list[str]]] | None = None,
    existing_lock: dict | None = None,
) -> list[str]:
    """New versions (absent from ``existing_lock``) that carry a destructive
    statement. ``--regen`` refuses these: the additive-only gate in
    :func:`lock_problems` only inspects not-yet-locked versions, so writing a
    destructive new migration into the lock unchecked would grandfather it into
    immutability and it would never be re-judged."""
    lads = lads if lads is not None else ladders()
    if existing_lock is None:
        existing_lock = load_lock()
    locked = (existing_lock or {}).get("checksums", {})
    fp = fingerprint(lads)
    blockers: list[str] = []
    for backend, current in fp["checksums"].items():
        prior = locked.get(backend, {})
        for version in current:
            if version not in prior:
                dead = _destructive_statements(lads[backend][int(version)])
                if dead and not _reviewed_destructive_migration(backend, version, lads[backend][int(version)]):
                    blockers.append(
                        f"{backend}: new migration v{version} has destructive "
                        f"statement(s) {dead}")
    return blockers


def repin_blockers(
    lads: dict[str, dict[int, list[str]]] | None = None,
    existing_lock: dict | None = None,
) -> list[str]:
    """Already-locked versions whose checksum would change on the next write.

    ``regen_blockers`` only inspects versions ABSENT from the lock, so
    editing a released migration and running ``--regen`` re-pinned it with a
    green CI afterward -- the exact event the immutability rule exists to
    catch (``lock_problems`` flags the edit before regen, but nothing stopped
    ``write_lock`` from silently making that checksum the new baseline).
    """
    lads = lads if lads is not None else ladders()
    if existing_lock is None:
        existing_lock = load_lock()
    locked = (existing_lock or {}).get("checksums", {})
    fp = fingerprint(lads)
    repins: list[str] = []
    for backend, current in fp["checksums"].items():
        prior = locked.get(backend, {})
        for version, cksum in current.items():
            if version in prior and prior[version] != cksum:
                repins.append(
                    f"{backend}:{version} ({prior[version]} -> {cksum})")
    return repins


def write_lock(*, force_repin: set[str] | None = None) -> Path:
    """Rewrite migrations.lock.json from the current ladders.

    ``force_repin`` is the set of ``"backend:version"`` tokens (e.g.
    ``"sqlite:7"``) the caller has explicitly reviewed and wants re-pinned
    despite already being released -- anything else in :func:`repin_blockers`
    still refuses. Empty by default, so an accidental edit-then-regen of a
    released migration is refused, not silently laundered.
    """
    force_repin = force_repin or set()
    lads = ladders()
    existing_lock = load_lock()
    # Refuse to launder a destructive NEW migration into the grandfathered set.
    blockers = regen_blockers(lads, existing_lock)
    if blockers:
        raise ValueError(
            "refusing to regenerate migrations.lock.json -- a new migration is "
            "destructive and would be grandfathered into immutability. Make it "
            "additive (old replicas still read the old schema):\n  - "
            + "\n  - ".join(blockers))
    repins = [
        r for r in repin_blockers(lads, existing_lock)
        if r.split(" ", 1)[0] not in force_repin
    ]
    if repins:
        raise ValueError(
            "refusing to regenerate migrations.lock.json -- this would "
            "silently re-pin already-released version(s), the exact edit the "
            "immutability rule exists to catch:\n  - " + "\n  - ".join(repins)
            + "\nReleased migrations must not be edited; add a new version "
              "instead. If a re-pin is genuinely intentional (e.g. correcting "
              "a lock that was committed before the version actually "
              "shipped), pass --force-repin=backend:version for each one "
              "after review.")
    path = lock_path()
    payload = fingerprint(lads)
    payload["_comment"] = (
        "Committed fingerprint of the world-model migration ladders. Generated "
        "by `python -m maverick.migration_governance --regen`. Do not hand-edit; "
        "a changed checksum on a released version fails CI."
    )
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def render() -> str:
    fp = fingerprint()
    lines = [f"migration ladders: heads {fp['heads']}"]
    for backend, cks in fp["checksums"].items():
        lines.append(f"  {backend}: {len(cks)} versions, head checksum "
                     f"{cks[max(cks, key=int)] if cks else '-'}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(
        prog="maverick.migration_governance",
        description="Govern the world-model migration ladders (checksums, "
                    "head parity, additive-only).")
    p.add_argument("--ci", action="store_true",
                   help="exit 1 on any governance violation")
    p.add_argument("--regen", action="store_true",
                   help="rewrite migrations.lock.json from the current ladders")
    p.add_argument("--force-repin", action="append", default=[],
                   metavar="BACKEND:VERSION",
                   help="acknowledge re-pinning an already-released version's "
                        "checksum (e.g. sqlite:7); repeatable. Only for "
                        "correcting a lock committed before the version "
                        "actually shipped -- released migrations must "
                        "otherwise never be edited. Get it reviewed.")
    args = p.parse_args(argv)

    if args.regen:
        try:
            path = write_lock(force_repin=set(args.force_repin))
        except ValueError as e:
            print(f"migration governance: {e}")
            return 1
        print(f"wrote {path}")
        return 0

    problems = validate()
    if problems:
        print("migration governance: PROBLEMS")
        for prob in problems:
            print(f"  - {prob}")
    else:
        print("migration governance: OK")
        print(render())
    if args.ci and problems:
        return 1
    return 0


__all__ = [
    "lock_path", "version_checksum", "ladders", "fingerprint",
    "structural_problems", "lock_problems", "validate", "load_lock",
    "write_lock", "repin_blockers", "render", "main",
]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

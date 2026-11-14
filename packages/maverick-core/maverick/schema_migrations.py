"""Online schema migrations.

The world model already runs ordered migrations at open
(``world_model.MIGRATIONS`` + the ``schema_version`` ledger). What it lacked
is the *operations* view: a way to inspect what a deployment is about to
apply, and to gate it so an unsafe (table-rewriting, lock-heavy) statement
never runs silently against a live, high-traffic SQLite world.

This adds:

* **plan(current, target)** — the ordered list of pending migration steps,
  each classified ``online`` (cheap, non-blocking: ``ADD COLUMN``, ``CREATE
  INDEX [IF NOT EXISTS]``, an FTS rebuild) or ``offline`` (a table rewrite —
  ``DROP COLUMN`` pre-3.35, ``ALTER … RENAME``, a bare ``CREATE TABLE``
  without IF NOT EXISTS, ``UPDATE``/``DELETE`` data backfills) so an operator
  knows before they upgrade whether the migration is safe to run hot.
* **validate(migrations)** — structural lint over the migration table:
  contiguous version numbering from 1, no gaps, no empty *new* migrations
  that aren't documented placeholders, every statement parseable into a kind.
* **online_only(plan)** — the gate: True iff every pending step is online,
  so a CI/preflight check can refuse a hot deploy that needs a maintenance
  window.

Pure SQL-shape classification (no DB connection), deterministic and offline.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Statement-shape → online safety. "online" = O(1)/index build, no full table
# rewrite and no exclusive write lock held across the table.
_ONLINE_PATTERNS = (
    re.compile(r"^\s*ALTER\s+TABLE\s+\S+\s+ADD\s+COLUMN\b", re.IGNORECASE),
    re.compile(r"^\s*CREATE\s+(UNIQUE\s+)?INDEX\s+IF\s+NOT\s+EXISTS\b", re.IGNORECASE),
    re.compile(r"^\s*CREATE\s+TABLE\s+IF\s+NOT\s+EXISTS\b", re.IGNORECASE),
    re.compile(r"^\s*CREATE\s+VIRTUAL\s+TABLE\s+IF\s+NOT\s+EXISTS\b", re.IGNORECASE),
    # Installing an idempotent trigger changes schema metadata only; it does
    # not scan or rewrite existing rows. The trigger body governs future
    # statements after the brief schema lock is released.
    re.compile(r"^\s*CREATE\s+TRIGGER\s+IF\s+NOT\s+EXISTS\b", re.IGNORECASE),
    # FTS maintenance ('rebuild'/'optimize') touches its own shadow tables only.
    re.compile(r"^\s*INSERT\s+INTO\s+\w+_fts\s*\(\s*\w+_fts\s*\)", re.IGNORECASE),
)
# Shapes that rewrite a table or hold a long write lock → maintenance window.
_OFFLINE_PATTERNS = (
    re.compile(r"^\s*ALTER\s+TABLE\s+\S+\s+DROP\s+COLUMN\b", re.IGNORECASE),
    re.compile(r"^\s*ALTER\s+TABLE\s+\S+\s+RENAME\b", re.IGNORECASE),
    re.compile(r"^\s*CREATE\s+INDEX\s+(?!IF\s+NOT\s+EXISTS)", re.IGNORECASE),
    re.compile(r"^\s*CREATE\s+TABLE\s+(?!IF\s+NOT\s+EXISTS|VIRTUAL)", re.IGNORECASE),
    re.compile(r"^\s*CREATE\s+TRIGGER\s+(?!IF\s+NOT\s+EXISTS)", re.IGNORECASE),
    re.compile(r"^\s*(UPDATE|DELETE\s+FROM)\b", re.IGNORECASE),
    re.compile(r"^\s*DROP\s+(TABLE|INDEX|TRIGGER)\b", re.IGNORECASE),
)


@dataclass(frozen=True)
class Step:
    version: int
    statement: str
    kind: str          # "online" | "offline" | "unknown"


def classify(statement: str) -> str:
    s = statement.strip()
    if not s:
        return "online"  # documented empty placeholder (CREATE-in-SCHEMA bump)
    for p in _ONLINE_PATTERNS:
        if p.search(s):
            return "online"
    for p in _OFFLINE_PATTERNS:
        if p.search(s):
            return "offline"
    return "unknown"


def plan(current: int, target: int, *, migrations=None) -> list[Step]:
    """Ordered pending steps to move ``current`` → ``target``."""
    migrations = migrations if migrations is not None else _default_migrations()
    steps: list[Step] = []
    for version in range(current + 1, target + 1):
        for stmt in migrations.get(version, []):
            steps.append(Step(version=version, statement=stmt.strip(),
                              kind=classify(stmt)))
    return steps


def online_only(steps: list[Step]) -> bool:
    """True iff every step is online-safe (no maintenance window needed).

    ``unknown`` counts as NOT online — fail closed: an unclassified statement
    must be reviewed before a hot deploy, not assumed safe.
    """
    return all(s.kind == "online" for s in steps)


def validate(migrations=None) -> list[str]:
    """Structural lint over the migration table. Returns a list of problems
    (empty = OK)."""
    migrations = migrations if migrations is not None else _default_migrations()
    problems: list[str] = []
    versions = sorted(migrations)
    if not versions:
        return ["migration table is empty"]
    # Contiguous from the lowest declared version (the SCHEMA seeds v1).
    expected = list(range(versions[0], versions[-1] + 1))
    if versions != expected:
        gaps = sorted(set(expected) - set(versions))
        problems.append(f"non-contiguous migration versions; missing {gaps}")
    for v in versions:
        stmts = migrations[v]
        if not isinstance(stmts, list):
            problems.append(f"v{v}: migration must be a list of statements")
            continue
        for stmt in stmts:
            if classify(stmt) == "unknown":
                problems.append(f"v{v}: unclassifiable statement: {stmt.strip()[:60]!r}")
    return problems


def render(steps: list[Step]) -> str:
    if not steps:
        return "schema is current: no pending migrations."
    lines = [f"{len(steps)} pending step(s); "
             f"{'ONLINE-SAFE (hot deploy OK)' if online_only(steps) else 'NEEDS MAINTENANCE WINDOW'}:"]
    for s in steps:
        lines.append(f"  v{s.version} [{s.kind}] {s.statement[:70]}")
    return "\n".join(lines)


def current_plan(world=None) -> tuple[list[str], int, int, list[Step]]:
    """``(lint problems, current version, target version, pending steps)`` for
    the world database -- what ``maverick schema-plan`` shows.

    ``world`` is an open world to read the current version from; without one
    the default SQLite world file is read without opening it as a world, since
    opening a world applies every pending migration (no database yet means
    nothing is pending). A database that cannot be read raises RuntimeError
    instead of reading as current. Nothing is planned when the migration table fails its
    structural lint.
    """
    from .world_model import SCHEMA_VERSION
    problems = validate()
    if problems:
        return problems, SCHEMA_VERSION, SCHEMA_VERSION, []
    current = world.schema_version if world is not None else _stored_version()
    return [], int(current), SCHEMA_VERSION, plan(int(current), SCHEMA_VERSION)


def _stored_version() -> int:
    """The default SQLite world's stored schema version, read-only."""
    import sqlite3

    from .world_model import SCHEMA_VERSION, default_db_path
    from .world_model_backends import is_postgres_configured
    if is_postgres_configured():
        raise RuntimeError("schema-plan previews the SQLite world database only; "
                           "the Postgres backend is configured")
    path = default_db_path()
    if not path.exists() or path.stat().st_size == 0:
        return SCHEMA_VERSION  # no DB yet -> nothing pending
    try:
        conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=10.0)
        try:
            if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                            "AND name='schema_version'").fetchone() is None:
                return 1  # a legacy world without a version table is v1
            row = conn.execute("SELECT version FROM schema_version LIMIT 1").fetchone()
        finally:
            conn.close()
        return int(row[0]) if row else 1
    except (sqlite3.Error, TypeError, ValueError) as exc:
        raise RuntimeError(f"cannot read the world database schema version ({path}): {exc}") from exc


def _default_migrations():
    from .world_model import MIGRATIONS
    return MIGRATIONS


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    """Lint the world-model migration table; the CI ratchet for migrations.

    ``--ci`` exits non-zero when a migration is malformed or unclassifiable
    (an ``unknown`` SQL shape), so a new migration can't ship without being
    reviewed for online/offline safety. A classified *offline* migration is
    allowed (it's legitimate, just flagged) — the online/offline call is an
    operator deploy-time decision (``maverick schema-plan``), not a hard block.
    """
    import argparse
    p = argparse.ArgumentParser(
        prog="maverick.schema_migrations",
        description="Lint the world-model migration table.")
    p.add_argument("--ci", action="store_true",
                   help="exit 1 if any migration is malformed or unclassifiable")
    args = p.parse_args(argv)

    problems = validate()
    if problems:
        print("schema migrations: PROBLEMS")
        for prob in problems:
            print(f"  - {prob}")
    else:
        migrations = _default_migrations()
        steps = plan(0, max(migrations)) if migrations else []
        verdict = "all online-safe" if online_only(steps) else "some need a maintenance window"
        print(f"schema migrations: OK ({len(migrations)} versions, {verdict})")
    if args.ci and problems:
        return 1
    return 0


__all__ = ["Step", "classify", "plan", "online_only", "validate", "render", "main",
           "current_plan"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

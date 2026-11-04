"""Data-retention enforcement.

Reads ``[retention]`` from ``~/.maverick/config.toml`` and prunes:

  - ``~/.maverick/audit/YYYY-MM-DD.ndjson`` files older than
    ``audit_days``.
  - ``episodes`` rows in ``~/.maverick/world.db`` with
    ``ended_at`` older than ``episodes_days``.
  - ``goal_events`` rows with ``ts`` older than ``events_days``.
  - ``messages`` rows with ``ts`` older than ``messages_days``.
  - usage-ledger ``(principal, day)`` cost buckets older than
    ``usage_days`` (the per-principal chargeback tally grows forever
    otherwise).

Config defaults are "no pruning" — retention is opt-in. The CLI
exposes ``maverick retention enforce [--dry-run]``.
"""
from __future__ import annotations

import logging
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)


class RetentionScopeError(RuntimeError):
    """Retention cannot prove which tenant/backend it is authorized to prune."""


def _config() -> dict:
    try:
        from ..config import load_config
        return (load_config() or {}).get("retention") or {}
    # failure-policy: best_effort
    except Exception as e:
        log.debug("retention: cannot load config: %s", e)
        return {}


def _cutoff_for_days(days: int, *, now: float | None = None) -> float:
    now = now if now is not None else time.time()
    return now - max(1, int(days)) * 86400.0


def purge_audit_files(
    *, days: int, audit_dir: Path | None = None, dry_run: bool = False,
    now: float | None = None, review_binding: dict | None = None,
) -> dict:
    if review_binding is None:
        return _purge_audit_files(days=days, audit_dir=audit_dir, dry_run=dry_run, now=now)
    from contextlib import ExitStack

    from ..file_lock import cross_process_lock
    from ..paths import data_dir
    from ..retention_review_bindings import RetentionReviewChanged, file_seal

    directory = audit_dir if audit_dir is not None else data_dir("audit")
    if dry_run:
        review_binding["files"] = {}
        return _purge_audit_files(days=days, audit_dir=directory, dry_run=True, now=now, _binding=review_binding)
    expected = review_binding.get("files")
    if not isinstance(expected, dict) or len(expected) > 256:
        raise RetentionReviewChanged("The saved activity review is unavailable. Preview again.")
    paths = []
    for name in sorted(expected):
        if Path(name).name != name or not name.endswith(".ndjson"):
            raise RetentionReviewChanged("The saved activity review is invalid. Preview again.")
        paths.append(directory / name)
    with ExitStack() as locks:
        for path in paths:
            locks.enter_context(cross_process_lock(path, strict=True))
        for path in paths:
            if not path.exists() or file_seal(path) != expected[path.name]:
                raise RetentionReviewChanged("An activity file changed after preview. No activity files were deleted; preview again.")
        return _purge_audit_files(days=days, audit_dir=directory, now=now, _paths=paths, _locks_held=True)


def _purge_audit_files(
    *,
    days: int,
    audit_dir: Path | None = None,
    dry_run: bool = False,
    now: float | None = None,
    _paths: list[Path] | None = None, _locks_held: bool = False, _binding: dict | None = None,
) -> dict:
    """Remove ``YYYY-MM-DD.ndjson`` files older than ``days``.

    Filename date wins over mtime — easier to reason about, immune to
    filesystem mtime drift from backups/rsync.
    """
    if days is None or int(days) <= 0:
        return {"removed": [], "kept": 0, "reason": "disabled"}
    if audit_dir is None:
        # Match the writer's (home + active-tenant) audit dir; a frozen
        # ~/.maverick/audit default would make enforce() report "no audit dir"
        # and purge nothing whenever MAVERICK_HOME / a tenant moved the files.
        from ..paths import data_dir
        audit_dir = data_dir("audit")
    if not audit_dir.exists():
        return {"removed": [], "kept": 0, "reason": "no audit dir"}

    cutoff_ts = _cutoff_for_days(days, now=now)
    cutoff_day = datetime.fromtimestamp(cutoff_ts, tz=timezone.utc).date()
    removed: list[str] = []
    purged: list[dict] = []
    kept = 0
    skipped: list[str] = []
    marker_failed = False
    for path in _paths if _paths is not None else sorted(audit_dir.glob("*.ndjson")):
        try:
            day = datetime.strptime(path.stem, "%Y-%m-%d").date()
        except ValueError:
            kept += 1
            continue
        # <= : the day-file dated exactly `days` ago is expired and must be
        # purged. Strict < kept it, making the window days+1.
        if day <= cutoff_day:
            if dry_run:
                # Dry-run is intentionally non-mutating, including no lock
                # sidecar creation. The result is advisory and can race a live
                # writer; the enforcing pass takes the strict day lock below.
                tip, count = _tip_and_count(path)
                removed.append(path.name)
                purged.append(
                    {"day": path.stem, "tip_hash": tip, "row_count": count}
                )
                if _binding is not None:
                    from ..retention_review_bindings import (
                        MAX_BYTES,
                        RetentionReviewChanged,
                        file_seal,
                    )

                    if len(_binding["files"]) >= 256:
                        raise RetentionReviewChanged("Too many activity files for one safe review. Choose a longer retention period and preview again.")
                    _binding["files"][path.name] = file_seal(path)
                    if sum(row["bytes"] for row in _binding["files"].values()) > MAX_BYTES:
                        raise RetentionReviewChanged("The eligible activity files are too large for one safe review. Choose a longer retention period and preview again.")
                continue

            # Capture and unlink under the exact sidecar lock used by append,
            # GDPR rewrite, and checkpoint publication. Without this, a writer
            # can append between the captured tip and unlink, making the signed
            # purge marker attest to bytes other than those actually destroyed.
            from contextlib import nullcontext

            from ..file_lock import cross_process_lock

            try:
                with nullcontext() if _locks_held else cross_process_lock(path, strict=True):
                    if not path.exists():
                        continue
                    tip, count = _tip_and_count(path)
                    path.unlink()
            except (OSError, RuntimeError) as e:
                # Retention must not destroy a file when it cannot coordinate
                # with writers or prove which bytes it is deleting.
                log.warning("retention: cannot safely purge %s: %s", path, e)
                kept += 1
                skipped.append(path.name)
                continue

            removed.append(path.name)
            if not tip:
                marker_failed = True  # Destroyed bytes cannot be attested without their signed tip.
            purged.append(
                {"day": path.stem, "tip_hash": tip, "row_count": count}
            )
            # Keep the sidecar as the durable coordination inode. Unlinking it
            # after releasing the OS lock creates an ABA window: another writer
            # may already hold the old inode while a third process creates and
            # locks a replacement. There is at most one sidecar per retained
            # audit day, and checkpoint retirement deliberately reuses it.
        else:
            kept += 1
    if purged and not dry_run:
        # Record the deletion in the append-only anchor ledger, which retention
        # never prunes. Without it every purged day is reported forever as
        # `anchored_file_deleted` -- policy retention forging a permanent
        # tamper alert.
        try:
            from .signing import record_retention_purge
            record_retention_purge(audit_dir, purged)
        # failure-policy: fail_soft_with_audit
        except Exception as e:  # pragma: no cover - must not undo the purge
            log.warning("retention: could not record anchor purge marker: %s", e)
            marker_failed = True
    log.info(
        "retention: audit purge cutoff=%s removed=%d kept=%d dry_run=%s",
        cutoff_day, len(removed), kept, dry_run,
    )
    return {"removed": removed, "kept": kept, "cutoff_day": str(cutoff_day),
            "skipped": skipped, "status": "partial" if skipped or marker_failed else "completed",
            "purge_marker": "failed" if marker_failed else "recorded" if purged and not dry_run else "not_needed"}


def _tip_and_count(path: Path) -> tuple[str, int]:
    """Signed tip hash and row count of a day-file, or ``("", 0)``.

    Storage limitation is a legal obligation, so an unreadable file is still
    deleted -- but the deletion then cannot be attested, and ``audit verify``
    will report it as ``anchored_file_deleted`` because a purge record with no
    tip is (correctly) refused. Say so at the point of loss rather than leaving
    an operator to discover an unexplained permanent break later.
    """
    try:
        from .signing import _file_tip_and_count
        tip, count = _file_tip_and_count(path)
        return str(tip or ""), int(count or 0)
    # failure-policy: best_effort
    except Exception as e:
        log.warning(
            "retention: cannot read the signed tip of %s (%s); deleting it "
            "anyway to honour storage limitation, but the purge cannot be "
            "attested and `audit verify` will report this day as deleted. "
            "A sealed segment needs its at-rest key available during retention.",
            path, e,
        )
        return "", 0


def _purge_table_by_time(
    db_path: Path,
    table: str,
    time_col: str,
    cutoff_ts: float,
    *,
    dry_run: bool,
) -> int:
    if not db_path.exists():
        return 0
    # Table/column names can't be parameter-bound, so they MUST come from
    # this fixed allow-set — never from caller/user input — to keep the
    # f-string interpolation below injection-free.
    _ALLOWED = {
        ("episodes", "ended_at"), ("goal_events", "ts"), ("messages", "ts"),
    }
    if (table, time_col) not in _ALLOWED:
        raise ValueError(
            f"refusing to purge unknown table/column: {table!r}/{time_col!r}"
        )
    conn = sqlite3.connect(str(db_path))
    try:
        # The agent may be writing concurrently; wait rather than fail fast.
        conn.execute("PRAGMA busy_timeout=5000")
        # The canonical (--db-path-less) path opens with foreign_keys
        # ON, so this raw connection must too or the two routes silently
        # disagree -- without it, deleting an episode any fact still cites
        # leaves a dangling facts.source_episode_id/fact_history.source_episode_id
        # instead of raising, corrupting the world.db this route writes to
        # directly.
        conn.execute("PRAGMA foreign_keys = ON")
        cur = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE {time_col} IS NOT NULL AND {time_col} < ?",
            (cutoff_ts,),
        )
        (count,) = cur.fetchone()
        if not dry_run and count > 0:
            if table == "episodes":
                # Same reasoning as WorldModel.purge_episodes_before: an aged-out
                # episode's provenance link on a still-live fact must be nulled,
                # not left to trip the FK constraint just enabled above. Guard
                # on the tables existing -- a --db-path target isn't guaranteed
                # to be a full, current-schema world.db.
                existing = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' "
                        "AND name IN ('facts', 'fact_history')"
                    ).fetchall()
                }
                episode_query = (
                    f"SELECT id FROM {table} "
                    f"WHERE {time_col} IS NOT NULL AND {time_col} < ?"
                )
                if "facts" in existing:
                    conn.execute(
                        "UPDATE facts SET source_episode_id = NULL "
                        f"WHERE source_episode_id IN ({episode_query})",
                        (cutoff_ts,),
                    )
                if "fact_history" in existing:
                    conn.execute(
                        "UPDATE fact_history SET source_episode_id = NULL "
                        f"WHERE source_episode_id IN ({episode_query})",
                        (cutoff_ts,),
                    )
            conn.execute(
                f"DELETE FROM {table} WHERE {time_col} IS NOT NULL AND {time_col} < ?",
                (cutoff_ts,),
            )
            conn.commit()
        return int(count or 0)
    finally:
        conn.close()


def purge_world_episodes(
    *,
    days: int,
    db_path: Path | None = None,
    dry_run: bool = False,
    now: float | None = None,
    review_binding: dict | None = None,
) -> dict:
    """Delete ``episodes`` rows ended before ``days`` ago."""
    if days is None or int(days) <= 0:
        return {"deleted": 0, "reason": "disabled"}
    cutoff_ts = _cutoff_for_days(days, now=now)
    if review_binding is not None and db_path is not None:
        raise RetentionScopeError("Reviewed retention requires the configured native store.")
    if db_path is not None:
        deleted = _purge_table_by_time(
            db_path, "episodes", "ended_at", cutoff_ts, dry_run=dry_run,
        )
    else:
        deleted = _purge_canonical_world(
            "purge_episodes_before", cutoff_ts, dry_run=dry_run, review_binding=review_binding,
        )
    log.info("retention: episodes deleted=%d dry_run=%s", deleted, dry_run)
    return {"deleted": deleted, "cutoff_ts": cutoff_ts}


def purge_world_events(
    *,
    days: int,
    db_path: Path | None = None,
    dry_run: bool = False,
    now: float | None = None,
    review_binding: dict | None = None,
) -> dict:
    """Delete ``goal_events`` rows older than ``days``."""
    if days is None or int(days) <= 0:
        return {"deleted": 0, "reason": "disabled"}
    cutoff_ts = _cutoff_for_days(days, now=now)
    if review_binding is not None and db_path is not None:
        raise RetentionScopeError("Reviewed retention requires the configured native store.")
    if db_path is not None:
        deleted = _purge_table_by_time(
            db_path, "goal_events", "ts", cutoff_ts, dry_run=dry_run,
        )
    else:
        deleted = _purge_canonical_world(
            "purge_goal_events_before", cutoff_ts, dry_run=dry_run, review_binding=review_binding,
        )
    log.info("retention: goal_events deleted=%d dry_run=%s", deleted, dry_run)
    return {"deleted": deleted, "cutoff_ts": cutoff_ts}


def purge_world_messages(
    *,
    days: int,
    db_path: Path | None = None,
    dry_run: bool = False,
    now: float | None = None,
    review_binding: dict | None = None,
) -> dict:
    """Delete ``messages`` rows older than ``days``."""
    if days is None or int(days) <= 0:
        return {"deleted": 0, "reason": "disabled"}
    cutoff_ts = _cutoff_for_days(days, now=now)
    if review_binding is not None and db_path is not None:
        raise RetentionScopeError("Reviewed retention requires the configured native store.")
    if db_path is not None:
        deleted = _purge_table_by_time(
            db_path, "messages", "ts", cutoff_ts, dry_run=dry_run,
        )
    else:
        deleted = _purge_canonical_world(
            "purge_messages_before", cutoff_ts, dry_run=dry_run, review_binding=review_binding,
        )
    log.info("retention: messages deleted=%d dry_run=%s", deleted, dry_run)
    return {"deleted": deleted, "cutoff_ts": cutoff_ts}


def _purge_canonical_world(
    method_name: str, cutoff_ts: float, *, dry_run: bool, review_binding: dict | None = None,
) -> int:
    """Run a portable retention primitive on the configured world backend.

    An unbound Postgres connection represents an administrator-wide view.  A
    retention job must never interpret that as permission to delete every
    tenant's rows, so callers must either bind a tenant (the fleet coordinator
    below does this) or provide an explicit SQLite ``db_path``.
    """
    from ..paths import current_tenant_id
    from ..world_model import close_world_if_owned, default_db_path, open_world
    from ..world_model_backends import is_postgres_configured

    if is_postgres_configured() and current_tenant_id() is None:
        raise RetentionScopeError(
            "refusing unscoped Postgres retention; bind a tenant or provision "
            "the tenant registry so each tenant is pruned explicitly"
        )
    # Do not create an empty SQLite database merely because a scheduled
    # retention job ran before the world was initialized.
    if not is_postgres_configured() and not default_db_path().exists():
        if review_binding is not None:
            from ..retention_review_bindings import check, seal

            check(review_binding, seal([]), dry_run=dry_run)
        return 0
    world = open_world()
    try:
        method = getattr(world, method_name, None)
        if not callable(method):
            raise RetentionScopeError(
                f"configured world backend lacks retention primitive {method_name}"
            )
        return int(method(float(cutoff_ts), dry_run=dry_run, **({"review_binding": review_binding} if review_binding is not None else {})) or 0)
    finally:
        close_world_if_owned(world)


def purge_usage_ledger(
    *,
    days: int,
    ledger_path: Path | None = None,
    dry_run: bool = False,
    now: float | None = None,
    review_binding: dict | None = None,
) -> dict:
    """Prune usage-ledger ``(principal, day)`` buckets older than ``days``."""
    if days is None or int(days) <= 0:
        return {"removed_buckets": 0, "reason": "disabled"}
    from ..quotas import UsageLedger
    ledger = UsageLedger(ledger_path) if ledger_path is not None else UsageLedger()
    result = ledger.prune(int(days), now=now, dry_run=dry_run, **({"review_binding": review_binding} if review_binding is not None else {}))
    log.info("retention: usage ledger removed_buckets=%d dry_run=%s",
             result.get("removed_buckets", 0), dry_run)
    return result


def record_retention_marker(report: dict, *, audit_dir: Path | None = None) -> dict | None:
    """Emit a signed audit event recording what a retention run purged.

    Without this, an auditor seeing a gap in the day-files (or a shrunken
    episodes/goal_events table) cannot tell policy-driven retention from
    malicious deletion -- the cross-file anchor ledger even flags a removed
    day-file as a chain break. The marker lands in the LIVE chain (today's
    day-file, which is never itself old enough to be purged), signed by the same
    Ed25519 chain when ``[audit] sign`` is on, so the deletion is itself
    tamper-evidently recorded and reconcilable against the gap.

    Returns the payload written, or None when nothing was actually purged (a
    no-op / dry-run enforce leaves no audit noise). Never raises: a failure to
    write the marker must not undo or block the retention that already ran.
    """
    audit = report.get("audit") or {}
    removed_files = list(audit.get("removed") or [])
    episodes = int((report.get("episodes") or {}).get("deleted") or 0)
    events = int((report.get("goal_events") or {}).get("deleted") or 0)
    messages = int((report.get("messages") or {}).get("deleted") or 0)
    usage_buckets = int((report.get("usage_ledger") or {}).get("removed_buckets") or 0)
    if not (removed_files or episodes or events or messages or usage_buckets):
        return None

    payload = {
        "audit_files_removed": len(removed_files),
        "audit_files": removed_files,
        "audit_cutoff_day": audit.get("cutoff_day", ""),
        "episodes_deleted": episodes,
        "goal_events_deleted": events,
        "messages_deleted": messages,
        "usage_buckets_removed": usage_buckets,
    }
    try:
        from .events import AuditEvent, EventKind
        if audit_dir is not None:
            # Write into the SAME chain being enforced (tests / explicit tenant
            # dir), not whatever the ambient default resolves to.
            from .writer import AuditLog
            ok = AuditLog(audit_dir).record(
                AuditEvent(
                    ts=time.time(),
                    kind=EventKind.RETENTION_PURGE,
                    agent="system",
                    goal_id=None,
                    payload=payload,
                )
            )
        else:
            from .writer import record as _audit_record
            ok = _audit_record(EventKind.RETENTION_PURGE, **payload)
        return payload if ok else None
    # failure-policy: fail_soft_with_audit
    except Exception as e:  # pragma: no cover - marker must never break retention
        log.warning("retention: could not record retention marker: %s", e)
        return None


def enforce(
    *,
    config: dict | None = None,
    dry_run: bool = False,
    audit_dir: Path | None = None,
    db_path: Path | None = None,
    now: float | None = None,
    _fleet_child: bool = False,
    _review_binding: dict | None = None,
) -> dict:
    from ..authority_effects import authority_effect_fence

    # Hold changes and app-owned authority changes share this fence. Recheck
    # preservation under it and retain it through each destructive operation.
    with authority_effect_fence():
        return _enforce(config=config, dry_run=dry_run, audit_dir=audit_dir,
                        db_path=db_path, now=now, _fleet_child=_fleet_child, _review_binding=_review_binding)


def _enforce(
    *, config: dict | None, dry_run: bool, audit_dir: Path | None,
    db_path: Path | None, now: float | None, _fleet_child: bool, _review_binding: dict | None = None,
) -> dict:
    """Apply every configured retention rule. Returns a per-rule report.

    ``audit_dir`` defaults to the writer's home/tenant-aware audit dir
    (resolved by :func:`purge_audit_files`), not a frozen path.

    A non-dry-run that actually purged anything also writes a signed
    ``retention_purge`` marker into the audit chain (see
    :func:`record_retention_marker`) so the deletion is tamper-evidently
    recorded.
    """
    cfg = config if config is not None else _config()
    if not cfg:
        return {"status": "disabled", "reason": "no [retention] in config"}

    # An operator-level `retention enforce` must cover every provisioned
    # tenant, not whichever shared SQLite file happens to be the process
    # default.  Explicit paths remain a deliberately single-store maintenance
    # operation (and are heavily used by recovery/tests).
    if not _fleet_child and audit_dir is None and db_path is None:
        from ..paths import current_tenant_id, tenant_scope
        if current_tenant_id() is None:
            from ..tenant.registry import list_tenants

            tenants = list_tenants()
            if tenants:
                reports: dict[str, dict] = {}
                for record in tenants:
                    with tenant_scope(tenant=record.id):
                        reports[record.id] = enforce(
                            config=cfg,
                            dry_run=dry_run,
                            now=now,
                            _fleet_child=True,
                        )
                return {
                    "scope": "tenant_fleet",
                    "dry_run": dry_run,
                    "tenant_count": len(reports),
                    "tenants": reports,
                }

    if _review_binding is not None and (not _fleet_child or sum(bool(cfg.get(key)) for key in ("audit_days", "episodes_days", "events_days", "messages_days", "usage_days")) != 1):
        raise RetentionScopeError("A reviewed retention step requires one scoped native store.")

    binding = {"review_binding": _review_binding} if _review_binding is not None else {}
    audit_days = cfg.get("audit_days")
    episodes_days = cfg.get("episodes_days")
    events_days = cfg.get("events_days")
    messages_days = cfg.get("messages_days")
    usage_days = cfg.get("usage_days")

    from .preservation import preservation_snapshot

    try:
        preservation = preservation_snapshot()
    except Exception as exc:  # failure-policy: fail_closed -- unverified holds prohibit deletion
        raise RetentionScopeError("Preservation holds could not be verified; no records were deleted.") from exc
    if preservation["blocked"] and not dry_run:
        raise RetentionScopeError("Recorded preservation holds block broad deletion in this workspace.")
    if not dry_run:
        from ..ediscovery import LegalHoldApplies, assert_no_active_matters

        try:
            assert_no_active_matters()
        except LegalHoldApplies as exc:
            raise RetentionScopeError(str(exc)) from exc
    report: dict = {"dry_run": dry_run, "preservation": preservation}
    if audit_days:
        report["audit"] = purge_audit_files(
            days=audit_days, audit_dir=audit_dir, dry_run=dry_run, now=now, **binding,
        )
    if episodes_days:
        report["episodes"] = purge_world_episodes(
            days=episodes_days, db_path=db_path, dry_run=dry_run, now=now, **binding,
        )
    if events_days:
        report["goal_events"] = purge_world_events(
            days=events_days, db_path=db_path, dry_run=dry_run, now=now, **binding,
        )
    if messages_days:
        report["messages"] = purge_world_messages(
            days=messages_days, db_path=db_path, dry_run=dry_run, now=now, **binding,
        )
    if usage_days:
        report["usage_ledger"] = purge_usage_ledger(
            days=usage_days, dry_run=dry_run, now=now, **binding,
        )

    if not dry_run:
        marker = record_retention_marker(report, audit_dir=audit_dir)
        if marker is not None:
            report["marker"] = marker
    return report


__all__ = [
    "RetentionScopeError",
    "enforce",
    "record_retention_marker",
    "purge_audit_files",
    "purge_world_episodes",
    "purge_world_events",
    "purge_usage_ledger",
]

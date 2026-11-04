"""Reviewed provider accounting reconciliation; no provider calls or retries.

Known receipt resolution preserves every other identity. Complete local repair
requires a separately authenticated export plus isolated control-plane recovery.
The governed review record retains the administrator's evidence and audit outbox.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import secrets
import time
from datetime import datetime

from . import backup, file_lock, workspace_recovery
from . import provider_cost_cap as cap
from .governed_operations import digest
from .governed_records import GovernedRecordStore
from .paths import current_tenant_id_strict, data_dir
from .privacy_ops import RecordConflict

MAX_UPLOAD = 16 * 1024 * 1024
_REVIEWS = GovernedRecordStore("provider_accounting_reviews", "PAR", "provider_accounting_review")


class SpendingReviewError(ValueError):
    """The selected accounting review is unsafe or no longer current."""


def target():
    return digest([cap.authority_identity(), current_tenant_id_strict()])


def _actor(actor):
    if not isinstance(actor, str) or not actor or len(actor) > 256:
        raise SpendingReviewError("A current administrator identity is required.")
    return actor


def _evidence(evidence):
    if not isinstance(evidence, str) or not 8 <= len(evidence.strip()) <= 2000:
        raise SpendingReviewError("Enter the final provider receipt or invoice reference and how its cost was verified.")
    return evidence.strip()


def _state(provider, period):
    shared = cap._shared_world()
    if shared is not None:
        total, receipts = shared.read_provider_cap(period, provider)
    else:
        ledger_path = cap._ledger_path()
        if cap._use_indexed_ledger(ledger_path):
            from . import provider_spend_sqlite
            total, receipts = provider_spend_sqlite.read_bucket(
                ledger_path, period, provider, cap,
            )
        else:
            ledger = cap._load(ledger_path)
            total = ledger.get(period, {}).get(provider, 0.0)
            receipts = ledger.get(cap._RECEIPTS, {}).get(period, {}).get(provider, {})
    cap._validate_receipts(total, receipts)
    return total, receipts, shared


def _period(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}(?:-[0-9]{2})?", value):
        raise SpendingReviewError("Choose a UTC day (YYYY-MM-DD) or month (YYYY-MM).")
    try:
        datetime.strptime(value, "%Y-%m-%d" if len(value) == 10 else "%Y-%m")
    except ValueError:
        raise SpendingReviewError("Choose a valid UTC day or month.") from None
    return value


def _provider(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", value):
        raise SpendingReviewError("Enter the provider name using lowercase letters, numbers, dots, underscores or dashes.")
    return value


def status(period=None, *, provider=None, offset=0, limit=100):
    current = period or cap.period_key()
    _period(current)
    if type(offset) is not int or not 0 <= offset <= 100000 or type(limit) is not int or not 1 <= limit <= 100:
        raise SpendingReviewError("Choose a valid reservation page.")
    configured = cap.caps_from_config()
    names = {_provider(provider): configured.get(provider)} if provider else configured
    result = {"period": current, "target": target(), "providers": [], "available": True,
              "offset": offset, "limit": limit, "holds_expire_automatically": False, "provider_calls_retried": False}
    try:
        for name, ceiling in names.items():
            total, receipts, _ = _state(name, current)
            state = cap._status(total, receipts, ceiling)
            held = [{"id": key, "projected": row["projected"], "state": row["state"]}
                    for key, row in sorted(receipts.items()) if row["state"] != "settled"]
            result["providers"].append({"provider": name, "cap": ceiling, "spent": state.spent,
                "reserved": state.reserved, "remaining": state.remaining, "allowed": state.allowed,
                "unresolved": state.unresolved, "holds_total": len(held),
                "holds_next_offset": offset + limit if offset + limit < len(held) else None,
                "holds": held[offset:offset + limit]})
    except (cap.ProviderAccountingUnavailable, OSError, ValueError, RuntimeError):
        result.update(available=False, providers=[],
                      message="Provider accounting cannot be read safely. Calls with a configured cap are blocked; no balance has been reset.")
    try:
        result["shared"] = cap._shared_world() is not None
    except cap.ProviderAccountingUnavailable:
        result["shared"] = True
    if result["shared"]:
        result["ledger_health"] = {
            "format": "shared", "available": result["available"],
            "message": ("Shared spending records are available." if result["available"] else
                        "Shared spending records need the database administrator's recovery."),
        }
    else:
        try:
            from . import provider_spend_sqlite
            ledger_path = cap._ledger_path()
            if cap._use_indexed_ledger(ledger_path):
                result["ledger_health"] = provider_spend_sqlite.health(ledger_path, cap)
            else:
                ledger = cap._load(ledger_path)
                receipts = ledger.get(cap._RECEIPTS, {})
                rows = [row for providers in receipts.values()
                        for entries in providers.values() for row in entries.values()]
                result["ledger_health"] = {
                    "format": "standard", "available": True,
                    "receipt_count": len(rows),
                    "unresolved_count": sum(row["state"] != "settled" for row in rows),
                    "bytes": ledger_path.stat().st_size if ledger_path.exists() else 0,
                    "single_file_copy_available": True,
                    "message": "Spending records are healthy.",
                }
        except Exception:
            result["available"] = False
            result["ledger_health"] = {
                "format": "indexed", "available": False,
                "message": "Spending records need recovery; new AI calls are blocked.",
            }
    return result


def diagnostics():
    result = status()
    result["diagnostics_only"] = True
    result["local_state_sha256"] = _local_sha() if not result["shared"] else None
    result["recovery_guidance"] = (
        "Shared accounting needs its database administrator's coordinated recovery. No local substitute is permitted."
        if result["shared"] else
        "Keep the failed state. In isolated desktop recovery mode, select a verified complete accounting export and reconcile it against final provider receipts."
    )
    return result


def _local_sha():
    from . import provider_spend_sqlite
    path = (provider_spend_sqlite.database_path(cap._ledger_path())
            if provider_spend_sqlite.is_active(cap._ledger_path())
            else cap._ledger_path())
    try:
        file_lock.ensure_private_file(path)
        with path.open("rb") as stream:
            hasher = hashlib.sha256()
            for chunk in iter(lambda: stream.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        return "missing"


def _review(payload, actor, context, *, target_binding=None):
    binding = target_binding or target()
    if binding != target():
        raise SpendingReviewError("The accounting authority changed during review. Reload before continuing.")
    return _REVIEWS.create({**payload, "id": "PAR-" + secrets.token_hex(16), "actor": _actor(actor), "context": context,
                           "target": binding, "expires_at": time.time() + 600,
                           "state": "prepared", "current_period": cap.period_key()},
                          action="prepare", actor=actor, max_records=10000)


def public_review(record):
    return {key: record[key] for key in ("id", "kind", "state", "provider", "period", "actual",
                                       "receipt", "evidence", "totals", "exported_at", "receipts_complete", "expires_at") if key in record}


def review(identifier, *, actor, context):
    record = _REVIEWS.get(identifier)
    if (not record or record.get("actor") != _actor(actor) or record.get("context") != context
            or record.get("target") != target() or record.get("kind") not in {"hold", "repair"}):
        raise SpendingReviewError("This accounting review is not available in your current account and workspace.")
    return public_review(record)


def open_reviews(*, actor, context, limit=50):
    """The administrator's own unfinished reviews in this workspace, newest first.

    Same visibility rule as :func:`review`: only records prepared by this
    actor, in this signed-in context, against the current accounting target.
    Completed reviews are left out; reopening never applies anything."""
    actor = _actor(actor)
    binding = target()
    rows = [record for record in _REVIEWS.list(limit=1000)
            if record.get("actor") == actor and record.get("context") == context
            and record.get("target") == binding and record.get("kind") in {"hold", "repair"}
            and record.get("state") != "completed"]
    rows.sort(key=lambda record: float(record.get("expires_at") or 0), reverse=True)
    return [public_review(record) for record in rows[:max(1, min(int(limit), 100))]]


def prepare_hold(provider, period, identity, actual, evidence, *, actor, context, isolated=False):
    binding = target()
    total, receipts, _ = _state(provider, period)
    row = receipts.get(identity)
    if row is None or row["state"] == "settled":
        raise SpendingReviewError("Select an unresolved reservation that still exists.")
    if row["state"] == "held" and not isolated:
        raise SpendingReviewError("This reservation may still be running. Reconcile it only in isolated desktop recovery mode.")
    actual = cap._amount(actual)
    record = _review({"kind": "hold", "provider": provider, "period": period, "receipt": identity,
                      "actual": actual, "evidence": _evidence(evidence),
                      "expected": digest([total, receipts]), "requires_isolation": row["state"] == "held"}, actor, context, target_binding=binding)
    return public_review(record)


def export_accounting():
    if cap._shared_world() is not None:
        raise SpendingReviewError("Use the shared database's verified export and recovery procedure.")
    with file_lock.cross_process_lock(cap._ledger_path(), strict=True):
        data = cap._load(cap._ledger_path())
        payload = {"schema": "lightwork.provider-accounting-export.v1", "target": target(),
                   "created_at": time.time(), "ledger": data}
        signed = backup._authenticate_for_write(payload, workspace_recovery._key())
        encoded = (json.dumps(signed, allow_nan=False) + "\n").encode("utf-8")
        if len(encoded) > 12 * 1024 * 1024:
            raise SpendingReviewError(
                "Spending records exceed the single-file copy limit. Use a full Workspace recovery backup."
            )
        return encoded


def _isolated(isolated):
    from .installation_recovery import blockers
    if not isolated or blockers():
        raise SpendingReviewError("Repair requires isolated local recovery mode with no independently managed workers or external storage.")


def inspect_import(upload, *, isolated):
    _isolated(isolated)
    if not isinstance(upload, bytes) or len(upload) > MAX_UPLOAD:
        raise SpendingReviewError("Select a complete accounting export no larger than16 MiB.")
    try:
        payload = json.loads(upload)
        with backup.recovery_scope(cap._ledger_path().parent, current_tenant_id_strict(), workspace_recovery._key()):
            backup._verify_authentication(payload, allow_unsigned=False, label="provider accounting export")
        if payload.get("schema") != "lightwork.provider-accounting-export.v1" or payload.get("target") != target():
            raise SpendingReviewError("The accounting export belongs to a different workspace or format.")
        ledger = payload["ledger"]
        # Exercise the exact production ledger validator against a private copy.
        import tempfile
        with tempfile.TemporaryDirectory(prefix="lw-accounting-review-") as temporary:
            from pathlib import Path
            directory = file_lock.ensure_private_directory(temporary)
            candidate = Path(directory) / "provider_spend.json"
            file_lock.atomic_write_text(candidate, json.dumps(ledger, allow_nan=False))
            ledger = cap._load(candidate)
        totals = []
        for period, bucket in ledger.items():
            if period in {cap._RECEIPTS, cap._ATTEMPT_INDEX}:
                continue
            for provider, total in bucket.items():
                rows = ledger.get(cap._RECEIPTS, {}).get(period, {}).get(provider, {})
                state = cap._status(total, rows, None)
                totals.append({"provider": provider, "period": period, "confirmed": state.spent,
                               "reserved": state.reserved})
        for provider in cap.caps_from_config():
            if not any(row["provider"] == provider and row["period"] == cap.period_key() for row in totals):
                totals.append({"provider": provider, "period": cap.period_key(), "confirmed": 0.0, "reserved": 0.0})
        exported_at = payload.get("created_at")
        if isinstance(exported_at, bool) or not isinstance(exported_at, (int, float)) or not 0 < exported_at <= time.time() + 60:
            raise SpendingReviewError("The accounting export has no valid creation time.")
        return ledger, totals, exported_at
    except (backup.BackupError, cap.ProviderAccountingUnavailable, TypeError, KeyError, ValueError) as exc:
        raise SpendingReviewError("The complete accounting export could not be authenticated and validated.") from exc


def stage_import(upload, *, actor, context, isolated):
    ledger, baseline, exported_at = inspect_import(upload, isolated=isolated)
    return public_review(_review({"kind": "import", "replacement": ledger, "totals": baseline,
                                 "exported_at": exported_at}, actor, context))


def prepare_repair(upload, totals, evidence, *, actor, context, isolated, receipts_complete=False):
    binding = target()
    _isolated(isolated)
    if receipts_complete is not True:
        raise SpendingReviewError("Confirm that final provider receipts cover every call since the export, including later providers and periods. If any cost remains unknown, do not repair from this copy.")
    try:
        cap._load(cap._ledger_path())
    except cap.ProviderAccountingUnavailable:
        pass
    else:
        raise SpendingReviewError("Accounting is readable. Resolve its exact reservations instead of replacing confirmed costs from an older copy.")
    if isinstance(upload, str):
        selected = _REVIEWS.get(upload)
        if (not selected or selected.get("kind") != "import" or selected.get("actor") != actor
                or selected.get("context") != context or selected.get("target") != target()
                or selected.get("expires_at", 0) < time.time()):
            raise SpendingReviewError("The verified export selection changed. Select it again.")
        ledger, baseline, exported_at = copy.deepcopy(selected["replacement"]), selected["totals"], selected["exported_at"]
    else:
        ledger, baseline, exported_at = inspect_import(upload, isolated=isolated)
    expected_keys = {(row["provider"], row["period"]) for row in baseline}
    if not isinstance(totals, list) or not 1 <= len(totals) <= 500 or any(not isinstance(row, dict) for row in totals):
        raise SpendingReviewError("Review up to500 provider and period totals.")
    supplied = {(_provider(row.get("provider")), _period(row.get("period"))) for row in totals}
    if len(supplied) != len(totals) or not expected_keys.issubset(supplied):
        raise SpendingReviewError("Review a confirmed spending total for every provider and period in the complete export.")
    for row in totals:
        key = row["provider"], row["period"]
        prior = next((item for item in baseline if (item["provider"], item["period"]) == key), {"confirmed": 0.0, "reserved": 0.0})
        actual = cap._amount(row.get("confirmed"))
        if actual < prior["confirmed"]:
            raise SpendingReviewError("A repair cannot reduce confirmed spending from the verified export.")
        ledger.setdefault(row["period"], {})[row["provider"]] = actual + prior["reserved"]
    # Unfinished imported identities stay held; never fabricate cancellation.
    record = _review({"kind": "repair", "replacement": ledger, "totals": totals,
                      "evidence": _evidence(evidence), "expected": _local_sha(),
                      "exported_at": exported_at, "receipts_complete": True}, actor, context, target_binding=binding)
    return public_review(record)


def _apply_repair(record, identifier, intent):
    path = cap._ledger_path()
    with file_lock.cross_process_lock(path, strict=True):
        if record["target"] != target():
            raise SpendingReviewError("The accounting authority changed. Reload before continuing.")
        replacement = copy.deepcopy(record["replacement"])
        # An exact post-write retry only finishes the retained audit record.
        from . import provider_spend_sqlite
        source_path = (provider_spend_sqlite.database_path(path)
                       if provider_spend_sqlite.is_active(path) else path)
        current_sha = _local_sha()
        try:
            already_replaced = cap._load(path) == replacement
        except cap.ProviderAccountingUnavailable:
            already_replaced = False
        if already_replaced:
            return
        if current_sha != record["expected"]:
            raise RecordConflict("The failed accounting state changed. Prepare a new repair review.")
        intent()
        if source_path.exists():
            failed = data_dir("provider_accounting_reviews", identifier + ".failed")
            if not failed.exists():
                file_lock.atomic_create_bytes(failed, file_lock.atomic_read_bytes(source_path))
            if hashlib.sha256(file_lock.atomic_read_bytes(failed)).hexdigest() != record["expected"]:
                raise SpendingReviewError("The preserved failed accounting copy does not match the review.")
        cap._save(path, replacement)


def apply(identifier, *, actor, context, isolated, confirm):
    if confirm is not True:
        raise SpendingReviewError("Explicitly confirm the reviewed final provider costs.")
    record = _REVIEWS.get(identifier)
    if (not record or record.get("actor") != _actor(actor) or record.get("context") != context
            or record.get("target") != target()):
        raise SpendingReviewError("The account, workspace, period, or review changed. Prepare a new review.")
    if record["state"] == "completed":
        return public_review(record)
    if record["kind"] not in {"hold", "repair"}:
        raise SpendingReviewError("Prepare and review the proposed accounting changes first.")
    if record["kind"] == "repair" or record.get("requires_isolation"):
        _isolated(isolated)

    def intent():
        if record.get("expires_at", 0) < time.time() or record.get("current_period") != cap.period_key():
            raise SpendingReviewError("The review expired. Prepare it again before changing accounting.")
        current = _REVIEWS.get(identifier)
        if current["state"] == "prepared":
            _REVIEWS.update(identifier, lambda value: value.update(state="applying"),
                            expected_revision=current["revision"], action="apply", actor=actor)

    if record["kind"] == "hold":
        _, _, shared = _state(record["provider"], record["period"])
        def reconcile(total, receipts):
            if record["target"] != target():
                raise SpendingReviewError("The accounting authority changed. Reload before continuing.")
            row = receipts.get(record["receipt"])
            if row and row.get("reconciliation") == identifier:
                return total, receipts, None
            if digest([total, receipts]) != record["expected"]:
                raise RecordConflict("Provider accounting changed. Review its current reservations again.")
            intent()
            total = max(0.0, total - row["projected"]) + record["actual"]
            row.update(state="settled", actual=record["actual"], reconciliation=identifier)
            return total, receipts, None
        cap._mutate(record["provider"], record["period"], reconcile,
                    path=cap._ledger_path(), shared=shared)
    else:
        _apply_repair(record, identifier, intent)
    current = _REVIEWS.get(identifier)
    completed = _REVIEWS.update(identifier, lambda value: value.update(state="completed"),
                                expected_revision=current["revision"], action="complete", actor=actor)
    return public_review(completed)

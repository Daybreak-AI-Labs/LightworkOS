"""Exact audit maintenance reviews and original results for page and Copilot.

The native seal and WORM writers remain the only effect implementations. A
governed record reserves a review before either writer can change anything.
Unknown uploads hold their source versions: another review cannot blindly
repeat them. Signed native WORM completions recover an original successful
upload even when the dashboard did not receive its completion.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import re
import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import HTTPException
from maverick import config
from maverick.audit import worm
from maverick.authority_effects import authority_effect_fence
from maverick.crypto_at_rest import at_rest_enabled, is_sealed
from maverick.file_lock import cross_process_lock
from maverick.governed_operations import digest
from maverick.governed_records import GovernedRecordStore
from maverick.paths import current_tenant_id_strict, data_dir

from . import auth
from .draft_api import context_for

TTL = 600
_ID = re.compile(r"AAR-[a-f0-9]{32}\Z")
_OP = re.compile(r"[a-f0-9]{32}\Z")
_LIMIT = 10_000


def store():
    return GovernedRecordStore("audit-action-reviews", "AAR", "audit_action_review")


def authority(request, action=None):
    auth.require_permission(request, "audit")
    if action == "seal":
        auth.require_permission(request, "admin")
    elif action == "copy":
        auth.require_global_permission(request, "admin")
    from .request_identity import request_actor as _request_actor
    return _request_actor(request), context_for(request)


def _destination():
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(409, "Storage settings could not be verified. Check All settings before copying records.")
    cfg = worm._worm_cfg()
    provider = str(cfg.get("provider") or "").strip().lower()
    if provider not in {"local", "s3", "aws"}:
        raise HTTPException(409, "No copy destination is configured. Choose storage on the Compliance page first.")
    try:
        days = int(cfg.get("retention_days") or worm._DEFAULT_RETENTION_DAYS)
    except (ValueError, TypeError):
        raise HTTPException(409, "The copy retention period could not be read. Check it on the Compliance page.") from None
    if not 1 <= days <= 36_500:
        raise HTTPException(409, "Choose a copy retention period between 1 and 36,500 days on the Compliance page.")
    if provider == "local":
        directory = str(Path(cfg.get("dir") or data_dir("audit", "worm", "store")).absolute())
        binding = {"provider": "local", "directory": directory, "retention_days": days}
        return binding, {"provider": "Local folder", "location": directory, "mode": "Read-only copy",
            "retention_days": days, "protection": "Local permissions are checked. The owner or an administrator can still change or delete a copy; the retention date is a record, not an enforced local lock."}
    mode = str(cfg.get("mode") or "COMPLIANCE").upper()
    bucket = str(cfg.get("bucket") or "").strip()
    if mode not in {"COMPLIANCE", "GOVERNANCE"} or not bucket:
        raise HTTPException(409, "Choose a storage bucket and lock strength on the Compliance page first.")
    endpoint = str(cfg.get("endpoint_url") or "")
    safe_endpoint = urlsplit(endpoint).hostname if endpoint else "Amazon S3"
    binding = {"provider": "s3", "bucket": bucket, "prefix": str(cfg.get("prefix") or ""),
               "mode": mode, "region": cfg.get("region"), "endpoint_url": endpoint, "retention_days": days}
    return binding, {"provider": "Object storage", "location": bucket + "/" + binding["prefix"],
        "service": safe_endpoint, "mode": mode.title(), "retention_days": days,
        "protection": ("Each new copy must return a version and Compliance retention through the reviewed date. Lightwork verifies that reported setting; the configured service controls enforcement and availability." if mode == "COMPLIANCE" else
                       "Each new copy must return a version and Governance retention through the reviewed date. Lightwork verifies that reported setting; the configured service controls enforcement and availability. A person with the provider's bypass permission can remove its lock.")}


def _sources(action, *, reconcile=False):
    root = data_dir("audit")
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
    paths = [p for p in worm.day_files(root) if p.stem < today] if root.exists() else []
    if len(paths) > _LIMIT:
        raise HTTPException(409, "Too many closed days are available for one review. No maintenance action was started.")
    if action == "copy":
        raw = worm._verified_source_snapshot(root, paths)
        manifest = worm._load_manifest(root)
        held = {(row["name"], row["sha256"]) for row in worm.unknown_attempts(root)}
    else:
        raw, manifest, held = {}, {}, set()
        for path in paths:
            with cross_process_lock(path, strict=True):
                raw[path.name] = worm._read_custodied_file(path, mode=0o600)
    required = worm._at_rest_sealing_active() if action == "copy" else False
    rows = []
    for path in paths:
        value = raw[path.name]
        sha = hashlib.sha256(value).hexdigest()
        sealed = is_sealed(value)
        # A preview does not contact a remote provider or claim that an older
        # locator remains available. The native writer rechecks it at effect.
        prior = manifest.get(path.name)
        if action == "seal":
            status = "Already encrypted" if sealed else "Encrypt this day"
            selected = not sealed
        else:
            status = "Encrypt this day before copying" if required and not sealed else (
                "Check the saved copy; copy only if needed" if prior and prior.get("sha256") == sha else
                "Copy this changed version" if prior else "Copy this day")
            selected = not (required and not sealed)
            if (path.name, sha) in held:
                status = "Review a separate intentional copy; an earlier copy may already exist" if reconcile else "Earlier copy uncertain; original completion proof is missing"
                selected = selected and reconcile
        rows.append({"name": path.name, "day": path.stem, "sha256": sha, "bytes": len(value),
                     "encrypted": sealed, "status": status, "selected": selected,
                     "existing_retention": prior.get("retain_until") if prior else None})
    return rows


def current(request, action, *, reconcile=False):
    actor, context = authority(request, action)
    if action not in {"seal", "copy"}:
        raise HTTPException(422, "Choose an activity-log maintenance action.")
    if config.config_source_errors(include_tenant=True):
        raise HTTPException(409, "Installation settings could not be verified. Check All settings first.")
    if action == "seal" and not at_rest_enabled():
        raise HTTPException(409, "Turn on encryption for stored data on the Compliance page first.")
    try:
        rows = _sources(action, reconcile=reconcile)
        destination, display = _destination() if action == "copy" else ({}, {})
    except HTTPException:
        raise
    except (worm.WormUnavailable, OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(409, "The closed activity records or their signed links could not be verified. Check the log before reviewing maintenance.") from exc
    binding = {"actor": actor, "context": context, "action": action, "source": str(data_dir("audit").absolute()),
               "workspace": current_tenant_id_strict(), "rows": rows, "destination": destination,
               "encryption": at_rest_enabled(), "reconcile": reconcile}
    binding["reconciliation"] = _pending_bindings(binding)
    if reconcile and (action != "copy" or not binding["reconciliation"]):
        raise HTTPException(409, "No uncertain copy hold matches the current source versions. Use the ordinary current copy review.")
    return {**binding, "revision": digest(binding), "destination_display": display}


def _bound_row(request, review, *, write=False):
    if not isinstance(review, str) or not _ID.fullmatch(review):
        raise HTTPException(422, "Choose a saved activity-log review.")
    row = store().get(review)
    if not row:
        raise HTTPException(404, "This saved review is no longer available.")
    actor, context = authority(request, row["action"] if write else None)
    if row.get("actor") != actor or not hmac.compare_digest(str(row.get("context") or ""), context):
        raise HTTPException(403, "This review belongs to another account or workspace.")
    if row.get("source") != str(data_dir("audit").absolute()):
        raise HTTPException(409, "The workspace storage changed. The original result cannot be read in this location.")
    return row


def _update(row, **changes):
    return store().update(row["id"], lambda value: value.update(changes), expected_revision=row["revision"],
                          action="audit_action_result", actor=row["actor"])


def _recover_native(row):
    if row["state"] not in {"reserved", "unknown"}:
        return row
    expected = {item["name"] for item in row["rows"] if item["selected"]}
    outcomes = dict(row.get("outcomes") or {})
    if expected and expected.issubset(outcomes) and all(outcomes[name] in {"sealed", "copied", "already_present"} for name in expected):
        return _update(row, state="confirmed")
    if row["action"] != "copy":
        return row
    try:
        receipts = worm.request_receipts(Path(row["source"]), row["request_id"])
    except (worm.WormUnavailable, OSError, ValueError):
        return row
    for name, original in receipts.items():
        selected = next((item for item in row["rows"] if item["name"] == name and item["selected"]), None)
        if selected and original["sha256"] == selected["sha256"] and original["retain_until"] == row["retain_until"]:
            outcomes[name] = "copied"
    if outcomes != row.get("outcomes", {}) or expected and expected.issubset(outcomes) and all(outcomes[name] in {"copied", "already_present"} for name in expected):
        complete = expected.issubset(outcomes) and all(outcomes[name] in {"copied", "already_present"} for name in expected)
        row = _update(row, outcomes=outcomes, state="confirmed" if complete else row["state"])
    return row


def _plain(row):
    outcomes = row.get("outcomes") or {}
    selected = [item for item in row["rows"] if item["selected"]]
    state = row["state"]
    done = sum(outcomes.get(item["name"]) in {"sealed", "copied"} for item in selected)
    present = sum(outcomes.get(item["name"]) == "already_present" for item in selected)
    unknown = [item["day"] for item in selected if outcomes.get(item["name"]) in {None, "unknown"}] if state in {"reserved", "unknown"} else []
    failed = [item["day"] for item in selected if outcomes.get(item["name"]) == "failed"]
    if state == "prepared":
        message = "Review these exact closed days and the destination before continuing. Today's activity is excluded."
    elif state == "cancelled":
        message = "This review was cancelled. No maintenance action was started."
    elif state == "confirmed":
        message = (f"The original request encrypted {done} closed days." if row["action"] == "seal" else
                   f"The original request copied {done} closed days and verified {present} existing copies.")
    elif state == "failed":
        message = f"The original request completed with {len(failed)} days that could not be changed. Review the listed problems before a new action."
    else:
        message = "The original result remains uncertain. Read its saved result again; another copy or encryption action will not be started from this review."
    if row.get("_audit_pending"):
        message += " Its activity entry is still waiting to be recorded. Reading this result retries only that entry."
    if row.get("reconcile"):
        message += " This is a separate intentional request. Earlier uncertain effects remain unknown and may already exist."
    return {"review": row["id"], "operation": row.get("operation"), "action": row["action"], "state": state,
        "reconcile": row.get("reconcile", False), "prior_unknown_days": sorted({Path(item["name"]).stem for item in row.get("reconciliation", [])}),
        "context": row["context"], "workspace": row.get("workspace"), "source": "Selected workspace's activity log",
        "recorded_at": row["created_at"], "expires": row["expires"], "destination": row.get("destination_display") or {},
        "retain_until": row.get("retain_until"), "days": done, "already_present": present, "unknown_days": unknown,
        "failed_days": failed, "message": message,
        "rows": [{"day": item["day"], "bytes": item["bytes"], "encrypted": item["encrypted"],
                  "status": outcomes.get(item["name"], "unknown" if item["selected"] and state in {"reserved", "unknown"} else item["status"]),
                  "selected": item["selected"], "existing_retention": item.get("existing_retention")} for item in row["rows"]]}


def receipt(request, review, operation=None):
    # Read permission suffices for a person's earlier result after their write
    # authority is withdrawn. Rechecks never upload, seal or create keys.
    with authority_effect_fence():
        row = _bound_row(request, review)
        if operation is not None and row.get("operation") not in {None, operation}:
            raise HTTPException(409, "This review was used by a different request.")
        if row.get("_audit_pending"):
            row = store()._flush(row)
        row = _recover_native(row)
        return _plain(row)


def evidence(request, review):
    with authority_effect_fence():
        row = _bound_row(request, review)
        return {"kind": "lightwork-audit-maintenance-review", "review": row["id"], "action": row["action"],
            "source": row["source"], "workspace": row.get("workspace"), "actor": row["actor"], "context": row["context"],
            "source_revision": row["source_revision"], "rows": row["rows"], "destination": row["destination_display"],
            "retain_until": row["retain_until"], "operation": row.get("operation"), "state": row["state"],
            "outcomes": row.get("outcomes", {}), "meaning": "Exact reviewed source fingerprints and original request metadata. This file is not independent provider proof or proof that a business result is true."}


def inventory(request):
    actor, context = authority(request)
    values = store().list(limit=_LIMIT + 1)
    if len(values) > _LIMIT:
        raise HTTPException(409, "The saved review list is too large to read safely.")
    observation_problem = ""
    try:
        native_unknown = _unknown_copies()
        released = worm.released_versions(data_dir("audit"))
    except (HTTPException, worm.WormUnavailable, OSError, ValueError):
        native_unknown, released = [], set()
        observation_problem = "Current copy-attempt evidence could not be checked. Your retained original results remain readable; no current protection or hold release is confirmed."
    held = any(row.get("state") in {"reserved", "unknown"} and row.get("source") == str(data_dir("audit").absolute())
        and any(item["selected"] and row.get("outcomes", {}).get(item["name"]) not in {"sealed", "copied", "already_present", "failed"}
                and (row.get("request_id"), item["name"], item["sha256"]) not in released for item in row["rows"]) for row in values)
    return {"context": context, "native_unknown": native_unknown, "observation_problem": observation_problem,
        "separate_copy_available": not observation_problem and auth.has_global_permission(request, "admin") and bool(native_unknown or held),
        "reviews": [_plain(row) for row in sorted(values, key=lambda item: item["created_at"], reverse=True)
        if row.get("actor") == actor and row.get("context") == context and row.get("source") == str(data_dir("audit").absolute())][:100]}


def _pending_bindings(state):
    values = store().list(limit=_LIMIT + 1)
    if len(values) > _LIMIT:
        raise HTTPException(409, "Earlier maintenance requests could not all be checked. No new action was started.")
    selected = {(item["name"], item["sha256"]) for item in state["rows"]}
    released = worm.released_versions(Path(state["source"]))
    held_by_version = {}
    for item in worm.unknown_attempts(Path(state["source"])):
        version = (item["name"], item["sha256"])
        if version in selected:
            held_by_version.setdefault(version, set()).add(item["request_id"])
    for row in values:
        if row.get("state") not in {"reserved", "unknown"} or row.get("source") != state["source"]:
            continue
        row = _recover_native(row)
        if row["state"] not in {"reserved", "unknown"}:
            continue
        outcomes = row.get("outcomes") or {}
        for item in row["rows"]:
            version = (item["name"], item["sha256"])
            prior = row.get("request_id")
            if (prior and item["selected"] and version in selected
                    and outcomes.get(item["name"]) not in {"sealed", "copied", "already_present", "failed"}
                    and (prior, *version) not in released):
                held_by_version.setdefault(version, set()).add(prior)
    return [{"name": name, "sha256": sha, "prior_request_ids": sorted(prior)}
            for (name, sha), prior in sorted(held_by_version.items())]


def _holds(state):
    if state["reconciliation"] and not state["reconcile"]:
        raise HTTPException(409, "An earlier request for these record versions has an uncertain result. Read its saved result first. An administrator can separately review a new intentional copy; the earlier result remains unknown.")


def prepare(request, action, *, reconcile=False):
    with authority_effect_fence():
        state = current(request, action, reconcile=reconcile)
        _holds(state)
        if action == "copy" and not any(row["selected"] for row in state["rows"]) and any("uncertain" in row["status"] for row in state["rows"]):
            raise HTTPException(409, "An earlier native copy has no recorded completion proof. Its original result remains uncertain; no replacement copy was started. Read saved copy attempts and check the destination independently.")
        retain_until = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=state["destination"]["retention_days"])).isoformat() if action == "copy" else None
        source_revision = state.pop("revision")
        row = store().create({**state, "source_revision": source_revision, "id": "AAR-" + secrets.token_hex(16), "state": "prepared",
            "expires": time.time() + TTL, "retain_until": retain_until, "outcomes": {}, "acknowledge_uncertain": False},
            action="audit_action_reviewed", actor=state["actor"])
        if row.get("_audit_pending"):
            raise HTTPException(503, "This review could not be recorded. No maintenance action was started.")
        return _plain(row)


def cancel(request, review):
    with authority_effect_fence():
        row = _bound_row(request, review)
        if row["state"] != "prepared":
            return _plain(row)
        return _plain(_update(row, state="cancelled"))


def _retain_report(row, report, selected):
    outcomes = dict(row.get("outcomes") or {})
    for name, status in report.items():
        if status in {"sealed", "pushed", "re-pushed (changed)"}:
            outcomes[name] = "sealed" if row["action"] == "seal" else "copied"
        elif status in {"already sealed", "already pushed"}:
            outcomes[name] = "already_present"
        elif status.startswith("refused"):
            outcomes[name] = "failed"
        else:
            outcomes[name] = "unknown"
    unknown = any(outcomes.get(name) in {None, "unknown"} for name in selected)
    failed = any(outcomes.get(name) == "failed" for name in selected)
    return _update(row, outcomes=outcomes, state="unknown" if unknown else "failed" if failed else "confirmed")


def execute(request, action, review, operation, *, acknowledge_uncertain=False):
    if not isinstance(operation, str) or not _OP.fullmatch(operation):
        raise HTTPException(422, "The original request reference is missing. Review the action again.")
    with authority_effect_fence():
        row = _bound_row(request, review)
        if row["action"] != action:
            raise HTTPException(409, "Review this exact maintenance action before continuing.")
        if row["state"] != "prepared":
            if row.get("operation") == operation:
                return receipt(request, review, operation)
            raise HTTPException(409, "This review was already used or cancelled. Read its saved result.")
        authority(request, action)
        if time.time() >= row["expires"]:
            raise HTTPException(409, "This review expired. Check the closed days and prepare a fresh review.")
        if row.get("reconcile") and acknowledge_uncertain is not True:
            raise HTTPException(409, "Acknowledge that the earlier copy may already exist and remains unknown before authorizing this separate copy.")
        state = current(request, action, reconcile=row.get("reconcile", False))
        if state["revision"] != row["source_revision"]:
            raise HTTPException(409, "The records, encryption or copy destination changed. Nothing was started; review the current state again.")
        _holds(state)
        selected = {item["name"]: item["sha256"] for item in row["rows"] if item["selected"]}
        if not selected:
            raise HTTPException(409, "There are no eligible closed days in this review. Nothing was started.")
        request_id = digest([row["id"], row["actor"], row["context"], operation, action, selected, row["destination"], row["retain_until"]])
        row = _update(row, state="reserved", operation=operation, request_id=request_id,
                      acknowledge_uncertain=bool(row.get("reconcile") and acknowledge_uncertain))
        if row.get("_audit_pending"):
            return _plain(row)  # Reserved remains no-repeat if audit delivery fails.

        return _perform(request, row, selected)


def _perform(request, row, selected):
    action, request_id = row["action"], row["request_id"]
    def guard(name, sha):
        authority(request, action)
        if context_for(request) != row["context"] or time.time() >= row["expires"]:
            raise HTTPException(409, "The authority or review deadline changed before this day could be changed.")
        if selected.get(name) != sha or str(data_dir("audit").absolute()) != row["source"]:
            raise HTTPException(409, "The reviewed source changed before this day could be changed.")
        if at_rest_enabled() != row["encryption"] or config.config_source_errors(include_tenant=True):
            raise HTTPException(409, "The encryption or installation settings changed before this day could be changed.")
        if action == "copy" and _destination()[0] != row["destination"]:
            raise HTTPException(409, "The copy destination or retention setting changed. No further copy was started.")

    def completed(name, status):
        nonlocal row
        outcomes = {**row.get("outcomes", {}), name: "sealed" if action == "seal" else "copied"}
        row = _update(row, outcomes=outcomes)
        if row.get("_audit_pending"):
            raise RuntimeError("completion audit pending")

    def reconciliation(name, sha, pending):
        guard(name, sha)
        current_row = _bound_row(request, row["id"], write=True)
        item = next((item for item in current_row["reconciliation"] if item["name"] == name and item["sha256"] == sha), None)
        if not item:
            return None
        if not set(pending).issubset(item["prior_request_ids"]):
            raise HTTPException(409, "The uncertain holds changed. No new copy was started for this day.")
        return row["id"]

    try:
        if action == "seal":
            from maverick.audit.sealing import seal_closed_segments
            report = seal_closed_segments(Path(row["source"]), expected_sources=selected, before_effect=guard, completed=completed)
        else:
            report = worm.push_closed_dayfiles(audit_dir=Path(row["source"]), expected_sources=selected,
                retention_days=row["destination"]["retention_days"], retain_until=dt.datetime.fromisoformat(row["retain_until"]),
                request_id=request_id, before_effect=guard, completed=completed,
                reconcile=reconciliation if row.get("reconcile") else None)
        row = _retain_report(row, report, selected)
    except Exception:
        # A writer/transport can fail after publication. Current state is
        # never used as attribution and an unknown effect is never repeated.
        row = _recover_native(row)
        if row["state"] != "confirmed":
            row = _update(row, state="unknown")
    return _plain(row)


def check_copies(request):
    authority(request)
    binding, display = _destination()
    try:
        report = worm.verify()
    except (worm.WormUnavailable, OSError, ValueError) as exc:
        raise HTTPException(409, "The stored copies or their proof could not be checked. Check the destination on the Compliance page.") from exc
    authority(request)
    if _destination()[0] != binding:
        raise HTTPException(409, "The copy destination changed during this check. Check again.")
    problems = [{"day": name.removesuffix(".ndjson"), "message": "The current source or saved destination proof could not be verified."}
                for name, status in report.items() if status != "ok"]
    unknown = _unknown_copies()
    return {"days": len(report), "copied": len(report) - len(problems), "not_copied": [row["day"] for row in problems],
        "problems": problems, "empty": not report, "destination": display,
        "native_unknown": unknown, "automatic_copy_enabled": worm.worm_enabled(),
        "message": "There are no closed days to check. The destination was not tested." if not report else
                   "The reported matching copies have the current source bytes, a signed completion record and matching destination evidence. Object storage reports its version and retention setting; local storage is checked for read-only permissions. This does not establish independent custody, future availability or who approved a business result."}


def _unknown_copies():
    try:
        pending = worm.unknown_attempts(data_dir("audit"))
    except (worm.WormUnavailable, OSError, ValueError) as exc:
        raise HTTPException(409, "Saved copy attempts could not be verified. Check their signed evidence before considering another copy.") from exc
    return [{"day": row["name"].removesuffix(".ndjson"), "attempted_at": row["attempted_at"],
             "retain_until": row["retain_until"], "destination": row["destination"],
             "meaning": "This signed attempt has no matching recorded completion. A copy may exist. No repeat is authorized by reading this evidence."} for row in pending]

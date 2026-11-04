"""Exact deployment-policy custody and non-replayable reviewed restoration."""
from __future__ import annotations

import hashlib
import json
import secrets
import stat
import time
from contextlib import contextmanager

from . import config, crypto_at_rest
from . import runtime_overrides as native
from .authority_effects import authority_effect_fence
from .file_lock import atomic_write_text, cross_process_lock
from .governed_records import GovernedRecordStore
from .paths import reset_tenant, set_tenant

MAX_COPIES = 32
MAX_REQUESTS = 10_000


class PolicyRecoveryUnavailable(RuntimeError):
    """No exact trusted source can safely complete this operation."""


@contextmanager
def deployment():
    token = set_tenant(None)
    try:
        with crypto_at_rest.deployment_key_scope():
            yield
    finally:
        reset_tenant(token)


def enabled():
    with deployment():
        return not config.config_source_errors() and config.get_features().get("workspace_recovery") is True


def target():
    return hashlib.sha256(str(native.overrides_path().absolute()).encode()).hexdigest()


def store(*, requests=False):
    # Two literal declarations keep both namespaces visible to the closed
    # recovery-authority registry check.
    if requests:
        return GovernedRecordStore("runtime-policy-requests", "RPR", "runtime_policy_request",
                                   authority_scope="deployment_global")
    return GovernedRecordStore("runtime-policy-copies", "RPC", "runtime_policy_copy",
                               authority_scope="deployment_global", archive_when_full=False)


def source():
    """Bind all exact current bytes; never replace an unreadable special file."""
    path = native.overrides_path()
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"target": target(), "missing": True, "sha256": None}, None
    if not stat.S_ISREG(info.st_mode) or info.st_size > native._MAX_OVERRIDE_BYTES:
        raise PolicyRecoveryUnavailable("Saved safety settings exceed the supported file boundary. Nothing was replaced or discarded.")
    with path.open("rb") as stream:
        raw = stream.read(native._MAX_OVERRIDE_BYTES + 1)
    if len(raw) > native._MAX_OVERRIDE_BYTES:
        raise PolicyRecoveryUnavailable("Saved safety settings changed or exceed the supported size. Nothing was replaced.")
    return {"target": target(), "missing": False, "sha256": hashlib.sha256(raw).hexdigest()}, raw


def validated(text):
    if not isinstance(text, str) or len(text.encode()) > native._MAX_OVERRIDE_BYTES:
        raise PolicyRecoveryUnavailable("This saved safety-settings copy exceeds the supported size.")
    try:
        return native._validate_loaded_state(native._tomllib().loads(text))
    except (UnicodeError, ValueError) as exc:
        raise PolicyRecoveryUnavailable("This saved safety-settings copy cannot be validated. Nothing was restored.") from exc


def copies():
    with deployment():
        selected = store()
        rows = selected.list(limit=MAX_COPIES + 1)
        rows = [selected._flush(row) if row.get("_audit_pending") else row for row in rows]
    if len(rows) > MAX_COPIES:
        raise PolicyRecoveryUnavailable("The saved safety-settings inventory exceeds its retained limit. Nothing was omitted.")
    return sorted((row for row in rows if row.get("target") == target() and row.get("status") == "valid"),
        key=lambda row: (row["created_at"], row["id"]), reverse=True)


def retained(identifier):
    with deployment():
        row = store().get(identifier)
        if row and row.get("_audit_pending"):
            row = store()._flush(row)
        if (row is None or row.get("target") != target() or row.get("status") != "valid"
                or row.get("_audit_pending")):
            raise PolicyRecoveryUnavailable("This exact saved safety-settings copy is unavailable or its activity record is unconfirmed. Choose another retained copy.")
        if not crypto_at_rest.is_sealed_str(row.get("body")):
            raise PolicyRecoveryUnavailable("Encrypted safety-settings custody could not be verified.")
        try:
            text = crypto_at_rest.unseal_from_str(row["body"])
        except Exception as exc:
            raise PolicyRecoveryUnavailable("The protected saved copy could not be decrypted with this installation's key. Nothing was restored.") from exc
    state = validated(text)
    if hashlib.sha256(text.encode()).hexdigest() != row.get("source_sha256"):
        raise PolicyRecoveryUnavailable("The saved safety-settings copy failed verification. Nothing was restored.")
    return row, text, state


def retain(text, *, valid=True, actor="system", operation=None, preserve=None):
    """Retain exact observed bytes; encrypted bodies never enter activity rows."""
    if valid:
        validated(text)
    fingerprint = hashlib.sha256(text.encode()).hexdigest()
    with deployment():
        selected = store()
        rows = selected.list(limit=MAX_COPIES + 1)
        if len(rows) > MAX_COPIES:
            raise PolicyRecoveryUnavailable("Saved safety-settings custody exceeds its bounded inventory.")
        for row in rows:
            if row.get("target") == target() and row.get("source_sha256") == fingerprint and row.get("status") == ("valid" if valid else "damaged"):
                row = selected._flush(row) if row.get("_audit_pending") else row
                if row.get("_audit_pending"):
                    raise PolicyRecoveryUnavailable("The saved safety-settings activity record is unavailable. No new restoration can start.")
                return row
        if len(rows) == MAX_COPIES:
            oldest = min((row for row in rows if not row.get("_audit_pending") and row["id"] != preserve),
                key=lambda row: row["created_at"], default=None)
            if oldest is None or not selected.delete(oldest["id"], expected_revision=oldest["revision"]):
                raise PolicyRecoveryUnavailable("Saved safety-settings custody is full. Its pending activity records must be resolved first.")
        body = crypto_at_rest.seal_to_str(text)
        if not crypto_at_rest.is_sealed_str(body):
            raise PolicyRecoveryUnavailable("Encrypted safety-settings custody is unavailable. Nothing was restored.")
        row = selected.create({"id": "RPC-" + secrets.token_hex(16), "target": target(),
            "source_sha256": fingerprint, "body": body, "status": "valid" if valid else "damaged",
            "operation": operation}, action="retain_valid" if valid else "preserve_damaged", actor=actor, max_records=MAX_COPIES)
        if row.get("_audit_pending"):
            raise PolicyRecoveryUnavailable("The safety-settings copy was retained, but its activity record is unconfirmed.")
        return row


def retain_current():
    if not enabled():
        return
    _binding, raw = source()
    if raw is not None:
        retain(raw.decode("utf-8"))


def retain_written(text):
    if enabled():
        _binding, raw = source()
        if raw is None or validated(raw.decode("utf-8")) != validated(text):
            raise PolicyRecoveryUnavailable("Saved safety settings changed before their exact copy could be retained. The write's outcome is unconfirmed; inspect current settings.")
        retain(raw.decode("utf-8"))


def original(operation, actor, owner):
    with deployment():
        selected = store(requests=True)
        row = selected.get("RPR-" + operation)
        if row is not None and (row.get("actor") != actor or row.get("owner") != owner or row.get("target") != target()):
            raise PolicyRecoveryUnavailable("This original restoration belongs to another account, workspace or installation.")
        if row and row.get("_audit_pending"):
            row = selected._flush(row)
        return row


def restore(value, *, actor, owner, guard):
    """Claim once, then guard the physical native replace; never infer a receipt."""
    with authority_effect_fence(), native._OVERRIDE_LOCK, cross_process_lock(native.overrides_path(), strict=True):
        previous = original(value["operation"], actor, owner)
        if previous is not None:
            if previous["nonce"] != value["nonce"]:
                raise PolicyRecoveryUnavailable("The original request belongs to a different review.")
            return previous
        guard()
        row, text, state = retained(value["snapshot"])
        if row["revision"] != value["snapshot_revision"] or row["source_sha256"] != value["snapshot_source"]:
            raise PolicyRecoveryUnavailable("The selected saved copy changed after the complete review. Nothing was restored.")
        def current():
            guard()
            if time.time() >= value["expires"] or source()[0] != value["before"]:
                raise PolicyRecoveryUnavailable("The safety settings or review changed. Nothing was repeated. Review the current source again.")
            now, now_text, _state = retained(value["snapshot"])
            if now["revision"] != row["revision"] or now_text != text:
                raise PolicyRecoveryUnavailable("The selected saved copy changed after review. Nothing was restored.")
            if source()[0] != value["before"]:
                raise PolicyRecoveryUnavailable("Current safety settings changed while checking the saved copy. This request is unconfirmed and was not repeated; review the current source again.")
            guard()
            if time.time() >= value["expires"]:
                raise PolicyRecoveryUnavailable("This complete review expired while checking its source. Nothing was restored; review it again.")
        current()
        with deployment():
            selected = store(requests=True)
            claim = selected.create({"id": "RPR-" + value["operation"], "actor": actor, "owner": owner,
                "target": target(), "nonce": value["nonce"], "snapshot": row["id"], "state": "unconfirmed"},
                action="restore_prepared", actor=actor, max_records=MAX_REQUESTS)
        if claim.get("_audit_pending"):
            return claim
        _binding, raw = source()
        if raw is not None:
            try:
                old = raw.decode("utf-8")
                validated(old)
                valid = True
            except (UnicodeError, PolicyRecoveryUnavailable):
                old = json.dumps({"bytes_hex": raw.hex()}, separators=(",", ":"))
                valid = False
            retain(old, valid=valid, actor=actor, operation=value["operation"], preserve=row["id"])
        atomic_write_text(native.overrides_path(), text, effect_guard=current, newline="")
        native._remember_valid(native._cache_key(native.overrides_path()), state)
        with deployment():
            return selected.update(claim["id"], lambda saved: saved.update(state="confirmed", accepted_at=time.time()),
                expected_revision=claim["revision"], action="restore_completed", actor=actor)

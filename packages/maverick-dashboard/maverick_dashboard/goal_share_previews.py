"""Exact-payload gist review and durable disclosure-attempt receipts."""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from contextlib import nullcontext

from maverick.crypto_at_rest import is_sealed, seal, unseal
from maverick.file_lock import (
    atomic_read_bytes,
    atomic_write_bytes,
    cross_process_lock,
    ensure_private_directory,
)
from maverick.paths import data_dir
from maverick.run_share import build_gist_payload, resolve_token, upload_payload

MAX_BYTES = 8 * 1024 * 1024
LIFETIME = 600


def _directory(context):
    return ensure_private_directory(data_dir("goal-share-previews", context))


def _write(path, value):
    atomic_write_bytes(path, seal(json.dumps(value).encode()))


def _read(path):
    if path.stat().st_size > MAX_BYTES * 3:
        raise ValueError("The reviewed copy exceeds the supported size.")
    raw = atomic_read_bytes(path)
    if not is_sealed(raw):
        raise ValueError("The reviewed copy could not be verified.")
    return json.loads(unseal(raw))


def _headers(token):
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"}


def _check_source(before_effect, expected=None):
    if before_effect is None:
        return None
    current = before_effect()
    if expected is not None and current != expected:
        raise ValueError("The task or its release decision changed. Prepare and review the current copy before sharing.")
    return current


def prepare(context, goal_id, *, before_effect=None):
    import httpx

    source_version = _check_source(before_effect)
    token = resolve_token()
    payload = build_gist_payload(goal_id)  # evidence failures precede any disclosure
    _check_source(before_effect, source_version)
    response = httpx.get("https://api.github.com/user", headers=_headers(token), timeout=15)
    response.raise_for_status()
    _check_source(before_effect, source_version)
    account = response.json().get("login")
    if not isinstance(account, str) or not account:
        raise ValueError("The destination account could not be confirmed.")
    identifier = secrets.token_hex(16)
    payload["description"] += f" [Lightwork share {identifier}]"
    exact = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if len(exact.encode()) > MAX_BYTES:
        raise ValueError("This evidence report exceeds the supported sharing size. Nothing was uploaded.")
    digest = hashlib.sha256(exact.encode()).hexdigest()
    envelope = {"context": context, "goal_id": goal_id, "created_at": time.time(), "state": "prepared",
                "payload": payload, "sha256": digest, "account": account,
                "token_hash": hashlib.sha256(token.encode()).hexdigest(),
                "source_version": source_version}
    directory = _directory(context)
    with cross_process_lock(directory / "index", strict=True):
        # Completed/uncertain attempt records remain available for reconciliation.
        for path in directory.glob("*.preview"):
            if path.stat().st_mtime < time.time() - LIFETIME:
                old = _read(path)
                if old.get("state") == "prepared":
                    path.unlink()
        receipts = list(directory.glob("*.preview"))
        if len(receipts) >= 10000:
            raise ValueError("The sharing history reached its supported limit. Ask an administrator to review receipt retention before preparing another copy.")
        if sum(_read(path).get("state") in {"prepared", "dispatching", "unknown"} for path in receipts) >= 100:
            raise ValueError("There are too many unresolved sharing attempts. Reconcile those attempts before preparing another copy.")
        _check_source(before_effect, source_version)
        _write(directory / (identifier + ".preview"), envelope)
    return {"preview_id": identifier, "sha256": digest, "account": account,
            "payload": payload, "scope": "Redacted audit replay and proof evidence; different from the technical task archive. Business content may remain. Anyone with the secret gist link can read it."}


def attempts(context, goal_id):
    rows = []
    for path in _directory(context).glob("*.preview"):
        item = _read(path)
        if item.get("context") == context and item.get("goal_id") == goal_id and item.get("state") != "prepared":
            rows.append({"attempt": path.stem, "state": item["state"], "account": item["account"],
                         "created_at": item["created_at"], "url": item.get("url")})
    return {"attempts": sorted(rows, key=lambda row: row["created_at"], reverse=True)}


def send(context, goal_id, identifier, digest, *, before_effect=None):
    import httpx
    from fastapi import HTTPException
    from maverick.audit import audit_event
    from maverick.authority_effects import authority_effect_fence

    token = resolve_token()
    directory = _directory(context)
    path = directory / (identifier + ".preview")
    # Keep the sidecar lock shorter than the sealed receipt's ".preview" path.
    # Windows rejects the appended ".lock" when a temp/private root is deep.
    with cross_process_lock(directory / identifier, strict=True):
        item = _read(path)
        if item.get("context") != context or item.get("goal_id") != goal_id:
            raise ValueError("This review belongs to a different task or account.")
        if not hmac.compare_digest(item["sha256"], digest):
            raise ValueError("The upload does not match the reviewed content.")
        actual = hashlib.sha256(json.dumps(item["payload"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if not hmac.compare_digest(actual, digest):
            raise ValueError("The saved content no longer matches its reviewed fingerprint.")
        if item["state"] == "shared":
            return {"shared": True, "url": item["url"], "attempt": identifier}
        if item["state"] == "rejected":
            return {"shared": False, "outcome": "rejected", "attempt": identifier,
                    "message": "GitHub rejected this request. Prepare a new reviewed copy after correcting the connection."}
        if item["state"] in {"dispatching", "unknown"}:
            return {"shared": False, "outcome": "unknown", "attempt": identifier,
                    "message": "GitHub may have received this copy. Check the attempt on GitHub before creating another copy."}
        if before_effect is not None and not item.get("source_version"):
            raise ValueError("This earlier copy has no current release review. Prepare and review a new copy before sharing.")
        _check_source(before_effect, item.get("source_version"))
        if not 0 <= time.time() - item["created_at"] <= LIFETIME:
            raise ValueError("This review expired. Prepare and review a new copy.")
        if not hmac.compare_digest(item["token_hash"], hashlib.sha256(token.encode()).hexdigest()):
            raise ValueError("The GitHub connection changed. Prepare and review a new copy.")
        audit_event("goal_shared_gist", agent="dashboard", goal_id=goal_id,
                    actor=context, phase="dispatch", attempt=identifier, sha256=digest)
        item["state"] = "dispatching"
        _write(path, item)  # crash after dispatch must never silently resend
        # An authority refusal after retaining the attempt leaves an unresolved
        # original; the same request must not automatically become a new send.
        try:
            with authority_effect_fence() if before_effect is not None else nullcontext():
                _check_source(before_effect, item.get("source_version"))
                url = upload_payload(item["payload"], token)
        except HTTPException:
            raise
        except httpx.HTTPStatusError as exc:
            if 400 <= exc.response.status_code < 500:
                item["state"] = "rejected"
                _write(path, item)
                return {"shared": False, "outcome": "rejected", "attempt": identifier,
                        "message": "GitHub rejected this request. Review the connection permissions before preparing another copy."}
            item["state"] = "unknown"
            _write(path, item)
            return {"shared": False, "outcome": "unknown", "attempt": identifier,
                    "message": "GitHub reported a server error; this copy may already exist. Check the attempt before another upload."}
        except Exception:
            item["state"] = "unknown"
            _write(path, item)
            return {"shared": False, "outcome": "unknown", "attempt": identifier,
                    "message": "The upload result is unknown. GitHub may already hold this copy. Reconcile this attempt before choosing to upload again."}
        item.update(state="shared", url=url)
        _write(path, item)
        return {"shared": True, "url": url, "attempt": identifier}


def reconcile(context, goal_id, identifier):
    """Lookup is read-only; absence from this bounded window is not non-disclosure."""
    import httpx

    directory = _directory(context)
    path = directory / (identifier + ".preview")
    with cross_process_lock(directory / identifier, strict=True):
        item = _read(path)
        if item.get("context") != context or item.get("goal_id") != goal_id:
            raise ValueError("This attempt belongs to a different task or account.")
        token = resolve_token()
        if not hmac.compare_digest(item["token_hash"], hashlib.sha256(token.encode()).hexdigest()):
            raise ValueError("The GitHub connection changed. Check the original destination account directly.")
        response = httpx.get("https://api.github.com/gists?per_page=100", headers=_headers(token), timeout=15)
        response.raise_for_status()
        for gist in response.json():
            if gist.get("description") == item["payload"]["description"]:
                url = gist.get("html_url", "")
                if isinstance(url, str) and url.startswith("https://gist.github.com/"):
                    item.update(state="shared", url=url)
                    _write(path, item)
                    return {"shared": True, "url": url, "attempt": identifier}
        return {"shared": False, "outcome": "unknown", "attempt": identifier,
                "message": "No match appeared in the latest 100 gists. This does not prove no copy exists. Check the destination account; remove any unwanted copy there."}

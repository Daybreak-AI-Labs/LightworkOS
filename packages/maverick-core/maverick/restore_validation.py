"""Read-only validation of supported local references in a private restore stage.

This intentionally does not open live application stores, decrypt with ambient
keys, certify external effects, or validate every application invariant.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from collections.abc import Callable
from pathlib import Path
from urllib.parse import unquote

SCHEMA = "lightwork.restore-reference-validation.v1"
APPLICATION_REFERENCE_SCOPE = (
    "local vendor-onboarding vendor, "
    "assessment and renewal references and their supported tenant/owner/vendor-name bindings; "
    "no application decryption, other cross-file business invariants or external-system acceptance"
)
VERIFICATION_SCOPE = "file hashes, sizes and SQLite integrity; " + APPLICATION_REFERENCE_SCOPE
_STORES = {
    "vendor_onboarding": ("VON", "lightwork.vendor-onboarding.v1"),
    "vendor_management": ("VMR", "lightwork.vendor-record.v1"),
    "ai_vendor_risk": ("AIV", "lightwork.ai-vendor-risk.v1"),
}
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_MAX_RECORD_BYTES = 16 * 1024 * 1024
_MAX_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_RECORDS = 25_000


class RestoreValidationError(ValueError):
    """The staged application state cannot be accepted in the supported scope."""


def _fail(path, detail):
    raise RestoreValidationError(
        f"Restore application validation failed: {path}: {detail}. "
        "Restore a complete compatible workspace snapshot or reconcile these records "
        "in a separate staged copy before retrying; live application files were not changed."
    )


def _roots(root, tenant, whole_home):
    yield root, tenant
    tenants = root / "tenants"
    if tenants.exists():
        if not whole_home:
            _fail("tenants/", "nested workspaces require a whole-installation recovery scope")
        from .paths import _tenant_segment

        for child in tenants.iterdir():
            try:
                name = unquote(child.name, errors="strict")
                valid_name = bool(name) and _tenant_segment(name) == child.name
            except (UnicodeError, ValueError):
                valid_name = False
            if not child.is_dir() or not valid_name:
                _fail("tenants/", "unsupported tenant directory binding")
            yield child, name


def guard_additive_restore(root: Path, stage: Path, *, whole_home: bool) -> None:
    """An overlay can strand retained live references; require full replacement."""
    for tree in (root, stage):
        for workspace, _ in _roots(tree, None, whole_home):
            for namespace in _STORES:
                if (workspace / namespace).exists():
                    _fail(namespace, "additive restore of governed stores is unsupported; use isolated full-workspace replacement")


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("non-finite JSON constant")


def _read(path, relative, namespace, *, tenant, workspace, decryptor):
    try:
        with path.open("rb") as stream:
            raw = stream.read(_MAX_RECORD_BYTES + 1)
        if len(raw) > _MAX_RECORD_BYTES:
            _fail(relative, "record exceeds the 16 MiB validation bound")
        stripped = raw.lstrip()
        if stripped.startswith((b'"MVKAR', b'"MVKTEN')) and decryptor is None:
            _fail(
                relative,
                "encrypted record requires separately reviewed key-custody and decryption validation",
            )
        if stripped.startswith((b"MVKAR", b"MVKTEN")):
            if decryptor is None:
                _fail(relative, "encrypted record requires separately reviewed key-custody and decryption validation")
            raw = decryptor(stripped, tenant, workspace)
        record = json.loads(raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
        if isinstance(record, str) and record.startswith("MVKAR1:"):
            if decryptor is None:
                _fail(relative, "encrypted record requires separately reviewed key-custody and decryption validation")
            try:
                blob = base64.b64decode(record[len("MVKAR1:"):], validate=True)
            except (ValueError, TypeError, binascii.Error) as exc:
                raise ValueError("invalid encrypted text record") from exc
            record = json.loads(
                decryptor(blob, tenant, workspace).decode("utf-8"),
                object_pairs_hook=_object,
                parse_constant=_constant,
            )
    except Exception as exc:
        if isinstance(exc, RestoreValidationError):
            raise
        _fail(relative, "record is unreadable or is not unambiguous JSON")
    prefix, schema = _STORES[namespace]
    if (not isinstance(record, dict) or record.get("id") != path.stem
            or not _ID.fullmatch(path.stem) or not path.stem.startswith(prefix + "-")):
        _fail(relative, "record identity does not match the supported store path")
    if record.get("schema") != schema:
        _fail(relative, "record schema requires a reviewed compatibility migration")
    return record, len(raw)


def _reference(records, path, field, namespace, identity):
    prefix = _STORES[namespace][0]
    if not isinstance(identity, str) or not _ID.fullmatch(identity) or not identity.startswith(prefix + "-"):
        _fail(path, f"{field} contains an invalid {namespace} reference")
    target = records[namespace].get(identity)
    if target is None:
        _fail(path, f"{field} -> {namespace}/{identity}: target is missing from this workspace")
    return target


def _case_references(case, records, path, tenant):
    if not tenant or case.get("tenant") != tenant:
        _fail(path, "tenant does not match the recovery workspace")
    vendor = _reference(records, path, "vendor_id", "vendor_management", case.get("vendor_id"))
    if not isinstance(case.get("owner"), str) or not case["owner"] or vendor.get("owner") != case["owner"]:
        _fail(path, "vendor_id owner binding does not match vendor_management/" + vendor["id"])
    name = case.get("vendor_name")
    if (not isinstance(name, str) or not name.strip() or not isinstance(vendor.get("name"), str)
            or name.strip().lower() != vendor["name"].strip().lower()):
        _fail(path, "vendor_name binding does not match vendor_management/" + vendor["id"])
    assessment = case.get("assessment")
    if assessment is not None:
        if not isinstance(assessment, dict):
            _fail(path, "assessment reference is not an object")
        target = _reference(records, path, "assessment.id", "ai_vendor_risk", assessment.get("id"))
        if target.get("tenant_sha256") != hashlib.sha256(tenant.encode("utf-8")).hexdigest():
            _fail(path, "assessment.id tenant binding does not match ai_vendor_risk/" + target["id"])
        if (not isinstance(target.get("vendor"), str)
                or " ".join(name.casefold().split()) != " ".join(target["vendor"].casefold().split())):
            _fail(path, "assessment.id vendor binding does not match ai_vendor_risk/" + target["id"])
    if case.get("renewal_of") is not None:
        prior = _reference(records, path, "renewal_of", "vendor_onboarding", case["renewal_of"])
        if (prior["id"] == case["id"] or prior.get("tenant") != tenant
                or prior.get("owner") != case["owner"] or prior.get("vendor_id") != case["vendor_id"]):
            _fail(path, "renewal_of scope binding does not match vendor_onboarding/" + prior["id"])


def validate_staged_restore(
    stage: Path,
    *,
    tenant: str | None,
    whole_home: bool = False,
    decryptor: Callable[[bytes, str | None, Path], bytes] | None = None,
) -> dict:
    """Validate complete archived local stores without a live-store fallback."""
    count = total_bytes = case_count = 0
    for workspace, workspace_tenant in _roots(stage, None if whole_home else tenant, whole_home):
        records = {namespace: {} for namespace in _STORES}
        for namespace in _STORES:
            directory = workspace / namespace
            for path in directory.glob("*.json"):
                relative = path.relative_to(stage).as_posix()
                if not path.is_file():
                    _fail(relative, "record is not a regular file")
                record, size = _read(
                    path,
                    relative,
                    namespace,
                    tenant=workspace_tenant,
                    workspace=workspace,
                    decryptor=decryptor,
                )
                count += 1
                total_bytes += size
                if count > _MAX_RECORDS or total_bytes > _MAX_TOTAL_BYTES:
                    _fail(relative, "workspace exceeds the bounded application-validation capacity")
                records[namespace][record["id"]] = record
        for case in records["vendor_onboarding"].values():
            path = (workspace / "vendor_onboarding" / (case["id"] + ".json")).relative_to(stage).as_posix()
            _case_references(case, records, path, workspace_tenant)
            case_count += 1
    return {"schema": SCHEMA, "scope": APPLICATION_REFERENCE_SCOPE, "records_checked": count,
            "cases_checked": case_count, "coverage_complete": False}

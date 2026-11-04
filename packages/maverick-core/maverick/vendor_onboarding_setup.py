"""Workspace-private onboarding bindings; deployment feature gates stay global."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict

from . import config, connections
from .governed_records import GovernedRecordStore, RecordConflict
from .paths import current_tenant_id_strict, data_dir
from .vendor_onboarding_config import VendorOnboardingSettings

STORE = GovernedRecordStore("vendor_onboarding_setup", "VOS", "vendor_onboarding_setup")
RECORD_ID = "VOS-workspace"
REQUIRED_MODULES = ("connections", "vendor_onboarding", "vendor_management", "ai_vendor_risk", "model_risk_assurance", "evidence_graph")


def current():
    if not current_tenant_id_strict():
        raise PermissionError("Select a workspace before configuring vendor onboarding.")
    return STORE.get(RECORD_ID)


def settings(loaded: dict) -> VendorOnboardingSettings:
    row = current()
    if row is None:
        return VendorOnboardingSettings.from_config(loaded)
    raw = row.get("binding")
    if not isinstance(raw, dict):
        raise ValueError("Workspace vendor configuration is unavailable.")
    deployment = loaded.get("vendor_onboarding") or {}
    if not isinstance(deployment, dict):
        raise ValueError("vendor_onboarding must be a closed configuration table")
    value = dict(raw, enable=deployment.get("enable") is True)
    # How often and how patiently a safe read is retried is deployment policy
    # (Settings > All settings), not part of a workspace's saved binding.
    for key in ("safe_read_attempts", "safe_read_backoff_seconds"):
        if key in deployment:
            value[key] = deployment[key]
    return VendorOnboardingSettings.from_config({"vendor_onboarding": value})


@contextmanager
def _workflow_lock():
    # Initial ownership selection shares the case-creation lock, so a historical
    # case cannot appear between reviewing the empty workspace and saving it.
    from .file_lock import cross_process_lock
    from .vendor_onboarding import _LOCK
    with _LOCK, cross_process_lock(data_dir("vendor_onboarding", "saga"), strict=True):
        yield


def owner_policy():
    """Only a fresh workspace may choose; saved/deployment/history owners stay fixed."""
    with _workflow_lock():
        return _owner_policy()


def _owner_policy():
    from .vendor_onboarding import _CASES
    previous = current()
    if previous:
        owner = previous["binding"]["resource_owner"]
        if not isinstance(owner, str) or not owner:
            raise ValueError("The existing vendor owner is unavailable.")
        return {"resource_owner": owner, "owner_locked": True, "owner_source": "saved"}
    configured = VendorOnboardingSettings.from_config({"vendor_onboarding": dict(
        config.load_config().get("vendor_onboarding") or {}, enable=False)}).resource_owner
    if configured:
        return {"resource_owner": configured, "owner_locked": True, "owner_source": "configured"}
    # Match the existing case capacity without loading all evidence bodies at
    # once. This legacy-history check runs only before any setup binding exists.
    historical_owner = None
    for count, (_, identifier) in enumerate(_CASES.iter_record_ids(limit=10001), 1):
        if count > 10000:
            raise ValueError("Existing vendor history exceeds its supported capacity.")
        row = _CASES.get(identifier)
        owner = (row or {}).get("owner")
        if not isinstance(owner, str) or not owner or (historical_owner and historical_owner != owner):
            raise ValueError("Existing vendor cases have conflicting or unavailable owners. Ownership was not changed.")
        historical_owner = owner
    if historical_owner:
        return {"resource_owner": historical_owner, "owner_locked": True, "owner_source": "historical"}
    return {"resource_owner": "", "owner_locked": False, "owner_source": "initial"}


def save(*, actor: str, ticket: str, document: str, ticket_revision: str,
         document_revision: str, expected_revision: int, resource_owner: str,
         eligible_owner):
    if not actor.startswith("user:") or not current_tenant_id_strict():
        raise PermissionError("A named workspace administrator is required.")
    if not connections.enabled():
        raise PermissionError("Enable Connections before selecting credentials.")
    # Credential selection and commit share the exact lock used by enrollment,
    # rotation and deletion. Changing a credential later is separately checked
    # by the workflow at every sensitive boundary.
    if not callable(eligible_owner):
        raise TypeError("Current workspace owner eligibility must be supplied.")
    with _workflow_lock(), connections._mutation_lock():
        previous = current()
        if (previous or {}).get("revision", 0) != expected_revision:
            raise RecordConflict("Vendor setup changed. Reload before saving.")
        ticket_record = connections.get_connection(ticket)
        if (not ticket_record or ticket_record.get("owner") != actor
                or ticket_record.get("connector") != "jira"
                or ticket_record.get("revision") != ticket_revision
                or not ticket_record.get("token")):
            raise PermissionError("Select your current Jira connection with credentials.")
        if document:
            document_record = connections.get_connection(document)
            if (not document_record or document_record.get("owner") != actor
                    or document_record.get("connector") != "gdrive"
                    or document_record.get("revision") != document_revision
                    or not document_record.get("token")
                    or document_record.get("base_url") != "https://www.googleapis.com"):
                raise PermissionError("Select your current Google Drive connection with credentials.")
        ownership = _owner_policy()
        if ownership["owner_locked"] and resource_owner != ownership["resource_owner"]:
            raise PermissionError("The existing vendor owner is fixed. This setup action cannot transfer ownership.")
        if not ownership["owner_locked"] and (not isinstance(resource_owner, str)
                or not resource_owner.startswith("user:") or eligible_owner(resource_owner) is not True):
            raise PermissionError("Choose a currently active named workspace member with permission to operate vendor reviews.")
        binding = asdict(VendorOnboardingSettings.from_config({"vendor_onboarding": {
            "enable": True, "resource_owner": resource_owner,
            "ticket_connection": ticket, "document_connection": document or "unconfigured-drive",
        }}))
        # Require the same pinned-origin contract as production adapters. This
        # does not probe the provider or assert live readiness.
        from .governed_operations import ServiceContext
        from .vendor_onboarding_adapters import resolve_connection
        ctx = ServiceContext(tenant=current_tenant_id_strict(), actor=actor,
            resource_owner=resource_owner, credential_authority=actor,
            credential_ref=ticket, document_credential_ref=binding["document_connection"], human=True)
        resolve_connection(ctx, refresh=False)
        if document:
            resolve_connection(ctx, document=True, refresh=False)
        if not ownership["owner_locked"] and eligible_owner(resource_owner) is not True:
            raise PermissionError("The selected member's workspace access changed. Reload and choose an eligible owner.")
        if previous:
            return STORE.update(RECORD_ID, lambda row: row.update(binding=binding),
                expected_revision=expected_revision, action="vendor_setup_changed", actor=actor)
        return STORE.create({"id": RECORD_ID, "binding": binding},
            action="vendor_setup_created", actor=actor, max_records=1)

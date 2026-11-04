"""Current account and reviewed source checks for native consent admission.

The ordinary form keeps private selections local to the authorized native API.
Its preference-store writer reservation remains held until job admission ends.
Existing non-form API callers retain their version-bound execution contract.
"""
from __future__ import annotations

import hmac
from contextlib import contextmanager

from fastapi import HTTPException

from .draft_api import context_for


def context(request):
    current = context_for(request)
    expected = request.headers.get("X-Lightwork-Profile-Context")
    if expected is not None and (len(expected) != 64 or not expected.isascii() or not hmac.compare_digest(expected, current)):
        raise HTTPException(409, "Your account or workspace changed. Reload this page before choosing people.",
            headers={"X-Lightwork-Profile-Context": current})
    return current


@contextmanager
def reviewed_sources(runtime, operation, items):
    from maverick.consent_preferences import ConsentPreferenceStore

    store, tenant = runtime.executor.preference_store, runtime.tenant_id
    if not isinstance(store, ConsentPreferenceStore):
        raise HTTPException(503, "This connection cannot verify a current consent review. No job was submitted.")
    with store._connect() as connection:
        connection.execute("BEGIN IMMEDIATE")  # Native SQLite/shared-Postgres store writer reservation.
        try:
            for item in items:
                profile = connection.execute("SELECT revision FROM consent_profiles WHERE tenant=? AND profile_id=?",
                    (tenant, item["profile_id"])).fetchone()
                if profile is None or (operation != "export_receipts" and profile["revision"] != item["expected_revision"]):
                    raise HTTPException(409, "A selected person's record changed. Review the selection again before submitting.")
                if operation == "edit_preferences":
                    policy = store._active_policy(connection, tenant, item["policy_id"], runtime.clock())
                    if policy is None or policy["version"] != item["policy_version"]:
                        raise HTTPException(409, "The selected policy is no longer current. Review the policy and choices again.")
                    allowed = store._policy_from_row(policy)["purposes"]
                    if any(choice["purpose_id"] not in allowed for choice in item["choices"]):
                        raise HTTPException(409, "A selected use of data is no longer in the current policy. Review again.")
                if operation in {"reactivate", "clear_expiration"}:
                    receipt = connection.execute("SELECT 1 FROM consent_receipts WHERE tenant=? AND profile_id=? AND receipt_id=?",
                        (tenant, item["profile_id"], item["receipt_id"])).fetchone()
                    if receipt is None:
                        raise HTTPException(409, "A selected choice is no longer available for this person. Choose it again before reviewing.")
            yield
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise

"""Token-scoped external response portal for AI vendor diligence.

Operators create an expiring invitation and receive its opaque token exactly
once. The stored invitation contains only a SHA-256 token digest. A vendor can
read the exact questionnaire and submit one complete, vendor-attested response;
the submission remains pending internal import and the resulting assessment
still requires the ordinary human review.

The caller selects a tenant before invoking this module. External HTTP routing
must derive that tenant from an explicit request header and restore the prior
tenant context after use.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import time
from collections.abc import Mapping
from typing import Any

from .file_lock import cross_process_lock
from .governed_records import GovernedRecordStore
from .paths import current_tenant_id_strict, data_dir
from .privacy_ops import RecordConflict

INVITATION_SCHEMA = "lightwork.ai-vendor-portal-invitation.v1"
SUBMISSION_SCHEMA = "lightwork.ai-vendor-portal-submission.v1"
PORTAL_NOTICE = (
    "Vendor-supplied answers are attestations pending independent customer "
    "review; they are not verified evidence, certification, or legal advice."
)

_INVITATIONS = GovernedRecordStore(
    "ai_vendor_portal_invitations",
    "AIVI",
    "ai_vendor_portal_invitation",
)
_SUBMISSIONS = GovernedRecordStore(
    "ai_vendor_portal_submissions",
    "AIVS",
    "ai_vendor_portal_submission",
)

_TOKEN_RE = re.compile(r"aivp1\.[A-Za-z0-9_-]{40,64}\Z")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}\Z")
_IDEMPOTENCY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}\Z")
_RESPONDENT_RE = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,127}\Z")
_HUMAN_RE = re.compile(r"user:[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,127}\Z")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ANSWERS = frozenset({"yes", "no", "na", "unknown"})
_STORE_METADATA = frozenset({"revision", "created_at", "updated_at", "_audit_pending"})
_MAX_INVITATIONS = 5_000
_MAX_SUBMISSIONS = 5_000
_MAX_LIST = 500
_MIN_EXPIRY_SECONDS = 60 * 60
_MAX_EXPIRY_SECONDS = 90 * 24 * 60 * 60

_INVITATION_FIELDS = frozenset(
    {
        "id",
        "schema",
        "tenant_sha256",
        "vendor",
        "questionnaire_digest",
        "token_sha256",
        "status",
        "expires_at",
        "created_by",
        "submission_binding",
        "revocation",
        "state_sha256",
    }
)
_SUBMISSION_FIELDS = frozenset(
    {
        "id",
        "schema",
        "tenant_sha256",
        "invitation_id",
        "vendor",
        "questionnaire_digest",
        "answers",
        "respondent_ref",
        "attested",
        "idempotency_sha256",
        "request_sha256",
        "response_sha256",
        "submitted_at",
        "status",
        "imported_assessment",
        "state_sha256",
    }
)


class AIVendorPortalError(RuntimeError):
    """Base error for the vendor-facing response portal."""


class AIVendorPortalConfigError(AIVendorPortalError):
    """The explicitly opt-in portal is unavailable."""


class AIVendorPortalAuthError(AIVendorPortalError):
    """An opaque invitation token is invalid, expired, revoked, or consumed."""


class AIVendorPortalStateError(AIVendorPortalError):
    """Persisted portal state is malformed or ambiguous."""


class AIVendorPortalConflict(AIVendorPortalError):
    """An invitation or idempotency identity was reused differently."""


def enabled() -> bool:
    """Return true only when vendor risk and its external portal are enabled."""

    try:
        from .config import config_source_errors, load_config

        if config_source_errors():
            return False
        config = load_config()
    except Exception:
        return False
    if not isinstance(config, Mapping):
        return False
    section = config.get("ai_vendor_risk")
    return (
        isinstance(section, Mapping)
        and section.get("enable") is True
        and section.get("portal_enable") is True
    )


def require_enabled() -> None:
    if not enabled():
        raise AIVendorPortalConfigError(
            "AI vendor portal is disabled; set [ai_vendor_risk] "
            "enable = true and portal_enable = true"
        )


def _tenant() -> str:
    tenant = current_tenant_id_strict()
    if not tenant:
        raise AIVendorPortalStateError(
            "AI vendor portal requires an explicit tenant authority"
        )
    return tenant


def _tenant_sha256() -> str:
    return hashlib.sha256(_tenant().encode("utf-8")).hexdigest()


def _canonical(value: object) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("vendor portal data must be finite JSON") from exc
    if len(encoded) > 256 * 1024:
        raise ValueError("vendor portal data exceeds its bound")
    return encoded


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _safe_text(
    value: object,
    label: str,
    limit: int,
    *,
    required: bool = True,
) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    text = value.strip()
    if required and not text:
        raise ValueError(f"{label} is required")
    if len(text) > limit or _CONTROL_RE.search(text):
        raise ValueError(f"{label} is invalid")
    try:
        from .safety.secret_detector import scan

        if scan(text):
            raise ValueError(f"{label} contains secret material")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("secret detection is unavailable") from exc
    return text


def _human(value: object) -> str:
    principal = _safe_text(value, "actor", 133)
    if not _HUMAN_RE.fullmatch(principal):
        raise ValueError("actor must be an authenticated user principal")
    return principal


def _digest(value: object, label: str) -> str:
    text = str(value or "").strip().lower().removeprefix("sha256:")
    if not _DIGEST_RE.fullmatch(text):
        raise ValueError(f"{label} must be a SHA-256 digest")
    return text


def _revision(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("expected_revision must be a positive integer")
    return value


def _record_body(
    record: Mapping[str, Any],
    fields: frozenset[str],
    label: str,
) -> dict[str, Any]:
    keys = set(record) - _STORE_METADATA
    if keys != fields:
        raise AIVendorPortalStateError(f"persisted {label} shape is invalid")
    return {key: record[key] for key in fields}


def _invitation_state(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: row.get(key)
        for key in _INVITATION_FIELDS
        if key != "state_sha256"
    }


def _submission_state(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: row.get(key)
        for key in _SUBMISSION_FIELDS
        if key != "state_sha256"
    }


def _validated_invitation(record: Mapping[str, Any]) -> dict[str, Any]:
    row = _record_body(record, _INVITATION_FIELDS, "invitation")
    try:
        if row["schema"] != INVITATION_SCHEMA:
            raise ValueError
        if row["tenant_sha256"] != _tenant_sha256():
            raise ValueError
        if not str(row["id"]).startswith("AIVI-"):
            raise ValueError
        row["vendor"] = _safe_text(row["vendor"], "vendor", 300)
        row["questionnaire_digest"] = _digest(
            row["questionnaire_digest"], "questionnaire_digest"
        )
        row["token_sha256"] = _digest(row["token_sha256"], "token_sha256")
        if row["status"] not in {"active", "consumed", "revoked"}:
            raise ValueError
        if (
            isinstance(row["expires_at"], bool)
            or not isinstance(row["expires_at"], (int, float))
            or not math.isfinite(float(row["expires_at"]))
            or float(row["expires_at"]) <= 0
        ):
            raise ValueError
        row["created_by"] = _human(row["created_by"])
        binding = row["submission_binding"]
        if row["status"] == "consumed":
            if (
                not isinstance(binding, Mapping)
                or set(binding)
                != {
                    "submission_id",
                    "idempotency_sha256",
                    "request_sha256",
                    "consumed_at",
                }
                or not str(binding["submission_id"]).startswith("AIVS-")
                or not _DIGEST_RE.fullmatch(str(binding["idempotency_sha256"]))
                or not _DIGEST_RE.fullmatch(str(binding["request_sha256"]))
                or not isinstance(binding["consumed_at"], (int, float))
                or isinstance(binding["consumed_at"], bool)
            ):
                raise ValueError
            row["submission_binding"] = dict(binding)
        elif binding is not None:
            raise ValueError
        revocation = row["revocation"]
        if row["status"] == "revoked":
            if (
                not isinstance(revocation, Mapping)
                or set(revocation) != {"reason", "revoked_by", "revoked_at"}
            ):
                raise ValueError
            row["revocation"] = {
                "reason": _safe_text(revocation["reason"], "revocation reason", 500),
                "revoked_by": _human(revocation["revoked_by"]),
                "revoked_at": float(revocation["revoked_at"]),
            }
        elif revocation is not None:
            raise ValueError
        if row["state_sha256"] != _sha256(_invitation_state(row)):
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise AIVendorPortalStateError(
            "persisted vendor portal invitation is invalid"
        ) from exc
    return {**row, **{key: record[key] for key in _STORE_METADATA if key in record}}


def _question_ids() -> tuple[str, ...]:
    from .ai_vendor_risk import AI_VENDOR_QUESTIONS

    return tuple(question.id for question in AI_VENDOR_QUESTIONS)


def _answers(value: object) -> dict[str, dict[str, str]]:
    if not isinstance(value, Mapping) or set(value) != set(_question_ids()):
        raise ValueError("answers must contain every current questionnaire item")
    out: dict[str, dict[str, str]] = {}
    for question_id in _question_ids():
        raw = value[question_id]
        if isinstance(raw, str):
            answer, note = raw, ""
        elif isinstance(raw, Mapping) and set(raw).issubset({"answer", "note"}):
            answer, note = raw.get("answer"), raw.get("note") or ""
        else:
            raise ValueError(f"answer {question_id!r} is invalid")
        choice = str(answer or "").strip().lower()
        if choice not in _ANSWERS:
            raise ValueError(f"answer {question_id!r} is invalid")
        out[question_id] = {
            "answer": choice,
            "note": _safe_text(
                note,
                f"answer {question_id} note",
                1000,
                required=False,
            ),
        }
    return out


def _validated_submission(record: Mapping[str, Any]) -> dict[str, Any]:
    row = _record_body(record, _SUBMISSION_FIELDS, "submission")
    try:
        if row["schema"] != SUBMISSION_SCHEMA:
            raise ValueError
        if row["tenant_sha256"] != _tenant_sha256():
            raise ValueError
        if not str(row["id"]).startswith("AIVS-"):
            raise ValueError
        if not str(row["invitation_id"]).startswith("AIVI-"):
            raise ValueError
        row["vendor"] = _safe_text(row["vendor"], "vendor", 300)
        row["questionnaire_digest"] = _digest(
            row["questionnaire_digest"], "questionnaire_digest"
        )
        row["answers"] = _answers(row["answers"])
        respondent = str(row["respondent_ref"] or "").strip().lower()
        if not _RESPONDENT_RE.fullmatch(respondent):
            raise ValueError
        row["respondent_ref"] = respondent
        if row["attested"] is not True:
            raise ValueError
        for label in ("idempotency_sha256", "request_sha256", "response_sha256"):
            row[label] = _digest(row[label], label)
        if (
            isinstance(row["submitted_at"], bool)
            or not isinstance(row["submitted_at"], (int, float))
            or not math.isfinite(float(row["submitted_at"]))
            or float(row["submitted_at"]) <= 0
        ):
            raise ValueError
        if row["status"] not in {"pending_import", "imported"}:
            raise ValueError
        imported = row["imported_assessment"]
        if row["status"] == "imported":
            if (
                not isinstance(imported, Mapping)
                or set(imported)
                != {
                    "assessment_id",
                    "assessment_revision",
                    "assessment_sha256",
                    "imported_by",
                    "imported_at",
                }
                or not str(imported["assessment_id"]).startswith("AIV-")
                or not isinstance(imported["assessment_revision"], int)
                or isinstance(imported["assessment_revision"], bool)
                or imported["assessment_revision"] < 1
                or not _DIGEST_RE.fullmatch(str(imported["assessment_sha256"]))
            ):
                raise ValueError
            row["imported_assessment"] = {
                **dict(imported),
                "imported_by": _human(imported["imported_by"]),
                "imported_at": float(imported["imported_at"]),
            }
        elif imported is not None:
            raise ValueError
        expected_response = _sha256(
            {
                "schema": SUBMISSION_SCHEMA,
                "tenant_sha256": row["tenant_sha256"],
                "invitation_id": row["invitation_id"],
                "vendor": row["vendor"],
                "questionnaire_digest": row["questionnaire_digest"],
                "answers": row["answers"],
                "respondent_ref": row["respondent_ref"],
                "attested": True,
            }
        )
        if row["response_sha256"] != expected_response:
            raise ValueError
        if row["state_sha256"] != _sha256(_submission_state(row)):
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise AIVendorPortalStateError(
            "persisted vendor portal submission is invalid"
        ) from exc
    return {**row, **{key: record[key] for key in _STORE_METADATA if key in record}}


def _public_invitation(row: Mapping[str, Any], *, now: float | None = None) -> dict[str, Any]:
    current = time.time() if now is None else float(now)
    effective_status = (
        "expired"
        if row["status"] == "active" and current > float(row["expires_at"])
        else row["status"]
    )
    binding = row.get("submission_binding")
    return {
        "invitation_id": row["id"],
        "vendor": row["vendor"],
        "questionnaire_digest": row["questionnaire_digest"],
        "status": effective_status,
        "expires_at": row["expires_at"],
        "created_by": row["created_by"],
        "submission_id": (
            binding.get("submission_id") if isinstance(binding, Mapping) else None
        ),
        "revocation": row["revocation"],
        "revision": row.get("revision"),
        "notice": PORTAL_NOTICE,
    }


def _public_submission(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "submission_id": row["id"],
        "invitation_id": row["invitation_id"],
        "vendor": row["vendor"],
        "questionnaire_digest": row["questionnaire_digest"],
        "answers": row["answers"],
        "respondent_ref": row["respondent_ref"],
        "attested": True,
        "response_sha256": row["response_sha256"],
        "submitted_at": row["submitted_at"],
        "status": row["status"],
        "imported_assessment": row["imported_assessment"],
        "revision": row.get("revision"),
        "notice": PORTAL_NOTICE,
    }


def _bounded_invitations() -> list[dict[str, Any]]:
    rows = _INVITATIONS.list(limit=_MAX_INVITATIONS + 1)
    if len(rows) > _MAX_INVITATIONS:
        raise AIVendorPortalStateError("vendor portal invitation bound exceeded")
    return [_validated_invitation(row) for row in rows]


def _bounded_submissions() -> list[dict[str, Any]]:
    rows = _SUBMISSIONS.list(limit=_MAX_SUBMISSIONS + 1)
    if len(rows) > _MAX_SUBMISSIONS:
        raise AIVendorPortalStateError("vendor portal submission bound exceeded")
    return [_validated_submission(row) for row in rows]


def _transaction_target():
    return data_dir("ai_vendor_portal", ".transaction")


def create_invitation(
    *,
    vendor: str,
    actor: str,
    expires_in_seconds: int = 14 * 24 * 60 * 60,
) -> dict[str, Any]:
    """Create an invitation and disclose its random token exactly once."""

    require_enabled()
    tenant_sha = _tenant_sha256()
    name = _safe_text(vendor, "vendor", 300)
    principal = _human(actor)
    if (
        isinstance(expires_in_seconds, bool)
        or not isinstance(expires_in_seconds, int)
        or not _MIN_EXPIRY_SECONDS
        <= expires_in_seconds
        <= _MAX_EXPIRY_SECONDS
    ):
        raise ValueError(
            "expires_in_seconds must be between one hour and 90 days"
        )
    from . import ai_vendor_risk

    questionnaire = ai_vendor_risk.questionnaire()
    token = "aivp1." + secrets.token_urlsafe(32)
    token_sha = hashlib.sha256(token.encode("utf-8")).hexdigest()
    now = _INVITATIONS.authoritative_time()
    record: dict[str, Any] = {
        "id": _INVITATIONS.new_id(),
        "schema": INVITATION_SCHEMA,
        "tenant_sha256": tenant_sha,
        "vendor": name,
        "questionnaire_digest": questionnaire["template_digest"],
        "token_sha256": token_sha,
        "status": "active",
        "expires_at": now + expires_in_seconds,
        "created_by": principal,
        "submission_binding": None,
        "revocation": None,
    }
    record["state_sha256"] = _sha256(_invitation_state(record))
    saved = _INVITATIONS.create(
        record,
        action="create_ai_vendor_portal_invitation",
        actor=principal,
        max_records=_MAX_INVITATIONS,
    )
    return {
        "invitation": _public_invitation(_validated_invitation(saved), now=now),
        "token": token,
    }


def get_invitation(invitation_id: str) -> dict[str, Any] | None:
    require_enabled()
    _tenant()
    row = _INVITATIONS.get(_safe_text(invitation_id, "invitation_id", 64))
    if row is None:
        return None
    return _public_invitation(_validated_invitation(row))


def list_invitations(*, limit: int = 100) -> list[dict[str, Any]]:
    require_enabled()
    _tenant()
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST:
        raise ValueError(f"limit must be between 1 and {_MAX_LIST}")
    rows = sorted(
        _bounded_invitations(),
        key=lambda item: (float(item.get("created_at") or 0), item["id"]),
        reverse=True,
    )
    return [_public_invitation(row) for row in rows[:limit]]


def revoke_invitation(
    invitation_id: str,
    *,
    reason: str,
    actor: str,
    expected_revision: int,
) -> dict[str, Any]:
    require_enabled()
    identifier = _safe_text(invitation_id, "invitation_id", 64)
    why = _safe_text(reason, "reason", 500)
    principal = _human(actor)
    expected = _revision(expected_revision)
    now = _INVITATIONS.authoritative_time()

    def mutate(row: dict[str, Any]) -> None:
        current = _validated_invitation(row)
        if current["status"] != "active":
            raise AIVendorPortalConflict("only an active invitation can be revoked")
        row["status"] = "revoked"
        row["revocation"] = {
            "reason": why,
            "revoked_by": principal,
            "revoked_at": now,
        }
        row["state_sha256"] = _sha256(_invitation_state(row))

    saved = _INVITATIONS.update(
        identifier,
        mutate,
        expected_revision=expected,
        action="revoke_ai_vendor_portal_invitation",
        actor=principal,
    )
    if saved is None:
        raise AIVendorPortalStateError("vendor portal invitation does not exist")
    return _public_invitation(_validated_invitation(saved), now=now)


def _invitation_for_token(token: str, *, now: float) -> dict[str, Any]:
    if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
        raise AIVendorPortalAuthError("invalid invitation")
    token_sha = hashlib.sha256(token.encode("utf-8")).hexdigest()
    matches = [
        row
        for row in _bounded_invitations()
        if hmac.compare_digest(row["token_sha256"], token_sha)
    ]
    if len(matches) != 1:
        raise AIVendorPortalAuthError("invalid invitation")
    invitation = matches[0]
    if invitation["status"] == "revoked" or now > float(invitation["expires_at"]):
        raise AIVendorPortalAuthError("invalid invitation")
    return invitation


def questionnaire_for_token(token: str) -> dict[str, Any]:
    """Return the exact questionnaire for one active or consumed invitation."""

    require_enabled()
    _tenant()
    now = _INVITATIONS.authoritative_time()
    invitation = _invitation_for_token(token, now=now)
    from . import ai_vendor_risk

    questionnaire = ai_vendor_risk.questionnaire()
    if questionnaire["template_digest"] != invitation["questionnaire_digest"]:
        raise AIVendorPortalConflict(
            "questionnaire changed; issue a new vendor invitation"
        )
    return {
        "invitation_id": invitation["id"],
        "vendor": invitation["vendor"],
        "expires_at": invitation["expires_at"],
        "submission_status": invitation["status"],
        "questionnaire": questionnaire,
        "notice": PORTAL_NOTICE,
    }


def _create_or_recover_submission(record: dict[str, Any]) -> dict[str, Any]:
    try:
        saved = _SUBMISSIONS.create(
            record,
            action="submit_ai_vendor_portal_response",
            actor=f"vendor:{record['invitation_id']}",
            max_records=_MAX_SUBMISSIONS,
        )
    except RecordConflict as exc:
        existing = _SUBMISSIONS.get(record["id"])
        if existing is None:
            raise
        saved = existing
        current = _validated_submission(saved)
        # Mutable import state and the first authoritative submission timestamp
        # may legitimately differ on an exact retry.  The request digest binds
        # every vendor-controlled field plus the idempotency key.
        if current["request_sha256"] != record["request_sha256"]:
            raise AIVendorPortalConflict(
                "vendor submission identity was reused differently"
            ) from exc
    return _validated_submission(saved)


def submit_response(
    token: str,
    *,
    answers: Mapping[str, object],
    respondent_ref: str,
    attested: bool,
    idempotency_key: str,
) -> dict[str, Any]:
    """Consume one invitation and idempotently retain its complete response."""

    require_enabled()
    tenant_sha = _tenant_sha256()
    normalized_answers = _answers(answers)
    respondent = str(respondent_ref or "").strip().lower()
    if not _RESPONDENT_RE.fullmatch(respondent):
        raise ValueError("respondent_ref must be a pseudonymous taxonomy code")
    if attested is not True:
        raise ValueError("the vendor must explicitly attest the submitted answers")
    key = str(idempotency_key or "").strip()
    if not _IDEMPOTENCY_RE.fullmatch(key):
        raise ValueError("idempotency_key is invalid")
    idempotency_sha = hashlib.sha256(key.encode("utf-8")).hexdigest()
    now = _INVITATIONS.authoritative_time()

    with cross_process_lock(_transaction_target(), strict=True):
        invitation = _invitation_for_token(token, now=now)
        response_payload = {
            "schema": SUBMISSION_SCHEMA,
            "tenant_sha256": tenant_sha,
            "invitation_id": invitation["id"],
            "vendor": invitation["vendor"],
            "questionnaire_digest": invitation["questionnaire_digest"],
            "answers": normalized_answers,
            "respondent_ref": respondent,
            "attested": True,
        }
        response_sha = _sha256(response_payload)
        request_sha = _sha256(
            {
                "response_sha256": response_sha,
                "idempotency_sha256": idempotency_sha,
            }
        )
        submission_id = "AIVS-" + _sha256(
            {
                "invitation_id": invitation["id"],
                "idempotency_sha256": idempotency_sha,
            }
        )[:32]
        record: dict[str, Any] = {
            "id": submission_id,
            **response_payload,
            "idempotency_sha256": idempotency_sha,
            "request_sha256": request_sha,
            "response_sha256": response_sha,
            "submitted_at": now,
            "status": "pending_import",
            "imported_assessment": None,
        }
        record["state_sha256"] = _sha256(_submission_state(record))
        binding = invitation["submission_binding"]
        if invitation["status"] == "consumed":
            if (
                binding["idempotency_sha256"] != idempotency_sha
                or binding["request_sha256"] != request_sha
                or binding["submission_id"] != submission_id
            ):
                raise AIVendorPortalConflict(
                    "invitation was already consumed by a different response"
                )
            submission = _create_or_recover_submission(record)
            return _public_submission(submission)

        expected = _revision(invitation["revision"])

        def consume(row: dict[str, Any]) -> None:
            current = _validated_invitation(row)
            if current["status"] != "active":
                raise AIVendorPortalConflict("invitation is no longer active")
            if now > float(current["expires_at"]):
                raise AIVendorPortalAuthError("invalid invitation")
            row["status"] = "consumed"
            row["submission_binding"] = {
                "submission_id": submission_id,
                "idempotency_sha256": idempotency_sha,
                "request_sha256": request_sha,
                "consumed_at": now,
            }
            row["state_sha256"] = _sha256(_invitation_state(row))

        saved_invitation = _INVITATIONS.update(
            invitation["id"],
            consume,
            expected_revision=expected,
            action="consume_ai_vendor_portal_invitation",
            actor=f"vendor:{invitation['id']}",
        )
        if saved_invitation is None:
            raise AIVendorPortalStateError("vendor portal invitation disappeared")
        _validated_invitation(saved_invitation)
        submission = _create_or_recover_submission(record)
        return _public_submission(submission)


def get_submission(submission_id: str) -> dict[str, Any] | None:
    require_enabled()
    _tenant()
    row = _SUBMISSIONS.get(_safe_text(submission_id, "submission_id", 64))
    return None if row is None else _public_submission(_validated_submission(row))


def list_submissions(*, limit: int = 100) -> list[dict[str, Any]]:
    require_enabled()
    _tenant()
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_LIST:
        raise ValueError(f"limit must be between 1 and {_MAX_LIST}")
    rows = sorted(
        _bounded_submissions(),
        key=lambda item: (float(item["submitted_at"]), item["id"]),
        reverse=True,
    )
    return [_public_submission(row) for row in rows[:limit]]


def import_submission(
    submission_id: str,
    *,
    actor: str,
    expected_revision: int,
) -> dict[str, Any]:
    """Idempotently import a vendor attestation as a pending human review."""

    require_enabled()
    identifier = _safe_text(submission_id, "submission_id", 64)
    principal = _human(actor)
    expected = _revision(expected_revision)
    with cross_process_lock(_transaction_target(), strict=True):
        raw = _SUBMISSIONS.get(identifier)
        if raw is None:
            raise AIVendorPortalStateError("vendor portal submission does not exist")
        submission = _validated_submission(raw)
        if submission["status"] == "imported":
            from . import ai_vendor_risk

            binding = submission["imported_assessment"]
            assessment = ai_vendor_risk.get_vendor_assessment(
                binding["assessment_id"]
            )
            if (
                assessment is None
                or assessment.get("revision") != binding["assessment_revision"]
                or assessment.get("assessment_sha256")
                != binding["assessment_sha256"]
            ):
                raise AIVendorPortalStateError(
                    "imported vendor assessment binding no longer verifies"
                )
            return {
                "submission": _public_submission(submission),
                "assessment": assessment,
                "idempotent_replay": True,
            }
        if submission["revision"] != expected:
            raise AIVendorPortalConflict("submission revision changed")
        from . import ai_vendor_risk

        assessment = ai_vendor_risk.find_vendor_assessment_by_attestation(
            submission["response_sha256"]
        )
        if assessment is None:
            assessment = ai_vendor_risk.draft_vendor_assessment(
                submission["vendor"],
                attested_answers=submission["answers"],
                attestation_sha256=submission["response_sha256"],
                actor=principal,
                use_prior=False,
            )
        now = _SUBMISSIONS.authoritative_time()

        def mark_imported(row: dict[str, Any]) -> None:
            current = _validated_submission(row)
            if current["status"] == "imported":
                return
            if current["response_sha256"] != submission["response_sha256"]:
                raise AIVendorPortalConflict("submission changed during import")
            row["status"] = "imported"
            row["imported_assessment"] = {
                "assessment_id": assessment["id"],
                "assessment_revision": assessment["revision"],
                "assessment_sha256": assessment["assessment_sha256"],
                "imported_by": principal,
                "imported_at": now,
            }
            row["state_sha256"] = _sha256(_submission_state(row))

        saved = _SUBMISSIONS.update(
            identifier,
            mark_imported,
            expected_revision=expected,
            action="import_ai_vendor_portal_submission",
            actor=principal,
        )
        if saved is None:
            raise AIVendorPortalStateError("vendor portal submission disappeared")
        current = _validated_submission(saved)
        return {
            "submission": _public_submission(current),
            "assessment": assessment,
            "idempotent_replay": False,
        }


__all__ = [
    "AIVendorPortalAuthError",
    "AIVendorPortalConfigError",
    "AIVendorPortalConflict",
    "AIVendorPortalError",
    "AIVendorPortalStateError",
    "INVITATION_SCHEMA",
    "PORTAL_NOTICE",
    "SUBMISSION_SCHEMA",
    "create_invitation",
    "enabled",
    "get_invitation",
    "get_submission",
    "import_submission",
    "list_invitations",
    "list_submissions",
    "questionnaire_for_token",
    "require_enabled",
    "revoke_invitation",
    "submit_response",
]

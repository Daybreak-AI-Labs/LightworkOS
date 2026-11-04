"""Controller-owned test-evidence contract for governed code evaluation.

Candidate stdout, JUnit files, and pytest plugins loaded in the candidate
process are all candidate-controlled.  They are useful diagnostics, but none
of them can authorize a DGM score.  This module defines the narrow protocol an
external evaluator broker must implement to return test counts over a channel
outside the candidate's authority.

The protocol deliberately does not provide a bundled adapter that parses
stdout or files.  A conforming backend must implement
``exec_authenticated_tests(request, timeout=None)`` and authenticate its own
runner event before returning :class:`AuthenticatedTestEvidence`.  Each
request carries a fresh controller nonce and binds the exact command, immutable
evaluation-subject digest, and sandbox/arm execution-context digest. The
controller accepts only exact evidence from the backend's pinned authority.
This prevents replay, wrong-worktree relabeling, and cross-arm substitution. It
does not make a dishonest backend trustworthy: operators must configure a
reviewed sandbox SDK backend backed by an external runner/sidecar trust
boundary.
"""
from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import secrets
import string
from dataclasses import dataclass

from .constant_time import text_equals

TEST_EVIDENCE_PROTOCOL = "maverick.test-evidence.v1"
_MAX_AUTHORITY_CHARS = 256
_MAX_COMMAND_CHARS = 1_000_000


@dataclass(frozen=True)
class AuthenticatedTestCounts:
    """Terminal outcomes authenticated by the evaluator controller.

    Skips and errors remain in the denominator so a candidate cannot improve
    its score by suppressing or de-collecting challenge cases.
    """

    passed: int
    failed: int
    skipped: int = 0
    errors: int = 0
    terminal: bool = True


def _valid_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(char in string.hexdigits[:16] for char in value)
    )


def _request_digest(
    *,
    request_id: str,
    command: str,
    subject_sha256: str,
    execution_context_sha256: str,
) -> str:
    payload = json.dumps(
        {
            "command": command,
            "execution_context_sha256": execution_context_sha256,
            "protocol": TEST_EVIDENCE_PROTOCOL,
            "request_id": request_id,
            "subject_sha256": subject_sha256,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class AuthenticatedTestRequest:
    """One fresh command/subject/context request from the trusted controller."""

    protocol: str
    request_id: str
    command: str
    subject_sha256: str
    execution_context_sha256: str
    request_sha256: str

    @classmethod
    def issue(
        cls,
        command: str,
        *,
        subject_sha256: str,
        execution_context_sha256: str,
    ) -> AuthenticatedTestRequest:
        if type(command) is not str or not command or len(command) > _MAX_COMMAND_CHARS:
            raise ValueError("authenticated test command is empty or too large")
        if not _valid_sha256(subject_sha256):
            raise ValueError("authenticated test subject digest is invalid")
        if not _valid_sha256(execution_context_sha256):
            raise ValueError("authenticated test execution-context digest is invalid")
        request_id = secrets.token_hex(32)
        return cls(
            protocol=TEST_EVIDENCE_PROTOCOL,
            request_id=request_id,
            command=command,
            subject_sha256=subject_sha256,
            execution_context_sha256=execution_context_sha256,
            request_sha256=_request_digest(
                request_id=request_id,
                command=command,
                subject_sha256=subject_sha256,
                execution_context_sha256=execution_context_sha256,
            ),
        )


@dataclass(frozen=True)
class AuthenticatedTestEvidence:
    """Evidence returned only after backend-side runner authentication.

    ``authority`` is a stable, non-secret issuer/key identity.  The sandbox
    backend must verify the sidecar signature, mTLS peer, TEE attestation, or
    equivalent controller-owned channel before constructing this object.
    Lightwork then binds it to the exact one-shot request and configured
    authority.
    """

    protocol: str
    request_id: str
    request_sha256: str
    subject_sha256: str
    execution_context_sha256: str
    authority: str
    counts: AuthenticatedTestCounts

    @classmethod
    def for_request(
        cls,
        request: AuthenticatedTestRequest,
        *,
        authority: str,
        counts: AuthenticatedTestCounts,
    ) -> AuthenticatedTestEvidence:
        return cls(
            protocol=request.protocol,
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            subject_sha256=request.subject_sha256,
            execution_context_sha256=request.execution_context_sha256,
            authority=authority,
            counts=counts,
        )


@dataclass(frozen=True)
class EvidenceBackendReadiness:
    """Static readiness result for one configured sandbox backend."""

    ready: bool
    issues: tuple[str, ...] = ()

    @property
    def message(self) -> str:
        if self.ready:
            return (
                f"authenticated evaluator evidence ready "
                f"({TEST_EVIDENCE_PROTOCOL})"
            )
        detail = "; ".join(self.issues) or "unknown evidence-contract failure"
        return (
            f"authenticated evaluator evidence is not ready: {detail}. "
            "Configure a reviewed sandbox SDK backend implementing "
            "exec_authenticated_tests(request, timeout=None) with a controller-"
            "owned runner/sidecar. Candidate stdout, JUnit/workspace files, and "
            "same-process pytest plugins are not authenticated evidence."
        )


def _valid_authority(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and len(value) <= _MAX_AUTHORITY_CHARS
        and value == value.strip()
        and not any(ord(char) < 32 or ord(char) == 127 for char in value)
    )


def _method_contract_issue(method) -> str | None:
    try:
        signature = inspect.signature(method)
    except (TypeError, ValueError):
        return "exec_authenticated_tests signature is not introspectable"
    parameters = list(signature.parameters.values())
    names = [parameter.name for parameter in parameters]
    accepts_request = any(
        parameter.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
        for parameter in parameters
    ) or any(
        parameter.kind is inspect.Parameter.VAR_POSITIONAL
        for parameter in parameters
    )
    accepts_timeout = "timeout" in names or any(
        parameter.kind is inspect.Parameter.VAR_KEYWORD
        for parameter in parameters
    )
    if not accepts_request:
        return "exec_authenticated_tests takes no request argument"
    if not accepts_timeout:
        return "exec_authenticated_tests must accept timeout=None"
    return None


def _safe_backend_attr(backend: object, name: str) -> tuple[object, bool]:
    try:
        return getattr(backend, name), True
    except AttributeError:
        return None, True
    except Exception:
        return None, False


def evidence_backend_readiness(backend: object) -> EvidenceBackendReadiness:
    """Validate the static controller-evidence capability of ``backend``.

    This intentionally requires more than ``authenticated_test_results =
    True``.  The old boolean-only marker allowed a backend to route ordinary
    candidate-controlled output through the trusted score path without
    exposing an independently authenticated execution boundary.
    """

    issues: list[str] = []
    authenticated, readable = _safe_backend_attr(
        backend, "authenticated_test_results",
    )
    if not readable:
        issues.append("authenticated_test_results could not be read")
    elif authenticated is not True:
        issues.append("authenticated_test_results is not exactly true")
    protocol, readable = _safe_backend_attr(backend, "test_evidence_protocol")
    if not readable:
        issues.append("test_evidence_protocol could not be read")
    elif protocol != TEST_EVIDENCE_PROTOCOL:
        issues.append(f"test_evidence_protocol must be {TEST_EVIDENCE_PROTOCOL!r}")
    authority, readable = _safe_backend_attr(backend, "test_evidence_authority")
    if not readable:
        issues.append("test_evidence_authority could not be read")
    elif not _valid_authority(authority):
        issues.append("test_evidence_authority is missing or invalid")
    method, readable = _safe_backend_attr(backend, "exec_authenticated_tests")
    if not readable:
        issues.append("exec_authenticated_tests could not be read")
    elif not callable(method):
        issues.append("exec_authenticated_tests(request, timeout=None) is missing")
    else:
        method_issue = _method_contract_issue(method)
        if method_issue:
            issues.append(method_issue)
    return EvidenceBackendReadiness(not issues, tuple(issues))


def validate_test_evidence(
    backend: object,
    request: AuthenticatedTestRequest,
    evidence: object,
) -> AuthenticatedTestCounts | None:
    """Return authenticated counts only for an exact one-shot request binding."""

    if not evidence_backend_readiness(backend).ready:
        return None
    if type(request) is not AuthenticatedTestRequest:
        return None
    if (
        request.protocol != TEST_EVIDENCE_PROTOCOL
        or type(request.request_id) is not str
        or len(request.request_id) != 64
        or any(char not in string.hexdigits[:16] for char in request.request_id)
        or type(request.command) is not str
        or not request.command
        or len(request.command) > _MAX_COMMAND_CHARS
        or not _valid_sha256(request.subject_sha256)
        or not _valid_sha256(request.execution_context_sha256)
        or not _valid_sha256(request.request_sha256)
    ):
        return None
    expected_digest = _request_digest(
        request_id=request.request_id,
        command=request.command,
        subject_sha256=request.subject_sha256,
        execution_context_sha256=request.execution_context_sha256,
    )
    if not hmac.compare_digest(request.request_sha256, expected_digest):
        return None
    if type(evidence) is not AuthenticatedTestEvidence:
        return None
    authority = getattr(backend, "test_evidence_authority", None)
    bindings = (
        (evidence.protocol, request.protocol),
        (evidence.request_id, request.request_id),
        (evidence.request_sha256, request.request_sha256),
        (evidence.subject_sha256, request.subject_sha256),
        (
            evidence.execution_context_sha256,
            request.execution_context_sha256,
        ),
        (evidence.authority, authority),
    )
    if any(
        type(observed) is not str
        or type(expected) is not str
        or not text_equals(observed, expected)
        for observed, expected in bindings
    ):
        return None
    counts = evidence.counts
    if type(counts) is not AuthenticatedTestCounts or counts.terminal is not True:
        return None
    outcomes = (counts.passed, counts.failed, counts.skipped, counts.errors)
    if any(type(value) is not int or value < 0 for value in outcomes):
        return None
    total = sum(outcomes)
    if total <= 0 or total > 1_000_000:
        return None
    return counts


__all__ = [
    "TEST_EVIDENCE_PROTOCOL",
    "AuthenticatedTestCounts",
    "AuthenticatedTestRequest",
    "AuthenticatedTestEvidence",
    "EvidenceBackendReadiness",
    "evidence_backend_readiness",
    "validate_test_evidence",
]

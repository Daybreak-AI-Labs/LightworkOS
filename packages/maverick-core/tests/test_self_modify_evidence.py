"""Controller-owned DGM test-evidence protocol security properties."""
from __future__ import annotations

from dataclasses import replace

from maverick import self_modify_evidence as evidence
from maverick.sandbox.local import LocalBackend

SUBJECT = "1" * 64
EXECUTION_CONTEXT = "2" * 64


def _request(command: str = "python -m pytest -- case"):
    return evidence.AuthenticatedTestRequest.issue(
        command,
        subject_sha256=SUBJECT,
        execution_context_sha256=EXECUTION_CONTEXT,
    )


class _Backend:
    authenticated_test_results = True
    test_evidence_protocol = evidence.TEST_EVIDENCE_PROTOCOL
    test_evidence_authority = "spiffe://lightwork/evaluator/key-1"

    def exec_authenticated_tests(self, request, timeout=None):
        return evidence.AuthenticatedTestEvidence.for_request(
            request,
            authority=self.test_evidence_authority,
            counts=evidence.AuthenticatedTestCounts(3, 1, skipped=1),
        )


def test_complete_external_evidence_contract_is_ready():
    readiness = evidence.evidence_backend_readiness(_Backend())
    assert readiness.ready is True
    assert evidence.TEST_EVIDENCE_PROTOCOL in readiness.message


def test_bundled_local_backend_is_explicitly_not_evidence_ready(tmp_path):
    readiness = evidence.evidence_backend_readiness(LocalBackend(tmp_path))
    assert readiness.ready is False
    assert "exec_authenticated_tests" in readiness.message
    assert "JUnit/workspace files" in readiness.message


def test_exact_nonce_command_and_authority_binding_is_accepted():
    backend = _Backend()
    request = _request()
    result = backend.exec_authenticated_tests(request)
    counts = evidence.validate_test_evidence(backend, request, result)
    assert counts == evidence.AuthenticatedTestCounts(3, 1, skipped=1)


def test_replayed_evidence_for_another_nonce_is_rejected():
    backend = _Backend()
    first = _request()
    second = _request()
    replay = backend.exec_authenticated_tests(first)
    assert evidence.validate_test_evidence(backend, second, replay) is None


def test_request_command_or_digest_mutation_is_rejected():
    backend = _Backend()
    request = _request("python -m pytest -- case-a")
    forged = replace(request, command="python -m pytest -- case-b")
    result = backend.exec_authenticated_tests(forged)
    assert evidence.validate_test_evidence(backend, forged, result) is None


def test_request_requires_artifact_and_execution_context_digests():
    for subject, context in (("", EXECUTION_CONTEXT), (SUBJECT, ""), ("z" * 64, EXECUTION_CONTEXT)):
        try:
            evidence.AuthenticatedTestRequest.issue(
                "pytest",
                subject_sha256=subject,
                execution_context_sha256=context,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("invalid evidence binding was accepted")


def test_cross_authority_substitution_is_rejected():
    backend = _Backend()
    request = _request()
    swapped = evidence.AuthenticatedTestEvidence.for_request(
        request,
        authority="spiffe://attacker/evaluator/key-9",
        counts=evidence.AuthenticatedTestCounts(100, 0),
    )
    assert evidence.validate_test_evidence(backend, request, swapped) is None


def test_non_ascii_authority_is_compared_not_crashed():
    # Readiness admits any printable authority identity, so an accented one
    # must still bind exactly and a different one must be the normal refusal.
    class _AccentedBackend(_Backend):
        test_evidence_authority = "spiffe://lightwork/évaluateur/key-1"

    backend = _AccentedBackend()
    assert evidence.evidence_backend_readiness(backend).ready is True
    request = _request()
    counts = evidence.validate_test_evidence(
        backend, request, backend.exec_authenticated_tests(request),
    )
    assert counts == evidence.AuthenticatedTestCounts(3, 1, skipped=1)
    swapped = evidence.AuthenticatedTestEvidence.for_request(
        request,
        authority="spiffe://attaquant/évaluateur/key-9",
        counts=evidence.AuthenticatedTestCounts(100, 0),
    )
    assert evidence.validate_test_evidence(backend, request, swapped) is None


def test_wrong_artifact_or_execution_context_is_rejected():
    backend = _Backend()
    request = _request()
    result = backend.exec_authenticated_tests(request)
    wrong_subject = replace(result, subject_sha256="3" * 64)
    wrong_context = replace(result, execution_context_sha256="4" * 64)
    assert evidence.validate_test_evidence(backend, request, wrong_subject) is None
    assert evidence.validate_test_evidence(backend, request, wrong_context) is None


def test_malformed_or_nonterminal_counts_are_rejected():
    backend = _Backend()
    request = _request()
    for counts in (
        evidence.AuthenticatedTestCounts(True, 0),
        evidence.AuthenticatedTestCounts(1, -1),
        evidence.AuthenticatedTestCounts(1, 0, terminal=False),
        evidence.AuthenticatedTestCounts(1_000_001, 0),
    ):
        result = evidence.AuthenticatedTestEvidence.for_request(
            request, authority=backend.test_evidence_authority, counts=counts,
        )
        assert evidence.validate_test_evidence(backend, request, result) is None


def test_boolean_marker_without_out_of_band_method_fails_readiness():
    class BooleanOnly:
        authenticated_test_results = True

    readiness = evidence.evidence_backend_readiness(BooleanOnly())
    assert readiness.ready is False
    assert any("protocol" in issue for issue in readiness.issues)
    assert any("authority" in issue for issue in readiness.issues)
    assert any("exec_authenticated_tests" in issue for issue in readiness.issues)


def test_evidence_method_requires_request_positional_and_timeout_keyword():
    class TimeoutOnly(_Backend):
        def exec_authenticated_tests(self, *, timeout=None):
            return None

    class NoTimeout(_Backend):
        def exec_authenticated_tests(self, request):
            return None

    timeout_only = evidence.evidence_backend_readiness(TimeoutOnly())
    no_timeout = evidence.evidence_backend_readiness(NoTimeout())
    assert timeout_only.ready is False
    assert any("request argument" in issue for issue in timeout_only.issues)
    assert no_timeout.ready is False
    assert any("timeout=None" in issue for issue in no_timeout.issues)

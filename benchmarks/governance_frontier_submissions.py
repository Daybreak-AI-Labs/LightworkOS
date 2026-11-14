#!/usr/bin/env python3
"""Privacy-bounded, signed third-party Governance Frontier submissions.

This is an offline foundation for a public Governance Frontier page.  A third
party signs a closed, aggregate-only submission with an externally retained
Ed25519 key.  The generator accepts a submission only when a separately
configured trust-root document recognizes that key and the submission carries
explicit, digest-bound consent, inclusion, anonymity, differential-privacy,
and privacy-budget review metadata.

Transport is intentionally outside this module.  No HTTP client, credential,
or hidden submission endpoint exists here, and a successful file copy cannot
substitute for any eligibility decision.  The schema has no raw-prompt,
raw-response, raw-record, tenant-identity, customer-identifier, free-text, or
artifact-URI field.  A page generated from these files therefore contains only
bounded aggregate counts, digests, opaque reviewer hashes, and runtime tokens.

``generate`` writes deterministic JSON and Markdown artifacts suitable for a
docs site.  ``verify`` regenerates them in memory and fails if the checked
artifacts or the benchmark-suite contract drift.  A CI workflow can call it
without granting publication or network authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from fractions import Fraction
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = ROOT / "benchmarks" / "results" / "governance-frontier-v1"
DEFAULT_SUBMISSIONS_DIR = RESULTS_DIR / "third-party-submissions"
DEFAULT_TRUST_ROOTS = RESULTS_DIR / "trusted-submitters.json"
DEFAULT_SUITE_CONTRACT = RESULTS_DIR / "suite-contract.json"
DEFAULT_LEADERBOARD_JSON = RESULTS_DIR / "leaderboard.json"
DEFAULT_LEADERBOARD_MARKDOWN = RESULTS_DIR / "leaderboard.md"

SUBMISSION_SCHEMA = "lightwork.governance-frontier-third-party-submission.v1"
TRUST_ROOTS_SCHEMA = "lightwork.governance-frontier-trusted-submitters.v1"
SUITE_CONTRACT_SCHEMA = "lightwork.governance-frontier-suite-contract.v1"
LEADERBOARD_SCHEMA = "lightwork.governance-frontier-leaderboard.v1"
SUITE = "governance-frontier-v1"
SIGNATURE_ALGORITHM = "ed25519"
SIGNATURE_CONTEXT = "lightwork.governance-frontier-third-party-submission.v1"

MAX_DOCUMENT_BYTES = 256 * 1024
MAX_SUBMISSIONS = 1_000
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 20_000
MAX_TEXT_BYTES = 128 * 1024

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_SUBMISSION_ID_RE = re.compile(r"^gfs-[0-9a-f]{32}$")
_RUNTIME_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,63}$")
_RUNTIME_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_KEY_ID_RE = re.compile(r"^gfs-key-[0-9a-f]{16}$")
_UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_BODY_FIELDS = frozenset(
    {
        "schema",
        "submission_id",
        "runtime",
        "benchmark",
        "metrics",
        "eligibility",
        "privacy",
        "submitted_at",
    }
)
_SIGNATURE_FIELDS = frozenset({"algorithm", "key_id", "public_key", "signature"})
_RUNTIME_FIELDS = frozenset({"runtime_id", "runtime_version", "implementation"})
_BENCHMARK_FIELDS = frozenset(
    {
        "suite",
        "suite_contract_sha256",
        "measurement_manifest_sha256",
        "measurement_verifier_sha256",
    }
)
_METRIC_FIELDS = frozenset(
    {
        "unsafe_prevented",
        "unsafe_scenarios",
        "benign_tasks_completed",
        "benign_scenarios",
        "false_positives",
    }
)
_ELIGIBILITY_FIELDS = frozenset(
    {
        "contribution_consent",
        "inclusion",
        "anonymity",
        "differential_privacy",
        "privacy_budget",
        "review",
    }
)
_DECISION_FIELDS = frozenset({"decision", "evidence_sha256"})
_REVIEW_FIELDS = frozenset({"reviewer_sha256", "reviewed_at"})
_PRIVACY_FIELDS = frozenset(
    {
        "raw_prompts_included",
        "raw_responses_included",
        "raw_records_included",
        "tenant_identity_included",
        "customer_identifiers_included",
        "anonymity_claim",
        "differential_privacy_claim",
        "privacy_budget_accounting",
    }
)
_TRUST_ROOT_FIELDS = frozenset({"schema", "version", "keys"})
_TRUST_KEY_FIELDS = frozenset({"key_id", "public_key", "status"})
_CONTRACT_FIELDS = frozenset(
    {
        "schema",
        "suite",
        "catalog_sha256",
        "runner_sha256",
        "scorer_sha256",
        "manifest_verifier_sha256",
        "metric_fields",
        "ranking",
        "eligibility_policy",
        "privacy_policy",
    }
)
_LEADERBOARD_FIELDS = frozenset(
    {
        "schema",
        "suite",
        "suite_contract_sha256",
        "entry_count",
        "ranking",
        "privacy_policy",
        "entries",
    }
)
_ENTRY_FIELDS = frozenset(
    {
        "rank",
        "submission_sha256",
        "runtime",
        "metrics",
        "rates_basis_points",
        "eligibility",
        "privacy",
    }
)

_ELIGIBILITY_POLICY = {
    "contribution_consent": "granted",
    "inclusion": "included",
    "anonymity": "reviewed_not_claimed",
    "differential_privacy": "reviewed_not_claimed",
    "privacy_budget": "not_applicable",
}
_PRIVACY_POLICY = {
    "raw_prompts_included": False,
    "raw_responses_included": False,
    "raw_records_included": False,
    "tenant_identity_included": False,
    "customer_identifiers_included": False,
    "anonymity_claim": False,
    "differential_privacy_claim": False,
    "privacy_budget_accounting": "unsupported",
}
_RANKING = [
    "unsafe_prevention_rate_desc",
    "benign_completion_rate_desc",
    "false_positive_rate_asc",
    "runtime_id_asc",
    "runtime_version_asc",
    "submission_sha256_asc",
]


class SubmissionError(ValueError):
    """A submission, trust root, contract, or derived artifact is invalid."""


class SubmissionVerificationError(SubmissionError):
    """A signed submission did not verify against the configured trust roots."""


@dataclass(frozen=True)
class SubmissionVerification:
    """Signature and eligibility result, kept separate from any transport state."""

    verified: bool
    eligible: bool
    reason: str
    submission_sha256: str | None = None


Signer = Callable[[bytes], bytes]


def _json_problem(value: object) -> str | None:
    """Check bounded JSON without relying on recursive input traversal."""
    stack: list[tuple[object, int]] = [(value, 0)]
    items = 0
    text_bytes = 0
    while stack:
        item, depth = stack.pop()
        items += 1
        if items > MAX_JSON_ITEMS:
            return f"JSON exceeds the {MAX_JSON_ITEMS}-item limit"
        if depth > MAX_JSON_DEPTH:
            return f"JSON exceeds the {MAX_JSON_DEPTH}-level nesting limit"
        if item is None or isinstance(item, bool):
            continue
        if isinstance(item, int):
            if item.bit_length() > 16_384:
                return "JSON integer is too large"
            continue
        if isinstance(item, float):
            return "canonical submission JSON does not allow floats"
        if isinstance(item, str):
            try:
                text_bytes += len(item.encode("utf-8"))
            except UnicodeError:
                return "JSON contains text that is not valid UTF-8"
            if text_bytes > MAX_TEXT_BYTES:
                return "JSON exceeds the decoded-text-size limit"
            continue
        if isinstance(item, list):
            stack.extend((nested, depth + 1) for nested in item)
            continue
        if isinstance(item, dict):
            for key, nested in item.items():
                if not isinstance(key, str):
                    return "JSON object keys must be strings"
                try:
                    text_bytes += len(key.encode("utf-8"))
                except UnicodeError:
                    return "JSON contains a key that is not valid UTF-8"
                if text_bytes > MAX_TEXT_BYTES:
                    return "JSON exceeds the decoded-text-size limit"
                stack.append((nested, depth + 1))
            continue
        return f"JSON contains unsupported value type {type(item).__name__}"
    return None


def canonical_json_bytes(value: object) -> bytes:
    """Return the deterministic, finite JSON bytes used by this protocol."""
    problem = _json_problem(value)
    if problem:
        raise SubmissionError(problem)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise SubmissionError(f"value cannot be canonicalized: {exc}") from exc


def canonical_json_file_bytes(value: object) -> bytes:
    """Return the one-LF-terminated canonical representation for JSON files.

    Signed bodies use :func:`canonical_json_bytes` directly.  On-disk artifacts
    use one exact trailing LF so that tracked JSON files remain readable in
    ordinary tooling without allowing arbitrary whitespace or line endings.
    """
    return canonical_json_bytes(value) + b"\n"


def _without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise SubmissionError(f"duplicate JSON object key {key!r}")
        value[key] = item
    return value


def _load_canonical_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_DOCUMENT_BYTES + 1)
    except OSError as exc:
        raise SubmissionError(f"cannot read {label}: {exc}") from exc
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise SubmissionError(f"{label} exceeds the {MAX_DOCUMENT_BYTES}-byte limit")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_without_duplicate_keys)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise SubmissionError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SubmissionError(f"{label} root must be a JSON object")
    if raw != canonical_json_file_bytes(parsed):
        raise SubmissionError(f"{label} is not canonical JSON")
    return parsed


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest(value: object, label: str) -> str:
    text = str(value or "").strip().lower().removeprefix("sha256:")
    if not _DIGEST_RE.fullmatch(text):
        raise SubmissionError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _utc_timestamp(value: object, label: str) -> str:
    if not isinstance(value, str) or not _UTC_TIMESTAMP_RE.fullmatch(value):
        raise SubmissionError(f"{label} must be an RFC3339 UTC second timestamp")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise SubmissionError(f"{label} must name a real UTC timestamp") from exc
    return value


def _closed(value: object, fields: frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SubmissionError(f"{label} must be a JSON object")
    actual = set(value)
    if actual != fields:
        missing = sorted(fields - actual)
        unexpected = sorted(actual - fields)
        raise SubmissionError(
            f"{label} has missing or unsupported fields "
            f"(missing={missing}, unexpected={unexpected})"
        )
    return dict(value)


def _nonnegative_integer(value: object, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise SubmissionError(f"{label} must be an integer >= {minimum}")
    if value > 1_000_000_000_000:
        raise SubmissionError(f"{label} exceeds the protocol maximum")
    return value


def _canonical_source_sha256(path: Path) -> str:
    try:
        text = path.read_bytes().decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise SubmissionError(f"suite source is not readable UTF-8: {path}") from exc
    return _sha256_bytes(text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8"))


def _public_key(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _DIGEST_RE.fullmatch(text):
        raise SubmissionError(f"{label} must be a 32-byte lowercase Ed25519 key")
    try:
        if len(bytes.fromhex(text)) != 32:
            raise ValueError("wrong length")
    except ValueError as exc:
        raise SubmissionError(f"{label} is malformed") from exc
    return text


def key_id_for(public_key_hex: str) -> str:
    """Opaque, deterministic key identifier; not an identity assertion."""
    key = _public_key(public_key_hex, "public_key")
    return "gfs-key-" + _sha256_bytes(bytes.fromhex(key))[:16]


def _signature(value: object) -> dict[str, str]:
    signature = _closed(value, _SIGNATURE_FIELDS, "signature")
    if signature["algorithm"] != SIGNATURE_ALGORITHM:
        raise SubmissionError("signature.algorithm must be ed25519")
    key = _public_key(signature["public_key"], "signature.public_key")
    key_id = signature["key_id"]
    if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
        raise SubmissionError("signature.key_id is malformed")
    if key_id != key_id_for(key):
        raise SubmissionError("signature.key_id does not match signature.public_key")
    encoded = signature["signature"]
    if not isinstance(encoded, str) or not re.fullmatch(r"[0-9a-f]{128}", encoded):
        raise SubmissionError("signature.signature must be 64 bytes of lowercase hex")
    return {
        "algorithm": SIGNATURE_ALGORITHM,
        "key_id": key_id,
        "public_key": key,
        "signature": encoded,
    }


def _runtime(value: object) -> dict[str, str]:
    runtime = _closed(value, _RUNTIME_FIELDS, "runtime")
    runtime_id = runtime["runtime_id"]
    runtime_version = runtime["runtime_version"]
    implementation = runtime["implementation"]
    if not isinstance(runtime_id, str) or not _RUNTIME_ID_RE.fullmatch(runtime_id):
        raise SubmissionError("runtime.runtime_id must be a bounded public token")
    if not isinstance(runtime_version, str) or not _RUNTIME_VERSION_RE.fullmatch(runtime_version):
        raise SubmissionError("runtime.runtime_version must be a bounded public token")
    if implementation not in {"external_runtime", "lightwork_runtime"}:
        raise SubmissionError("runtime.implementation is unsupported")
    return {
        "runtime_id": runtime_id,
        "runtime_version": runtime_version,
        "implementation": implementation,
    }


def _benchmark(value: object) -> dict[str, str]:
    benchmark = _closed(value, _BENCHMARK_FIELDS, "benchmark")
    if benchmark["suite"] != SUITE:
        raise SubmissionError(f"benchmark.suite must be {SUITE!r}")
    return {
        "suite": SUITE,
        "suite_contract_sha256": _digest(
            benchmark["suite_contract_sha256"], "benchmark.suite_contract_sha256"
        ),
        "measurement_manifest_sha256": _digest(
            benchmark["measurement_manifest_sha256"],
            "benchmark.measurement_manifest_sha256",
        ),
        "measurement_verifier_sha256": _digest(
            benchmark["measurement_verifier_sha256"],
            "benchmark.measurement_verifier_sha256",
        ),
    }


def _metrics(value: object) -> dict[str, int]:
    metrics = _closed(value, _METRIC_FIELDS, "metrics")
    normalized = {
        key: _nonnegative_integer(metrics[key], f"metrics.{key}") for key in sorted(_METRIC_FIELDS)
    }
    for numerator, denominator in (
        ("unsafe_prevented", "unsafe_scenarios"),
        ("benign_tasks_completed", "benign_scenarios"),
        ("false_positives", "benign_scenarios"),
    ):
        if normalized[denominator] < 1:
            raise SubmissionError(f"metrics.{denominator} must be at least 1")
        if normalized[numerator] > normalized[denominator]:
            raise SubmissionError(f"metrics.{numerator} cannot exceed metrics.{denominator}")
    return normalized


def _eligibility_decision(value: object, *, label: str, expected_decision: str) -> dict[str, str]:
    decision = _closed(value, _DECISION_FIELDS, label)
    if decision["decision"] != expected_decision:
        raise SubmissionError(f"{label}.decision must be explicitly {expected_decision!r}")
    return {
        "decision": expected_decision,
        "evidence_sha256": _digest(decision["evidence_sha256"], f"{label}.evidence_sha256"),
    }


def _eligibility(value: object) -> dict[str, Any]:
    eligibility = _closed(value, _ELIGIBILITY_FIELDS, "eligibility")
    normalized: dict[str, Any] = {
        key: _eligibility_decision(
            eligibility[key],
            label=f"eligibility.{key}",
            expected_decision=expected,
        )
        for key, expected in _ELIGIBILITY_POLICY.items()
    }
    review = _closed(eligibility["review"], _REVIEW_FIELDS, "eligibility.review")
    reviewers = review["reviewer_sha256"]
    if not isinstance(reviewers, list) or len(reviewers) != 2:
        raise SubmissionError("eligibility.review.reviewer_sha256 must contain two reviewers")
    reviewer_hashes = [_digest(item, "eligibility.review.reviewer_sha256") for item in reviewers]
    if reviewer_hashes != sorted(reviewer_hashes) or len(set(reviewer_hashes)) != 2:
        raise SubmissionError(
            "eligibility.review.reviewer_sha256 must contain two distinct sorted hashes"
        )
    normalized["review"] = {
        "reviewer_sha256": reviewer_hashes,
        "reviewed_at": _utc_timestamp(review["reviewed_at"], "eligibility.review.reviewed_at"),
    }
    return normalized


def _privacy(value: object) -> dict[str, bool | str]:
    privacy = _closed(value, _PRIVACY_FIELDS, "privacy")
    if privacy != _PRIVACY_POLICY:
        raise SubmissionError(
            "privacy must explicitly state that raw prompts/responses/records and "
            "identifiers are absent and that anonymity/differential privacy are not claimed"
        )
    return dict(_PRIVACY_POLICY)


def validate_unsigned_submission(value: Mapping[str, Any] | object) -> dict[str, Any]:
    """Validate every unsigned field; no metadata is optional or inferred."""
    body = _closed(value, _BODY_FIELDS, "submission")
    if body["schema"] != SUBMISSION_SCHEMA:
        raise SubmissionError(f"submission.schema must be {SUBMISSION_SCHEMA!r}")
    submission_id = body["submission_id"]
    if not isinstance(submission_id, str) or not _SUBMISSION_ID_RE.fullmatch(submission_id):
        raise SubmissionError("submission.submission_id must be a gfs- hexadecimal id")
    return {
        "schema": SUBMISSION_SCHEMA,
        "submission_id": submission_id,
        "runtime": _runtime(body["runtime"]),
        "benchmark": _benchmark(body["benchmark"]),
        "metrics": _metrics(body["metrics"]),
        "eligibility": _eligibility(body["eligibility"]),
        "privacy": _privacy(body["privacy"]),
        "submitted_at": _utc_timestamp(body["submitted_at"], "submission.submitted_at"),
    }


def validate_submission(value: Mapping[str, Any] | object) -> dict[str, Any]:
    """Validate a closed signed submission without trusting its provenance."""
    if not isinstance(value, Mapping):
        raise SubmissionError("submission must be a JSON object")
    actual = set(value)
    expected = _BODY_FIELDS | {"signature"}
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise SubmissionError(
            "submission has missing or unsupported fields "
            f"(missing={missing}, unexpected={unexpected})"
        )
    body = validate_unsigned_submission({key: value[key] for key in _BODY_FIELDS})
    return {**body, "signature": _signature(value["signature"])}


def signing_bytes(submission: Mapping[str, Any]) -> bytes:
    """The canonical unsigned body that an external Ed25519 signer receives."""
    return canonical_json_bytes({key: submission[key] for key in _BODY_FIELDS})


def submission_sha256(submission: Mapping[str, Any]) -> str:
    """Stable identity of the complete signed submission artifact."""
    return _sha256_bytes(canonical_json_bytes(dict(submission)))


def sign_submission(
    body: Mapping[str, Any], *, public_key_hex: str, signer: Signer
) -> dict[str, Any]:
    """Sign a validated body through an injected external-key-custody seam.

    This helper never creates, stores, exports, or loads a private key.  A
    caller owns the signer and is responsible for custody and any identity
    assurance around its public key.
    """
    normalized = validate_unsigned_submission(body)
    public_key = _public_key(public_key_hex, "public_key_hex")
    try:
        signature = signer(signing_bytes(normalized))
    except Exception as exc:  # noqa: BLE001 - signer failures cannot produce a submission
        raise SubmissionError(
            f"external submission signer failed: {type(exc).__name__}: {exc}"
        ) from exc
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise SubmissionError("external submission signer must return a 64-byte Ed25519 signature")
    signed = {
        **normalized,
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": key_id_for(public_key),
            "public_key": public_key,
            "signature": signature.hex(),
        },
    }
    return validate_submission(signed)


def _normalise_trusted_keys(
    trusted_public_keys: Iterable[str] | Mapping[str, str] | None,
) -> set[str]:
    if trusted_public_keys is None:
        return set()
    values: Iterable[object]
    if isinstance(trusted_public_keys, Mapping):
        values = trusted_public_keys.values()
    elif isinstance(trusted_public_keys, str):
        values = (trusted_public_keys,)
    else:
        values = trusted_public_keys
    keys: set[str] = set()
    for value in values:
        try:
            keys.add(_public_key(value, "trusted public key"))
        except SubmissionError:
            continue
    return keys


def verify_submission(
    submission: Mapping[str, Any] | object,
    *,
    trusted_public_keys: Iterable[str] | Mapping[str, str] | None,
    expected_suite_contract_sha256: str | None = None,
) -> SubmissionVerification:
    """Verify explicit eligibility, suite binding, provenance, and signature."""
    try:
        normalized = validate_submission(submission)
    except SubmissionError as exc:
        return SubmissionVerification(False, False, str(exc))
    digest = submission_sha256(normalized)
    if expected_suite_contract_sha256 is not None:
        try:
            expected = _digest(expected_suite_contract_sha256, "expected suite contract")
        except SubmissionError as exc:
            return SubmissionVerification(False, False, str(exc), digest)
        if normalized["benchmark"]["suite_contract_sha256"] != expected:
            return SubmissionVerification(
                False,
                False,
                "submission is bound to a different Governance Frontier suite contract",
                digest,
            )
    trusted = _normalise_trusted_keys(trusted_public_keys)
    if not trusted:
        return SubmissionVerification(
            False,
            False,
            "an explicit trusted public-key set is required",
            digest,
        )
    signature = normalized["signature"]
    public_key = signature["public_key"]
    if public_key not in trusted:
        return SubmissionVerification(
            False,
            False,
            "submission signing key is not in the configured active trust roots",
            digest,
        )
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return SubmissionVerification(
            False,
            False,
            "cryptography is required to verify an Ed25519 submission",
            digest,
        )
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(
            bytes.fromhex(signature["signature"]),
            signing_bytes(normalized),
        )
    except (InvalidSignature, ValueError, TypeError):
        return SubmissionVerification(
            False,
            False,
            "submission signature does not verify over its canonical body",
            digest,
        )
    return SubmissionVerification(
        True,
        True,
        "trusted Ed25519 signature and explicit privacy eligibility verified",
        digest,
    )


def load_submission(path: Path | str) -> dict[str, Any]:
    """Load only one exact canonical submission file."""
    submission = _load_canonical_json(Path(path), label="submission")
    return validate_submission(submission)


def current_suite_contract() -> dict[str, Any]:
    """Build the deterministic contract against the locally reviewed harness files."""
    return {
        "schema": SUITE_CONTRACT_SCHEMA,
        "suite": SUITE,
        "catalog_sha256": _canonical_source_sha256(
            ROOT / "benchmarks" / "eval_fixtures" / "governance_control_paths.v1.jsonl"
        ),
        "runner_sha256": _canonical_source_sha256(
            ROOT / "benchmarks" / "eval_governance_frontier.py"
        ),
        "scorer_sha256": _canonical_source_sha256(
            ROOT / "benchmarks" / "_common" / "governance_metrics.py"
        ),
        "manifest_verifier_sha256": _canonical_source_sha256(RESULTS_DIR / "verify_manifest.py"),
        "metric_fields": sorted(_METRIC_FIELDS),
        "ranking": list(_RANKING),
        "eligibility_policy": dict(_ELIGIBILITY_POLICY),
        "privacy_policy": dict(_PRIVACY_POLICY),
    }


def validate_suite_contract(value: Mapping[str, Any] | object) -> dict[str, Any]:
    contract = _closed(value, _CONTRACT_FIELDS, "suite contract")
    if contract["schema"] != SUITE_CONTRACT_SCHEMA or contract["suite"] != SUITE:
        raise SubmissionError("suite contract schema or suite is unsupported")
    metric_fields = contract["metric_fields"]
    ranking = contract["ranking"]
    eligibility_policy = contract["eligibility_policy"]
    privacy_policy = contract["privacy_policy"]
    if not isinstance(metric_fields, list):
        raise SubmissionError("suite contract.metric_fields must be a JSON array")
    if not isinstance(ranking, list):
        raise SubmissionError("suite contract.ranking must be a JSON array")
    if not isinstance(eligibility_policy, dict):
        raise SubmissionError("suite contract.eligibility_policy must be a JSON object")
    if not isinstance(privacy_policy, dict):
        raise SubmissionError("suite contract.privacy_policy must be a JSON object")
    normalized = {
        "schema": SUITE_CONTRACT_SCHEMA,
        "suite": SUITE,
        "catalog_sha256": _digest(contract["catalog_sha256"], "suite contract.catalog_sha256"),
        "runner_sha256": _digest(contract["runner_sha256"], "suite contract.runner_sha256"),
        "scorer_sha256": _digest(contract["scorer_sha256"], "suite contract.scorer_sha256"),
        "manifest_verifier_sha256": _digest(
            contract["manifest_verifier_sha256"],
            "suite contract.manifest_verifier_sha256",
        ),
        "metric_fields": list(metric_fields),
        "ranking": list(ranking),
        "eligibility_policy": dict(eligibility_policy),
        "privacy_policy": dict(privacy_policy),
    }
    if normalized["metric_fields"] != sorted(_METRIC_FIELDS):
        raise SubmissionError("suite contract metric_fields differs from v1")
    if normalized["ranking"] != _RANKING:
        raise SubmissionError("suite contract ranking differs from v1")
    if normalized["eligibility_policy"] != _ELIGIBILITY_POLICY:
        raise SubmissionError("suite contract eligibility policy differs from v1")
    if normalized["privacy_policy"] != _PRIVACY_POLICY:
        raise SubmissionError("suite contract privacy policy differs from v1")
    return normalized


def suite_contract_sha256(contract: Mapping[str, Any]) -> str:
    """Stable digest that a third-party submission must name explicitly."""
    return _sha256_bytes(canonical_json_bytes(validate_suite_contract(contract)))


def load_suite_contract(path: Path | str) -> dict[str, Any]:
    return validate_suite_contract(_load_canonical_json(Path(path), label="suite contract"))


def validate_trust_roots(value: Mapping[str, Any] | object) -> dict[str, Any]:
    roots = _closed(value, _TRUST_ROOT_FIELDS, "trusted submitters")
    if roots["schema"] != TRUST_ROOTS_SCHEMA or roots["version"] != 1:
        raise SubmissionError("trusted submitters schema or version is unsupported")
    rows = roots["keys"]
    if not isinstance(rows, list) or len(rows) > MAX_SUBMISSIONS:
        raise SubmissionError("trusted submitters keys must be a bounded JSON array")
    keys: list[dict[str, str]] = []
    seen: set[str] = set()
    for index, row in enumerate(rows):
        key = _closed(row, _TRUST_KEY_FIELDS, f"trusted submitters.keys[{index}]")
        public_key = _public_key(key["public_key"], f"trusted submitters.keys[{index}].public_key")
        key_id = key["key_id"]
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id):
            raise SubmissionError(f"trusted submitters.keys[{index}].key_id is malformed")
        if key_id != key_id_for(public_key):
            raise SubmissionError(f"trusted submitters.keys[{index}].key_id does not match its key")
        if key["status"] not in {"active", "revoked"}:
            raise SubmissionError(f"trusted submitters.keys[{index}].status is unsupported")
        if public_key in seen:
            raise SubmissionError("trusted submitters contains duplicate public keys")
        seen.add(public_key)
        keys.append({"key_id": key_id, "public_key": public_key, "status": key["status"]})
    if keys != sorted(keys, key=lambda item: item["key_id"]):
        raise SubmissionError("trusted submitters keys must be sorted by key_id")
    return {"schema": TRUST_ROOTS_SCHEMA, "version": 1, "keys": keys}


def load_trust_roots(path: Path | str) -> dict[str, Any]:
    return validate_trust_roots(_load_canonical_json(Path(path), label="trusted submitters"))


def active_public_keys(roots: Mapping[str, Any]) -> set[str]:
    """Return only explicit active roots; revoked roots never verify submissions."""
    normalized = validate_trust_roots(roots)
    return {row["public_key"] for row in normalized["keys"] if row["status"] == "active"}


def _basis_points(numerator: int, denominator: int) -> int:
    return (numerator * 10_000 + denominator // 2) // denominator


def _entry(submission: Mapping[str, Any], verification: SubmissionVerification) -> dict[str, Any]:
    if not verification.verified or not verification.eligible or not verification.submission_sha256:
        raise SubmissionVerificationError(
            "an unverified submission cannot become a leaderboard entry"
        )
    metrics = dict(submission["metrics"])
    return {
        "rank": 0,
        "submission_sha256": verification.submission_sha256,
        "runtime": dict(submission["runtime"]),
        "metrics": metrics,
        "rates_basis_points": {
            "unsafe_prevention": _basis_points(
                metrics["unsafe_prevented"], metrics["unsafe_scenarios"]
            ),
            "benign_completion": _basis_points(
                metrics["benign_tasks_completed"], metrics["benign_scenarios"]
            ),
            "false_positive": _basis_points(
                metrics["false_positives"], metrics["benign_scenarios"]
            ),
        },
        "eligibility": dict(submission["eligibility"]),
        "privacy": dict(submission["privacy"]),
    }


def _ranking_key(entry: Mapping[str, Any]) -> tuple[Any, ...]:
    metrics = entry["metrics"]
    runtime = entry["runtime"]
    return (
        -Fraction(metrics["unsafe_prevented"], metrics["unsafe_scenarios"]),
        -Fraction(metrics["benign_tasks_completed"], metrics["benign_scenarios"]),
        Fraction(metrics["false_positives"], metrics["benign_scenarios"]),
        runtime["runtime_id"],
        runtime["runtime_version"],
        entry["submission_sha256"],
    )


def _submission_paths(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    if not directory.is_dir():
        raise SubmissionError("third-party submissions path is not a directory")
    paths = sorted(path for path in directory.iterdir() if path.suffix == ".json")
    if len(paths) > MAX_SUBMISSIONS:
        raise SubmissionError("too many third-party submission files")
    return paths


def build_leaderboard(
    *,
    submissions_dir: Path = DEFAULT_SUBMISSIONS_DIR,
    trust_roots: Mapping[str, Any],
    suite_contract: Mapping[str, Any],
) -> dict[str, Any]:
    """Verify every candidate and return a deterministic aggregate-only page model."""
    contract = validate_suite_contract(suite_contract)
    contract_digest = suite_contract_sha256(contract)
    trusted = active_public_keys(trust_roots)
    entries: list[dict[str, Any]] = []
    seen_submission_digests: set[str] = set()
    for path in _submission_paths(submissions_dir):
        submission = load_submission(path)
        verification = verify_submission(
            submission,
            trusted_public_keys=trusted,
            expected_suite_contract_sha256=contract_digest,
        )
        if not verification.verified or not verification.eligible:
            raise SubmissionVerificationError(f"{path.name}: {verification.reason}")
        if verification.submission_sha256 in seen_submission_digests:
            raise SubmissionVerificationError(f"{path.name}: duplicate signed submission")
        seen_submission_digests.add(str(verification.submission_sha256))
        entries.append(_entry(submission, verification))
    entries.sort(key=_ranking_key)
    for rank, entry in enumerate(entries, 1):
        entry["rank"] = rank
    return {
        "schema": LEADERBOARD_SCHEMA,
        "suite": SUITE,
        "suite_contract_sha256": contract_digest,
        "entry_count": len(entries),
        "ranking": list(_RANKING),
        "privacy_policy": dict(_PRIVACY_POLICY),
        "entries": entries,
    }


def render_leaderboard_markdown(leaderboard: Mapping[str, Any]) -> str:
    """Render a deterministic public page with no free-text submission content."""
    artifact = _closed(leaderboard, _LEADERBOARD_FIELDS, "leaderboard")
    if artifact["schema"] != LEADERBOARD_SCHEMA or artifact["suite"] != SUITE:
        raise SubmissionError("leaderboard schema or suite is unsupported")
    digest = _digest(artifact["suite_contract_sha256"], "leaderboard.suite_contract_sha256")
    entries = artifact["entries"]
    if not isinstance(entries, list) or artifact["entry_count"] != len(entries):
        raise SubmissionError("leaderboard entries are malformed")
    lines = [
        "# Governance Frontier - third-party signed submissions",
        "",
        "> This page is generated only from trusted, signed, aggregate-only submissions.",
        "> It is not a population estimate, certification, or claim that an",
        "> entry is anonymous, differentially private, or independently audited.",
        "",
        "## Admission policy",
        "",
        f"- Suite contract SHA-256: `{digest}`",
        "- Every entry names explicit, digest-bound contribution-consent and",
        "  inclusion decisions; those decisions are never inferred from delivery.",
        "- Anonymity and differential privacy must be explicitly",
        "  `reviewed_not_claimed`; privacy budget must be `not_applicable`.",
        "- No raw prompts, raw responses, records, tenant identities, customer",
        "  identifiers, artifact URLs, or free-text submission fields are accepted.",
        "",
        "## Ranked submissions",
        "",
        "| Rank | Runtime | Version | Unsafe prevention | Benign completion | FPR | Signed submission SHA-256 |",
        "|---:|---|---|---:|---:|---:|---|",
    ]
    if not entries:
        lines.append("| - | No eligible trusted submissions | - | - | - | - | - |")
    for entry in entries:
        normalized = _closed(entry, _ENTRY_FIELDS, "leaderboard entry")
        metrics = _closed(normalized["metrics"], _METRIC_FIELDS, "leaderboard metrics")
        runtime = _runtime(normalized["runtime"])
        rank = _nonnegative_integer(normalized["rank"], "leaderboard rank", minimum=1)
        unsafe = f"{metrics['unsafe_prevented']}/{metrics['unsafe_scenarios']}"
        benign = f"{metrics['benign_tasks_completed']}/{metrics['benign_scenarios']}"
        fpr = f"{metrics['false_positives']}/{metrics['benign_scenarios']}"
        lines.append(
            f"| {rank} | `{runtime['runtime_id']}` | `{runtime['runtime_version']}` | "
            f"{unsafe} | {benign} | {fpr} | `{normalized['submission_sha256']}` |"
        )
    lines.extend(
        [
            "",
            "## Verification limits",
            "",
            "- The signature proves only that a configured trusted key signed the",
            "  closed submission body; trust-root governance remains external.",
            "- The listed manifest and verifier digests are evidence bindings, not",
            "  downloaded or replayed evidence. A reviewer must obtain and verify",
            "  those artifacts separately before relying on a measurement claim.",
            "- Hosting, independent review of contributor evidence, and public",
            "  trust-root publication are separate operational steps.",
            "",
        ]
    )
    return "\n".join(lines)


def _write_exact(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def generate_site_artifacts(
    *,
    submissions_dir: Path = DEFAULT_SUBMISSIONS_DIR,
    trust_roots_path: Path = DEFAULT_TRUST_ROOTS,
    suite_contract_path: Path = DEFAULT_SUITE_CONTRACT,
    leaderboard_json_path: Path = DEFAULT_LEADERBOARD_JSON,
    leaderboard_markdown_path: Path = DEFAULT_LEADERBOARD_MARKDOWN,
) -> dict[str, Any]:
    """Write the canonical JSON and deterministic Markdown docs-site artifacts."""
    roots = load_trust_roots(trust_roots_path)
    contract = load_suite_contract(suite_contract_path)
    leaderboard = build_leaderboard(
        submissions_dir=submissions_dir,
        trust_roots=roots,
        suite_contract=contract,
    )
    _write_exact(leaderboard_json_path, canonical_json_file_bytes(leaderboard))
    _write_exact(
        leaderboard_markdown_path,
        render_leaderboard_markdown(leaderboard).encode("utf-8"),
    )
    return leaderboard


def verify_site_artifacts(
    *,
    submissions_dir: Path = DEFAULT_SUBMISSIONS_DIR,
    trust_roots_path: Path = DEFAULT_TRUST_ROOTS,
    suite_contract_path: Path = DEFAULT_SUITE_CONTRACT,
    leaderboard_json_path: Path = DEFAULT_LEADERBOARD_JSON,
    leaderboard_markdown_path: Path = DEFAULT_LEADERBOARD_MARKDOWN,
) -> tuple[bool, list[str]]:
    """Fail when contract, signed inputs, JSON, or Markdown outputs drift."""
    errors: list[str] = []
    try:
        tracked_contract = load_suite_contract(suite_contract_path)
        expected_contract = validate_suite_contract(current_suite_contract())
    except SubmissionError as exc:
        return False, [str(exc)]
    if tracked_contract != expected_contract:
        errors.append("suite contract differs from the current reviewed benchmark sources")
    try:
        roots = load_trust_roots(trust_roots_path)
        expected_leaderboard = build_leaderboard(
            submissions_dir=submissions_dir,
            trust_roots=roots,
            suite_contract=tracked_contract,
        )
        expected_json = canonical_json_file_bytes(expected_leaderboard)
        expected_markdown = render_leaderboard_markdown(expected_leaderboard).encode("utf-8")
    except SubmissionError as exc:
        return False, [*errors, str(exc)]
    for path, expected, label in (
        (leaderboard_json_path, expected_json, "leaderboard JSON"),
        (leaderboard_markdown_path, expected_markdown, "leaderboard Markdown"),
    ):
        try:
            actual = path.read_bytes()
        except OSError as exc:
            errors.append(f"{label} unreadable: {exc}")
        else:
            if actual != expected:
                errors.append(f"{label} is not the deterministic submission render")
    return not errors, errors


def write_suite_contract(path: Path = DEFAULT_SUITE_CONTRACT) -> dict[str, Any]:
    """Write the current contract explicitly; useful when reviewed sources change."""
    contract = validate_suite_contract(current_suite_contract())
    _write_exact(path, canonical_json_file_bytes(contract))
    return contract


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    contract_cmd = sub.add_parser("build-contract", help="write the current suite contract")
    contract_cmd.add_argument("--output", type=Path, default=DEFAULT_SUITE_CONTRACT)
    submission_cmd = sub.add_parser(
        "verify-submission",
        help="verify one signed third-party submission against explicit trust roots",
    )
    submission_cmd.add_argument("--submission", required=True, type=Path)
    submission_cmd.add_argument("--trusted-roots", type=Path, default=DEFAULT_TRUST_ROOTS)
    submission_cmd.add_argument("--suite-contract", type=Path, default=DEFAULT_SUITE_CONTRACT)
    for name, help_text in (
        ("generate", "generate deterministic leaderboard JSON and Markdown"),
        ("verify", "fail if current contract or generated artifacts drift"),
    ):
        command = sub.add_parser(name, help=help_text)
        command.add_argument("--submissions-dir", type=Path, default=DEFAULT_SUBMISSIONS_DIR)
        command.add_argument("--trusted-roots", type=Path, default=DEFAULT_TRUST_ROOTS)
        command.add_argument("--suite-contract", type=Path, default=DEFAULT_SUITE_CONTRACT)
        command.add_argument("--leaderboard-json", type=Path, default=DEFAULT_LEADERBOARD_JSON)
        command.add_argument(
            "--leaderboard-markdown", type=Path, default=DEFAULT_LEADERBOARD_MARKDOWN
        )
    args = parser.parse_args(argv)
    if args.command == "build-contract":
        try:
            contract = write_suite_contract(args.output)
        except SubmissionError as exc:
            print(f"FAILED: {exc}", file=sys.stderr)
            return 1
        print(f"WROTE: suite contract {suite_contract_sha256(contract)} at {args.output}")
        return 0
    if args.command == "verify-submission":
        try:
            roots = load_trust_roots(args.trusted_roots)
            contract = load_suite_contract(args.suite_contract)
            submission = load_submission(args.submission)
            verification = verify_submission(
                submission,
                trusted_public_keys=active_public_keys(roots),
                expected_suite_contract_sha256=suite_contract_sha256(contract),
            )
        except SubmissionError as exc:
            print(f"FAILED: {exc}", file=sys.stderr)
            return 1
        if not verification.verified or not verification.eligible:
            print(f"FAILED: {verification.reason}", file=sys.stderr)
            return 1
        print(
            "VERIFIED: signed third-party submission "
            f"{verification.submission_sha256} is eligible under the explicit trust roots"
        )
        return 0
    if args.command == "generate":
        try:
            leaderboard = generate_site_artifacts(
                submissions_dir=args.submissions_dir,
                trust_roots_path=args.trusted_roots,
                suite_contract_path=args.suite_contract,
                leaderboard_json_path=args.leaderboard_json,
                leaderboard_markdown_path=args.leaderboard_markdown,
            )
        except SubmissionError as exc:
            print(f"FAILED: {exc}", file=sys.stderr)
            return 1
        print(
            f"WROTE: {leaderboard['entry_count']} eligible signed submission(s) to "
            f"{args.leaderboard_json} and {args.leaderboard_markdown}"
        )
        return 0
    ok, errors = verify_site_artifacts(
        submissions_dir=args.submissions_dir,
        trust_roots_path=args.trusted_roots,
        suite_contract_path=args.suite_contract,
        leaderboard_json_path=args.leaderboard_json,
        leaderboard_markdown_path=args.leaderboard_markdown,
    )
    if ok:
        print("VERIFIED: third-party submission contract and docs artifacts are drift-free")
        return 0
    for error in errors:
        print(f"FAILED: {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover - direct CLI invocation
    raise SystemExit(main())


__all__ = [
    "DEFAULT_LEADERBOARD_JSON",
    "DEFAULT_LEADERBOARD_MARKDOWN",
    "DEFAULT_SUBMISSIONS_DIR",
    "DEFAULT_SUITE_CONTRACT",
    "DEFAULT_TRUST_ROOTS",
    "LEADERBOARD_SCHEMA",
    "SIGNATURE_ALGORITHM",
    "SUBMISSION_SCHEMA",
    "SUITE",
    "SUITE_CONTRACT_SCHEMA",
    "SubmissionError",
    "SubmissionVerification",
    "SubmissionVerificationError",
    "TRUST_ROOTS_SCHEMA",
    "active_public_keys",
    "build_leaderboard",
    "canonical_json_bytes",
    "canonical_json_file_bytes",
    "current_suite_contract",
    "generate_site_artifacts",
    "key_id_for",
    "load_submission",
    "load_suite_contract",
    "load_trust_roots",
    "main",
    "render_leaderboard_markdown",
    "sign_submission",
    "signing_bytes",
    "submission_sha256",
    "suite_contract_sha256",
    "validate_submission",
    "validate_suite_contract",
    "validate_trust_roots",
    "verify_site_artifacts",
    "verify_submission",
    "write_suite_contract",
]

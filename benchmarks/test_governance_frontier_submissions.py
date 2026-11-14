"""Focused offline tests for third-party Governance Frontier submissions."""

from __future__ import annotations

import copy
import importlib.util
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _load():
    path = Path(__file__).with_name("governance_frontier_submissions.py")
    spec = importlib.util.spec_from_file_location(
        "benchmarks_governance_frontier_submissions", path
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


frontier = _load()


def _digest(number: int) -> str:
    return f"{number:064x}"


def _public_key(private_key: Ed25519PrivateKey) -> str:
    return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _body(
    *,
    submission_id: str = "gfs-11111111111111111111111111111111",
    runtime_id: str = "external-runtime",
    runtime_version: str = "1.0.0",
    unsafe_prevented: int = 22,
    unsafe_scenarios: int = 24,
    benign_completed: int = 15,
    benign_scenarios: int = 16,
    false_positives: int = 1,
    suite_contract_sha256: str | None = None,
) -> dict[str, object]:
    suite_digest = suite_contract_sha256 or frontier.suite_contract_sha256(
        frontier.current_suite_contract()
    )
    return {
        "schema": frontier.SUBMISSION_SCHEMA,
        "submission_id": submission_id,
        "runtime": {
            "runtime_id": runtime_id,
            "runtime_version": runtime_version,
            "implementation": "external_runtime",
        },
        "benchmark": {
            "suite": frontier.SUITE,
            "suite_contract_sha256": suite_digest,
            "measurement_manifest_sha256": _digest(81),
            "measurement_verifier_sha256": _digest(82),
        },
        "metrics": {
            "unsafe_prevented": unsafe_prevented,
            "unsafe_scenarios": unsafe_scenarios,
            "benign_tasks_completed": benign_completed,
            "benign_scenarios": benign_scenarios,
            "false_positives": false_positives,
        },
        "eligibility": {
            "contribution_consent": {
                "decision": "granted",
                "evidence_sha256": _digest(1),
            },
            "inclusion": {
                "decision": "included",
                "evidence_sha256": _digest(2),
            },
            "anonymity": {
                "decision": "reviewed_not_claimed",
                "evidence_sha256": _digest(3),
            },
            "differential_privacy": {
                "decision": "reviewed_not_claimed",
                "evidence_sha256": _digest(4),
            },
            "privacy_budget": {
                "decision": "not_applicable",
                "evidence_sha256": _digest(5),
            },
            "review": {
                "reviewer_sha256": [_digest(6), _digest(7)],
                "reviewed_at": "2026-09-02T12:00:00Z",
            },
        },
        "privacy": {
            "raw_prompts_included": False,
            "raw_responses_included": False,
            "raw_records_included": False,
            "tenant_identity_included": False,
            "customer_identifiers_included": False,
            "anonymity_claim": False,
            "differential_privacy_claim": False,
            "privacy_budget_accounting": "unsupported",
        },
        "submitted_at": "2026-09-02T12:01:00Z",
    }


def _sign(body: dict[str, object], private_key: Ed25519PrivateKey) -> dict[str, object]:
    return frontier.sign_submission(
        body,
        public_key_hex=_public_key(private_key),
        signer=private_key.sign,
    )


def _roots(public_keys: list[str], *, revoked: bool = False) -> dict[str, object]:
    keys = [
        {
            "key_id": frontier.key_id_for(public_key),
            "public_key": public_key,
            "status": "revoked" if revoked else "active",
        }
        for public_key in public_keys
    ]
    return {
        "schema": frontier.TRUST_ROOTS_SCHEMA,
        "version": 1,
        "keys": sorted(keys, key=lambda row: row["key_id"]),
    }


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(frontier.canonical_json_file_bytes(value))


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))


def test_trusted_signature_and_explicit_eligibility_verify(signing_key):
    signed = _sign(_body(), signing_key)
    verification = frontier.verify_submission(
        signed,
        trusted_public_keys=[_public_key(signing_key)],
        expected_suite_contract_sha256=frontier.suite_contract_sha256(
            frontier.current_suite_contract()
        ),
    )

    assert verification.verified
    assert verification.eligible
    assert verification.submission_sha256 == frontier.submission_sha256(signed)
    assert "explicit privacy eligibility" in verification.reason


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (
            lambda body: body["eligibility"].pop("contribution_consent"),
            "contribution_consent",
        ),
        (
            lambda body: body["eligibility"]["inclusion"].update({"decision": "inferred"}),
            "explicitly 'included'",
        ),
        (
            lambda body: body["privacy"].update({"anonymity_claim": True}),
            "privacy must explicitly state",
        ),
        (
            lambda body: body.update({"raw_prompt": "sensitive-prompt-never-publish"}),
            "unsupported fields",
        ),
    ],
)
def test_consent_inclusion_and_privacy_are_closed_and_never_inferred(signing_key, mutate, expected):
    body = _body()
    mutate(body)

    with pytest.raises(frontier.SubmissionError, match=expected):
        _sign(body, signing_key)


def test_untrusted_revoked_tampered_and_wrong_contract_submissions_fail(signing_key):
    signed = _sign(_body(), signing_key)
    public_key = _public_key(signing_key)

    untrusted = frontier.verify_submission(
        signed,
        trusted_public_keys=(),
    )
    assert not untrusted.verified
    assert "explicit trusted public-key set" in untrusted.reason

    roots = _roots([public_key], revoked=True)
    assert frontier.active_public_keys(roots) == set()
    revoked = frontier.verify_submission(
        signed,
        trusted_public_keys=frontier.active_public_keys(roots),
    )
    assert not revoked.verified

    tampered = copy.deepcopy(signed)
    tampered["metrics"]["unsafe_prevented"] = 21
    invalid_signature = frontier.verify_submission(
        tampered,
        trusted_public_keys=[public_key],
    )
    assert not invalid_signature.verified
    assert "signature does not verify" in invalid_signature.reason

    wrong_contract = frontier.verify_submission(
        signed,
        trusted_public_keys=[public_key],
        expected_suite_contract_sha256=_digest(99),
    )
    assert not wrong_contract.verified
    assert "different Governance Frontier suite contract" in wrong_contract.reason


def test_contract_binds_the_metric_scorer():
    contract = frontier.current_suite_contract()
    scorer = frontier.ROOT / "benchmarks" / "_common" / "governance_metrics.py"
    assert contract["scorer_sha256"] == frontier._canonical_source_sha256(scorer)
    drifted = dict(contract, scorer_sha256=_digest(93))
    assert frontier.suite_contract_sha256(drifted) != frontier.suite_contract_sha256(contract)


def test_contract_rejects_type_confusion_and_source_contract_is_deterministic():
    contract = frontier.current_suite_contract()
    assert frontier.validate_suite_contract(contract) == contract
    assert frontier.suite_contract_sha256(contract) == frontier.suite_contract_sha256(
        copy.deepcopy(contract)
    )

    malformed = copy.deepcopy(contract)
    malformed["metric_fields"] = "unsafe_prevented"
    with pytest.raises(frontier.SubmissionError, match="metric_fields"):
        frontier.validate_suite_contract(malformed)


def test_submission_verifier_cli_requires_an_explicit_active_root(tmp_path, signing_key, capsys):
    public_key = _public_key(signing_key)
    submission_path = tmp_path / "submission.json"
    roots_path = tmp_path / "trusted-submitters.json"
    contract_path = tmp_path / "suite-contract.json"
    _write_json(submission_path, _sign(_body(), signing_key))
    _write_json(roots_path, _roots([public_key]))
    _write_json(contract_path, frontier.current_suite_contract())

    assert (
        frontier.main(
            [
                "verify-submission",
                "--submission",
                str(submission_path),
                "--trusted-roots",
                str(roots_path),
                "--suite-contract",
                str(contract_path),
            ]
        )
        == 0
    )
    assert "VERIFIED: signed third-party submission" in capsys.readouterr().out

    _write_json(roots_path, _roots([public_key], revoked=True))
    assert (
        frontier.main(
            [
                "verify-submission",
                "--submission",
                str(submission_path),
                "--trusted-roots",
                str(roots_path),
                "--suite-contract",
                str(contract_path),
            ]
        )
        == 1
    )
    assert "explicit trusted public-key set" in capsys.readouterr().err


def test_generator_and_no_drift_verifier_are_aggregate_only_and_deterministic(
    tmp_path, signing_key
):
    other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
    submissions_dir = tmp_path / "third-party-submissions"
    submissions_dir.mkdir()
    first = _sign(
        _body(
            submission_id="gfs-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            runtime_id="alpha-runtime",
            runtime_version="1.0.0",
            unsafe_prevented=24,
            benign_completed=16,
            false_positives=0,
        ),
        signing_key,
    )
    second = _sign(
        _body(
            submission_id="gfs-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            runtime_id="beta-runtime",
            runtime_version="2.0.0",
            unsafe_prevented=23,
            benign_completed=16,
            false_positives=0,
        ),
        other_key,
    )
    _write_json(submissions_dir / "alpha.json", first)
    _write_json(submissions_dir / "beta.json", second)
    roots_path = tmp_path / "trusted-submitters.json"
    contract_path = tmp_path / "suite-contract.json"
    leaderboard_json = tmp_path / "leaderboard.json"
    leaderboard_markdown = tmp_path / "leaderboard.md"
    _write_json(
        roots_path,
        _roots([_public_key(signing_key), _public_key(other_key)]),
    )
    _write_json(contract_path, frontier.current_suite_contract())

    generated = frontier.generate_site_artifacts(
        submissions_dir=submissions_dir,
        trust_roots_path=roots_path,
        suite_contract_path=contract_path,
        leaderboard_json_path=leaderboard_json,
        leaderboard_markdown_path=leaderboard_markdown,
    )
    assert [entry["runtime"]["runtime_id"] for entry in generated["entries"]] == [
        "alpha-runtime",
        "beta-runtime",
    ]
    assert [entry["rank"] for entry in generated["entries"]] == [1, 2]
    rendered = leaderboard_markdown.read_text(encoding="utf-8")
    rendered_json = leaderboard_json.read_text(encoding="utf-8")
    assert "measurement_manifest_sha256" not in rendered_json
    assert "artifact URLs" in rendered

    assert frontier.verify_site_artifacts(
        submissions_dir=submissions_dir,
        trust_roots_path=roots_path,
        suite_contract_path=contract_path,
        leaderboard_json_path=leaderboard_json,
        leaderboard_markdown_path=leaderboard_markdown,
    ) == (True, [])

    source_drift = frontier.current_suite_contract()
    source_drift["catalog_sha256"] = _digest(91)
    _write_json(contract_path, source_drift)
    ok, errors = frontier.verify_site_artifacts(
        submissions_dir=submissions_dir,
        trust_roots_path=roots_path,
        suite_contract_path=contract_path,
        leaderboard_json_path=leaderboard_json,
        leaderboard_markdown_path=leaderboard_markdown,
    )
    assert not ok
    assert "suite contract differs from the current reviewed benchmark sources" in errors
    _write_json(contract_path, frontier.current_suite_contract())

    leaderboard_markdown.write_text(rendered + "tamper\n", encoding="utf-8")
    ok, errors = frontier.verify_site_artifacts(
        submissions_dir=submissions_dir,
        trust_roots_path=roots_path,
        suite_contract_path=contract_path,
        leaderboard_json_path=leaderboard_json,
        leaderboard_markdown_path=leaderboard_markdown,
    )
    assert not ok
    assert any("leaderboard Markdown is not the deterministic" in error for error in errors)


def test_checked_in_empty_public_artifacts_are_current_and_fail_closed():
    ok, errors = frontier.verify_site_artifacts()
    assert ok, errors
    roots = frontier.load_trust_roots(frontier.DEFAULT_TRUST_ROOTS)
    assert roots["keys"] == []
    leaderboard = frontier.build_leaderboard(
        trust_roots=roots,
        suite_contract=frontier.load_suite_contract(frontier.DEFAULT_SUITE_CONTRACT),
    )
    assert leaderboard["entry_count"] == 0

"""Offline validation for the governance-overhead benchmark.

The suite exercises the runner's pure functions and one real paired task
execution. It deliberately never calls :func:`run_benchmark` (36 paired
instances, a signed audit chain, and a SQLite world) -- that is the CI gate's
job. Everything here stays fast and deterministic.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
RUNNER = REPO / "benchmarks" / "eval_harness_overhead.py"
TRACKED_MANIFEST = REPO / "benchmarks" / "results" / "harness-overhead-v1" / "measured-manifest.json"
TRACKED_REPORT = REPO / "benchmarks" / "HARNESS_OVERHEAD_RESULTS.md"


def _load():
    """Import the standalone runner by path, with the repo root importable."""
    spec = importlib.util.spec_from_file_location("benchmarks_harness_overhead", RUNNER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    inserted = str(REPO) not in sys.path
    if inserted:
        sys.path.insert(0, str(REPO))
    try:
        spec.loader.exec_module(module)
    finally:
        if inserted:
            sys.path.remove(str(REPO))
    return module


overhead = _load()


# -- task table ------------------------------------------------------------

def test_task_table_is_balanced_and_table_driven():
    tasks = overhead.load_tasks()
    assert len(tasks) == 12
    assert len({task["id"] for task in tasks}) == 12
    assert {task["shape"] for task in tasks} == overhead.EXPECTED_SHAPES
    for shape in sorted(overhead.EXPECTED_SHAPES):
        assert sum(task["shape"] == shape for task in tasks) == 6
    # The screens can only be measured if something actually trips them.
    assert sum(task["embeds_credential"] for task in tasks) > 0
    assert sum(task["embeds_injection"] for task in tasks) > 0


@pytest.mark.parametrize(
    "mutation",
    [
        lambda rows: rows[1:],                                   # wrong count
        lambda rows: [rows[0], *rows[1:11], dict(rows[0])],      # duplicate id
        lambda rows: [{**rows[0], "shape": "invented"}, *rows[1:]],
        lambda rows: [{k: v for k, v in rows[0].items() if k != "id"}, *rows[1:]],
    ],
)
def test_load_tasks_rejects_a_broken_table(mutation):
    rows = [dict(task) for task in overhead.TASKS]
    with pytest.raises(ValueError):
        overhead.load_tasks(tuple(mutation(rows)))


def test_load_tasks_rejects_an_unbalanced_shape_split():
    rows = [dict(task) for task in overhead.TASKS]
    rows[0] = {
        "id": rows[0]["id"], "shape": "actuation", "period": "2024-11",
        "account": "6100", "amount_cents": 1, "memo": "swapped shape",
        "embeds_credential": False, "embeds_injection": False,
    }
    with pytest.raises(ValueError, match="exactly six"):
        overhead.load_tasks(tuple(rows))


def test_documents_embed_the_screen_material_and_never_reach_tool_params():
    tasks = {task["id"]: task for task in overhead.load_tasks()}
    with_credential = next(t for t in tasks.values() if t["embeds_credential"])
    with_injection = next(t for t in tasks.values() if t["embeds_injection"])

    from maverick.memory_guard import injection_markers
    from maverick.safety.secret_detector import redact

    credential_doc = overhead.task_document(with_credential)
    _redacted, matches = redact(credential_doc)
    assert matches, "the credential-bearing document must trip the secret detector"
    assert injection_markers(overhead.task_document(with_injection))

    for task in tasks.values():
        document = overhead.task_document(task)
        for step in overhead.task_steps(task):
            if step["kind"] == "tool":
                assert document not in json.dumps(step["params"])


def test_task_steps_are_pure_and_shape_specific():
    tasks = {task["id"]: task for task in overhead.load_tasks()}
    analysis = next(t for t in tasks.values() if t["shape"] == "analysis")
    actuation = next(t for t in tasks.values() if t["shape"] == "actuation")

    assert overhead.task_steps(analysis) == overhead.task_steps(analysis)
    assert [step["kind"] for step in overhead.task_steps(analysis)] == ["tool", "model", "tool"]
    assert [step["kind"] for step in overhead.task_steps(actuation)] == [
        "tool", "model", "tool", "tool",
    ]
    assert overhead.task_steps(actuation)[-1]["tool"] == overhead.CONSEQUENTIAL_TOOL
    assert overhead.CONSEQUENTIAL_TOOL not in [
        step.get("tool") for step in overhead.task_steps(analysis)
    ]


# -- stubbed model boundary and tools --------------------------------------

def test_stub_model_call_is_a_pure_function_of_the_prompt():
    first = overhead.stub_model_call("analyse::alpha")
    assert first == overhead.stub_model_call("analyse::alpha")
    assert first != overhead.stub_model_call("analyse::beta")
    assert first["model"] == overhead.STUB_MODEL
    assert first["input_tokens"] > 0 and first["output_tokens"] > 0


def test_execute_tool_is_deterministic_and_only_the_posting_tool_has_an_effect(tmp_path):
    ledger = tmp_path / "ledger.ndjson"
    read = overhead.execute_tool("gl_read_trial_balance", {"period": "2024-11"}, ledger)
    assert read == overhead.execute_tool("gl_read_trial_balance", {"period": "2024-11"}, ledger)
    assert not ledger.exists()

    params = {"account": "6100", "amount_cents": 100, "period": "2024-11"}
    overhead.execute_tool(overhead.CONSEQUENTIAL_TOOL, params, ledger)
    assert ledger.read_text(encoding="utf-8").count("\n") == 1
    overhead.execute_tool(overhead.CONSEQUENTIAL_TOOL, params, ledger)
    assert ledger.read_text(encoding="utf-8").count("\n") == 2


# -- one real paired execution ---------------------------------------------

def test_run_arms_closes_its_world_when_a_pair_fails(tmp_path, monkeypatch):
    import maverick.world_model as world_model

    class FakeWorld:
        closed = False

        def close(self):
            self.closed = True

    world = FakeWorld()
    monkeypatch.setattr(world_model, "open_world", lambda _path: world)
    monkeypatch.setattr(overhead, "load_tasks", lambda: ({"id": "only-task"},))
    monkeypatch.setattr(overhead, "_shield_profile", lambda: {"backend": "test"})

    def fail_pair(*_args, **_kwargs):
        raise RuntimeError("pair failed")

    monkeypatch.setattr(overhead, "_pair_instance", fail_pair)

    with pytest.raises(RuntimeError, match="pair failed"):
        overhead._run_arms((11,), tmp_path)

    assert world.closed is True


@pytest.fixture
def governed_home(tmp_path, monkeypatch):
    """A throwaway Lightwork home so the arms never touch the real stores."""
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.setenv("MAVERICK_GOVERNED_ACTIONS", "1")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.delenv("MAVERICK_APPROVALS_REQUIRED", raising=False)
    from maverick.config import reset_config_cache

    reset_config_cache()
    overhead._reset_audit_writer()
    yield tmp_path
    overhead._reset_audit_writer()
    reset_config_cache()


def _run_pair(task, tmp_path):
    from maverick.file_lock import ensure_private_directory
    from maverick.world_model import open_world

    # This directory belongs exclusively to the test. On Windows chmod does
    # not tighten its DACL, so use the same cross-platform private-directory
    # helper as production rather than depending on the host temp ACL.
    ensure_private_directory(tmp_path)
    governed_ws = tmp_path / "governed"
    ungoverned_ws = tmp_path / "ungoverned"
    governed_ws.mkdir(parents=True, exist_ok=True)
    ungoverned_ws.mkdir(parents=True, exist_ok=True)
    governed = overhead.run_governed(
        task, 11, governed_ws, world=open_world(tmp_path / "world.db"),
        goal_id=1, lineage_dir=tmp_path / "lineage",
    )
    ungoverned = overhead.run_ungoverned(task, 11, ungoverned_ws)
    return governed, ungoverned


def test_both_arms_agree_on_the_answer_and_the_effect(governed_home):
    task = next(t for t in overhead.load_tasks() if t["shape"] == "actuation")
    governed, ungoverned = _run_pair(task, governed_home)

    assert governed["answer_sha256"] == ungoverned["answer_sha256"]
    assert governed["effect_sha256"] == ungoverned["effect_sha256"]
    assert governed["effect_sha256"], "the actuation shape must leave an effect"
    for field in ("steps", "model_calls", "tool_calls", "input_tokens", "output_tokens"):
        assert governed[field] == ungoverned[field], field


def test_the_ungoverned_arm_produces_no_governance_artifacts(governed_home):
    task = next(t for t in overhead.load_tasks() if t["shape"] == "actuation")
    _governed, ungoverned = _run_pair(task, governed_home)
    assert set(ungoverned["artifacts"]) == set(overhead.ARTIFACT_KEYS)
    assert sum(ungoverned["artifacts"].values()) == 0


def test_the_governed_arm_persists_receipts_approvals_and_audit_rows(governed_home):
    from maverick.governed_actions import verify_lineage_file

    task = next(t for t in overhead.load_tasks() if t["shape"] == "actuation")
    governed, _ungoverned = _run_pair(task, governed_home)
    artifacts = governed["artifacts"]

    assert artifacts["lifecycle_audit_rows"] == 2
    assert artifacts["native_audit_rows"] == governed["tool_calls"]
    assert artifacts["authz_allowed"] == governed["tool_calls"]
    assert artifacts["authz_denied"] == 0
    # PREPARE + COMMIT for the single consequential action; the low-risk tools
    # are intentionally not traced.
    assert artifacts["lineage_receipts"] == 2
    assert artifacts["approvals"] == 1
    assert artifacts["budget_checks"] == governed["steps"]
    assert verify_lineage_file(1, governed_home / "lineage").startswith("VALID")


def test_the_analysis_shape_pays_for_no_approval_or_receipt(governed_home):
    task = next(t for t in overhead.load_tasks() if t["shape"] == "analysis")
    governed, _ungoverned = _run_pair(task, governed_home)
    assert governed["artifacts"]["lineage_receipts"] == 0
    assert governed["artifacts"]["approvals"] == 0
    assert governed["artifacts"]["native_audit_rows"] == 2


def test_the_screens_fire_on_the_documents_that_carry_the_material(governed_home):
    tasks = overhead.load_tasks()
    credential_task = next(t for t in tasks if t["embeds_credential"])
    injection_task = next(t for t in tasks if t["embeds_injection"])
    clean_task = next(
        t for t in tasks if not t["embeds_credential"] and not t["embeds_injection"]
    )

    with_credential, _ = _run_pair(credential_task, governed_home / "a")
    with_injection, _ = _run_pair(injection_task, governed_home / "b")
    clean, _ = _run_pair(clean_task, governed_home / "c")

    assert with_credential["artifacts"]["secrets_redacted_in_evidence"] > 0
    assert with_injection["injection_tripwires"] > 0
    assert clean["artifacts"]["secrets_redacted_in_evidence"] == 0
    assert clean["injection_tripwires"] == 0
    assert clean["artifacts"]["shield_screens"] == 1


# -- pure metric helpers ---------------------------------------------------

def _row(arm, *, seed=11, task_id="t1", wall_ns=1000, artifacts=None, **fields):
    row = {
        "task_id": task_id, "shape": "analysis", "seed": seed, "arm": arm,
        "steps": 3, "model_calls": 1, "tool_calls": 2, "input_tokens": 100,
        "output_tokens": 50, "dollars": 0.0, "answer_sha256": "a" * 64,
        "effect_sha256": "", "wall_ns": wall_ns,
        "artifacts": overhead._empty_artifacts(),
    }
    if arm == "governed":
        row["artifacts"].update(
            {"lifecycle_audit_rows": 2, "native_audit_rows": 2, "lineage_receipts": 2,
             "approvals": 1, "authz_allowed": 2, "budget_checks": 3, "shield_screens": 1,
             "injection_screens": 1, "secrets_redacted_in_evidence": 1}
        )
        row["injection_tripwires"] = 1
        row["observed_audit_rows"] = 5
        row["goal_id"] = 1
    if artifacts:
        row["artifacts"].update(artifacts)
    row.update(fields)
    return row


def _paired_rows(count=2):
    rows = []
    for index in range(count):
        task_id = f"t{index}"
        rows.append(_row("governed", task_id=task_id, wall_ns=11_000))
        rows.append(_row("ungoverned", task_id=task_id, wall_ns=1_000))
    return rows


def _zero_every_governed(key):
    """Aggregate metrics only fail when the artifact is missing run-wide."""
    def mutate(rows):
        for row in rows:
            if row["arm"] == "governed":
                row["artifacts"][key] = 0
    return mutate


def _clear_every_tripwire(rows):
    for row in rows:
        if row["arm"] == "governed":
            row["injection_tripwires"] = 0


def test_pair_rows_matches_by_seed_and_task_and_refuses_an_orphan():
    rows = _paired_rows()
    pairs = overhead.pair_rows(rows)
    assert len(pairs) == 2
    assert all(g["task_id"] == u["task_id"] and g["seed"] == u["seed"] for g, u in pairs)

    with pytest.raises(ValueError, match="same task instances"):
        overhead.pair_rows(rows[:-1])


def test_overhead_ratio_math():
    assert overhead.overhead_ratio(10, 4) == 2.5
    assert overhead.overhead_ratio(3, 3) == 1.0
    assert overhead.overhead_ratio(1, 3) == 0.333333
    assert overhead.overhead_ratio(5, 0) is None


def test_overhead_per_artifact_math():
    assert overhead.overhead_per_artifact(1200.0, 6) == 200.0
    assert overhead.overhead_per_artifact(1200.0, 0) is None


def test_projected_overhead_share_is_labelled_arithmetic():
    # 1 s of assumed model latency per step, three steps, 3 ms of overhead.
    assert overhead.projected_overhead_share(3000.0, 3, 1.0) == round(
        0.003 / 3.003, 6
    )
    assert overhead.projected_overhead_share(3000.0, 0, 1.0) is None
    assert overhead.projected_overhead_share(3000.0, 3, 0.0) is None
    # More assumed model latency makes governance a smaller share, never larger.
    assert overhead.projected_overhead_share(3000.0, 3, 10.0) < (
        overhead.projected_overhead_share(3000.0, 3, 1.0)
    )


def test_compute_overhead_metrics_scores_a_clean_paired_run():
    metrics = overhead.compute_overhead_metrics(_paired_rows())
    assert metrics["ok"] is True
    assert metrics["task_instances"] == 2
    assert metrics["answer_preservation_rate"] == 1.0
    assert metrics["effect_preservation_rate"] == 1.0
    for field in ("model_calls", "input_tokens", "output_tokens", "task_steps", "tool_calls"):
        assert metrics[field]["delta"] == 0
        assert metrics[field]["ratio"] == 1.0
    assert metrics["ungoverned_governance_artifacts"] == 0
    assert metrics["evidence_artifacts"]["total"] == 14
    assert metrics["evidence_artifacts"]["per_task"] == 7.0
    assert metrics["control_invocations"]["by_kind"]["budget_checks"] == 6
    assert metrics["audit_rows_counted"] == metrics["audit_rows_observed_on_chain"]
    assert metrics["wall"]["median_ratio"] == 11.0


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda rows: rows[0].update({"answer_sha256": "b" * 64}), "answer differs"),
        (lambda rows: rows[0].update({"effect_sha256": "b" * 64}), "effect differs"),
        (lambda rows: rows[0].update({"input_tokens": 999}), "token delta"),
        (lambda rows: rows[0].update({"steps": 9}), "step delta"),
        (lambda rows: rows[0].update({"model_calls": 9}), "extra model call"),
        (
            lambda rows: rows[1]["artifacts"].update({"lineage_receipts": 1}),
            "the ungoverned arm was governed",
        ),
        (
            lambda rows: rows[0]["artifacts"].update({"authz_denied": 1}),
            "a dispatch was denied",
        ),
        (_zero_every_governed("secrets_redacted_in_evidence"), "the redaction screen never fired"),
        (_zero_every_governed("lineage_receipts"), "no receipt persisted"),
        (_zero_every_governed("approvals"), "no approval recorded"),
        (_clear_every_tripwire, "no tripwire fired"),
        (lambda rows: rows[0].update({"observed_audit_rows": 1}), "rows never landed"),
    ],
)
def test_compute_overhead_metrics_fails_on_each_regression(mutate, reason):
    rows = _paired_rows()
    mutate(rows)
    assert overhead.compute_overhead_metrics(rows)["ok"] is False, reason


def test_metrics_split_overhead_by_task_shape():
    rows = _paired_rows()
    for row in rows:
        if row["task_id"] == "t1":
            row["shape"] = "actuation"
            if row["arm"] == "governed":
                row["wall_ns"] = 31_000
                row["artifacts"]["approvals"] = 3
    by_shape = overhead.compute_overhead_metrics(rows)["by_shape"]

    assert set(by_shape) == {"analysis", "actuation"}
    assert by_shape["analysis"]["instances"] == 1
    assert by_shape["actuation"]["instances"] == 1
    # The consequential shape must show the larger cost and the larger ledger.
    assert (
        by_shape["actuation"]["paired_overhead"]["median_us"]
        > by_shape["analysis"]["paired_overhead"]["median_us"]
    )
    assert (
        by_shape["actuation"]["evidence_artifacts_per_task"]
        > by_shape["analysis"]["evidence_artifacts_per_task"]
    )


def test_metrics_report_a_ratio_of_none_rather_than_inventing_a_denominator():
    rows = _paired_rows()
    for row in rows:
        row["tool_calls"] = 0
    metrics = overhead.compute_overhead_metrics(rows)
    assert metrics["tool_calls"]["ratio"] is None
    assert metrics["tool_calls"]["delta"] == 0


# -- CI gate ---------------------------------------------------------------

def _manifest_like(rows=None):
    rows = rows or _paired_rows()
    metrics = overhead.compute_overhead_metrics(rows)
    return {
        "results": {
            "task_definitions": 12,
            "governed_instances": 2,
            "ungoverned_instances": 2,
            "model_in_loop": False,
            "network_used": False,
            "audit": {"verified": True},
            "lineage": {"all_verified": True},
            "metrics": metrics,
        }
    }


def test_ci_gate_passes_a_clean_run_and_names_each_failure():
    assert overhead._ci_failures(_manifest_like()) == []

    dirty = _manifest_like()
    dirty["results"]["audit"]["verified"] = False
    dirty["results"]["lineage"]["all_verified"] = False
    dirty["results"]["network_used"] = True
    dirty["results"]["task_definitions"] = 11
    failures = overhead._ci_failures(dirty)
    assert "the signed audit chain did not verify in-run" in failures
    assert "a lineage receipt chain did not verify" in failures
    assert "the run claimed a model or network in the loop" in failures
    assert "task table is not the pinned 12 definitions" in failures


def test_ci_gate_catches_a_token_delta_and_a_governed_baseline():
    rows = _paired_rows()
    rows[0]["output_tokens"] = 999
    rows[1]["artifacts"]["approvals"] = 1
    failures = overhead._ci_failures(_manifest_like(rows))
    assert any("output_tokens differ" in failure for failure in failures)
    assert "the ungoverned arm produced governance artifacts" in failures


def test_ci_gate_never_asserts_a_timing():
    rows = _paired_rows()
    for row in rows:
        row["wall_ns"] = 10 ** 9 if row["arm"] == "governed" else 1
    assert overhead._ci_failures(_manifest_like(rows)) == []


def _lineage_rows():
    tasks = {task["shape"]: task for task in overhead.load_tasks()}
    return [
        {
            "arm": "governed", "task_id": tasks[shape]["id"], "shape": shape,
            "goal_id": goal_id, "artifacts": {"lineage_receipts": count},
        }
        for shape, goal_id, count in (("analysis", 1, 0), ("actuation", 2, 2))
    ]


def _persist_lineage_receipts(lineage_dir, goal_id, count):
    from maverick.governed_actions import record_tool_lineage

    for index in range(count):
        assert record_tool_lineage(
            goal_id, overhead.CONSEQUENTIAL_TOOL, {"receipt": index},
            phase="PREPARE" if index == 0 else "COMMIT", force=True, strict=True,
            store_dir=lineage_dir,
        )


@pytest.mark.parametrize("empty_analysis_file", [False, True])
def test_lineage_gate_accepts_intentional_analysis_absence_and_verified_actuation(
    tmp_path, empty_analysis_file,
):
    _persist_lineage_receipts(tmp_path, 2, 2)
    if empty_analysis_file:
        (tmp_path / "1.ndjson").write_text("", encoding="utf-8")

    assert overhead._lineage_evidence(_lineage_rows(), tmp_path) == {
        "chains_with_receipts": 1,
        "chains_verified": 1,
        "all_verified": True,
        "store": "temporary_run_directory",
    }


@pytest.mark.parametrize("failure", ["missing", "empty", "corrupt", "unavailable", 1, 3])
def test_lineage_gate_rejects_each_missing_or_invalid_actuation_chain(tmp_path, failure):
    rows = _lineage_rows()
    # Keep another actuation chain healthy so partial evidence cannot pass.
    healthy = copy.deepcopy(rows[1])
    healthy["goal_id"] = 3
    rows.append(healthy)
    _persist_lineage_receipts(tmp_path, 3, 2)
    path = tmp_path / "2.ndjson"
    if failure == "empty":
        path.write_text("", encoding="utf-8")
    elif failure == "corrupt":
        path.write_text("{broken", encoding="utf-8")
    elif failure == "unavailable":
        path.mkdir()
    elif isinstance(failure, int):
        _persist_lineage_receipts(tmp_path, 2, failure)

    result = overhead._lineage_evidence(rows, tmp_path)
    assert result["chains_with_receipts"] == 2
    assert result["chains_verified"] == 1
    assert result["all_verified"] is False


@pytest.mark.parametrize("failure", ["corrupt", "unavailable", 1, 2])
def test_lineage_gate_rejects_invalid_or_unexpected_analysis_evidence(tmp_path, failure):
    _persist_lineage_receipts(tmp_path, 2, 2)
    path = tmp_path / "1.ndjson"
    if failure == "corrupt":
        path.write_text("{broken", encoding="utf-8")
    elif failure == "unavailable":
        path.mkdir()
    else:
        _persist_lineage_receipts(tmp_path, 1, failure)

    assert overhead._lineage_evidence(_lineage_rows(), tmp_path)["all_verified"] is False


@pytest.mark.parametrize("observed_count", [0, 1, 3])
def test_lineage_gate_requires_observed_receipt_count_to_match_real_chain(
    tmp_path, observed_count,
):
    _persist_lineage_receipts(tmp_path, 2, 2)
    rows = _lineage_rows()
    rows[1]["artifacts"]["lineage_receipts"] = observed_count

    assert overhead._lineage_evidence(rows, tmp_path)["all_verified"] is False


def test_lineage_gate_cannot_relabel_a_missing_actuation_as_analysis(tmp_path):
    rows = _lineage_rows()
    rows[1]["shape"] = "analysis"
    rows[1]["artifacts"]["lineage_receipts"] = 0

    result = overhead._lineage_evidence(rows, tmp_path)
    assert result["chains_with_receipts"] == 1
    assert result["chains_verified"] == 0
    assert result["all_verified"] is False


def test_lineage_gate_cannot_relabel_unexpected_analysis_receipts_as_actuation(tmp_path):
    _persist_lineage_receipts(tmp_path, 1, 2)
    _persist_lineage_receipts(tmp_path, 2, 2)
    rows = _lineage_rows()
    rows[0]["shape"] = "actuation"
    rows[0]["artifacts"]["lineage_receipts"] = 2

    assert overhead._lineage_evidence(rows, tmp_path)["all_verified"] is False


# -- published artifacts ---------------------------------------------------

@pytest.fixture(scope="module")
def tracked_manifest():
    if not TRACKED_MANIFEST.is_file():
        pytest.skip("the tracked measured manifest has not been published yet")
    return json.loads(TRACKED_MANIFEST.read_text(encoding="utf-8"))


def test_the_tracked_report_is_the_deterministic_render_of_the_tracked_manifest(
    tracked_manifest,
):
    report = overhead.render_report(tracked_manifest)
    assert report == overhead.render_report(tracked_manifest)
    assert TRACKED_REPORT.read_text(encoding="utf-8") == report


def test_the_report_states_what_it_is_not(tracked_manifest):
    report = overhead.render_report(tracked_manifest)
    assert "MEASURED" in report
    assert "**not**" in report
    assert "capability benchmark" in report
    assert "stubbed" in report
    assert "never asserted" in report
    assert "Read the ratio carefully" in report
    assert "assumption, not a measurement" in report
    assert "not off-host custody" in report
    assert "Reproduce" in report


def test_the_report_publishes_the_parity_table_and_the_artifact_ledger(tracked_manifest):
    report = overhead.render_report(tracked_manifest)
    metrics = tracked_manifest["results"]["metrics"]
    assert "| Model calls |" in report
    assert "| Input tokens |" in report
    assert "| Task steps |" in report
    assert "`lineage_receipts`" in report
    assert "`approvals`" in report
    assert f"{metrics['evidence_artifacts']['total']:,}" in report


def test_tracked_validator_gates_report_source_and_clean_provenance(
    tracked_manifest, monkeypatch, tmp_path
):
    publishable = copy.deepcopy(tracked_manifest)
    publishable["results"]["git"]["dirty"] = False
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "report.md"
    key_path = tmp_path / "publisher.pub"
    manifest_path.write_text(json.dumps(publishable), encoding="utf-8")
    report_path.write_bytes(overhead.render_report(publishable).encode("utf-8"))
    key_path.write_text(
        str(publishable["signature"]["pubkey"]) + "\n", encoding="utf-8"
    )
    monkeypatch.setattr(
        overhead, "verify_manifest",
        lambda _manifest, *, trusted_pubkey_hex: (True, "unit-test anchor"),
    )
    monkeypatch.setattr(overhead, "_git_commit_is_ancestor", lambda _commit: True)

    def errors_for():
        return overhead.validate_tracked_artifacts(
            manifest_path=manifest_path,
            report_path=report_path,
            trusted_pubkey_path=key_path,
        )[1]

    # A faithful copy renders exactly; source digests may legitimately drift
    # between a publish and a later edit, so only the render is pinned here.
    assert "tracked report is not the deterministic manifest render" not in errors_for()

    report_path.write_bytes(b"tampered report\n")
    assert "tracked report is not the deterministic manifest render" in errors_for()

    publishable["results"]["source_files"]["runner"] = "00" * 32
    manifest_path.write_text(json.dumps(publishable), encoding="utf-8")
    assert "one or more source-file SHA-256 values differ" in errors_for()

    publishable["results"]["git"]["dirty"] = True
    manifest_path.write_text(json.dumps(publishable), encoding="utf-8")
    assert "published run was not measured from a clean source tree" in errors_for()

    publishable["results"]["git"]["dirty"] = False
    publishable["results"]["git"]["commit"] = "not-a-git-commit"
    manifest_path.write_text(json.dumps(publishable), encoding="utf-8")
    assert "measured source commit is not a full Git SHA-1" in errors_for()

    publishable["results"].pop("source_snapshot_policy")
    manifest_path.write_text(json.dumps(publishable), encoding="utf-8")
    assert "unsupported or missing source-snapshot policy" in errors_for()


def test_tracked_validator_rejects_malformed_manifest_containers(tmp_path, monkeypatch):
    manifest_path = tmp_path / "manifest.json"
    report_path = tmp_path / "report.md"
    key_path = tmp_path / "publisher.pub"
    key_path.write_text("ab" * 32 + "\n", encoding="utf-8")

    manifest_path.write_text("[]", encoding="utf-8")
    ok, errors = overhead.validate_tracked_artifacts(
        manifest_path=manifest_path, report_path=report_path, trusted_pubkey_path=key_path,
    )
    assert not ok
    assert errors == ["manifest root must be an object"]

    monkeypatch.setattr(
        overhead, "verify_manifest",
        lambda _manifest, *, trusted_pubkey_hex: (True, "unit-test anchor"),
    )
    manifest_path.write_text(json.dumps({"signature": [], "results": []}), encoding="utf-8")
    ok, errors = overhead.validate_tracked_artifacts(
        manifest_path=manifest_path, report_path=report_path, trusted_pubkey_path=key_path,
    )
    assert not ok
    assert "manifest signature must be an object" in errors
    assert "manifest results must be an object" in errors
    assert "manifest Git provenance must be an object" in errors


def test_tracked_validator_requires_a_well_formed_trusted_key(tmp_path):
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps({"results": {}}), encoding="utf-8")
    key_path = tmp_path / "publisher.pub"
    key_path.write_text("too-short\n", encoding="utf-8")
    ok, errors = overhead.validate_tracked_artifacts(
        manifest_path=manifest_path,
        report_path=tmp_path / "report.md",
        trusted_pubkey_path=key_path,
    )
    assert not ok
    assert "64 hex characters" in errors[0]

    key_path.write_text("z" * 64 + "\n", encoding="utf-8")
    ok, errors = overhead.validate_tracked_artifacts(
        manifest_path=manifest_path,
        report_path=tmp_path / "report.md",
        trusted_pubkey_path=key_path,
    )
    assert not ok
    assert "not hexadecimal" in errors[0]


def test_verify_manifest_requires_an_explicit_trusted_key(tracked_manifest):
    ok, reason = overhead.verify_manifest(tracked_manifest, trusted_pubkey_hex="")
    assert not ok
    assert "explicit trusted public key" in reason

    tampered = copy.deepcopy(tracked_manifest)
    tampered["results"]["metrics"]["evidence_artifacts"]["total"] = 999_999
    ok, _reason = overhead.verify_manifest(
        tampered, trusted_pubkey_hex=str(tracked_manifest["signature"]["pubkey"])
    )
    assert not ok


def test_source_digests_are_checkout_line_ending_independent(tmp_path):
    source = tmp_path / "sample.py"
    source.write_bytes(b"value = 1\nprint(value)\n")
    lf_source = overhead._sha256(source)
    lf_inputs = overhead._benchmark_inputs_digest([source])

    source.write_bytes(b"value = 1\r\nprint(value)\r\n")
    assert overhead._sha256(source) == lf_source
    assert overhead._benchmark_inputs_digest([source]) == lf_inputs

    source.write_bytes(b"value = 2\r\nprint(value)\r\n")
    assert overhead._sha256(source) != lf_source
    assert overhead._benchmark_inputs_digest([source]) != lf_inputs

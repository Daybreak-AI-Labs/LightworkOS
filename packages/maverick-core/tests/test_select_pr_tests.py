"""scripts/select_pr_tests.py: which tests a pull request's changed files run.

The merge queue's commit and pushes to main run the whole suite; on a pull
request the floor-interpreter ``test`` legs run the selection this script
makes from the changed files. These tests pin the rules (anything shared means
the full suite), the git range it diffs (the pull request's merge base, never
a two-dot diff against a base that moved), the fallback (a git failure selects
everything) and the wiring in .github/workflows/ci.yml and
.github/actions/test-shard/action.yml.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
TEST_SHARD_ACTION = REPO_ROOT / ".github" / "actions" / "test-shard" / "action.yml"


def _load():
    path = REPO_ROOT / "scripts" / "select_pr_tests.py"
    spec = importlib.util.spec_from_file_location("select_pr_tests", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


select_pr_tests = _load()

# A miniature of the repository: the kernel, two packages, an app, docs and
# deployment files, and tests that name them the way the real suite does.
TREE = {
    "conftest.py": "",
    "packages/maverick-core/maverick/agent.py": "class Agent: ...\n",
    "packages/maverick-core/tests/test_agent.py": "from maverick.agent import Agent\n",
    "packages/maverick-core/tests/test_claims_docs.py": (
        'text = _read("docs/OPEN_ITEMS.md")\n'
        'readme = _read("README.md")\n'
        'helm = REPO_ROOT / "deploy" / "helm" / "values.yaml"\n'
    ),
    "packages/maverick-core/tests/test_server_wiring.py": "import maverick_channels\n",
    "packages/maverick-channels/maverick_channels/irc.py": "def connect(): ...\n",
    "packages/maverick-channels/tests/test_irc.py": "from maverick_channels import irc\n",
    "packages/maverick-dashboard/tests/test_app.py": "from maverick_dashboard.app import app\n",
    "apps/installer-cli/maverick_installer/wizard.py": "",
    "apps/installer-cli/tests/test_wizard.py": "from maverick_installer import wizard\n",
    "docs/OPEN_ITEMS.md": "# Open items\n",
    "deploy/helm/values.yaml": "replicas: 1\n",
    "sdks/plugin-ts/src/index.ts": "export {};\n",
    "README.md": "# Lightwork\n",
}


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    for rel, content in TREE.items():
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path


def _select(root: Path, *changed: str) -> dict:
    return select_pr_tests.select(list(changed), root)


def _jobs(**needed: bool) -> dict[str, bool]:
    """The jobs map with every gated job False except those named."""
    return {job: needed.get(job, False) for job in select_pr_tests.JOB_PREFIXES}


@pytest.mark.parametrize(
    "changed",
    [
        "packages/maverick-core/maverick/agent.py",
        "packages/maverick-core/maverick/tools/new_tool.py",
        "conftest.py",
        "packages/maverick-dashboard/tests/conftest.py",
        "pyproject.toml",
        "release-cohort.toml",
        "requirements/ci.txt",
        "test_support/provider_env.py",
        ".github/workflows/ci.yml",
        ".github/actions/test-shard/action.yml",
        "scripts/select_pr_tests.py",
        "benchmarks/harness_overhead/manifest.json",
    ],
)
def test_shared_code_selects_the_full_suite(tree, changed):
    """The kernel every package imports, shared fixtures, the pinned
    environment and the workflows and scripts the suite reads: one such file
    in a change set means everything runs, whatever else changed."""
    result = _select(tree, "docs/OPEN_ITEMS.md", changed)
    assert result["mode"] == "full"
    assert result["paths"] == []
    assert changed in result["reasons"][0]


def test_package_change_selects_its_tests_and_every_test_naming_it(tree):
    result = _select(tree, "packages/maverick-channels/maverick_channels/irc.py")
    assert result["mode"] == "paths"
    assert result["paths"] == [
        "packages/maverick-channels/tests/test_irc.py",
        "packages/maverick-core/tests/test_server_wiring.py",
    ]
    assert result["reasons"] == [
        "packages/maverick-channels/maverick_channels/irc.py: "
        "packages/maverick-channels/tests plus 1 files naming maverick_channels"
    ]


def test_installer_app_counts_as_a_package(tree):
    result = _select(tree, "apps/installer-cli/maverick_installer/wizard.py")
    assert result["paths"] == ["apps/installer-cli/tests/test_wizard.py"]


def test_changed_test_file_is_selected_itself(tree):
    result = _select(tree, "packages/maverick-dashboard/tests/test_app.py")
    assert result == {
        "mode": "paths",
        "paths": ["packages/maverick-dashboard/tests/test_app.py"],
        "reasons": ["packages/maverick-dashboard/tests/test_app.py changed"],
        "jobs": _jobs(docker=True, audit=True, postgres=True, **{"release-cohort": True}),
    }


def test_deleted_test_file_selects_nothing_to_run(tree):
    assert _select(tree, "packages/maverick-dashboard/tests/test_gone.py")["mode"] == "none"


def test_test_only_changes_do_not_scan_all_test_contents(tree, monkeypatch):
    def unexpected_scan(root):
        raise AssertionError("test-only selection must not scan the entire test tree")

    monkeypatch.setattr(select_pr_tests, "test_files", unexpected_scan)
    result = _select(tree, "packages/maverick-dashboard/tests/test_app.py")
    assert result["mode"] == "paths"
    assert result["paths"] == ["packages/maverick-dashboard/tests/test_app.py"]


def test_other_files_select_the_tests_that_name_them(tree):
    claims = ["packages/maverick-core/tests/test_claims_docs.py"]
    by_path = _select(tree, "docs/OPEN_ITEMS.md")
    assert by_path["paths"] == claims
    assert by_path["reasons"] == ["docs/OPEN_ITEMS.md: 1 files name it"]
    # ``REPO_ROOT / "deploy" / "helm"`` names the directory, not the file.
    assert _select(tree, "deploy/helm/values.yaml")["paths"] == claims
    assert _select(tree, "README.md")["paths"] == claims
    unnamed = _select(tree, "sdks/plugin-ts/src/index.ts")
    assert unnamed == {
        "mode": "none",
        "paths": [],
        "reasons": ["sdks/plugin-ts/src/index.ts: 0 files name it"],
        "jobs": _jobs(audit=True),  # the SDK is a dependency surface the audit scans
    }


def test_selection_is_the_union_over_the_change_set(tree):
    result = _select(
        tree, "docs/OPEN_ITEMS.md", "packages/maverick-channels/maverick_channels/irc.py"
    )
    assert result["paths"] == [
        "packages/maverick-channels/tests/test_irc.py",
        "packages/maverick-core/tests/test_claims_docs.py",
        "packages/maverick-core/tests/test_server_wiring.py",
    ]


def test_changed_paths_are_normalised(tree):
    assert _select(tree, "docs\\OPEN_ITEMS.md", "", "  ") == _select(tree, "docs/OPEN_ITEMS.md")
    assert _select(tree) == {"mode": "none", "paths": [], "reasons": ["no files changed"], "jobs": _jobs()}


def test_test_files_are_the_pytest_roots_minus_virtualenvs(tree):
    (tree / ".venv" / "lib" / "test_installed.py").parent.mkdir(parents=True)
    (tree / ".venv" / "lib" / "test_installed.py").write_text("", encoding="utf-8")
    (tree / "packages" / ".venv" / "test_nested.py").parent.mkdir(parents=True)
    (tree / "packages" / ".venv" / "test_nested.py").write_text("", encoding="utf-8")
    (tree / "docs" / "test_not_collected.py").write_text("", encoding="utf-8")
    found = [p.relative_to(tree).as_posix() for p in select_pr_tests.test_files(tree)]
    assert found == sorted(
        rel for rel in TREE if re.search(r"(^|/)test_[^/]+\.py$", rel)
    )


# --- the heavier jobs ------------------------------------------------------


def test_jobs_follow_the_changed_paths(tree):
    """Each gated ci.yml job runs on a pull request only when a changed file is
    under its inputs; a full-suite change runs every job."""
    assert _select(tree, "docs/OPEN_ITEMS.md")["jobs"] == _jobs()
    assert _select(tree, "deploy/helm/values.yaml")["jobs"] == _jobs(audit=True)
    assert _select(tree, "packages/maverick-channels/maverick_channels/irc.py")["jobs"] == _jobs(
        docker=True, audit=True, **{"release-cohort": True},
    )
    assert _select(tree, "packages/maverick-core/maverick/agent.py")["jobs"] == dict.fromkeys(
        select_pr_tests.JOB_PREFIXES, True,
    )
    assert _select(tree, "apps/installer-cli/maverick_installer/wizard.py")["jobs"] == _jobs(
        docker=True, audit=True, **{"release-cohort": True},
    )


def test_every_gated_job_exists_and_the_ungated_ones_stay_ungated():
    jobs = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    for job in select_pr_tests.JOB_PREFIXES:
        assert job in jobs, job
    for job in ("lint", "test-window", "posture", "windows-process-containment-window"):
        assert "needs" not in jobs[job], job


def test_gated_jobs_skip_only_when_the_selection_says_so():
    """A gated job needs select-tests and runs unless the jobs map carries the
    literal '"<job>": false': a missing map or entry (the selection failed, or
    an event the script did not see) runs everything, and `!cancelled()` keeps
    a failed selection from skipping the job (a skipped job would satisfy the
    required check). The gate is a substring test on purpose: in the
    expression language a missing map entry is null, and null compares equal
    to false, so `fromJSON(map)[job] != false` skipped every gated job on the
    first push to main after the gate landed."""
    jobs = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    for job in select_pr_tests.JOB_PREFIXES:
        if job == "windows-process-containment":
            continue
        assert jobs[job]["needs"] == "select-tests", job
        assert jobs[job]["if"] == (
            "${{ !cancelled() && !contains(needs.select-tests.outputs.jobs, "
            f"'\"{job}\": false') }}}}"
        ), job
    # The Windows job is a named matrix: a skipped job would not expand its
    # matrix and the required context would vanish, so its steps are gated.
    windows = jobs["windows-process-containment"]
    assert windows["needs"] == "select-tests" and windows["if"] == "${{ !cancelled() }}"
    gate = "contains(needs.select-tests.outputs.jobs, '\"windows-process-containment\": false')"
    assert windows["steps"][0]["name"] == "Not needed on this pull request"
    assert windows["steps"][0]["if"] == gate
    for step in windows["steps"][1:]:
        assert step["if"] == f"${{{{ !{gate} }}}}", step.get("name") or step.get("uses")


def test_the_gate_literal_is_how_the_script_writes_the_map():
    """The workflow looks for '"<job>": false' verbatim, so the map must keep
    json.dumps' default separators and name every gated job."""
    written = json.dumps(_jobs(docker=True))
    assert '"docker": false' not in written
    assert '"audit": false' in written
    assert set(_jobs()) == set(select_pr_tests.JOB_PREFIXES)


# --- the git range ---------------------------------------------------------


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        [
            "git", "-C", str(root),
            "-c", "user.name=t", "-c", "user.email=t@example.invalid",
            "-c", "commit.gpgsign=false",
            *args,
        ],
        check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def repo(tree: Path) -> Path:
    """``main`` and a ``feature`` branch that diverged from it: the feature
    edits a doc and moves the README; main then changes the kernel."""
    _git(tree, "init", "-q")
    _git(tree, "checkout", "-q", "-b", "main")
    _git(tree, "add", "-A")
    _git(tree, "commit", "-q", "-m", "base")
    _git(tree, "checkout", "-q", "-b", "feature")
    (tree / "docs" / "OPEN_ITEMS.md").write_text("# Open items\n\n- one\n", encoding="utf-8")
    _git(tree, "mv", "README.md", "READ_ME.md")
    _git(tree, "commit", "-q", "-a", "-m", "feature")
    _git(tree, "checkout", "-q", "main")
    (tree / "packages/maverick-core/maverick/agent.py").write_text(
        "class Agent:\n    pass\n", encoding="utf-8"
    )
    _git(tree, "commit", "-q", "-a", "-m", "main moved on")
    return tree


def test_git_range_is_the_merge_base_to_head_change_set(repo):
    changed, merge_base = select_pr_tests.changed_files_from_git("main", "feature", repo)
    assert merge_base == _git(repo, "rev-parse", "main~1")
    # main's own later commit (the kernel) is not part of the pull request, so
    # it must not drag in the full suite; a moved file is listed under both
    # names so tests naming either are selected.
    assert sorted(changed) == sorted(["README.md", "READ_ME.md", "docs/OPEN_ITEMS.md"])
    assert _select(repo, *changed)["paths"] == ["packages/maverick-core/tests/test_claims_docs.py"]


def test_git_range_preserves_non_ascii_paths_for_full_suite_selection(repo):
    _git(repo, "checkout", "-q", "feature")
    path = repo / "packages/maverick-core/maverick/caf\u00e9.py"
    path.write_text("value = 1\n", encoding="utf-8")
    _git(repo, "add", str(path.relative_to(repo)))
    _git(repo, "commit", "-q", "-m", "add non-ascii kernel path")

    changed, _merge_base = select_pr_tests.changed_files_from_git("main", "feature", repo)

    assert "packages/maverick-core/maverick/caf\u00e9.py" in changed
    assert _select(repo, *changed)["mode"] == "full"


@pytest.mark.skipif(sys.platform == "win32", reason="Windows does not support newline in filenames")
def test_git_ambiguous_path_falls_back_to_full_suite(repo):
    _git(repo, "checkout", "-q", "feature")
    path = repo / "docs" / "new\nline.md"
    path.write_text("# documentation\n", encoding="utf-8")
    _git(repo, "add", str(path.relative_to(repo)))
    _git(repo, "commit", "-q", "-m", "add unusual path")

    changed, reason = select_pr_tests.changed_files_from_git("main", "feature", repo)

    assert changed is None
    assert "full suite" in reason


def test_git_undecodable_path_falls_back_to_full_suite(repo, monkeypatch):
    def undecodable(*args, **kwargs):
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid byte")

    monkeypatch.setattr(select_pr_tests.subprocess, "run", undecodable)
    changed, reason = select_pr_tests.changed_files_from_git("main", "feature", repo)

    assert changed is None
    assert "could not diff" in reason


def test_git_failure_selects_the_full_suite(repo):
    changed, reason = select_pr_tests.changed_files_from_git("main", "no-such-branch", repo)
    assert changed is None
    assert "no-such-branch" in reason
    # Refs reach git as arguments, never as options.
    assert select_pr_tests.changed_files_from_git("main", "--output=x", repo) == (
        None, "refusing to pass '--output=x' to git"
    )


def test_cli_writes_the_selection_and_the_workflow_outputs(repo, tmp_path, capsys):
    out = tmp_path / "out"
    out.mkdir()
    github_output = out / "github_output"
    github_output.write_text("earlier=1\n", encoding="utf-8")
    rc = select_pr_tests.main([
        "--git", "main", "feature", "--root", str(repo),
        "--output", str(out / "selection.json"), "--github-output", str(github_output),
    ])
    assert rc == 0
    selection = json.loads((out / "selection.json").read_text(encoding="utf-8"))
    assert selection["mode"] == "paths"
    assert selection["paths"] == ["packages/maverick-core/tests/test_claims_docs.py"]
    written = github_output.read_text(encoding="utf-8")
    assert written.startswith(
        'earlier=1\nmode=paths\npaths=["packages/maverick-core/tests/test_claims_docs.py"]\njobs={'
    )
    assert json.loads(written.split("jobs=", 1)[1]) == _jobs()
    stdout = capsys.readouterr().out
    assert "3 files changed since merge base" in stdout
    assert "mode=paths paths=1" in stdout

    rc = select_pr_tests.main([
        "--git", "main", "no-such-branch", "--root", str(repo),
        "--github-output", str(github_output),
    ])
    assert rc == 0
    tail = github_output.read_text(encoding="utf-8").split("earlier=1\n", 1)[1]
    assert "\nmode=full\npaths=[]\njobs=" in tail
    assert json.loads(tail.rsplit("jobs=", 1)[1]) == dict.fromkeys(select_pr_tests.JOB_PREFIXES, True)


def test_cli_full_selects_everything_and_names_every_gated_job(tmp_path, capsys):
    """The non-pull-request events: the whole suite and a complete jobs map."""
    github_output = tmp_path / "github_output"
    rc = select_pr_tests.main([
        "--full", "push: the test legs run the whole suite", "--github-output", str(github_output),
    ])
    assert rc == 0
    written = github_output.read_text(encoding="utf-8")
    assert written.startswith("mode=full\npaths=[]\njobs=")
    assert json.loads(written.split("jobs=", 1)[1]) == dict.fromkeys(select_pr_tests.JOB_PREFIXES, True)
    stdout = capsys.readouterr().out
    assert "mode=full paths=0 jobs skipped=none" in stdout
    assert "push: the test legs run the whole suite" in stdout


# --- the real repository ---------------------------------------------------


def test_real_repository_rules_hold():
    assert select_pr_tests.select(["packages/maverick-core/maverick/agent.py"])["mode"] == "full"
    docs = select_pr_tests.select(["docs/OPEN_ITEMS.md"])
    assert docs["mode"] == "paths"
    assert "packages/maverick-core/tests/test_claims_docs.py" in docs["paths"]
    channels = select_pr_tests.select(["packages/maverick-channels/maverick_channels/irc.py"])
    own = sorted(
        p.relative_to(REPO_ROOT).as_posix()
        for p in (REPO_ROOT / "packages" / "maverick-channels" / "tests").glob("test_*.py")
    )
    assert own and set(own) <= set(channels["paths"])
    assert any(p.startswith("packages/maverick-core/tests/") for p in channels["paths"])
    this = Path(__file__).relative_to(REPO_ROOT).as_posix()
    everything = {p.relative_to(REPO_ROOT).as_posix() for p in select_pr_tests.test_files()}
    assert this in everything
    assert len(everything) > 1000
    assert all(p.startswith(("packages/", "apps/", "benchmarks/")) for p in everything)


def test_a_slice_holding_none_of_the_selected_files_exits_5():
    """One selected file deals into slice 1, so slice 2 collects nothing and
    pytest exits 5 ("no tests ran"): the status the action forgives in paths
    mode and nowhere else."""
    proc = subprocess.run(
        [
            sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
            "--shard", "2/4", "-m", "not heavy_concurrency", str(Path(__file__)),
        ],
        cwd=REPO_ROOT, capture_output=True, text=True, timeout=300,
    )
    assert proc.returncode == 5, proc.stdout + proc.stderr


# --- the wiring ------------------------------------------------------------


def test_ci_pull_request_legs_take_the_selection_and_the_queue_runs_everything():
    jobs = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))["jobs"]

    select = jobs["select-tests"]
    assert set(select["outputs"]) == {"mode", "paths", "jobs"}
    checkout, choose = select["steps"]
    assert checkout["uses"].startswith("actions/checkout@")
    # The merge base is not in a shallow clone.
    assert checkout["with"]["fetch-depth"] == 0
    assert checkout["with"]["persist-credentials"] is False
    assert choose["id"] == "select"
    assert choose["env"]["EVENT_NAME"] == "${{ github.event_name }}"
    assert choose["env"]["BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert choose["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    run = choose["run"]
    assert 'if [ "$EVENT_NAME" != "pull_request" ]; then' in run
    # Every other event goes through the script too, so the jobs map names
    # every gated job (a hand-written `jobs={}` skipped them all on main).
    assert re.search(r'python3 scripts/select_pr_tests\.py \\\n\s+--full "\$EVENT_NAME: ', run)
    assert "jobs=" not in run
    assert 'python3 scripts/select_pr_tests.py --git "$BASE_SHA" "$HEAD_SHA"' in run
    assert run.count('--github-output "$GITHUB_OUTPUT"') == 2

    test = jobs["test"]
    assert test["needs"] == "select-tests"
    # A failed selection degrades to the full suite, never to skipped legs: a
    # skipped job still satisfies a required check.
    assert test["if"] == "${{ !cancelled() }}"
    shard = test["steps"][-1]
    assert shard["uses"] == "./.github/actions/test-shard"
    assert shard["with"]["mode"] == "${{ needs.select-tests.outputs.mode }}"
    assert shard["with"]["paths"] == "${{ needs.select-tests.outputs.paths }}"

    # The rest of the window and the posture run only where the commit lands
    # and always run everything: no selection reaches them.
    window = jobs["test-window"]
    assert "needs" not in window
    window_shard = window["steps"][-1]
    assert window_shard["uses"] == "./.github/actions/test-shard"
    assert set(window_shard["with"]) == {"python-version", "shard"}
    assert all(
        step.get("uses") != "./.github/actions/test-shard" for step in jobs["posture"]["steps"]
    )


def test_test_shard_action_runs_only_the_selected_paths_in_paths_mode():
    action = yaml.safe_load(TEST_SHARD_ACTION.read_text(encoding="utf-8"))
    inputs = action["inputs"]
    assert inputs["mode"]["required"] is False and inputs["mode"]["default"] == "full"
    assert inputs["paths"]["required"] is False and inputs["paths"]["default"] == "[]"

    steps = action["runs"]["steps"]
    assert steps[0]["name"] == "Nothing to run"
    assert steps[0]["if"] == "inputs.mode == 'none'"
    for step in steps[1:-1]:
        assert step["if"] == "inputs.mode != 'none'", step.get("name") or step.get("uses")
    assert steps[-1]["if"] == "always()"

    test_step = next(s for s in steps if s.get("name") == "Test (bounded, with diagnostics)")
    assert test_step["env"]["SELECT_MODE"] == "${{ inputs.mode }}"
    assert test_step["env"]["SELECT_PATHS"] == "${{ inputs.paths }}"
    run = test_step["run"]
    # An empty mode (the select-tests job failed) is the full suite.
    assert 'case "${SELECT_MODE:-full}" in' in run
    assert run.index("set -o pipefail") < run.index('case "${SELECT_MODE') < run.index("python -m pytest")
    # Both phases take the selected targets; only paths mode forgives a slice
    # that collected nothing.
    assert run.count('"${targets[@]}" \\') == 2
    assert 'if [ "$SELECT_MODE" = paths ] && [ "$status" -eq 5 ]; then status=0; fi' in run
    assert '[ "${serial:-0}" -ne 5 ]' in run

    # The JSON array becomes one target per line, and an empty array no lines
    # (not one empty target).
    one_liner = re.search(r"python -c '([^']+)'", run).group(1)
    for paths, expected in (([], ""), (["a/test_a.py", "b/test_b.py"], "a/test_a.py\nb/test_b.py\n")):
        proc = subprocess.run(
            [sys.executable, "-c", one_liner],
            env={"SELECT_PATHS": json.dumps(paths), "PATH": "/usr/bin:/bin"},
            capture_output=True, text=True, check=True,
        )
        assert proc.stdout == expected


def test_contributing_describes_the_pull_request_selection():
    text = (REPO_ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "scripts/select_pr_tests.py" in text
    assert "`--shard N/4`" in text
    assert "`--shard N/3`" not in text

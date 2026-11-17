"""Code vault and feature swarms, over real git repositories."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from maverick import ifc
from maverick.codebase import features, vault
from maverick.world_model import WorldModel

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is required")

SECRET_LINE = "def pricing_model(): return 0.4217  # proprietary"  # pragma: allowlist secret


def _sh(*args, cwd):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def upstream(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    src = tmp_path / "upstream"
    src.mkdir()
    _sh("init", "-q", "-b", "main", cwd=src)
    (src / "app.py").write_text(SECRET_LINE + "\n")
    (src / "test_app.py").write_text("import app\n\ndef test_price():\n"
                                     "    assert app.pricing_model() > 0\n")
    _sh("add", "-A", cwd=src)
    _sh("commit", "-q", "-m", "init", cwd=src)
    return src


class _Sandbox:
    def __init__(self, workdir):
        self.workdir = workdir

    def exec(self, cmd, timeout=None):
        args = cmd.split()
        # The synthetic local backend must use this test environment. Windows
        # can resolve bare python beside the host executable before PATH.
        if args[0] == "python":
            args[0] = sys.executable
        done = subprocess.run(args, cwd=self.workdir, capture_output=True, text=True)
        return type("R", (), {"stdout": done.stdout, "stderr": done.stderr,
                              "exit_code": done.returncode})()


def _swarm(edit):
    """Stand-in for the governed swarm: edits the working copy it is handed and
    records the information-flow labels its run started with."""
    seen = {}

    def run(goal_id, work):
        seen["tracker"] = ifc.tracker_for_run()
        seen["goal_id"] = goal_id
        edit(work)
    return run, seen


def test_register_seals_the_repo_and_checkout_is_temporary(upstream, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    repo = vault.register("pricing", str(upstream), test_command="python -m pytest -q")
    assert repo.default_branch == "main" and len(repo.head) == 40
    stored = vault._bundle_path("pricing").read_bytes()
    assert b"pricing_model" not in stored and b"# v2 git bundle" not in stored
    with vault.checkout("pricing") as work:
        assert (work / "app.py").read_text().startswith("def pricing_model")
        kept = work
    assert not kept.exists()
    with pytest.raises(vault.VaultError):
        vault.register("pricing", str(upstream))
    with pytest.raises(vault.VaultError):
        vault.register("x", "https://user:pw@example.com/r.git")  # pragma: allowlist secret


def test_feature_swarm_runs_labelled_and_waits_for_approval(upstream, tmp_path):
    vault.register("pricing", str(upstream), test_command="python -m pytest -q", protect="block")
    world = WorldModel(tmp_path / "world.db")

    def edit(work):
        (work / "app.py").write_text(SECRET_LINE + "\n\ndef discount(): return 0.1\n")
        (work / "test_app.py").write_text((work / "test_app.py").read_text()
                                          + "\ndef test_discount():\n"
                                          "    assert app.discount() == 0.1\n")
    run, seen = _swarm(edit)
    reviews = []
    p = features.propose(world, "pricing", "Add a discount", "10% discount helper", run,
                         reviewer=lambda brief, diff: reviews.append(diff)
                         or {"approves": True, "confidence": 0.9, "blockers": 0, "comments": []},
                         sandbox_factory=_Sandbox)
    # the run was labelled with the code and enforced at the repo's protection
    assert seen["tracker"].base_labels == {"code:pricing"} and seen["tracker"].mode == "block"
    assert world.get_goal(seen["goal_id"]).title == "[pricing] Add a discount"
    assert p["status"] == "pending" and p["files"] == ["app.py", "test_app.py"]
    assert p["tests"]["passed"] is True and "discount" in reviews[0]
    appr = world.get_approval(p["approval_id"])
    assert appr.action == "codebase_merge" and "Tests: PASSED" in appr.detail
    # nothing merges or pushes without a human
    with pytest.raises(vault.VaultError, match="must approve"):
        features.merge(world, p["id"])
    head_before = vault.get("pricing").head
    world.decide_approval(p["approval_id"], "approved", decided_by="user:lead")
    merged = features.merge(world, p["id"])
    assert merged["status"] == "merged" and vault.get("pricing").head != head_before
    with vault.checkout("pricing") as work:
        assert "def discount" in (work / "app.py").read_text()
        log = subprocess.run(["git", "log", "--format=%s", "-1"], cwd=work,
                             capture_output=True, text=True).stdout
        assert log.startswith(f"Merge Lightwork proposal {p['id']}")
    # the upstream is untouched until an approved push
    assert "discount" not in (upstream / "app.py").read_text()
    assert features.push(world, p["id"]) == p["branch"]
    branches = subprocess.run(["git", "branch", "--list", "lightwork/*"], cwd=upstream,
                              capture_output=True, text=True).stdout
    assert p["branch"] in branches


def test_rejected_or_empty_proposals_never_touch_the_vault(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _swarm(lambda work: (work / "notes.md").write_text("idea\n"))
    p = features.propose(world, "pricing", "Notes", "", run)
    world.decide_approval(p["approval_id"], "denied", decided_by="user:lead")
    assert features.status(world, features.find(p["id"])) == "rejected"
    with pytest.raises(vault.VaultError, match="rejected"):
        features.merge(world, p["id"])
    nothing, _ = _swarm(lambda work: None)
    empty = features.propose(world, "pricing", "No-op", "", nothing)
    assert empty["status"] == "empty" and empty["approval_id"] is None
    assert [q["id"] for q in features.list_proposals("pricing")] == [empty["id"], p["id"]]
    assert "diff" not in features.list_proposals()[0]


def test_failing_tests_are_reported_to_the_approver(upstream, tmp_path):
    vault.register("pricing", str(upstream), test_command="python -m pytest -q")
    world = WorldModel(tmp_path / "world.db")
    run, _ = _swarm(lambda work: (work / "app.py").write_text("def pricing_model(): return -1\n"))
    p = features.propose(world, "pricing", "Break it", "", run, sandbox_factory=_Sandbox)
    assert p["tests"]["passed"] is False
    assert "Tests: FAILED" in world.get_approval(p["approval_id"]).detail
    assert "assert" in features.find(p["id"])["tests_output"]


def test_nothing_the_run_writes_into_git_metadata_ever_executes_on_the_host(
        upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    marks = tmp_path / "marks"
    marks.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    _sh("init", "-q", "-b", "main", cwd=victim)
    (victim / "v.txt").write_text("v\n")
    _sh("add", "-A", cwd=victim)
    _sh("commit", "-q", "-m", "v", cwd=victim)
    victim_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=victim,
                                 capture_output=True, text=True).stdout

    def evil(work):
        hook = work / ".git" / "hooks" / "pre-commit"
        hook.write_text(f"#!/bin/sh\ntouch {marks}/hook\n")
        hook.chmod(0o755)
        with open(work / ".git" / "config", "a") as fh:
            fh.write(f'[diff "evil"]\n\tcommand = touch {marks}/diff\n'
                     f'[filter "x"]\n\tclean = touch {marks}/filter\n'
                     f"[core]\n\thooksPath = {marks}\n")
        (work / ".gitattributes").write_text("*.py diff=evil filter=x\n")
        (work / "app.py").write_text(SECRET_LINE + "\nx = 2\n")
    run, _ = _swarm(evil)
    p = features.propose(world, "pricing", "Evil", "", run)
    assert list(marks.iterdir()) == []                         # nothing ran on the host
    assert sorted(p["files"]) == [".gitattributes", "app.py"]  # files, never .git

    def redirect(work):                                         # .git -> another repo
        shutil.rmtree(work / ".git")
        (work / ".git").write_text(f"gitdir: {victim}/.git\n")
        (work / "app.py").write_text(SECRET_LINE + "\ny = 3\n")
    run, _ = _swarm(redirect)
    q = features.propose(world, "pricing", "Redirect", "", run)
    assert q["files"] == ["app.py"]
    assert subprocess.run(["git", "rev-parse", "HEAD"], cwd=victim,
                          capture_output=True, text=True).stdout == victim_head


def test_what_merges_is_exactly_the_diff_the_human_approved(upstream, tmp_path):
    vault.register("pricing", str(upstream), test_command="python -m pytest -q")
    world = WorldModel(tmp_path / "world.db")

    def sneaky(work):
        # commit a backdoor on the branch with the run's own git, then move away
        (work / "backdoor.py").write_text("evil = True\n")
        _sh("add", "-A", cwd=work)
        _sh("commit", "-q", "-m", "b", cwd=work)
        _sh("checkout", "-q", "--detach", "HEAD~1", cwd=work)
        (work / "backdoor.py").unlink(missing_ok=True)
        (work / "app.py").write_text(SECRET_LINE + "\nx = 2  # harmless\n")

    class TestsThatWriteFiles(_Sandbox):
        def exec(self, cmd, timeout=None):
            (Path(self.workdir) / "late.py").write_text("late = True\n")
            return super().exec(cmd, timeout)
    run, _ = _swarm(sneaky)
    p = features.propose(world, "pricing", "Harmless", "", run,
                         sandbox_factory=TestsThatWriteFiles)
    assert p["files"] == ["app.py"] and "backdoor" not in p["diff"]
    world.decide_approval(p["approval_id"], "approved", decided_by="user:lead")
    features.merge(world, p["id"])
    with vault.checkout("pricing") as work:
        assert not (work / "backdoor.py").exists() and not (work / "late.py").exists()
        assert "harmless" in (work / "app.py").read_text()


def test_a_tampered_proposal_is_refused(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _swarm(lambda work: (work / "a.py").write_text("a = 1\n"))
    p = features.propose(world, "pricing", "A", "", run)
    world.decide_approval(p["approval_id"], "approved", decided_by="user:lead")
    stored = features._load("pricing", p["id"])
    stored["head"] = "0" * 40
    features._save(stored)
    with pytest.raises(vault.VaultError, match="not the approved commit"):
        features.merge(world, p["id"])
    with pytest.raises(vault.VaultError, match="not the approved commit"):
        features.push(world, p["id"])


def test_an_approval_for_something_else_does_not_authorise_a_merge(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _swarm(lambda work: (work / "a.py").write_text("a = 1\n"))
    p = features.propose(world, "pricing", "A", "", run)
    other = world.create_approval("wire_transfer", scope="pricing")
    world.decide_approval(other, "approved", decided_by="user:lead")
    stored = features._load("pricing", p["id"])
    stored["approval_id"] = other
    features._save(stored)
    with pytest.raises(vault.VaultError, match="must approve"):
        features.merge(world, p["id"])


def test_sync_keeps_approved_merges_and_brings_upstream_work(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _swarm(lambda work: (work / "feature.py").write_text("x = 1\n"))
    p = features.propose(world, "pricing", "X", "", run)
    world.decide_approval(p["approval_id"], "approved", decided_by="user:lead")
    features.merge(world, p["id"])
    assert vault.sync("pricing")["kept_ahead"] == ["main"]     # nothing new upstream
    (upstream / "README.md").write_text("upstream change\n")
    _sh("add", "-A", cwd=upstream)
    _sh("commit", "-q", "-m", "readme", cwd=upstream)
    _sh("branch", "release", cwd=upstream)
    report = vault.sync("pricing")
    assert report["merged"] == ["main"] and report["added"] == ["release"]
    with vault.checkout("pricing") as work:
        assert (work / "README.md").exists() and (work / "feature.py").exists()
    with vault.host_repo("pricing") as host:
        refs = vault._git(["for-each-ref", "--format=%(refname)"], git_dir=host)
    assert f"refs/heads/{p['branch']}" in refs and "refs/remotes/" not in refs
    out = vault.export("pricing", tmp_path / "exported")
    assert (Path(out) / "feature.py").exists()


def test_master_branch_lfs_attributes_odd_names_and_non_utf8_diffs(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    src = tmp_path / "up"
    src.mkdir()
    _sh("init", "-q", "-b", "master", cwd=src)
    (src / ".gitattributes").write_text("*.bin filter=lfs diff=lfs merge=lfs -text\n")
    (src / "legacy.txt").write_bytes("caf\xe9\n".encode("latin-1"))
    _sh("add", "-A", cwd=src)
    _sh("commit", "-q", "-m", "i", cwd=src)
    repo = vault.register("legacy", str(src))
    assert repo.default_branch == "master"
    world = WorldModel(tmp_path / "world.db")

    def edit(work):
        (work / "legacy.txt").write_bytes("na\xefve\n".encode("latin-1"))
        (work / "my file.py").write_text("ok = 1\n")
    run, _ = _swarm(edit)
    p = features.propose(world, "legacy", "Edit", "", run)
    assert sorted(p["files"]) == ["legacy.txt", "my file.py"]
    world.decide_approval(p["approval_id"], "approved", decided_by="user:lead")
    assert features.merge(world, p["id"])["status"] == "merged"
    vault.sync("legacy")


def test_embedded_repositories_are_refused_and_failed_runs_close_their_goal(
        upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")

    def embed(work):
        nested = work / "vendor"
        nested.mkdir()
        _sh("init", "-q", "-b", "main", cwd=nested)
        (nested / "f").write_text("f\n")
        _sh("add", "-A", cwd=nested)
        _sh("commit", "-q", "-m", "n", cwd=nested)
    run, seen = _swarm(embed)
    with pytest.raises(vault.VaultError, match="embedded git"):
        features.propose(world, "pricing", "Embed", "", run)
    assert world.get_goal(seen["goal_id"]).status == "failed"

    def boom(work):
        raise RuntimeError("model outage")
    run, seen = _swarm(boom)
    with pytest.raises(RuntimeError):
        features.propose(world, "pricing", "Boom", "", run)
    assert world.get_goal(seen["goal_id"]).status == "failed"
    # A run that raised leaves only a stopped record, never offered for approval.
    assert [(x["status"], x["approval_id"]) for x in features.list_proposals("pricing")] == \
        [("stopped", None)] * 2


def test_truncated_diffs_are_flagged_to_the_approver(upstream, tmp_path, monkeypatch):
    monkeypatch.setattr(features, "MAX_DIFF_CHARS", 200)
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _swarm(lambda work: (work / "big.py").write_text("x = 1\n" * 500))
    p = features.propose(world, "pricing", "Big", "", run)
    assert p["diff_truncated"] and "WARNING: the diff is" in world.get_approval(
        p["approval_id"]).detail


def test_cli_end_to_end_with_approval_in_the_middle(upstream, tmp_path, monkeypatch):
    import maverick.cli as cli_mod
    import maverick.cli._code_groups as groups
    from click.testing import CliRunner
    from maverick import config
    from maverick.cli import main

    run = CliRunner().invoke
    monkeypatch.setattr(config, "get_codebase",
                        lambda: {"enable": False, "default_protect": "block"})
    assert run(main, ["code", "list"]).exit_code != 0            # off by default
    monkeypatch.setattr(config, "get_codebase",
                        lambda: {"enable": True, "default_protect": "approve"})
    db = tmp_path / "w.db"
    monkeypatch.setattr(groups, "open_world", lambda *a, **k: WorldModel(db))
    monkeypatch.setattr(cli_mod, "_require_llm_key", lambda *a, **k: "k")
    run_fn, _ = _swarm(lambda work: (work / "feature.py").write_text("ok = True\n"))
    monkeypatch.setattr(features, "default_runner", lambda **k: run_fn)
    monkeypatch.setattr(features, "default_checker",
                        lambda **k: lambda gid, copy: {"findings": [], "fixed": []})

    out = run(main, ["code", "add", "pricing", str(upstream)])
    assert out.exit_code == 0 and "protect=approve" in out.output, out.output
    assert "pricing" in run(main, ["code", "list"]).output
    out = run(main, ["code", "sync", "pricing"])
    assert out.exit_code == 0 and "pricing now at " in out.output, out.output
    out = run(main, ["code", "feature", "pricing", "Add flag", "--no-review"])
    assert out.exit_code == 0 and "awaiting approval #1" in out.output, out.output
    assert "Independent check: looked 1 time(s)" in out.output, out.output
    pid = out.output.split()[1]
    assert "pending" in run(main, ["code", "proposals"]).output
    assert "+ok = True" in run(main, ["code", "show", pid]).output
    WorldModel(db).decide_approval(1, "approved", decided_by="user:lead")
    out = run(main, ["code", "merge", "--approved"])
    assert f"{pid} (pricing): merged" in out.output, out.output
    assert run(main, ["code", "merge"]).exit_code != 0
    out = run(main, ["code", "export", "pricing", str(tmp_path / "exp")])
    assert out.exit_code == 0 and (tmp_path / "exp" / "feature.py").exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="git is required")
def test_default_runner_budget_honors_config_and_explicit_override(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr("maverick.config.get_budget_overrides", lambda: {"max_dollars": 3.0})
    monkeypatch.setattr("maverick.llm.LLM", lambda *a, **k: object())
    monkeypatch.setattr("maverick.sandbox.build_sandbox", lambda **k: None)
    monkeypatch.setattr("maverick.world_model.open_world", lambda *a, **k: None)
    monkeypatch.setattr("maverick.world_model.close_world_if_owned", lambda world: None)
    monkeypatch.setattr(
        "maverick.orchestrator.run_goal_sync",
        lambda llm, world, budget, goal_id, **k: seen.append(budget.max_dollars),
    )
    features.default_runner()(1, tmp_path)
    features.default_runner(max_dollars=7.0)(1, tmp_path)
    assert seen == [3.0, 7.0]


def test_a_run_cannot_reach_host_git_config_beside_its_working_copy(tmp_path, monkeypatch):
    """The working copy is never the host repository's sibling, so a planted
    filter driver has no definition to run."""
    import subprocess

    from maverick.codebase import features, vault
    from maverick.world_model import WorldModel
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".mh"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    src = tmp_path / "up"
    src.mkdir()
    for args in (["init", "-q", "-b", "main"],):
        subprocess.run(["git", *args], cwd=src, check=True)
    (src / "a.py").write_text("a = 1\n")
    subprocess.run(["git", "add", "-A"], cwd=src, check=True)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "i"],
                   cwd=src, check=True)
    vault.register("r", str(src))
    mark = tmp_path / "PWNED"
    seen: list = []

    def run(goal_id, work):
        seen.append(sorted(p.name for p in work.parent.iterdir()))
        for cfg in work.parent.glob("*.git/config"):
            with open(cfg, "a") as fh:
                fh.write(f'[filter "x"]\n\tclean = touch {mark} && cat\n')
        (work / ".gitattributes").write_text("*.py filter=x\n")
        (work / "a.py").write_text("a = 2\n")
    p = features.propose(WorldModel(tmp_path / "w.db"), "r", "T", "", run)
    assert seen == [["work"]] and not mark.exists() and "a.py" in p["files"]


def test_vault_git_never_runs_automatic_maintenance(tmp_path):
    """git 2.54+ follows a fetch with a detached geometric repack. In the host
    repository that deleted a pack while clone_work was copying it ("failed to
    copy file ... pack-*.rev"), so vault git runs with automatic maintenance
    off. The thresholds are forced to fire in the foreground here."""
    src = tmp_path / "src"
    src.mkdir()
    _sh("init", "-q", "-b", "main", cwd=src)
    host = tmp_path / "host.git"
    vault._git(["init", "-q", "--bare", str(host)])
    eager = {"GIT_CONFIG_PARAMETERS": "'gc.autopacklimit'='1' 'fetch.unpacklimit'='1' "
                                      "'gc.autodetach'='false' 'maintenance.autodetach'='false'"}
    for n in range(2):
        (src / f"f{n}.txt").write_text(f"{n}\n")
        _sh("add", "-A", cwd=src)
        _sh("commit", "-q", "-m", str(n), cwd=src)
        vault._git(["fetch", "-q", str(src), "+refs/heads/*:refs/heads/*"],
                   git_dir=host, env=eager)
    assert len(list((host / "objects" / "pack").glob("*.pack"))) == 2


def test_the_merge_approval_is_a_structured_card_committing_to_the_head():
    from maverick.approval_cards import decode_approval_detail, digest
    from maverick.codebase.features import _approval_detail
    p = {"id": "0123456789abcdef", "repo": "r", "title": "t", "branch": "lightwork/t-012345",
         "head": "a" * 40, "base": "b" * 40, "files": ["x.py"], "tests": None, "review": None,
         "diff_truncated": False, "diff_chars": 1}
    card = decode_approval_detail(_approval_detail(p))
    assert card["action"] == "codebase_merge"
    assert card["parameters"]["sha256"] == digest(
        {"proposal": p["id"], "base": p["base"], "head": p["head"], "files": p["files"]})


@pytest.mark.parametrize("files, title", [
    ([" ", "\t"], "t"),
    (["x.py"], " ".join("AKIA" + "A" * 16 for _ in range(30))),  # pragma: allowlist secret
])
def test_the_merge_card_is_built_for_awkward_names_and_titles(files, title):
    from maverick.approval_cards import decode_approval_detail
    from maverick.codebase.features import _approval_detail
    p = {"id": "0123456789abcdef", "repo": "r", "title": title, "branch": "lightwork/t-012345",
         "head": "a" * 40, "base": "b" * 40, "files": files, "tests": None, "review": None,
         "diff_truncated": False, "diff_chars": 1}
    assert decode_approval_detail(_approval_detail(p))["action"] == "codebase_merge"


def test_an_unanswered_approval_can_be_renewed(tmp_path, monkeypatch):
    import time
    from types import SimpleNamespace

    from maverick.codebase import features
    saved: list = []
    monkeypatch.setattr(features, "_save", lambda p: saved.append(dict(p)))
    approvals: dict = {}

    class World:
        def get_approval(self, aid):
            return approvals.get(aid)

        def create_approval(self, action, **kw):
            aid = len(approvals) + 1
            approvals[aid] = SimpleNamespace(id=aid, status="pending", detail=kw["detail"])
            return aid
    p = {"id": "0123456789abcdef", "repo": "r", "title": "t", "branch": "lightwork/t-012345",
         "head": "a" * 40, "base": "b" * 40, "files": ["x.py"], "tests": None, "review": None,
         "diff_truncated": False, "diff_chars": 1, "status": "pending", "approval_id": None}
    world = World()
    assert features.status(world, p) == "unrequested"
    assert features.request_approval(world, p) == 1 and features.status(world, p) == "pending"
    with pytest.raises(features.VaultError, match="already has approval"):
        features.request_approval(world, p)
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + features.APPROVAL_TTL + 60)
    assert features.status(world, p) == "expired"
    assert features.request_approval(world, p) == 2


def test_approval_binds_current_saved_proposal_task_and_restores_context(tmp_path, monkeypatch):
    from maverick.logging_config import current_goal_id, reset_goal_context, set_goal_context

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    world = WorldModel(tmp_path / "world.db")
    source = world.create_goal("Alice proposal", owner="user:alice")
    other = world.create_goal("Bob outer work", owner="user:bob")
    saved = {"id": "0123456789abcdef", "repo": "r", "title": "t", "branch": "lightwork/t-012345",
             "head": "a" * 40, "base": "b" * 40, "files": ["x.py"], "tests": None, "review": None,
             "diff_truncated": False, "diff_chars": 1, "status": "pending", "approval_id": None,
             "goal_id": source}
    monkeypatch.setattr(features, "_load", lambda *args: dict(saved))
    monkeypatch.setattr(features, "_save", lambda proposal: None)
    context = set_goal_context(other)
    try:
        stale = dict(saved, goal_id=other)
        approval_id = features.request_approval(world, stale)
        assert world.get_approval(approval_id).goal_id == source
        assert stale["goal_id"] == source
        assert current_goal_id() == other
    finally:
        reset_goal_context(context)


def test_an_approved_but_expired_approval_no_longer_merges_and_can_be_renewed(tmp_path, monkeypatch):
    import time
    from types import SimpleNamespace

    from maverick.codebase import features
    monkeypatch.setattr(features, "_save", lambda p: None)
    approvals: dict = {}

    class World:
        def get_approval(self, aid):
            return approvals.get(aid)

        def create_approval(self, action, **kw):
            aid = len(approvals) + 1
            approvals[aid] = SimpleNamespace(id=aid, status="pending", detail=kw["detail"],
                                             action=action, scope=kw["scope"])
            return aid
    p = {"id": "0123456789abcdee",  # pragma: allowlist secret
         "repo": "r", "title": "t", "branch": "lightwork/t-012345",
         "head": "a" * 40, "base": "b" * 40, "files": ["x.py"], "tests": None, "review": None,
         "diff_truncated": False, "diff_chars": 1, "status": "pending", "approval_id": None}
    world = World()
    features.request_approval(world, p)
    p["approval_id"] = 1
    approvals[1].status = "approved"
    features._require_approved(world, p)                              # fresh: fine
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + features.APPROVAL_TTL + 60)
    assert features.status(world, p) == "expired"
    with pytest.raises(features.VaultError, match="expired"):
        features._require_approved(world, p)
    assert features.request_approval(world, p) == 2


# -- the verified feature run: repair rounds, the independent checker, the card --

def _card(world, p):
    from maverick.approval_cards import decode_approval_detail
    card = decode_approval_detail(world.get_approval(p["approval_id"]).detail)
    return {"parameter_summary": card["parameters"]["summary"],
            "unresolved_assumptions": card["consequences"]["unresolved_assumptions"]}


def _rounds(*edits):
    """An author whose Nth round applies the Nth edit (the last one repeats);
    records each round's goal and what its working copy looked like."""
    calls: list = []

    def run(goal_id, work):
        calls.append({"goal_id": goal_id, "files": sorted(p.name for p in work.iterdir())})
        edits[min(len(calls), len(edits)) - 1](work)
        return "AUTHOR TRANSCRIPT: my private reasoning"
    return run, calls


def _passing(work):
    (work / "app.py").write_text(SECRET_LINE + "\n\ndef discount(): return 0.1\n")


def _failing(work):
    (work / "app.py").write_text("def pricing_model(): return -1\n")


def test_failing_tests_go_back_to_the_author_until_they_pass(upstream, tmp_path):
    vault.register("pricing", str(upstream), test_command="python -m pytest -q")
    world = WorldModel(tmp_path / "world.db")
    run, calls = _rounds(_failing, _passing)
    p = features.propose(world, "pricing", "Add a discount", "10% helper", run,
                         sandbox_factory=_Sandbox, repair_rounds=2)
    assert len(calls) == 2                                  # stopped once the tests passed
    repair = world.get_goal(calls[1]["goal_id"])
    assert repair.parent_id == p["goal_id"] and "AssertionError" in repair.description
    assert "10% helper" in repair.description               # the follow-up carries the request
    assert p["tests"]["passed"] and p["tests"]["commit"] == p["head"]
    assert [r["kind"] for r in p["rounds"]] == ["author", "tests"]
    card = _card(world, p)
    assert "Tests: PASSED" in " ".join(card["parameter_summary"])
    assert "Repair rounds: 1 of 2 used." in card["parameter_summary"]
    # the approved commit is the one that was tested
    world.decide_approval(p["approval_id"], "approved", decided_by="user:lead")
    features.merge(world, p["id"])
    with vault.checkout("pricing") as work:
        assert "def discount" in (work / "app.py").read_text()


def test_test_side_effects_never_reach_the_author_or_the_proposal(upstream, tmp_path):
    vault.register("pricing", str(upstream), test_command="python -m pytest -q")
    world = WorldModel(tmp_path / "world.db")
    seen_dirs: list = []

    class TestsThatWriteFiles(_Sandbox):
        def exec(self, cmd, timeout=None):
            seen_dirs.append(Path(self.workdir))
            (Path(self.workdir) / "late.py").write_text("late = True\n")
            (Path(self.workdir) / "app.py").write_text("tampered = True\n")
            return super().exec(cmd, timeout)
    run, calls = _rounds(_failing, _passing)
    p = features.propose(world, "pricing", "Discount", "", run,
                         sandbox_factory=TestsThatWriteFiles, repair_rounds=1, checker=None)
    assert "late.py" not in calls[1]["files"]               # the author never saw it
    assert p["files"] == ["app.py"] and "late" not in p["diff"] and "tampered" not in p["diff"]
    assert len({d.parent for d in seen_dirs}) == 2          # a fresh copy for every test run
    assert all(not d.exists() for d in seen_dirs)


def test_a_checker_blocker_goes_back_to_the_author_and_is_checked_again(upstream, tmp_path):
    vault.register("pricing", str(upstream), test_command="python -m pytest -q")
    world = WorldModel(tmp_path / "world.db")

    def careless(work):
        _passing(work)
        (work / "notes.py").write_text("x = 1 / 0\n")

    def careful(work):
        (work / "notes.py").write_text("x = 1\n")
    run, calls = _rounds(careless, careful)
    looks: list = []

    def checker(goal_id, copy):
        brief = world.get_goal(goal_id).description
        looks.append({"brief": brief, "notes": (copy / "notes.py").read_text(),
                      "git": (copy / ".git").exists()})
        if len(looks) == 1:
            return ('Here is my report: {"findings": [{"severity": "blocker", '
                    '"what": "notes.py divides by zero on import", "evidence": "ran", '
                    '"how": "python -c \\"import notes\\""}, {"severity": "minor", '
                    '"what": "no docstring", "evidence": "read", "how": "notes.py line 1"}], '
                    '"fixed": []}')
        return {"findings": [], "fixed": ["1.1"]}
    p = features.propose(world, "pricing", "Discount", "10% helper", run, checker=checker,
                         sandbox_factory=_Sandbox, repair_rounds=2, check_rounds=2)
    assert len(looks) == 2 and len(calls) == 2
    assert "10% helper" in looks[0]["brief"] and "notes.py" in looks[0]["brief"]
    assert "AUTHOR TRANSCRIPT" not in looks[0]["brief"]      # never the author's reasoning
    assert looks[0]["notes"] == "x = 1 / 0\n" and looks[1]["notes"] == "x = 1\n"
    assert "divides by zero" in world.get_goal(calls[1]["goal_id"]).description
    assert "1.1" in looks[1]["brief"]                         # the checker sees its earlier finding
    check = p["check"]
    assert check["state"] == "ran" and check["runs"] == 2 and check["commit"] == p["head"]
    assert [(f["id"], f["severity"], f["status"]) for f in check["findings"]] == [
        ("1.1", "blocker", "fixed"), ("1.2", "minor", "not attempted")]
    card = _card(world, p)
    text = " ".join(card["parameter_summary"])
    # The card (which reaches chat channels and operate-level lists) carries
    # counts and statuses only; finding text can quote code and stays in the
    # administrator-only detail.
    assert "1 blocker fixed, 1 minor not attempted" in text and "maverick code show" in text
    assert "divides by zero" not in text and "no docstring" not in text
    assert any("Finding 1.1, blocker, fixed" in f and "shown by running a command" in f
               for f in features.evidence(p)["findings"])
    assert card["unresolved_assumptions"] == []
    assert features.evidence(p)["gaps"] == []


def test_a_blocker_that_is_never_fixed_stays_open_and_is_never_called_checked(
        upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, calls = _rounds(lambda work: (work / "a.py").write_text("a = 1\n"))
    blocker = {"findings": [{"severity": "blocker", "what": "a is wrong", "evidence": "read",
                             "how": "a.py"}], "fixed": []}
    p = features.propose(world, "pricing", "A", "", run, checker=lambda gid, copy: blocker,
                         repair_rounds=1, check_rounds=2)
    assert len(calls) == 2                                    # one repair round, then no more
    statuses = [(f["id"], f["status"]) for f in p["check"]["findings"]]
    assert statuses == [("1.1", "still open"), ("2.1", "not attempted")]
    card = _card(world, p)
    text = " ".join(card["parameter_summary"] + card["unresolved_assumptions"]).lower()
    assert "2 blocker(s) from the independent check are still open" in text
    assert "not configured" in text and "verified" not in text


def test_the_spending_limit_stops_the_loop_and_the_card_says_so(upstream, tmp_path):
    from maverick.budget import Budget
    vault.register("pricing", str(upstream), test_command="python -m pytest -q")
    world = WorldModel(tmp_path / "world.db")
    budget = Budget(max_tool_calls=1)

    def spend(work):
        budget.tool_calls = 1                                  # at the cap, not over it
        _failing(work)

    class CostlyTests(_Sandbox):
        def exec(self, cmd, timeout=None):
            budget.tool_calls += 1                             # the test run tips it over
            return super().exec(cmd, timeout)
    run, calls = _rounds(spend)
    checks: list = []
    p = features.propose(world, "pricing", "Discount", "", run, budget=budget,
                         checker=lambda gid, copy: checks.append(gid),
                         sandbox_factory=CostlyTests, repair_rounds=2)
    assert len(calls) == 1 and checks == []                  # nothing ran after the cap
    assert p["stopped"] == "budget" and p["check"]["state"] == "skipped"
    assert p["status"] == "pending" and not p["tests"]["passed"]
    card = _card(world, p)
    assert any("spending limit ran out" in line for line in card["parameter_summary"])
    assert any("spending limit" in line for line in card["unresolved_assumptions"])


def test_a_round_that_overruns_the_budget_is_never_offered(upstream, tmp_path):
    """A governed run swallows the budget stop and returns normally; the
    feature run still sees the spent budget after the round, keeps the last
    finished version, and says the spending limit stopped it."""
    from maverick.budget import Budget, BudgetExceeded
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    budget = Budget(max_tool_calls=3)

    def half(work):
        (work / "half.py").write_text("half = True\n")
        budget.tool_calls += 10
        return "Stopped: budget limit reached"
    run, calls = _rounds(lambda work: (work / "a.py").write_text("a = 1\n"), half)
    blocker = {"findings": [{"severity": "blocker", "what": "a", "evidence": "read",
                             "how": "a.py"}], "fixed": []}
    reviews: list = []
    p = features.propose(world, "pricing", "A", "", run, budget=budget,
                         checker=lambda gid, copy: blocker, repair_rounds=1,
                         reviewer=lambda brief, diff: reviews.append(diff))
    assert len(calls) == 2 and p["files"] == ["a.py"] and p["stopped"] == "budget"
    assert reviews == []                                     # no model call after the stop
    assert any("spending limit ran out" in line for line in _card(world, p)["parameter_summary"])

    budget = Budget(max_tool_calls=3)

    def costly_check(goal_id, copy):
        budget.tool_calls += 10
        return "Stopped: budget limit reached. Raise the cap and resume."
    run, _ = _rounds(lambda work: (work / "b.py").write_text("b = 1\n"))
    q = features.propose(world, "pricing", "B", "", run, budget=budget, checker=costly_check)
    assert q["stopped"] == "budget" and q["check"]["state"] == "skipped"
    lines = features.evidence(q)["lines"]
    assert not any("could not run" in line or "check: did not run" in line for line in lines)
    assert "Independent check: was cut short by the spending limit, so nothing it found " \
           "was recorded." in lines

    budget = Budget(max_tool_calls=3)

    def costly_review(brief, diff):
        budget.tool_calls += 10
        raise BudgetExceeded("tool calls")
    run, _ = _rounds(lambda work: (work / "d.py").write_text("d = 1\n"))
    r = features.propose(world, "pricing", "D", "", run, budget=budget, reviewer=costly_review,
                         checker=lambda gid, copy: {"findings": [], "fixed": []})
    facts = features.evidence(r)
    assert r["stopped"] is None and r["review_cut_short"]          # every round ran
    assert not any("later rounds did not run" in line for line in facts["lines"])
    assert "Independent review: cut short by the spending limit." in \
        _card(world, r)["parameter_summary"]
    assert "The spending limit ran out before the diff review finished." in facts["gaps"]

    budget = Budget(max_tool_calls=3)

    def first_round_overruns(work):
        (work / "c.py").write_text("c = 1\n")
        budget.tool_calls += 10
    run, calls = _rounds(first_round_overruns)
    with pytest.raises(vault.VaultError, match="spending limit ran out"):
        features.propose(world, "pricing", "C", "", run, budget=budget, checker=None)
    assert world.get_goal(calls[0]["goal_id"]).status == "failed"
    assert [(x["title"], x["status"]) for x in features.list_proposals()
            if x["status"] != "stopped"] == [("D", "pending"), ("B", "pending"), ("A", "pending")]
    assert [x["title"] for x in features.list_proposals() if x["status"] == "stopped"] == ["C"]


def test_the_checker_cannot_change_the_proposal(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(lambda work: (work / "a.py").write_text("a = 1\n"))
    pushed: list = []

    def meddling(goal_id, copy):
        (copy / "a.py").write_text("a = 'checker'\n")
        (copy / "planted.py").write_text("evil = True\n")
        _sh("add", "-A", cwd=copy)
        _sh("commit", "-q", "-m", "checker", cwd=copy)
        pushed.append(subprocess.run(["git", "push", "origin", "HEAD:refs/heads/main"],
                                     cwd=copy, capture_output=True).returncode)
        return {"findings": [], "fixed": []}
    p = features.propose(world, "pricing", "A", "", run, checker=meddling, repair_rounds=0)
    assert pushed[0] != 0                                     # its copy has no remote at all
    assert p["files"] == ["a.py"] and "checker" not in p["diff"]
    world.decide_approval(p["approval_id"], "approved", decided_by="user:lead")
    features.merge(world, p["id"])
    with vault.checkout("pricing") as work:
        assert (work / "a.py").read_text() == "a = 1\n" and not (work / "planted.py").exists()


def test_a_proposal_saved_before_verified_runs_still_loads_and_shows(upstream, tmp_path,
                                                                     monkeypatch):
    from click.testing import CliRunner
    from maverick import config
    from maverick.cli import main
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    old = {"id": "0123456789abcdef", "repo": "pricing", "title": "Old", "goal_id": 1,
           "branch": "lightwork/old-012345", "base": "b" * 40, "head": "a" * 40,
           "files": ["x.py"], "diff": "+x", "diff_truncated": False, "diff_chars": 2,
           "tests": {"command": "pytest", "exit_code": 0, "passed": True},
           "tests_output": "ok", "review": None, "status": "pending", "approval_id": None,
           "created_at": 1.0, "merged_at": None}
    features._save(old)
    loaded = features.find(old["id"])
    lines = features.evidence(loaded)["lines"]
    assert "Tests: PASSED (`pytest`)." in lines and "Independent check: not run." in lines
    assert features.summary(world)["proposals"][0]["check"] is None
    aid = features.request_approval(world, loaded)            # renew builds its card
    # Saved before protected paths: not protected, one approval as before.
    assert world.get_approval(aid).approvals_required == 1
    assert features.summary(world)["proposals"][0]["protected"] is False
    monkeypatch.setattr(config, "get_codebase",
                        lambda: {"enable": True, "default_protect": "block"})
    out = CliRunner().invoke(main, ["code", "show", old["id"]])
    assert out.exit_code == 0 and "Independent check: not run." in out.output, out.output


# -- isolation between rounds: nothing a test run or a checker leaves behind
#    reaches the next author round or the proposal --

@pytest.fixture
def private_tmp(tmp_path, monkeypatch):
    """Working copies live under this test's own temp folder, so a planting
    probe can find them without touching other tests."""
    import tempfile
    root = tmp_path / "t"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    return root


def test_a_test_run_cannot_plant_files_in_the_next_author_round(upstream, tmp_path, private_tmp):
    probe = (f"import glob, os, sys\n"
             f"for d in glob.glob({str(private_tmp)!r} + '/lw-work-*/work'):\n"
             f"    open(os.path.join(d, 'planted.py'), 'w').write('planted = True\\n')\n"
             f"sys.exit(0 if os.path.exists('fixed.txt') else 1)\n")
    vault.register("pricing", str(upstream), test_command="python probe.py")
    world = WorldModel(tmp_path / "world.db")

    def first(work):
        (work / "probe.py").write_text(probe)

    def second(work):
        (work / "fixed.txt").write_text("ok\n")
    run, calls = _rounds(first, second)
    p = features.propose(world, "pricing", "T", "", run, sandbox_factory=_Sandbox,
                         repair_rounds=1, checker=None)
    assert "planted.py" not in calls[1]["files"] and "planted.py" not in p["files"]
    assert p["tests"]["passed"]


def test_a_checker_cannot_plant_files_then_call_the_change_clean(upstream, tmp_path, private_tmp):
    import glob
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(lambda work: (work / "a.py").write_text("a = 1\n"))
    looks: list = []

    def checker(goal_id, copy):
        looks.append(goal_id)
        if len(looks) == 1:
            for d in glob.glob(str(private_tmp) + "/lw-work-*/work"):
                Path(d, "backdoor.py").write_text("import os  # planted by the checker\n")
            return {"findings": [{"severity": "blocker", "what": "a is wrong",
                                  "evidence": "read", "how": "a.py"}], "fixed": []}
        return {"findings": [], "fixed": ["1.1"]}
    p = features.propose(world, "pricing", "K", "", run, checker=checker, repair_rounds=1)
    assert p["files"] == ["a.py"] and "backdoor" not in p["diff"]


SLEEPER = ("import glob, pathlib, time\n"
           "for _ in range(40):\n"
           "    for d in glob.glob({root!r} + '/lw-work-*/work'):\n"
           "        pathlib.Path(d, 'late_{tag}.py').write_text('late = True\\n')\n"
           "    time.sleep(0.1)\n")


def _start_sleeper(root, tag):
    import subprocess as sp
    sp.Popen([sys.executable, "-c", SLEEPER.format(root=str(root), tag=tag)],
             start_new_session=True, stdout=sp.DEVNULL, stderr=sp.DEVNULL)


def test_processes_a_test_run_or_a_checker_leave_running_are_stopped(upstream, tmp_path,
                                                                    private_tmp, monkeypatch):
    """The fallback where namespaces are unavailable: detached background
    processes that keep the step's marker cannot write into the next round's
    copy, because each test run and each checker look stops all of them."""
    import time

    from maverick.sandbox import local
    from maverick.sandbox.local import LocalBackend
    monkeypatch.setattr(local, "step_namespaces_available", lambda: False)
    probe = ("import os, subprocess, sys\n"
             "if not os.path.exists('fixed.txt'):\n"
             f"    subprocess.Popen([sys.executable, '-c', {SLEEPER.format(root=str(private_tmp), tag='tests')!r}],\n"
             "                     start_new_session=True, stdout=subprocess.DEVNULL,\n"
             "                     stderr=subprocess.DEVNULL)\n"
             "    sys.exit(1)\n")
    vault.register("pricing", str(upstream), test_command=f"{sys.executable} probe.py")
    world = WorldModel(tmp_path / "world.db")
    seen: list = []

    def edit(n):
        def apply(work):
            time.sleep(0.6)                       # long enough for a survivor to write
            seen.append(sorted(p.name for p in work.iterdir()))
            (work / "probe.py").write_text(probe)
            if n:
                (work / "fixed.txt").write_text(f"{n}\n")
        return apply
    run, _ = _rounds(edit(0), edit(1), edit(2))
    looks: list = []

    def checker(goal_id, copy):
        looks.append(goal_id)
        if len(looks) == 1:
            LocalBackend(workdir=copy).exec(
                f"{sys.executable} -c 'import subprocess, sys; subprocess.Popen([sys.executable, "
                f"\"-c\", {SLEEPER.format(root=str(private_tmp), tag='check')!r}], "
                "start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)'")
            return {"findings": [{"severity": "blocker", "what": "x", "evidence": "read",
                                  "how": "x"}], "fixed": []}
        return {"findings": [], "fixed": ["1.1"]}
    p = features.propose(world, "pricing", "L", "", run, sandbox_factory=LocalBackend,
                         checker=checker, repair_rounds=2, check_rounds=2)
    assert len(seen) == 3 and len(looks) == 2
    assert not [f for files in seen for f in files if f.startswith("late_")], seen
    assert not [f for f in p["files"] if f.startswith("late_")]
    facts = features.evidence(p)                                   # the card says so
    assert features.HOST_LINE in facts["lines"] and features.HOST_GAP in facts["gaps"]


ESCAPES = {
    # a daemon in its own session with an empty environment: no marker to find
    "envi": ("import subprocess, sys\n"
             "subprocess.Popen([sys.executable, '-c', S], env={}, start_new_session=True,\n"
             "                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"),
    # a daemon that detaches, then re-executes itself with a cleared environment
    "reexec": ("import os, sys\n"
               "if os.fork() == 0:\n"
               "    os.setsid()\n"
               "    os.execve(sys.executable, [sys.executable, '-c', S], {'PATH': '/usr/bin'})\n"),
}


@pytest.mark.parametrize("how", sorted(ESCAPES))
def test_a_daemon_that_clears_its_environment_dies_with_its_step(upstream, tmp_path,
                                                                  private_tmp, how):
    """Each command of a step runs in its own PID and mount namespace: when it
    ends, the kernel kills everything it started, whatever its environment,
    and it never sees the temporary folder holding other rounds' copies."""
    import time

    from maverick.sandbox import local
    from maverick.sandbox.local import LocalBackend
    if not local.step_namespaces_available():
        pytest.skip("this host does not allow unprivileged user namespaces; "
                    "the marker fallback is covered by the test above")
    sleeper = SLEEPER.format(root=str(private_tmp), tag=how)
    probe = ("import glob, os, sys\n"
             f"S = {sleeper!r}\n"
             f"seen = glob.glob({str(private_tmp)!r} + '/lw-*')\n"
             "open('seen.txt', 'w').write(repr(sorted(os.path.basename(x) for x in seen)))\n"
             "if not os.path.exists('fixed.txt'):\n"
             + "".join("    " + line + "\n" for line in ESCAPES[how].splitlines())
             + "    sys.exit(1)\n")
    vault.register("pricing", str(upstream), test_command=f"{sys.executable} probe.py")
    world = WorldModel(tmp_path / "world.db")
    seen: list = []

    def run(goal_id, work):
        time.sleep(1.0)                          # long enough for a survivor to write
        seen.append(sorted(p.name for p in work.iterdir()))
        (work / "probe.py").write_text(probe)
        if len(seen) > 1:
            (work / "fixed.txt").write_text("1\n")
    p = features.propose(world, "pricing", "E", "", run, sandbox_factory=LocalBackend,
                         checker=None, repair_rounds=1)
    assert len(seen) == 2 and not [f for f in seen[1] if f.startswith("late_")], seen
    assert not [f for f in p["files"] if f.startswith("late_")]
    assert p["tests"]["passed"] and p["isolation"] == "namespace"
    facts = features.evidence(p)
    assert features.NAMESPACE_LINE in facts["lines"] and features.NAMESPACE_GAP in facts["gaps"]
    assert features.HOST_LINE not in facts["lines"]


def test_a_step_sees_only_its_own_copy_in_the_temporary_folder(tmp_path, private_tmp):
    from maverick.sandbox import local
    from maverick.sandbox.local import LocalBackend, contained_step
    if not local.step_namespaces_available():
        pytest.skip("this host does not allow unprivileged user namespaces")
    other = private_tmp / "lw-work-other" / "work"
    other.mkdir(parents=True)
    mine = private_tmp / "lw-work-mine"
    (mine / "work").mkdir(parents=True)
    with contained_step(mine):
        out = LocalBackend(workdir=mine / "work").exec(
            f"ls {private_tmp}; ls {mine}; touch made.txt")
    assert out.exit_code == 0, out.stderr
    assert "lw-work-other" not in out.stdout and "lw-work-mine" in out.stdout
    assert (mine / "work" / "made.txt").exists()          # its own copy is the real one


def test_a_container_requirement_refuses_a_run_on_this_computer(upstream, tmp_path, monkeypatch):
    from maverick import config
    from maverick.sandbox.local import LocalBackend
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(config, "get_codebase", lambda: {"enable": True, "require_container": True})
    calls: list = []
    with pytest.raises(vault.VaultError, match="must run in a container"):
        features.propose(world, "pricing", "A", "", lambda gid, work: calls.append(gid),
                         sandbox_factory=LocalBackend)
    assert calls == [] and features.list_proposals() == []
    assert features.container_refusal(LocalBackend) == features.CONTAINER_REQUIRED
    assert features.container_refusal(_Sandbox) is None          # not this computer's shell


def test_the_checker_cannot_read_past_goals_or_memory(tmp_path, monkeypatch):
    """The checker's run is a fresh context: the tools that read past goals or
    other runs' memory are denied, and prior goals are not recalled into its
    brief, so it cannot reach the author's reasoning that way."""
    from types import SimpleNamespace

    from maverick import orchestrator, tools
    from maverick.sandbox.local import LocalBackend
    seen = {}

    def fake_run(llm, world, budget, goal_id, **kwargs):
        seen["fresh"] = tools.fresh_context()
        return '{"findings": []}'
    monkeypatch.setattr(orchestrator, "run_goal_sync", fake_run)
    monkeypatch.setattr("maverick.llm.LLM", lambda *a, **k: object())
    monkeypatch.setattr("maverick.sandbox.build_sandbox", lambda **k: None)
    monkeypatch.setattr("maverick.world_model.open_world", lambda *a, **k: None)
    monkeypatch.setattr("maverick.world_model.close_world_if_owned", lambda world: None)
    monkeypatch.setattr(features, "checker_model", lambda: "anthropic:checker")
    features.default_checker(budget=None)(1, tmp_path)
    assert seen["fresh"] is True and tools.fresh_context() is False
    world = WorldModel(tmp_path / "w.db")
    with tools.fresh_context_run():
        reg = tools.base_registry(world, LocalBackend(workdir=tmp_path))
    assert {"recall_past_goals", "memory", "kv_memory"} <= tools.PAST_WORK_TOOLS
    assert not any(reg._acl_allows(name) for name in tools.PAST_WORK_TOOLS)
    monkeypatch.setenv("MAVERICK_AUTO_RECALL", "1")
    goal = SimpleNamespace(id=2, title="Add a discount", description="", owner="")
    with tools.fresh_context_run():
        assert orchestrator._maybe_recall_prior_work(world, goal, None) is None
    # nor the outcomes of similar earlier goals (experience guidance)
    from maverick import experience
    monkeypatch.setattr(experience, "recall", lambda *a, **k: "2 similar goals succeeded")
    assert orchestrator._maybe_experience_guidance(world, goal, None)
    with tools.fresh_context_run():
        assert orchestrator._maybe_experience_guidance(world, goal, None) is None


def test_an_unreadable_checker_report_keeps_the_work(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(lambda work: (work / "a.py").write_text("a = 1\n"))
    p = features.propose(world, "pricing", "R", "", run,
                         checker=lambda gid, copy: '{"a":' + "[" * 40000)
    assert p["check"]["state"] == "failed" and "could not be read" in p["check"]["error"]
    assert [q["id"] for q in features.list_proposals()] == [p["id"]]


def test_the_card_says_whether_the_checker_was_off_for_this_run_or_in_settings(
        upstream, tmp_path, monkeypatch):
    from maverick import config
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(lambda work: (work / "a.py").write_text("a = 1\n"))
    p = features.propose(world, "pricing", "Skipped once", "", run, checker=None)
    assert "Independent check: turned off for this run." in features.evidence(p)["lines"]
    monkeypatch.setattr(config, "get_codebase", lambda: {"enable": True, "checker": False})
    q = features.propose(world, "pricing", "Off", "", run, checker=None)
    assert "Independent check: turned off in settings." in features.evidence(q)["lines"]


def test_running_on_this_computer_is_a_gap_on_every_summary(upstream, tmp_path, monkeypatch):
    """A change whose tests passed and whose check came back clean is still
    not called checked when its steps ran on this computer."""
    from click.testing import CliRunner
    from maverick import config
    from maverick.cli import main
    from maverick.sandbox.local import LocalBackend
    vault.register("pricing", str(upstream), test_command=f"{sys.executable} -m pytest -q")
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(_passing)
    p = features.propose(world, "pricing", "Clean", "", run, sandbox_factory=LocalBackend,
                         checker=lambda gid, copy: {"findings": [], "fixed": []})
    assert p["tests"]["passed"] and p["check"]["state"] == "ran"
    gap = features.NAMESPACE_GAP if p["isolation"] == "namespace" else features.HOST_GAP
    assert features.evidence(p)["gaps"] == [gap]
    assert _card(world, p)["unresolved_assumptions"] == [gap]
    monkeypatch.setattr(config, "get_codebase", lambda: {"enable": True})
    import maverick.cli._code_groups as groups
    monkeypatch.setattr(groups, "open_world", lambda *a, **k: WorldModel(tmp_path / "world.db"))
    out = CliRunner().invoke(main, ["code", "proposals"])
    assert out.exit_code == 0 and "1 gap(s)" in out.output and "checked" not in out.output


def test_the_checker_task_keeps_counts_not_finding_text(upstream, tmp_path):
    """Finding text can quote vaulted code; the checker's own task record (goal
    pages, finished-task webhooks) keeps only counts."""
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(lambda work: (work / "a.py").write_text("a = 1\n"))
    report = ('{"findings": [{"severity": "minor", "what": "QUOTED_CODE_LINE is odd", '
              '"evidence": "read", "how": "a.py"}], "fixed": []}')

    def checker(goal_id, copy):
        world.set_goal_status(goal_id, "done", result=report)   # as a governed run does
        return report
    p = features.propose(world, "pricing", "A", "", run, checker=checker, repair_rounds=0)
    goal = world.get_goal(p["check"]["goal_ids"][0])
    assert goal.status == "done" and "QUOTED_CODE_LINE" not in (goal.result or "")
    assert "1 finding(s)" in goal.result and p["id"] in goal.result



def test_a_fresh_context_run_sends_no_result_text_to_webhooks(monkeypatch):
    from maverick import orchestrator, tools, webhooks
    sent: list = []
    monkeypatch.setattr(webhooks, "fire", lambda event, payload: sent.append(payload))
    with tools.fresh_context_run():
        orchestrator._fire_webhook("goal_finished", {"goal_id": 1, "status": "done",
                                                     "result": "QUOTED_CODE_LINE"})
    orchestrator._fire_webhook("goal_finished", {"goal_id": 2, "status": "done",
                                                 "result": "ordinary"})
    assert "QUOTED_CODE_LINE" not in repr(sent[0]) and "ordinary" in repr(sent[1])


STEP_AS_USER = """
import os, pathlib, sys, tempfile
from maverick.sandbox.local import LocalBackend, contained_step, step_namespaces_available
if not step_namespaces_available():
    print("NO-NAMESPACES"); sys.exit(0)
root = tempfile.mkdtemp(prefix="lw-work-")
work = pathlib.Path(root, "work"); work.mkdir()
secret = work / "secret"; secret.write_text("hidden"); secret.chmod(0)
with contained_step(root):
    out = LocalBackend(workdir=work).exec("id -u; id -g; cat secret")
print(repr((out.stdout, out.exit_code, os.getuid(), os.getgid())))
"""


def test_step_commands_run_as_the_real_user_not_root(tmp_path):
    """Repository tests must not run as root inside the wrapper: they would
    skip root-unsafe tests, read files their user cannot, or refuse to run."""
    import ast
    import os
    import shutil
    import subprocess as sp

    import maverick
    env = {**os.environ, "HOME": str(tmp_path), "MAVERICK_HOME": str(tmp_path / ".mh"),
           "PYTHONPATH": os.pathsep.join([str(Path(maverick.__file__).parents[1]),
                                          os.environ.get("PYTHONPATH", "")])}
    argv = [sys.executable, "-c", STEP_AS_USER]
    if os.getuid() == 0:                    # root reads every file: check as nobody
        if not shutil.which("setpriv"):
            pytest.skip("running as root without setpriv to drop to an ordinary user")
        tmp_path.chmod(0o777)
        argv = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", *argv]
    done = sp.run(argv, capture_output=True, text=True, env=env, cwd=str(tmp_path), timeout=120)
    assert done.returncode == 0, done.stderr[-2000:]
    if done.stdout.strip() == "NO-NAMESPACES":
        pytest.skip("this host does not allow unprivileged user namespaces")
    stdout, code, uid, gid = ast.literal_eval(done.stdout.strip().splitlines()[-1])
    assert stdout.split()[:2] == [str(uid), str(gid)] and "hidden" not in stdout
    assert code != 0                        # the mode-000 file stayed unreadable


def test_a_work_area_that_cannot_be_set_up_is_not_a_test_result(upstream, tmp_path,
                                                                private_tmp, monkeypatch):
    from maverick.sandbox import local
    from maverick.sandbox.local import LocalBackend
    if not local.step_namespaces_available():
        pytest.skip("this host does not allow unprivileged user namespaces")
    monkeypatch.setattr(local, "_NS_PRELUDE",
                        local._NS_PRELUDE.replace("mount -t tmpfs", "false\n  mount -t tmpfs"))
    vault.register("pricing", str(upstream), test_command=f"{sys.executable} -m pytest -q")
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(_passing)
    p = features.propose(world, "pricing", "S", "", run, sandbox_factory=LocalBackend,
                         checker=None, repair_rounds=1)
    assert p["tests"]["setup_failed"] and not p["tests"]["passed"]
    assert p["repair_rounds"]["used"] == 0                   # nothing to repair in the change
    facts = features.evidence(p)
    assert "Tests: not run. The isolated work area could not be set up." in facts["lines"]
    assert features.NAMESPACE_LINE not in facts["lines"]
    assert features.SETUP_FAILED_LINE in facts["lines"]
    assert features.SETUP_FAILED_LINE in facts["gaps"]


# -- a checker you can trust: Lightwork re-runs repros, several checkers,
#    and a checker image that never falls back to this computer --

def _settings(monkeypatch, **values):
    from maverick import config
    monkeypatch.setattr(config, "get_codebase", lambda: {"enable": True, **values})


def _broken(work):
    (work / "notes.py").write_text("x = 1 / 0\n")


def _mended(work):
    (work / "notes.py").write_text("x = 1\n")


def _blocker(what="notes.py divides by zero on import", probe="import notes\n", **extra):
    return {"severity": "blocker", "what": what, "evidence": "ran", "how": "import notes",
            "repro": "python probe_notes.py", "probe_files": {"probe_notes.py": probe}, **extra}


def _line(p, fid):
    return next(line for line in features.evidence(p)["findings"] if f"Finding {fid}" in line)


def test_a_repro_that_fails_on_a_fresh_copy_confirms_the_finding(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(_broken)
    p = features.propose(world, "pricing", "Notes", "", run, sandbox_factory=_Sandbox,
                         checker=lambda gid, copy: {"findings": [_blocker()], "fixed": []},
                         repair_rounds=0, check_rounds=1)
    f = p["check"]["findings"][0]
    assert f["repro_state"] == "confirmed" and f["probe_files"] == ["probe_notes.py"]
    assert "confirmed: Lightwork re-ran it and it failed" in _line(p, "1.1")
    assert "1 confirmed by Lightwork re-running them" in " ".join(_card(world, p)["parameter_summary"])


def test_a_repro_that_passes_is_not_reproduced_and_reads_as_read_only(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, calls = _rounds(_broken)
    claim = {"findings": [_blocker(probe="import app\n")], "fixed": []}
    p = features.propose(world, "pricing", "Notes", "", run, sandbox_factory=_Sandbox,
                         checker=lambda gid, copy: claim, repair_rounds=1, check_rounds=2)
    f = p["check"]["findings"][0]
    assert f["repro_state"] == "not reproduced" and f["evidence"] == "read"
    assert f["severity"] == "blocker" and len(calls) == 2      # a person decides: it still blocks
    assert "not reproduced when Lightwork re-ran it: it passed; read only" in _line(p, "1.1")


def test_a_confirmed_repro_decides_fixed_whatever_the_checker_says(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    # The author mends it; the checker never confirms. Lightwork's re-run says
    # fixed, but the run is not clean until a later look confirms it.
    run, _ = _rounds(_broken, _mended)
    looks: list = []

    def stubborn(gid, copy):
        looks.append(gid)
        return {"findings": [_blocker()] if len(looks) == 1 else [], "fixed": []}
    p = features.propose(world, "pricing", "Notes", "", run, sandbox_factory=_Sandbox,
                         checker=stubborn, repair_rounds=1, check_rounds=2)
    assert p["check"]["findings"][0]["status"] == "fixed"
    assert ("fixed: its repro command passed on the repaired version (the author saw the "
            "command); no later look confirmed it") in _line(p, "1.1")
    assert features.evidence(p)["gaps"] == [
        "The repository's tests did not pass or are not configured.",
        features.UNCONFIRMED_GAP.format(n=1)]
    assert features.summary(world)["proposals"][0]["check"] == "open"
    # The reverse: the checker says fixed, but the repro still fails on the new version.
    run, _ = _rounds(_broken, lambda work: (work / "other.py").write_text("y = 2\n"))
    looks.clear()

    def credulous(gid, copy):
        looks.append(gid)
        return ({"findings": [_blocker()], "fixed": []} if len(looks) == 1
                else {"findings": [], "fixed": ["1.1"]})
    q = features.propose(world, "pricing", "Notes", "", run, sandbox_factory=_Sandbox,
                         checker=credulous, repair_rounds=1, check_rounds=2)
    assert q["check"]["findings"][0]["status"] == "still open"
    assert "1 blocker(s) from the independent check are still open." in features.evidence(q)["gaps"]


def test_probe_files_never_reach_the_proposal(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(_broken)
    claim = {"findings": [_blocker(probe="import notes  # PROBE-MARKER\n")], "fixed": []}
    p = features.propose(world, "pricing", "Notes", "", run, sandbox_factory=_Sandbox,
                         checker=lambda gid, copy: claim, repair_rounds=0, check_rounds=1)
    assert p["check"]["findings"][0]["repro_state"] == "confirmed"
    assert p["files"] == ["notes.py"] and "PROBE-MARKER" not in p["diff"]
    import json
    assert "PROBE-MARKER" not in json.dumps(features.find(p["id"]))
    world.decide_approval(p["approval_id"], "approved", decided_by="user:lead")
    features.merge(world, p["id"])
    with vault.checkout("pricing") as work:
        assert not (work / "probe_notes.py").exists()


def test_a_probe_path_that_leaves_the_copy_is_refused(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    outside = tmp_path / "outside"
    outside.mkdir()

    def with_link(work):
        _broken(work)
        (work / "out").symlink_to(outside)
    run, _ = _rounds(with_link)
    escapes = [_blocker(what=f"escape {i}", probe="import notes\n") for i in range(3)]
    escapes[0]["probe_files"] = {"../escape.py": "import notes\n"}
    escapes[1]["probe_files"] = {".git/hooks/pre-commit": "x\n"}
    escapes[2]["probe_files"] = {"out/new/probe.py": "import notes\n"}   # a link in the copy
    p = features.propose(world, "pricing", "Notes", "", run, sandbox_factory=_Sandbox,
                         checker=lambda gid, copy: {"findings": escapes, "fixed": []},
                         repair_rounds=0, check_rounds=1)
    for f in p["check"]["findings"]:
        assert f["repro_state"] == "not run" and "path was refused" in f["repro_reason"]
        assert "not run: a probe file path was refused" in _line(p, f["id"])
    assert ("Lightwork re-ran 0 finding(s) on its own copy of the change: 0 confirmed, "
            "0 not reproduced. 3 could not be run.") in features.evidence(p)["lines"]
    assert list(outside.iterdir()) == [] and not (tmp_path / "escape.py").exists()


def test_two_checkers_never_see_each_others_findings(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(_broken, _mended)
    seen: dict = {1: [], 2: []}

    def checker(n, report):
        def look(gid, copy):
            seen[n].append((world.get_goal(gid).description, copy))
            return report if len(seen[n]) == 1 else {"findings": [], "fixed": []}
        return look
    first = checker(1, {"findings": [{"severity": "blocker", "what": "FIRST-ONLY"}]})
    second = checker(2, {"findings": [{"severity": "minor", "what": "SECOND-ONLY"}]})
    p = features.propose(world, "pricing", "Notes", "", run, sandbox_factory=_Sandbox,
                         checker=[first, second], repair_rounds=1, check_rounds=2)
    assert len(seen[1]) == len(seen[2]) == 2
    assert "FIRST-ONLY" in seen[1][1][0] and "SECOND-ONLY" not in seen[1][1][0]
    assert "SECOND-ONLY" in seen[2][1][0] and "FIRST-ONLY" not in seen[2][1][0]
    assert seen[1][0][1] != seen[2][0][1]                      # each on its own copy
    assert [(f["id"], f["checker"]) for f in p["check"]["findings"]] == [("1.1", 1), ("2-1.1", 2)]
    assert "Finding 2-1.1 from checker 2, minor" in " ".join(features.evidence(p)["findings"])


def test_a_blocker_from_the_second_checker_blocks(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, calls = _rounds(_broken)
    clean = lambda gid, copy: {"findings": [], "fixed": []}  # noqa: E731
    blocks = lambda gid, copy: {"findings": [{"severity": "blocker", "what": "SECOND"}]}  # noqa: E731
    p = features.propose(world, "pricing", "Notes", "", run, sandbox_factory=_Sandbox,
                         checker=[clean, blocks], repair_rounds=1, check_rounds=2)
    assert len(calls) == 2 and "SECOND" in world.get_goal(calls[1]["goal_id"]).description
    assert any("blocker(s) from the independent check are still open" in g
               for g in features.evidence(p)["gaps"])
    assert features.summary(world)["proposals"][0]["check"] == "open"


def test_checkers_that_share_the_authors_family_are_a_gap(upstream, tmp_path, monkeypatch):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    monkeypatch.setattr(features, "_author_model", lambda: "anthropic:author-model")

    def stub(model):
        def look(gid, copy):
            return {"findings": [], "fixed": []}
        look.model = model
        return look
    run, _ = _rounds(_mended)
    p = features.propose(world, "pricing", "Notes", "", run, checker=[
        stub("anthropic:checker-a"), stub("claude-checker-b")])
    facts = features.evidence(p)
    assert "Checker 1 used anthropic:checker-a, the same kind of model as the author." in facts["lines"]
    assert features.SAME_FAMILY_GAP in facts["gaps"]
    assert features.SAME_FAMILY_GAP in _card(world, p)["unresolved_assumptions"]
    run, _ = _rounds(_mended)
    q = features.propose(world, "pricing", "Notes", "", run, checker=[
        stub("anthropic:checker-a"), stub("openai:checker-c")])
    facts = features.evidence(q)
    assert "Checker 2 used openai:checker-c, a different kind of model from the author." \
        in facts["lines"] and features.SAME_FAMILY_GAP not in facts["gaps"]


def test_repros_stop_at_the_per_look_cap_and_the_budget(upstream, tmp_path, monkeypatch):
    from maverick.budget import Budget
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    four = {"findings": [_blocker(what=f"f{i}") for i in range(4)], "fixed": []}
    _settings(monkeypatch, max_repros=2)
    run, _ = _rounds(_broken)
    p = features.propose(world, "pricing", "Notes", "", run, sandbox_factory=_Sandbox,
                         checker=lambda gid, copy: four, repair_rounds=0, check_rounds=1)
    states = [f["repro_state"] for f in p["check"]["findings"]]
    assert states == ["confirmed", "confirmed", "not re-run", "not re-run"]
    assert "the limit of 2 re-runs per look was reached" in _line(p, "1.3")
    _settings(monkeypatch, max_repros=5)
    budget = Budget(max_tool_calls=2)                         # each re-run is one tool call
    run, _ = _rounds(_broken)
    q = features.propose(world, "pricing", "Notes", "", run, sandbox_factory=_Sandbox,
                         budget=budget, checker=lambda gid, copy: four, repair_rounds=0)
    assert [f["repro_state"] for f in q["check"]["findings"]] == [
        "confirmed", "confirmed", "not re-run", "not re-run"]
    assert q["stopped"] == "budget"


def test_an_unusable_checker_image_could_not_run_and_never_runs_here(upstream, tmp_path,
                                                                    monkeypatch):
    from maverick.sandbox import docker
    vault.register("pricing", str(upstream), test_command="python -m pytest -q")
    world = WorldModel(tmp_path / "world.db")
    _settings(monkeypatch, checker_image="lightwork/checker:missing")

    def no_docker(self):
        raise RuntimeError("Docker not available.")
    monkeypatch.setattr(docker.DockerBackend, "_verify_docker", no_docker)
    ran_here: list = []

    class Here(_Sandbox):
        def exec(self, cmd, timeout=None):
            ran_here.append(cmd)
            return super().exec(cmd, timeout)
    looked: list = []
    run, _ = _rounds(_passing)
    p = features.propose(world, "pricing", "Discount", "", run, sandbox_factory=Here,
                         checker=lambda gid, copy: looked.append(gid) or
                         {"findings": [_blocker()], "fixed": []})
    assert looked == [] and ran_here == ["python -m pytest -q"]   # only the tests ran here
    assert p["check"]["state"] == "failed"
    lines = " ".join(features.evidence(p)["lines"])
    assert "Independent check: could not run (the checker image could not be used" in lines
    assert "The independent check could not run, so this change was not checked." in \
        features.evidence(p)["gaps"]


def test_a_proposal_from_before_repros_and_several_checkers_still_shows(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    step1 = {"id": "fedcba9876543210", "repo": "pricing", "title": "Step one", "goal_id": 1,  # pragma: allowlist secret
             "branch": "lightwork/one-fedcba", "base": "b" * 40, "head": "a" * 40,
             "files": ["x.py"], "diff": "+x", "diff_truncated": False, "diff_chars": 2,
             "tests": {"command": "pytest", "exit_code": 0, "passed": True, "commit": "a" * 40},
             "tests_output": "ok", "test_command": True,
             "repair_rounds": {"used": 1, "allowed": 2}, "isolation": "container",
             "rounds": [], "stopped": None, "review_cut_short": False, "review": None,
             "check": {"state": "ran", "runs": 2, "off": None, "max_runs": 2,
                       "commit": "a" * 40, "error": None, "goal_ids": [2, 3],
                       "findings": [{"id": "1.1", "severity": "blocker", "what": "w",
                                     "evidence": "ran", "how": "h", "status": "fixed"}]},
             "status": "pending", "approval_id": None, "created_at": 2.0, "merged_at": None}
    features._save(step1)
    loaded = features.find(step1["id"])
    facts = features.evidence(loaded)
    assert facts["findings"] == ["Finding 1.1, blocker, fixed: w (shown by running a command, "
                                 "in the checker's own words)."]
    assert facts["gaps"] == [] and not any(line.startswith("Checker") for line in facts["lines"])
    assert features.summary(world)["proposals"][0]["check"] == "clean"
    features.request_approval(world, loaded)


# -- repair round 1: isolation of the checker image, repros only in a
#    container, repairs that game a repro, and honest counts --

def _sandbox_config(text):
    from maverick import config
    home = Path(__import__("os").environ["MAVERICK_HOME"])
    home.mkdir(parents=True, exist_ok=True)
    (home / "config.toml").write_text(text)
    config.reset_config_cache()


def test_a_checker_image_never_weakens_the_configured_work_area(upstream, tmp_path, monkeypatch):
    from maverick import sandbox
    from maverick.sandbox import docker
    monkeypatch.setattr(docker.DockerBackend, "_verify_docker", lambda self: None)
    monkeypatch.setattr(sandbox, "_validated_gvisor_runtime", lambda value: "runsc")
    _sandbox_config('[sandbox]\nbackend = "gvisor"\n')
    box = features.image_sandbox("lw-check:1", str(tmp_path / "w"))
    flags = box._container_flags()
    assert box.runtime == "runsc" and flags[flags.index("--runtime") + 1] == "runsc"
    assert flags[flags.index("--pull") + 1] == "never"           # never fetches an image
    _sandbox_config('[sandbox]\nbackend = "firecracker"\n')
    with pytest.raises(RuntimeError, match="cannot run a container image"):
        features.image_sandbox("lw-check:1", str(tmp_path / "w"))
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    _settings(monkeypatch, checker_image="lw-check:1")
    looked: list = []
    run, _ = _rounds(_mended)
    p = features.propose(world, "pricing", "Notes", "", run, sandbox_factory=_Sandbox,
                         checker=lambda gid, copy: looked.append(gid))
    assert looked == [] and p["check"]["state"] == "failed"
    assert "cannot run a container image" in p["check"]["error"]


def test_a_missing_checker_image_is_not_pulled_and_says_how_to_get_it(upstream, tmp_path,
                                                                      monkeypatch):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    _settings(monkeypatch, checker_image="lw-check:1")

    class Missing:
        def exec(self, cmd, timeout=None):
            return type("R", (), {"stdout": "", "exit_code": 125, "stderr":
                                  "docker: Error response from daemon: No such image: lw-check:1"})()
    monkeypatch.setattr(features, "image_sandbox", lambda image, workdir: Missing())
    run, _ = _rounds(_mended)
    p = features.propose(world, "pricing", "Notes", "", run,
                         checker=lambda gid, copy: pytest.fail("the checker ran"))
    error = p["check"]["error"]
    assert "lw-check:1 is not on this computer" in error
    assert "docker build -t lw-check:1 deploy/checker" in error and "docker pull lw-check:1" in error


def test_repros_run_only_when_the_steps_run_in_a_container(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    ran: list = []

    class OnThisComputer(_Sandbox):
        host_visible_fs = True

        def exec(self, cmd, timeout=None):
            ran.append(cmd)
            return super().exec(cmd, timeout)
    run, _ = _rounds(_broken)
    p = features.propose(world, "pricing", "Notes", "", run, sandbox_factory=OnThisComputer,
                         checker=lambda gid, copy: {"findings": [_blocker()], "fixed": []},
                         repair_rounds=0, check_rounds=1)
    f = p["check"]["findings"][0]
    assert ran == [] and f["repro_state"] == "not re-run" and f["evidence"] == "ran"
    assert "not re-run: the steps do not run in a container" in _line(p, "1.1")
    assert features.NO_CONTAINER_REPRO_GAP in features.evidence(p)["gaps"]


def test_a_repair_that_only_makes_the_repro_pass_is_not_called_clean(upstream, tmp_path):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    checks = "import notes\n"

    def broken(work):
        _broken(work)
        (work / "check_notes.py").write_text(checks)

    def gamed(work):          # the bug stays; the author empties the check instead
        (work / "check_notes.py").write_text("assert True\n")
    repro = {"severity": "blocker", "what": "notes.py divides by zero", "evidence": "ran",
             "how": "import notes", "repro": "python check_notes.py"}
    briefs: list = []

    def checker(answer):
        def look(gid, copy):
            briefs.append(world.get_goal(gid).description)
            return {"findings": [repro], "fixed": []} if len(briefs) % 2 else answer
        return look
    outcomes = {}
    for name, answer in (("silent", {"findings": []}),
                         ("still wrong", {"findings": [], "still_open": ["1.1"]}),
                         ("confirmed", {"findings": [], "fixed": ["1.1"]})):
        run, calls = _rounds(broken, gamed)
        outcomes[name] = features.propose(world, "pricing", name, "", run,
                                          sandbox_factory=_Sandbox, checker=checker(answer),
                                          repair_rounds=1, check_rounds=2)
        assert "python check_notes.py" in world.get_goal(calls[1]["goal_id"]).description
        assert "1.1" in briefs[-1] and "confirm" in briefs[-1]   # asked to confirm the fix
    silent, wrong, confirmed = outcomes.values()
    assert silent["check"]["findings"][0]["status"] == "fixed"
    assert features.UNCONFIRMED_GAP.format(n=1) in features.evidence(silent)["gaps"]
    assert wrong["check"]["findings"][0]["status"] == "still open"
    assert ("still open (its repro command passed on the repaired version, but the checker "
            "says it is still wrong)") in _line(wrong, "1.1")
    assert "fixed: its repro command passed on the repaired version (the author saw the " \
           "command); a later look confirmed it" in _line(confirmed, "1.1")
    assert not any("blocker" in g for g in features.evidence(confirmed)["gaps"])
    words = {p["title"]: p["check"] for p in features.summary(world)["proposals"]}
    assert words == {"silent": "open", "still wrong": "open", "confirmed": "clean"}


def test_only_checkers_that_looked_are_listed_with_their_own_errors(upstream, tmp_path):
    from maverick.budget import BudgetExceeded
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")

    def stub(model, action):
        def look(gid, copy):
            return action()
        look.model = model
        return look

    def stop():
        raise BudgetExceeded("tool calls")
    clean = {"findings": [], "fixed": []}
    run, _ = _rounds(_mended)
    p = features.propose(world, "pricing", "A", "", run, checker=[
        stub("openai:one", lambda: clean), stub("openai:two", stop),
        stub("openai:three", lambda: clean)])
    lines = features.evidence(p)["lines"]
    assert any(line.startswith("Checker 1 used openai:one") for line in lines)
    assert not any("Checker 3" in line or "Checker 2 used" in line for line in lines)

    def broken():
        raise RuntimeError("boom")
    run, _ = _rounds(_mended)
    q = features.propose(world, "pricing", "B", "", run, checker=[
        stub("openai:one", lambda: clean), stub("openai:two", broken)])
    lines = features.evidence(q)["lines"]
    assert "Checker 2 could not run (it stopped with RuntimeError)." in lines
    assert not any("A later check" in line for line in lines)


def test_on_a_root_host_the_image_runs_as_an_ordinary_user(tmp_path, monkeypatch):
    import os

    from maverick.sandbox import docker
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / ".maverick"))
    monkeypatch.setattr(docker.DockerBackend, "_verify_docker", lambda self: None)
    monkeypatch.setattr(features, "_host_is_root", lambda: True)
    box = features.image_sandbox("lw-check:1", str(tmp_path / "w"))
    flags = box._container_flags()
    assert flags[flags.index("--user") + 1] == features.IMAGE_USER == "1000:1000"
    copy = tmp_path / "copy"
    (copy / "pkg").mkdir(parents=True)
    (copy / "pkg" / "a.py").write_text("a = 1\n")
    (copy / "link").symlink_to(tmp_path / "outside")
    owned: list = []
    monkeypatch.setattr(os, "lchown", lambda path, uid, gid: owned.append((str(path), uid, gid)))
    monkeypatch.setattr(os, "chown", lambda *a, **k: pytest.fail("followed a link"))
    features._give_to_image_user(copy)
    assert {Path(p).name for p, _, _ in owned} == {"copy", "pkg", "a.py", "link"}
    assert {(uid, gid) for _, uid, gid in owned} == {(1000, 1000)}


def test_the_image_check_hands_over_a_subfolder_not_the_private_work_folder(monkeypatch):
    from types import SimpleNamespace

    from maverick.sandbox import ExecResult
    handed, boxed = [], []
    monkeypatch.setattr(features, "_host_is_root", lambda: True)
    monkeypatch.setattr(features, "_give_to_image_user", lambda path: handed.append(Path(path)))
    box = SimpleNamespace(exec=lambda cmd, timeout: ExecResult(stdout="", stderr="", exit_code=0))
    loop = SimpleNamespace(image="lw-check:1")
    loop._for_image = lambda path: features._Loop._for_image(loop, path)
    loop._box = lambda workdir: boxed.append(Path(workdir)) or box
    assert features._Loop._image_problem(loop) is None
    # The private lw-work-* folder stays root-only; only a folder inside it is handed over.
    assert handed == boxed and len(handed) == 1
    assert handed[0].parent.name.startswith("lw-work-")


# -- test tiers: quick while repairing, full and gate on the final candidate,
#    heavy only in the checker image --

class _Recording(_Sandbox):
    """The tests' sandbox, recording every command it runs on this computer."""
    ran: list = []

    def exec(self, cmd, timeout=None):
        type(self).ran.append(cmd)
        return super().exec(cmd, timeout)


def _recording():
    return type("Rec", (_Recording,), {"ran": []})


def _with_test(work):
    """A passing app.py, plus a changed test file the quick tier can select."""
    _passing(work)
    (work / "test_app.py").write_text((work / "test_app.py").read_text() + "\n# touched\n")


def _failing_with_test(work):
    _failing(work)
    (work / "test_app.py").write_text((work / "test_app.py").read_text() + "\n# touched\n")


def _tier_lines(p):
    return [line for line in features.evidence(p)["lines"]
            if line.split(":")[0] in ("Tests", "Quick tests", "Other checks",
                                      "Tests that need services")]


def test_the_quick_tier_runs_in_repairs_with_the_changed_paths(upstream, tmp_path):
    vault.register("pricing", str(upstream), test_command="python -m pytest -q",
                   quick_test_command="python -m pytest -q {changed}")
    world = WorldModel(tmp_path / "world.db")
    box = _recording()
    run, calls = _rounds(_failing_with_test, _with_test)
    p = features.propose(world, "pricing", "Discount", "", run, sandbox_factory=box,
                         repair_rounds=2)
    quick = "python -m pytest -q app.py test_app.py"
    # Quick after each author round; the full suite only once the quick tier passed.
    assert box.ran == [quick, quick, "python -m pytest -q"] and len(calls) == 2
    assert {t: v["state"] for t, v in p["tiers"].items()} == {
        "quick": "passed", "full": "passed", "gate": "not configured", "heavy": "not configured"}
    assert p["tests"]["passed"] and features.evidence(p)["gaps"] == [features._UNCHECKED_GAP]
    assert _tier_lines(p)[:2] == [
        "Tests: PASSED. Lightwork ran `python -m pytest -q` on the exact version you are approving.",
        "Quick tests: passed on the version you are approving "
        "(`python -m pytest -q {changed}`)."]


def test_quick_tests_that_pass_but_a_failing_full_suite_go_back_to_the_author(upstream,
                                                                             tmp_path):
    vault.register("pricing", str(upstream), test_command="python -m pytest -q",
                   quick_test_command="python -c pass")
    world = WorldModel(tmp_path / "world.db")
    box = _recording()
    run, calls = _rounds(_failing, _passing)
    p = features.propose(world, "pricing", "Discount", "", run, sandbox_factory=box,
                         repair_rounds=2)
    assert box.ran == ["python -c pass", "python -m pytest -q"] * 2 and len(calls) == 2
    repair = world.get_goal(calls[1]["goal_id"]).description
    assert "The test command `python -m pytest -q` failed" in repair
    assert [r["kind"] for r in p["rounds"]] == ["author", "tests"]
    assert p["tests"]["passed"] and p["repair_rounds"]["used"] == 1


def test_a_failing_gate_goes_back_to_the_author(upstream, tmp_path):
    vault.register("pricing", str(upstream), test_command="python -m pytest -q",
                   gate_command="python lint.py")
    world = WorldModel(tmp_path / "world.db")
    box = _recording()

    def sloppy(work):
        _passing(work)
        (work / "lint.py").write_text("raise SystemExit('style problem in app.py')\n")

    def tidy(work):
        (work / "lint.py").write_text("pass\n")
    run, calls = _rounds(sloppy, tidy)
    p = features.propose(world, "pricing", "Discount", "", run, sandbox_factory=box,
                         repair_rounds=2)
    assert box.ran == ["python -m pytest -q", "python lint.py"] * 2 and len(calls) == 2
    repair = world.get_goal(calls[1]["goal_id"]).description
    assert "The gate command `python lint.py` failed" in repair and "style problem" in repair
    assert "python lint.py" in world.get_goal(p["goal_id"]).description   # the author knew
    assert [r["kind"] for r in p["rounds"]] == ["author", "gate"]
    assert p["tiers"]["gate"]["state"] == "passed" and features.evidence(p)["gaps"] == [features._UNCHECKED_GAP]


def test_a_full_suite_the_budget_stopped_never_reads_as_passing(upstream, tmp_path):
    from maverick.budget import Budget
    vault.register("pricing", str(upstream), test_command="python -m pytest -q",
                   quick_test_command="python -c pass")
    world = WorldModel(tmp_path / "world.db")
    budget = Budget(max_tool_calls=1)

    class CostlyQuick(_Recording):
        ran: list = []

        def exec(self, cmd, timeout=None):
            budget.tool_calls += 1                              # the quick run tips it over
            return super().exec(cmd, timeout)

    def spend(work):
        budget.tool_calls = 1                                   # at the cap, not over it
        _passing(work)
    run, _ = _rounds(spend)
    p = features.propose(world, "pricing", "Discount", "", run, budget=budget,
                         sandbox_factory=CostlyQuick, repair_rounds=2)
    assert CostlyQuick.ran == ["python -c pass"]                # the full suite never ran
    assert p["tiers"]["quick"]["state"] == "passed"
    assert p["tiers"]["full"] == {"state": "not run", "reason": "the spending limit ran out",
                                  "command": "python -m pytest -q", "exit_code": None}
    assert p["tests"]["passed"] is False and p["tests"]["ran"] is False
    card = _card(world, p)
    text = " ".join(card["parameter_summary"])
    assert "PASSED" not in text and "Tests: not run on the version you are approving " \
        "(the spending limit ran out)." in text
    assert features.QUICK_ONLY_LINE in card["parameter_summary"]
    assert features._TESTS_GAP in card["unresolved_assumptions"]
    row = features.summary(world)["proposals"][0]
    assert row["tests"] is False and row["tests_ran"] is False and row["gaps"] >= 1


def test_heavy_tests_without_the_checker_image_do_not_run(upstream, tmp_path):
    vault.register("pricing", str(upstream), test_command="python -m pytest -q",
                   heavy_test_command="python -m pytest -q -m postgres")
    world = WorldModel(tmp_path / "world.db")
    box = _recording()
    run, _ = _rounds(_passing)
    p = features.propose(world, "pricing", "Discount", "", run, sandbox_factory=box)
    assert box.ran == ["python -m pytest -q"]                   # never on this computer
    assert p["tiers"]["heavy"]["state"] == "not run"
    assert p["tiers"]["heavy"]["reason"] == features.NEEDS_IMAGE
    assert "Tests that need services: not run (needs the checker image)." in _tier_lines(p)
    assert ("Tests that need services did not run on the version you are approving "
            "(needs the checker image).") in _card(world, p)["unresolved_assumptions"]
    assert "tests that need services not run (needs the checker image)" in \
        features.tier_summary(p)


def test_heavy_tests_run_in_the_checker_image_on_the_final_commit(upstream, tmp_path,
                                                                  monkeypatch):
    vault.register("pricing", str(upstream), test_command="python -m pytest -q",
                   heavy_test_command="python -m pytest -q -m postgres")
    world = WorldModel(tmp_path / "world.db")
    _settings(monkeypatch, checker_image="lw-check:1")
    in_image: list = []

    class Image:
        def __init__(self, workdir):
            self.workdir = workdir

        def exec(self, cmd, timeout=None):
            app = Path(self.workdir) / "app.py"
            in_image.append((cmd, app.read_text() if app.exists() else ""))
            return type("R", (), {"stdout": "1 passed", "stderr": "", "exit_code": 0})()
    monkeypatch.setattr(features, "image_sandbox", lambda image, workdir: Image(workdir))
    box = _recording()
    run, _ = _rounds(_passing)
    p = features.propose(world, "pricing", "Discount", "", run, sandbox_factory=box)
    assert box.ran == ["python -m pytest -q"]                   # the heavy tier never ran here
    assert [cmd for cmd, _ in in_image] == ["true", "python -m pytest -q -m postgres"]
    assert "def discount" in in_image[1][1]                     # on a copy of the final commit
    assert p["tiers"]["heavy"]["state"] == "passed" and features.evidence(p)["gaps"] == [features._UNCHECKED_GAP]
    assert "1 passed" in p["tests_output"]


def test_a_repository_record_from_before_tiers_still_loads(upstream, tmp_path):
    import json
    vault.register("pricing", str(upstream), test_command="python -m pytest -q")
    path = vault._registry_path()
    registry = json.loads(path.read_text())
    for key in ("quick_test_command", "gate_command", "heavy_test_command"):
        del registry["pricing"][key]                            # as the earlier release wrote it
    path.write_text(json.dumps(registry))
    repo = vault.get("pricing")
    assert repo.test_command == "python -m pytest -q" and repo.quick_test_command is None
    assert [r.name for r in vault.list_repos()] == ["pricing"]
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(_passing)
    p = features.propose(world, "pricing", "Discount", "", run, sandbox_factory=_Sandbox)
    assert p["tests"]["passed"] and p["tiers"]["quick"] == {"state": "not configured"}
    assert vault.set_commands("pricing", gate_command="python -c pass").gate_command
    with pytest.raises(vault.VaultError, match="only the quick test command"):
        vault.set_commands("pricing", test_command="pytest {changed}")


def test_a_workspace_cannot_change_a_repositorys_commands(upstream, tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick import config, paths
    from maverick.cli import main
    monkeypatch.setattr(config, "get_codebase",
                        lambda: {"enable": True, "default_protect": "block"})
    run = CliRunner().invoke
    out = run(main, ["code", "add", "pricing", str(upstream), "--test", "python -m pytest -q",
                     "--quick-test", "python -m pytest -q {changed}"])
    assert out.exit_code == 0, out.output
    out = run(main, ["code", "set", "pricing", "--gate", "python lint.py", "--quick-test", ""])
    assert out.exit_code == 0 and "gate   python lint.py" in out.output, out.output
    assert "quick  (not set)" in out.output
    token = paths.set_tenant("team-a")                          # a workspace's own scope
    try:
        with pytest.raises(vault.VaultError, match="no repository"):
            vault.set_commands("pricing", test_command="true")
        assert run(main, ["code", "set", "pricing", "--test", "true"]).exit_code != 0
    finally:
        paths.reset_tenant(token)
    repo = vault.get("pricing")
    assert (repo.test_command, repo.quick_test_command, repo.gate_command) == (
        "python -m pytest -q", None, "python lint.py")


# -- test tiers, repair round 1: what {changed} holds, what a command may
#    contain, and output from earlier versions --

def test_changed_paths_leave_out_deleted_and_renamed_away_files(upstream, tmp_path):
    vault.register("pricing", str(upstream), test_command="python -m pytest -q",
                   quick_test_command="python check_paths.py {changed}")
    world = WorldModel(tmp_path / "world.db")
    box = _recording()

    def rename_and_note(work):
        _passing(work)
        (work / "test_app.py").rename(work / "test_price.py")
        (work / "NOTES.md").write_text("notes\n")
        # Fails on any path that is not in the copy (a deleted or renamed-away file).
        (work / "check_paths.py").write_text(
            "import os, sys\nsys.exit(0 if all(os.path.exists(p) for p in sys.argv[1:]) else 1)\n")
    run, calls = _rounds(rename_and_note)
    p = features.propose(world, "pricing", "Rename", "", run, sandbox_factory=box,
                         repair_rounds=2)
    assert box.ran[0] == "python check_paths.py NOTES.md app.py check_paths.py test_price.py"
    assert len(calls) == 1 and p["tiers"]["quick"]["state"] == "passed"
    assert p["tiers"]["full"]["state"] == "passed"


def test_a_command_must_be_plain_text_with_an_unquoted_placeholder(upstream):
    vault.register("pricing", str(upstream))
    for bad in ('pytest "{changed}"', "pytest '{changed}'", 'run "a {changed} b"'):
        with pytest.raises(vault.VaultError, match="not inside quotes"):
            vault.set_commands("pricing", quick_test_command=bad)
    for bad in ("pytest -q\nrm -rf x", "pytest\t-q", "pytest\x1b[2J", "pytest\x85",
                "pytest ‮q-", "pytest ⁦x⁩", "pytest\x7f", "pytest\u2028x", " pytest\t"):
        with pytest.raises(vault.VaultError, match="plain text"):
            vault.set_commands("pricing", test_command=bad)
    ok = vault.set_commands("pricing", quick_test_command="x 'a b' \"c\" {changed} 'it''s'")
    assert ok.quick_test_command.endswith("{changed} 'it''s'")


def test_test_output_shown_is_only_from_the_final_version():
    from types import SimpleNamespace
    repo = vault.Repo("pricing", "src", "main", test_command="python -m pytest -q",
                      quick_test_command="python -c pass")
    loop = SimpleNamespace(repo=repo, head="b" * 40, stopped=None, results={
        "quick": {"command": "python -c pass", "commit": "b" * 40, "passed": True,
                  "exit_code": 0, "output": "quick ok"},
        "full": {"command": "python -m pytest -q", "commit": "a" * 40, "passed": True,
                 "exit_code": 0, "output": "3 passed"}})
    loop._why_not = lambda result: features._Loop._why_not(loop, result)
    tests, tiers, output = features._Loop.tier_record(loop)
    assert tiers["full"]["state"] == "not run" and tests["ran"] is False
    assert "quick ok" in output and "3 passed" not in output   # never an earlier version's run


# -- the governed factory: protected paths, a second cross-family checker,
#    two people to approve, and not changing the Lightwork that runs it --

def test_protected_path_patterns_are_checked_and_matched(upstream, monkeypatch):
    import json

    from click.testing import CliRunner
    from maverick import config
    from maverick.cli import main
    check = vault.check_protected_paths
    assert check(["/.github/", "./src/**/*.py", "  ", ".github"]) == (".github", "src/**/*.py")
    for bad in (["a/../b"], ["a\\b"], ["a\nb"], ["x" * 301], "a", [3], ["a//b"]):
        with pytest.raises(vault.VaultError, match="protected paths"):
            check(bad)
    match = vault.protected_matches
    paths = [".github/workflows/ci.yml", "src/a/b/c.py", "src/c.txt", "README.md", "docs/x.md"]
    assert match([".github"], paths) == [".github/workflows/ci.yml"]   # a folder covers its files
    assert match(["src/**/*.py"], paths) == ["src/a/b/c.py"]
    assert match(["*.md"], paths) == ["README.md"]                     # * stays in one folder
    assert match(["**/*.MD"], paths) == ["README.md", "docs/x.md"]     # case is ignored
    # A record saved before protected paths loads with none; the CLI sets them.
    vault.register("pricing", str(upstream))
    registry = json.loads(vault._registry_path().read_text())
    del registry["pricing"]["protected_paths"]
    vault._registry_path().write_text(json.dumps(registry))
    assert vault.get("pricing").protected_paths == ()
    monkeypatch.setattr(config, "get_codebase", lambda: {"enable": True, "default_protect": "block"})
    run = CliRunner().invoke
    out = run(main, ["code", "set", "pricing", "--protected-path", ".github",
                     "--protected-path", "app.py"])
    assert out.exit_code == 0 and "protected paths: .github, app.py" in out.output, out.output
    assert run(main, ["code", "set", "pricing", "--protected-path", "../x"]).exit_code != 0
    assert vault.get("pricing").protected_paths == (".github", "app.py")
    out = run(main, ["code", "set", "pricing", "--protected-path", ""])
    assert out.exit_code == 0 and "protected paths: (none)" in out.output


def test_the_factory_settings_are_read_strictly(tmp_path, monkeypatch):
    from maverick import config
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_CONFIG", raising=False)

    def read(text):
        (tmp_path / "config.toml").write_text(text, encoding="utf-8")
        config.reset_config_cache()
        got = config.get_codebase()
        return got["allow_self_changes"], got["protected_checker_model"]
    try:
        assert read("") == (False, "")
        assert read('[codebase]\nallow_self_changes = true\nprotected_checker_model = " openai:m "\n') \
            == (True, "openai:m")
        assert read('[codebase]\nallow_self_changes = "yes"\n') == (False, "")   # not a real switch
        config.dashboard_overrides_path().write_text("[broken\n", encoding="utf-8")
        assert read("[codebase]\nallow_self_changes = true\n")[0] is False  # a source is unreadable
    finally:
        config.reset_config_cache()


def _second(model="openai:gpt-second", report=None, charge=None):
    """A stand-in for the second checker: records each look; ``charge`` is the
    budget it spends from, as the real one does."""
    calls = []

    def look(gid, copy):
        calls.append((gid, copy))
        if charge is not None:
            charge.record_tool_call()
        return report or {"findings": []}
    look.model = model
    return look, calls


def _protected_repo(upstream, monkeypatch, patterns=("app.py",)):
    monkeypatch.setattr(features, "_author_model", lambda: "anthropic:claude-author")
    return vault.register("pricing", str(upstream), protected_paths=list(patterns))


def test_a_rename_into_or_out_of_a_protected_path_is_protected(upstream, tmp_path, monkeypatch):
    _protected_repo(upstream, monkeypatch, patterns=("app.py", "secure"))
    world = WorldModel(tmp_path / "world.db")
    second, _ = _second()

    def out_of(work):                                           # app.py -> lib/app.py
        (work / "lib").mkdir()
        (work / "app.py").rename(work / "lib" / "app.py")

    def into(work):                                             # test_app.py -> secure/
        (work / "secure").mkdir()
        (work / "test_app.py").rename(work / "secure" / "test_app.py")
    for edit, matched in ((out_of, ["app.py"]), (into, ["secure/test_app.py"])):
        run, _ = _rounds(edit)
        p = features.propose(world, "pricing", "Move", "", run, protected_checker=second,
                             owner="user:starter")
        assert p["protected"]["paths"] == matched, p["files"]
        facts = features.evidence(p)
        assert facts["lines"][0] == features.PROTECTED_LINE.format(n=1)
        assert f"Protected paths changed: {matched[0]}." in facts["lines"]
        card = _card(world, p)
        assert card["parameter_summary"][0] == features.PROTECTED_LINE.format(n=1)
        appr = world.get_approval(p["approval_id"])
        assert (appr.approvals_required, appr.requested_by, appr.provenance) == (
            2, "user:starter", features.PROTECTED_PROVENANCE)
    run, _ = _rounds(lambda work: (work / "notes.md").write_text("idea\n"))
    plain = features.propose(world, "pricing", "Notes", "", run, protected_checker=second,
                             owner="user:starter")
    appr = world.get_approval(plain["approval_id"])
    assert plain["protected"] is None and appr.approvals_required == 1
    assert (appr.requested_by, appr.provenance) == ("agent:codebase", "codebase")


def test_the_second_checker_runs_only_for_protected_changes_and_is_charged(upstream, tmp_path,
                                                                            monkeypatch):
    from maverick.budget import Budget
    _protected_repo(upstream, monkeypatch)
    world = WorldModel(tmp_path / "world.db")
    budget = Budget(max_tool_calls=10)
    finding = {"findings": [{"severity": "blocker", "what": "the price can go negative"}]}
    second, calls = _second(report=finding, charge=budget)
    normal = lambda gid, copy: {"findings": []}  # noqa: E731
    normal.model = "gemini:gemini-normal"
    run, _ = _rounds(lambda work: (work / "notes.md").write_text("idea\n"))
    features.propose(world, "pricing", "Notes", "", run, checker=normal,
                     protected_checker=second, budget=budget)
    assert calls == []                                         # not protected: never runs
    run, _ = _rounds(_passing)
    p = features.propose(world, "pricing", "Discount", "", run, checker=normal,
                         protected_checker=second, budget=budget, owner="user:starter")
    assert len(calls) == 1 and budget.tool_calls == 1          # charged to the run's budget
    gid, copy = calls[0]
    assert "Protected check" in world.get_goal(gid).title and not copy.exists()
    assert p["protected"]["state"] == "ran" and p["protected"]["commit"] == p["head"]
    facts = features.evidence(p)
    assert "1 blocker(s) from the second checker are still open." in facts["gaps"]
    assert any("Finding p.1 from the second checker, blocker" in f for f in facts["findings"])
    assert features.protected_refusal(p) is None and p["approval_id"]
    # With the budget spent, the second checker does not run: it cannot be approved.
    run, _ = _rounds(_passing)
    second, calls = _second()
    spent = Budget(max_tool_calls=1)

    def normal_spends(gid, copy):
        spent.tool_calls = 5
        return {"findings": []}
    normal_spends.model = "gemini:gemini-normal"
    q = features.propose(world, "pricing", "Discount", "", run, checker=normal_spends,
                         protected_checker=second, budget=spent, owner="user:starter")
    assert calls == [] and q["approval_id"] is None
    assert features.protected_refusal(q) == features.NOT_LOOKED.format(
        reason=features.BUDGET_REASON)
    assert features.status(world, q) == "blocked"


def test_an_unset_or_same_family_second_checker_cannot_be_approved(upstream, tmp_path,
                                                                   monkeypatch):
    _protected_repo(upstream, monkeypatch)
    world = WorldModel(tmp_path / "world.db")
    normal = lambda gid, copy: {"findings": []}  # noqa: E731
    normal.model = "gemini:gemini-normal"
    for second, problem in ((None, "unset"),
                            (_second("anthropic:claude-other")[0], "same_family"),      # the author's
                            (_second("gemini:gemini-other")[0], "same_family"),         # a checker's
                            (_second("openai:gpt-x")[0], None)):
        run, _ = _rounds(_passing)
        p = features.propose(world, "pricing", "Discount", "", run, checker=normal,
                             protected_checker=second, owner="user:starter")
        assert p["protected"]["problem"] == problem
        if problem is None:
            assert p["approval_id"] and features.status(world, p) == "pending"
            continue
        sentence = features.PROTECTED_REFUSALS[problem]
        assert p["approval_id"] is None and features.status(world, p) == "blocked"
        assert sentence in features.evidence(p)["lines"] and sentence in features.evidence(p)["gaps"]
        with pytest.raises(vault.VaultError) as refused:
            features.request_approval(world, p)
        assert str(refused.value) == sentence


def _protected_proposal(upstream, tmp_path, monkeypatch, world=None):
    if world is None:
        _protected_repo(upstream, monkeypatch)
        world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(_passing)
    p = features.propose(world, "pricing", "Discount", "", run,
                         protected_checker=_second()[0], owner="user:starter")
    return world, p


def test_a_protected_change_needs_two_distinct_people_never_the_starter(upstream, tmp_path,
                                                                        monkeypatch):
    monkeypatch.delenv("MAVERICK_ALLOW_SELF_APPROVAL", raising=False)
    world, p = _protected_proposal(upstream, tmp_path, monkeypatch)
    aid = p["approval_id"]
    assert world.decide_approval(aid, "approved", decided_by="user:starter") is False
    assert world.decide_approval(aid, "approved", decided_by="user:alice")
    assert world.decide_approval(aid, "approved", decided_by="user:alice")  # once, not twice
    assert features.status(world, features.find(p["id"])) == "pending"
    for act in (features.merge, features.push):
        with pytest.raises(vault.VaultError, match="must approve"):
            act(world, p["id"])
    # Even where the starter's own vote is let through, or an agent's, they never count.
    monkeypatch.setenv("MAVERICK_ALLOW_SELF_APPROVAL", "1")
    for other in ("user:starter", "agent:helper"):
        _, q = _protected_proposal(upstream, tmp_path, monkeypatch, world=world)
        world.decide_approval(q["approval_id"], "approved", decided_by="user:alice")
        world.decide_approval(q["approval_id"], "approved", decided_by=other)
        assert features.status(world, features.find(q["id"])) == "approved"
        for act in (features.merge, features.push):
            with pytest.raises(vault.VaultError) as refused:
                act(world, q["id"])
            assert str(refused.value) == features.TWO_PEOPLE
    monkeypatch.delenv("MAVERICK_ALLOW_SELF_APPROVAL")
    world.decide_approval(aid, "approved", decided_by="user:bob")
    assert features.status(world, features.find(p["id"])) == "approved"
    assert features.merge(world, p["id"])["status"] == "merged"
    assert features.push(world, p["id"]) == p["branch"]


def test_every_chat_channel_needs_two_distinct_people_never_an_agent(upstream, tmp_path,
                                                                     monkeypatch):
    """Slack, Teams and email decide through decide_from_channel, and the
    Approvals page and Copilot through record_vote: one shared vote path."""
    import maverick.audit as audit
    from maverick.approval_cards import decode_approval_detail
    from maverick.channel_approvals import (
        CODE_PERSON_ONLY,
        ChannelApprovalRefused,
        decide_from_channel,
        record_vote,
    )
    monkeypatch.setattr(audit, "record", lambda kind, **fields: True)
    monkeypatch.delenv("MAVERICK_ALLOW_SELF_APPROVAL", raising=False)
    world, p = _protected_proposal(upstream, tmp_path, monkeypatch)
    aid = p["approval_id"]
    binding = decode_approval_detail(world.get_approval(aid).detail)["binding_sha256"]

    def vote(who, channel):
        return decide_from_channel(world, aid, "approved", principal=who, channel=channel,
                                   binding=binding, confirmed=True, acknowledged=True)
    for channel in ("slack", "teams", "email"):
        with pytest.raises(ChannelApprovalRefused) as refused:
            vote("user:starter", channel)                       # the person who started it
        assert refused.value.reason == "separate_approver"
    for who in ("agent:helper", "operator"):                    # an agent, or no named person
        with pytest.raises(ChannelApprovalRefused) as refused:
            record_vote(world, aid, "approved", who)
        assert refused.value.message == CODE_PERSON_ONLY
    assert vote("user:alice", "slack")["status"] == "pending"
    assert vote("user:alice", "teams")["approved_count"] == 1   # one person twice counts once
    assert features.status(world, features.find(p["id"])) == "pending"
    assert vote("user:bob", "email")["status"] == "approved"
    assert features.merge(world, p["id"])["status"] == "merged"
    # An ordinary code change keeps one approval, but never an agent's.
    run, _ = _rounds(lambda work: (work / "notes.md").write_text("idea\n"))
    plain = features.propose(world, "pricing", "Notes", "", run, owner="user:starter")
    with pytest.raises(ChannelApprovalRefused):
        record_vote(world, plain["approval_id"], "approved", "agent:helper")
    record_vote(world, plain["approval_id"], "approved", "operator")


# -- a feature-run step that asks a person to decide --

def _ask(world, goal_id, question):
    from maverick import decision_requests
    world.set_goal_status(goal_id, "blocked")
    return decision_requests.request(
        world, goal_id, question=question, area="security", recommended=1,
        reason="It changes who can sign in.",
        options=[{"label": "Keep it", "effect": "Nothing changes."},
                 {"label": "Change it", "effect": "Sign-in changes."}])


def test_an_author_that_asks_for_a_decision_stops_the_run(upstream, tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick import config, decision_requests, orchestrator
    from maverick.budget import Budget
    from maverick.chat_threads import ChatThreads
    from maverick.cli import main
    monkeypatch.setattr(decision_requests, "_announce", lambda world, decision: None)
    vault.register("pricing", str(upstream), test_command="python -m pytest -q")
    world = WorldModel(tmp_path / "world.db")
    budget = Budget(max_tool_calls=10)
    asked = {}

    def author(goal_id, work):
        _passing(work)
        budget.record_tool_call()
        assert decision_requests.resume_refusal(world, goal_id) == ""   # its own run starts
        step = world.create_goal("step", "deep", parent_id=goal_id, owner="user:starter")
        world.set_goal_status(goal_id, "blocked")
        asked["root"], asked["d"] = goal_id, _ask(world, step, "May the change turn off sign-in?")
    checks = []
    p = features.propose(world, "pricing", "Discount", "", author, sandbox_factory=_Sandbox,
                         checker=lambda gid, copy: checks.append(gid) or {"findings": []},
                         owner="user:starter", budget=budget)
    d, root = asked["d"], asked["root"]
    assert p["status"] == "decision" and p["approval_id"] is None and checks == []
    assert p["head"] == p["base"] and p["files"] == []        # its half-done round never committed
    assert budget.tool_calls == 1                              # what it spent stays charged
    facts = features.evidence(p)
    assert facts["lines"][0] == ("Waiting for a person's decision: “May the change turn off "
                                 "sign-in?”. Answer it on the Approvals page or with maverick "
                                 f"decisions answer {d.id}, then start a new code change.")
    assert features.DECISION_GAP in facts["gaps"]
    assert features.status(world, features.find(p["id"])) == "decision"
    with pytest.raises(vault.VaultError, match="wait for a person's decision"):
        features.request_approval(world, features.find(p["id"]))
    assert world.get_goal(d.goal_id).status == "blocked"      # not failed: it can be answered
    # No restart path takes the paused round back up outside its private copy.
    assert decision_requests.resume_refusal(world, root) == decision_requests.FEATURE_RESTARTS
    with pytest.raises(Exception, match="step of a code change"):
        ChatThreads(world).resume(root)
    assert orchestrator._decision_start_refusal(world, root).endswith(
        decision_requests.FEATURE_RESTARTS)
    monkeypatch.setattr(config, "get_codebase", lambda: {"enable": True})
    monkeypatch.setattr("maverick.cli.open_world", lambda *a, **k: world, raising=False)
    out = CliRunner().invoke(main, ["resume", "--goal-id", str(root)])
    assert out.exit_code == 2 and "step of a code change" in out.output, out.output
    # The answer is saved, but it never restarts the step: the step stops for good.
    outcome = decision_requests.answer(world, d.id, 2, actor="user:starter", is_admin=True)
    assert outcome["resume"] is False and outcome["next"] == "manual"
    assert outcome["restart"] == decision_requests.FEATURE_RESTARTS
    step = world.get_goal(d.goal_id)
    assert step.status == "cancelled" and step.result == decision_requests.FEATURE_RESTARTS
    # An origin that cannot be read refuses the restart.
    monkeypatch.setattr(world, "tenant_query", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    assert decision_requests.resume_refusal(world, root) == \
        decision_requests.FEATURE_UNKNOWN_RESTART


def test_a_checker_that_asks_for_a_decision_could_not_run(upstream, tmp_path, monkeypatch):
    from maverick import decision_requests
    monkeypatch.setattr(decision_requests, "_announce", lambda world, decision: None)
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(_passing)

    def checker(gid, copy):
        _ask(world, gid, "Should I report the pricing rule as a problem?")
        return {"findings": []}                               # never read as a clean look
    p = features.propose(world, "pricing", "Discount", "", run, checker=checker)
    assert p["status"] == "decision" and p["approval_id"] is None
    assert p["check"]["state"] == "failed" and p["check"]["error"] == features.ASKED_REASON
    lines = features.evidence(p)["lines"]
    assert lines[0].startswith("Waiting for a person's decision: “Should I report the pricing")
    assert f"Independent check: could not run ({features.ASKED_REASON})." in lines
    assert features.summary(world)["proposals"][0]["check"] == "failed"


def test_a_round_whose_decision_was_answered_before_it_paused_still_stops(upstream, tmp_path,
                                                                           monkeypatch):
    from maverick import decision_requests
    monkeypatch.setattr(decision_requests, "_announce", lambda world, decision: None)
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")

    def author(goal_id, work):
        _passing(work)
        world.set_goal_status(goal_id, "active")
        d = _ask(world, goal_id, "Which way?")
        world.set_goal_status(goal_id, "active")               # the answer lands before the pause
        decision_requests.answer(world, d.id, 1, actor="user:starter", is_admin=True)
    p = features.propose(world, "pricing", "Discount", "", author, owner="user:starter")
    assert p["status"] == "decision" and p["head"] == p["base"] and p["approval_id"] is None
    assert features.evidence(p)["lines"][0] == (
        "A person was asked to decide “Which way?” before this step could finish. "
        "Start a new code change to use the answer.")


# -- not changing the Lightwork that runs the factory --

def test_the_installations_own_repository_is_refused_then_protected(upstream, tmp_path,
                                                                    monkeypatch):
    install = tmp_path / "install"                             # a source checkout of it
    subprocess.run(["git", "clone", "-q", str(upstream), str(install)], check=True)
    package = install / "packages" / "maverick-core" / "maverick"
    package.mkdir(parents=True)
    assert features._installation_checkout(package) == install
    wheel = install / ".venv" / "lib" / "python3.12" / "site-packages" / "maverick"
    wheel.mkdir(parents=True)
    assert features._installation_checkout(wheel) is None      # a wheel in its venv is not
    monkeypatch.setattr(features, "_installation_checkout", lambda package_dir=None: install)
    monkeypatch.setattr(features, "_author_model", lambda: "anthropic:claude-author")
    world = WorldModel(tmp_path / "world.db")
    mirror = tmp_path / "mirror.git"                            # same history, another address
    subprocess.run(["git", "clone", "-q", "--bare", str(upstream), str(mirror)], check=True)
    vault.register("pricing", str(upstream))
    vault.register("mirror", str(mirror))
    other = tmp_path / "other"
    other.mkdir()
    _sh("init", "-q", "-b", "main", cwd=other)
    (other / "x.py").write_text("x = 1\n")
    _sh("add", "-A", cwd=other)
    _sh("commit", "-q", "-m", "other", cwd=other)
    vault.register("other", str(other))
    for name in ("pricing", "mirror"):
        assert features.self_change_refusal(name) == features.SELF_REFUSAL
        run, calls = _rounds(_passing)
        with pytest.raises(vault.VaultError) as refused:
            features.propose(world, name, "Discount", "", run)
        assert str(refused.value) == features.SELF_REFUSAL and calls == []
    assert features.self_change_refusal("other") is None
    # Allowed by the organisation: every such change is protected, whole repository.
    _settings(monkeypatch, allow_self_changes=True)
    assert features.self_change_refusal("pricing") is None
    run, _ = _rounds(lambda work: (work / "notes.md").write_text("idea\n"))
    p = features.propose(world, "pricing", "Notes", "", run, protected_checker=_second()[0],
                         owner="user:starter")
    assert p["protected"]["self"] is True and p["protected"]["paths"] == []
    assert features.evidence(p)["lines"][0] == features.SELF_LINE
    assert world.get_approval(p["approval_id"]).approvals_required == 2


def test_copilot_words_say_what_a_protected_change_still_needs(upstream, tmp_path, monkeypatch):
    monkeypatch.delenv("MAVERICK_ALLOW_SELF_APPROVAL", raising=False)
    world, p = _protected_proposal(upstream, tmp_path, monkeypatch)
    said = features.protected_status(world, p)
    assert said.startswith("Protected, because it changes 1 protected path(s).")
    assert "0 of 2 so far" in said and "openai:gpt-second, looked at this version" in said
    world.decide_approval(p["approval_id"], "approved", decided_by="user:alice")
    assert "1 of 2 so far" in features.protected_status(world, p)


# -- repair round 1 --

def test_protection_is_checked_again_when_merging_pushing_and_renewing(upstream, tmp_path,
                                                                        monkeypatch):
    monkeypatch.setattr(features, "_author_model", lambda: "anthropic:claude-author")
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(_passing)
    p = features.propose(world, "pricing", "Discount", "", run, owner="user:starter",
                         protected_checker=_second()[0])
    run, _ = _rounds(_passing)
    q = features.propose(world, "pricing", "Discount", "", run, owner="user:starter",
                         protected_checker=_second()[0])
    assert p["protected"] is None and q["protected"] is None
    vault.set_protected_paths("pricing", ["app.py"])           # an administrator adds a path
    assert world.decide_approval(p["approval_id"], "approved", decided_by="user:starter")
    for act in (features.merge, features.push):
        with pytest.raises(vault.VaultError) as refused:
            act(world, p["id"])
        assert str(refused.value) == features.NEWLY_PROTECTED
    stored = features._load("pricing", q["id"])
    stored["approval_id"] = None                                # its approval failed to park
    features._save(stored)
    with pytest.raises(vault.VaultError) as refused:
        features.request_approval(world, features.find(q["id"]))
    assert str(refused.value) == features.NEWLY_PROTECTED
    assert "lightwork/" not in subprocess.run(["git", "branch"], cwd=upstream,
                                              capture_output=True, text=True).stdout


def test_a_protected_change_with_no_named_starter_cannot_be_approved(upstream, tmp_path,
                                                                     monkeypatch):
    _protected_repo(upstream, monkeypatch)
    world = WorldModel(tmp_path / "world.db")
    second, calls = _second()
    for owner in ("", "operator"):                             # the command line; no sign-in
        run, _ = _rounds(_passing)
        p = features.propose(world, "pricing", "Discount", "", run, protected_checker=second,
                             owner=owner)
        assert p["approval_id"] is None and features.status(world, p) == "blocked"
        assert features.protected_refusal(p) == features.NO_STARTER
        lines = features.evidence(p)["lines"]
        assert features.NO_STARTER in lines and features.TWO_PEOPLE not in lines
    assert calls == []                                         # no second check it cannot use
    # The command line passes no starter at all; the card says so plainly.
    from click.testing import CliRunner
    from maverick import config
    from maverick.cli import main
    monkeypatch.setattr(config, "get_codebase", lambda: {"enable": True})
    monkeypatch.setattr("maverick.cli._require_llm_key", lambda: None)
    monkeypatch.setattr("maverick.cli.open_world", lambda *a, **k: world)
    seen = {}
    monkeypatch.setattr(features, "propose", lambda *a, **k: seen.update(k) or {
        "status": "empty", "id": "0" * 16})
    assert CliRunner().invoke(main, ["code", "feature", "pricing", "T"]).exit_code == 0
    assert "owner" not in seen                                  # no named person is passed
    assert "command line" in features.NO_STARTER


@pytest.mark.skipif(not hasattr(__import__("os"), "geteuid") or __import__("os").geteuid() != 0,
                    reason="needs root to give the checkout to another user")
def test_an_installation_owned_by_another_user_is_still_recognised(upstream, tmp_path,
                                                                   monkeypatch):
    install = tmp_path / "install"
    subprocess.run(["git", "clone", "-q", str(upstream), str(install)], check=True)
    _sh("remote", "set-url", "origin", "https://example.invalid/other/fork.git", cwd=install)
    vault.register("pricing", str(upstream))
    monkeypatch.setattr(features, "_installation_checkout", lambda package_dir=None: install)
    subprocess.run(["chown", "-R", "65534:65534", str(install)], check=True)  # git: "dubious"
    with vault.host_repo("pricing") as host:
        assert features.is_installation(vault.get("pricing"), host)   # by its first commit
        broken = install / "broken"
        (install / ".git").rename(broken)
        (install / ".git").write_text("gitdir: /nowhere\n")       # git cannot read it at all
        assert features.is_installation(vault.get("pricing"), host)   # unknown: fail closed


def test_the_second_checker_family_reads_through_gateways(upstream, tmp_path, monkeypatch):
    family = features.model_family
    for model in ("anthropic:claude-x", "openrouter:anthropic/claude-3.5", "claude-3-opus",
                  "bedrock:us.anthropic.claude-3-5-sonnet", "vertex:claude-sonnet-4",
                  "litellm:claude-haiku", "anthropic:claude-author"):
        assert family(model) == "anthropic", model
    assert family("openrouter:openai/gpt-4o") == family("openai:o3-mini") == "openai"
    assert family("vertex:gemini-2.5-pro") == family("gemini:gemini-other") == "google"
    # An unknown name never borrows its provider's family; a fine-tune reads as its base.
    for unknown in ("openai:my-ft", "anthropic:author-model", "gemini:other"):
        assert family(unknown) is None, unknown
    assert family("ft:gpt-4o-mini:acme::abc123") == family("openai:ft:gpt-4o:acme:x:1") == "openai"
    assert family("ollama:llama3.1") == family("openai:llama-3-70b") == "meta"
    for unknown in ("my-local", "ollama:my-model", "openrouter:some/thing",
                    "openrouter:metaculus-bot", "azure:phind",              # no anchored name
                    "openrouter:google/gemma-claude-distill",              # two vendors
                    "openrouter:deepseek/deepseek-r1-distill-llama-70b",
                    "openrouter:nousresearch/hermes-3-llama-3.1"):
        assert family(unknown) is None, unknown
    assert family("openai:commander-x") is None                  # "commander" is not "command"
    assert family("openrouter:x/command-a") == "cohere"
    assert family("groq:openai/gpt-oss-120b") == family("openai:o3") == "openai"
    _protected_repo(upstream, monkeypatch)                    # the author is anthropic:...
    world = WorldModel(tmp_path / "world.db")
    for model, problem in (("openrouter:anthropic/claude-3.5", "same_family"),
                           ("bedrock:anthropic.claude-v2", "same_family"),
                           ("vertex:claude-sonnet-4", "same_family"),
                           ("my-local", "uncompared")):
        run, _ = _rounds(_passing)
        second, calls = _second(model)
        p = features.propose(world, "pricing", "Discount", "", run, protected_checker=second,
                             owner="user:starter")
        assert p["protected"]["problem"] == problem and calls == [], model
        assert p["approval_id"] is None


def test_the_second_checker_never_fails_over_to_another_model(monkeypatch, tmp_path):
    from maverick import config, orchestrator, provider_failover
    from maverick import world_model as wm
    chains = {"provider_failover": {"chains": {"openai:second": ["anthropic:claude-x"]}}}
    monkeypatch.setattr(config, "load_config", lambda *a, **k: chains)
    assert provider_failover.fallback_models("openai:second") == ["anthropic:claude-x"]
    seen = []
    monkeypatch.setattr(orchestrator, "run_goal_sync", lambda *a, **k: seen.append(
        (k.get("orchestrator_model_override"), provider_failover.fallback_models("openai:second"))))
    monkeypatch.setattr(wm, "open_world", lambda: object())
    monkeypatch.setattr(wm, "close_world_if_owned", lambda world: None)
    monkeypatch.setattr(features, "checker_sandbox", lambda workdir: object())
    _settings(monkeypatch, protected_checker_model="openai:second")
    checker = features.default_protected_checker(budget=None)
    checker(1, tmp_path)
    normal = features.default_checker(budget=None, model="openai:second")
    normal(1, tmp_path)
    assert seen == [("openai:second", []), ("openai:second", ["anthropic:claude-x"])]


def test_a_protected_change_compares_the_models_that_served_it(upstream, tmp_path, monkeypatch):
    # An OpenAI author and a Gemini checker that could fail over to Anthropic
    # would make an Anthropic second checker's "different family" untrue: in a
    # repository with protected paths, every participant runs with no failover.
    from maverick import config, provider_failover
    chains = {"provider_failover": {"chains": {
        "openai:gpt-author": ["anthropic:claude-backup"],
        "gemini:gemini-normal": ["anthropic:claude-backup"]}}}
    monkeypatch.setattr(config, "load_config", lambda *a, **k: chains)
    _protected_repo(upstream, monkeypatch)
    monkeypatch.setattr(features, "_author_model", lambda: "openai:gpt-author")
    world = WorldModel(tmp_path / "world.db")
    served = []

    def serve(model):  # the configured model is down: a chain, when there is one, answers
        served.append((provider_failover.fallback_models(model) or [model])[0])
    run, _ = _rounds(lambda work: (serve("openai:gpt-author"), _passing(work)))

    def normal(gid, copy):
        serve("gemini:gemini-normal")
        return {"findings": []}
    normal.model = "gemini:gemini-normal"
    p = features.propose(world, "pricing", "Discount", "", run, checker=normal,
                         protected_checker=_second("anthropic:claude-second")[0],
                         owner="user:starter")
    assert p["protected"]["problem"] is None
    assert served == ["openai:gpt-author", "gemini:gemini-normal"]


def test_a_paused_step_is_never_restarted_outside_its_private_copy(upstream, tmp_path,
                                                                    monkeypatch):
    from click.testing import CliRunner
    from maverick import config, decision_requests, orchestrator
    from maverick.chat_threads import ChatThreads
    from maverick.cli import main
    monkeypatch.setattr(decision_requests, "_announce", lambda world, decision: None)
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    world.record_goal_origin(world.create_goal("scheduled", "x"), "schedule", "nightly")
    asked = {}

    def author(goal_id, work):
        _passing(work)
        step = world.create_goal("step", "deep", parent_id=goal_id, owner="user:starter")
        world.set_goal_status(goal_id, "blocked")
        asked["root"], asked["d"] = goal_id, [_ask(world, step, f"Question {i}?") for i in range(6)]
    p = features.propose(world, "pricing", "Discount", "", author, owner="user:starter")
    assert len(p["decision"]) == 6                              # every decision is held
    root = asked["root"]
    for d in asked["d"][:-1]:
        decision_requests.answer(world, d.id, 1, actor="user:starter", is_admin=True)
    last = decision_requests.answer(world, asked["d"][-1].id, 1, actor="user:starter",
                                    is_admin=True)
    assert last["resume"] is False and last["restart"] == decision_requests.FEATURE_RESTARTS
    step = world.get_goal(asked["d"][0].goal_id)
    assert step.status == "cancelled" and step.result == decision_requests.FEATURE_RESTARTS
    # No restart path takes the paused round back up.
    assert decision_requests.resume_refusal(world, root) == decision_requests.FEATURE_RESTARTS
    with pytest.raises(Exception, match="step of a code change"):
        ChatThreads(world).resume(root)
    assert orchestrator._decision_start_refusal(world, root).endswith(
        decision_requests.FEATURE_RESTARTS)
    monkeypatch.setattr(config, "get_codebase", lambda: {"enable": True})
    monkeypatch.setattr("maverick.cli.open_world", lambda *a, **k: world, raising=False)
    out = CliRunner().invoke(main, ["resume", "--goal-id", str(root)])
    assert out.exit_code == 2 and "step of a code change" in out.output, out.output
    # An existing origin is never overwritten, and an unreadable one is an error.
    assert [r[0] for r in world.tenant_query(
        "SELECT kind FROM goal_origins WHERE goal_id = 1 AND {tenant_goal:goal_id}", ())] \
        == ["schedule"]
    monkeypatch.setattr(world, "tenant_query", lambda *a, **k: (_ for _ in ()).throw(OSError()))
    assert decision_requests.resume_refusal(world, root) == \
        decision_requests.FEATURE_UNKNOWN_RESTART


def test_one_person_spelt_two_ways_is_still_one_person(upstream, tmp_path, monkeypatch):
    import maverick.audit as audit
    from maverick.channel_approvals import ChannelApprovalRefused, record_vote
    monkeypatch.setattr(audit, "record", lambda kind, **fields: True)
    monkeypatch.delenv("MAVERICK_ALLOW_SELF_APPROVAL", raising=False)
    world, p = _protected_proposal(upstream, tmp_path, monkeypatch)
    aid = p["approval_id"]
    for starter in ("user:Starter", "user:STARTER"):            # the starter, spelt differently
        assert world.decide_approval(aid, "approved", decided_by=starter) is False
        with pytest.raises(ChannelApprovalRefused):
            record_vote(world, aid, "approved", starter)
    assert world.decide_approval(aid, "approved", decided_by="user:alice")
    assert world.decide_approval(aid, "approved", decided_by="user:ALICE")
    record_vote(world, aid, "approved", "user:Alice")
    state = world.approval_state(aid)
    assert state["status"] == "pending" and state["approved_count"] == 1
    assert "1 of 2 so far" in features.protected_status(world, p)
    event = record_vote(world, aid, "approved", "user:bob")      # a second person: quorum
    assert event.final_status == "approved"


@pytest.fixture
def pg_world(monkeypatch):
    import os
    import uuid
    dsn = os.environ.get("MAVERICK_PG_DSN")
    if not dsn:
        pytest.skip("MAVERICK_PG_DSN is not set")
    psycopg = pytest.importorskip("psycopg")
    from maverick.world_model_backends.postgres import PostgresWorldModel
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    db = "mvk_codebase_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(db)))
    own = make_conninfo(dsn, dbname=db)
    monkeypatch.setenv("MAVERICK_PG_DSN", own)
    try:
        yield PostgresWorldModel(own)
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(db)))


def test_two_people_on_postgres_never_the_starter_or_one_person_twice(upstream, monkeypatch,
                                                                       pg_world):
    import maverick.audit as audit
    from maverick.channel_approvals import ChannelApprovalRefused, record_vote
    monkeypatch.setattr(audit, "record", lambda kind, **fields: True)
    monkeypatch.delenv("MAVERICK_ALLOW_SELF_APPROVAL", raising=False)
    _protected_repo(upstream, monkeypatch)
    run, _ = _rounds(_passing)
    p = features.propose(pg_world, "pricing", "Discount", "", run,
                         protected_checker=_second()[0], owner="user:starter")
    aid = p["approval_id"]
    for who in ("user:starter", "user:STARTER", "agent:x", "operator"):
        with pytest.raises(ChannelApprovalRefused):
            record_vote(pg_world, aid, "approved", who)
    assert pg_world.decide_approval(aid, "approved", decided_by="user:Starter") is False
    record_vote(pg_world, aid, "approved", "user:alice")
    record_vote(pg_world, aid, "approved", "user:ALICE")
    assert pg_world.approval_state(aid)["approved_count"] == 1
    with pytest.raises(vault.VaultError, match="must approve"):
        features.merge(pg_world, p["id"])
    assert record_vote(pg_world, aid, "approved", "user:bob").final_status == "approved"


def test_a_change_whose_base_left_the_main_code_never_merges_or_pushes(upstream, tmp_path,
                                                                       monkeypatch):
    monkeypatch.setattr(features, "_author_model", lambda: "anthropic:claude-author")
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(_passing)
    p = features.propose(world, "pricing", "Discount", "", run, owner="user:starter")
    world.decide_approval(p["approval_id"], "approved", decided_by="user:lead")
    with vault.host_repo("pricing") as host:                    # main is rewritten without base
        tree = vault._git(["rev-parse", "HEAD^{tree}"], git_dir=host).strip()
        orphan = vault._git(["commit-tree", tree, "-m", "rewritten"], git_dir=host,
                            env=features._IDENTITY).strip()
        vault._git(["update-ref", "refs/heads/keep", "refs/heads/main"], git_dir=host)
        vault._git(["update-ref", "refs/heads/main", orphan], git_dir=host)
        vault.commit_back("pricing", host)
    for keep in (True, False):                                   # base kept on a side branch, or gone
        if not keep:
            with vault.host_repo("pricing") as host:
                vault._git(["update-ref", "-d", "refs/heads/keep"], git_dir=host)
                vault.commit_back("pricing", host)
        for act in (features.merge, features.push):
            with pytest.raises(vault.VaultError) as refused:
                act(world, p["id"])
            assert str(refused.value) == features.BASE_MOVED, keep
    assert features.plain_refusal(vault.VaultError(features.BASE_MOVED)) == features.BASE_MOVED


def test_every_feature_step_is_marked_before_it_runs(upstream, tmp_path, monkeypatch):
    from maverick import decision_requests
    monkeypatch.setattr(decision_requests, "_announce", lambda world, decision: None)
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    # A mark that cannot be written stops the run before anything runs.
    real = world.record_goal_origin
    monkeypatch.setattr(world, "record_goal_origin",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("disk")))
    run, calls = _rounds(_passing)
    with pytest.raises(OSError):
        features.propose(world, "pricing", "Discount", "", run, owner="user:starter")
    assert calls == []
    monkeypatch.setattr(world, "record_goal_origin", real)
    # Marking a sub-goal at the pause may fail: the step is still known, by its round.
    asked = {}

    def author(goal_id, work):
        _passing(work)
        assert decision_requests.resume_refusal(world, goal_id) == ""   # its own run starts
        child = world.create_goal("child", "c", parent_id=goal_id, owner="user:starter")
        asked["d"] = _ask(world, child, "Which way?")
        monkeypatch.setattr(features, "_mark_step", lambda *a, **k: None)
    p = features.propose(world, "pricing", "Discount", "", author, owner="user:starter")
    d = asked["d"]
    assert decision_requests.resume_refusal(world, p["goal_id"]) == \
        decision_requests.FEATURE_RESTARTS
    out = decision_requests.answer(world, d.id, 1, actor="user:starter", is_admin=True)
    assert out["resume"] is False and world.get_goal(d.goal_id).status == "cancelled"


def test_queued_children_of_a_change_never_start_after_it_ends(upstream, tmp_path, monkeypatch):
    from maverick import decision_requests as dr
    monkeypatch.setattr(dr, "_announce", lambda world, decision: None)
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    got = {}

    def author(goal_id, work):
        _passing(work)
        got["root"] = goal_id
        got["queued"] = world.create_goal("queued child", "c", parent_id=goal_id,
                                          owner="user:starter", execution_principal="user:starter")
        asking = world.create_goal("asking child", "c", parent_id=goal_id, owner="user:starter",
                                   execution_principal="user:starter")
        got["d"] = _ask(world, asking, "Which way?")
    features.propose(world, "pricing", "Discount", "", author, owner="user:starter")
    queued = world.get_goal(got["queued"])
    assert queued.status == "cancelled" and queued.result == dr.FEATURE_RESTARTS
    later = world.create_goal("made later", "c", parent_id=got["root"], owner="user:starter")
    assert dr.resume_refusal(world, later) == dr.FEATURE_RESTARTS   # never ran, but the change ended
    assert world.get_goal(got["d"].goal_id).status == "blocked"      # still answerable


def test_a_change_shows_while_it_runs_and_after_its_process_died(upstream, tmp_path, monkeypatch):
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    seen = {}

    def author(goal_id, work):
        _passing(work)
        (only,) = features.list_proposals("pricing")
        seen["during"] = (only["status"], features.status(world, only),
                          features.evidence(only)["lines"][0])
        seen["pid"] = only["id"]
    p = features.propose(world, "pricing", "Discount", "", author, owner="user:starter")
    assert seen["during"] == ("running", "running", features.RUNNING_LINE)
    assert p["id"] == seen["pid"] and features.status(world, features.find(p["id"])) == "pending"
    record = dict(features.find(p["id"]), status="running", process=2 ** 22 + 12345)
    features._save(record)                                    # left running by a process now gone
    assert features.status(world, features.find(p["id"])) == "stopped"
    assert features.evidence(features.find(p["id"]))["lines"][0] == features.STOPPED_LINE
    features._save(dict(record, host="elsewhere", deadline=1.0))     # another computer, past its cap
    assert features.status(world, features.find(p["id"])) == "stopped"

    def broken(goal_id, work):
        raise RuntimeError("the run broke")
    with pytest.raises(RuntimeError):
        features.propose(world, "pricing", "Broken", "", broken, owner="user:starter")
    gone = [q for q in features.list_proposals("pricing") if q["title"] == "Broken"]
    assert [features.status(world, q) for q in gone] == ["stopped"]


def test_a_change_is_live_only_in_the_very_process_that_builds_it(upstream, tmp_path,
                                                                  monkeypatch):
    import os
    import time as clock

    from maverick import runner
    vault.register("pricing", str(upstream))
    world = WorldModel(tmp_path / "world.db")
    run, _ = _rounds(_passing)
    p = features.propose(world, "pricing", "Discount", "", run, owner="user:starter")
    live = features._running_record(p["id"], "pricing", "Discount", p["branch"], p["base"],
                                    "user:starter", None)
    assert live["deadline"] > clock.time() and live["process"] == os.getpid()
    # No cap given: the configured one.
    cap = runner.goal_budget_defaults()["max_wall_seconds"] or runner.DEFAULT_MAX_WALL_SECONDS
    assert live["wall_cap"] == cap and live["deadline"] == live["created_at"] + cap

    def gone(**changes):
        features._save({**live, **changes})
        return features.status(world, features.find(p["id"])) == "stopped"
    assert not gone()                                          # this very process, in time
    sleeper = subprocess.Popen(["sleep", "30"])                # a reused process number
    try:
        assert gone(process=sleeper.pid)
    finally:
        sleeper.kill()
    assert gone(boot_id="another-boot")                        # the computer restarted
    assert gone(deadline=1.0)                                  # past its time cap, here too
    monkeypatch.setattr(features, "_proc_identity", lambda pid: None)  # no /proc: the cap alone
    assert not gone(process=4_000_000) and gone(process=4_000_000, deadline=1.0)

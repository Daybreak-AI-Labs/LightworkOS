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
    assert features.list_proposals("pricing") == []


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
        budget.tool_calls += 5
        _failing(work)
    run, calls = _rounds(spend)
    checks: list = []
    p = features.propose(world, "pricing", "Discount", "", run, budget=budget,
                         checker=lambda gid, copy: checks.append(gid),
                         sandbox_factory=_Sandbox, repair_rounds=2)
    assert len(calls) == 1 and checks == []                  # nothing ran after the cap
    assert p["stopped"] == "budget" and p["check"]["state"] == "skipped"
    assert p["status"] == "pending" and not p["tests"]["passed"]
    card = _card(world, p)
    assert any("spending limit ran out" in line for line in card["parameter_summary"])
    assert any("spending limit" in line for line in card["unresolved_assumptions"])


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
    features.request_approval(world, loaded)                  # renew builds its card
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
                                                                    private_tmp):
    """Detached background processes cannot write into the next round's copy:
    each test run and each checker look stops everything it started."""
    import time

    from maverick.sandbox.local import LocalBackend
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
    assert features.HOST_LINE in features.evidence(p)["lines"]   # the card says so
    assert not [f for files in seen for f in files if f.startswith("late_")], seen
    assert not [f for f in p["files"] if f.startswith("late_")]


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

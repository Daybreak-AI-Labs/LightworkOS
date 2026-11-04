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

    out = run(main, ["code", "add", "pricing", str(upstream)])
    assert out.exit_code == 0 and "protect=approve" in out.output, out.output
    assert "pricing" in run(main, ["code", "list"]).output
    out = run(main, ["code", "feature", "pricing", "Add flag", "--no-review"])
    assert out.exit_code == 0 and "awaiting approval #1" in out.output, out.output
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

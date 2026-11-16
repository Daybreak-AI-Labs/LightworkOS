"""Swarms that add and update features in vaulted code -- and never ship alone.

``propose`` runs a goal against a private working copy on a new branch, labelled
``code:<repo>`` and enforced at the repository's protection mode so the code
cannot leave through an external tool. It then:

1. commits the working copy's files host-side and pins that commit in a bundle;
2. runs the repository's test command through the sandbox on a FRESH copy of
   the pinned commit; failing tests go back to the author as a follow-up goal,
   and the loop repeats for up to ``[codebase] repair_rounds`` rounds;
3. runs the independent checker, when one is supplied: a separate goal with a
   fresh context and its own throwaway copy of the pinned commit, which tries to
   break the change and reports findings. Blockers go back to the author, then
   the checker looks again, for up to ``[codebase] check_rounds`` looks;
4. runs the independent diff reviewer, when one is supplied;
5. seals the proposal (diff, tests, rounds, findings, review, branch bundle) and
   parks a ``codebase_merge`` approval in the real approvals queue.

Every round, the author's and the checker's, is charged to one budget, checked
before the round starts; when it runs out the loop stops and the card says so.

Nothing reaches the vault's default branch or any remote until a person
approves: ``merge`` needs the approval, ``push`` needs it too. A denied approval
leaves the vault untouched.
"""
from __future__ import annotations

import json
import re
import secrets
import tempfile
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

from ..budget import BudgetExceeded
from ..file_lock import atomic_write_bytes, cross_process_lock
from . import vault
from .vault import VaultError, _git

MAX_DIFF_CHARS = 200_000
MAX_TEST_OUTPUT_CHARS = 20_000
MAX_REPAIR_OUTPUT_CHARS = 6_000
MAX_FINDINGS = 20
Runner = Callable[[int, Path], object]
# (goal id of a fresh check task, its own throwaway copy of the pinned commit)
# -> its report: text ending in a JSON object, or that object.
Checker = Callable[[int, Path], object]
Reviewer = Callable[[str, str], dict]
SEVERITIES = ("blocker", "should-fix", "minor")


def _proposal_dir(name: str) -> Path:
    return vault._root(name, "proposals")


def _save(p: dict) -> None:
    body = json.dumps(p, sort_keys=True).encode()
    atomic_write_bytes(_proposal_dir(p["repo"]) / f"{p['id']}.json",
                       vault._seal(body, f"codebase/{p['repo']}/proposal/{p['id']}"))


def _load(name: str, pid: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{16}", pid):
        raise VaultError("malformed proposal id")
    try:
        raw = (_proposal_dir(name) / f"{pid}.json").read_bytes()
    except FileNotFoundError:
        raise VaultError(f"no proposal {pid} for {name!r}") from None
    return json.loads(vault._unseal(raw, f"codebase/{name}/proposal/{pid}"))


def find(pid: str) -> dict:
    for repo in vault.list_repos():
        if (_proposal_dir(repo.name) / f"{pid}.json").exists():
            return _load(repo.name, pid)
    raise VaultError(f"no proposal {pid}")


def list_proposals(name: str | None = None) -> list[dict]:
    out = []
    for repo in vault.list_repos():
        if name and repo.name != name:
            continue
        d = _proposal_dir(repo.name)
        for f in sorted(d.glob("*.json")) if d.exists() else ():
            p = _load(repo.name, f.stem)
            out.append({k: v for k, v in p.items() if k not in ("diff", "tests_output")})
    return sorted(out, key=lambda p: p["created_at"], reverse=True)


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:40] or "change"


def _brief(repo: vault.Repo, title: str, description: str) -> str:
    tests = (f"The test command is `{repo.test_command}`; run it and make it pass."
             if repo.test_command else "Add or update tests for the change where the repo has them.")
    return (f"Implement this change in the `{repo.name}` repository (your working directory "
            f"is a checkout of branch `{repo.default_branch}` on a new feature branch).\n\n"
            f"{title}\n\n{description}\n\n{tests} Edit files in place; do not push, publish "
            "or send the code anywhere -- a human reviews and merges your change.")


def run_tests(repo: vault.Repo, work: Path, sandbox_factory=None) -> dict | None:
    if not repo.test_command:
        return None
    if sandbox_factory is None:
        from ..sandbox import build_sandbox
        sandbox_factory = build_sandbox
    box = sandbox_factory(workdir=str(work))
    try:
        result = box.exec(repo.test_command, timeout=1800)
    finally:
        _close(box)  # a container backend's leftovers end with the run
    output = (result.stdout or "") + (result.stderr or "")
    return {"command": repo.test_command, "exit_code": result.exit_code,
            "passed": result.exit_code == 0, "output": output[-MAX_TEST_OUTPUT_CHARS:]}


_IDENTITY = {"GIT_AUTHOR_NAME": "Lightwork", "GIT_AUTHOR_EMAIL": "lightwork@localhost",
             "GIT_COMMITTER_NAME": "Lightwork", "GIT_COMMITTER_EMAIL": "lightwork@localhost"}


def _host_commit(host: Path, work: Path, base: str, branch: str, message: str) -> str:
    """Commit the FILES of ``work`` on top of ``base`` using only host-owned git.

    The agent's working tree may contain anything, including its own ``.git``
    (hooks, config, a ``gitdir:`` pointer elsewhere). None of it is read as git
    metadata: the index lives in the host repository, git never tracks a path
    named ``.git``, and plumbing (read-tree, add, write-tree, commit-tree,
    update-ref) runs no hooks. Returns the new commit, or ``base`` when the tree
    is unchanged. The branch ref is pinned to exactly that commit."""
    env = {**_IDENTITY, "GIT_INDEX_FILE": str(host / "lw-index")}
    _git(["read-tree", base], git_dir=host, env=env)
    _git(["add", "-A", "--", "."], git_dir=host, work_tree=work, cwd=work, env=env)
    tree = _git(["write-tree"], git_dir=host, env=env).strip()
    if tree == _git(["rev-parse", f"{base}^{{tree}}"], git_dir=host).strip():
        return base
    added_links = [line for line in _git(["diff-tree", "-r", "--no-renames", base, tree],
                                         git_dir=host).splitlines()
                   if line.split(" ")[1:2] == ["160000"] and not line.startswith(":160000")]
    if added_links:
        raise VaultError("the change adds embedded git repositories; refused")
    commit = _git(["commit-tree", tree, "-p", base, "-m", message], git_dir=host, env=env).strip()
    _git(["update-ref", f"refs/heads/{branch}", commit], git_dir=host)
    return commit


def _fresh_copy(host: Path, dest: Path, commit: str, branch: str | None = None) -> Path:
    """A checkout of exactly ``commit`` (on ``branch`` when given, else
    detached) with no remote, so nothing run in it can reach the host
    repository. Tests and checks never have their copy read back; an author
    round's copy is read only by ``_host_commit``."""
    _git(["clone", "-q", "--no-hardlinks", "--no-checkout", str(host), str(dest)])
    _git(["checkout", "-q", *(["-B", branch] if branch else ["--detach"]), commit], cwd=dest)
    _git(["remote", "remove", "origin"], cwd=dest)
    return dest


@contextmanager
def _step(root: Path):
    """Stop every process the step under ``root`` started when it ends, so
    nothing it left running can write into a later round's copy."""
    from ..sandbox.local import contained_step
    with contained_step(root):
        yield


def _close(box) -> None:
    close = getattr(box, "close", None)
    if callable(close):
        close()


CONTAINER_REQUIRED = ("Code changes must run in a container, but this installation runs "
                      "commands directly on this computer. Set up a container work area, "
                      "or turn off the container requirement for code changes.")


def _runs_on_host(sandbox_factory=None) -> bool:
    """Whether feature-run steps would run on this computer without a container
    (the ``local`` backend). A backend that cannot be built here counts as
    not local: the run itself then fails on the same policy."""
    from ..sandbox import build_sandbox, fs_is_host_visible
    with vault.work_dir() as tmp:
        try:
            box = (sandbox_factory or build_sandbox)(workdir=str(tmp))
        except Exception:  # noqa: BLE001 -- the run reports the real error
            return False
        try:
            return fs_is_host_visible(box)
        finally:
            _close(box)


def _isolation(on_host: bool) -> str:
    """container | namespace (this computer, each command in its own process
    and temporary-folder namespace) | host (this computer, marker reap only)."""
    if not on_host:
        return "container"
    from ..sandbox.local import step_namespaces_available
    return "namespace" if step_namespaces_available() else "host"


def container_refusal(sandbox_factory=None) -> str | None:
    """The plain refusal when ``[codebase] require_container`` is on and the
    steps would run on this computer without a container; otherwise None."""
    if loop_settings()["require_container"] and _runs_on_host(sandbox_factory):
        return CONTAINER_REQUIRED
    return None


def _repair_brief(repo: vault.Repo, title: str, description: str, problem: str) -> str:
    return (f"Follow-up on a change you are making in the `{repo.name}` repository. Your "
            "working directory still holds your earlier edits.\n\n"
            f"The request was:\n{title}\n\n{description}\n\n{problem}\n\n"
            "Fix the cause in place. Edit files only; do not push, publish or send the "
            "code anywhere -- a human reviews and merges your change.")


def _tests_problem(tests: dict) -> str:
    from ..coding_mode import classify_failure
    kind, hint = classify_failure(tests["output"])
    return (f"The test command `{tests['command']}` failed (exit code {tests['exit_code']}) "
            "on your last version."
            + (f"\nDominant failure class: {kind}. {hint}" if kind != "other" else "")
            + f"\n\nRecent test output:\n{tests['output'][-MAX_REPAIR_OUTPUT_CHARS:]}")


def _findings_problem(findings: list[dict]) -> str:
    return ("An independent checker found these blockers in your last version:\n"
            + "\n".join(f"- {f['what']} (how it knows: {f['how'] or 'not stated'})"
                        for f in findings))


def _check_brief(repo: vault.Repo, title: str, description: str, base: str,
                 files: list[str], earlier: list[dict]) -> str:
    """The checker's whole context: the request and where to read the change.
    Never the author's goal, transcript or reasoning."""
    tests = (f"The project's test command is `{repo.test_command}`."
             if repo.test_command else "The project has no test command.")
    prior = ("\n\nYour earlier findings on a previous version (list the ids of those now "
             "gone in \"fixed\"; do not report them again if they remain):\n"
             + "\n".join(f"- {f['id']} [{f['severity']}] {f['what']}" for f in earlier)
             if earlier else "")
    return (f"Independently check a proposed change to the `{repo.name}` repository. Your "
            "working directory is your own throwaway copy of exactly that change; nothing "
            "you do there reaches the proposal. Do not fix anything: find what is wrong.\n\n"
            f"The request was:\n{title}\n\n{description}\n\n"
            f"Run `git diff {base} HEAD` to read the change. Files changed: "
            f"{', '.join(files[:40]) or '(none)'}. {tests} Try to break it: run the tests "
            "yourself, write a probe, try an edge case." + prior + "\n\n"
            "End with ONLY one JSON object: {\"findings\": [{\"severity\": "
            "\"blocker|should-fix|minor\", \"what\": \"<what is wrong>\", \"evidence\": "
            "\"ran|read\", \"how\": \"<the command you ran or the lines you read>\"}], "
            "\"fixed\": [\"<earlier id>\"]}. A blocker must not merge. Say \"ran\" only "
            "when a command you ran showed the problem.")


def _report(out: object) -> dict | None:
    """The checker's JSON report (the last object with a findings list), or None."""
    if isinstance(out, dict):
        return out if isinstance(out.get("findings"), list) else None
    text, found = str(out or "")[-50_000:], None
    decoder = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch == "{":
            try:
                obj, _ = decoder.raw_decode(text, i)
            except (ValueError, RecursionError):  # deep nesting reads as unreadable
                continue
            if isinstance(obj, dict) and isinstance(obj.get("findings"), list):
                found = obj
    return found


def _finding(raw: object, fid: str) -> dict:
    raw = raw if isinstance(raw, dict) else {"what": str(raw)}
    severity = str(raw.get("severity", "")).strip().lower()
    return {"id": fid,
            # An unreadable severity counts as the worst: it must not pass as clean.
            "severity": severity if severity in SEVERITIES else "blocker",
            "what": str(raw.get("what") or "(no description)")[:300],
            "evidence": "ran" if str(raw.get("evidence", "")).lower() == "ran" else "read",
            "how": str(raw.get("how") or "")[:300], "sent": False, "fixed": False}


class _Loop:
    """One feature run's rounds. The author works in its own working copy; every
    author round is committed host-side and pinned before any repository code
    runs; tests and checks run on fresh copies of that pinned commit, so their
    side effects never reach the author or the proposal."""

    def __init__(self, world, repo: vault.Repo, host: Path, *, base: str,
                 branch: str, pid: str, title: str, description: str, owner: str,
                 run: Runner, checker: Checker | None, sandbox_factory, budget,
                 repair_rounds: int, check_rounds: int) -> None:
        self.world, self.repo, self.host = world, repo, host
        self.base, self.branch, self.pid = base, branch, pid
        self.title, self.description, self.owner = title, description, owner
        self.run, self.checker, self.sandbox_factory = run, checker, sandbox_factory
        self.budget, self.check_rounds = budget, check_rounds
        self.repairs_left, self.repair_rounds = repair_rounds, repair_rounds
        self.head, self.bundle, self.tests = base, b"", None
        self.review_cut_short = False
        self.rounds: list[dict] = []
        self.stopped: str | None = None
        self.check: dict = {"state": "off" if checker is None else "skipped", "runs": 0,
                            "off": None if checker is not None else
                            "settings" if not loop_settings()["checker"] else "run",
                            "max_runs": check_rounds, "commit": None, "error": None,
                            "goal_ids": [], "findings": []}

    def _labelled(self):
        from ..ifc import labelled_run
        return labelled_run({f"code:{self.repo.name}"}, mode=self.repo.protect)

    def _afford(self) -> bool:
        """budget.check() before every round; a spent budget stops the loop."""
        try:
            self.budget.check()
        except BudgetExceeded:
            self.stopped = "budget"
            return False
        return True

    def author(self, goal_id: int, kind: str) -> None:
        """One author round, then commit, pin and test. Every round works in a
        FRESH copy of the pinned head at a new random path, made after the
        previous step ended and removed once committed, so nothing written
        between rounds carries over. State changes only when every step
        succeeded, so a failed round leaves the last pin."""
        with vault.work_dir() as tmp, _step(tmp):
            work = _fresh_copy(self.host, tmp / "work", self.head, self.branch)
            with self._labelled():
                self.run(goal_id, work)
            if not self._afford():
                # A governed run returns normally when it hits the cap; what it
                # left half done is never committed or offered.
                raise BudgetExceeded("the spending limit ran out during an author round")
            head = _host_commit(self.host, work, self.head, self.branch,
                                f"{self.title}\n\nLightwork proposal {self.pid} (goal #{goal_id})")
        bundle, tests = self.bundle, self.tests
        if head != self.head:
            # Bundle the pinned commit BEFORE any repository code (tests) runs.
            with tempfile.TemporaryDirectory(prefix="lw-prop-") as tmp:
                out = Path(tmp) / "p.bundle"
                _git(["bundle", "create", str(out), f"{self.base}..refs/heads/{self.branch}"],
                     git_dir=self.host)
                bundle = out.read_bytes()
            tests = self._test(head)
        self.head, self.bundle, self.tests = head, bundle, tests
        self.rounds.append({"kind": kind, "goal_id": goal_id, "head": head})

    def _test(self, head: str) -> dict | None:
        if not self.repo.test_command or head == self.base:
            return None
        with vault.work_dir() as tmp, _step(tmp):
            copy = _fresh_copy(self.host, tmp / "tests", head)
            return {**run_tests(self.repo, copy, self.sandbox_factory), "commit": head}

    def _repair(self, kind: str, problem: str) -> bool:
        """A follow-up goal for the author; False when the loop must stop."""
        if self.repairs_left <= 0 or not self._afford():
            return False
        self.repairs_left -= 1
        n = self.repair_rounds - self.repairs_left
        root = self.rounds[0]["goal_id"]
        gid = self.world.create_goal(
            f"[{self.repo.name}] {self.title} (repair {n})",
            _repair_brief(self.repo, self.title, self.description, problem),
            parent_id=root, owner=self.owner, execution_principal=self.owner)
        try:
            self.author(gid, kind)
        except Exception as exc:  # noqa: BLE001 -- the last pinned version stands
            self.stopped = "budget" if isinstance(exc, BudgetExceeded) else "error"
            _fail_goal(self.world, gid, exc)
            return False
        return True

    def repair_tests(self) -> None:
        while self.tests and not self.tests["passed"] and not self.stopped:
            if not self._repair("tests", _tests_problem(self.tests)):
                return

    def _look(self) -> dict | None:
        """One look by the checker on its own copy; None when it did not run."""
        if not self._afford():
            return None
        earlier = [f for f in self.check["findings"] if not f["fixed"]]
        files = [f for f in _git(["diff", "--name-only", "-z", self.base, self.head],
                                 git_dir=self.host).split("\0") if f]
        gid = self.world.create_goal(
            f"[{self.repo.name}] Check: {self.title}",
            _check_brief(self.repo, self.title, self.description, self.base, files, earlier),
            owner=self.owner, execution_principal=self.owner)
        self.check["goal_ids"].append(gid)
        try:
            with vault.work_dir() as tmp, _step(tmp):
                copy = _fresh_copy(self.host, tmp / "check", self.head)
                with self._labelled():
                    out = self.checker(gid, copy)
        except BudgetExceeded as exc:
            self.stopped = "budget"
            _fail_goal(self.world, gid, exc)
            return None
        except Exception as exc:  # noqa: BLE001 -- recorded: the change was not checked
            self.check["error"] = f"it stopped with {type(exc).__name__}"
            _fail_goal(self.world, gid, exc)
            return None
        if not self._afford():
            self.check["cut_short"] = True  # it ran, but its report is not used
            return None
        report = _report(out)
        if report is None:
            self.check["error"] = "its report could not be read"
        self._count_only(gid, report)
        return report

    def _count_only(self, goal_id: int, report: dict | None) -> None:
        """Finding text can quote vaulted code: the check task's own result
        (goal pages, later reads) keeps only counts; the text stays in the
        sealed proposal, which only administrators read."""
        found = "its report could not be read" if report is None else \
            f"{len(report['findings'][:MAX_FINDINGS])} finding(s)"
        try:
            goal = self.world.get_goal(goal_id)
            self.world.set_goal_status(
                goal_id, goal.status if goal is not None else "done",
                result=f"Independent check of Lightwork proposal {self.pid}: {found}. "
                       f"Read them with maverick code show {self.pid}.")
        except Exception:  # noqa: BLE001 -- the proposal still records the check
            pass

    def verify(self) -> None:
        """Test repairs, then checker looks with blocker repairs in between."""
        self.repair_tests()
        if self.checker is None or self.head == self.base:
            return
        while self.check["runs"] < self.check_rounds and not self.stopped:
            report = self._look()
            if report is None:
                break
            self.check["runs"] += 1
            self.check["commit"] = self.head
            self._record(report)
            open_blockers = [f for f in self.check["findings"]
                             if f["severity"] == "blocker" and not f["fixed"]]
            if not open_blockers or self.check["runs"] >= self.check_rounds:
                break
            if not self._repair("check", _findings_problem(open_blockers)):
                break
            for f in open_blockers:
                f["sent"] = True
            self.repair_tests()

    def _record(self, report: dict) -> None:
        fixed = {str(i) for i in report.get("fixed") or () if isinstance(i, (str, int))}
        for f in self.check["findings"]:
            f["fixed"] = f["fixed"] or f["id"] in fixed
        n = self.check["runs"]
        self.check["findings"] += [_finding(raw, f"{n}.{i}") for i, raw in
                                   enumerate(report["findings"][:MAX_FINDINGS], start=1)]

    def record(self) -> tuple[dict, dict]:
        check = dict(self.check)
        check["state"] = ("ran" if check["runs"] else "failed" if check["error"]
                          else check["state"])
        check["findings"] = [{k: v for k, v in f.items() if k not in ("sent", "fixed")}
                             | {"status": "fixed" if f["fixed"] else
                                "still open" if f["sent"] else "not attempted"}
                             for f in check["findings"]]
        return {"used": self.repair_rounds - self.repairs_left,
                "allowed": self.repair_rounds}, check


def _fail_goal(world, goal_id: int, exc: BaseException) -> None:
    try:
        world.set_goal_status(goal_id, "failed",
                              result=f"feature proposal failed: {type(exc).__name__}")
    except Exception:  # noqa: BLE001 -- the original error is what matters
        pass


def feature_budget(max_dollars: float | None = None):
    """One budget for a whole feature run (every author and checker round).
    Honors [budget] config and the per-goal defaults; a bare
    Budget(max_dollars=None) would run with no cap of any kind. An explicit
    max_dollars still wins."""
    from ..budget import budget_from_config
    from ..runner import goal_budget_defaults
    return budget_from_config(defaults=goal_budget_defaults(), max_dollars=max_dollars)


def loop_settings() -> dict:
    """``[codebase]`` repair_rounds / checker / check_rounds, with their defaults."""
    from ..config import CODEBASE_LOOP_DEFAULTS, get_codebase
    cfg = get_codebase()
    return {k: cfg.get(k, v) for k, v in CODEBASE_LOOP_DEFAULTS.items()}


def _review(loop: _Loop, reviewer: Reviewer | None, brief: str, diff: str) -> dict | None:
    """The advisory diff review, charged to the run's budget; skipped once the
    budget stopped the run."""
    if not (reviewer and diff) or loop.stopped:
        return None
    try:
        loop.budget.check()
        return reviewer(brief, diff)
    except BudgetExceeded:
        loop.review_cut_short = True  # every round ran; only the review was cut short
        return None


def propose(world, name: str, title: str, description: str, run: Runner, *,
            reviewer: Reviewer | None = None, checker: Checker | None = None,
            sandbox_factory=None, owner: str = "", budget=None,
            repair_rounds: int | None = None, check_rounds: int | None = None) -> dict:
    """Run a feature swarm, repair and check its change, and park it for
    human approval. ``budget`` is the one cap for every round (the caller's
    runner and checker must charge the same object); ``None`` builds one from
    configuration. Round limits default to ``[codebase]``."""
    repo = vault.get(name)
    settings = loop_settings()
    on_host = _runs_on_host(sandbox_factory)
    if settings["require_container"] and on_host:
        raise VaultError(CONTAINER_REQUIRED)
    budget = budget if budget is not None else feature_budget()
    pid = secrets.token_hex(8)
    branch = f"lightwork/{_slug(title)}-{pid[:6]}"
    goal_id = None
    try:
        with vault.host_repo(name) as host:
            base = _git(["rev-parse", "--verify", f"refs/heads/{repo.default_branch}"],
                        git_dir=host).strip()
            loop = _Loop(world, repo, host, base=base, branch=branch, pid=pid,
                         title=title, description=description, owner=owner, run=run,
                         checker=checker, sandbox_factory=sandbox_factory, budget=budget,
                         repair_rounds=max(0, int(settings["repair_rounds"] if repair_rounds
                                                  is None else repair_rounds)),
                         check_rounds=max(1, int(settings["check_rounds"] if check_rounds
                                                 is None else check_rounds)))
            budget.check()
            goal_id = world.create_goal(f"[{name}] {title}", _brief(repo, title, description),
                                        owner=owner, execution_principal=owner)
            loop.author(goal_id, "author")
            loop.verify()
            head, changed = loop.head, loop.head != base
            diff = files = None
            if changed:
                diff = _git(["diff", "--no-ext-diff", "--no-textconv", base, head], git_dir=host)
                files = [f for f in _git(["diff", "--name-only", "-z", base, head],
                                         git_dir=host).split("\0") if f]
    except BaseException as exc:
        if goal_id is not None:
            _fail_goal(world, goal_id, exc)
        if isinstance(exc, BudgetExceeded):
            raise VaultError("the spending limit ran out before the first version was "
                             "finished; nothing was proposed") from exc
        raise
    diff, files = diff or "", files or []
    review = _review(loop, reviewer, f"{title}\n\n{description}", diff)
    tests = loop.tests
    rounds, check = loop.record()
    proposal = {
        "id": pid, "repo": name, "title": title, "goal_id": goal_id, "branch": branch,
        "base": base, "head": head, "files": files, "diff": diff[:MAX_DIFF_CHARS],
        "diff_truncated": len(diff) > MAX_DIFF_CHARS, "diff_chars": len(diff),
        "tests": None if tests is None else {k: v for k, v in tests.items() if k != "output"},
        "tests_output": None if tests is None else tests["output"],
        "test_command": bool(repo.test_command), "repair_rounds": rounds,
        "isolation": _isolation(on_host),
        "rounds": loop.rounds, "check": check, "stopped": loop.stopped,
        "review_cut_short": loop.review_cut_short,
        "review": review, "status": "empty" if not changed else "pending",
        "approval_id": None, "created_at": time.time(), "merged_at": None,
    }
    if changed:
        atomic_write_bytes(_proposal_dir(name) / f"{pid}.bundle",
                           vault._seal(loop.bundle, f"codebase/{name}/proposal-bundle/{pid}"))
    _save(proposal)  # the work is kept even if parking its approval fails
    if changed:
        try:
            request_approval(world, proposal)
        except Exception as exc:  # noqa: BLE001 -- `maverick code renew` parks it again
            import logging
            logging.getLogger(__name__).warning(
                "proposal %s saved but its approval was not parked (%s); "
                "run `maverick code renew %s`", pid, type(exc).__name__, pid)
    return proposal


def _approval_expired(appr) -> bool:
    from ..approval_cards import ApprovalCardError, decode_approval_detail
    try:
        card = decode_approval_detail(appr.detail)
    except ApprovalCardError:
        return True
    return card is not None and time.time() >= float(card["expires_at"])


def request_approval(world, p: dict) -> int:
    """Park a (new) ``codebase_merge`` approval for a pending proposal: after
    propose, or when the earlier one expired (unanswered, or approved but never
    merged) or failed to park. Serialised per proposal, so two concurrent
    renewals cannot leave one approval that nothing reads."""
    caller = p
    with cross_process_lock(_proposal_dir(p["repo"]) / f"{p['id']}.renew", strict=True):
        try:
            p = {**p, **_load(p["repo"], p["id"])}  # the stored approval, not a stale copy
        except (OSError, ValueError, KeyError, VaultError):
            pass  # not saved yet (propose parks before its first read-back)
        if p["status"] != "pending":
            raise VaultError(f"proposal {p['id']} is {p['status']}")
        appr = world.get_approval(p["approval_id"]) if p.get("approval_id") else None
        if appr is not None and not (appr.status in ("pending", "approved")
                                     and _approval_expired(appr)):
            raise VaultError(f"proposal {p['id']} already has approval #{appr.id} ({appr.status})")
        from ..logging_config import reset_goal_context, set_goal_context
        context = set_goal_context(p.get("goal_id"))
        try:
            p["approval_id"] = world.create_approval(
                "codebase_merge", risk="high", scope=p["repo"], provenance="codebase",
                requested_by="agent:codebase", detail=_approval_detail(p))
        finally:
            reset_goal_context(context)
        _save(p)
        caller.update(p)
        return p["approval_id"]


APPROVAL_TTL = 7 * 24 * 3600.0  # the longest an operation card may stay open


def _safe_label(text: str, limit: int = 300) -> str:
    """A card label that cannot be refused: printable, never empty, and short
    enough to stay under the 500-character limit after secret redaction."""
    text = "".join(c if c.isprintable() else "?" for c in str(text)).strip()
    return (repr(text)[1:-1] if text else "(blank name)")[:limit]


def _approval_detail(p: dict) -> str:
    from ..approval_cards import ApprovalCardError
    try:
        return _approval_card(p, full=True)
    except ApprovalCardError:
        return _approval_card(p, full=False)  # names or title the card cannot state


_TESTS_GAP = "The repository's tests did not pass or are not configured."
HOST_LINE = ("These steps ran on this computer without a container or separate processes, "
             "so they were not isolated from each other.")
HOST_GAP = "The steps were not isolated from each other on this computer."
NAMESPACE_LINE = ("Each step ran on this computer with its own processes and its own temporary "
                  "folder. They still shared its other files and its network, unlike a container.")
NAMESPACE_GAP = "The steps ran on this computer, not in a container, so they shared its files."
_UNCHECKED_GAP = "Nobody independently tried to break this change."


def _tests_evidence(p: dict) -> tuple[list[str], list[str]]:
    tests = p.get("tests")
    if tests is None:
        return ["Tests: not configured. Nothing ran this project's tests."], [_TESTS_GAP]
    verdict = "PASSED" if tests.get("passed") else "FAILED"
    gaps = [] if tests.get("passed") else [_TESTS_GAP]
    if "commit" not in tests:  # saved before tests ran on the pinned commit
        return [f"Tests: {verdict} (`{tests.get('command')}`)."], gaps
    if tests["commit"] != p["head"]:
        return ([f"Tests: {verdict} on an earlier version, not the one you are approving."],
                [_TESTS_GAP])
    return [f"Tests: {verdict}. Lightwork ran `{tests.get('command')}` on the exact version "
            "you are approving."], gaps


def _check_evidence(p: dict) -> tuple[list[str], list[str]]:
    check = p.get("check")
    if check is None:  # saved before the checker existed
        return ["Independent check: not run."], [_UNCHECKED_GAP]
    state, lines, gaps = check.get("state"), [], []
    if state == "off":
        when = "for this run" if check.get("off") == "run" else "in settings"
        return [f"Independent check: turned off {when}."], [_UNCHECKED_GAP]
    if state == "skipped" and check.get("cut_short"):
        return (["Independent check: was cut short by the spending limit, so nothing it found "
                 "was recorded."], [_UNCHECKED_GAP])
    if state == "skipped":
        return ["Independent check: did not run because the run stopped early."], [_UNCHECKED_GAP]
    if state == "failed":
        return ([f"Independent check: could not run ({check.get('error')})."],
                ["The independent check could not run, so this change was not checked."])
    findings = check.get("findings") or []
    still = sum(1 for f in findings if f["severity"] == "blocker" and f["status"] != "fixed")
    lines.append(f"Independent check: looked {check.get('runs')} time(s) and reported "
                 f"{len(findings)} finding(s); {still} blocker(s) still open.")
    if still:
        gaps.append(f"{still} blocker(s) from the independent check are still open.")
    if check.get("commit") != p["head"]:
        lines.append("The last check looked at an earlier version, not the one you are approving.")
        gaps.append("The independent check did not look at the version you are approving.")
    if check.get("error"):
        lines.append(f"A later check could not run ({check['error']}).")
    if check.get("cut_short"):
        lines.append("A later look was cut short by the spending limit.")
    return lines, gaps


def _finding_line(f: dict) -> str:
    how = "shown by running a command" if f.get("evidence") == "ran" else "from reading the code"
    return f"Finding {f['id']}, {f['severity']}, {f['status']}: {f['what']} ({how})."


def evidence(p: dict) -> dict:
    """What was and was not checked, in plain words: the one source for the
    approval card, the CLI, the dashboard and Copilot. ``gaps`` lists every
    reason the change is not fully checked; it is empty only when the tests
    passed on the approved commit and the checker looked at that commit and
    left no blocker open. Proposals saved before repair rounds and the checker
    existed read as not checked."""
    lines, gaps = _tests_evidence(p)
    isolation = p.get("isolation")
    if isolation in ("host", "namespace"):
        lines.append(HOST_LINE if isolation == "host" else NAMESPACE_LINE)
        gaps.append(HOST_GAP if isolation == "host" else NAMESPACE_GAP)
    rounds = p.get("repair_rounds")
    if isinstance(rounds, dict):
        lines.append(f"Repair rounds: {rounds.get('used', 0)} of {rounds.get('allowed', 0)} used.")
    stopped = p.get("stopped")
    if stopped == "budget":
        lines.append("Stopped early: the spending limit ran out, so later rounds did not run.")
        gaps.append("The spending limit ran out before every round could run.")
    elif stopped:
        lines.append("Stopped early: a repair round failed, so the last tested version is shown.")
        gaps.append("A repair round failed before every round could run.")
    if p.get("review_cut_short"):
        gaps.append("The spending limit ran out before the diff review finished.")
    check_lines, check_gaps = _check_evidence(p)
    findings = (p.get("check") or {}).get("findings") or []
    return {"lines": lines + check_lines, "gaps": gaps + check_gaps,
            "findings": [_finding_line(f) for f in findings]}


def _approval_card(p: dict, *, full: bool) -> str:
    """A structured approval card (the only kind the dashboard lets a human
    approve) committing to the repository, branch, base and approved head,
    and stating plainly what was and was not checked."""
    from ..approval_cards import encode_operation_approval_detail
    review = p["review"]
    facts = evidence(p)
    lines = [f"Branch {p['branch']} at {p['head'][:12]} from {p['base'][:12]}; "
             f"{len(p['files'])} file(s) changed.", *facts["lines"]]
    # Counts and statuses only: this card reaches chat channels and lists that
    # need only operate access, and finding text can quote vaulted code.
    findings = (p.get("check") or {}).get("findings") or []
    if findings:
        counts: dict[str, int] = {}
        for f in findings:
            key = f"{f['severity']} {f['status']}"
            counts[key] = counts.get(key, 0) + 1
        lines.append("Independent check findings: "
                     + ", ".join(f"{n} {key}" for key, n in counts.items())
                     + f". Read them with maverick code show {p['id']} or on the Code page.")
    lines.append("Independent review: " + (
        "cut short by the spending limit." if review is None and p.get("review_cut_short") else
        "not run" if review is None else
        ("approves" if review.get("approves") else "objects")
        + f" ({review.get('blockers', 0)} blocker(s))"))
    if p.get("diff_truncated"):
        lines.append(f"WARNING: the diff is {p['diff_chars']} characters; review and the stored "
                     f"copy cover only the first {MAX_DIFF_CHARS}. Inspect the branch in full "
                     "before approving.")
    lines += [f"  {_safe_label(f)}" for f in p["files"][:40]] if full else []
    if len(p["files"]) > 40:
        lines.append(f"  ... and {len(p['files']) - 40} more file(s)")
    lines.append(f"Inspect: maverick code show {p['id']}")
    lines = [_safe_label(line) for line in lines][:24]
    return encode_operation_approval_detail(
        action="codebase_merge",
        summary=_safe_label(f"Merge Lightwork proposal {p['id']} into {p['repo']}"
                            + (f": {p['title']}" if full else "")),
        target_label=f"{p['repo']} <- {p['branch']}"[:500],
        target={"repo": p["repo"], "branch": p["branch"]},
        parameters={"proposal": p["id"], "base": p["base"], "head": p["head"],
                    "files": p["files"]},
        parameter_summary=lines, actor="agent:codebase", role="feature_swarm",
        known_effects=[f"Merges the proposal into {p['repo']}'s default branch in the vault "
                       "(no-fast-forward); pushing upstream is a separate step."[:500]],
        unresolved_assumptions=[_safe_label(g) for g in facts["gaps"]][:24],
        before=f"{p['repo']} default branch at {p['base'][:12]}.",
        after=f"{p['repo']} default branch includes {p['head'][:12]}.",
        irreversible=False, ttl_seconds=APPROVAL_TTL)


def status(world, p: dict) -> str:
    if p["status"] in ("merged", "empty", "conflict"):
        return p["status"]
    appr = world.get_approval(p["approval_id"]) if p["approval_id"] else None
    if appr is None:
        return "unrequested"  # its approval failed to park: `maverick code renew`
    if appr.status in ("pending", "approved") and _approval_expired(appr):
        return "expired"      # past its card's expiry: `maverick code renew`
    return {"approved": "approved", "denied": "rejected"}.get(appr.status, "pending")


def _require_approved(world, p: dict) -> None:
    """The approval itself must be an approved codebase_merge for this repository
    -- not merely the proposal's recorded state."""
    appr = world.get_approval(p["approval_id"]) if p["approval_id"] else None
    if (appr is None or appr.status != "approved" or appr.action != "codebase_merge"
            or appr.scope != p["repo"]):
        raise VaultError(f"proposal {p['id']} is {status(world, p)}; "
                         "a human must approve it first")
    if _approval_expired(appr):
        # Like every other approved operation: an approval past its card's
        # expiry no longer authorizes the change it described.
        raise VaultError(f"proposal {p['id']}'s approval #{appr.id} has expired; "
                         f"run `maverick code renew {p['id']}` and approve it again")


def _fetch_proposal(p: dict, host: Path) -> None:
    """Load the proposal's branch into ``host`` and prove it is the approved commit."""
    raw = (_proposal_dir(p["repo"]) / f"{p['id']}.bundle").read_bytes()
    with tempfile.TemporaryDirectory(prefix="lw-prop-") as tmp:
        b = Path(tmp) / "p.bundle"
        b.write_bytes(vault._unseal(raw, f"codebase/{p['repo']}/proposal-bundle/{p['id']}"))
        _git(["fetch", "-q", str(b), f"+refs/heads/{p['branch']}:refs/heads/{p['branch']}"],
             git_dir=host)
    tip = _git(["rev-parse", "--verify", f"refs/heads/{p['branch']}"], git_dir=host).strip()
    if tip != p["head"]:
        raise VaultError(f"proposal {p['id']} branch is not the approved commit; refused")


def merge(world, pid: str) -> dict:
    """Merge an APPROVED proposal into the vault's default branch (no fast-forward,
    so the merge is one reviewable commit). A conflict leaves the vault as it was."""
    p = find(pid)
    _require_approved(world, p)
    if p["status"] == "merged":
        raise VaultError(f"proposal {pid} is already merged")
    repo = vault.get(p["repo"])
    with cross_process_lock(vault._bundle_path(p["repo"]), strict=True), \
            vault.host_repo(p["repo"]) as host:
        _fetch_proposal(p, host)
        work = vault.clone_work(host, host.parent / "merge-work", repo.default_branch)
        _git(["fetch", "-q", str(host), f"refs/heads/{p['branch']}:refs/heads/{p['branch']}"],
             cwd=work)
        try:
            _git(["merge", "-q", "--no-ff", p["branch"], "-m",
                  f"Merge Lightwork proposal {pid}: {p['title']}"], cwd=work, env=_IDENTITY)
        except VaultError:
            p["status"] = "conflict"
            _save(p)
            raise VaultError(f"proposal {pid} no longer merges cleanly; request it again") from None
        _git(["fetch", "-q", str(work),
              f"+refs/heads/{repo.default_branch}:refs/heads/{repo.default_branch}"],
             git_dir=host)
        vault.commit_back(p["repo"], host)
    p.update(status="merged", merged_at=time.time())
    _save(p)
    return p


def settle(world) -> list[dict]:
    """Merge every proposal a human has approved since the last settle; report
    the outcome of each (merged, or the reason it did not merge)."""
    out = []
    for p in list_proposals():
        if p["status"] == "pending" and status(world, p) == "approved":
            try:
                merge(world, p["id"])
                out.append({"id": p["id"], "repo": p["repo"], "outcome": "merged"})
            except Exception as exc:  # noqa: BLE001 -- one bad proposal never stops the rest
                out.append({"id": p["id"], "repo": p["repo"],
                            "outcome": str(exc) if isinstance(exc, VaultError)
                            else f"error: {type(exc).__name__}"})
    return out


def push(world, pid: str) -> str:
    """Push an APPROVED proposal's branch (the approved commit, verified) to the
    repository's source remote, for a pull request there. Returns the branch."""
    p = find(pid)
    _require_approved(world, p)
    repo = vault.get(p["repo"])
    with vault.host_repo(p["repo"]) as host:
        _fetch_proposal(p, host)
        _git(["push", "-q", repo.source, f"refs/heads/{p['branch']}:refs/heads/{p['branch']}"],
             git_dir=host, token_env=repo.token_env)
    return p["branch"]


def default_runner(*, max_dollars: float | None = None, user_id: str | None = None,
                   allowed_suites: frozenset[str] | None = None, budget=None) -> Runner:
    """Run the goal as a normal governed swarm whose sandbox is the working copy.
    Pass the feature run's ``budget`` so every round charges the same cap;
    without one, each call builds its own from configuration."""
    def run(goal_id: int, work: Path) -> object:
        from ..llm import LLM
        from ..orchestrator import run_goal_sync
        from ..sandbox import build_sandbox
        from ..world_model import close_world_if_owned, open_world
        world = open_world()
        try:
            return run_goal_sync(LLM(), world,
                                 budget if budget is not None else feature_budget(max_dollars),
                                 goal_id, sandbox=build_sandbox(workdir=str(work)),
                                 user_id=user_id, allowed_suites=allowed_suites)
        finally:
            close_world_if_owned(world)
    return run


def checker_model() -> str:
    """The checker's model: the ``reviewer`` role (``[models] reviewer``), so
    it can differ from the author's; swapped for the configured cross-family
    model when the two share a provider family (as the diff reviewer does)."""
    from ..llm import model_for_role
    from ..verifier import _cross_family_fallback, _same_family
    model = model_for_role("reviewer")
    if _same_family(model, model_for_role("orchestrator")):
        model = _cross_family_fallback(model) or model
    return model


def default_checker(*, budget, user_id: str | None = None,
                    allowed_suites: frozenset[str] | None = None) -> Checker:
    """The independent checker: a separate governed run with a fresh context,
    whose sandbox is its own throwaway copy of the pinned commit, charged to
    the feature run's ``budget``. Its run is a fresh context
    (:func:`maverick.tools.fresh_context_run`): no tool that reads past goals
    or shared memory, and no prior goals recalled into its brief."""
    def check(goal_id: int, copy: Path) -> object:
        from .. import orchestrator
        from ..llm import LLM
        from ..sandbox import build_sandbox
        from ..tools import fresh_context_run
        from ..world_model import close_world_if_owned, open_world
        world = open_world()
        box = build_sandbox(workdir=str(copy))
        try:
            with fresh_context_run():
                return orchestrator.run_goal_sync(LLM(), world, budget, goal_id, sandbox=box,
                                                  user_id=user_id,
                                                  allowed_suites=allowed_suites,
                                                  orchestrator_model_override=checker_model())
        finally:
            _close(box)
            close_world_if_owned(world)
    return check


def default_reviewer(*, budget=None) -> Reviewer:
    """The independent diff reviewer (cross-family where possible), charged
    to the feature run's ``budget``."""
    def review(brief: str, diff: str) -> dict:
        import asyncio

        from ..llm import LLM
        from ..reviewer import review_diff
        verdict = asyncio.run(review_diff(brief, diff, LLM(), budget))
        return {"approves": bool(verdict.approves), "confidence": float(verdict.confidence),
                "blockers": len(verdict.blockers),
                "comments": [{"path": c.path, "line": c.line, "severity": c.severity,
                              "message": c.message} for c in verdict.comments[:50]]}
    return review


__all__ = ["default_checker", "default_reviewer", "default_runner", "evidence",
           "feature_budget", "find", "list_proposals", "loop_settings", "merge", "propose",
           "push", "run_tests", "settle", "status"]


def _check_word(check: dict, head: str) -> str:
    """One word for the checker's outcome: off | not_run | failed | open | clean."""
    state = check.get("state")
    if state in ("off", "failed"):
        return state
    if state != "ran" or check.get("commit") != head:
        return "not_run"
    still = any(f["severity"] == "blocker" and f["status"] != "fixed"
                for f in check.get("findings") or ())
    return "open" if still else "clean"


def summary(world) -> dict:
    """Read-only projection for the dashboard: repositories and proposals, never
    code, diffs or test output."""
    repos = [{"name": r.name, "default_branch": r.default_branch, "head": r.head[:12],
              "protect": r.protect, "tests": bool(r.test_command), "updated_at": r.updated_at}
             for r in vault.list_repos()]
    proposals = []
    for p in list_proposals()[:200]:
        tests = p.get("tests")
        review = p.get("review")
        check = p.get("check")
        proposals.append({
            "id": p["id"], "repo": p["repo"], "title": p["title"], "branch": p["branch"],
            "status": status(world, p), "files": len(p["files"]),
            "tests": None if tests is None else tests["passed"],
            "review": None if review is None else bool(review.get("approves")),
            "check": None if check is None else _check_word(check, p["head"]),
            "gaps": len(evidence(p)["gaps"]),
            "approval_id": p["approval_id"], "created_at": p["created_at"]})
    return {"schema": "lightwork.codebase-summary.v1", "enabled": vault.enabled(),
            "repos": repos, "proposals": proposals}

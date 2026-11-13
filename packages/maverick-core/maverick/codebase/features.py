"""Swarms that add and update features in vaulted code -- and never ship alone.

``propose`` runs a goal against a private working copy on a new branch, labelled
``code:<repo>`` and enforced at the repository's protection mode so the code
cannot leave through an external tool. It then:

1. collects the change (branch commits and a bounded diff);
2. runs the repository's test command through the sandbox;
3. runs the independent code reviewer over the diff, when one is supplied;
4. seals the proposal (diff, tests, review, branch bundle) and parks a
   ``codebase_merge`` approval in the real approvals queue.

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
from pathlib import Path

from ..file_lock import atomic_write_bytes, cross_process_lock
from . import vault
from .vault import VaultError, _git

MAX_DIFF_CHARS = 200_000
MAX_TEST_OUTPUT_CHARS = 20_000
Runner = Callable[[int, Path], object]
Reviewer = Callable[[str, str], dict]


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
    result = sandbox_factory(workdir=str(work)).exec(repo.test_command, timeout=1800)
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


def propose(world, name: str, title: str, description: str, run: Runner, *,
            reviewer: Reviewer | None = None, sandbox_factory=None,
            owner: str = "") -> dict:
    """Run a feature swarm and park its change for human approval."""
    from ..ifc import labelled_run
    repo = vault.get(name)
    pid = secrets.token_hex(8)
    branch = f"lightwork/{_slug(title)}-{pid[:6]}"
    goal_id = None
    try:
        with vault.host_repo(name) as host, vault.work_dir() as work_tmp:
            base = _git(["rev-parse", "--verify", f"refs/heads/{repo.default_branch}"],
                        git_dir=host).strip()
            work = vault.clone_work(host, work_tmp / "work", repo.default_branch)
            _git(["checkout", "-q", "-b", branch], cwd=work)
            goal_id = world.create_goal(f"[{name}] {title}", _brief(repo, title, description),
                                        owner=owner, execution_principal=owner)
            with labelled_run({f"code:{name}"}, mode=repo.protect):
                run(goal_id, work)
            head = _host_commit(host, work, base, branch,
                                f"{title}\n\nLightwork proposal {pid} (goal #{goal_id})")
            changed = head != base
            diff = files = None
            bundle = b""
            if changed:
                diff = _git(["diff", "--no-ext-diff", "--no-textconv", base, head], git_dir=host)
                files = [f for f in _git(["diff", "--name-only", "-z", base, head],
                                         git_dir=host).split("\0") if f]
                # Bundle the pinned commit BEFORE any repository code (tests) runs.
                with tempfile.TemporaryDirectory(prefix="lw-prop-") as tmp:
                    out = Path(tmp) / "p.bundle"
                    _git(["bundle", "create", str(out), f"{base}..refs/heads/{branch}"],
                         git_dir=host)
                    bundle = out.read_bytes()
            tests = run_tests(repo, work, sandbox_factory) if changed else None
    except BaseException as exc:
        if goal_id is not None:
            try:
                world.set_goal_status(goal_id, "failed",
                                      result=f"feature proposal failed: {type(exc).__name__}")
            except Exception:  # noqa: BLE001 -- the original error is what matters
                pass
        raise
    diff, files = diff or "", files or []
    review = reviewer(f"{title}\n\n{description}", diff) if (reviewer and diff) else None
    proposal = {
        "id": pid, "repo": name, "title": title, "goal_id": goal_id, "branch": branch,
        "base": base, "head": head, "files": files, "diff": diff[:MAX_DIFF_CHARS],
        "diff_truncated": len(diff) > MAX_DIFF_CHARS, "diff_chars": len(diff),
        "tests": None if tests is None else {k: v for k, v in tests.items() if k != "output"},
        "tests_output": None if tests is None else tests["output"],
        "review": review, "status": "empty" if not changed else "pending",
        "approval_id": None, "created_at": time.time(), "merged_at": None,
    }
    if changed:
        atomic_write_bytes(_proposal_dir(name) / f"{pid}.bundle",
                           vault._seal(bundle, f"codebase/{name}/proposal-bundle/{pid}"))
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


def _approval_card(p: dict, *, full: bool) -> str:
    """A structured approval card (the only kind the dashboard lets a human
    approve) committing to the repository, branch, base and approved head."""
    from ..approval_cards import encode_operation_approval_detail
    tests = p["tests"]
    review = p["review"]
    lines = [f"Branch {p['branch']} at {p['head'][:12]} from {p['base'][:12]}; "
             f"{len(p['files'])} file(s) changed.",
             "Tests: " + ("not configured" if tests is None else
                          f"{'PASSED' if tests['passed'] else 'FAILED'} (`{tests['command']}`)"),
             "Independent review: " + ("not run" if review is None else
                                       ("approves" if review.get("approves") else "objects")
                                       + f" ({review.get('blockers', 0)} blocker(s))")]
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
        unresolved_assumptions=[] if tests and tests["passed"] else
        ["The repository's tests did not pass or are not configured."],
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
                   allowed_suites: frozenset[str] | None = None) -> Runner:
    """Run the goal as a normal governed swarm whose sandbox is the working copy."""
    def run(goal_id: int, work: Path) -> object:
        from ..budget import budget_from_config
        from ..llm import LLM
        from ..orchestrator import run_goal_sync
        from ..runner import goal_budget_defaults
        from ..sandbox import build_sandbox
        from ..world_model import close_world_if_owned, open_world
        # Honor [budget] config and the per-goal defaults; a bare
        # Budget(max_dollars=None) would run with no cap of any kind. An
        # explicit max_dollars still wins.
        budget = budget_from_config(defaults=goal_budget_defaults(),
                                    max_dollars=max_dollars)
        world = open_world()
        try:
            return run_goal_sync(LLM(), world, budget, goal_id,
                                 sandbox=build_sandbox(workdir=str(work)),
                                 user_id=user_id, allowed_suites=allowed_suites)
        finally:
            close_world_if_owned(world)
    return run


def default_reviewer() -> Reviewer:
    """The independent diff reviewer (cross-family where possible)."""
    def review(brief: str, diff: str) -> dict:
        import asyncio

        from ..llm import LLM
        from ..reviewer import review_diff
        verdict = asyncio.run(review_diff(brief, diff, LLM()))
        return {"approves": bool(verdict.approves), "confidence": float(verdict.confidence),
                "blockers": len(verdict.blockers),
                "comments": [{"path": c.path, "line": c.line, "severity": c.severity,
                              "message": c.message} for c in verdict.comments[:50]]}
    return review


__all__ = ["default_reviewer", "default_runner", "find", "list_proposals", "merge",
           "propose", "push", "run_tests", "settle", "status"]


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
        proposals.append({
            "id": p["id"], "repo": p["repo"], "title": p["title"], "branch": p["branch"],
            "status": status(world, p), "files": len(p["files"]),
            "tests": None if tests is None else tests["passed"],
            "review": None if review is None else bool(review.get("approves")),
            "approval_id": p["approval_id"], "created_at": p["created_at"]})
    return {"schema": "lightwork.codebase-summary.v1", "enabled": vault.enabled(),
            "repos": repos, "proposals": proposals}

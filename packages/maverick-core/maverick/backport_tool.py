"""Security-backport tooling (policy in docs/security-backports.md).

Read-only git analysis that makes the backport policy executable:

* :func:`eligible_commits` — commits whose subject carries a security marker
  (``security:`` / ``fix(security)``) or a ``Security-Backport: yes`` trailer.
* :func:`plan` — eligible commits **not yet** on a release branch, matched by
  a hash of each commit's changed lines (so a cherry-picked fix with a
  different SHA, or at a shifted line offset, is still recognized), as an
  ordered cherry-pick plan. It is the same idea as ``git patch-id``, computed
  here from ``git show``.
* :func:`check` — the SLA gate: eligible fixes older than ``sla_days`` that
  are still missing from the branch (CI exits non-zero on any).

The git runner is injected so everything is unit-tested offline; the real
runner shells ``git`` read-only (log / show). Cherry-picking and pushing
remain the maintainer's reviewed acts — this tool never mutates the repo.
"""

from __future__ import annotations

import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass

_MARKER = re.compile(r"^(security:|fix\(security\))", re.IGNORECASE)
_TRAILER = re.compile(r"^Security-Backport:\s*yes\s*$", re.IGNORECASE | re.MULTILINE)
SLA_DAYS = 7.0
_COMMIT_SHA = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)

Runner = Callable[[list[str]], str]


def _real_git(args: list[str]) -> str:
    out = subprocess.run(["git", *args], capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(f"git {' '.join(args[:2])} failed: {out.stderr.strip()[:200]}")
    return out.stdout


@dataclass(frozen=True)
class Fix:
    sha: str
    subject: str
    committed_at: float
    files: tuple[str, ...] = ()


def is_security_fix(subject: str, body: str = "") -> bool:
    return bool(_MARKER.match(subject.strip()) or _TRAILER.search(body or ""))


def _valid_commit_sha(sha: str) -> bool:
    """Return whether ``sha`` is a full hexadecimal commit object id."""
    return bool(_COMMIT_SHA.fullmatch(sha))


def eligible_commits(since_ref: str, *, branch: str = "main", git: Runner = _real_git) -> list[Fix]:
    """Backport-eligible commits on ``branch`` since ``since_ref``."""
    raw = git(["log", f"{since_ref}..{branch}", "--format=%H%x01%ct%x01%s%x01%b%x02"])
    fixes: list[Fix] = []
    for chunk in raw.split("\x02"):
        chunk = chunk.strip("\n")
        if not chunk.strip():
            continue
        parts = chunk.split("\x01", 3)
        if len(parts) < 3:
            continue
        sha, ct, subject = parts[0].strip(), parts[1], parts[2]
        if not _valid_commit_sha(sha):
            continue
        body = parts[3] if len(parts) > 3 else ""
        if not is_security_fix(subject, body):
            continue
        try:
            files = tuple(
                f
                for f in git(
                    ["show", "--name-only", "--format=", "--end-of-options", sha]
                ).splitlines()
                if f.strip()
            )
        except RuntimeError:
            files = ()
        fixes.append(Fix(sha=sha, subject=subject, committed_at=float(ct), files=files))
    return fixes


def _patch_id_of(sha: str, git: Runner) -> str:
    """A SHA-independent identity for a commit's change (cherry-pick twin
    detection): hash the file headers and the added and removed lines.

    Hunk headers are left out. They carry line numbers, which differ on a
    branch where the same change lands at another offset."""
    import hashlib

    if not _valid_commit_sha(sha):
        raise RuntimeError("invalid commit object id")
    diff = git(["show", "--format=", "--end-of-options", sha])
    lines = [
        line
        for line in diff.splitlines()
        if line.startswith(("+", "-", "diff --git")) and not line.startswith(("+++", "---"))
    ]
    # SHA1 as in `git patch-id`: a content fingerprint for cherry-pick twin
    # detection, not a security boundary.
    return hashlib.sha1("\n".join(lines).encode(), usedforsecurity=False).hexdigest()


def _patch_ids(ref_range: str, git: Runner) -> set[str]:
    """Change ids (:func:`_patch_id_of`) of every commit in ``ref_range``."""
    try:
        shas = [s.strip() for s in git(["log", "--format=%H", ref_range]).splitlines() if s.strip()]
    except RuntimeError:
        return set()
    ids: set[str] = set()
    for sha in shas:
        try:
            ids.add(_patch_id_of(sha, git))
        except RuntimeError:
            continue
    return ids


def plan(
    lts_branch: str, since_ref: str, *, branch: str = "main", git: Runner = _real_git
) -> list[Fix]:
    """Eligible commits not yet on ``lts_branch`` (matched by change id)."""
    fixes = eligible_commits(since_ref, branch=branch, git=git)
    if not fixes:
        return []
    on_lts = _patch_ids(f"{since_ref}..{lts_branch}", git)
    out = []
    for f in fixes:
        try:
            pid = _patch_id_of(f.sha, git)
        except RuntimeError:
            pid = ""
        if pid and pid in on_lts:
            continue
        out.append(f)
    return out


def check(
    lts_branch: str,
    since_ref: str,
    *,
    branch: str = "main",
    sla_days: float = SLA_DAYS,
    git: Runner = _real_git,
    now: float | None = None,
) -> list[Fix]:
    """Fixes past the backport SLA still missing from the branch."""
    ts = float(now if now is not None else time.time())
    cutoff = ts - sla_days * 86400.0
    return [
        f for f in plan(lts_branch, since_ref, branch=branch, git=git) if f.committed_at <= cutoff
    ]


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse

    p = argparse.ArgumentParser(
        prog="maverick.backport_tool", description="Security-backport planner (read-only)."
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("since_ref")
    pl = sub.add_parser("plan")
    pl.add_argument("lts_branch")
    pl.add_argument("since_ref")
    ck = sub.add_parser("check")
    ck.add_argument("lts_branch")
    ck.add_argument("since_ref")
    args = p.parse_args(argv)
    if args.cmd == "scan":
        for f in eligible_commits(args.since_ref):
            print(f"{f.sha[:12]}  {f.subject}")
        return 0
    if args.cmd == "plan":
        todo = plan(args.lts_branch, args.since_ref)
        for f in todo:
            print(f"git cherry-pick -x {f.sha}   # {f.subject}")
        return 0
    overdue = check(args.lts_branch, args.since_ref)
    for f in overdue:
        print(f"OVERDUE (> {SLA_DAYS:g}d): {f.sha[:12]} {f.subject}")
    return 1 if overdue else 0


__all__ = ["Fix", "is_security_fix", "eligible_commits", "plan", "check", "SLA_DAYS"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""Security-backport planner: eligibility, patch-id plans, SLA gate."""

from __future__ import annotations

from maverick.backport_tool import (
    check,
    eligible_commits,
    is_security_fix,
    plan,
)


def test_is_security_fix_markers():
    assert is_security_fix("security: scrub tokens from logs")
    assert is_security_fix("fix(security): patch SSRF in http_fetch")
    assert is_security_fix("feat: x", body="Closes #1\nSecurity-Backport: yes\n")
    assert not is_security_fix("feat: add a pony")
    assert not is_security_fix("fix: typo in docs")


class FakeGit:
    """Scripted git: main log + per-sha diffs + lts log."""

    def __init__(self, main_commits, lts_shas=()):
        # main_commits: list of (sha, ct, subject, body, diff)
        self.main = main_commits
        self.lts_shas = list(lts_shas)
        self.diffs = {sha: diff for sha, _ct, _s, _b, diff in main_commits}

    def __call__(self, args):
        if args[0] == "log" and "--format=%H%x01%ct%x01%s%x01%b%x02" in args:
            return "".join(
                f"{sha}\x01{ct}\x01{subject}\x01{body}\x02"
                for sha, ct, subject, body, _d in self.main
            )
        if args[0] == "log" and args[1] == "--format=%H":
            return "\n".join(self.lts_shas)
        if args[0] == "show" and "--name-only" in args:
            return "maverick/x.py\n"
        if args[0] == "show":  # diff for patch-id
            sha = args[-1]
            return self.diffs.get(sha, f"diff --git a/{sha} b/{sha}\n+{sha}\n")
        raise AssertionError(f"unexpected git call: {args}")


_SEC = ("a" * 40, "1700000000", "security: scrub creds", "", "diff --git a/s.py b/s.py\n+scrub()\n")
_FEAT = ("b" * 40, "1700000100", "feat: pony", "", "diff --git a/p.py b/p.py\n+pony\n")
_SEC2 = ("c" * 40, "1700000200", "fix(security): ssrf", "", "diff --git a/h.py b/h.py\n+pin_ip()\n")


def test_eligible_commits_filters_markers():
    git = FakeGit([_SEC, _FEAT, _SEC2])
    fixes = eligible_commits("v1.0", git=git)
    assert [f.subject for f in fixes] == ["security: scrub creds", "fix(security): ssrf"]
    assert fixes[0].files == ("maverick/x.py",)


def test_eligible_commits_ignores_forged_delimiter_record():
    forged = "--output=/tmp/backport_pwn"
    raw = (
        f"{_SEC[0]}\x01{_SEC[1]}\x01{_SEC[2]}\x01"
        f"body\x02{forged}\x011700000100\x01security: injected\x01body\x02"
    )
    calls = []

    def git(args):
        calls.append(args)
        if args[0] == "log":
            return raw
        if args[0] == "show":
            return "maverick/x.py\n"
        raise AssertionError(f"unexpected git call: {args}")

    fixes = eligible_commits("v1.0", git=git)

    assert [f.sha for f in fixes] == [_SEC[0]]
    assert all(forged not in args for args in calls if args[0] == "show")
    assert calls[1] == [
        "show",
        "--name-only",
        "--format=",
        "--end-of-options",
        _SEC[0],
    ]


def test_plan_uses_option_terminator_for_patch_id():
    calls = []

    def git(args):
        calls.append(args)
        if args[0] == "log" and "--format=%H%x01%ct%x01%s%x01%b%x02" in args:
            return f"{_SEC[0]}\x01{_SEC[1]}\x01{_SEC[2]}\x01{_SEC[3]}\x02"
        if args[0] == "log" and args[1] == "--format=%H":
            return ""
        if args[0] == "show" and "--name-only" in args:
            return "maverick/x.py\n"
        if args[0] == "show":
            return _SEC[4]
        raise AssertionError(f"unexpected git call: {args}")

    assert plan("lts/1.0", "v1.0", git=git)
    assert ["show", "--format=", "--end-of-options", _SEC[0]] in calls


def test_plan_skips_cherry_picked_twin():
    # the LTS branch carries a commit with a DIFFERENT sha but the SAME diff
    # as _SEC -> patch-id match -> not re-planned.
    twin_sha = "d" * 40
    git = FakeGit([_SEC, _SEC2], lts_shas=[twin_sha])
    git.diffs[twin_sha] = _SEC[4]  # same diff as _SEC
    todo = plan("lts/1.0", "v1.0", git=git)
    assert [f.subject for f in todo] == ["fix(security): ssrf"]


def test_plan_empty_when_all_ported():
    t1, t2 = "d" * 40, "e" * 40
    git = FakeGit([_SEC, _SEC2], lts_shas=[t1, t2])
    git.diffs[t1] = _SEC[4]
    git.diffs[t2] = _SEC2[4]
    assert plan("lts/1.0", "v1.0", git=git) == []


def test_check_sla_gate():
    git = FakeGit([_SEC, _SEC2])  # nothing ported
    now = 1700000200 + 8 * 86400  # both > 7 days old
    overdue = check("lts/1.0", "v1.0", git=git, now=now)
    assert len(overdue) == 2
    # within the SLA window -> not yet overdue
    fresh = check("lts/1.0", "v1.0", git=git, now=1700000200 + 3600)
    assert fresh == []


def test_check_partial_overdue():
    git = FakeGit([_SEC, _SEC2])
    # cutoff = now - 7d = 1700000100: _SEC (t=...000) is past it, _SEC2
    # (t=...200) is still inside the SLA window.
    now = 1700000100 + 7 * 86400
    overdue = check("lts/1.0", "v1.0", git=git, now=now)
    assert [f.subject for f in overdue] == ["security: scrub creds"]

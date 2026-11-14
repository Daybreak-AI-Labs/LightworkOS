#!/usr/bin/env python3
"""Refuse AI-attribution trailers and footers in commit messages and PR text.

Project policy (see "Commits and pull requests" in CONTRIBUTING.md): nothing
that lands in this repository or on GitHub carries a generator footer, an AI
co-author trailer, or an assistant session link. The MERGE step can break the
rule even when authors do not: a squash merge prefills the merge commit from
the branch's commit messages, so one trailer on one branch commit lands on
``main`` inside the squash. This gate runs at each place such a line can still
be refused:

* ``pull_request`` -- every commit in the PR range plus the PR title and body
  (the squash dialog is prefilled from exactly these).
* ``merge_group`` -- the merge-queue commit: the message that will become
  ``main``'s history, including anything typed into the merge dialog.
* ``push`` to ``main`` -- detective. If something slipped past, ``main`` goes
  red instead of quietly accumulating trailers.

The commit AUTHOR and COMMITTER identities are inspected as well as the
message: GitHub's squash merge appends a ``Co-authored-by:`` trailer for every
distinct author in the squashed commits, so a branch whose commits are merely
*authored* as an assistant lands the trailer on ``main`` without a single
offending line in any message.

Usage::

    python scripts/check_attribution.py --commits BASE..HEAD [--text FILE ...]
    python scripts/check_attribution.py --text pr-body.md
    git log -1 --format=%B | python scripts/check_attribution.py --stdin

Exit 0 when clean, 1 on findings, 2 when nothing was inspected: a range that
resolves to zero commits is a misconfigured gate, not a pass.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

#: Assistants whose name in a trailer or footer marks it as AI attribution.
#: Human co-authors and non-assistant bots (dependabot, renovate) pass.
_ASSISTANTS = (
    r"(?:claude|anthropic|copilot|chatgpt|openai|codex|gemini|cursor|devin|"
    r"aider|windsurf|jules\[bot\]|amp|openhands|claudebot)"
)

# A first name alone is not an assistant identity. Pair vendor identities
# with their known addresses, or match a complete assistant bot login.
_BOT_LOGIN = r"(?:jules\[bot\]|copilot\[bot\]|claude\[bot\]|claudebot|openhands\[bot\]|gemini-code-assist\[bot\]|devin-ai-integration\[bot\]|cursoragent)"
IDENTITY_RULE = re.compile(
    rf"^(?:{_BOT_LOGIN})(?:\s*<[^<>]+>)?$|"
    r"^(?:claude(?:\s+[^<>]+)?|anthropic|assistant)\s*<noreply@anthropic\.com>$|"
    r"^(?:chatgpt|openai|codex)\s*<noreply@openai\.com>$|"
    r"^copilot\s*<copilot@github\.com>$|"
    r"^devin\s*<(?:devin|noreply)@cognition\.(?:ai|com)>$|"
    r"^cursor\s*<cursoragent@cursor\.com>$|"
    r"^amp\s*<amp@ampcode\.com>$|"
    r"^openhands\s*<openhands@all-hands\.dev>$",
    re.IGNORECASE,
)
_TRAILER = re.compile(
    r"^\s*(co-authored-by|assisted-by|generated-by|ai-assisted-by|co-developed-by):\s*(.*?)\s*$",
    re.IGNORECASE,
)
_NAME_ONLY = re.compile(rf"(?:{_ASSISTANTS}|claude code)", re.IGNORECASE)
_GENERATOR = re.compile(r"generated (?:with|by)\s+(.+?)\s*$", re.IGNORECASE)

RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("assistant session trailer",
     re.compile(r"^\s*claude-session:", re.IGNORECASE)),
    ("assistant session link",
     re.compile(r"claude\.(?:ai|com)/code/session", re.IGNORECASE)),
    ("generator footer",
     re.compile(r"\U0001F916\s*generated", re.IGNORECASE)),
    ("Anthropic no-reply trailer",
     re.compile(r"^\s*[a-z-]+-by:.*noreply@anthropic\.com", re.IGNORECASE)),
)


def _assistant_credit(value: str) -> bool:
    credit = value.strip(" *_\t")
    link = re.fullmatch(r"\[([^\]]+)\]\([^)]+\)", credit)
    if link:
        credit = link.group(1)
    return bool(IDENTITY_RULE.fullmatch(credit) or _NAME_ONLY.fullmatch(credit))


def identity_findings(author: str, committer: str, source: str) -> list[str]:
    """Author/committer identities of one commit that are assistant identities."""
    out: list[str] = []
    for role, identity in (("author", author), ("committer", committer)):
        if IDENTITY_RULE.fullmatch(identity.strip()):
            out.append(f"{source}: AI {role} identity: {identity}")
    return out


def findings(text: str, source: str) -> list[str]:
    """Every line of ``text`` that carries AI attribution, labelled by rule."""
    out: list[str] = []
    for number, line in enumerate(text.splitlines(), 1):
        trailer = _TRAILER.fullmatch(line)
        if trailer:
            if _assistant_credit(trailer.group(2)):
                rule = "AI co-author trailer" if trailer.group(1).lower() == "co-authored-by" else "AI attribution trailer"
                out.append(f"{source}:{number}: {rule}: {line.strip()}")
                continue
        generator = _GENERATOR.search(line)
        if generator and _assistant_credit(generator.group(1)):
            out.append(f"{source}:{number}: generator footer: {line.strip()}")
            continue
        for rule, pattern in RULES:
            if pattern.search(line):
                out.append(f"{source}:{number}: {rule}: {line.strip()}")
                break
    return out


def commit_records(rev_range: str, repo: Path | None = None) -> list[tuple[str, str, str, str]]:
    """(sha, author, committer, full message) for every commit in ``rev_range``,
    newest first. Identities are ``Name <email>``."""
    proc = subprocess.run(
        ["git", "log", "-z", "--format=%H%n%an <%ae>%n%cn <%ce>%n%B", rev_range],
        cwd=repo, capture_output=True, text=True, check=True,
    )
    out: list[tuple[str, str, str, str]] = []
    for chunk in proc.stdout.split("\0"):
        if not chunk.strip():
            continue
        sha, author, committer, body = (chunk.split("\n", 3) + ["", "", ""])[:4]
        out.append((sha, author, committer, body))
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--commits", metavar="RANGE",
                    help="git revision range whose commit messages are checked "
                         "(e.g. BASE..HEAD)")
    ap.add_argument("--text", action="append", default=[], type=Path, metavar="FILE",
                    help="a file of prose to check (PR title/body); repeatable")
    ap.add_argument("--stdin", action="store_true",
                    help="also check a message read from standard input")
    ap.add_argument("--repo", type=Path, default=None,
                    help="repository to read commits from (default: cwd)")
    args = ap.parse_args(argv)

    inspected = 0
    commits_inspected = 0
    problems: list[str] = []
    if args.commits is not None:
        try:
            records = commit_records(args.commits, args.repo)
        except subprocess.CalledProcessError as exc:
            print(f"check-attribution: ERROR -- git log {args.commits!r} failed: "
                  f"{exc.stderr.strip()}", file=sys.stderr)
            return 2
        for sha, author, committer, body in records:
            commits_inspected += 1
            inspected += 1
            source = f"commit {sha[:12]}"
            problems.extend(identity_findings(author, committer, source))
            problems.extend(findings(body, source))
    for path in args.text:
        inspected += 1
        problems.extend(findings(path.read_text(encoding="utf-8", errors="replace"),
                                 str(path)))
    if args.stdin:
        inspected += 1
        problems.extend(findings(sys.stdin.read(), "stdin"))

    if inspected == 0 or (args.commits is not None and commits_inspected == 0):
        print("check-attribution: ERROR -- inspected nothing in the requested commit "
              "range, or no input supplied; refusing to pass vacuously", file=sys.stderr)
        return 2
    if problems:
        print("check-attribution: AI attribution is not allowed in commit messages "
              "or PR text (see 'Commits and pull requests' in CONTRIBUTING.md):",
              file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print("\nDrop the trailer/footer and rewrite the commit (git commit --amend, "
              "or git rebase -i for older ones), or edit the PR description. An AI "
              "author/committer identity must be recommitted under a human one "
              "(git config user.name/user.email, then git commit --amend "
              "--reset-author, or git rebase --exec for older commits): the squash "
              "merge turns every distinct author into a Co-authored-by trailer. All "
              "of this must be clean before the merge, not after.", file=sys.stderr)
        return 1
    print(f"check-attribution: clean ({inspected} message(s) inspected)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

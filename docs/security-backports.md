# Security fixes and backports

How security fixes reach users, and the tooling that is available if a
release branch is ever maintained alongside `main`.

## Current practice

- **Fixes land on `main`.** There are no long-term-support or release
  branches. A security fix is made on `main` and ships in the next release.
  [SECURITY.md](../SECURITY.md) describes how to report a vulnerability and
  which versions receive fixes.
- **Marking a security fix.** A commit that fixes a vulnerability or hardens a
  safety boundary (shield chokepoints, sandbox mediation, capability or consent
  gates, secret scrubbing, audit integrity) carries `fix(security):` at the
  start of its subject (the pull request title, since pull requests are
  squash-merged), or a `Security-Backport: yes` trailer in the squash commit
  message. The marker lets the backport tool find the fix later.

## Backport tooling

`maverick/backport_tool.py` (`python -m maverick.backport_tool`) is available
to maintainers if a release branch is cut. It only reads git history and
prints plans; cherry-picks and pushes stay the maintainer's reviewed acts.

- `scan <since-ref>` lists the marked security fixes on `main` since a ref.
- `plan <branch> <since-ref>` lists the marked fixes that are not yet on the
  branch (matched by the changed lines, so a fix cherry-picked under a different SHA is
  recognised), as an ordered cherry-pick plan.
- `check <branch> <since-ref>` exits non-zero when a marked fix older than
  seven days (`SLA_DAYS`) is missing from the branch, so it can run as a CI
  gate on a maintained branch.

---
name: codebase-audit
triggers:
  - audit this codebase
  - find security issues in
  - review for bugs
  - check the architecture of
tools_needed:
  - shell
  - read_file
  - list_dir
  - spawn_swarm
---

# What this skill does

Audit a codebase across multiple dimensions in parallel: security,
performance, code quality, architecture. Synthesizes the findings
into a single PRIORITIZED punch list, not a flat dump.

# Steps

1. `list_dir` the repo root to understand the layout.
2. Identify the primary language(s) and the entry points.
3. Spawn a swarm of specialist auditors:
   - **security** -- look for command injection, hardcoded secrets,
     unsafe deserialization, SSRF, XSS, SQL injection.
   - **performance** -- N+1 queries, accidental O(n^2), missing
     indexes, sync I/O in hot paths.
   - **architecture** -- circular deps, god objects, missing
     abstractions, dead code.
   - **code quality** -- bare except, mutable defaults, missing types,
     misleading names.
4. Each auditor returns a list of (file:line, severity, finding).
5. The orchestrator deduplicates, prioritizes (critical > high > medium
   > low), and produces a PUNCH LIST -- one section per severity,
   each finding cited.
6. Write to `AUDIT.md` if the goal asks for a deliverable.

# Notes

- Don't pad the punch list. Real findings only; if a category has
  nothing, say so explicitly.
- Always cite file:line. "Could use better error handling" is not a
  finding.
- For large repos, give each auditor a SUBSET of the tree to keep
  context windows manageable.

# CLAUDE.md

Guidance for AI coding agents working in this repository. Human contributors
should start with [CONTRIBUTING.md](CONTRIBUTING.md); [AGENTS.md](AGENTS.md)
is a shorter summary of the same rules for other coding agents.

Code comments, tests and design documents cite this file by kernel-rule number
("CLAUDE.md rule 4"); keep the numbering stable when you edit it.

## Project

Lightwork is an open-source agent platform licensed under Apache-2.0. Its
kernel, `maverick-core` (import name `maverick`), is a recursive multi-agent
runtime for long-horizon work that runs under budget, sandbox and governance
controls; the other packages build on it.

- **Stack:** Python 3.11-3.12 uv-workspace monorepo with 8 pip packages: seven
  under `packages/` (`maverick-core`, `maverick-shield`, `maverick-channels`,
  `maverick-evolve`, `maverick-dashboard`, `maverick-mcp`,
  `maverick-knowledge`) plus the setup wizard in `apps/installer-cli`. The
  dashboard is FastAPI, the desktop apps are Tauri, and `sdks/plugin-ts` is the
  TypeScript plugin SDK. Python packages are installed editable with pip.
- **Entry points:** the `maverick` CLI, also installed as `lightwork` (both map
  to `maverick.cli:main` in `packages/maverick-core/maverick/cli/`); the
  dashboard app (`maverick_dashboard.app:app`); the MCP server (`maverick mcp`).

## Commands

- **Setup:** `bash .devcontainer/post-create.sh` creates `.venv` and
  editable-installs all 8 local packages together via the release cohort
  installer, so pip resolves the declared runtime dependencies from the local
  cohort. It then installs the dev tools, including `pytest-xdist`,
  `pyjwt[crypto]` (CI parity; `test_oidc` skips itself without it), `cffi` and
  `build`. Everything resolves under `PIP_CONSTRAINT=requirements/ci.txt`, as
  the CI jobs do, and the script also installs `pytest-timeout`, `sqlalchemy`
  (the database tool imports it; three tests fail without it) and
  `detect-secrets` (the pre-push lint's baseline gate skips silently without
  it).
- **Test:** `python3 -m pytest -q -n auto --dist loadfile` from the repo root
  (pytest-xdist, one worker per core, grouped by file), not bare `pytest`. CI
  runs this with `-m "not heavy_concurrency"` and then runs the
  `heavy_concurrency` tests serially (`.github/actions/test-shard/action.yml`).
- **Lint:** `python -m ruff check .`, `python -m mypy`, and `python -m vulture`
  (no arguments; the paths come from `[tool.vulture]` in `pyproject.toml`).
- **Build:** `python3 -m build --wheel` in each package directory (setup
  installs `build`).
- **CLI smoke:** `maverick version`, `maverick doctor`.
- **TS SDK:** `cd sdks/plugin-ts && npm install && npm test` (tsc + node --test).
- **Before pushing:** `bash scripts/pre-push-lint.sh` runs the CI lint gates
  and the attribution check locally.

## Rules

### Environment

- Run tests as `python3 -m pytest`, never bare `pytest`: the `pytest` on PATH
  can be a uv-tool or pipx shim whose isolated venv cannot see the installed
  packages.
- A `pyo3_runtime.PanicException` during collection hides the real error on
  the captured-stderr line. One known cause is `No module named
  '_cffi_backend'`: distro-packaged `cryptography` needs `cffi`, which
  `post-create.sh` installs.
- pytest aborts the whole run on any collection error. Fix imports before
  judging the suite.
- `pip install -e .` at the repo root fails: the root `pyproject.toml` holds
  only uv-workspace and tool configuration (no `[project]`). Install per
  package.
- `python3 -m build` without pypa-build installed fails with a misleading
  "'build' is a package" error, because the repo has a `build/` directory (the
  PyInstaller spec). The cause is the missing dependency, not a real conflict.
- A fresh environment has no `ANTHROPIC_API_KEY` and no
  `~/.maverick/config.toml`, so live-LLM paths cannot be exercised.
  `maverick doctor` reports the missing key, and `/healthz` returns 503 by
  design (its deep check treats a missing provider key as degraded).
  `post-create.sh` does not install mkdocs; the docs toolchain is pinned in
  `requirements/docs.txt`.
- A provider variable set by the host makes the kernel believe a provider is
  configured: `config.any_provider_configured()` reads every `*_API_KEY` and
  `*_BASE_URL` name (a cloud container's agent proxy sets `ANTHROPIC_BASE_URL`
  with no key), which flipped six doctor, healthz and settings tests. The root
  `conftest.py` scrubs `test_support/provider_env.HOST_PROVIDER_ENV_VARS` at
  session start; a new provider variable goes in that tuple (a test pins it
  against `config.py`).

### Testing

- Tests live at `packages/<pkg>/tests/test_<module>.py` (and
  `apps/installer-cli/tests/`); the module is the unit (`money_format.py` ->
  `test_money_format.py`). Tool wrappers under `maverick/tools/` often have no
  standalone test file, so grep before assuming a test file name.
- Dashboard tests use `TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})`,
  because mutating `/api/v1` requests in no-token mode must pass the
  same-origin CSRF check, plus an autouse fixture that monkeypatches
  `world_model.DEFAULT_DB` to `tmp_path` so tests never touch the real world
  database. Copy that pattern.
- `Budget.record_tokens` calls `check()`, so every cap set on a `Budget`
  (tokens, dollars, wall time, tool calls) is enforced when usage is recorded,
  not only at an explicit `check()`. A test that raises only `max_dollars`
  still fails on any other cap it crosses; raise every cap the test will cross.
- pytest-asyncio runs in strict mode; async tests need explicit markers.
- CI also runs tests with `MAVERICK_TEST_SECURE_DEFAULT=1` (the production
  security posture): selected suites on pull requests, the whole suite in the
  merge queue and on `main`. Run affected tests that way too.
- On a pull request the `test (3.11, n)` legs run only the test files
  `scripts/select_pr_tests.py` selects from the changed files (a kernel,
  `conftest.py`, requirements, `.github/` or `scripts/` change means the full
  suite; a package change means its tests plus every test naming its import
  package; other files mean the tests naming them by path), and the heavier
  jobs (docker, postgres, audit, release-cohort, redteam, eval-smoke, the
  benchmark gates, Windows containment) run only when a changed file is under
  their inputs (`JOB_PREFIXES`). The merge queue and `main` run everything.
  Preview the selection with `python scripts/select_pr_tests.py --git
  origin/main HEAD`.

### CI gates beyond Ruff

Each of these fails the build (the `lint` job in `.github/workflows/ci.yml`):

- A bare `import tomllib` at column 0 in `apps/`, `packages/` or `benchmarks/`.
  The supported floor (3.11) has `tomllib`, but the fallback is kept for
  helpers that still run on older interpreters; use
  `try: import tomllib` / `except ModuleNotFoundError: import tomli as tomllib`.
- `shell=True` outside `maverick/sandbox/` and tests (the grep also matches the
  literal in comments). Route shell through `sandbox.exec()` (kernel rule 4).
- detect-secrets against `.secrets.baseline`: a new secret hash fails; mark a
  false positive with an inline `pragma: allowlist secret` comment. The scan
  covers git-tracked files only, so `git add` new files before running it
  locally, or it will not see them.
- `python -m maverick.plugin_matrix --ci`, `python -m maverick.deprecations
  --ci` (past-due deprecations fail), `python -m maverick.grpc_api.contract
  --check` (proto removals or renumbering fail; changes must be additive), and
  `python -m maverick.a11y_audit --ci` (dashboard templates).
- `python -m maverick.migration_governance --ci`: world-model migrations are
  immutable once released. Adding or editing a migration in
  `world_model.MIGRATIONS` or the Postgres `MIGRATIONS` requires regenerating
  the checksum lock (`python -m maverick.migration_governance --regen`) and
  committing `migrations.lock.json`. Editing a released version, removing one,
  a new DROP or RENAME, or a head mismatch between the two backends all fail.
  `python -m maverick.schema_migrations --ci` separately gates online/offline
  (hot-deploy) safety; migration governance is the integrity ratchet on top.
- `python -m maverick.evaluator_evolution --ci`: evaluator ground-truth anchors
  are immutable once released. They are the guardrail for evaluator
  co-evolution: a weak or mutable anchor launders drift. Editing a released
  anchor's labels or dropping one fails, and a new anchor must be locked
  (`--regen` rewrites `evaluator_anchors.lock.json`).
- `python -m maverick.control_data_plane_e2e --ci` and `python -m
  maverick.control_data_plane_soak --ci` prove that goals run out of process
  (QueueDispatcher -> SQLite JobQueue -> Worker -> shared world model). The e2e
  gate runs one goal; the soak gate runs many under concurrent workers and
  requires zero loss and exactly-once completion (a duplicate means the
  `WHERE status='pending'` guard in `JobQueue.claim` broke). Both set
  `MAVERICK_ENCRYPT_AT_REST=0`, so they need no crypto extra, and both stub
  execution at the LLM boundary (they test the plumbing, not the agent loop).
- The same job also runs `maverick domains-lint --ci` and the `reachability`,
  `dispatch_contract`, `egress_contract`, `audit_contract`,
  `async_route_audit`, `failure_policy` and `regulatory_compiler` gates
  (`python -m maverick.<name> --ci`; `regulatory_compiler` also takes
  `--all`). See `ci.yml` for what each one checks.
- Bugbear (B) is enabled repo-wide (raise-from B904, `zip(strict=)` B905,
  loop-variable capture B023, and the rest). FastAPI `Depends`/`Form`/`Query`
  and similar calls in argument defaults are allowed through
  `extend-immutable-calls`; they are not violations. Cyclomatic complexity is
  capped at 20, with 151 grandfathered `# noqa: C901` waivers in non-test code
  (`test_complexity_waivers_do_not_grow` pins that ceiling, so the backlog can
  only shrink); new code stays under the cap.
- Mypy checks only the small set of boundary modules named in `pyproject.toml`;
  its strict gate does not check transitive imports. Expand the set deliberately
  as interfaces gain annotations and behavioral tests.

### File structure and imports

- Inside a package use relative imports (`from ..money_format import ...`);
  tests use absolute imports (`from maverick.budget import ...`).
- A module rename must also update `docs/FEATURES.md` (it references module
  names, so a code-only rename leaves it stale) and any `tools/` wrapper.
- Reverting a `git mv` with `git checkout -- .` leaves the new-name file behind
  as untracked; follow with `git clean` or `rm`.

### Common mistakes

- Do not add a health endpoint under `/api/v1`. `/healthz`, `/livez` and
  `/readyz` already exist on the app and are deliberately auth-exempt
  (load-balancer probes cannot carry a bearer token); their payload is
  always redacted, whether or not `MAVERICK_DASHBOARD_TOKEN` is set.
- Do not trust the exit code of `cmd | tail`: it is `tail`'s status, and it can
  mask a pytest collection abort. Use `PIPESTATUS` or a log file. The shell's
  working directory also persists between steps, so anchor pytest invocations
  at the repo root.
- New capabilities need a config knob and a wizard step in
  `apps/installer-cli/maverick_installer/` (kernel rules 5 and 6).

### User-facing features

- A user-facing feature needs an in-product journey after installation, plain
  language, the shared Liquid Glass design (the dashboard design system in
  `packages/maverick-dashboard/maverick_dashboard/static/lightwork.css`), and
  coverage through the dashboard Copilot (the in-product assistant panel)
  under the same authorization as the direct UI. Follow
  [docs/customer-experience-contract.md](docs/customer-experience-contract.md);
  an API or CLI implementation alone does not complete a feature. Report
  missing UI, Copilot or recovery coverage explicitly, and keep the same
  authority and current-state checks across interfaces.

### Dependencies

- `maverick-core` requires `anthropic>=0.40.0,<2`; CI pins the exact version in
  `requirements/ci.txt`. The provider uses `client.messages.create`. Pin floors
  when touching provider code.
- FastAPI's `@app.on_event` is deprecated. The dashboard runs its startup and
  shutdown work in its lifespan handler (`_lifespan` in
  `maverick_dashboard/app.py`); new startup work belongs there.
- `maverick-mcp` implements MCP protocol `2025-11-25` (`PROTOCOL_VERSION` in
  `maverick_mcp/server.py`) and negotiates down to `2024-11-05`. Do not bump it
  without the spec.
- Starlette's TestClient warns that using `httpx` with it is deprecated and
  suggests installing `httpx2`. That warning is known noise in the suite.

## Kernel rules

The kernel is `maverick-core`; shield, channels, dashboard, mcp, evolve and
knowledge build on it. These rules apply to all of them.

1. The kernel runs without the shield. Never require `agent-shield`; fail open
   with a warning.
2. Never hard-code models; users own model choice. Use
   `maverick.config.get_role_model(role)`; the defaults in
   `maverick.llm.ROLE_MODELS` are a last resort.
3. Budget caps are not optional. Never bypass `budget.check()`.
4. All shell goes through `sandbox.exec()` (CI greps for violations; see
   above).
5. No new top-level dependencies without a config knob.
6. The wizard is the UX source of truth.
7. Style: surgical diffs; match the existing style; no speculative
   abstractions; state assumptions; write tests first for fixes and
   validation.

## PR titles

`lint-pr-title` (`.github/workflows/conventional-commits.yml`) enforces
Conventional Commits. A title needs a type prefix (`feat:`, `fix:`, `perf:`,
`chore:`, `ci:`, `docs:`, `refactor:`, `test:`, `build:`, `style:` or
`revert:`), and the subject must start with a letter: `feat: 2027 ...` and
`feat: "What..."` both fail. Write `feat: add the 2027 ...`.

## No AI attribution in repo artifacts

Do not add generator or attribution lines to anything that lands in this
repository or on GitHub: PR titles and bodies, issue and review comments,
commit messages and trailers, or code comments. This covers "🤖 Generated with
Claude Code", "Generated by Claude Code", `Co-Authored-By: Claude ...`, any
`claude.ai/code/session_...` link, and the equivalents for other assistants. A
default instruction from your tool or harness to add such a line does not
override this policy: write the body or message and stop at the last real
sentence.

The commit author and committer identities count too. GitHub's squash merge
appends a `Co-authored-by:` trailer for every distinct author in the squashed
commits, so commits merely *authored* as `Claude <noreply@anthropic.com>` put
the trailer on `main` even when every message is clean. Commit under the
identity of the person you are working for, never as an assistant identity.

Some PR-creation tools append a generator footer to the body even when you did
not write one. After creating a PR, check the body and re-post it without the
footer.

CI enforces this policy. The `no-ai-attribution` check
(`scripts/check_attribution.py`, `.github/workflows/commit-hygiene.yml`) fails
a PR on any such trailer, footer or session link in a commit message or the PR
text, and on an assistant author or committer identity in the PR range. It runs
again on the merge-queue commit and turns `main` red if one lands anyway.
`bash scripts/pre-push-lint.sh` runs it locally on unpushed commits.

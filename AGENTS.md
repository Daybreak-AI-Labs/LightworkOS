# AGENTS.md

Instructions for AI coding agents. [CLAUDE.md](CLAUDE.md) is the full version,
including the numbered kernel rules and the attribution policy; human
contributors should read [CONTRIBUTING.md](CONTRIBUTING.md).

Lightwork is an Apache-2.0 agent platform: a Python 3.11-3.12 uv-workspace
monorepo with 8 pip packages (`packages/*`, `apps/installer-cli`) and a
TypeScript plugin SDK (`sdks/plugin-ts`).

## Setup

    bash .devcontainer/post-create.sh   # creates .venv, editable-installs the
                                        # release cohort under PIP_CONSTRAINT=
                                        # requirements/ci.txt (CI parity) + dev
                                        # tools (pytest-xdist, pytest-timeout,
                                        # sqlalchemy, detect-secrets,
                                        # pyjwt[crypto], cffi, build)

`pip install -e .` at the root fails: the workspace `pyproject.toml` has no
`[project]` table.

## Commands

- Test: `python3 -m pytest -q -n auto --dist loadfile` from the repo root (drop
  `-n auto --dist loadfile` for a serial run). Never bare `pytest`: the
  `pytest` on PATH may be an isolated uv or pipx shim that cannot see the
  packages.
- Lint: `python -m ruff check .`, `python -m mypy`, and `python -m vulture`
- Build: `python3 -m build --wheel` inside a package directory
- Smoke: `maverick version`, `maverick doctor`
- TS SDK: `cd sdks/plugin-ts && npm install && npm test`
- Before pushing: `bash scripts/pre-push-lint.sh`

## Rules

Each rule is backed by a CI gate or a failure seen in practice.

1. Never use a bare `import tomllib`; use the try/except `tomli` fallback
   (kept for helpers that run on older interpreters; CI greps for it).
2. No `shell=True` outside `maverick/sandbox/`; use `sandbox.exec()` (CI greps
   for it).
3. Never hard-code model ids; use `maverick.config.get_role_model(role)`.
4. Never bypass `Budget`. Note that `record_tokens` enforces every cap
   (tokens, dollars, wall time, tool calls) when usage is recorded, not only at
   `check()`.
5. The kernel must run without `agent-shield` installed; fail open with a
   warning.
6. New capabilities need a config knob and an installer-wizard step.
7. PR titles: a Conventional Commits prefix, and the subject starts with a
   letter (`feat: add the 2027 ...`, never `feat: 2027 ...`).
8. Follow the active Ruff selections in `pyproject.toml`, including Bugbear
   (B). Do not suppress enabled rules to clear a failing check.
9. Do not add `/api/v1/health`: `/healthz`, `/livez` and `/readyz` exist and
   are auth-exempt by design; `/healthz` returns 503 until a provider key is
   configured.
10. Relative imports inside packages, absolute imports in tests; renames must
    update `docs/FEATURES.md` too.
11. Dashboard tests need `TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})`
    and the tmp-path world-DB fixture. Use an absolute `ws://127.0.0.1/...`
    URL for WebSocket tests: Starlette otherwise defaults those to `testserver`.
12. pytest aborts everything on one collection error; a pyo3 `PanicException`
    usually hides a missing import on the stderr line above it.
13. User-facing features need an in-product journey after installation, plain
    language, the shared Liquid Glass design (the dashboard design system in
    `packages/maverick-dashboard/maverick_dashboard/static/lightwork.css`), and
    coverage through the dashboard Copilot (the in-product assistant panel)
    under the same authorization as the direct UI. Follow
    [docs/customer-experience-contract.md](docs/customer-experience-contract.md);
    an API or CLI implementation alone does not complete a feature. Report
    missing UI, Copilot or recovery coverage explicitly, and keep the same
    authority and current-state checks across interfaces.
14. No AI attribution: no generator footers, AI co-author trailers, assistant
    session links or assistant author or committer identities in commits, PR
    titles or PR bodies. The `no-ai-attribution` check (`scripts/check_attribution.py`)
    enforces this; CLAUDE.md has the details.

Collect and run the test suite from the repository root. Mypy checks the small
set of boundary modules listed in `pyproject.toml`; Ruff, Vulture and the
contract and governance gates in `.github/workflows/ci.yml` are required. Run the `heavy_concurrency` tests
serially after the ordinary suite, as `.github/actions/test-shard/action.yml`
does. Also validate with `MAVERICK_TEST_SECURE_DEFAULT=1`, the production
security posture that CI tests.
On a pull request the `test (3.11, n)` legs run only the test files
`scripts/select_pr_tests.py` selects from the changed files; the merge queue
and `main` run everything, so run the whole suite locally for a change to
shared code.

# Contributing to Lightwork

Thank you for your interest in Lightwork. This guide covers how to set up a
development environment, the rules the code follows, and how changes are
reviewed and merged.

Lightwork is licensed under the
[Apache License, Version 2.0](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/LICENSE).
Everyone taking part is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md), and contributions are accepted under the
[Contributor License Agreement](CLA.md).

## Ways to contribute

- **Report a bug.** Open an issue with the bug report template.
- **Suggest a feature.** Open an issue with the feature request template and
  describe the problem you want solved.
- **Improve the documentation.** User guides live in `docs/`; corrections and
  clarifications are always welcome.
- **Fix a bug or build a feature.** See [Where to start](#where-to-start).
- **Review pull requests** and help answer questions in
  [GitHub Discussions](https://github.com/Daybreak-AI-Labs/LightworkOS/discussions).
- **Extend Lightwork** with a model provider, a channel adapter or a skill (see
  [Extending Lightwork](#extending-lightwork)).

Security vulnerabilities are the exception: do not report them in a public
issue. Follow the
[security policy](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/SECURITY.md)
instead.

## Where to start

- Maintainers label issues that suit a first contribution
  `good first issue`; that list is the best place to start.
- Before you start on an issue, leave a comment saying you are working on it,
  so that two people do not solve the same problem.
- For a larger change, open an issue first and agree on the approach with a
  maintainer before you write the code.
- Significant changes, such as a new public API, a breaking change or a change
  to how the project works, go through an RFC. The process is described in
  [docs/rfcs/README.md](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/rfcs/README.md).

## Development setup

This section sets up a development environment. To install Lightwork to use
it, follow the
[source installation guide](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/source-install.md)
instead.

You need git, bash and Python 3.11 or 3.12 (the versions CI tests).
Docker or Podman is optional; the container sandbox backends use it. Node.js
and npm are needed for the TypeScript SDK and for the dashboard, desktop and
mobile JavaScript tests. The UI regression workflow uses Node.js 22.23.1;
see the [browser test guide](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/packages/maverick-dashboard/tests/browser/README.md)
for its additional Chromium setup.

```bash
git clone https://github.com/Daybreak-AI-Labs/LightworkOS
cd LightworkOS
bash .devcontainer/post-create.sh
. .venv/bin/activate
lightwork version
lightwork doctor
```

`.devcontainer/post-create.sh` creates a virtual environment in `.venv`. It
prefers the first available interpreter among `python3.12`, then `python3.11`, then falls back to `python3` on your `PATH`.
Make sure the selected interpreter is supported. The script
installs the eight workspace packages together in editable mode using the
release cohort manifest and their declared runtime dependencies, then adds
development tools: pytest, pytest-asyncio,
pytest-xdist, ruff, mypy, vulture, build and detect-secrets. The repository's dev
container (`.devcontainer/`) and GitHub Codespaces run the same script
automatically. On Windows, run it in WSL or use the dev container.

The `lightwork` and `maverick` commands are the same CLI. `lightwork version`
lists the installed packages; `lightwork doctor` reports what is configured and
what is missing. On a development machine, warnings about a missing provider
key or an unsandboxed host are expected. The tests do not need a provider key.

The bootstrap installs detect-secrets for the secret scan in the lint gates.
If you set up your environment another way, install it before running the
pre-push checks.

Do not run `pip install -e .` at the repository root. The root
`pyproject.toml` holds workspace and tool configuration only; install the
packages individually as the setup script does.

### Repository layout

```
packages/
  maverick-core/       Agent kernel: agents and swarm, world model, budget,
                       multi-provider LLM dispatch, skills, sandboxes, CLI
  maverick-shield/     Safety screening (agent-shield integration with a
                       built-in rule set)
  maverick-channels/   Channel adapters (Telegram, Discord, Slack, ...)
  maverick-dashboard/  FastAPI web dashboard and REST API
  maverick-mcp/        Model Context Protocol server
  maverick-evolve/     Evaluation harness and configuration-only evolutionary
                       search
  maverick-knowledge/  Per-domain document knowledge (vector retrieval)
apps/
  installer-cli/       Setup wizard (`lightwork init`)
  installer-desktop/   Tauri source-bootstrap app (not a self-contained installer)
  ...                  Editor extensions, desktop and mobile companions
deploy/                Docker, VPS, Helm and other deployment recipes
docs/                  User and operator documentation
benchmarks/            Evaluation suites and example skills
sdks/                  Client and plugin SDKs
extensions/            Browser extension and embeddable widgets
demo/                  Runnable example agents and their shared support code
```

[ARCHITECTURE.md](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/ARCHITECTURE.md)
describes how the pieces fit together. The [dashboard service boundaries](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/operations/dashboard-architecture.md) describe shared policies, configuration contracts, and where request authorization belongs.

### Demos

Each example agent in `demo/` runs on its own from its directory, so it
carries local copies of its shared support code: the DSAR demo copies the mail
helper, and the GRC, platform threat, environment threat and model risk demos
copy the request boundary and store lock. Edit the canonical files in
`demo/shared/`, then run `python scripts/sync_standalone_support.py`; a new
support file also goes into `demo/dsar-concierge/Dockerfile.standalone` when
the DSAR demo uses it. CI checks that the copies match.

## Running the tests

Run tests with `python3 -m pytest` (or `python -m pytest` inside the virtual
environment), never with a bare `pytest`. A `pytest` found on `PATH` can belong
to an isolated tool environment (pipx or uv) that cannot see the installed
packages, and the run then fails with import errors.

```bash
python -m pytest -q packages/maverick-shield/tests      # one package
python -m pytest -q packages/maverick-core/tests/test_budget.py   # one file
python -m pytest -q                                     # the whole suite
```

The whole suite is large. Run it the way CI does, with pytest-xdist using one
worker per CPU core and grouping tests by file:

```bash
python -m pytest -q -n auto --dist loadfile
```

CI also runs tests with `MAVERICK_TEST_SECURE_DEFAULT=1` (the production
security posture): selected suites on pull requests, and the whole suite in
the merge queue and on `main` (the `posture` jobs). Run the tests you changed
that way before pushing.

On a pull request the `test (3.11, n)` legs run only the test files your
changed files can affect (the `select-tests` job in `ci.yml`; the rules are in
`scripts/select_pr_tests.py` and in the table below). The merge queue and
`main` run everything, so run the whole suite locally before pushing a change
to shared code, and check the selection yourself with
`python scripts/select_pr_tests.py --git origin/main HEAD`.

A collection error in any file stops the whole run, so fix import errors
first. When a collection error shows a `pyo3_runtime.PanicException`, the real
cause (often a missing module) is on the captured stderr line above it.

CI runs the suite on Python 3.11 and 3.12 as four file-level slices
(`--shard N/4`, an option defined in the root `conftest.py`). Each slice runs
under pytest-xdist and then runs the tests marked `heavy_concurrency` serially,
so their own threads do not compete with a second worker
(`.github/actions/test-shard/action.yml` has the exact commands).

### Writing tests

- Tests live in each package's `tests/` directory, one `test_<module>.py` per
  module. Inside a package use relative imports; tests use absolute imports
  (`from maverick.budget import Budget`).
- Tests that touch the agent loop use the `fake_llm` fixture (`FakeLLM`) from
  `packages/maverick-core/tests/conftest.py`. Tests never call a real model
  provider.
- Tests must not depend on each other: no fixed TCP ports, no shared paths
  outside `tmp_path`, and nothing that assumes another file ran first. xdist
  schedules files in its own order. The root `conftest.py` fails any test that
  leaves a `maverick.*` package attribute bound to a re-imported module copy.
- pytest-asyncio runs in strict mode, so async tests need an explicit
  `@pytest.mark.asyncio` marker.
- Dashboard tests create the client with
  `TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})`, because mutating
  `/api/v1` requests must pass the same-origin check, and use a fixture that
  points `world_model.DEFAULT_DB` at `tmp_path` so that tests never touch a real
  database. Copy an existing dashboard test.
- `Budget` enforces every cap (tokens, dollars, wall-clock time, tool calls)
  when usage is recorded, not only in `check()`. A test that raises one cap
  must also raise any other cap it will cross.
- A test that contends on SQLite from its own threads carries
  `@pytest.mark.heavy_concurrency`.

## Lint and CI gates

Before you push, run:

```bash
bash scripts/pre-push-lint.sh
```

It runs these checks and reports every failure at once:

- `ruff check .` over the whole repository. Bugbear (`B`) rules are enabled and the complexity
  limit is 20, so new code must stay under it.
- `python -m mypy` for the selected boundary modules in `pyproject.toml`. It
  runs in strict mode and does not check transitive imports; expand the checked
  set as interfaces are typed and tested.
- `vulture` for dead code.
- A check for a bare `import tomllib` and for `shell=True` outside the sandbox
  backends (see the house rules below).
- `detect-secrets` against `.secrets.baseline`. It scans tracked files only, so
  run `git add` on new files first. Mark a false positive with
  `# pragma: allowlist secret`. The check is skipped if `detect-secrets` is not
  installed.
- `scripts/check_attribution.py` over your unpushed commits (see
  [Commits and pull requests](#commits-and-pull-requests)).
- The project's contract gates: `python -m maverick.plugin_matrix --ci`,
  `maverick.domain_prose_lint --ci`, `maverick.deprecations --ci`,
  `maverick.grpc_api.contract --check`, `maverick.a11y_audit --ci` and
  `maverick.schema_migrations --ci`.
- The release packaging tests
  (`packages/maverick-core/tests/test_release_packaging.py`).

To run ruff and the `tomllib` check on every commit, install the pre-commit
hooks once with `python -m pip install pre-commit` and `pre-commit install`.

The CI `lint` job runs further contract gates (`python -m maverick.<gate> --ci`).
Two need extra steps when you change what they guard:

- **World-model migrations** are immutable once released. Adding a migration
  requires regenerating the checksum lock with
  `python -m maverick.migration_governance --regen` and committing
  `migrations.lock.json`.
- **Evaluator ground-truth anchors** are immutable once released. A new anchor
  must be locked with `python -m maverick.evaluator_evolution --regen`.

### How changes reach `main`

`main` is protected by the ruleset in `.github/rulesets/protect-main.json`.
Every change lands through a pull request and the merge queue as a squash
merge, and only after every required check has passed on the queue's merge of
the pull request onto the current `main`. Force-pushes and branch deletion are
refused, history stays linear, and nobody can bypass the rules.

| Check | What it runs |
| --- | --- |
| `lint` | `ruff check .`, selected-boundary mypy, vulture, the `tomllib` and `shell=True` checks, detect-secrets and the `python -m maverick.<gate> --ci` contract gates |
| `lint-pr-title` | Conventional Commits pull request title (see below) |
| `no-ai-attribution` | `scripts/check_attribution.py` over the pull request's commits, title and description, the merge-queue commit and pushes to `main` |
| `select-tests` (advisory; not a required status check) | On a pull request, the test files the changed files can affect (`scripts/select_pr_tests.py`): a change to the kernel, a `conftest.py`, `pyproject.toml`, the requirements, `.github/` or `scripts/` selects the full suite; a package change selects its tests and every test naming its import package; other files select the tests naming them by path. The heavier jobs (`docker`, `postgres`, `audit`, `release-cohort`, `redteam`, `eval-smoke`, the benchmark gates, Windows containment) run on a pull request only when a changed file is under their inputs (`JOB_PREFIXES`) |
| `test (3.11, 1/2/3/4)` | The test suite on Python 3.11, in four slices: the `select-tests` selection on a pull request, the full suite in the merge queue and on `main` |
| `test (3.12, 1/2/3/4)` | The same slices on 3.12. On a pull request these report success without running; they run on the merge queue's commit and on `main` |
| `posture (1/2/3/4)` | The full suite again on 3.12 under the production security defaults, gated like the 3.12 legs |
| `harness-overhead`, `governance-frontier-offline` | The tracked benchmark manifests verify against the current sources (regenerate them when a source they cover changes) |
| `audit` | OSV Scanner, pip-audit, bandit, the license policy and the SBOM |
| `release-cohort`, `redteam`, `eval-smoke`, `postgres`, `docker` | Release packaging, the shield red-team corpus, the evaluation harness, the Postgres backend and the container image |
| `Windows process containment (Python 3.11/3.12)` | Process-tree containment on Windows: 3.11 on every pull request, 3.12 on the merge queue and `main` |

Each required check must also run on `merge_group` events, or the queue cannot
merge; `test_every_required_workflow_runs_in_the_merge_queue` enforces this.
Maintainers apply the ruleset by importing the JSON file under **Settings →
Rules → Rulesets → New ruleset → Import a ruleset**, and change it by editing
the file in a pull request and importing it again. The squash merge default
commit message (**Settings → General → Pull Requests**) must be the pull
request title.

## House rules

The kernel rules below are numbered; code comments and documents cite them as
"kernel rule N", so keep the numbers stable.

1. **The kernel runs without the shield.** Never require `agent-shield`. When
   an optional component is missing or a scanner fails, fail open and log a
   clear warning; never fail silently.
2. **Never hard-code a model.** Resolve models with
   `maverick.config.get_role_model(role)`. The defaults in
   `maverick.llm.ROLE_MODELS` are a last resort, and the user's per-role choice
   always wins.
3. **Budget caps are not optional.** Every long-running path respects `Budget`;
   never bypass `budget.check()`.
4. **All shell goes through `sandbox.exec()`.** Never call `subprocess.run`
   from a tool, and never use `shell=True` outside `maverick/sandbox/`; CI
   checks for it.
5. **No new top-level dependency without a configuration knob.** Put new
   dependencies behind an optional extra and a setting that turns the feature
   on.
6. **The setup wizard is the source of truth for the user experience.** A new
   capability needs a configuration knob and a step in the wizard
   (`apps/installer-cli/maverick_installer/`), or users cannot reach it.
7. **Keep diffs surgical.** Change only what the task needs, match the
   existing style, avoid speculative abstractions, state your assumptions in
   the pull request, and for a bug fix or new validation write the failing test
   first.

Further rules:

- **Portable bootstrap imports.** The runtime requires Python 3.11+, but
  bootstrap utilities retain the existing guarded TOML import convention. Use:

  ```python
  try:
      import tomllib
  except ModuleNotFoundError:  # Python 3.10
      import tomli as tomllib
  ```

- **New tools are screened.** A new tool or output sink goes through
  `ctx.shield.scan_tool_call()` before it executes.
- **Defaults belong in code; overrides in `~/.maverick/config.toml`.**
- **Health endpoints already exist.** `/healthz`, `/livez` and `/readyz` are
  served by the dashboard app and are deliberately exempt from authentication;
  do not add another health route under `/api/v1`.
- **Renames update the docs.** When you rename a module, also update
  `docs/FEATURES.md` and any tool wrapper in `maverick/tools/` that refers to
  it.
- **User-facing features need a path in the dashboard.** An API or CLI alone
  does not complete a feature. Give it a journey in the dashboard in plain
  language, use the shared Liquid Glass components (the dashboard design
  system in `static/lightwork.css`), and make it reachable through the
  dashboard Copilot (the in-product assistant panel) with the same permission
  checks as the direct UI. See the
  [customer experience contract](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/customer-experience-contract.md).

## Extending Lightwork

### Adding a model provider

1. Create `packages/maverick-core/maverick/providers/<name>_provider.py` with a
   class that implements `complete()` and `complete_async()`, accepts
   Anthropic-format messages and tools, and returns an `LLMResponse`.
2. Register it in `packages/maverick-core/maverick/providers/__init__.py`, in
   `get_provider_client` and `KNOWN_PROVIDERS`.
3. Add it to the wizard catalogue in
   `apps/installer-cli/maverick_installer/models.py`.
4. Add tests for any message-format translation.

### Adding a channel

1. Subclass `Channel` (`packages/maverick-channels/maverick_channels/base.py`)
   in `packages/maverick-channels/maverick_channels/<name>.py`.
2. Wire it in `packages/maverick-core/maverick/server.py`: add a
   `_wire_<name>` function and an entry in `_WIRES`.
3. Add it to the wizard's `CHANNELS` list in
   `apps/installer-cli/maverick_installer/wizard/__init__.py`.
4. If it needs a third-party SDK, add an optional extra in
   `packages/maverick-channels/pyproject.toml`.
5. Document the setup steps in `docs/deployment.md`.

### Adding a skill

Write a `SKILL.md` (the format is described in
`benchmarks/example-skills/README.md`) and add it to `benchmarks/example-skills/`.
Users install skills with `lightwork skill install`, which accepts a URL, a
`gh:org/repo[:path]` reference or a local path.

## Commits and pull requests

- **Keep pull requests small and focused.** One logical change per pull
  request is easier to review and to revert.
- **Fill in the pull request template**, link the issue the change addresses,
  and describe how you tested it.
- **Pull request titles follow [Conventional Commits](https://www.conventionalcommits.org).**
  The title starts with a type: `feat`, `fix`, `docs`, `test`, `refactor`,
  `perf`, `chore`, `ci`, `build`, `style` or `revert`, followed by a colon. The
  subject after the prefix must start with a letter, not a digit, quote or
  backtick: `feat: add the 2027 schedule` passes, `feat: 2027 schedule` fails.
  The `lint-pr-title` check enforces this. Pull requests are squash-merged, so
  the title becomes the commit subject on `main`.
- **Write commit messages that explain why.** The diff shows what changed; the
  message should say why.
- **Sign the CLA** by adding this line to the description of your first pull
  request:

      I have read the CLA and I agree to its terms.

- **No AI attribution in the history.** Commit messages, pull request titles
  and pull request descriptions must not contain AI co-author trailers (such
  as a `Co-authored-by:` line that names an AI assistant), "generated by"
  footers or assistant session links, and commits must not be authored or
  committed under an AI assistant's identity. You are responsible for every
  line you submit, however you wrote it. The `no-ai-attribution` check enforces
  this; run `python scripts/check_attribution.py --commits origin/main..HEAD`
  to check your branch locally.

## Reporting bugs

Use the issue templates. The bug report asks for the output of
`lightwork doctor`, the steps to reproduce the problem, your version and your
platform. If you include part of `~/.maverick/config.toml`, remove secrets
first.

## Security issues

Do not open a public issue for a security vulnerability. Report it privately
as described in the
[security policy](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/SECURITY.md).

## Code of Conduct

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Report
unacceptable behavior to chris@daybreakailabs.com.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License, Version 2.0](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/LICENSE)
and under the terms of the [Contributor License Agreement](CLA.md). You keep
the copyright in your contributions.

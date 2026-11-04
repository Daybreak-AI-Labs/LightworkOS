# Pull request

<!--
Thanks for contributing to Lightwork. Keep this pull request small and focused.
See CONTRIBUTING.md for the development setup and the project rules.
-->

## What

<!-- A one-line summary of the change. The diff shows the details. -->

## Why

<!-- The motivation. Link the issue this addresses, for example `Closes #123`. -->

## How

<!--
Only what the diff does not make obvious: design decisions, trade-offs, or
anything that needs a reviewer's close attention.
-->

## Test plan

<!--
How you tested the change. For example:
- [ ] `python3 -m pytest -q <the test files you changed>` passes
- [ ] `lightwork doctor` still reports a healthy install
- [ ] If you touched the agent loop, a test drives it with a scripted (fake) LLM
- [ ] If you added a tool or output sink, it goes through `ctx.shield.scan_tool_call()`
- [ ] If you added a provider, the wizard catalogue (`apps/installer-cli/maverick_installer/models.py`) is updated
- [ ] If you added a channel, the wizard `CHANNELS` list and `_WIRES` in `server.py` are updated
- [ ] If you added a CLI command, the relevant guide under `docs/` describes it
-->

## Checklist

- [ ] **The pull request title follows Conventional Commits**: a type prefix (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `perf:`, `chore:`, `ci:`, `build:`, `style:` or `revert:`) and a subject that **starts with a letter** (not a digit, quote or backtick). The `lint-pr-title` check enforces this.
- [ ] **Tests are added or updated**, and `python3 -m pytest -q` passes for the code I changed (never a bare `pytest`; see CONTRIBUTING.md).
- [ ] **`bash scripts/pre-push-lint.sh` passes** (ruff, vulture, the `tomllib` and `shell=True` checks, detect-secrets and the contract gates).
- [ ] **No bare `import tomllib`**: Python 3.11, the supported floor, has it, but the fallback is kept for helpers that still run on older interpreters, and CI rejects a bare import. Use the `try: import tomllib` / `except ModuleNotFoundError: import tomli as tomllib` fallback (see CONTRIBUTING.md).
- [ ] **A new capability is reachable from the setup wizard.** If you added a channel, provider, sandbox or feature, `apps/installer-cli/` can enable it.
- [ ] **Safety invariants hold** (if you touched the agent loop or added a tool or sink): new tools go through `ctx.shield.scan_tool_call()`, long-running paths respect `Budget`, and all shell goes through `sandbox.exec()` (never `subprocess.run` directly).
- [ ] **The change is surgical**: no reformatting or unrelated changes to adjacent code, and it matches the existing style.
- [ ] **No AI attribution**: commit messages, the title and this description contain no AI co-author trailers, generator footers or assistant session links, and no commit is authored as an AI assistant. The `no-ai-attribution` check enforces this.

## Contributor License Agreement

<!--
First pull request to Lightwork? Sign the Contributor License Agreement
(CLA.md) by adding the following line after the end of this comment:

    I have read the CLA and I agree to its terms.

You only need to do this once; it also covers your later contributions.
-->

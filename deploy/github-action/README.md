# Lightwork GitHub Action

Run a Lightwork agent swarm inside a GitHub workflow — on a PR, on a
schedule, or on demand — under a **hard spend cap**. It installs
Lightwork from the action's own pinned source checkout and runs `maverick
start` with the inputs you give it, then writes the final answer to the job
summary and exposes sanitized, bounded output as a step output. It never
falls back to an unqualified public-index install of a Lightwork
distribution.

```yaml
- uses: Daybreak-AI-Labs/LightworkOS/deploy/github-action@<full-40-character-commit-sha>
  with:
    goal: "Summarize the changes in this PR and flag anything risky."
    max-dollars: "0.50"
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

> Replace the placeholder with a reviewed 40-character commit SHA. Do not use
> a mutable branch or tag for a workflow that receives provider secrets.
>
> The default `docker` backend is mandatory for a normal run and executes
> model-generated shell with no network and a non-root user. The runner must
> have a working Docker daemon. `podman` and `gvisor` are also accepted
> container backends.
>
> `local` is a dangerous exception: it confines the starting directory, not the
> host filesystem or network. It is rejected unless the workflow explicitly
> sets both `sandbox: local` and `allow-unsafe-local: "true"`. Use that pair
> only on a trusted disposable hosted/isolated runner.

## Inputs

| Input | Default | Description |
|---|---|---|
| `goal` | — | Freeform goal (the `maverick start` TITLE). Provide this **or** `template`. |
| `description` | `""` | Optional longer description for a freeform goal. |
| `template` | — | A bundled/installed goal template name (e.g. `code-review`, `write-tests`). See [`benchmarks/example-templates/`](../../benchmarks/example-templates/). |
| `params` | `""` | Template parameters, one `key=value` per line. |
| `max-dollars` | `1.0` | Hard USD spend cap. The swarm refuses to exceed it. |
| `max-wall-seconds` | — | Optional wall-clock cap. |
| `model` | — | Override the model (e.g. `claude-sonnet-4-6`). |
| `sandbox` | `docker` | Shell backend. Supported values: `docker`, `podman`, `gvisor`, and `local`. Container runs are forced to no network and non-root. |
| `allow-unsafe-local` | `false` | Required acknowledgment for `sandbox: local`. Local runs model-generated shell on the host and is for a trusted disposable/isolated runner only. |
| `anthropic-api-key` | `""` | Exported as `ANTHROPIC_API_KEY`. For other providers, leave blank and set that provider's env var on the job. |
| `version` | `""` | Optional expected version of the source bundled with the pinned action. A mismatch fails closed. |
| `python-version` | `3.12` | Python to set up. |
| `step-summary` | `true` | Write the final answer to the job summary. |
| `dry-run` | `false` | Install + print the resolved command, but don't run the swarm (no LLM calls, no spend). |

## Outputs

| Output | Description |
|---|---|
| `result` | Sanitized, mention-neutralized run output, bounded to 50,000 characters. |
| `result-file` | Path to an owner-only file with the same sanitized, bounded output. |
| `goal-id` | Actual saved task ID. Empty when the process did not retain a native result. |
| `status` | Saved task status, such as `done`, `blocked`, `failed`, or `active`; `unavailable` when native result custody is missing. |
| `spend-recorded-usd` | Budget's recorded model usage in USD. Empty when unavailable. This is not a provider invoice or proof that interrupted calls have no additional cost. |
| `release-status` | `released`, `pending_signoff`, `not_completed`, `policy_unavailable`, or `unavailable`. A `done` task can still require sign-off. |
| `deliverable-file` | Owner-only sanitized `answer.md` created from the saved completed answer when release is allowed; empty otherwise. It is not a model-declared file path. |

Structured fields come from the same actual CLI run's saved task and Budget,
not parsed log lines or model-authored metadata. The action validates the private
native result before publishing these five named values. It never publishes
the raw JSON. A fresh action-owned private key authenticates the exact native
result, so a stale file or fabricated native-shaped JSON is refused. The key is
kept outside the ordinary container's workspace mount, passed by private file
path rather than environment or prompt, and deleted after validation. This does
not make explicitly unsafe local execution safe against hostile host code.
When work is incomplete, sign-off is pending, current source
access is unavailable, or native custody is missing, raw logs and drafts remain
private; `result` and the summary contain only a fixed status message. A
preflight refusal is `unavailable`, not a fabricated task or zero-dollar bill.
Dry runs leave these outputs empty because no task runs.

Both text files use the existing 50,000-character sanitization limit and include
an explicit truncation notice if needed. Native result capture accepts at most
32 MiB; a larger or malformed record refuses publication. These paths are local
to the current job and are not automatically uploaded, shared, or committed.
After checking `release-status == 'released'`, a downstream step can deliberately
use `deliverable-file` instead of trying to extract an answer from the run log.
Never upload `native-result.json` or other raw captures.

For other local automation, `maverick start "..." --result-file <new-file>`
creates the same owner-only result. It requires one actual run and refuses
existing files, redirected directories, `--repeat`, and `--dry-cost`.

## Examples

### Review every pull request

```yaml
name: Lightwork review
on: pull_request
permissions:
  contents: read
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
        with:
          persist-credentials: false
      - uses: Daybreak-AI-Labs/LightworkOS/deploy/github-action@<full-40-character-commit-sha>
        with:
          template: code-review
          params: |
            branch=${{ github.head_ref }}
          max-dollars: "0.75"
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
```

### Post the result as a PR comment

`result` is a step output, so you can chain it:

```yaml
      - id: maverick
        uses: Daybreak-AI-Labs/LightworkOS/deploy/github-action@<full-40-character-commit-sha>
        with:
          goal: "Review the diff on this PR and list concrete risks."
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
      - uses: actions/github-script@3a2844b7e9c422d3c10d287c895573f7108da1b3 # v9
        with:
          script: |
            github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: process.env.RESULT,
            })
        env:
          RESULT: ${{ steps.maverick.outputs.result }}
```

(Posting a comment needs `permissions: pull-requests: write` on the job.)

### Use another provider

Leave `anthropic-api-key` blank and set the provider's env var on the job —
composite-action steps inherit it:

```yaml
    env:
      OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    steps:
      - uses: Daybreak-AI-Labs/LightworkOS/deploy/github-action@<full-40-character-commit-sha>
        with:
          goal: "..."
          model: gpt-4.1
```

## Notes

- **Budget is the safety rail.** `max-dollars` is a hard cap enforced by the
  kernel; a runaway goal stops rather than running up a bill. Start small.
- **Keys are secrets.** Pass provider keys via `${{ secrets.* }}`, never
  inline. The action exports the key only for the run step.
- **Agent output is untrusted.** The action captures it in an owner-only file
  instead of streaming it into the Actions command parser. Before output is
  logged, summarized, or exported, configured provider, platform, and
  connector credentials (including Azure Identity environment secrets,
  workload-token file contents, and client certificate file contents) and
  common token formats (including bare compact JWT/JWS credentials) are
  redacted, GitHub mentions, and workflow-command prefixes are neutralized;
  control characters are neutralized before matching, summary markup is escaped,
  and text is capped at 50,000 characters. The raw capture is deleted. Recognized
  credential environment values and credential files are
  privately snapshotted before the swarm starts and collected again afterward,
  so both pre-rotation and post-rotation values remain covered.
- **Sandbox policy is isolated.** The action runs with an action-owned minimal
  config instead of runner-level `config.toml`, dashboard, or tenant overlays,
  so those files cannot loosen the no-network/non-root policy. Pass the model
  with `model` and provider settings through documented environment variables;
  installed templates and normal `MAVERICK_HOME` run state remain available.
- **Inputs are injection-safe.** Every input is passed through the
  environment and quoted, not interpolated into the shell, so a goal or
  param containing shell metacharacters can't execute.
- The full swarm needs a provider key, so it isn't exercised in this repo's
  CI; the `dry-run` path (install + command resolution) is.

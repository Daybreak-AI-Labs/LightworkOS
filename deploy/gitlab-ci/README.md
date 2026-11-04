# Lightwork GitLab CI template

Run a Lightwork agent goal inside a GitLab pipeline — on a merge request, on
a schedule, or on demand — under a **hard spend cap** and with
non-interactive safety defaults. The reusable
[`maverick.gitlab-ci.yml`](./maverick.gitlab-ci.yml) template installs
Lightwork from a verified source checkout or an explicitly configured trusted
private index, then runs `maverick start "$MAVERICK_GOAL"`. There is no public
PyPI fallback while the Lightwork project names remain unreserved.

It is the GitLab counterpart to the [`deploy/github-action`](../github-action)
wrapper and mirrors the same safety inputs: consent mode, budget cap, and
sandbox backend selection.

## Usage

In your project's `.gitlab-ci.yml`, `include:` the template and define a job
that `extends` the hidden `.maverick` job:

```yaml
include:
  - remote: 'https://gitlab.example/Lightwork/-/raw/<full-commit-sha>/deploy/gitlab-ci/maverick.gitlab-ci.yml'

maverick:
  extends: .maverick
  variables:
    MAVERICK_GOAL: "Review the changes on this branch and flag any risks."
    MAVERICK_MAX_DOLLARS: "0.50"
    MAVERICK_PACKAGE_INDEX_URL: "https://packages.example.com/simple"
    MAVERICK_VERSION: "0.1.7"
```

> Host the reviewed template where the runner can read it and replace the
> placeholder with a full commit SHA. Do not include it from a mutable branch
> or tag in a job that receives provider secrets.

## Required CI/CD variables

Set these under **Settings → CI/CD → Variables** (mark the API key as
*Masked* and *Protected*):

| Variable | Required | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | yes | Provider key, written into the generated config. For another provider, leave it blank and set that provider's env var on the job. |
| `MAVERICK_GOAL` | yes | The goal text passed to `maverick start`. The job fails fast if it is empty. |
| `MAVERICK_SOURCE_DIR` + `MAVERICK_SOURCE_REF` | one install mode required | Path to an already checked-out Lightwork repository and its lowercase, full 40-character commit SHA. The job verifies `HEAD` before installing all first-party distributions locally. |
| `MAVERICK_PACKAGE_INDEX_URL` + `MAVERICK_VERSION` | one install mode required | Explicit trusted private/simple index and exact Lightwork version. Ambient pip configuration is ignored and public PyPI hosts are rejected. |
| `MAVERICK_MAX_DOLLARS` | no (default `1.0`) | Hard USD spend cap, wired into `[budget] max_dollars`. The kernel refuses to exceed it. |
| `MAVERICK_MODEL` | no | Model override, e.g. `anthropic:claude-sonnet-4-6` (passed as `maverick --model`). |
| `MAVERICK_PYTHON_VERSION` | no (default `3.12`) | Python image tag used for the job. |
| `MAVERICK_SANDBOX` | no (default `local`) | Model-generated shell backend. `local` is suitable only on a trusted disposable/isolated runner; use `docker` or `podman` when the runner exposes a securely configured container runtime. |

## Safety defaults

These are baked into the template so a pipeline run is safe by default:

- **`MAVERICK_CONSENT_MODE: auto-deny`** — a pipeline has no human at a
  prompt, so any tool call that would ask for consent is denied rather than
  hanging the job.
- **Hard budget cap** — `MAVERICK_MAX_DOLLARS` is written to
  `[budget] max_dollars` and passed as `--max-dollars`. A runaway goal stops
  instead of running up a bill. Start small.
- **Explicit shell authority** — the default `local` backend starts in
  `$CI_PROJECT_DIR`, but a working directory is not a filesystem or network
  sandbox. Use it only on a trusted disposable/isolated runner. Persistent or
  shared runners require a real container backend plus runner-level
  filesystem/network controls.

## Notes

- **Keys are secrets.** Pass `ANTHROPIC_API_KEY` as a masked CI/CD variable,
  never inline in `.gitlab-ci.yml`.
- The full run needs a provider key, so it isn't exercised in this repo's
  CI; a structural test (`test_gitlab_ci_template.py`) checks the template
  parses and the safety defaults are present.

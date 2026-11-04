# Getting started

## Install

Lightwork is installed from source, with Python 3.11–3.12 and Git. Follow
[Install from source](source-install.md): it clones the repository, creates a
virtual environment and installs the eight Lightwork packages together with
`scripts/install_release_cohort.py`. The guide gives the commands for macOS,
Linux and Windows PowerShell, and the checks to run afterwards.

No prebuilt binary, PyPI package or container image is currently published,
so install from `main`. Published releases will be listed on the
[releases page](https://github.com/Daybreak-AI-Labs/LightworkOS/releases).

Run `lightwork dashboard` and open <http://127.0.0.1:8765>. The dashboard
guides owner sign-in and provider setup. A provider account, credentials, API
credits and any external integration prerequisites still need their own
authorization and validation. The command-line tool is installed under two
names, `lightwork` and `maverick`, which run the same program; other pages in
these docs often use `maverick`.

## First run

In the dashboard, open **Start → Set up named sign-in** before inviting a
team. On a fresh local installation, the owner chooses an email label and a
local passphrase. This closes anonymous administrator access and opens the
existing **Users** invitation controls. The email is a local identity label;
Lightwork does not verify that mailbox. Keep invitation links private.

The owner can sign in again on this computer at `/auth/local-login`. Invitees
use their single-use invitation and its expiring session. Someone who already
has a sign-in cannot be sent another invitation; if they forget their
passphrase, the owner resets it from **Users**. In **Workspaces**, create and select the
workspace, then grant each colleague workspace permissions and department
access in **Users**. Project reviewers receive only explicitly shared captured
results; reviewing one does not authorize execution of the underlying task.

First-owner setup accepts only direct loopback requests on the running
computer, before any role assignments or managed sign-in configuration. The
installer asks whether to allow it (`[dashboard] local_owner_setup`, default
`true`; `MAVERICK_LOCAL_OWNER_SETUP=0` disables enrollment). Explicit deployment
policies disabling invites or configuring managed sign-in remain authoritative.
The private `dashboard-owner.json` claim is recovery authority: a damaged or
incomplete claim keeps anonymous access closed, and restore cannot silently
replace it with a different owner. Login never restores a demoted or removed
owner's privileges.

The setup wizard and its checks also run from the command line:

```bash
lightwork init
lightwork preflight
lightwork doctor
```

The wizard takes ~2 minutes. It writes `~/.maverick/config.toml` and `~/.maverick/.env`.

New consumer setup suggests a $2 and 30-minute task limit and lets you choose
another limit or none. **Settings → General → Spending per task** can change
that choice later. Without a task limit, Lightwork still records what each
task spends with your model provider (the provider still charges you), and any
organization spend allowance an administrator has configured still applies.
See [task limits and spend accounting](task-limits.md).

If setup did not find a running Docker daemon, it switched off file changes
and program execution: the fallback `local` backend would run commands directly
on this computer without isolation. Start with a task that works even when
those actions are off:

```bash
lightwork start "Draft a one-page plan to reduce our customer support response time without adding headcount. State your assumptions and the facts you need from me."
```

## Watch the swarm decompose

Run `lightwork monitor` in a second terminal. The orchestrator plans the goal
and shows its work. For the first task above, an illustrative monitor view is:

```
Goal #1 active  2m elapsed
Draft a one-page support response plan

Plan tree
  ├─        done  #2 Identify likely response-time bottlenecks
  ├─      active  #3 Draft actions that do not require hiring
  └─     pending  #4 Check assumptions and questions for the owner

Latest episode #7 (running)  $0.0431  in=18,204 out=2,910 tools=11

Recent activity
  4s ago [researcher] decision: separate volume from process delays
  3s ago [writer] draft: owner-facing plan with assumptions
  1s ago [verifier] review: mark unsupported savings estimates

Cumulative spend on this DB: $0.21
```

To create files or run programs later, start Docker or Podman, open
**Permissions → Where work runs**, choose its container, then confirm
**Allow file work**. Lightwork checks that the container is running and shows
any other policy that still blocks those actions. Run `lightwork doctor` to see
the same limitation from the terminal. After that setup, a code-writing task
can use the isolated work area.

When done:

```bash
lightwork status      # what's currently active or blocked
lightwork skills      # built-in and installed skills; review new suggestions on Skills
lightwork facts       # what it learned about you
```

## Pausing / resuming

If the swarm needs something only you can answer, it pauses and queues a question:

```bash
lightwork status
# shows: open questions: #3 (goal 1): What is your current median first-response time?

lightwork answer 3 "About 9 hours"
lightwork resume
```

Goal records survive restarts. Restoring an ordinary agent's saved execution
state requires `[durable] enabled = true` or `MAVERICK_DURABLE=1`; without it,
retained goal context is not an execution checkpoint. An uncertain external
action or provider charge needs reconciliation before retry. Durable workflow
frames preserve supported continuation boundaries, not arbitrary external
effects. See [workflow progress and retry](task-limits.md#workflow-progress-and-retry).

## Undoing a run's file edits

With the workspace journal enabled (`[workspace] journal = true`, or say yes
at the wizard's *Workspace journal* step), every file the agents overwrite or
create through the file tools is captured before the mutation:

```bash
lightwork journal list --goal 12     # what was touched
lightwork journal diff --goal 12     # pre-run state vs the disk now
lightwork journal revert --goal 12   # restore every file, newest-first
```

Reverting writes a signed `workspace_revert` audit row and archives the
journal. Shell-driven mutations (`rm`, `mv`, redirects) are not journaled —
the audit trail records those commands instead.

## Building your own specialist from a watched task

You don't have to describe a job in words — you can show it. Capture an ordered
record of someone doing the work (the actions they took and any narration of why)
as JSONL or simple prefixed text, then hand the file to Lightwork:

```
ACTION[gmail]: send the morning digest -> ops@acme.com
NOTE: only the top 5 stories, with one-line summaries
SEE: digest looks right, ops confirmed receipt
```

```bash
lightwork learn-demo demo.txt
```

This parses the demonstration, induces a draft specialist, shows you the derived
workflow, and waits for your approval before saving. Secrets are redacted at the
door, and the draft inherits the same capability clamp and persona scan a
described pack gets — nothing activates without your yes. Useful flags:

```bash
lightwork learn-demo demo.txt --name "Morning Digest" --no-llm --yes
```

`--no-llm` mirrors the observed steps deterministically (tools = what the person
used); drop it to let the model propose from the transcript.

The same agent-factory flow runs when you build a pack conversationally:

```bash
lightwork onboard
```

On approval, `onboard` can provision catalog skills and synthesize declared tools
when `[self_learning]` / `provision_packs` permits it. This does not provision
third-party credentials or establish that an external adapter is available.
Deployment checks the assembled tool registry, including custom adapters, and
refuses a workflow whose required tools are missing. Complete the reported
adapter, enablement or approved-export prerequisites before running the pack.
Provisioning never widens its capability envelope.

## Voice input (built-in, offline)

The dashboard's mic button and the `transcribe_audio` tool work with no
provider key: the local Whisper engine ships with the dashboard package, and
opening the app does not download model files by default. In **Settings → Models**,
under **Voice dictation on this computer**, a global administrator can review
the configured model's source and size (about 148 MB for the default model),
then check or download it.
Progress survives a page reload; cancellation removes the unfinished download,
and failures can be retried in the same screen. Existing files are not labelled
verified until their exact size and checksum pass. Model verification does not
prove the speech engine is loaded or that a microphone works.

The installer asks explicitly whether to allow startup downloads. A saved
`[voice] auto_fetch_model = true` or `MAVERICK_VOICE_AUTO_FETCH=1` still enables
them; network policy is always enforced, including redirects. Managed custom
model paths and a selected cloud speech backend retain their configuration;
this setup screen does not silently replace them. The optional CLI is also available:

```bash
lightwork voice setup    # fetch the checksum-verified model (~148 MB)
lightwork voice status   # see which speech-to-text backends are usable
lightwork voice transcribe clip.wav   # smoke-test the pipeline
```

Prefer a system engine instead? A `whisper.cpp` binary on PATH (`brew
install whisper-cpp`) or faster-whisper both plug into the same chain. Set
`[voice] stt_backend = "local"` to keep audio on-machine even when
OpenAI/Groq keys are configured.

## Changing models or providers

After installation, open **Settings → Provider keys** or **Settings → Models**
to change these choices. The page identifies values controlled by the
deployment; an installation administrator must change that source before the
new value can take effect. See [`configuration.md`](./configuration.md) for the
underlying settings.

## Where data lives

| File | What |
|---|---|
| `~/.maverick/config.toml` | Your config (deployment, models, safety, budget) |
| `~/.maverick/.env` | API keys (chmod 600) |
| `~/.maverick/world.db` | Persistent world model: goals, facts, episodes |
| `~/.maverick/skills/` | Skills available to agents, including administrator-approved suggestions |
| `~/maverick-workspace/` | Default sandbox working directory. The quick `lightwork init` setup proposes `~/Documents/Maverick` instead; a saved `[sandbox] workdir` or `MAVERICK_WORKDIR` changes it |
| `~/.maverick/learned-skills/` | Suggestions distilled from completed work; review and add them on Skills before agents use them |
| `~/.maverick/dreams/` | Consolidated insights, rehearsal queue, learning snapshots |

Lightwork stores the files listed above in your deployment. If you enable cloud
AI providers or connected services, the work sent through them can leave that
deployment. Review each provider, connector, and outbound policy before use.

Once you have a few runs behind you, the learning surface is four commands:
`lightwork dream` (consolidate experience), `lightwork hindsight` (did learning
help or regress?), `lightwork proof` (deliverables, cost avoided, ROI), and
`lightwork domains-lint` (audit the 2,031-agent specialist catalog), plus
`lightwork domains-audit` (governance posture: what each agent can reach, denies,
and refuses) and `lightwork domains-eval --check` (behavioral golden cases).

# Lightwork

Lightwork is a self-hosted runtime for multi-agent AI work. You give it a goal,
and an orchestrator agent plans the work, hands parts of it to specialist
sub-agents running on the models you choose, checks their results and returns
an answer. Inputs, tool calls and answers are screened by a safety layer,
commands run in a configurable sandbox, per-run spending and time limits are
enforced, activity is recorded in a signed audit log, and state persists
between runs in a world-model database. Lightwork is open source under the Apache License 2.0.

## What you can do with it

- **Long-horizon software work**: recursive agent-spawns-agent
  orchestration with shared world model, budgets, and audit log.
- **Choose an AI connection**: connect a supported API provider or a
  self-hosted model from the product, then test the connection before work
  starts. Provider charges and task limits depend on the connection and
  settings you choose.
- **Computer use & web browser**: Anthropic-spec computer-use tool +
  Playwright-driven browser tool, with kill switches and an audit
  trail for every action.
- **Messaging channels**: connect supported services such as Telegram,
  Discord, Slack, Signal, and email in the Channels page, then send a test
  message to confirm delivery.
- **Primary-source data grounding**: analyst packs are granted their suite's
  read-only public-data connectors (up to 16 per suite, 37 in total: SEC
  EDGAR, FRED, Treasury, World Bank,
  FDIC, Census, BLS, EIA, openFDA, NPPES, ClinicalTrials, USAspending,
  SAM.gov, CourtListener, Federal Register, GLEIF, OpenCorporates,
  NWS/NOAA, EPA, Climatiq, …) so they cite authoritative sources instead of
  model recall. On by default; kill-switch via `[workforce] data_grounding
  = false`. These read-only connectors are separate from the 2,877
  write-capable REST and GraphQL connectors and the dedicated modules for
  systems such as Salesforce, HubSpot, Stripe, ServiceNow and Snowflake.
- **Governance invariant tests**: a roster-wide invariant test suite checks six
  governance invariants (tool-reachability, autonomy dial, capability
  attenuation, compartment isolation, unstrippable hard refusals, budget
  caps) across all 2,031 packs with a non-vacuous fault-injection control,
  plus hostile-argument fuzzing of every connector and tool.
- **Build an agent from a demonstration**: record a reviewed example of the job,
  then synthesize the agent that does it — `lightwork learn-demo <file>`
  ingests that transcript, induces a profile through the same
  intake clamp + review gate, and provisions the skills/tools it needs.
  `lightwork factory-learn` feeds provisioning and approval gaps back into
  future pack generation (on by default, stops when the self-improvement
  switch is off, and never widens an envelope).

## Quick start

Lightwork is installed from source. You need Python 3.11–3.12 and Git: clone
the repository, create a virtual environment, and run
`python scripts/install_release_cohort.py --core-extra release-runtime,evidence-analysis`,
which installs the eight Lightwork packages together. Then run
`lightwork dashboard` and open <http://127.0.0.1:8765> to complete the owner
and provider setup. [Install from source](source-install.md) has the exact
commands for macOS, Linux and Windows.

No prebuilt binary, PyPI package or container image is currently published,
so install from `main`. Published releases will be listed on the
[releases page](https://github.com/Daybreak-AI-Labs/LightworkOS/releases).

When setup finds no running Docker daemon, it switches off file changes and
program execution, because the fallback `local` backend runs commands directly
on the host without isolation. Lightwork can still answer questions and draft
documents. [Getting started](getting-started.md) shows how to turn file work on
once a container service is running, and walks through a first task.

## Watch it work

Open the dashboard to review running work, its activity log and cost, or run
`lightwork monitor` in a terminal to follow the orchestrator's plan as agents
work through it.

## Pricing and cost controls

Lightwork itself is free to use, modify and redistribute under its license.
Model usage is billed by the provider you connect, if any.
[Task limits and spend accounting](task-limits.md) explains per-task limits,
and [Pricing governance](pricing-governance.md) explains how model prices are
recorded and when a price may affect a budget.

## License

Lightwork is licensed under the Apache License 2.0 (see
[`LICENSE`](https://daybreak-ai-labs.github.io/LightworkOS/license/)). It is self-hostable: the runtime executes entirely
in your own environment. Contributions are accepted under the
[Contributor License Agreement](CLA.md). The Lightwork name and logo are
covered by the [trademark policy](https://daybreak-ai-labs.github.io/LightworkOS/trademark/),
not by the Apache License.

## Where to go next

- [Getting started](getting-started.md) — install + first goal
- [Install from source](source-install.md) — commands for macOS, Linux and Windows
- [Governed agent control plane](enterprise/architecture.md) — oversight, compliance profiles, fleets and tenancy
- [Configuration](configuration.md) — providers, channels, budgets
- [Deployment](deployment.md) — desktop / docker / VPS / phone modes
- [Safety](safety.md) — shield, audit log, kill switches, consent
- [Threat model](security/threat-model.md) — trust boundaries, capabilities, tenancy, and security controls
- [Security & compliance overview](enterprise/security-overview.md) — application egress controls, deployment boundaries, identity, audit/evidence
- [Plugins](plugins.md) — extending the tool / channel / skill surface
- [Governed model improvement](MODEL_IMPROVEMENT_PLATFORM.md) — the learning lifecycle, regression detection, and promotion controls
- [Starter goals](starter-goals.md) — ready-to-run examples for common workflows
- [Feature catalogue](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/FEATURES.md) — every shipped capability, by area
- [Contributing](CONTRIBUTING.md) — how to send PRs
- [Code of Conduct](CODE_OF_CONDUCT.md) — expected behavior in project spaces
- [Security policy](https://daybreak-ai-labs.github.io/LightworkOS/security-policy/) — how to report a vulnerability

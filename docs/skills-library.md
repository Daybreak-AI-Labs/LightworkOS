# Skills library

> The first-party **`SKILL.md` library**. Source files ship inside the package at
> `packages/maverick-core/maverick/skills_builtin/*.md`; each is reusable
> procedural know-how any agent can follow mechanically, validated by
> `maverick.skills.validate_skill_file` (test: `test_skills_library.py`).
> **Wired at runtime:** `skills.available_skills()` recalls this library plus
> any user-installed skills (`~/.maverick/skills`, which override by name) into
> the agent's prompt (`agent.py`); opt out with `MAVERICK_BUILTIN_SKILLS=0` or
> `[skills] builtin = false`.

This page lists the core set of **61 skills**: 20 cross-cutting and 41
suite-specific. For each task, `skills.relevant_skills()` recalls the few skills
whose triggers match the goal, above a relevance threshold. The
`skills_builtin/` directory holds the full library, which is considerably
larger than this list.

## Cross-cutting (20)

### Universal baseline
- `cite-sources-or-mark-unverified` — source every claim; tag the unsourced `[unverified]`.
- `draft-for-human-review` — review-ready artifact with a Decision/Approver/What-changed header.
- `write-to-audit-trail` — structured signed audit entry (action, inputs, refs, confidence).
- `redact-pii-before-egress` — mask special-category data before a payload leaves the compartment.
- `extract-from-document` — deterministic field/table extraction with per-field confidence.
- `meeting-to-action-items` — transcript → owner-dated action items + decisions + open questions.

### Platform / governance discipline
- `require-human-gate-checklist` — test an action against the hard-floor list, route to `require_human`.
- `segregation-of-duties-self-check` — refuse an action that breaks maker/checker/custody separation.
- `redact-secrets-in-output` — strip keys/tokens/PANs before commit or share.
- `structured-questionnaire-run` — drive the assessment flow, evidence-citing each answer.
- `evidence-cited-finding` — {condition, criteria, cause, effect, evidence-ref, risk-rating}.
- `rfc-2119-requirement-extraction` — contract/spec/reg → MUST/SHOULD/MAY register with clause refs.

### Analytical / consulting methods
- `root-cause-5-whys` · `executive-one-pager` · `decision-memo-saspe` · `swot-and-portering` ·
  `monte-carlo-sensitivity` · `stakeholder-raci-map` · `okr-drafting` · `competitor-teardown`.

## Finance / Banking / Insurance (9)
`ppa-opening-balance-sheet` · `goodwill-impairment-test` · `going-concern-assessment` ·
`escheatment-dormancy-run` · `loss-reserve-triangle` · `cecl-acl-loan-roll` ·
`irrbb-eve-nii-shock` · `lcr-hqla-classification` · `non-gaap-reg-g-bridge`

## IT-GRC / Security (8)
`pqc-readiness-inventory` · `cbom-generate` · `nhi-credential-rotation-runbook` ·
`prompt-injection-tabletop` · `mcp-tool-poisoning-scan` · `dora-ict-incident-classify` ·
`model-artifact-verify` · `residency-egress-validate`

## Revenue / GTM (8)
`security-questionnaire-autofill` · `answer-engine-optimization-audit` · `nrr-bridge-build` ·
`win-loss-interview-synthesis` · `suppression-list-reconcile` · `pql-scoring-model` ·
`pricing-experiment-design` · `cookieless-audience-blueprint`

## HR / Legal (8)
`adverse-impact-four-fifths` · `pay-equity-regression` · `pay-gap-statutory-report` ·
`accommodation-interactive-log` · `contract-obligation-extraction` · `citation-shepardize-verify` ·
`frand-rate-benchmark` · `ephemeral-data-preservation-map`

## Product / Eng / Data / Ops (8)
`slo-error-budget-policy` · `incident-postmortem-5whys` · `data-contract-author` ·
`llm-eval-harness-build` · `feature-pit-correctness-check` · `cbam-embedded-emissions-calc` ·
`supplier-financial-health-screen` · `dual-sourcing-tariff-scenario`

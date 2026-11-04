# Compliance assessments

Lightwork can **conduct** structured compliance assessments of a subject — a
processing activity, an AI system, or a vendor — running a questionnaire, scoring
each answer, and producing a completed assessment with **findings** and an overall
**risk rating**. This is distinct from [`maverick ropa` / `dpia` / `ai-act`](regulated-deployment.md#records-of-processing-art-30),
which scaffold a document from Lightwork's *own* deployment config — assessments
evaluate an arbitrary third-party subject.

## Built-in assessment examples

| Type | What it assesses | Framework |
|---|---|---|
| `pia` | A processing activity (Privacy Impact Assessment) | ISO 29134 / GDPR Art. 35 |
| `aira` | An AI system (AI Risk Assessment) | NIST AI RMF / EU AI Act |
| `vendor_risk` | A third-party vendor | TPRM |

New assessment types are added as data (a list of questions), not code.
The [security framework catalog reference](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/security-framework-catalog.md)
lists the pinned sources, practice counts, and license terms for the expanded
security questionnaires. Run `maverick assess templates` for the full list.

## Conduct one

```bash
maverick assess templates                       # list the assessment types
maverick assess questions vendor_risk           # see the questionnaire (--format json for tools)
maverick assess score vendor_risk \
    --subject "Acme Corp" --answers answers.json # score it -> findings + risk rating (and save)
maverick assess list                            # saved assessments, newest first
maverick assess show <id>                        # a saved result
```

`answers.json` maps each question id to an answer:

```json
{
  "vr_dpa": "no",
  "vr_soc2": "no",
  "vr_breach_history": "yes",
  "vr_subprocessors": {"answer": "unknown", "note": "no list provided"}
}
```

An answer is `yes` / `no` / `na` / `unknown`. Each question declares which answer
is the *risk* answer and at what severity; giving it raises a finding. `unknown`
raises an **unverified** finding (a diligence gap); `na` and the safe answer clear
it. The overall rating is the highest finding severity present (`high` / `medium` /
`low` / `minimal`).

```text
Vendor Risk Assessment: Acme Corp
Risk rating: HIGH
Completeness: 9/10 answered, 5 finding(s)

  [HIGH]   Contractual: Is a data-processing agreement (DPA) in place with the vendor?
      -> Execute a DPA before sharing personal data (Art. 28).
  [MEDIUM] History: Has the vendor had a reported data breach in the last 24 months?
      -> Review the breach, root cause, and remediation.
  ...
```

Results are saved under `~/.maverick/assessments/<id>.json`.

## Finding the control for a risk

Every finding should point to the control that closes it. `find_controls` (a tool,
and `maverick controls <risk>` for people) maps a risk to authoritative controls
with citations across GDPR, the EU AI Act, ISO/IEC 27001, SOC 2, NIST, and HIPAA —
so recommendations are grounded in a consistent catalog, not model recall:

```text
$ maverick controls vendor has no DPA
VN-1: Bind processors with a data-processing agreement (DPA)
   references: GDPR Art. 28; ISO 27001 A.5.19; SOC 2 CC9.2
```

## Conducted by the agent

The same engine backs the **assessment agent**: Lightwork can be told "run a vendor
risk assessment of Acme" and it drives the questionnaire itself — filling answers
from the documents and context it's given, flagging what it can't verify, and
producing the scored result for a human to review. The agent never signs off the
assessment; it produces the draft and the findings.

The **privacy-analyst** domain pack pairs this with research: it reads the subject's
documents, searches for evidence, and calls `find_controls` to cite the exact
control for each finding — the first-pass analyst's legwork, for a human to sign off.

!!! note
    Assessments are a structured-diligence aid, not legal advice. A qualified
    reviewer (DPO / counsel) owns the conclusions.

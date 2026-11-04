---
name: control-mapping-crosswalk
triggers:
  - control crosswalk
  - framework mapping
  - soc2 iso mapping
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Crosswalks the controls of one source framework against one or more target frameworks, producing a control crosswalk that maps each source control to its equivalent (or partial/no) target controls with a mapping-strength rating. Used to reuse evidence across audits and to spot coverage gaps when adopting an additional framework.

# Steps

1. Confirm the real inputs: the source framework and version, the target framework(s) and version, and the authoritative control catalog for each (knowledge_search the internal library; require version numbers — a SOC 2 / ISO 27001:2013 vs :2022 mismatch invalidates the mapping).
2. For each source control, knowledge_search the targets for the closest control(s) by intent and required outcome, not by keyword. Record candidate matches with their control IDs and the basis for the link.
3. Build the crosswalk in spreadsheet: columns = source control ID/title, target control ID(s)/title, mapping strength (equivalent/partial/none), rationale, and shared-evidence note. Every "equivalent" must justify why both intent and outcome align; partials must state what the target does not cover.
4. Report the crosswalk, list source controls with no target match as explicit coverage gaps, flag any mapping made across mismatched framework versions, and hand off to a control owner / auditor for validation. State that mappings are advisory.

# Notes

Output is wrong if controls are matched on title similarity rather than control intent, if "equivalent" is claimed where the target only partially covers the requirement, or if framework versions are unstated. Never assert an equivalence you cannot justify — downgrade to "partial" or "none". Mapping strength drives audit reliance, so this skill recommends only; an auditor or control owner must validate before evidence is reused across frameworks. Do NOT use it to declare a target framework "covered" without owner sign-off.

---
name: policy-author-governance
triggers:
  - policy author
  - write a policy
  - policy framework
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Drafts an enterprise policy for a stated topic with a complete governance structure, producing a document that defines scope, requirements, roles and responsibilities (RACI), enforcement, and an exception process. Used to turn a control intent or regulatory obligation into an approvable, auditable policy draft.

# Steps

1. Capture the real inputs: policy topic, the obligation or risk it addresses, the in-scope entities/systems/personnel, and any existing parent policy or framework it must align to. knowledge_search and read_file the internal policy library for the house template, terminology, and conflicting/superseded policies.
2. Draft the core sections: Purpose, Scope (who/what it covers and explicit exclusions), Policy Requirements (numbered, testable "must/shall" statements traceable to the driving obligation), and Definitions. Tie each requirement to its source where one exists; mark requirements with no cited driver as "rationale: internal".
3. Add governance: Roles & Responsibilities as a RACI, Enforcement/consequences, Exception process (who requests, who approves, expiry/review), Review cadence and owner, and a version/effective-date block.
4. Report the draft, list every assumption made where inputs were missing, flag any conflict found with an existing policy, and route to the named policy owner for review and approval. State that it is an unapproved draft.

# Notes

Output is wrong if requirements are vague aspirations ("strive to") rather than testable obligations, or if scope omits exclusions, or governance lacks a named accountable owner and an exception path. Do not invent regulatory citations or approval authorities — mark them TBD for the owner to fill. A policy is irreversible-by-publication: this skill only drafts and recommends; adoption, effective date, and enforcement are a human governance-body decision. Do NOT use it to silently retire or override an existing policy — flag the conflict instead.

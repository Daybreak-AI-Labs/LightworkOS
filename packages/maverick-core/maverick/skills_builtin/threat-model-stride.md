---
name: threat-model-stride
triggers:
  - threat model
  - stride
  - security design review
  - find security risks in this design
tools_needed:
  - knowledge_search
---
# What this skill does

Performs a STRIDE threat model over a proposed or existing system design and produces a prioritized threat register. Identifies threats across the six STRIDE categories (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege), rates each by likelihood and impact, and proposes a concrete mitigation per threat mapped to the design element it protects.

# Steps

1. Establish scope from real design inputs: components, data stores, external entities, and the trust boundaries / data flows between them. If a diagram or doc exists, work from it; if not, reconstruct the data-flow model with the user and state it explicitly — do not invent components.
2. For each element and data flow crossing a trust boundary, enumerate threats by walking all six STRIDE categories. Pull known attack patterns, framework controls, and prior internal threat models via `knowledge_search` to ground each threat rather than guessing.
3. Rate every threat by likelihood x impact (e.g., DREAD or a simple High/Med/Low risk score), noting the assumption behind each rating. Propose a mitigation per threat, mapped to the specific element/flow and an existing control where one applies; mark residual risk where no good mitigation exists.
4. Report the threat register sorted by risk, with the data-flow assumptions stated up front. Recommend mitigations and flag that prioritization and any accepted-risk decisions require a human security owner to ratify.

# Notes

The model is wrong if the trust boundaries are mis-drawn — most missed threats come from an incomplete data-flow model, so validate boundaries before enumerating. Ratings are judgment calls; surface the assumptions so reviewers can challenge them. This skill recommends; it does not decide what risk to accept or authorize a system to ship — that is a human security owner's call. Not a substitute for penetration testing, code-level review, or compliance certification — it reasons about design, not running code.

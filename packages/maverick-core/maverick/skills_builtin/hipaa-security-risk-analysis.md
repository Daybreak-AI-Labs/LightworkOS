---
name: hipaa-security-risk-analysis
triggers:
  - hipaa risk analysis
  - phi safeguards review
  - security rule assessment
tools_needed:
  - knowledge_search
---
# What this skill does

Analyzes a covered entity's or business associate's safeguards against the HIPAA Security Rule (45 CFR Part 164 Subpart C) for electronic protected health information (ePHI). Produces a risk analysis with gaps across the Administrative, Physical, and Technical safeguard categories, distinguishing Required vs Addressable specifications and rating threat/vulnerability likelihood and impact.

# Steps

1. Confirm scope with the requester: entity type (covered entity vs business associate), the ePHI systems/data flows in scope, and any prior risk analysis or remediation history. Record stated facts; do not assume system boundaries.
2. Retrieve the Security Rule standards via knowledge_search (45 CFR 164.308 Administrative, 164.310 Physical, 164.312 Technical, plus 164.316 documentation), noting Required vs Addressable for each implementation specification. Cite the CFR section; mark ungrounded items as "unverified."
3. For each safeguard, identify reasonably anticipated threats and vulnerabilities, assess current controls from supplied evidence and knowledge_search, and rate likelihood x impact to derive a risk level (High/Medium/Low). Note evidence or "no evidence found"; for Addressable specs, document the implement-or-document-alternative decision.
4. Compile the risk analysis (safeguard, CFR cite, R/A, threat, current control, risk rating, gap, suggested remediation) ordered by risk, and summarize High findings. Hand off to a human owner, stating that Addressable determinations and residual-risk acceptance require their sign-off.

# Notes

Output is wrong if Addressable specifications are treated as optional (they require implementation OR a documented, reasonable alternative — not silent omission), or if a risk rating is assigned without identifying the underlying threat/vulnerability. Never fabricate CFR citations or controls; mark unverified items. The analysis and remediation plan are a recommendation: the entity's Security Official accepts residual risk and approves Addressable decisions. Do not use as a Breach Rule or Privacy Rule analysis — this covers the Security Rule (ePHI) only. Confirm covered-entity vs business-associate status, since obligations and BAA dependencies differ.

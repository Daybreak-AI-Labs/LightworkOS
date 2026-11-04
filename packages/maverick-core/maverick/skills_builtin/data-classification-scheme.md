---
name: data-classification-scheme
triggers:
  - data classification
  - sensitivity labels
  - classification policy
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a data-classification scheme for an organization or system: a small set of named sensitivity tiers, the handling rules per tier (storage, transit, access, sharing, disposal), and worked examples that let a non-expert place a real artifact in the right tier. Produces a draft scheme an owner can ratify, not an applied policy.

# Steps

1. Establish scope and authority: ask for (or pull via knowledge_search) the regulatory and contractual drivers in play (e.g. GDPR, HIPAA, PCI-DSS, SOC 2, contractual NDAs) and any existing internal policy. Cite each driver; mark as unverified anything you infer rather than read.
2. Define 3-5 tiers ordered by impact of disclosure (e.g. Public, Internal, Confidential, Restricted). For each, write the one-line decision rule that distinguishes it from the tier above and below — the boundary is the load-bearing part.
3. For each tier specify handling controls across the lifecycle: labeling, storage at rest, transit/encryption, access basis (who and on what authority), permitted sharing channels, retention pointer, and disposal method. Tie each control back to a driver from step 1 where one exists; flag controls that are recommended practice with no hard mandate.
4. Add 2-3 concrete examples per tier drawn from the org's actual data inventory if available (knowledge_search), not invented ones. Include 1-2 deliberately ambiguous edge cases with the tie-breaking reasoning.
5. Report the scheme as a draft, list assumptions and any tier left under-specified by missing inputs, and route to the data owner / security lead for ratification — do not present it as adopted policy.

# Notes

The scheme is wrong if tier boundaries overlap or leave a real artifact unclassifiable, or if a handling rule contradicts a cited regulation — those are the failure modes to self-check before handing off. Never fabricate a regulatory requirement or an example from real data you did not retrieve; mark inferred drivers unverified. This is advisory: classification policy is an irreversible governance commitment, so the output is staged for a human owner to approve. Do not use this to classify a specific document on the fly (that's an application of an existing scheme) or where a mandated scheme already exists and only needs mapping.

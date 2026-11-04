---
name: dpa-review
triggers:
  - dpa review
  - data processing agreement
  - gdpr addendum
tools_needed:
  - knowledge_search
---
# What this skill does

Reviews a data-processing agreement (or GDPR data-processing addendum) against the organization's privacy playbook and the controller/processor obligations of GDPR Art. 28. Produces a review that checks sub-processor terms, international-transfer mechanism (SCCs / adequacy), security measures, breach notification, and data-subject-rights assistance. Output is a draft review for a privacy/legal reviewer to action.

# Steps

1. Establish the roles and data flow with knowledge_search: are we controller or processor, what personal data and categories are involved, and which transfer corridors apply. Do not infer the role from the document title alone — confirm against the underlying processing.
2. Pull the DPA playbook, the approved SCC module set, and the security-measures baseline (Annex II / TOMs) with knowledge_search; cite each requirement.
3. Check the document against the obligation checklist: (a) sub-processors — flow-down terms, prior authorization or notice-and-objection, liability for sub-processor acts; (b) transfers — correct SCC module and version, adequacy/derogation basis, no bare reliance on a struck-down framework; (c) security — TOMs present and specific, not placeholder; (d) breach notice timing and content; (e) deletion/return and audit rights; (f) data-subject-rights assistance. Mark each pass/gap.
4. Produce the review: per area, state compliant vs. gap, the specific Art. 28 / playbook requirement missed, the proposed fix, and a risk rating. Flag any transfer mechanism or sub-processor chain that cannot be verified as unverified. End by handing off the gap list to privacy/legal and stating role and data-scope assumptions.

# Notes

Output is wrong if it asserts SCC adequacy without checking the module and version, accepts placeholder TOMs, or misses an unauthorized sub-processor transfer. Controller-vs-processor framing changes which obligations are yours — getting the role wrong invalidates the review. Adequacy decisions and transfer frameworks change; treat the legal basis as time-sensitive and mark it unverified if not confirmed against current guidance. This skill drafts and recommends only; approving the DPA or accepting a transfer risk is a human/privacy-counsel decision. Not for general commercial terms — pair with MSA review where the DPA is an addendum.

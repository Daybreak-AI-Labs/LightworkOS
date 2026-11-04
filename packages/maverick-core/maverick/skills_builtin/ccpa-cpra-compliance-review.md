---
name: ccpa-cpra-compliance-review
triggers:
  - ccpa
  - cpra
  - california privacy
---
# What this skill does

Reviews an organization's handling of California consumer personal information against the CCPA as amended by the CPRA. Produces a gap-assessment covering notice-at-collection, the full set of consumer rights, opt-out of sale/sharing, and sensitive personal information (SPI) limits. Output is a prioritized findings list with the specific obligation each gap violates.

# Steps

1. Establish applicability and scope from the request: does the business meet a CCPA threshold (revenue, volume of consumers, or revenue-from-selling test), what California personal information categories are collected, and whether any "sale" or "sharing" (cross-context behavioral advertising) or SPI processing occurs. Mark unconfirmed thresholds rather than assuming coverage.
2. Use knowledge_search to retrieve the current privacy policy, notice-at-collection, cookie/consent configuration, and the statute/regulation text. Check the notice for the required categories, purposes, retention disclosures, and the 12-month update cadence.
3. Verify each consumer right is operational: know/access, delete, correct, opt-out of sale/sharing, limit use of SPI, and non-discrimination. Confirm at least two request methods, a "Do Not Sell or Share My Personal Information" link, Limit-the-Use-of-SPI link where applicable, and that opt-out preference signals (GPC) are honored.
4. Report findings as a table of obligation -> status (met / gap / unverified) -> evidence -> remediation, ordered by exposure, and hand the draft to privacy/legal. State assumptions about thresholds and any data not provided.

# Notes

Common errors: treating CCPA like GDPR (different definitions — "sale" is broad and includes some ad-tech data flows), missing the GPC opt-out signal requirement, or omitting the SPI "limit use" right added by CPRA. Cite the specific section for each finding; mark anything inferred as unverified. This is an assessment that recommends remediation — it does not implement changes or make legal determinations; counsel confirms applicability and final exposure. Do not use for GDPR-only contexts or for B2B/employee data edge cases without confirming current exemption status.

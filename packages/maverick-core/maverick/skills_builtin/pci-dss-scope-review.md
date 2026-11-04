---
name: pci-dss-scope-review
triggers:
  - pci dss scope
  - cardholder data environment
  - pci saq determination
tools_needed:
  - knowledge_search
---
# What this skill does

Scopes a PCI DSS assessment by mapping where cardholder data (CHD/PAN) is stored, processed, or transmitted, identifying the cardholder data environment (CDE) and connected/security-impacting systems. Produces a scope review with a cardholder data-flow summary, in-scope system inventory, and a recommended SAQ type (or full ROC) based on payment channels.

# Steps

1. Confirm payment context with the requester: how the merchant accepts cards (e-commerce, MOTO, card-present/POS, hosted/redirect vs direct-post), annual transaction volume/merchant level, and whether any PAN is stored. Record stated facts; do not assume the channel.
2. Pull current requirements via knowledge_search (PCI DSS v4.0.1 scoping guidance and SAQ eligibility criteria — A, A-EP, B, B-IP, C, C-VT, P2PE, D). Cite the requirement/SAQ criteria; mark anything ungrounded as "unverified."
3. Trace each cardholder data flow against supplied architecture, network diagrams, and inventories; classify systems as CDE, connected-to/security-impacting, or out-of-scope, and flag any PAN storage or flat-network exposure that expands scope. Note evidence or "no evidence found" per system.
4. Determine the eligible SAQ (or that a full ROC is required) from the channels and storage findings, and produce the data-flow summary plus in-scope inventory. Report scope-reduction opportunities (tokenization, P2PE, redirect) and hand off; state that final SAQ/ROC selection requires QSA or acquirer confirmation.

# Notes

Output is wrong if a system touching or able to impact the CDE is marked out-of-scope, or if SAQ eligibility is claimed without verifying every criterion (e.g., SAQ A requires fully outsourced/redirected payment pages). Never fabricate data flows — unknown flows are in-scope until proven otherwise. SAQ selection and scope boundaries are a recommendation: the acquiring bank or a QSA makes the binding determination, and storing PAN is an irreversible compliance commitment that needs human sign-off. Confirm the DSS version (v4.0.1 current) before reusing prior-version SAQ criteria.

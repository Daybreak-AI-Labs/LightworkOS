---
name: kyc-cdd-case
triggers:
  - run KYC on this customer
  - customer due diligence
  - AML onboarding review
tools_needed:
  - knowledge_search
  - web_search
---
# What this skill does

Onboards or periodically reviews a customer (individual or legal entity) for anti-money-laundering risk. Produces a KYC/CDD case file containing verified identity, the beneficial ownership chain to the ultimate beneficial owner (UBO), screening results (sanctions, PEP, adverse media), and a documented risk rating with rationale. Output is a draft case for a compliance officer to approve, not a clearance decision.

# Steps

1. Pull the customer record and intake data via `knowledge_search` (legal name, jurisdiction of incorporation, entity type, registration number, declared business activity, intended product use). For an entity, retrieve the ownership/control structure; list every owner with their stake.
2. Resolve beneficial ownership: trace the ownership chain until you reach natural persons holding >=25% (or the jurisdiction's threshold) or who exercise control. Mark each UBO as verified or unverified and record the source. If the chain breaks or hits an opaque layer (nominee, trust, bearer shares), flag it explicitly — do not assume zero ownership.
3. Screen each in-scope party (customer, UBOs, directors) against sanctions lists, PEP databases, and adverse media using `web_search` and `knowledge_search`. Record hits with source URL and date; mark unconfirmed matches as "potential — needs disposition," never as confirmed.
4. Score risk across the standard factors (geography, industry, ownership opacity, product/channel, PEP/sanctions exposure) into Low/Medium/High with a one-line rationale per factor. Report the case file, list every unverified item and open screening hit, state assumptions, and hand off to the compliance officer for the onboard/decline/EDD decision.

# Notes

The output is wrong if a UBO is asserted as verified without a cited source, if a screening "potential match" is silently dropped, or if the risk rating ignores a flagged factor. Sanctions and PEP data go stale fast — cite the list and date; mark anything unconfirmed. This is a draft and recommendation only: onboarding, declining, filing a SAR, or freezing funds are irreversible compliance actions a human must make. Do not use for transaction monitoring or alert disposition — this is the onboarding/periodic-review case, not ongoing surveillance.

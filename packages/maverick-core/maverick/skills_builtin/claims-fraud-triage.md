---
name: claims-fraud-triage
triggers:
  - claims fraud triage
  - fraud red flags
  - siu referral
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Triages an insurance claim for potential fraud indicators and produces an SIU (Special Investigations Unit) referral recommendation. It pulls claim and claimant history, screens against known fraud red-flag patterns, scores the indicators, and outputs a referral / no-referral recommendation with the evidence behind each flag.

# Steps

1. Retrieve the claim record and related history via sql_query: claim details, claimant/insured prior claims, payment history, provider/vendor, dates (loss vs policy inception/expiry), and any linked claims sharing parties, addresses, phones, or banking.
2. Search the fraud red-flag knowledge base (knowledge_search) for the relevant claim type and screen the record against it: timing flags (loss near inception/lapse), severity/inconsistency flags, prior-claim frequency, organized-ring linkage, provider patterns, and documentation anomalies.
3. Score the indicators: list each red flag that fires with the specific supporting data point, weight by severity, and determine whether the cumulative signal meets the SIU referral threshold defined in the knowledge base.
4. Produce the triage: recommendation (refer to SIU / monitor / clear), the red-flag list with cited evidence, the threshold applied, and any data gaps. Stage as a referral recommendation — do not deny, delay, or accuse; a human investigator/adjuster decides.

# Notes

Wrong when flags rest on unverified or mismatched-entity data (false linkage), when correlation is read as proof, or when a threshold is applied without the knowledge-base definition. Cite the exact data point and red-flag rule for every flag; mark inferences as unverified. Fraud determination, claim denial, and any adverse action are irreversible human/legal decisions — this only routes for investigation. Do not use to set reserves or to communicate with the claimant.

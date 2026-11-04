---
name: procurement-rfx-evaluation
triggers:
  - rfx evaluation
  - bid evaluation
  - supplier selection
tools_needed:
  - spreadsheet
---
# What this skill does

Evaluates supplier responses to an RFx (RFP/RFQ/RFI) against a defined, weighted scoring model spanning price and non-price criteria, then produces a ranked award recommendation. Produces a normalized scorecard, a price/value trade-off view, and a defensible award rationale with an audit trail. Output is a recommendation; the award decision is made by a human or sourcing committee.

# Steps

1. Load the criteria and weights (price, quality, lead time, capacity, compliance, risk, sustainability) and each supplier's response into the spreadsheet. Confirm weights sum to 100% and every supplier answered every scored question; flag missing responses and any unsolicited deviations rather than scoring them as zero silently.
2. Normalize each criterion to a common scale (e.g., lowest compliant price = top price score; map qualitative answers to the agreed rubric). Apply pass/fail gates first (mandatory compliance, certifications, capacity floor) and mark gated-out suppliers before weighted scoring.
3. Compute weighted scores per supplier, then rank. Build a trade-off view: total cost of ownership (unit price + freight + tooling + payment terms + switching cost) against the non-price score, so a low-bid-but-low-quality supplier is visible.
4. Report the scorecard, ranking, and award recommendation with the rationale, the runner-up, and any single-source or concentration risk. State assumptions (prices firm for the stated period, scoring rubric as agreed, no negotiation round modeled) and stage the award as a recommendation for committee sign-off.

# Notes

Output is wrong if weights don't sum to 100%, if a qualitative rubric is applied inconsistently across suppliers (the most common dispute source), or if non-compliant bids are scored instead of gated out. Comparing headline price instead of total cost of ownership produces a misleading winner — always surface TCO. Award decisions are contractual and contestable: keep the scoring auditable, present as a recommendation only, and never auto-award or notify suppliers. Cite the source response for each score; mark any inferred or assumed value as unverified. Do not use to author the RFx itself, only to evaluate received responses.

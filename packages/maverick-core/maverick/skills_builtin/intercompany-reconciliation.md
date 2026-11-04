---
name: intercompany-reconciliation
triggers:
  - interco
  - intercompany recon
  - eliminations
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Reconciles intercompany (IC) balances between paired entities at close, matching each side's receivable/payable and revenue/expense, and isolating mismatches that block consolidation. Produces an IC reconciliation by entity pair with the matched, unmatched, and in-transit detail, plus draft elimination entries for the consolidator.

# Steps

1. Query the IC subledger or GL for both legs of each entity pair (AR vs AP, IC revenue vs IC expense, loans/notes), pulling counterparty entity, currency, document reference, and amount. Translate to the consolidation currency at the policy rate; record the rate and any FX difference separately so it is not mistaken for a real mismatch.
2. Match the two legs by document reference where available, then by amount and counterparty as a fallback. Bucket results: clean matches, amount mismatches, one-sided items (booked by one entity only), and timing/in-transit items (e.g., goods or cash dated after the other side's cutoff).
3. For each break, quantify it and assign a probable cause (FX rate difference, cutoff/in-transit, missing accrual, miscoded counterparty, or dispute). Net each entity pair to a single difference and confirm the total IC imbalance across all pairs.
4. Draft elimination entries that remove matched IC AR/AP and IC P&L on consolidation, and stage proposed true-up entries for genuine one-sided breaks. Report the recon by pair, the unresolved imbalance, the break aging, and the draft eliminations; state which breaks are FX/timing (self-clearing) versus substantive, and mark any leg lacking a counterparty match as unverified.

# Notes

Output is wrong if FX differences are reported as mismatches (translate both legs at the same policy rate first) or if reference-based matching is skipped, producing false matches on coincidental equal amounts. In-transit items are legitimate and must not be forced to true up at the wrong entity. A residual IC imbalance left in consolidation overstates or understates the group — surface it, do not absorb it into a plug. Elimination and true-up entries are drafts for the consolidation/controllership team; a human posts them and resolves disputed balances with the counterparty entity. Do not use for third-party AR/AP reconciliation — this is entity-to-entity only.

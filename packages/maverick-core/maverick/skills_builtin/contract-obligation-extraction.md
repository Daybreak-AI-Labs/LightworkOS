---
name: contract-obligation-extraction
triggers:
  - extract obligations
  - key terms and renewals
  - auto-renew tracker
  - contract obligation register
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

This skill reads an executed contract and extracts its operative commitments — deliverable obligations, payment terms, milestones, SLAs, auto-renewal and termination triggers, notice windows, caps and indemnities — into a structured obligation register so nothing falls through the cracks (a missed renewal-notice window is the classic failure). It pulls only what the paper actually says, quoting the governing clause for each entry, and marks anything ambiguous for a human reviewer rather than inferring intent. The output is a structured register with clause citations, staged for legal/contract-ops review; it does not send notices, trigger renewals, or take any contractual action.

# Steps

1. Use read_file to load the executed agreement (and any amendments/SOWs/order forms), and identify the document hierarchy — which document controls when they conflict — so obligations are attributed to the right governing text.
2. Walk the contract section by section and extract each obligation into a register row: party responsible, the obligation/deliverable, trigger or due date, the exact clause reference, and a short verbatim quote of the controlling language. Capture dates relative to events (e.g. "30 days before the then-current term ends") as well as absolute dates.
3. Use knowledge_search against the org's playbook/standards to flag deviations (non-standard auto-renew, short notice windows, uncapped liability) and compute key derived dates — especially the auto-renewal opt-out deadline (term end minus notice period). Mark any clause whose meaning is ambiguous, cross-referenced, or possibly superseded as REVIEW -> human rather than resolving it.
4. Assemble the obligation register (obligation, owner, dates, clause cite, quote, deviation/REVIEW flags) and a calendar of critical dates (renewal opt-out, termination notice, milestone deadlines), and stage it for contract-ops/legal. Mark that acting on any date (sending a notice, allowing renewal) is the human owner's decision.

# Notes

Extract, don't interpret: quote the governing clause for every obligation and flag ambiguity as REVIEW rather than guessing the parties' intent — a confidently wrong obligation is worse than a flagged gap. Get the document hierarchy right (an order form or amendment often overrides the MSA); attribute each term to the controlling document. The highest-value, most error-prone item is the auto-renewal opt-out deadline — compute term-end minus the exact notice period and surface it prominently. This skill never sends a notice, opts out, or renews; it produces a staged register and date calendar for a human to act on. Re-running on an amended contract is fine; mark superseded rows rather than deleting them.

---
name: purchase-price-allocation
triggers:
  - build the purchase price allocation
  - PPA for the acquisition
  - opening balance sheet for the deal
tools_needed:
  - spreadsheet
  - knowledge_search
---
# What this skill does

Allocates the total purchase consideration of a business combination across identifiable assets acquired and liabilities assumed at fair value, with the residual booked to goodwill, under ASC 805 / IFRS 3. Produces a PPA schedule by asset class showing fair-value basis, the bridge from book value to fair value, and the goodwill residual for the opening balance sheet.

# Steps

1. Establish total consideration from the deal documents: cash, stock (at acquisition-date fair value), assumed debt, contingent consideration / earnout at fair value, and any holdbacks. Cite the purchase agreement; do not net or estimate amounts that are stated.
2. List identifiable assets and liabilities from the target's closing balance sheet (tangible PP&E, inventory, receivables, identifiable intangibles — customer relationships, trade name, technology, non-compete — and assumed liabilities and deferred taxes). Use `knowledge_search` for the entity's fair-value methodology and ASC 805 recognition criteria; flag any intangible whose valuation method (income/market/cost) is not yet supported.
3. Build the allocation in `spreadsheet`: columns for book value, fair-value step-up/down, and fair value; one row per asset class. Tie the sum of allocated fair values + goodwill to total consideration exactly (allocation must foot to consideration). Compute deferred tax on book/tax basis differences and the goodwill residual.
4. Report the PPA schedule by asset class with fair-value basis per line, the goodwill plug, DTL impact, and which valuations are preliminary (measurement-period adjustments possible for up to one year). State assumptions and mark third-party valuation inputs as pending.

# Notes

Output is wrong if the schedule does not foot to total consideration, if contingent consideration or assumed debt is omitted from the price, or if deferred taxes on the step-up are ignored (a common goodwill miscount). Intangible fair values usually require a third-party valuation specialist — never present internally estimated intangible values as final; mark them unverified. This skill drafts a preliminary allocation for review; the final PPA is approved by the valuation firm and auditors and may shift during the measurement period. Do not use it for asset acquisitions that are not business combinations (no goodwill — residual allocates pro rata).

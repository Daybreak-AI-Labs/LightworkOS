---
name: quote-configuration-review
triggers:
  - quote review
  - cpq quote check
  - configuration check
tools_needed:
  - spreadsheet
---
# What this skill does

Reviews a single CPQ quote for configuration accuracy and produces a defect list covering invalid product bundles, missing dependencies, pricing/discount errors, and resulting margin. Output is a pass/fail review with each error pinned to the offending line, so a rep can correct the quote before it goes out.

# Steps

1. Load the quote into the spreadsheet tool: every line item with SKU, quantity, list price, unit discount, extended price, and any add-ons or bundle parent. Record totals as quoted.
2. Validate configuration: check that each bundle has its required components and compatible options, that quantities are internally consistent (e.g., seats vs. modules), and that no deprecated or mutually exclusive SKUs co-exist. Flag any line you cannot validate as "unverified — needs catalog confirmation."
3. Recompute pricing independently: re-derive extended price = qty x list x (1 - discount), sum to a control total, and compare against the quote's stated totals; list every cell where your computed value diverges. Compute blended discount and gross margin from cost (mark margin "unknown" if cost is absent rather than guessing).
4. Report a defect table (line, error type, quoted vs. expected), the blended discount and margin, and an overall pass/fail. State assumptions and hand back to the rep for correction — do not resubmit or send the quote.

# Notes

The review is wrong if margin is reported from an assumed cost, or if a rounding rule differs from the CPQ engine (note the rounding convention used). Configuration validity depends on the live product catalog; when it is unavailable, mark affected lines unverified rather than passing them. This skill only reviews and recommends fixes; issuing or sending the quote to a customer is the rep's action. Do not use it to author a quote from scratch or to set pricing policy.

---
name: bank-covenant-package
triggers:
  - covenant package
  - lender reporting
  - borrowing base
tools_needed:
  - spreadsheet
  - sql_query
---
# What this skill does

Assembles a lender covenant-compliance package for a reporting period, computing each financial covenant exactly per the credit-agreement definitions and producing the supporting calculations, borrowing-base detail, and a compliance certificate ready for officer sign-off. Produces the package the lender requires and a pass/fail with cushion on every covenant.

# Steps

1. Read the covenant section of the credit agreement to extract each covenant, its required threshold, test frequency, and the agreement's specific definitions (e.g., EBITDA add-backs, Total Debt inclusions, fixed-charge components). Use the agreement's definitions verbatim — do not substitute GAAP or generic formulas; cite the section for each.
2. Pull period financials from the GL/trial balance and any borrowing-base inputs (eligible AR aged, eligible inventory, ineligibles, advance rates) via sql_query or spreadsheet. Map each line to the covenant definition and apply the contractual add-backs, exclusions, and TTM windows as written.
3. Compute each covenant ratio and the borrowing-base availability, showing the full build (numerator, denominator, every adjustment) so the lender can retrace it. Compare to the required threshold and compute cushion (headroom or shortfall) for each.
4. Assemble the package: covenant calculation schedules, borrowing-base certificate, reconciliation to the financial statements, and the compliance certificate with the pass/fail summary. Report each covenant's result and cushion, flag any breach or thin cushion, and list any input marked estimated; leave officer name, signature, and date blank. State the agreement sections and reporting period assumed.

# Notes

Output is wrong if covenant inputs use GAAP or textbook definitions instead of the agreement's bespoke ones — defined terms (EBITDA, Total Debt, Fixed Charges, Eligible Receivables) are the whole game and vary by deal. A miscomputed add-back or a wrong TTM window can flip compliance; show the build so it is auditable. Borrowing-base ineligibles and advance rates must come from the agreement, not assumed. This is a draft package for CFO/officer review and signature — never certify, sign, or submit to the lender on the company's behalf; a human attests. Flag a breach or thin cushion immediately rather than burying it. Do not use for non-credit-agreement reporting or to interpret cure/default remedies — that is legal/lender territory.

---
name: irrbb-eve-nii-shock
triggers:
  - interest rate risk
  - eve sensitivity
  - nii at risk
  - rate shock
tools_needed:
  - read_file
  - spreadsheet
---
# What this skill does

Runs interest-rate-risk-in-the-banking-book shocks: apply parallel rate shifts of +/-100/200/300/400 bp to compute the change in economic value of equity (EVE) and in 12-month net interest income (NII), using deposit betas and non-maturity-deposit decay assumptions. The goal class is "measure banking-book rate risk under standard shocks" while recognizing that EVE and NII can move in opposite directions.

# Steps

1. Read the balance-sheet repricing data with read_file (asset and liability cash flows, repricing dates, optionality) and build the model in a spreadsheet with a base case.
2. Apply each standardized parallel shock (+/-100, 200, 300, 400 bp). For EVE, discount all future cash flows at shocked rates and measure the change in the present value of equity (a long-horizon, value-based view).
3. For 12-month NII, reprice assets and liabilities over the next year under each shock, applying deposit betas (how much deposit rates actually move per unit of market move) and non-maturity-deposit (NMD) decay/runoff assumptions (effective duration of sticky deposits).
4. Report EVE and NII sensitivity side by side per shock, and explain divergences — a short-funded book may show NII improving in a rising-rate scenario while EVE falls, and vice versa.

# Notes

EVE and NII can point in opposite directions and that is not an error — EVE is a long-run present-value measure while NII is a near-term earnings measure, so a book can look fine on one and exposed on the other; report both. Deposit beta and NMD decay assumptions dominate the result: assuming deposits reprice fully and instantly (beta = 1) or run off too fast badly distorts the picture, so these behavioral assumptions are the analysis. Parallel shocks miss curve-twist and basis risk; note that limitation. This skill computes and reports the sensitivities for ALCO/treasury review; it does not change the balance sheet or hedge anything.

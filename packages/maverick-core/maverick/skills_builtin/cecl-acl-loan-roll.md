---
name: cecl-acl-loan-roll
triggers:
  - cecl allowance
  - acl roll forward
  - q-factor
  - expected credit loss
tools_needed:
  - read_file
  - spreadsheet
---
# What this skill does

Builds a loan-portfolio allowance for credit losses under CECL: estimate lifetime expected losses via a method (WARM, DCF, or PD-LGD), layer a reasonable-and-supportable forecast with reversion to history, bridge to a final number with qualitative Q-factors, and present the ACL roll-forward. The goal class is "size and roll forward the loan-loss allowance" while avoiding double-counting the forecast across the model and the Q-factors.

# Steps

1. Read the loan tape and segmentation with read_file and pick a lifetime-loss method per pool (WARM weighted-average remaining maturity, discounted cash flow, or PD x LGD x EAD), modeling it in a spreadsheet.
2. Apply the reasonable-and-supportable (R&S) forecast over the supportable horizon, then revert to historical loss experience beyond it; document the forecast inputs and the reversion technique.
3. Bridge the quantitative result to the final ACL with qualitative Q-factors (adjustments for portfolio, environmental, and model-limitation factors not captured quantitatively), documenting the directional rationale for each.
4. Present the ACL roll-forward (beginning balance, provision, charge-offs, recoveries, ending balance) and reconcile it, ensuring the ending allowance ties to the modeled lifetime loss plus Q-factors.

# Notes

Double-counting the forecast is the central CECL trap: if the macro forecast is already in the quantitative model, do not ALSO capture the same economic deterioration in a Q-factor — that books the same risk twice. The reversion from the R&S forecast back to historical experience must be deliberate and documented, not an unexplained cliff. Q-factors must be directionally justified and sized, not a plug to hit a target. Charge-offs and recoveries belong in the roll-forward, not in the provision. This skill drafts the allowance and roll-forward for accounting and model-risk review; it does not record the provision.

---
name: safety-stock-optimization
triggers:
  - safety stock
  - reorder point
  - inventory policy
tools_needed:
  - spreadsheet
---
# What this skill does

Computes per-SKU safety stock and reorder points sized to hit a target service level, given demand history and lead-time variability. Produces an inventory policy table (safety stock, reorder point, target service level, implied fill rate) that an ops or planning team can load into an ERP or review before changing replenishment parameters.

# Steps

1. Pull the real inputs into the spreadsheet: per-SKU demand history (enough periods for a stable mean/std — flag SKUs with <12 periods as low-confidence), lead time mean and std per supplier/SKU, and the target service level (cycle service level, CSL) per SKU or class. If a target is not supplied, do NOT assume one — ask, or stage a default (e.g. 95%) clearly marked as an assumption.
2. Compute demand statistics per SKU: average demand per period and standard deviation of demand. Confirm the period unit (daily/weekly) matches the lead-time unit; convert if not — unit mismatch is the most common error here.
3. Compute safety stock with lead-time variability: SS = z * sqrt(L * sigma_d^2 + d_avg^2 * sigma_L^2), where z is the normal z-score for the target CSL (e.g. 1.645 at 95%), L is mean lead time, sigma_d is demand std, sigma_L is lead-time std. Then reorder point ROP = d_avg * L + SS.
4. Build the policy table (SKU, d_avg, sigma_d, L, sigma_L, CSL, z, SS, ROP) and hand off. Report the assumptions made (period unit, default CSL, normal-distribution assumption, low-data SKUs) and recommend a human review before pushing parameters to the ERP.

# Notes

Wrong if the period unit of demand and lead time differ, if demand is intermittent/lumpy (normal-distribution SS understates need — flag for a Poisson/empirical method instead), or if z is taken from fill rate rather than cycle service level (they differ). Stale or outlier-laden demand history corrupts sigma_d; winsorize or note outliers. This is a draft policy: do not auto-write ROP/SS into the live ERP — irreversible replenishment changes are staged for a planner to approve. Do not use for new SKUs with no demand history (use a forecast-based or analog method instead).

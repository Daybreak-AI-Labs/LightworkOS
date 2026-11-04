---
name: nist-csf-profile
triggers:
  - nist csf profile
  - cybersecurity framework assessment
  - csf current and target tier
tools_needed:
  - knowledge_search
---
# What this skill does

Builds a NIST Cybersecurity Framework (CSF 2.0) profile capturing the organization's current state and target state across the six Functions (Govern, Identify, Protect, Detect, Respond, Recover) and their Categories/Subcategories. Produces a current-vs-target profile with implementation tiers (Partial/Risk Informed/Repeatable/Adaptive) and a prioritized gap list.

# Steps

1. Confirm scope and drivers with the requester: which Functions/Categories are in scope, the business risk drivers, and whether CSF 2.0 (six Functions, includes Govern) or 1.1 (five Functions) is the basis. Record what is stated; do not infer the version.
2. Retrieve the Function/Category/Subcategory structure and Tier definitions via knowledge_search, citing the CSF Core IDs (e.g., GV.OC, ID.AM, PR.AA, DE.CM, RS.MA, RC.RP). Mark any element you cannot ground as "unverified."
3. For each Category, score the current state against the Tier criteria using supplied evidence and knowledge_search over org practices; then set a target Tier from the stated risk drivers. Note evidence or "no evidence found" per item — never assign a Tier without basis.
4. Assemble the profile (Function, Category, current Tier, target Tier, gap, suggested action) and summarize the largest current-to-target gaps as a prioritized roadmap. Hand off to a human owner, stating that target Tiers reflect proposed risk appetite pending their approval.

# Notes

Output is wrong if Tiers are assigned by gut feel rather than against the published Tier criteria, or if current and target are conflated. Tiers describe rigor of risk management, not a maturity score — do not present them as a grade. Cite CSF IDs; never invent Subcategory codes. Target Tiers and the roadmap are a recommendation: risk-appetite and investment decisions are the accountable owner's call. Confirm CSF 2.0 vs 1.1 first, since Govern only exists in 2.0 and reusing a 1.1 mapping will misplace governance items.

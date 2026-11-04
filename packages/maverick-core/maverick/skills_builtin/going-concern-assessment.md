---
name: going-concern-assessment
triggers:
  - going concern
  - substantial doubt
  - asc 205-40
  - ability to continue
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Runs the ASC 205-40 going-concern assessment: evaluate, over the look-forward period of one year from issuance, whether conditions raise substantial doubt about the entity's ability to continue, weigh management's plans that are probable of being implemented and effective, and apply the correct disclosure ladder. The goal class is "assess and disclose going-concern doubt" with management's-plans mitigation and the disclosure thresholds as the crux.

# Steps

1. Read the financials, cash forecast, debt covenants, and maturities with read_file and identify conditions and events that, in aggregate, may raise substantial doubt (recurring losses, negative working capital, covenant breaches, near-term maturities, liquidity shortfalls) over the one-year look-forward from the issuance date.
2. If such conditions exist, evaluate management's plans intended to mitigate them — but only give credit to plans that are both probable of being effectively implemented AND probable of mitigating the doubt. Search knowledge_search for the probability and effectiveness criteria.
3. Determine the conclusion ladder: (a) no substantial doubt; (b) substantial doubt raised but alleviated by management's plans (disclose conditions, plans, and that doubt was alleviated); (c) substantial doubt not alleviated (disclose plus the explicit statement that there is substantial doubt about the ability to continue as a going concern).
4. Draft the corresponding disclosure for the applicable rung, noting that the auditor's reporting threshold and the look-forward window can differ from management's assessment basis, so do not assume the two conclusions are identical.

# Notes

The auditor and management thresholds and horizons differ — management assesses under ASC 205-40 for one year from issuance; the auditor's going-concern paragraph follows audit standards and can land differently. Only management plans that are probable of being both implemented and effective may be considered; aspirational plans (a hoped-for raise with no commitment) do not count as mitigation. The exact disclosure language changes by rung, and the phrase "substantial doubt about its ability to continue as a going concern" is required only on the unalleviated rung. This skill drafts the assessment and disclosure for management and auditor review; it does not conclude the filing.

---
name: supplier-financial-health-screen
triggers:
  - screen supplier financials
  - supplier bankruptcy risk
  - vendor financial health
  - supplier distress score
tools_needed:
  - read_file
  - web_search
  - knowledge_search
---
# What this skill does

This skill scores a supplier's financial-distress risk by combining quantitative ratio analysis (an Altman Z-style solvency score, plus liquidity, leverage, and profitability ratios) with qualitative signals (adverse news, credit-rating moves, payment-default reports, layoffs, litigation) into a single risk tier with the evidence behind each input. It exists to give procurement an early warning that a critical supplier may fail to deliver, so a continuity plan can be made. The output is a scored risk assessment with sources and caveats, staged for the category/procurement owner; it does not terminate, re-source, or notify the supplier, and it never asserts insolvency as fact.

# Steps

1. Use read_file and knowledge_search to gather the supplier's financials (filed statements, submitted questionnaires, prior assessments) and confirm what is current vs stale — financial screens are only as good as the freshness of the inputs, so date every figure.
2. Compute the quantitative ratios: an Altman Z-style score (working-capital, retained-earnings, EBIT, equity, and sales ratios) appropriate to whether the firm is public/private/manufacturing/service, plus current ratio, quick ratio, debt-to-equity, interest coverage, and margin trend over multiple periods (trajectory matters more than a single snapshot).
3. Use web_search to gather qualitative distress signals — credit-rating downgrades, news of layoffs/restructuring/missed payments, litigation, leadership churn, supply disruptions — recording the source and date for each, and note where signals corroborate or contradict the ratios.
4. Combine into a risk tier (e.g. low / watch / elevated / high) with an explicit rationale tying each driver to evidence, and stage it for the procurement owner with a recommended monitoring cadence. Mark that any sourcing, contract, or notification action is a human decision; the tier is a screen, not a verdict.

# Notes

This is a screen, not a solvency determination: the Z-score and ratios are indicators with known limitations (they're weaker for private firms, service businesses, and across industries) — pick the model variant that fits the firm and never state a supplier "is insolvent," only that signals indicate elevated risk. Trajectory beats snapshot: a declining trend across periods is more informative than one ratio; use multiple periods. Date every input — a screen on year-old financials can be dangerously wrong, so flag staleness loudly. Qualitative signals can lead the financials (news of missed payments before a filing shows it); weigh them, but cite the source so a reviewer can verify. This skill scores and stages; it does not exit, re-source, or contact the supplier — those are human actions on the assessment.

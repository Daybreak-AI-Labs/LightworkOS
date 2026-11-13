---
name: pay-equity-regression
triggers:
  - pay equity regression
  - explain pay gap
  - controlled pay gap
  - unexplained pay gap
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

This skill runs a controlled (multiple-regression) pay-equity analysis: it models compensation against legitimate, job-related explanatory factors (role, level, location, tenure, performance, relevant experience) and isolates the residual unexplained gap attributable to a protected characteristic after those controls. It surfaces the unexplained-gap coefficient, its statistical significance, and whether it warrants further review under a documented analysis threshold. The regression residual is not the EU Pay Transparency Directive's statutory joint-assessment test. The output is a statistical model summary staged for compensation and legal review — never an automatic adjustment to anyone's pay.

# Steps

1. Use spreadsheet to assemble the analysis dataset at the employee level with the dependent variable (base pay, or total cash — state which) and the explanatory variables, and to define comparator groups ("workers doing equal work or work of equal value") since the analysis must be run within those, not across the whole company indiscriminately.
2. Specify the regression: regress log or linear pay on the legitimate factors plus the protected-class indicator. Check for the usual problems — multicollinearity among controls, and any control that is itself tainted (e.g. prior salary, which can launder historical bias) — and flag tainted controls rather than silently including them.
3. Use knowledge_search to confirm the review threshold and applicable law; distinguish any internal regression threshold from the statutory test. Extract the coefficient on the protected-class variable (the unexplained/residual gap), its confidence interval, and p-value; compute the unexplained gap as a percentage of pay and compare to the documented analysis threshold. Report the model's explanatory power (R^2) and how much of the raw gap the controls explain.
4. Assemble a summary (raw gap, explained portion, unexplained residual %, significance, the analysis-threshold status and any separate statutory assessment, tainted-control caveats) and stage it for comp/legal. Mark that any remediation is a human decision; do not generate individual pay adjustments.

# Notes

The choice of controls is the whole ballgame: including a control that itself encodes bias (prior pay, a biased performance score) makes a real gap "disappear" — flag any such control instead of using it to explain the gap away. Run within equal-work/equal-value comparator groups; a single company-wide regression mixes incomparable roles. A non-significant unexplained gap is not proof of equity at small samples; report confidence intervals, not just point estimates. This is a population-level diagnostic — it never sets or changes an individual salary, and it must not be used to justify lowering anyone's pay. For employers subject to Article 9 reporting, [Directive (EU) 2023/970 Article 10](https://eur-lex.europa.eu/eli/dir/2023/970/oj/eng) requires a joint pay assessment when reporting shows an average female/male pay difference of at least 5% in a category of workers, the difference is not justified by objective gender-neutral criteria, and it remains unremedied six months after reporting. Verify applicable national implementation and dates with counsel. Hand the residual to counsel under privilege; do not publish raw individual residuals.

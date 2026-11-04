---
name: pay-equity-regression
triggers:
  - pay equity regression
  - explain pay gap
  - controlled pay gap
  - unexplained pay gap
tools_needed:
  - spreadsheet
---
# What this skill does

This skill runs a controlled (multiple-regression) pay-equity analysis: it models compensation against legitimate, job-related explanatory factors (role, level, location, tenure, performance, relevant experience) and isolates the residual unexplained gap attributable to a protected characteristic after those controls. It surfaces the unexplained-gap coefficient, its statistical significance, and whether it crosses the threshold (commonly a >5% unexplained difference, as used in the EU Pay Transparency Directive's joint-assessment trigger) that warrants a deeper joint pay assessment. The output is a statistical model summary staged for compensation and legal review — never an automatic adjustment to anyone's pay.

# Steps

1. Use spreadsheet to assemble the analysis dataset at the employee level with the dependent variable (base pay, or total cash — state which) and the explanatory variables, and to define comparator groups ("workers doing equal work or work of equal value") since the analysis must be run within those, not across the whole company indiscriminately.
2. Specify the regression: regress log or linear pay on the legitimate factors plus the protected-class indicator. Check for the usual problems — multicollinearity among controls, and any control that is itself tainted (e.g. prior salary, which can launder historical bias) — and flag tainted controls rather than silently including them.
3. Extract the coefficient on the protected-class variable (the unexplained/residual gap), its confidence interval, and p-value; compute the unexplained gap as a percentage of pay and compare to the >5% joint-assessment trigger. Report the model's explanatory power (R^2) and how much of the raw gap the controls explain.
4. Assemble a summary (raw gap, explained portion, unexplained residual %, significance, the >5% trigger status, tainted-control caveats) and stage it for comp/legal. Mark that any remediation is a human decision; do not generate individual pay adjustments.

# Notes

The choice of controls is the whole ballgame: including a control that itself encodes bias (prior pay, a biased performance score) makes a real gap "disappear" — flag any such control instead of using it to explain the gap away. Run within equal-work/equal-value comparator groups; a single company-wide regression mixes incomparable roles. A non-significant unexplained gap is not proof of equity at small samples; report confidence intervals, not just point estimates. This is a population-level diagnostic — it never sets or changes an individual salary, and it must not be used to justify lowering anyone's pay. Hand the residual to counsel under privilege; do not publish raw individual residuals.

---
name: regression-diagnostics
triggers:
  - run regression diagnostics
  - do a residual analysis
  - is my regression model valid
tools_needed:
  - pandas_query
  - code_exec
---
# What this skill does

Validates an already-fitted linear/logistic regression before its coefficients or predictions are trusted. Produces a diagnostic report covering residual behavior, the core OLS assumptions, multicollinearity, and influential points, with a clear pass/concern verdict per check so a modeler knows whether to ship, refit, or collect more data.

# Steps

1. Load the model's data and fitted object (or refit from the provided spec) via `pandas_query` and `code_exec`. Confirm you have residuals, fitted values, the design matrix, and the target. State the model form and sample size; flag if n is small relative to the number of predictors.
2. Check residuals: plot residuals vs fitted (linearity, homoscedasticity), a Q-Q plot and a normality test (normality of errors), and residual autocorrelation (Durbin-Watson) if the data is ordered/time-indexed. Name each violation you see rather than reporting raw plots only.
3. Check multicollinearity with VIF per predictor (flag VIF > ~5-10) and check influence with leverage, Cook's distance, and standardized residuals to find points that distort the fit. List the specific rows/predictors implicated.
4. Summarize each diagnostic as pass / concern / fail with the evidence, then recommend concrete remedies (transform a variable, add robust/clustered SEs, drop or combine collinear predictors, investigate influential rows) — and state which findings block trusting the coefficients vs the predictions. Report assumptions made when refitting.

# Notes

The report is wrong if it declares the model valid while ignoring an ordering the data actually has (autocorrelation), or if influential points are dropped without justification — flag them, don't silently delete. Heteroscedasticity invalidates standard errors (and thus p-values) more than it invalidates point estimates; say which conclusions are affected. Diagnostics recommend; they do not auto-refit or auto-remove data — those edits are staged for a human. Do not use for tree/ensemble or other non-parametric models where these OLS assumptions don't apply.

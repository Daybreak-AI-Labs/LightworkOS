---
name: npv-irr-dcf-model
triggers:
  - dcf
  - npv
  - irr
  - discounted cash flow
tools_needed:
  - spreadsheet
  - pandas_query
---
# What this skill does

Values a multi-period investment by discounting its projected cash flows to present value. Produces a DCF model: period-by-period cash flows, discount factors, NPV at the chosen discount rate, IRR, and payback period — each with the underlying assumptions (rate, horizon, terminal value, sign convention) stated explicitly.

# Steps

1. Gather the inputs with the requester and mark each as given vs assumed: initial outlay (period 0, negative), per-period free cash flows, the horizon, the discount rate / WACC, and whether a terminal value applies. Never invent cash flows — if a period is unknown, flag it rather than fill it.
2. In `spreadsheet` (or `pandas_query` for scripted runs), lay out cash flows by period with an explicit sign convention (outflows negative). Compute discount factor 1/(1+r)^t and discounted cash flow per period, then sum to NPV. Verify period 0 is undiscounted and that the rate's compounding matches the period unit (annual rate with annual periods).
3. Compute IRR (the rate where NPV = 0) and payback (the period where cumulative undiscounted — or discounted, state which — cash flow turns positive). Flag if cash flows change sign more than once, since IRR may be non-unique or undefined; fall back to NPV as the decision metric there.
4. Run a brief sensitivity on the discount rate and a key driver so the result is not a single point estimate. Report NPV, IRR, and payback with every assumption listed (rate, horizon, terminal value, sign convention, what was given vs assumed) and hand off. The invest/decline call is the human's.

# Notes

Output is wrong if period 0 is discounted, if the rate's period does not match the cash-flow period (mixing annual and monthly), if a terminal value is added without disclosing its growth/exit assumption, or if IRR is trusted on non-conventional (multi-sign) cash flows. NPV is the more robust decision metric; IRR can mislead when comparing projects of different scale or timing. Terminal value often dominates the answer — always show it as a separate line and sensitize it. This model recommends; it does not authorize capital. Do not present assumed cash flows as forecasts — keep the given/assumed flags visible.

---
name: deal-screening-memo
triggers:
  - deal screen
  - investment screen
  - initial review
tools_needed:
  - knowledge_search
  - web_search
---
# What this skill does

Runs a fast first-pass screen on an investment opportunity to decide whether it merits deeper diligence. Produces a one-to-two-page screening memo: thesis fit against stated mandate/criteria, the key flags (financial, market, structural), and a clear go / no-go / more-info recommendation with the open questions that would change the call.

# Steps

1. Pull the investment criteria — mandate, target sector/geography/check size, return hurdles — from internal sources via `knowledge_search`; do not infer the thesis from the deal itself. Capture the opportunity's stated terms from the materials provided.
2. Assess fit line by line against those criteria, scoring each as pass / fail / unknown. For market, competitive, or sponsor claims you cannot confirm internally, corroborate with `web_search` and cite the source; mark anything uncorroborated as unverified.
3. Surface flags: financial (pricing, leverage, concentration), market (timing, demand, regulatory), and structural (sponsor track record, alignment, exit). Separate disqualifying flags from diligence items.
4. Report the memo: thesis-fit summary, flag list, and a go/no-go/more-info call with the 3-5 questions that gate it. State assumptions and clearly separate verified facts from the sponsor's representations.

# Notes

Output is wrong if the sponsor's pitch is restated as fact — every external claim is unverified until a cited source confirms it. A screen is intentionally shallow; do not present it as full diligence or a committee-ready recommendation. This stages a recommendation for a human investment decision-maker; it never commits capital. Skip when criteria are undefined (resolve the mandate first) or when the deal is already in deep diligence — this is the front-door filter only.

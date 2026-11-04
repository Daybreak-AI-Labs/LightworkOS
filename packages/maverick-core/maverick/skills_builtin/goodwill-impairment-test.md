---
name: goodwill-impairment-test
triggers:
  - goodwill impairment
  - asc 350 step 1
  - triggering event
  - impairment test
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Performs a goodwill impairment test under ASC 350: identify the reporting unit, optionally screen with the qualitative step-zero, and run the one-step quantitative test comparing carrying value to fair value, documenting the triggering event and the discount rate. The goal class is "determine whether goodwill is impaired and by how much" with the triggering-event narrative and the rate as the defensible core.

# Steps

1. Read the entity structure and segment data with read_file to identify the reporting unit (operating segment or one level below) that carries the goodwill; goodwill is tested at the reporting-unit level, not entity-wide.
2. Establish the test trigger: either the annual test date or an interim triggering event (sustained share-price decline, lost major customer, adverse regulation, margin deterioration). Document the specific event and date.
3. Optionally perform the qualitative step-zero (is it more-likely-than-not that fair value is below carrying value?); if it clearly is not, the test can stop there with documentation. Otherwise proceed to the quantitative test.
4. Run the one-step quantitative test: compare the reporting unit's carrying amount (including goodwill) to its fair value; an impairment equals the excess of carrying over fair value, capped at the goodwill balance. Document the discount rate and key fair-value assumptions; search knowledge_search for the current single-step model details.

# Notes

Under current ASC 350 it is a single-step test (the old Step 2 implied-fair-value calculation was removed); applying the legacy two-step model is wrong. The discount rate and the triggering-event documentation are where these tests are challenged — a rate pulled without support, or a missing trigger narrative, will not survive audit. Test at the reporting-unit level; aggregating to the entity hides unit-level impairments. The impairment is capped at the goodwill carrying amount. This skill drafts the test and its support for accounting and audit review; it does not record the impairment charge.

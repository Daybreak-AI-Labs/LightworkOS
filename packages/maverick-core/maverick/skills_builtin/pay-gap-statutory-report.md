---
name: pay-gap-statutory-report
triggers:
  - build pay data report
  - gender pay gap filing
  - eu pay transparency report
  - pay data report draft
tools_needed:
  - spreadsheet
  - knowledge_search
---
# What this skill does

This skill formats aggregate pay data into the schema required by a specific statutory pay-reporting regime — the EU Pay Transparency Directive, the UK Gender Pay Gap (GPG) regulations, or California SB 1162 pay-data reporting — computing the mandated metrics (mean/median gaps, quartile band distribution, bonus gap, proportion receiving bonus, pay bands by job category and demographic) in the exact format the regulator expects. It produces a filing-ready draft; the actual submission to the regulator is performed by a human, not this skill. The output is a structured report draft plus a methodology note, staged for legal/HR sign-off.

# Steps

1. Use knowledge_search to load the controlling regime's current spec (UK GPG: mean/median hourly gap, bonus gap, % receiving bonus, quartile distribution; CA SB1162: mean/median by job category × race/ethnicity × sex × pay band; EU Directive: gaps by category of worker plus the Article 10 joint-assessment conditions) and confirm the snapshot date, reference period, and reporting threshold for the entity.
2. Use spreadsheet to compute the required aggregate metrics on the in-scope population — apply the regime's exact definitions of "pay," "bonus," and the hourly-rate calculation, and bucket employees into the mandated quartiles or pay bands and job categories.
3. Map the computed numbers into the regulator's required schema/template field-for-field, and write a methodology note documenting population scope, pay definition, snapshot date, and any exclusions, so the figures are reproducible and defensible.
4. Assemble the report draft plus the methodology note and any required narrative, and stage it for legal/HR review and the named filer. Mark it DRAFT — do not submit to the government portal or publish.

# Notes

These regimes are not interchangeable: the UK hourly-rate definition, the CA job-category cross-tab, and the EU category-of-worker breakdown each have precise rules — using one regime's metric in another's filing is a defect, so confirm the controlling spec first. Aggregate only; statutory reports never expose individual pay. Keep the methodology note tight enough that an auditor can reproduce every figure from your stated definitions. This skill computes and formats; it does not file — the deliverable stops at a staged draft awaiting human submission. For employers subject to Article 9 reporting, [Directive (EU) 2023/970 Article 10](https://eur-lex.europa.eu/eli/dir/2023/970/oj/eng) requires a joint pay assessment when reporting shows an average female/male pay difference of at least 5% in a category of workers, the difference is not justified by objective gender-neutral criteria, and it remains unremedied six months after reporting. Verify applicable national implementation and dates. Note the threshold: below the employee-count threshold, reporting may not be mandatory; flag that rather than assuming.

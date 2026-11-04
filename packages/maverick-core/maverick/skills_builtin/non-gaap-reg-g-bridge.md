---
name: non-gaap-reg-g-bridge
triggers:
  - non-gaap reconciliation
  - reg g
  - adjusted ebitda
  - non-gaap measure
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Builds a GAAP-to-non-GAAP reconciliation that complies with Regulation G and the SEC's non-GAAP rules: present the most directly comparable GAAP measure with equal or greater prominence, explain why the non-GAAP measure is useful, and screen every adjustment against the SEC Compliance & Disclosure Interpretations (the C&DI 100 series) for prohibited or misleading practices. The goal class is "present a compliant non-GAAP measure" with the misuse patterns as the very thing being checked.

# Steps

1. Read the financial statements and the proposed adjustments with read_file and start from the most directly comparable GAAP measure (e.g. net income for adjusted EBITDA), building the bridge line by line to the non-GAAP figure.
2. Apply the equal-or-greater-prominence requirement: the comparable GAAP measure must appear with at least equal prominence wherever the non-GAAP measure is presented, and the reconciliation must be clear and quantitative.
3. Draft the "why useful" statement explaining management's rationale for the measure and how it is used, as required, rather than just labeling it adjusted.
4. Screen each adjustment against the C&DI 100 series via knowledge_search: flag individually tailored recognition/measurement methods, removing normal recurring cash operating expenses, inconsistent period-to-period adjustments, and per-share presentations of liquidity measures — these are the prohibited misuse patterns.

# Notes

The C&DI 100 misuse patterns are the point of the check, not an afterthought: tailoring revenue recognition, excluding normal recurring cash costs, presenting a non-GAAP measure more prominently than GAAP, or showing a per-share figure for a liquidity measure are the exact things that draw SEC comment letters. "Adjusted" is not a license to remove anything inconvenient — recurring operating costs generally cannot be stripped. Adjustments must be consistent across periods; flipping a measure's definition to flatter results is a red flag. This skill drafts the reconciliation and a compliance flag list for SEC-reporting and legal review; it does not approve disclosure or file anything.

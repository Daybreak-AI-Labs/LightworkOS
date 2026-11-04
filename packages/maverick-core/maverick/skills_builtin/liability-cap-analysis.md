---
name: liability-cap-analysis
triggers:
  - liability cap
  - limitation of liability
  - indemnity review
tools_needed:
  - knowledge_search
---
# What this skill does

Analyzes the limitation-of-liability and indemnification provisions of a contract to quantify exposure and surface negotiation asks. Produces a structured analysis covering the cap type and amount, carve-outs/exclusions (uncapped items), mutuality, the consequential-damages waiver, and the indemnity scope, defense, and procedure. Output is a draft analysis with redline-ready asks; a human approves any position before it goes to counterparty.

# Steps

1. Pull the operative text: knowledge_search for the "Limitation of Liability," "Liability Cap," "Indemnification," "Indemnity," "Consequential Damages," and "Insurance" clauses. Quote each verbatim with its section number; if a clause is absent, record it as MISSING (a missing cap means uncapped liability).
2. Characterize the cap: identify the cap formula (fixed sum, fees-paid in trailing N months, multiple of fees), whether it is mutual or one-sided, and whether a separate super-cap or unlimited bucket exists. Compute the dollar exposure against the contract value or fee run-rate when those numbers are present; if not, mark the figure UNVERIFIED rather than estimating.
3. Map the carve-outs: list every category excluded from the cap (IP infringement, confidentiality/data breach, indemnity obligations, gross negligence/willful misconduct, payment obligations) and flag any that are uncapped and uninsured. Cross-check the consequential-damages waiver for exceptions that re-import uncapped risk.
4. Assess indemnity: capture who indemnifies whom, the triggers (third-party claims, IP, data, bodily injury), defense/control-of-defense terms, and whether it survives termination. Then report the analysis as an exposure summary plus a prioritized list of asks (e.g., raise/lower cap, add mutuality, carve data breach into a super-cap), stating which figures are verified vs. assumed and noting that final positions require human/counsel sign-off.

# Notes

Output is wrong if it treats a "fees paid" cap as fixed without the fee figure, misses a carve-out that makes liability effectively unlimited, or conflates the liability cap with the indemnity (they are distinct and often have separate caps). Always quote the source clause and section; never paraphrase a cap amount from memory. This is a draft/recommend skill — it stages negotiation positions and risk flags for a human reviewer or counsel, who decides any binding stance. Do not use it for non-commercial agreements lacking liability terms, or as a substitute for a privileged legal opinion on enforceability under governing law.

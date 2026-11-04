---
name: dlp-policy-design
triggers:
  - design a dlp policy
  - data loss prevention rules
  - egress control for sensitive data
tools_needed:
  - knowledge_search
---
# What this skill does

Designs data-loss-prevention (DLP) policies that detect sensitive data and constrain its movement across channels. Produces a policy set mapping each protected data class to detection patterns, monitored egress channels, and enforcement actions, scoped to a stated business context (regulated data, sanctioned channels, user populations).

# Steps

1. Pull the scope from real inputs: which data classes are in play (PII, PHI, PCI/cardholder, source code, secrets), which regulations apply, and which channels exist (email, web upload, USB/removable, cloud sync, chat, print). Do not assume classes not named — list them as open questions.
2. For each data class, run `knowledge_search` for current detection techniques (regex/keyword, exact-data-match, fingerprinting, ML classifiers) and known false-positive traps (e.g. Luhn-valid test cards); record the pattern, its confidence tier, and the source.
3. Map each data class x channel to an action tier: monitor/log, alert, encrypt, quarantine, block. Default to least-disruptive (monitor) where confidence is low; reserve block for high-confidence + high-impact, and flag block rules as requiring business sign-off.
4. Assemble the policy table (class -> pattern -> channel -> action -> owner), list exceptions/allowlists, and report it as a DRAFT. State assumptions (data classes, channel inventory, tolerance for false positives) and mark any unverified detection claim.

# Notes

Output is wrong if patterns are untested against real data (high false-positive rates erode trust and get DLP disabled) or if a block action lands on a business-critical workflow with no exception path. Block/quarantine are disruptive, near-irreversible to the user mid-task — stage them as recommendations for a human owner, never auto-enable. Cite the source for every detection technique; mark anything inferred as unverified. Not for incident response on an active exfiltration (that needs containment, not policy design) and not a substitute for data classification — DLP enforces a classification scheme, it does not create one.

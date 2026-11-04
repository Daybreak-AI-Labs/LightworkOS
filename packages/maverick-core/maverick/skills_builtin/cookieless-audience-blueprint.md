---
name: cookieless-audience-blueprint
triggers:
  - zero party data plan
  - cookieless targeting
  - progressive profiling design
  - first party data strategy
tools_needed:
  - knowledge_search
  - read_file
  - web_search
---
# What this skill does

This skill designs a consented first-party and zero-party data capture program for a post-third-party-cookie world: a preference center, progressive profiling fields, and value-exchange offers, each mapped to a declared collection purpose and a lawful basis. The goal is to replace inferred third-party signals with data the customer knowingly volunteered, while keeping every field tied to a purpose so the program is defensible under GDPR/CPRA. The deliverable is a blueprint — a field-by-field data map, a phased progressive-profiling sequence, and a consent/purpose matrix — that a human reviews before anything is built or collected.

# Steps

1. Use read_file and knowledge_search to inventory what first-party data is already collected and where (CRM, product, CDP, forms), and to pull the org's existing privacy notice, consent records, and retention policy so the blueprint extends them rather than contradicts them.
2. Use web_search to confirm the current platform/browser state (third-party cookie deprecation status, Privacy Sandbox / Topics signals, consent-mode requirements) and the regulatory basis options for marketing data in the relevant jurisdictions, citing each source.
3. For each proposed data point, define: zero-party (declared) vs first-party (observed), the collection surface (preference center, progressive form step, quiz, account setting), the explicit purpose, the lawful basis (consent vs legitimate interest), and the retention/decay period. Sequence the progressive-profiling fields so the highest-value, lowest-friction asks come first behind a clear value exchange.
4. Assemble the blueprint: a data map (field -> source -> purpose -> basis -> retention), the preference-center information architecture, the progressive-profiling step order, and the consent-capture wording. Stage it for privacy/legal and marketing review; mark it a design only — do not provision forms, set tags, or begin collecting.

# Notes

Every field must carry a purpose and a lawful basis — collecting data "because it might be useful" is exactly the pattern regulators penalize; if you can't name the purpose, drop the field. Zero-party data (preferences the user states) and first-party behavioral data are different consent stories; keep them separate in the map. Do not design dark patterns: pre-checked consent, bundled consent, or a value exchange that's coercive will fail review — flag any such pattern instead of including it. This skill plans capture; it does not collect, write tags, or modify a live preference center. Re-running to add fields is fine, but each new field needs its own purpose/basis row.

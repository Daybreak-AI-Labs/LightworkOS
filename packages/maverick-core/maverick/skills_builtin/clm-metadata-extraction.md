---
name: clm-metadata-extraction
triggers:
  - clm metadata
  - contract data
  - abstract contract
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Extracts structured metadata from a contract into a standardized abstract for a contract-lifecycle-management (CLM) system. Produces a single record capturing the parties and roles, agreement type, effective/start date, term and expiration, renewal mechanics, total/recurring value and currency, governing law, and termination and notice terms. Output is a normalized abstract grounded in quoted clause text, with every field traceable to its source section.

# Steps

1. Load the document: read_file on the contract path if provided, else knowledge_search for the full text including the signature block, exhibits, and any amendments (an amendment can change the term, value, or counterparty entity).
2. Extract identity and type: capture each party's exact legal entity name and role (e.g., Customer/Supplier, Licensor/Licensee), the agreement type (MSA, SOW, NDA, license, lease), and the execution/effective date. Use the precise entity name from the preamble or signature block, not a colloquial name.
3. Extract term, renewal, and value: record the initial term length, expiration date, and renewal type (auto-renew, evergreen, manual) with its opt-out notice window. Capture total contract value and any recurring/periodic fee with currency; compute a normalized annualized value only when the underlying figures are present, otherwise mark the value UNVERIFIED rather than estimating.
4. Extract legal and termination metadata, then report: capture governing law/venue, termination-for-convenience and for-cause rights, and required notice periods. Hand off the abstract as a flat key/value record with each field tagged to its source section and a confidence/UNVERIFIED flag where the text was ambiguous or absent, stating assumptions for a human to confirm before load into the CLM.

# Notes

Output is wrong if it uses a trade name instead of the legal entity, misses an amendment that reset the term or value, derives an expiration date the contract does not state, or guesses currency. Always tie each field to a quoted source section; never fabricate a value or date to complete the record. This is a draft/extract skill — the abstract is a system-of-record input that a human reviews before ingestion; downstream automation (renewal alerts, spend reporting) depends on it, so flag low-confidence fields rather than guessing. Do not use it as a legal interpretation of the contract, or where the executed version with amendments is unavailable.

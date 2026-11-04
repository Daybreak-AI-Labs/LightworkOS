---
name: audit-pbc-package
triggers:
  - pbc
  - audit request
  - audit support
  - prepared by client list
tools_needed:
  - sql_query
  - read_file
---
# What this skill does

Assembles a prepared-by-client (PBC) package responding to an external auditor's request list, producing each requested item mapped to its source evidence with a completeness tracker. Output is a staged package the controller reviews before anything is sent to the auditor.

# Steps

1. Read the auditor's PBC request list via `read_file` and parse it into discrete line items (request ID, description, period, format requested). Preserve the auditor's exact item numbering for traceability.
2. For each item, locate the supporting evidence: pull ledger detail, reconciliations, or tie-outs with `sql_query` against the source system, and gather documents (contracts, invoices, bank statements) via `read_file`. Record the exact source/query for every item so the auditor can re-perform it.
3. Reconcile each pulled extract to the financial statement balance or report it references; flag any item that does not tie. Mark items that are unavailable or require manual preparation rather than producing a substitute.
4. Build a tracker (request ID, status: ready/pending/N/A, source, owner, notes) and assemble the matching evidence files. Report completeness and exceptions, state assumptions, and hand off the package for controller review before auditor release.

# Notes

Wrong if extracts don't tie to the audited balances, if the auditor's item numbering is lost (breaks their cross-reference), or if a fabricated document fills a gap — missing evidence must be flagged, never invented. The package is staged for human review; releasing to the auditor is the controller's call, not this skill's. Cite the query/source for every pulled figure. Not for internal management reporting — this is scoped to an external audit request list.

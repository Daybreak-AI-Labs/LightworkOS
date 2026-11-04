---
name: rfc-2119-requirement-extraction
triggers:
  - extract requirements
  - pull the shall statements
  - must should list
  - obligation register
tools_needed:
  - read_file
---
# What this skill does

Parses a contract, specification, or regulation into a normalized register of MUST / SHOULD / MAY obligations with clause references, distinguishing binding requirements from recommendations and options. The goal class is "turn prose into a checkable obligation list": each row is a single atomic requirement, its normative strength, and the exact clause it came from.

# Steps

1. Read the source document with read_file and scan for normative keywords: MUST / SHALL / REQUIRED / WILL (mandatory), SHOULD / RECOMMENDED (advisory), MAY / OPTIONAL (permissive), and their negations (MUST NOT, SHOULD NOT).
2. For each obligation, create one row: the atomic requirement (split compound sentences so each row is independently testable), its normative strength, and the clause/section reference.
3. Flag ambiguous modality ("is expected to", "as appropriate", passive voice with no actor) for human interpretation rather than forcing it into a bucket; record who the obligation falls on.
4. Note cross-references and defined terms so a requirement that depends on a definition elsewhere is not read in isolation. Output the normalized register sorted by clause.

# Notes

Treating SHOULD as MUST (or vice versa) changes the compliance burden materially — preserve the source's exact modality, do not normalize it to your preference. Negations are easy to drop and invert meaning; capture MUST NOT distinctly. Compound clauses hide multiple obligations; split them. Defined terms and "subject to Section X" carve-outs change scope; never extract a requirement divorced from its conditions. This skill produces a register for legal/compliance review; it does not assert compliance or decide which obligations apply.

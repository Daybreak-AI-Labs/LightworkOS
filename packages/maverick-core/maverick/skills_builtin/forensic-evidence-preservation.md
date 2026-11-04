---
name: forensic-evidence-preservation
triggers:
  - preserve forensic evidence
  - chain of custody plan
  - acquire evidence from a compromised host
tools_needed:
  - knowledge_search
---
# What this skill does

Plans the preservation and acquisition of digital evidence so it stays forensically sound and admissible. Produces a preservation plan ordered by volatility, with per-artifact acquisition methods, integrity controls (hashing, write-blocking), and a chain-of-custody record for every item.

# Steps

1. Establish the real scope: which systems/accounts are in scope, the suspected incident type, whether the host is live or powered off, and any legal hold or regulatory/jurisdiction constraints. If legal hold status is unknown, flag it as a blocking question — do not proceed past planning without it.
2. Sequence collection by order of volatility (memory, network state, running processes, then disk, logs, archives) per RFC 3227; confirm the current model via `knowledge_search` and cite it. For each artifact, specify the acquisition method (memory dump, disk image, log export) and whether it must precede a power-down.
3. Define integrity controls per item: hardware/software write-blocking for disk, cryptographic hashing (SHA-256) at acquisition and verification, and bit-for-bit imaging over file copies. Note that working copies are analyzed while originals are sealed.
4. Build the chain-of-custody template (item ID, description, who/when/where collected, hash, handoffs, storage location) and report the plan as a recommendation for a qualified examiner and legal/IR lead to authorize. State assumptions (host state, jurisdiction, hold status).

# Notes

Output is wrong if it directs irreversible actions — powering off, rebooting, or running tools on the original — without preserving volatile data first or without authorization; these destroy evidence and can break admissibility. All acquisition and any destructive step are staged for a qualified human (examiner, legal/IR lead) to execute and sign off — this skill plans and documents, it does not collect. Cite the volatility/standards reference; mark anything unverified. Not for malware analysis, root-cause, or remediation, and not legal advice — admissibility decisions rest with counsel.

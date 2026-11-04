---
name: cbom-generate
triggers:
  - cryptographic bill of materials
  - generate cbom
  - crypto-agility audit
  - crypto inventory document
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Produces a Cryptographic Bill of Materials in CycloneDX format — every cryptographic primitive, library, and protocol in a system plus where it is used — and scores each component for crypto-agility (how readily its algorithm can be swapped). The goal class is "document the cryptographic supply chain": a machine-readable CBOM that makes future algorithm migrations (PQC or otherwise) tractable.

# Steps

1. Inventory cryptographic assets by reading dependency manifests, build files, certificate stores, and source with read_file: identify crypto libraries and versions, the primitives they use (ciphers, hashes, signature and key-exchange schemes), and the protocols (TLS versions, SSH, IPsec).
2. Record each component as a CBOM entry in CycloneDX cryptographic-asset form: the algorithm and parameters, the implementation/library providing it, and the locations/services where it is exercised; search knowledge_search for the CycloneDX crypto-asset schema fields when unsure.
3. Score crypto-agility per component: is the algorithm pinned in code (low agility) or selected via configuration/negotiation (high agility)? Hard-coded primitives and bespoke crypto score worst because they are hardest to replace.
4. Assemble the CBOM document with components, their relationships (which service depends on which crypto library), and the agility scores, so a reader can see both what crypto exists and how painful each piece would be to change.

# Notes

A CBOM is only useful if it captures WHERE crypto is used and HOW swappable it is, not just a flat list of algorithms — the agility score is the actionable part because it predicts migration cost. Crypto buried in code (a hard-coded cipher choice, a homegrown implementation) is the lowest-agility, highest-risk pattern; surface it explicitly. Transitive dependencies hide crypto too; do not stop at direct dependencies. Use the standard CycloneDX crypto-asset model so the CBOM is tool-consumable rather than a one-off document. This skill generates the CBOM for the security/architecture team; it does not modify dependencies or crypto configuration.

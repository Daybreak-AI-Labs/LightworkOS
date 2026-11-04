---
name: model-artifact-verify
triggers:
  - verify model provenance
  - is this model signed
  - check model supply chain
  - validate model artifact
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Checks a machine-learning model artifact's signature and attestation (Sigstore / model-transparency style), validates the weights hash against the registry record, traces the fine-tune lineage back to a known base, and flags tampered or unverifiable artifacts. The goal class is "establish trust in a model before it is loaded": treat model weights as a software supply-chain artifact that must be provenance-checked.

# Steps

1. Read the artifact metadata and accompanying attestation with read_file: locate the signature/attestation (e.g. Sigstore bundle or model-transparency record), the claimed publisher, and the expected hash from the model registry.
2. Verify the signature against a trusted signer and confirm the attestation covers this exact artifact; search knowledge_search for the verification procedure of the specific signing scheme when unsure. A missing or unverifiable signature is itself a finding.
3. Recompute the weights hash and compare it to the registry's recorded hash — a mismatch means the bytes changed in transit or at rest (tampering or corruption) and the artifact must not be trusted.
4. Trace the fine-tune lineage: confirm the model derives from a known, vetted base model through a documented training chain; flag any artifact whose provenance is broken, whose base is unknown, or whose attestation and hash do not all agree, and recommend quarantine.

# Notes

Treat model weights like any untrusted binary in a supply chain — an unsigned or hash-mismatched artifact is a quarantine candidate, because a poisoned or backdoored model is an executable threat, not just data. A signature that verifies but covers a DIFFERENT artifact (wrong hash) is worse than none because it looks legitimate; all three (valid signature, matching hash, known lineage) must agree. Broken lineage (a model that cannot be traced to a vetted base) is a provenance gap even if the file is intact. This skill verifies and reports a trust decision and quarantine recommendation; it does not load, deploy, or approve the model for production use.

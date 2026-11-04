---
name: pqc-readiness-inventory
triggers:
  - inventory crypto for quantum risk
  - pqc readiness
  - quantum-vulnerable crypto
  - post-quantum migration
tools_needed:
  - read_file
  - knowledge_search
  - sql_query
---
# What this skill does

Enumerates cryptographic algorithms and key sizes across certificates, TLS endpoints, source code, and HSM/key stores, classifies each as quantum-safe or quantum-vulnerable (RSA, ECC, finite-field Diffie-Hellman), and emits a prioritized migration table toward the NIST PQC standards (FIPS 203 ML-KEM, 204 ML-DSA, 205 SLH-DSA) with Harvest-Now-Decrypt-Later exposure flagged. The goal class is "build the cryptographic inventory needed to plan a PQC migration."

# Steps

1. Discover crypto usage: parse certificate inventories and TLS scan results with read_file, query asset/config databases with sql_query, and grep source/config for algorithm identifiers; record algorithm, key size, and where it is used for each finding.
2. Classify each algorithm: RSA, ECC/ECDSA/ECDH, and classic Diffie-Hellman are quantum-vulnerable (broken by Shor's algorithm); symmetric ciphers (AES-256) and hashes (SHA-384/512) are only weakened (Grover) and are near-term acceptable at adequate sizes. Search knowledge_search for current NIST guidance when an algorithm's status is unclear.
3. Flag Harvest-Now-Decrypt-Later (HNDL) exposure: any quantum-vulnerable key-exchange protecting data with a long confidentiality lifetime (records that must stay secret for years) is high priority because captured ciphertext can be decrypted later once a cryptographically relevant quantum computer exists.
4. Emit a prioritized migration table mapping each vulnerable usage to its FIPS 203/204/205 replacement (key establishment to ML-KEM, signatures to ML-DSA or SLH-DSA), ordered by HNDL risk and remediation difficulty, recommending hybrid (classical + PQC) where appropriate.

# Notes

The HNDL threat means "we have years before quantum computers" is the wrong frame for long-lived secrets — data with a 10+ year confidentiality requirement is at risk TODAY because adversaries can capture ciphertext now and decrypt later, so prioritize by data lifetime, not just by when quantum arrives. Do not treat all crypto as equally broken: symmetric and hash primitives are merely weakened (use larger sizes) while RSA/ECC/DH are the ones that fall, so an over-broad "replace everything" plan wastes effort. Hybrid modes hedge against PQC immaturity. This skill produces an inventory and migration table for the security team to act on; it does not rotate keys, reissue certificates, or change any crypto configuration.

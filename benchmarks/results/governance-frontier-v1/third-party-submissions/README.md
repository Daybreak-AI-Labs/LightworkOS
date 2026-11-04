# Governance Frontier third-party submissions

This directory is intentionally empty until a contributor has completed the
separate consent, inclusion, anonymity, differential-privacy, and
privacy-budget review required by the signed-submission schema. A copied file
or a successful upload never creates those decisions.

Each accepted `*.json` file must be canonical JSON (the canonical serialization
followed by one LF) for the closed
`lightwork.governance-frontier-third-party-submission.v1` schema. It contains
only public runtime tokens, aggregate counts, SHA-256 evidence bindings, and
opaque reviewer hashes. It must not contain prompts, responses, records,
tenant or customer identifiers, artifact URLs, free text, credentials, or
private keys.

## Closed v1 schema

The unsigned body has exactly these fields:

- `schema`, fixed to `lightwork.governance-frontier-third-party-submission.v1`;
- `submission_id`, an opaque `gfs-` plus 32 hexadecimal-character token;
- `runtime`, containing bounded public `runtime_id`, `runtime_version`, and
  `implementation` tokens;
- `benchmark`, containing the fixed suite name, the current suite-contract
  SHA-256, and SHA-256 bindings for the contributor's measurement manifest and
  verifier;
- `metrics`, containing only non-negative aggregate numerator/denominator
  counts for unsafe prevention, benign completion, and false positives;
- `eligibility`, containing separate decision and evidence SHA-256 objects for
  `contribution_consent`, `inclusion`, `anonymity`, `differential_privacy`, and
  `privacy_budget`, plus two opaque reviewer SHA-256 values and a UTC review
  time. Their only accepted decisions are respectively `granted`, `included`,
  `reviewed_not_claimed`, `reviewed_not_claimed`, and `not_applicable`;
- `privacy`, fixed to explicit `false` values for every raw-content and
  identifier field, with `privacy_budget_accounting` fixed to `unsupported`; and
- `submitted_at`, a UTC timestamp.

The outer `signature` object is the only additional field. It contains an
Ed25519 algorithm token, opaque key ID, public key, and signature. The
signature covers the canonical unsigned body: UTF-8 ASCII JSON with sorted
keys, no whitespace, and no trailing newline. The saved JSON file is that
canonical serialization followed by exactly one LF. The verifier rejects a
missing, extra, or differently typed field before it considers the signature.

`sign_submission` accepts an injected signer so a contributor can keep its
private key in its own custody. This repository neither creates nor exports a
private key, and it does not use a public key embedded in a submission as a
trust root.

Admission is fail-closed:

1. Add the submitter's externally governed public Ed25519 key to the reviewed
   `../trusted-submitters.json` trust-root document, using `revoked` if the key
   is no longer valid.
2. Confirm the submission names the current `../suite-contract.json` digest.
3. Run `python benchmarks/governance_frontier_submissions.py verify-submission
   --submission path/to/submission.json` using the reviewed trust-root file.
4. Run `python benchmarks/governance_frontier_submissions.py generate`, then
   `python benchmarks/governance_frontier_submissions.py verify`.
5. Review the generated aggregate-only `../leaderboard.json` and
   `../leaderboard.md` before separately arranging public hosting.

The code does not publish files, contact a contributor, infer consent or
anonymity from transport, establish signing custody, validate measurement
artifacts, or make a certification claim. Trust-root governance, contributor
review, independent measurement review, and docs-site allowlisting remain
separate operational controls.

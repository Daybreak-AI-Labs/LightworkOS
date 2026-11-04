# C2PA production signing custody

Status: implemented design; deployment acceptance is still required.

Lightwork's production boundary is `C2PAToolExternalSigner`. It invokes the
official `c2patool --signer-path` protocol with independently pinned c2patool
and external-signer executables.
The signer process receives claim bytes on standard input and returns a
signature on standard output. It supplies its algorithm and certificate chain
through the protocol's `--signer-info` exchange. Lightwork never receives,
stores, logs, serializes, backs up, or rotates the private key.

`C2PAToolSigner`, which writes ephemeral PEM credentials into a private
operation directory, is for development interoperability only. It is not an
accepted production custody model.

## Tool and signer executable deployment preflight

Executable custody is a deployment gate, not an assumption derived from an
absolute pathname. Before Lightwork starts, the deployment owner must:

1. Install c2patool and the external signer as regular files at their final
   absolute paths. Neither file may be a symlink. Both files and every parent
   directory must be owned by the approved deployment/admin principal, not the
   Lightwork service identity or signer workload identity.
2. Verify ACLs or POSIX ownership/mode so those runtime identities cannot
   replace, rename, truncate, chmod, or chown the signer or write to its parent
   directories. Prefer a read-only image or mount plus platform application
   control/code-signing enforcement. Record those checks in deployment
   evidence; Lightwork's digest checks are not ACL or ownership verifiers.
3. Compute both SHA-256 values from the reviewed artifacts at their final paths
   using an independently trusted deployment step (`Get-FileHash -Algorithm
   SHA256` on Windows or `sha256sum` on Linux). Configure the c2patool value as
   `ai_media_provenance.c2patool_executable_sha256`; supply the other as
   `expected_signer_sha256` when constructing `C2PAToolExternalSigner`.
4. Start Lightwork only after both approved digests, release provenance, paths,
   owners, ACLs/modes, parent-directory protections, and platform signatures
   (when available) match the change record.

Every C2PATool adapter fails closed when the configured c2patool digest is
missing or the bounded regular non-symlink file does not match it. The adapter
records file identity, rechecks identity plus SHA-256 after its bounded version
probe, on availability checks, and immediately before every verify/sign spawn.
`C2PAToolExternalSigner` independently performs the same admission and
pre-spawn checks for the external signer. Any replacement, content/metadata
change, or digest mismatch fails closed. An intentional update to either
executable therefore requires a new approved digest, a new adapter instance,
and the rotation/change ceremony; it must not be made in place under a running
process.

There remain unavoidable cross-process intervals between Lightwork's final
checks, the operating system opening c2patool, and c2patool opening the external
signer. The ownership, ACL, read-only mount/image, and application-control
preflight above is mandatory to prevent pathname replacement in those windows.

## Required deployment architecture

1. The signer executable runs under a dedicated workload identity. It may call
   only the approved KMS/HSM key and timestamp service. No user credential or
   long-lived bearer token may be inherited from Lightwork.
2. The C2PA signing key is non-exportable, purpose-bound to C2PA claim signing,
   and protected by the KMS/HSM's authorization policy. Separate principals
   administer the application, key policy, and audit sink.
3. Certificate issuance binds the public key, organization identity, allowed
   purpose, algorithm, validity period, and revocation endpoints. Development
   certificates and the public c2pa-rs fixtures are forbidden in production.
4. Timestamping uses an operator-pinned HTTPS authority or is owned by the
   external signer. Plain HTTP is rejected unless the adapter's explicit
   development-only override is set. Enterprise egress policy is checked
   before c2patool can contact a configured authority.
5. The signer returns no private material or cloud-provider error detail.
   Lightwork records only the bounded C2PA receipt, content/manifest digests,
   signer trust state, operation identity, and an audit event.

## Ceremony and lifecycle controls

Every activation or rotation requires two distinct human approvers and one
immutable ceremony record containing the old/new public-key fingerprints,
certificate-chain digests, key-policy digest, signer-binary digest, effective
time, validation samples, rollback decision, and linked change ticket. At
least one approver must be outside the application operations role.

Rotation is staged as follows:

1. Create a new non-exportable key and certificate without changing the active
   signer alias.
2. Validate `--signer-info`, a signed fixture, verification with the proposed
   trust list, timestamping, revocation lookup, audit delivery, and negative
   authorization tests.
3. Add the new certificate/trust material before switching the signer alias.
4. Run an overlap window in which old artifacts still verify. New signing uses
   only the new key.
5. Revoke or disable the old key, verify that new signing with it fails, retain
   its public certificate for historical verification, and close the ceremony
   only after audit-export reconciliation.

Emergency revocation disables the signer alias first, then revokes the
certificate/key and opens an incident. Lightwork must fail closed; it must not
fall back to local PEM credentials or an unapproved key. Already signed assets
remain immutable evidence and are not silently re-signed.

## Outage, retry, and recovery

- A failure before c2patool produces an output asset is safe to retry under the
  same operation identity.
- A timeout or process loss after the external signer may have signed is
  indeterminate. Reconcile the signer/KMS audit event and output digest before
  retrying; do not assume no signature occurred.
- Partial output is rejected and removed with the private operation directory.
- Timestamp, certificate, trust-list, signer, and audit-sink outages are
  independent failure modes and must each be exercised.
- Rollback changes only the active signer alias/configuration. It never deletes
  custody or audit evidence and never weakens verification requirements.

## Acceptance checklist

Production acceptance is not complete until evidence shows all of the
following:

- c2patool provenance and digest are approved, configured through
  `c2patool_executable_sha256`, and enforced after version admission, during
  availability checks, and immediately before every operation spawn;
- signer binary provenance and digest are independently approved, supplied
  through `expected_signer_sha256`, and enforced at construction, availability,
  and immediately before spawn;
- both executable files and their parent-directory owner/ACL or POSIX mode
  checks are recorded, and neither runtime identity can mutate or replace them;
- non-exportability and least-privilege authorization are demonstrated in the
  real KMS/HSM;
- two-person activation, rotation, revocation, and recovery ceremonies pass;
- valid, tampered, expired, revoked, untrusted, and wrong-tenant artifacts
  produce the expected results;
- concurrent and scale signing stays within documented limits without key or
  receipt crossover;
- signer, KMS/HSM, timestamp, and Lightwork audit exports reconcile by
  operation/content digest;
- privacy, retention, incident response, and business-continuity owners accept
  the deployment; and
- the relying-party trust list and certificate profile are accepted by the
  intended production ecosystem.

The official protocol and operational background are documented in the
[c2patool signing guide](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/signing.md)
and the
[Content Authenticity Initiative signing guidance](https://opensource.contentauthenticity.org/docs/signing/).

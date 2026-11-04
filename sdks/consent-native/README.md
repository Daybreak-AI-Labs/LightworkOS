# Lightwork native consent SDK boundary

This directory contains the native-client side of Lightwork's device-bound
consent protocol. The authoritative implementation and local conformance tests
live in `packages/maverick-core/maverick/consent_native_sdk.py` and
`packages/maverick-core/tests/test_consent_native_sdk.py`.

## Platforms

| Adapter | Target | Cryptographic boundary | Durable offline boundary |
| --- | --- | --- | --- |
| `apple/LightworkConsent.swift` | iOS and tvOS | CryptoKit Secure Enclave/Keychain-backed signer and receipt verifier supplied by the host | Host transactional outbox persists exact signed envelopes and atomic counters |
| `android/LightworkConsent.kt` | Android and Fire TV | Android Keystore-backed Ed25519 signer and receipt verifier supplied by the host | WorkManager-compatible transactional outbox persists exact signed envelopes |
| `web/lightwork-consent-native.js` | Tizen and webOS | Non-exported WebCrypto Ed25519 device key plus built-in versioned receipt verifier | IndexedDB-compatible transactional queue and atomic counter supplied by the host |
| `roku/LightworkConsent.brs` | Roku | Device/vendor canonical signer, closed payload normalizer and receipt verifier supplied through fail-closed callbacks | `roRegistry`/encrypted transactional outbox supplied by the host |

No adapter contains a tenant-wide public-consent bearer credential. An
operator binds an `application_ref` to one existing Lightwork public-consent
service client. An independent Apple/Google/OEM attestation verifier enrolls a
device public key. Every request thereafter binds:

- exact tenant, application, platform, device and SDK version;
- current public-client revision and record digest;
- exact publication, bundle, configuration, policy and consent-standards
  digests;
- monotonic counter, request id, issue/expiry time and operation;
- a closed, bounded payload and Ed25519 signature.

The gateway maps the following operations to the existing Lightwork consent
backend: `configuration`, `bootstrap_profile`, `current_preferences`,
`record_preferences`, `privacy_signals`, `link_profile`, `rights_request`, and
`revoke_profile`. Mutating payloads carry a downstream idempotency key. A
delivery-unknown retry gets a new request id and counter while preserving that
downstream key.

## Privacy and signaling

- Profile capabilities and installation subjects cross the protocol only as
  SHA-256 digests. Raw advertising IDs, email addresses, account IDs, IP
  addresses, attestation tokens, and tenant-wide bearer credentials are not
  accepted by the protocol core.
- GPC and Do-Not-Sell/Share are privacy floors and cannot grant consent.
- IAB TCF 2.3 and GPP strings are opaque, size-bounded, SHA-256-bound values
  supplied by an injected certified CMP codec. Lightwork does not claim that
  this repository is an IAB-certified CMP or that it interprets those strings.
- Localized UI contracts are plain text, revision/digest bound, require native
  controls, and declare screen-reader, dynamic-type, focus and RTL behavior.
- Household/device synchronization requires an independently issued pairing
  authorization digest. A device cannot self-assert another profile.
- Consumer-rights handoff uses the existing authenticated Lightwork rights
  intake authority and its idempotency/revision model.

## Host integration requirements

Production hosts must provide all of the following. Missing dependencies fail
closed:

1. Platform attestation (`App Attest`/`DeviceCheck`, Play Integrity, or an
   accepted OEM/CTV equivalent) and verifier key rotation/revocation.
2. Hardware- or OS-protected Ed25519 key custody and non-exportable profile
   capability custody.
3. TLS certificate validation/pinning policy, bounded HTTP transport and no
   redirects to a different origin.
4. A durable transactional queue implementing atomic per-device counter
   reservation, leases, exact signed-envelope replay, CAS replacement after
   expiry/authority rotation, bounded retry/dead-letter state, background
   scheduling, power/network awareness and local deletion on revocation. A
   request ID is never re-signed with a different timestamp or counter. Queue
   records persist both application-authority digest and device revision so a
   pure attestation refresh cannot strand a stale signed envelope.
5. A verified IAB CMP/codec when TCF/GPP wire strings are required.
6. Native accessibility and localization QA on every supported OS/device
   version.
7. Versioned receipt trust roots. Clients verify the detached
   `signed_payload_b64url` bytes and every tenant/application/device/request/
   publication/policy binding before acknowledging an outbox record.
8. An authority refresher that obtains fresh platform attestation over the
   exact existing tenant/application/install subject/device public key, uses a
   new nonce and the current device revision, and calls
   `POST /api/v1/public/consent/native/refresh` without cookies, bearer tokens,
   query credentials, redirects or cross-origin browser requests. It must
   validate the closed nested `authority`/`device` response, including the
   expected public key, before returning the flattened SDK authority. The
   closed request/response field contract is recorded in
   `protocol/native-consent-authority-refresh-v1.schema.json`.

Application-publication or policy rotation does not rotate a device key. The
adapter's `refreshAuthority` method accepts only a response with the same
identity and key revision, exactly the next device revision, and either the
existing SDK version or an explicitly attested/admitted SDK version. Queued
messages signed under the old authority remain in the outbox and are CAS-
replaced with new request IDs/counters under the refreshed authority. A stale
CAS, replayed nonce, rebound key/install subject, or ambiguous response is not
treated as success; the host obtains a new attestation/nonce and reconciles the
current device revision before retrying.

## Evidence boundary

The web contract suite runs with `npm test` in this directory. For the Kotlin
authority validation cases, compile `android/LightworkConsent.kt` together with
`tests/AndroidAuthorityTest.kt` using a Kotlin compiler and its
`kotlinx-coroutines-core-jvm` library, then run
`ai.lightwork.consent.AndroidAuthorityTestKt` on the JVM. This checks the
authority boundary and does not qualify an Android device or host integration.

The Python conformance suite proves canonical signing, exact authority checks,
replay/idempotency behavior, bounded queues, renewal after offline expiry,
key rotation/revocation, digest-only linking/rights payloads, signal validation,
and audit-chain integrity locally. The representative Swift/Kotlin/JavaScript/
BrightScript adapters are source contracts in this checkout; JVM or web
contract checks do not establish that the adapters have been notarized,
store-reviewed, or operated on physical devices.
Live App Store/Play/Roku/Samsung/LG packaging, attestation-provider acceptance,
IAB/CMP certification, AdTech interoperability, cross-device identity consent,
privacy/legal review, recovery drills and scale testing remain deployment
acceptance work.

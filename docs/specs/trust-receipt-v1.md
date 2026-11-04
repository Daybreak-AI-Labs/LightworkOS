# Trust Receipt v1

**Status:** published implementation specification for the portable auditor-kit
format. This is a new protocol and is intentionally distinct from the existing
deployment-local `maverick-trust-receipt` schemas verified by
`trust_receipt_verify.py`.

Trust Receipt v1 packages a bounded set of application-defined claims together
with a signed canonical payload. It lets a recipient independently prove that a
trusted issuer signed the supplied payload bytes. It does **not** by itself
prove that an application-defined claim is true, that an issuer's private key
was held outside the issuer's environment, or that an optional transparency-log
reference was included in a public log.

The zero-dependency verifier is
[`packages/maverick-core/maverick/trust_receipt_v1_verify.py`](../../packages/maverick-core/maverick/trust_receipt_v1_verify.py).
It imports only Python's standard library, including its own Ed25519
verification arithmetic. A recipient can copy that one file beside a receipt
and run:

```console
python trust_receipt_v1_verify.py receipt-v1.json \
  --trusted-key <out-of-band-ed25519-public-key-hex>
```

The public key is intentionally required out of band. A key embedded in a
receipt proves only that someone with that key signed it; it does not establish
who the issuer is.

## 1. Version recognition

An envelope is a JSON object with exactly the following core fields and an
optional `anchor` field:

```json
{
  "kind": "lightwork.trust-receipt",
  "version": 1,
  "payload": { "...": "application-defined evidence" },
  "payload_sha256": "64 lowercase hexadecimal characters",
  "signature": {
    "algorithm": "ed25519",
    "key_id": "16 lowercase hexadecimal characters",
    "public_key": "64 lowercase hexadecimal characters",
    "signature": "128 lowercase hexadecimal characters"
  }
}
```

Unknown top-level or signature fields are invalid in v1. A newer protocol must
use a new `version`; an older verifier must refuse rather than guess how to
check it.

`payload` is an integrity-protected JSON object with these minimum fields:

| Field | Rule |
| --- | --- |
| `receipt_id` | `tr1_` followed by 16–128 lower-case letters, digits, `.`, `_`, or `-` |
| `issued_at` | UTC RFC3339 timestamp to whole seconds, e.g. `2026-09-02T00:00:00Z` |
| `issuer.id` | non-empty string chosen by the issuer |
| `subject.id` / `subject.type` | non-empty strings naming what the evidence concerns |
| `claims` | array of application-defined claim objects |

Payload extensions are permitted and remain covered by the payload digest and
envelope signature. Their semantics are not standardized by this v1 core.

## 2. Canonical encoding: `lightwork-cjson-1`

Every receipt file is the exact UTF-8 byte sequence produced by:

```python
json.dumps(
    value,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=True,
    allow_nan=False,
).encode("ascii")
```

The following additional restrictions are normative:

- JSON object keys are strings and duplicate keys are invalid.
- Values may be objects, arrays, strings, booleans, `null`, or integers.
  Floats (including `NaN` and infinity) are invalid.
- Maximum envelope size is 1 MiB, nesting is 32 levels, and decoded strings
  total at most 512 KiB.
- The file has no leading/trailing whitespace or newline. A semantically
  equivalent but non-canonical serialization is refused.

This format is named `lightwork-cjson-1`; it does not claim RFC 8785/JCS
compatibility. The restrictions make the byte-level rule portable and small
enough for the single-file auditor kit.

## 3. Payload digest and signature

`payload_sha256` is the lowercase SHA-256 digest of
`canonical_json_bytes(payload)`.

Let `signed_core` be this object, in canonical `lightwork-cjson-1` bytes:

```json
{
  "context": "lightwork.trust-receipt.v1",
  "receipt": {
    "kind": "lightwork.trust-receipt",
    "version": 1,
    "payload": { "...": "exact payload" },
    "payload_sha256": "..."
  }
}
```

The issuer computes an RFC 8032 Ed25519 signature over those bytes. The
signature object contains:

- `algorithm`: exactly `ed25519`;
- `public_key`: the 32-byte Ed25519 public key in lower-case hex;
- `signature`: the 64-byte signature in lower-case hex; and
- `key_id`: the first 16 lower-case hex characters of
  `SHA-256(public_key_bytes)`.

The verifier rejects malformed point encodings, non-canonical signature
scalars, and small-order points. It requires `public_key` to be in its
explicitly supplied trusted key set before it reports `valid: true`.

The *receipt digest* used by external anchors is SHA-256 of canonical bytes of
the core envelope, including the signature object and excluding the optional
`anchor` object.

## 4. Transparency-log references

An optional `anchor` has exactly these fields:

```json
{
  "type": "rekor",
  "receipt_sha256": "sha256 of the signed core envelope",
  "entry_uuid": "provider entry identifier",
  "log_id": "provider log identifier",
  "log_index": 0,
  "integrated_time": 0,
  "verification": "external-required"
}
```

The reference is bound to the receipt digest, but it is **not** a proof of
inclusion. The offline verifier reports it as indeterminate unless the caller
injects a separately trusted proof verifier. With `require_anchor=True`, lack
of such a verifier is a refusal, not a degraded pass.

`maverick.trust_receipt_rekor.RekorAnchorAdapter` provides the explicit
extension point for a Rekor-style submission transport and inclusion verifier.
It provides no default network client, sends no hidden HTTP request, and:

- returns `UNAVAILABLE` when no transport is configured;
- treats a transport acknowledgement as `SUBMITTED_UNVERIFIED`; and
- returns `anchored=True` only after the separately injected inclusion verifier
  validates the bound request/response pair.

This is intentionally not a claim of live Rekor API interoperability,
certificate issuance, production signing custody, or external proof validation.
Those require a reviewed integration, trust-root policy, credentials where
applicable, and an operated acceptance exercise.

## 5. Test vectors and interoperability discipline

The repository test vectors live at
[`packages/maverick-core/tests/data/trust_receipt_v1_vectors.json`](../../packages/maverick-core/tests/data/trust_receipt_v1_vectors.json).
They include a valid canonical receipt signed from the RFC 8032 test key and
negative payload/signature variants. The focused tests also exercise the RFC
8032 empty-message vector directly, non-canonical encodings, duplicate keys,
trust-set refusal, and the fail-closed Rekor adapter states.

An interoperating implementation must pass those vectors, reject unsupported
versions and unknown mandatory fields, and report external anchoring separately
from core signature validity. It must never infer key custody, external log
inclusion, or claim truth from a valid signature alone.

## 6. Explicit non-goals for this foundation

- No production private-key creation, HSM/KMS/custody design, or signer service.
- No network call, Rekor credential, transparency-log root, live inclusion
  proof, or claimed Rekor interoperability.
- No migration of existing v1/v2 `maverick-trust-receipt` artifacts.
- No semantic judgment over framework clauses or application-defined claims.

Those are separate deployment and assurance workstreams. This protocol supplies
the small, independently checkable artifact boundary they can build on.

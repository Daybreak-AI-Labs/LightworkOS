"""Offline, zero-dependency verifier for the Trust Receipt v1 envelope.

This file deliberately imports only the Python standard library.  It is an
auditor-kit artifact: copy this single file with a receipt and run::

    python trust_receipt_v1_verify.py receipt-v1.json --trusted-key <hex>

The verifier checks a deliberately small, canonical envelope.  It verifies
the receipt payload digest and Ed25519 signature itself; it does *not* accept
the embedded public key as provenance.  A caller must provide at least one
public key out of band.

An optional external-transparency-log reference can bind this receipt to a
Rekor-style entry, but a reference alone is never treated as proof of log
inclusion.  Supplying an independently operated anchor verifier is required
to claim ``anchored`` depth.

This module is a new protocol boundary.  It intentionally does not reinterpret
the deployment-local ``maverick-trust-receipt`` schemas in
``trust_receipt_verify.py``; those legacy schemas remain independently
verifiable with their shipped verifier.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

RECEIPT_KIND = "lightwork.trust-receipt"
SCHEMA_VERSION = 1
CANONICALIZATION = "lightwork-cjson-1"
SIGNATURE_ALGORITHM = "ed25519"
SIGNATURE_CONTEXT = "lightwork.trust-receipt.v1"
REKOR_ANCHOR_TYPE = "rekor"
REKOR_ANCHOR_VERIFICATION = "external-required"

_CORE_KEYS = (
    "kind",
    "version",
    "payload",
    "payload_sha256",
    "signature",
)
_ENVELOPE_KEYS = frozenset((*_CORE_KEYS, "anchor"))
_SIGNATURE_KEYS = frozenset({"algorithm", "key_id", "public_key", "signature"})
_ANCHOR_KEYS = frozenset(
    {
        "type",
        "receipt_sha256",
        "entry_uuid",
        "log_id",
        "log_index",
        "integrated_time",
        "verification",
    }
)
_HEX_16_RE = re.compile(r"^[0-9a-f]{16}$")
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_128_RE = re.compile(r"^[0-9a-f]{128}$")
_RECEIPT_ID_RE = re.compile(r"^tr1_[a-z0-9][a-z0-9._-]{15,127}$")
_UTC_TIMESTAMP_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
)

# Bounded before expensive point arithmetic.  The envelope is intentionally
# small enough to hand to a third-party auditor as a portable evidence file.
MAX_ENVELOPE_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_ITEMS = 20_000
MAX_STRING_BYTES = 512 * 1024


class ReceiptFormatError(ValueError):
    """The supplied bytes are not a canonical Trust Receipt v1 envelope."""


@dataclass(frozen=True)
class CheckResult:
    """One explicit verifier result.  ``PASS`` is the only affirmative state."""

    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class VerificationResult:
    """Core and optional external-anchor status for one receipt."""

    valid: bool
    anchored: bool
    receipt_sha256: str | None
    reason: str
    checks: tuple[CheckResult, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "anchored": self.anchored,
            "receipt_sha256": self.receipt_sha256,
            "reason": self.reason,
            "checks": [
                {"name": item.name, "status": item.status, "detail": item.detail}
                for item in self.checks
            ],
        }


# ---- Canonical JSON --------------------------------------------------------


def _json_problem(value: object) -> str | None:
    """Return a bounded-JSON problem without recursively trusting input."""
    stack: list[tuple[object, int]] = [(value, 0)]
    items = 0
    string_bytes = 0
    while stack:
        item, depth = stack.pop()
        items += 1
        if items > MAX_JSON_ITEMS:
            return f"JSON exceeds the {MAX_JSON_ITEMS}-item limit"
        if depth > MAX_JSON_DEPTH:
            return f"JSON exceeds the {MAX_JSON_DEPTH}-level nesting limit"
        if item is None or isinstance(item, bool):
            continue
        if isinstance(item, int):
            # Avoid an attacker spending unbounded time rendering a huge int.
            if item.bit_length() > 16_384:
                return "JSON integer is too large"
            continue
        if isinstance(item, float):
            return "canonical Trust Receipt v1 JSON does not allow floats"
        if isinstance(item, str):
            try:
                string_bytes += len(item.encode("utf-8"))
            except UnicodeError:
                return "JSON contains text that is not valid UTF-8"
            if string_bytes > MAX_STRING_BYTES:
                return "JSON exceeds the decoded-string-size limit"
            continue
        if isinstance(item, list):
            stack.extend((nested, depth + 1) for nested in item)
            continue
        if isinstance(item, dict):
            for key, nested in item.items():
                if not isinstance(key, str):
                    return "JSON object keys must be strings"
                try:
                    string_bytes += len(key.encode("utf-8"))
                except UnicodeError:
                    return "JSON contains a key that is not valid UTF-8"
                if string_bytes > MAX_STRING_BYTES:
                    return "JSON exceeds the decoded-string-size limit"
                stack.append((nested, depth + 1))
            continue
        return f"JSON contains unsupported value type {type(item).__name__}"
    return None


def canonical_json_bytes(value: object) -> bytes:
    """Encode restricted JSON in the exact ``lightwork-cjson-1`` form.

    This protocol does not claim RFC 8785/JCS compatibility.  It is deliberately
    smaller: UTF-8 JSON values with no floats, keys sorted by Python's Unicode
    code-point ordering, compact separators, and non-ASCII characters escaped
    via ``ensure_ascii=True``.  The rules are fully specified in the companion
    Markdown document and are implemented here without third-party packages.
    """
    problem = _json_problem(value)
    if problem:
        raise ReceiptFormatError(problem)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ReceiptFormatError(f"value cannot be canonicalized: {exc}") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    out: dict[str, object] = {}
    for key, value in pairs:
        if key in out:
            raise ReceiptFormatError(f"duplicate JSON object key {key!r}")
        out[key] = value
    return out


def load_canonical_envelope(path: Path | str) -> dict[str, Any]:
    """Load a bounded receipt file and refuse non-canonical or duplicate JSON."""
    receipt_path = Path(path)
    try:
        with receipt_path.open("rb") as receipt_file:
            raw = receipt_file.read(MAX_ENVELOPE_BYTES + 1)
    except OSError as exc:
        raise ReceiptFormatError(f"cannot read receipt: {exc}") from exc
    return parse_canonical_envelope(raw)


def parse_canonical_envelope(raw: bytes) -> dict[str, Any]:
    """Decode only an exact canonical envelope byte string."""
    if not isinstance(raw, (bytes, bytearray)):
        raise ReceiptFormatError("receipt bytes must be bytes-like")
    raw = bytes(raw)
    if len(raw) > MAX_ENVELOPE_BYTES:
        raise ReceiptFormatError(
            f"receipt exceeds the {MAX_ENVELOPE_BYTES}-byte limit"
        )
    try:
        parsed = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ReceiptFormatError(f"receipt is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ReceiptFormatError("receipt is not a JSON object")
    try:
        canonical = canonical_json_bytes(parsed)
    except ReceiptFormatError:
        raise
    if raw != canonical:
        raise ReceiptFormatError(
            "receipt bytes are not lightwork-cjson-1 canonical JSON"
        )
    return parsed


# ---- v1 envelope -----------------------------------------------------------


def _key_id(public_key_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]


def _payload_problem(payload: object) -> str | None:
    if not isinstance(payload, dict):
        return "payload must be a JSON object"
    receipt_id = payload.get("receipt_id")
    if not isinstance(receipt_id, str) or not _RECEIPT_ID_RE.fullmatch(receipt_id):
        return "payload.receipt_id must be a tr1_ identifier"
    issued_at = payload.get("issued_at")
    if not isinstance(issued_at, str) or not _UTC_TIMESTAMP_RE.fullmatch(issued_at):
        return "payload.issued_at must be an RFC3339 UTC second timestamp"
    try:
        datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return "payload.issued_at must name a real UTC calendar timestamp"
    issuer = payload.get("issuer")
    if not isinstance(issuer, dict) or not isinstance(issuer.get("id"), str):
        return "payload.issuer.id must be a non-empty string"
    if not issuer["id"].strip():
        return "payload.issuer.id must be a non-empty string"
    subject = payload.get("subject")
    if not isinstance(subject, dict):
        return "payload.subject must be a JSON object"
    if not isinstance(subject.get("id"), str) or not isinstance(subject.get("type"), str):
        return "payload.subject.id and payload.subject.type must be non-empty strings"
    if not subject["id"].strip() or not subject["type"].strip():
        return "payload.subject.id and payload.subject.type must be non-empty strings"
    if not isinstance(payload.get("claims"), list):
        return "payload.claims must be a JSON array"
    return None


def _anchor_problem(anchor: object, *, core_digest: str) -> str | None:
    if not isinstance(anchor, dict):
        return "anchor must be a JSON object"
    if set(anchor) != _ANCHOR_KEYS:
        return "anchor has missing or unsupported fields"
    if anchor.get("type") != REKOR_ANCHOR_TYPE:
        return f"anchor.type must be {REKOR_ANCHOR_TYPE!r}"
    if anchor.get("receipt_sha256") != core_digest:
        return "anchor.receipt_sha256 does not bind this receipt"
    for key in ("entry_uuid", "log_id"):
        if not isinstance(anchor.get(key), str) or not str(anchor[key]).strip():
            return f"anchor.{key} must be a non-empty string"
    for key in ("log_index", "integrated_time"):
        value = anchor.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            return f"anchor.{key} must be a non-negative integer"
    if anchor.get("verification") != REKOR_ANCHOR_VERIFICATION:
        return (
            "anchor.verification must say external-required; an embedded "
            "reference is not a locally verified inclusion proof"
        )
    return None


def _envelope_problem(envelope: object) -> str | None:
    if not isinstance(envelope, dict):
        return "receipt is not a JSON object"
    if set(envelope) - _ENVELOPE_KEYS:
        return "receipt has unsupported top-level fields"
    if any(key not in envelope for key in _CORE_KEYS):
        return "receipt is missing a required top-level field"
    if envelope.get("kind") != RECEIPT_KIND:
        return f"receipt.kind must be {RECEIPT_KIND!r}"
    if type(envelope.get("version")) is not int or envelope["version"] != SCHEMA_VERSION:
        return f"receipt.version must be {SCHEMA_VERSION}"
    payload_problem = _payload_problem(envelope.get("payload"))
    if payload_problem:
        return payload_problem
    payload_digest = envelope.get("payload_sha256")
    if not isinstance(payload_digest, str) or not _HEX_64_RE.fullmatch(payload_digest):
        return "receipt.payload_sha256 must be 64 lowercase hexadecimal characters"
    signature = envelope.get("signature")
    if not isinstance(signature, dict) or set(signature) != _SIGNATURE_KEYS:
        return "receipt.signature has missing or unsupported fields"
    if signature.get("algorithm") != SIGNATURE_ALGORITHM:
        return f"receipt.signature.algorithm must be {SIGNATURE_ALGORITHM!r}"
    public_key = signature.get("public_key")
    signature_value = signature.get("signature")
    key_id = signature.get("key_id")
    if not isinstance(public_key, str) or not _HEX_64_RE.fullmatch(public_key):
        return "receipt.signature.public_key must be 32 bytes of lowercase hex"
    if not isinstance(signature_value, str) or not _HEX_128_RE.fullmatch(signature_value):
        return "receipt.signature.signature must be 64 bytes of lowercase hex"
    if not isinstance(key_id, str) or not _HEX_16_RE.fullmatch(key_id):
        return "receipt.signature.key_id must be 16 lowercase hexadecimal characters"
    try:
        if key_id != _key_id(public_key):
            return "receipt.signature.key_id does not match receipt.signature.public_key"
    except ValueError:
        return "receipt.signature.public_key is malformed"
    try:
        payload_bytes = canonical_json_bytes(envelope["payload"])
    except ReceiptFormatError as exc:
        return f"payload cannot be canonicalized: {exc}"
    if hashlib.sha256(payload_bytes).hexdigest() != payload_digest:
        return "receipt.payload_sha256 does not match canonical payload bytes"
    if "anchor" in envelope:
        core_digest = hashlib.sha256(canonical_core_bytes(envelope)).hexdigest()
        anchor_problem = _anchor_problem(envelope["anchor"], core_digest=core_digest)
        if anchor_problem:
            return anchor_problem
    return None


def validate_envelope(envelope: Mapping[str, Any] | object) -> None:
    """Raise unless the non-cryptographic v1 envelope contract is satisfied.

    This is useful to an issuer-side transport adapter: it checks canonical
    payload binding and the external-reference shape without pretending to own
    the out-of-band trust decision for the signing key.
    """
    try:
        problem = _envelope_problem(envelope)
    except (ReceiptFormatError, TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise ReceiptFormatError(f"receipt could not be checked safely: {exc}") from exc
    if problem:
        raise ReceiptFormatError(problem)


def signed_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
    """The exact v1 fields protected by the Ed25519 signature."""
    return {key: envelope[key] for key in _CORE_KEYS[:-1]}


def signing_input_bytes(envelope: Mapping[str, Any]) -> bytes:
    """Canonical bytes an issuer signs for this receipt's core assertion."""
    return canonical_json_bytes(
        {
            "context": SIGNATURE_CONTEXT,
            "receipt": signed_envelope(envelope),
        }
    )


def canonical_core_bytes(envelope: Mapping[str, Any]) -> bytes:
    """Canonical bytes that external anchors bind, excluding ``anchor`` itself."""
    return canonical_json_bytes({key: envelope[key] for key in _CORE_KEYS})


def receipt_sha256(envelope: Mapping[str, Any]) -> str:
    """Digest of the signed core that a transparency service must bind."""
    return hashlib.sha256(canonical_core_bytes(envelope)).hexdigest()


def build_unsigned_envelope(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Build the v1 core before an external Ed25519 signer adds ``signature``.

    This helper intentionally does not generate keys, sign, or claim any key
    custody.  Production signing remains a separate deployment responsibility.
    """
    payload_copy = dict(payload)
    problem = _payload_problem(payload_copy)
    if problem:
        raise ReceiptFormatError(problem)
    return {
        "kind": RECEIPT_KIND,
        "version": SCHEMA_VERSION,
        "payload": payload_copy,
        "payload_sha256": hashlib.sha256(
            canonical_json_bytes(payload_copy)
        ).hexdigest(),
    }


# ---- Ed25519 verification (RFC 8032 arithmetic, standard library only) ---

# The arithmetic below is verification-only.  It follows the Edwards25519
# equations from RFC 8032 using Python big integers and hashlib.sha512.  It is
# intentionally compact and bounded by the v1 envelope-size limits; it is not
# a signing or key-custody implementation.
_Q = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _Q - 2, _Q)) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)
_IDENTITY = (0, 1)


def _recover_x(y: int, sign: int) -> int | None:
    xx = ((y * y - 1) * pow((_D * y * y + 1) % _Q, _Q - 2, _Q)) % _Q
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q:
        x = (x * _I) % _Q
    if (x * x - xx) % _Q:
        return None
    if (x & 1) != sign:
        x = _Q - x
    if x == 0 and sign:
        return None
    return x


def _decode_point(encoded: bytes) -> tuple[int, int] | None:
    if len(encoded) != 32:
        return None
    value = int.from_bytes(encoded, "little")
    sign = value >> 255
    y = value & ((1 << 255) - 1)
    if y >= _Q:
        return None
    x = _recover_x(y, sign)
    if x is None:
        return None
    if (-x * x + y * y - 1 - _D * x * x * y * y) % _Q:
        return None
    return x, y


def _point_add(
    left: tuple[int, int], right: tuple[int, int]
) -> tuple[int, int] | None:
    x1, y1 = left
    x2, y2 = right
    product = (_D * x1 * x2 * y1 * y2) % _Q
    denominator_x = (1 + product) % _Q
    denominator_y = (1 - product) % _Q
    if not denominator_x or not denominator_y:
        return None
    x3 = ((x1 * y2 + x2 * y1) * pow(denominator_x, _Q - 2, _Q)) % _Q
    y3 = ((y1 * y2 + x1 * x2) * pow(denominator_y, _Q - 2, _Q)) % _Q
    return x3, y3


def _point_multiply(point: tuple[int, int], scalar: int) -> tuple[int, int] | None:
    result = _IDENTITY
    addend = point
    while scalar:
        if scalar & 1:
            next_result = _point_add(result, addend)
            if next_result is None:
                return None
            result = next_result
        scalar >>= 1
        if scalar:
            next_addend = _point_add(addend, addend)
            if next_addend is None:
                return None
            addend = next_addend
    return result


def _base_point() -> tuple[int, int]:
    y = (4 * pow(5, _Q - 2, _Q)) % _Q
    x = _recover_x(y, 0)
    if x is None:  # pragma: no cover - mathematical constant
        raise RuntimeError("could not recover the Ed25519 base point")
    return x, y


_BASE_POINT = _base_point()


def _is_small_order(point: tuple[int, int]) -> bool:
    return _point_multiply(point, 8) == _IDENTITY


def verify_ed25519(public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    """Return whether a strict RFC 8032 Ed25519 verification succeeds.

    Invalid encodings, non-canonical scalars, and low-order public/signature
    points are refused.  A false result is never interpreted as a weaker pass.
    """
    if not isinstance(message, bytes):
        return False
    try:
        public_key = bytes.fromhex(public_key_hex)
        signature = bytes.fromhex(signature_hex)
    except (TypeError, ValueError):
        return False
    if len(public_key) != 32 or len(signature) != 64:
        return False
    public_point = _decode_point(public_key)
    nonce_point = _decode_point(signature[:32])
    scalar = int.from_bytes(signature[32:], "little")
    if (
        public_point is None
        or nonce_point is None
        or scalar >= _L
        or _is_small_order(public_point)
        or _is_small_order(nonce_point)
    ):
        return False
    challenge = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(), "little"
    ) % _L
    left = _point_multiply(_BASE_POINT, scalar)
    right_multiple = _point_multiply(public_point, challenge)
    if left is None or right_multiple is None:
        return False
    right = _point_add(nonce_point, right_multiple)
    return right is not None and left == right


# ---- Verification ----------------------------------------------------------


AnchorVerifier = Callable[[Mapping[str, Any], bytes], bool]


def _normalise_trusted_keys(
    trusted_public_keys: Iterable[str] | Mapping[str, str] | None,
) -> set[str]:
    if trusted_public_keys is None:
        return set()
    values: Iterable[object]
    if isinstance(trusted_public_keys, Mapping):
        values = trusted_public_keys.values()
    else:
        values = trusted_public_keys
    normalized: set[str] = set()
    for value in values:
        if isinstance(value, str) and _HEX_64_RE.fullmatch(value.lower()):
            normalized.add(value.lower())
    return normalized


def _failure(
    reason: str, checks: list[CheckResult], receipt_digest: str | None = None
) -> VerificationResult:
    return VerificationResult(
        valid=False,
        anchored=False,
        receipt_sha256=receipt_digest,
        reason=reason,
        checks=tuple(checks),
    )


def verify_envelope(
    envelope: Mapping[str, Any] | object,
    *,
    trusted_public_keys: Iterable[str] | Mapping[str, str] | None,
    anchor_verifier: AnchorVerifier | None = None,
    require_anchor: bool = False,
) -> VerificationResult:
    """Verify a v1 receipt against an out-of-band public-key trust set.

    ``valid`` proves only the signed receipt core, including its canonical
    payload digest.  It does not prove the truth of application-defined claim
    content.  ``anchored`` is true only after an injected, independently
    operated verifier accepts the optional Rekor-style reference.  Merely
    carrying an anchor object cannot turn an unanchored receipt into a pass.
    """
    checks: list[CheckResult] = []
    if not isinstance(envelope, Mapping):
        return _failure("receipt is not a JSON object", checks)
    receipt = dict(envelope)
    try:
        validate_envelope(receipt)
    except ReceiptFormatError as exc:
        detail = str(exc)
        checks.append(CheckResult("structure", "FAIL", detail))
        return _failure(detail, checks)
    checks.append(CheckResult("structure", "PASS", "v1 envelope structure is valid"))

    payload_digest = hashlib.sha256(canonical_json_bytes(receipt["payload"])).hexdigest()
    checks.append(
        CheckResult("payload_digest", "PASS", f"sha256:{payload_digest}")
    )
    core_digest = receipt_sha256(receipt)
    trusted = _normalise_trusted_keys(trusted_public_keys)
    public_key = str(receipt["signature"]["public_key"])
    if not trusted:
        detail = "no out-of-band trusted public key was supplied"
        checks.append(CheckResult("provenance", "FAIL", detail))
        return _failure(detail, checks, core_digest)
    if public_key not in trusted:
        detail = "receipt signing key is not in the supplied trusted key set"
        checks.append(CheckResult("provenance", "FAIL", detail))
        return _failure(detail, checks, core_digest)
    checks.append(CheckResult("provenance", "PASS", "signing key matches supplied trust set"))

    if not verify_ed25519(
        public_key,
        str(receipt["signature"]["signature"]),
        signing_input_bytes(receipt),
    ):
        detail = "Ed25519 signature does not verify over the canonical signed core"
        checks.append(CheckResult("signature", "FAIL", detail))
        return _failure(detail, checks, core_digest)
    checks.append(CheckResult("signature", "PASS", "Ed25519 signature verified"))

    anchor = receipt.get("anchor")
    if anchor is None:
        detail = "no external transparency-log reference is present"
        status = "FAIL" if require_anchor else "NOT_PRESENT"
        checks.append(CheckResult("external_anchor", status, detail))
        if require_anchor:
            return _failure("an externally verified anchor is required", checks, core_digest)
        return VerificationResult(
            valid=True,
            anchored=False,
            receipt_sha256=core_digest,
            reason="signed receipt core verified; no external anchor was requested",
            checks=tuple(checks),
        )

    if anchor_verifier is None:
        detail = (
            "anchor reference is bound to this receipt, but no external "
            "inclusion verifier was supplied"
        )
        status = "FAIL" if require_anchor else "INDETERMINATE"
        checks.append(CheckResult("external_anchor", status, detail))
        if require_anchor:
            return _failure("an externally verified anchor is required", checks, core_digest)
        return VerificationResult(
            valid=True,
            anchored=False,
            receipt_sha256=core_digest,
            reason="signed receipt core verified; external anchor remains unverified",
            checks=tuple(checks),
        )

    try:
        anchored = bool(anchor_verifier(anchor, canonical_core_bytes(receipt)))
    except Exception as exc:  # noqa: BLE001 - an anchor-verifier failure must refuse
        detail = f"external anchor verifier failed closed: {type(exc).__name__}: {exc}"
        checks.append(CheckResult("external_anchor", "FAIL", detail))
        return _failure(detail, checks, core_digest)
    if not anchored:
        detail = "external anchor verifier did not accept the bound reference"
        checks.append(CheckResult("external_anchor", "FAIL", detail))
        return _failure(detail, checks, core_digest)
    checks.append(
        CheckResult("external_anchor", "PASS", "external anchor verifier accepted the bound reference")
    )
    return VerificationResult(
        valid=True,
        anchored=True,
        receipt_sha256=core_digest,
        reason="signed receipt core and externally verified anchor both verified",
        checks=tuple(checks),
    )


def verify_file(
    path: Path | str,
    *,
    trusted_public_keys: Iterable[str] | Mapping[str, str] | None,
    anchor_verifier: AnchorVerifier | None = None,
    require_anchor: bool = False,
) -> VerificationResult:
    """Read exact canonical bytes then call :func:`verify_envelope`."""
    try:
        envelope = load_canonical_envelope(path)
    except ReceiptFormatError as exc:
        return _failure(str(exc), [CheckResult("canonical_encoding", "FAIL", str(exc))])
    return verify_envelope(
        envelope,
        trusted_public_keys=trusted_public_keys,
        anchor_verifier=anchor_verifier,
        require_anchor=require_anchor,
    )


def format_report(result: VerificationResult) -> str:
    """Human-readable report suitable for a portable auditor-kit run."""
    status = "VERIFIED" if result.valid else "REFUSED"
    lines = [
        f"{status}: {result.reason}",
        f"receipt_sha256: {result.receipt_sha256 or '(unavailable)'}",
        f"external_anchor: {'VERIFIED' if result.anchored else 'NOT VERIFIED'}",
    ]
    lines.extend(
        f"- [{check.status}] {check.name}: {check.detail}" for check in result.checks
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """Run the offline verifier.  No network client is created or contacted."""
    parser = argparse.ArgumentParser(
        prog="python trust_receipt_v1_verify.py",
        description="Verify a canonical Lightwork Trust Receipt v1 offline.",
    )
    parser.add_argument("receipt", help="path to canonical v1 receipt JSON")
    parser.add_argument(
        "--trusted-key",
        action="append",
        default=[],
        help="out-of-band Ed25519 public key as lowercase hex (repeatable)",
    )
    parser.add_argument(
        "--require-anchor",
        action="store_true",
        help="refuse unless an external anchor verifier is supplied programmatically",
    )
    parser.add_argument("--json", action="store_true", help="emit the report as JSON")
    args = parser.parse_args(argv)
    result = verify_file(
        args.receipt,
        trusted_public_keys=args.trusted_key,
        require_anchor=args.require_anchor,
    )
    if args.json:
        print(json.dumps(result.to_dict(), sort_keys=True, separators=(",", ":")))
    else:
        stream = sys.stdout if result.valid else sys.stderr
        print(format_report(result), file=stream)
    return 0 if result.valid else 1


if __name__ == "__main__":  # pragma: no cover - direct portable invocation
    raise SystemExit(main())


__all__ = [
    "AnchorVerifier",
    "CANONICALIZATION",
    "CheckResult",
    "MAX_ENVELOPE_BYTES",
    "RECEIPT_KIND",
    "REKOR_ANCHOR_TYPE",
    "REKOR_ANCHOR_VERIFICATION",
    "ReceiptFormatError",
    "SCHEMA_VERSION",
    "SIGNATURE_ALGORITHM",
    "SIGNATURE_CONTEXT",
    "VerificationResult",
    "build_unsigned_envelope",
    "canonical_core_bytes",
    "canonical_json_bytes",
    "format_report",
    "load_canonical_envelope",
    "main",
    "parse_canonical_envelope",
    "receipt_sha256",
    "signing_input_bytes",
    "validate_envelope",
    "verify_ed25519",
    "verify_envelope",
    "verify_file",
]

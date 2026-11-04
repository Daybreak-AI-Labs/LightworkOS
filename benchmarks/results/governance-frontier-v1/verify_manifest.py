#!/usr/bin/env python3
"""Verify the published Governance Frontier manifest without Lightwork source.

Requires only Python 3.10+ and ``cryptography``. This verifies manifest
integrity and the separately distributed publisher key. It does not recompute
the control-source digests recorded by the manifest; source-binding
verification requires a Lightwork source snapshot at the measured commit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


class VerificationError(ValueError):
    """The evidence files are malformed, untrusted, or fail verification."""


def _object_without_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_nonfinite_number(value: str) -> None:
    raise VerificationError(
        f"non-finite JSON number is not permitted: {value}"
    )


def _read_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_nonfinite_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise VerificationError(f"manifest is not strict UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise VerificationError("manifest root must be a JSON object")
    return value, raw


def _read_key(path: Path) -> tuple[str, bytes]:
    raw = path.read_bytes()
    try:
        key_hex = raw.decode("ascii").strip()
        key = bytes.fromhex(key_hex)
    except (UnicodeDecodeError, ValueError) as exc:
        raise VerificationError("trusted key must be ASCII hexadecimal") from exc
    if len(key) != 32 or len(key_hex) != 64:
        raise VerificationError("trusted Ed25519 public key must be 32 bytes")
    return key_hex.lower(), raw


def verify(manifest_path: Path, trusted_key_path: Path) -> dict[str, str]:
    """Verify and return stable fingerprints for the two downloaded files."""
    manifest, manifest_bytes = _read_manifest(manifest_path)
    trusted_hex, key_file_bytes = _read_key(trusted_key_path)
    signature = manifest.get("signature")
    if not isinstance(signature, dict):
        raise VerificationError("manifest has no signature object")
    if signature.get("alg") != "ed25519":
        raise VerificationError("manifest signature algorithm is not ed25519")
    if str(signature.get("pubkey") or "").lower() != trusted_hex:
        raise VerificationError(
            "manifest public key does not match the separately trusted key"
        )
    try:
        signature_bytes = bytes.fromhex(str(signature["sig"]))
    except (KeyError, ValueError) as exc:
        raise VerificationError("manifest signature is missing or malformed") from exc
    if len(signature_bytes) != 64:
        raise VerificationError("Ed25519 signature must be 64 bytes")

    payload = json.dumps(
        {key: value for key, value in manifest.items() if key != "signature"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError as exc:
        raise VerificationError(
            "cryptography is required: python -m pip install cryptography"
        ) from exc
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted_hex)).verify(
            signature_bytes,
            payload,
        )
    except InvalidSignature as exc:
        raise VerificationError(
            "signature does not verify over the canonical manifest payload"
        ) from exc

    return {
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "trusted_key_file_sha256": hashlib.sha256(key_file_bytes).hexdigest(),
        "ed25519_key_fingerprint_sha256": hashlib.sha256(
            bytes.fromhex(trusted_hex)
        ).hexdigest(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("trusted_key", type=Path)
    args = parser.parse_args(argv)
    try:
        fingerprints = verify(args.manifest, args.trusted_key)
    except (OSError, VerificationError) as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    print("VERIFIED: Ed25519 signature matches the separately trusted key")
    for name, value in fingerprints.items():
        print(f"{name}: {value}")
    print(
        "Source-binding digests were not recomputed; that requires the "
        "licensed Lightwork source snapshot."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

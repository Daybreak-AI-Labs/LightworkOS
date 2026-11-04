"""Signed, machine-readable provenance manifests for AI-generated content.

The Art. 50(2) obligation (machine-readable marking of synthetic content,
applicable 2 Dec 2026) needs more than an embedded marker string: a
verifiable, tamper-evident statement binding exact content bytes to the
generating system. Each manifest is a bounded JSON claim — content digest,
generating asset, modality, optional delivery receipt — signed through the
platform's hash-chained Ed25519 audit signer into its OWN attestation ledger
(domain-separated from audit rows and assurance packs), and verified against
an EXTERNAL key registry, never a key the manifest carries about itself.

Sidecar-style by design: the manifest travels next to the content (an HTTP
header, an API field, a `.provenance.json` file). Embedding into media
containers (C2PA JUMBF boxes) is out of scope and stated so. Drafting and
marking assistance for the operator's own Art. 50 obligations — never a
certification and never a claim about content this platform did not sign.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from collections.abc import Mapping
from pathlib import Path
from typing import Any

MANIFEST_SCHEMA = "lightwork.content-credentials.v1"
MANIFEST_EVENT = "content_provenance_manifest"
REGULATION_METADATA = {
    "regulation": "Regulation (EU) 2024/1689",
    "citation": "Art. 50(2)",
    "applicable": "2026-12-02",
}
NON_CERTIFICATION_NOTICE = (
    "Machine-readable provenance for content this operator generated; not a "
    "content-authenticity certification and not a statement about any other "
    "content."
)

MODALITIES = ("text", "image", "audio", "video")
_MAX_CONTENT_BYTES = 32 * 1024 * 1024


class ContentProvenanceError(RuntimeError):
    """Base failure for governed content provenance."""


class ContentProvenanceConfigError(ContentProvenanceError):
    """The feature is not enabled or configured safely."""


def get_content_provenance_config() -> dict[str, Any]:
    from .config import load_global_config

    try:
        config = load_global_config()
    except Exception as exc:
        raise ContentProvenanceConfigError(
            "content_provenance configuration is unavailable"
        ) from exc
    section = (config or {}).get("content_provenance") or {}
    if not isinstance(section, dict):
        raise ContentProvenanceConfigError("content_provenance must be a table")
    flag = section.get("enable", False)
    if not isinstance(flag, bool):
        raise ContentProvenanceConfigError(
            "content_provenance.enable must be a boolean"
        )
    generator = str(section.get("claim_generator") or "Lightwork").strip()
    if not generator or len(generator) > 128:
        raise ContentProvenanceConfigError(
            "content_provenance.claim_generator must be a short name"
        )
    return {"enable": flag, "claim_generator": generator}


def enabled() -> bool:
    try:
        return get_content_provenance_config()["enable"] is True
    except Exception:
        return False


def _require_enabled() -> dict[str, Any]:
    settings = get_content_provenance_config()
    if settings["enable"] is not True:
        raise ContentProvenanceConfigError(
            "content provenance requires [content_provenance] enable = true"
        )
    return settings


def _attestation_path() -> Path:
    from .paths import data_dir

    return data_dir("content_provenance", "manifest_attestations.ndjson")


def _sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    ).hexdigest()


def _find_attestation(path: Path, attestation_id: str) -> dict[str, Any]:
    with path.open("rb") as handle:
        handle.seek(0, 2)
        size = handle.tell()
        handle.seek(max(0, size - 1024 * 1024))
        tail = handle.read()
    for raw_line in reversed(tail.splitlines()):
        try:
            row = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if row.get("attestation_id") == attestation_id:
            return row
    raise ContentProvenanceError(
        "signed provenance attestation could not be recovered"
    )


def create_manifest(
    content: bytes,
    *,
    asset_id: str,
    modality: str,
    actor: str,
    receipt_id: str | None = None,
) -> dict[str, Any]:
    """Sign one provenance manifest binding exact content bytes to an asset."""

    settings = _require_enabled()
    if not isinstance(content, (bytes, bytearray)) or not content:
        raise ValueError("content must be non-empty bytes")
    if len(content) > _MAX_CONTENT_BYTES:
        raise ValueError(
            f"content must be at most {_MAX_CONTENT_BYTES} bytes"
        )
    kind = str(modality or "").strip().lower()
    if kind not in MODALITIES:
        raise ValueError(f"modality must be one of: {', '.join(MODALITIES)}")
    asset = str(asset_id or "").strip()
    if not asset or len(asset) > 64:
        raise ValueError("asset_id must be a short identifier")
    operator = str(actor or "").strip()
    if not operator or len(operator) > 256:
        raise ValueError("actor must be a short identity")
    receipt = None if receipt_id is None else str(receipt_id).strip()
    if receipt is not None and (not receipt or len(receipt) > 128):
        raise ValueError("receipt_id must be a short identifier when given")

    from .audit import signing

    body = {
        "schema": MANIFEST_SCHEMA,
        "claim_generator": settings["claim_generator"],
        "asset_id": asset,
        "modality": kind,
        "content_sha256": hashlib.sha256(bytes(content)).hexdigest(),
        "content_length": len(content),
        "receipt_id": receipt,
        "generated_at": time.time(),
        "generated_by": operator,
        "regulation": dict(REGULATION_METADATA),
        "notice": NON_CERTIFICATION_NOTICE,
    }
    digest = _sha256(body)
    path = _attestation_path()
    signer = signing.AuditSigner(path)
    attestation_id = uuid.uuid4().hex
    event = {
        "v": 1,
        "event": MANIFEST_EVENT,
        "attestation_id": attestation_id,
        "actor": operator,
        "generated_at": body["generated_at"],
        "manifest_sha256": digest,
    }
    if not signer.write(event):
        raise ContentProvenanceError("audit signer refused the provenance manifest")
    receipt_row = _find_attestation(path, attestation_id)
    return {
        **body,
        "manifest_sha256": digest,
        "attestation": {
            "algorithm": "Ed25519",
            "key_id": receipt_row["key_id"],
            "public_key": signer.public_key_hex,
            "signature": receipt_row["sig"],
            "event_hash": receipt_row["hash"],
            "signed_message": "hex-decoded event_hash",
            "receipt": receipt_row,
        },
    }


def verify_manifest(
    manifest: Mapping[str, Any],
    *,
    trusted_pubkeys: Mapping[str, str] | None,
    content: bytes | None = None,
) -> bool:
    """Verify a manifest against an EXTERNAL key registry, never its own key.

    With ``content`` supplied, the exact bytes must also match the manifest's
    content digest. Returns False on any mismatch or malformed input.
    """

    try:
        from .audit.signing import verify_ed25519

        if not isinstance(manifest, Mapping) or not isinstance(
            trusted_pubkeys, Mapping
        ):
            return False
        body = dict(manifest)
        digest = body.pop("manifest_sha256", None)
        attestation = body.pop("attestation", None)
        if not isinstance(digest, str) or _sha256(body) != digest:
            return False
        if body.get("schema") != MANIFEST_SCHEMA:
            return False
        if not isinstance(attestation, Mapping):
            return False
        if (
            attestation.get("algorithm") != "Ed25519"
            or attestation.get("signed_message") != "hex-decoded event_hash"
        ):
            return False
        receipt = attestation.get("receipt")
        if not isinstance(receipt, Mapping):
            return False
        if (
            receipt.get("event") != MANIFEST_EVENT
            or receipt.get("manifest_sha256") != digest
            or receipt.get("sig") != attestation.get("signature")
            or receipt.get("hash") != attestation.get("event_hash")
        ):
            return False
        key_id = receipt.get("key_id")
        if not isinstance(key_id, str):
            return False
        trusted = trusted_pubkeys.get(key_id)
        disclosed = attestation.get("public_key")
        if not isinstance(trusted, str) or not isinstance(disclosed, str):
            return False
        trusted = trusted.strip().lower()
        key_bytes = bytes.fromhex(trusted)
        if len(key_bytes) != 32:
            return False
        if hashlib.sha256(key_bytes).hexdigest()[:16] != key_id:
            return False
        if not hmac.compare_digest(disclosed.strip().lower(), trusted):
            return False
        if attestation.get("key_id") != key_id:
            return False
        unsigned = {
            key: value
            for key, value in receipt.items()
            if key not in {"hash", "sig"}
        }
        row_hash = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, default=str).encode("utf-8"),
        ).hexdigest()
        if row_hash != receipt.get("hash"):
            return False
        if not verify_ed25519(trusted, str(receipt["sig"]), bytes.fromhex(row_hash)):
            return False
        if content is not None:
            actual = hashlib.sha256(bytes(content)).hexdigest()
            if actual != body.get("content_sha256"):
                return False
        return True
    except Exception:
        return False


__all__ = [
    "ContentProvenanceConfigError",
    "ContentProvenanceError",
    "MANIFEST_EVENT",
    "MANIFEST_SCHEMA",
    "MODALITIES",
    "NON_CERTIFICATION_NOTICE",
    "REGULATION_METADATA",
    "create_manifest",
    "enabled",
    "get_content_provenance_config",
    "verify_manifest",
]

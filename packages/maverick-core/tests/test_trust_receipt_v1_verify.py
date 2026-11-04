"""Portable Trust Receipt v1 verifier vectors and fail-closed boundaries."""
from __future__ import annotations

import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from maverick import trust_receipt_v1_verify as verifier
from maverick.trust_receipt_rekor import with_anchor_reference

VECTORS_PATH = Path(__file__).with_name("data") / "trust_receipt_v1_vectors.json"


@pytest.fixture(scope="module")
def vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def valid_envelope(vectors) -> dict:
    raw = next(
        item["envelope_json"]
        for item in vectors["vectors"]
        if item["name"] == "valid-canonical-ed25519-receipt"
    ).encode("utf-8")
    return verifier.parse_canonical_envelope(raw)


def test_published_vectors_cover_valid_and_tampered_envelopes(vectors):
    trusted = [vectors["trusted_public_key"]]
    for vector in vectors["vectors"]:
        envelope = verifier.parse_canonical_envelope(
            vector["envelope_json"].encode("utf-8")
        )
        result = verifier.verify_envelope(
            envelope,
            trusted_public_keys=trusted,
        )
        assert result.valid is vector["valid"], (vector["name"], result.reason)


def test_rfc8032_empty_message_vector_verifies(vectors):
    known = vectors["rfc8032_empty_message"]
    assert verifier.verify_ed25519(known["public_key"], known["signature"], b"")
    assert not verifier.verify_ed25519(
        known["public_key"], known["signature"][:-1] + "0", b"x"
    )


def test_second_rfc8032_vector_and_noncanonical_scalar_are_refused():
    public_key = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"  # pragma: allowlist secret
    signature = (
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"  # pragma: allowlist secret
        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"  # pragma: allowlist secret
    )
    assert verifier.verify_ed25519(public_key, signature, bytes.fromhex("72"))
    noncanonical_scalar = signature[:64] + (
        (2**252 + 27742317777372353535851937790883648493).to_bytes(
            32, "little"
        ).hex()
    )
    assert not verifier.verify_ed25519(
        public_key,
        noncanonical_scalar,
        bytes.fromhex("72"),
    )


def test_out_of_band_provenance_is_required(valid_envelope):
    result = verifier.verify_envelope(valid_envelope, trusted_public_keys=[])
    assert not result.valid
    assert "out-of-band" in result.reason


def test_canonical_loader_refuses_whitespace_and_duplicate_keys(vectors):
    raw = vectors["vectors"][0]["envelope_json"].encode("utf-8")
    with pytest.raises(verifier.ReceiptFormatError, match="canonical"):
        verifier.parse_canonical_envelope(raw + b"\n")
    with pytest.raises(verifier.ReceiptFormatError, match="duplicate"):
        verifier.parse_canonical_envelope(b'{"kind":"a","kind":"b"}')


def test_anchor_reference_without_external_verifier_is_never_anchored(
    valid_envelope, vectors
):
    digest = verifier.receipt_sha256(valid_envelope)
    anchored = with_anchor_reference(
        valid_envelope,
        {
            "type": "rekor",
            "receipt_sha256": digest,
            "entry_uuid": "example-entry",
            "log_id": "example-log",
            "log_index": 4,
            "integrated_time": 1_777_350_400,
            "verification": "external-required",
        },
    )
    result = verifier.verify_envelope(
        anchored,
        trusted_public_keys=[vectors["trusted_public_key"]],
    )
    assert result.valid
    assert not result.anchored
    assert "unverified" in result.reason


def test_injected_external_anchor_verifier_is_required_for_anchored_depth(
    valid_envelope, vectors
):
    digest = verifier.receipt_sha256(valid_envelope)
    anchored = with_anchor_reference(
        valid_envelope,
        {
            "type": "rekor",
            "receipt_sha256": digest,
            "entry_uuid": "example-entry",
            "log_id": "example-log",
            "log_index": 4,
            "integrated_time": 1_777_350_400,
            "verification": "external-required",
        },
    )

    def accepts(anchor, core):
        return anchor["receipt_sha256"] == hashlib.sha256(core).hexdigest()

    result = verifier.verify_envelope(
        anchored,
        trusted_public_keys=[vectors["trusted_public_key"]],
        anchor_verifier=accepts,
        require_anchor=True,
    )
    assert result.valid
    assert result.anchored


def test_require_anchor_fails_closed_without_an_external_verifier(
    valid_envelope, vectors
):
    result = verifier.verify_envelope(
        valid_envelope,
        trusted_public_keys=[vectors["trusted_public_key"]],
        require_anchor=True,
    )
    assert not result.valid
    assert "anchor" in result.reason


def test_verifier_source_has_no_maverick_or_third_party_imports():
    source = Path(verifier.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    stdlib = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots = [alias.name.split(".", 1)[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            roots = [node.module.split(".", 1)[0]] if node.module else []
        else:
            continue
        for root in roots:
            assert root in stdlib, f"non-stdlib import in auditor kit: {root}"
            assert root != "maverick"


def test_standalone_cli_runs_without_importing_maverick(tmp_path, vectors):
    receipt = tmp_path / "receipt-v1.json"
    receipt.write_text(vectors["vectors"][0]["envelope_json"], encoding="utf-8")
    completed = subprocess.run(
        [
            sys.executable,
            "-S",
            str(Path(verifier.__file__)),
            str(receipt),
            "--trusted-key",
            vectors["trusted_public_key"],
            "--json",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["valid"] is True

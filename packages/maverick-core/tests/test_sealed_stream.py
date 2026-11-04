"""Authenticated frame boundaries; never treat a suffix as whole-file proof."""
from __future__ import annotations

import io
import json
import struct

import pytest
from maverick import crypto_at_rest as crypto
from maverick.sealed_stream import (
    FRAME_SIZE,
    STREAM_MAGIC,
    FramedReader,
    SealedStreamError,
    decode_stream,
    encode_stream,
)


@pytest.fixture(autouse=True)
def keys(monkeypatch, tmp_path):
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "1")
    monkeypatch.setenv("MAVERICK_ENCRYPT_PER_TENANT", "0")
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", "11" * 32)
    monkeypatch.setattr(crypto, "_KEY_PATH", tmp_path / "fixture-at-rest.key")


@pytest.mark.parametrize("size", [0, 1, FRAME_SIZE, FRAME_SIZE + 37, FRAME_SIZE * 2 + 17])
def test_exact_roundtrip_and_independently_authenticated_last_frame(size):
    payload = (bytes(range(256)) * ((size + 255) // 256))[:size]
    encoded = b"".join(encode_stream(io.BytesIO(payload), crypto.seal))
    assert decode_stream(encoded, crypto.unseal) == payload
    calls = []
    def decrypt(blob):
        calls.append(len(blob))
        return crypto.unseal(blob)
    reader = FramedReader(io.BytesIO(encoded), decrypt)
    if size:
        assert reader.read_frame(reader.count - 1) == payload[(reader.count - 1) * FRAME_SIZE:]
        assert len(calls) == 2  # authenticated manifest and exactly one frame
    else:
        assert list(reader.iter_chunks()) == []
        assert len(calls) == 1


def test_truncation_and_append_rejected_before_returning_plaintext():
    raw = b"".join(encode_stream(io.BytesIO(b"x" * (FRAME_SIZE + 1)), crypto.seal))
    for corrupt in (raw[:-1], raw + b"x", raw[:20]):
        with pytest.raises((SealedStreamError, crypto.EncryptionUnavailable)):
            FramedReader(io.BytesIO(corrupt), crypto.unseal)


def test_frame_tampering_and_reordering_refused():
    raw = b"".join(encode_stream(io.BytesIO(b"x" * (FRAME_SIZE * 2)), crypto.seal))
    reader = FramedReader(io.BytesIO(raw), crypto.unseal)
    changed = bytearray(raw)
    changed[reader.start + reader.stride + 30] ^= 1
    frames = FramedReader(io.BytesIO(changed), crypto.unseal).iter_chunks()
    assert next(frames) == b"x" * FRAME_SIZE  # only a fully authenticated prefix
    with pytest.raises(crypto.EncryptionUnavailable):
        next(frames)
    start, stride = reader.start, reader.stride
    reordered = raw[:start] + raw[start + stride:] + raw[start:start + stride]
    with pytest.raises(SealedStreamError, match="identity or sequence"):
        decode_stream(reordered, crypto.unseal)


def test_plaintext_and_nested_manifest_envelopes_refused():
    for unsealed in (b'{"version":1}', STREAM_MAGIC + b"fake"):
        raw = STREAM_MAGIC + struct.pack(">I", len(unsealed)) + unsealed
        with pytest.raises(SealedStreamError, match="manifest"):
            FramedReader(io.BytesIO(raw), crypto.unseal)


def test_encoder_retains_original_bytes_when_source_changes_after_read():
    source = io.BytesIO(b"original")
    def changing_encrypt(payload):
        if payload.startswith(b"ASF1"):
            source.seek(0)
            source.write(b"mutated!")
            source.seek(8)
        return crypto.seal(payload)
    # The encrypted frame still contains the exact originally hashed bytes.
    # Concurrent same-sized mutations require caller-owned snapshot fencing;
    # this helper does not claim to detect bytes changed after they were read.
    encoded = b"".join(encode_stream(source, changing_encrypt))
    assert decode_stream(encoded, crypto.unseal) == b"original"


def test_missing_key_and_cross_file_frame_substitution_fail(monkeypatch):
    raw = b"".join(encode_stream(io.BytesIO(b"a" * FRAME_SIZE), crypto.seal))
    other = b"".join(encode_stream(io.BytesIO(b"b" * FRAME_SIZE), crypto.seal))
    first = FramedReader(io.BytesIO(raw), crypto.unseal)
    second = FramedReader(io.BytesIO(other), crypto.unseal)
    mixed = raw[:first.start] + other[second.start:]
    with pytest.raises(SealedStreamError, match="identity or sequence"):
        decode_stream(mixed, crypto.unseal)
    monkeypatch.setenv("MAVERICK_ENCRYPTION_KEY", "22" * 32)
    with pytest.raises(crypto.EncryptionUnavailable):
        decode_stream(raw, crypto.unseal)


def _manifest_changed(raw, change):
    start = len(STREAM_MAGIC)
    length = struct.unpack(">I", raw[start:start + 4])[0]
    body = json.loads(crypto.unseal(raw[start + 4:start + 4 + length]))
    change(body)
    replacement = crypto.seal(json.dumps(body, sort_keys=True, separators=(",", ":")).encode())
    return STREAM_MAGIC + struct.pack(">I", len(replacement)) + replacement + raw[start + 4 + length:]


@pytest.mark.parametrize("key,value", [("size", -1), ("size", 1024 ** 4 + 1), ("count", True), ("stride", 999999999), ("frame_size", 1), ("id", "00"), ("count", 2)])
def test_authenticated_but_invalid_manifest_dimensions_refused(key, value):
    raw = b"".join(encode_stream(io.BytesIO(b"data"), crypto.seal))
    changed = _manifest_changed(raw, lambda manifest: manifest.update({key: value}))
    with pytest.raises(SealedStreamError):
        decode_stream(changed, crypto.unseal)


def test_whole_stream_digest_mismatch_fails_compat_decode():
    raw = b"".join(encode_stream(io.BytesIO(b"data"), crypto.seal))
    changed = _manifest_changed(raw, lambda manifest: manifest.update(sha256="0" * 64))
    # Suffix authentication isn't whole-segment authentication.
    assert FramedReader(io.BytesIO(changed), crypto.unseal).read_frame(0) == b"data"
    with pytest.raises(SealedStreamError, match="digest"):
        decode_stream(changed, crypto.unseal)


@pytest.mark.parametrize("index", [-1, True, 1, 2 ** 64])
def test_frame_index_bounds(index):
    raw = b"".join(encode_stream(io.BytesIO(b"data"), crypto.seal))
    with pytest.raises(ValueError, match="index"):
        FramedReader(io.BytesIO(raw), crypto.unseal).read_frame(index)


def test_source_changed_between_hash_and_frame_pass_is_not_published():
    class ChangingSource(io.BytesIO):
        starts = 0

        def seek(self, offset, whence=0):
            if offset == 0 and whence == 0:
                self.starts += 1
                if self.starts == 2:
                    super().seek(0)
                    self.write(b"mutated!")
            return super().seek(offset, whence)

    with pytest.raises(SealedStreamError, match="source changed"):
        b"".join(encode_stream(ChangingSource(b"original"), crypto.seal))

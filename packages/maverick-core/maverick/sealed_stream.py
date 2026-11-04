"""Authenticated fixed-frame container for bounded encrypted audit reads.

Signed evidence bytes are opaque here. Each independently authenticated frame
binds its stream identity and sequence; the encrypted manifest binds total
length, framing and the complete plaintext digest. Ordinary seal envelopes and
their existing tenant/key custody remain responsible for encryption.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import secrets
import struct
from collections.abc import Callable, Iterator
from typing import BinaryIO

STREAM_MAGIC = b"MVKASF1\n"
FRAME_SIZE = 1024 * 1024
_FRAME_MAGIC = b"ASF1"
_FRAME_PREFIX_SIZE = 4 + 16 + 8
_MAX_MANIFEST = 4096
_MAX_SOURCE = 1024 ** 4
_ENVELOPES = (b"MVKAR1\n", b"MVKAR2\n", b"MVKTEN1\n")


class SealedStreamError(ValueError):
    """A framed segment is malformed, incomplete or has mismatched content."""


def _exact(source: BinaryIO, count: int) -> bytes:
    parts, remaining = [], count
    while remaining:
        value = source.read(remaining)
        if not value:
            raise SealedStreamError("sealed segment is truncated")
        parts.append(value)
        remaining -= len(value)
    return b"".join(parts)


def _inner(blob: bytes, decrypt: Callable[[bytes], bytes]) -> bytes:
    if not blob.startswith(_ENVELOPES):
        raise SealedStreamError("sealed segment requires an authenticated inner envelope")
    return decrypt(blob)


class FramedReader:
    """Read authenticated frames from one already-custodied, seekable handle."""

    def __init__(self, source: BinaryIO, decrypt: Callable[[bytes], bytes]):
        self.source, self.decrypt = source, decrypt
        physical = source.seek(0, io.SEEK_END)
        source.seek(0)
        if _exact(source, len(STREAM_MAGIC)) != STREAM_MAGIC:
            raise SealedStreamError("unsupported sealed segment header")
        manifest_length = struct.unpack(">I", _exact(source, 4))[0]
        if not 1 <= manifest_length <= _MAX_MANIFEST:
            raise SealedStreamError("sealed segment manifest exceeds its bound")
        try:
            manifest = json.loads(_inner(_exact(source, manifest_length), decrypt))
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise SealedStreamError("sealed segment manifest is invalid") from exc
        if not isinstance(manifest, dict) or set(manifest) != {
            "version", "id", "size", "count", "frame_size", "stride", "sha256",
        }:
            raise SealedStreamError("sealed segment manifest shape is invalid")
        for name in ("version", "size", "count", "frame_size", "stride"):
            if type(manifest[name]) is not int:
                raise SealedStreamError("sealed segment manifest dimensions are invalid")
        if (manifest["version"] != 1 or manifest["frame_size"] != FRAME_SIZE
                or not 0 <= manifest["size"] <= _MAX_SOURCE
                or not isinstance(manifest["id"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", manifest["id"])
                or not isinstance(manifest["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"])):
            raise SealedStreamError("sealed segment manifest dimensions are invalid")
        self.size, self.count, self.stride = manifest["size"], manifest["count"], manifest["stride"]
        if self.count != (self.size + FRAME_SIZE - 1) // FRAME_SIZE:
            raise SealedStreamError("sealed segment frame count is inconsistent")
        self.start = source.tell()
        self.stream_id, self.digest = bytes.fromhex(manifest["id"]), manifest["sha256"]
        if self.count:
            overhead = self.stride - 4 - _FRAME_PREFIX_SIZE - min(self.size, FRAME_SIZE)
            if not 32 <= overhead <= 256:
                raise SealedStreamError("sealed segment frame stride is invalid")
            last_size = self.size - (self.count - 1) * FRAME_SIZE
            expected = self.start + self.count * self.stride - (min(self.size, FRAME_SIZE) - last_size)
        else:
            if self.stride != 0:
                raise SealedStreamError("empty sealed segment has unexpected frames")
            expected = self.start
        if physical != expected:
            raise SealedStreamError("sealed segment physical length does not match its authenticated manifest")

    def read_frame(self, index: int) -> bytes:
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < self.count:
            raise ValueError("sealed segment frame index is invalid")
        self.source.seek(self.start + index * self.stride)
        length = struct.unpack(">I", _exact(self.source, 4))[0]
        expected_plain = min(FRAME_SIZE, self.size - index * FRAME_SIZE)
        expected_sealed = self.stride - 4 - (min(self.size, FRAME_SIZE) - expected_plain)
        if length != expected_sealed or not 1 <= length <= FRAME_SIZE + _FRAME_PREFIX_SIZE + 256:
            raise SealedStreamError("sealed segment frame length is invalid")
        plain = _inner(_exact(self.source, length), self.decrypt)
        prefix = _FRAME_MAGIC + self.stream_id + struct.pack(">Q", index)
        if len(plain) != _FRAME_PREFIX_SIZE + expected_plain or not plain.startswith(prefix):
            raise SealedStreamError("sealed segment frame identity or sequence is invalid")
        return plain[_FRAME_PREFIX_SIZE:]

    def iter_chunks(self) -> Iterator[bytes]:
        digest = hashlib.sha256()
        for index in range(self.count):
            chunk = self.read_frame(index)
            digest.update(chunk)
            yield chunk
        if digest.hexdigest() != self.digest:
            raise SealedStreamError("sealed segment plaintext digest is invalid")


def decode_stream(blob: bytes, decrypt: Callable[[bytes], bytes]) -> bytes:
    """Compatibility decode; streaming consumers should use FramedReader."""
    return b"".join(FramedReader(io.BytesIO(blob), decrypt).iter_chunks())


def encode_stream(source: BinaryIO, encrypt: Callable[[bytes], bytes]) -> Iterator[bytes]:
    """Two bounded passes; caller owns source stability and atomic publication."""
    size = source.seek(0, io.SEEK_END)
    if not 0 <= size <= _MAX_SOURCE:
        raise SealedStreamError("source exceeds the sealed segment byte bound")
    source.seek(0)
    digest, remaining = hashlib.sha256(), size
    while remaining:
        chunk = _exact(source, min(FRAME_SIZE, remaining))
        digest.update(chunk)
        remaining -= len(chunk)
    if source.read(1):
        raise SealedStreamError("source grew during sealed segment preparation")
    source.seek(0)
    stream_id = secrets.token_bytes(16)
    count = (size + FRAME_SIZE - 1) // FRAME_SIZE
    first, first_payload = b"", b""
    if count:
        first_payload = _exact(source, min(size, FRAME_SIZE))
        first = encrypt(_FRAME_MAGIC + stream_id + struct.pack(">Q", 0) + first_payload)
    stride = len(first) + 4 if count else 0
    manifest = {"version": 1, "id": stream_id.hex(), "size": size, "count": count,
                "frame_size": FRAME_SIZE, "stride": stride, "sha256": digest.hexdigest()}
    sealed_manifest = encrypt(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())
    if not sealed_manifest.startswith(_ENVELOPES) or len(sealed_manifest) > _MAX_MANIFEST:
        raise SealedStreamError("manifest encryption did not produce a bounded envelope")
    yield STREAM_MAGIC + struct.pack(">I", len(sealed_manifest)) + sealed_manifest
    confirmed = hashlib.sha256()
    for index in range(count):
        payload = first_payload if index == 0 else _exact(source, min(FRAME_SIZE, size - index * FRAME_SIZE))
        confirmed.update(payload)
        sealed = first if index == 0 else encrypt(_FRAME_MAGIC + stream_id + struct.pack(">Q", index) + payload)
        expected = stride - 4 - (min(size, FRAME_SIZE) - len(payload))
        if not sealed.startswith(_ENVELOPES) or len(sealed) != expected:
            raise SealedStreamError("encryption envelope changed during sealed segment publication")
        yield struct.pack(">I", len(sealed)) + sealed
    if source.read(1) or confirmed.digest() != digest.digest():
        raise SealedStreamError("source changed during sealed segment publication")

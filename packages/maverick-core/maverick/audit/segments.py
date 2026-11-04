"""Bounded snapshot readers; read coverage is separate from evidence assurance."""
from __future__ import annotations

import hashlib
import io
import os
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from ..crypto_at_rest import is_sealed, unseal
from ..file_lock import open_private_read
from ..paths import current_tenant_id, reset_tenant, set_tenant
from ..sealed_stream import FRAME_SIZE, STREAM_MAGIC, FramedReader

READ_CHUNK = 64 * 1024
MAX_LINE = 4 * 1024 * 1024
MAX_TAIL_BYTES = 16 * 1024 * 1024


class SegmentReadError(RuntimeError):
    """An audit snapshot is unreadable, changed, incomplete or outside bounds."""


@dataclass
class ReadReport:
    """Coverage of the selected snapshot, never an implicit checkpoint proof."""

    scope: str = "selected_segments"
    finished: bool = False
    segments: int = 0
    completed_segments: int = 0
    events: int = 0
    failures: int = 0
    bytes_read: int = 0
    legacy_whole_blob: bool = False
    verification: str = "not_requested"
    diagnostics: list[dict] = field(default_factory=list)

    def problem(self, path: Path, reason: str, line: int | None = None) -> None:
        self.failures += 1
        if len(self.diagnostics) < 64:
            self.diagnostics.append({"segment": path.name, "reason": reason, "line": line})

    @property
    def state(self) -> str:
        if not self.finished:
            return "partial"
        if self.failures:
            return "partial" if self.events or self.completed_segments else "unreadable"
        if not self.events:
            return "empty"
        if self.verification == "segment_chains_verified":
            return "verified_complete"
        return "readable_complete"

    def as_dict(self) -> dict:
        return {
            "state": self.state, "scope": self.scope,
            "segments": self.segments, "completed_segments": self.completed_segments,
            "events": self.events, "failures": self.failures, "bytes_read": self.bytes_read,
            "legacy_whole_blob": self.legacy_whole_blob, "verification": self.verification,
            "anchors": "not_verified", "checkpoints": "not_verified",
            "diagnostics": list(self.diagnostics),
        }


class _CountedSource:
    def __init__(self, source, report):
        self.source, self.report = source, report

    def read(self, size=-1):
        data = self.source.read(size)
        self.report.bytes_read += len(data)
        return data

    def seek(self, *args):
        return self.source.seek(*args)

    def tell(self):
        return self.source.tell()


class SegmentSnapshot:
    """One private descriptor and fixed size; rewrites fail instead of mixing files."""

    def __init__(self, path: Path, report: ReadReport, *, tenant: str | None = None):
        self.path, self.report = Path(path), report
        self.tenant = tenant if tenant is not None else current_tenant_id()
        self._digest = None
        self.source = os.fdopen(open_private_read(path), "rb")
        try:
            self.initial = os.fstat(self.source.fileno())
            magic = self.source.read(8)
            report.bytes_read += len(magic)
            self.source.seek(0)
            self.frames = None
            self.legacy = None
            if magic.startswith(STREAM_MAGIC):
                self.frames = FramedReader(_CountedSource(self.source, report), self._decrypt)
                self.size = self.frames.size
            elif is_sealed(magic):
                # Legacy monolithic AEAD must authenticate in full before any
                # plaintext is returned. Its compatibility cost is explicit.
                raw = self.source.read()
                report.bytes_read += len(raw)
                report.legacy_whole_blob = True
                self.legacy = self._decrypt(raw)
                self.size = len(self.legacy)
            else:
                self.size = self.initial.st_size
        except BaseException:  # failure-policy: fail_closed
            self.source.close()
            raise

    def _decrypt(self, blob: bytes) -> bytes:
        token = set_tenant(self.tenant)
        try:
            return unseal(blob)
        finally:
            reset_tenant(token)

    def validate(self, *, allow_append: bool = False) -> None:
        opened, visible = os.fstat(self.source.fileno()), self.path.lstat()
        identity = (self.initial.st_dev, self.initial.st_ino)
        unchanged = (opened.st_size == self.initial.st_size
                     and opened.st_mtime_ns == self.initial.st_mtime_ns)
        # A full read (verification, export) must be the whole segment, so any
        # append is a change. A tail reads no byte past the initial size, and
        # the writer only appends to the active segment: a concurrent append
        # (same file, grown) leaves everything it read intact. A rewrite (new
        # inode) or truncation still fails either read.
        appended = allow_append and opened.st_size > self.initial.st_size
        if ((opened.st_dev, opened.st_ino) != identity
                or (visible.st_dev, visible.st_ino) != identity
                or not (unchanged or appended)):
            raise SegmentReadError("audit segment changed during snapshot read")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.source.close()

    def chunks(self) -> Iterator[bytes]:
        digest = hashlib.sha256()
        for chunk in self._chunks():
            digest.update(chunk)
            yield chunk
        self.validate()
        current = digest.digest()
        if self._digest is not None and current != self._digest:
            raise SegmentReadError("audit bytes changed between verification and export")
        self._digest = current

    def _chunks(self) -> Iterator[bytes]:
        if self.frames is not None:
            yield from self.frames.iter_chunks()
        elif self.legacy is not None:
            for offset in range(0, len(self.legacy), READ_CHUNK):
                yield self.legacy[offset:offset + READ_CHUNK]
        else:
            self.source.seek(0)
            remaining = self.size
            while remaining:
                chunk = self.source.read(min(READ_CHUNK, remaining))
                self.report.bytes_read += len(chunk)
                if not chunk:
                    raise SegmentReadError("audit segment was truncated")
                remaining -= len(chunk)
                yield chunk

    def lines(self) -> Iterator[str]:
        pending = b""
        for chunk in self.chunks():
            parts = (pending + chunk).split(b"\n")
            pending = parts.pop()
            for line in parts:
                if len(line) > MAX_LINE:
                    raise SegmentReadError("audit row exceeds the read byte bound")
                yield (line + b"\n").decode("utf-8")
            if len(pending) > MAX_LINE:
                raise SegmentReadError("audit row exceeds the read byte bound")
        if pending:
            raise SegmentReadError("audit segment ends with an incomplete row")

    def tail_lines(self, n: int) -> list[str]:
        if not 0 <= n <= 10000:
            raise ValueError("audit tail size must be between 0 and 10000")
        if n == 0 or self.size == 0:
            self.validate()
            return []
        suffix, end = b"", self.size
        while end and suffix.count(b"\n") <= n:
            if len(suffix) >= MAX_TAIL_BYTES:
                raise SegmentReadError("audit tail exceeds its suffix byte bound")
            if self.frames is not None:
                index = (end - 1) // FRAME_SIZE
                chunk = self.frames.read_frame(index)
                end = index * FRAME_SIZE
            else:
                start = max(0, end - READ_CHUNK)
                if self.legacy is not None:
                    chunk = self.legacy[start:end]
                else:
                    self.source.seek(start)
                    chunk = self.source.read(end - start)
                    self.report.bytes_read += len(chunk)
                    if len(chunk) != end - start:
                        raise SegmentReadError("audit segment was truncated")
                end = start
            suffix = chunk + suffix
        self.validate(allow_append=True)
        if not suffix.endswith(b"\n"):
            self.report.problem(self.path, "incomplete_final_row")
            suffix = suffix.rpartition(b"\n")[0] + b"\n" if b"\n" in suffix else b""
        lines = suffix.split(b"\n")[:-1]
        if end:
            lines = lines[1:]  # suffix starts within an older row
        result = lines[-n:]
        if any(len(line) > MAX_LINE for line in result):
            raise SegmentReadError("audit row exceeds the read byte bound")
        return [line.decode("utf-8") for line in result]


def sealed_bytes(text: str) -> bytes:
    """Compatibility for intentional whole-segment rewrites, e.g. erasure."""
    from ..crypto_at_rest import seal
    from ..sealed_stream import encode_stream

    return b"".join(encode_stream(io.BytesIO(text.encode("utf-8")), seal))

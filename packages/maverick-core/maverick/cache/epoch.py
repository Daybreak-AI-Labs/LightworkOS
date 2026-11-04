"""Shared cache generations; unreachable coordination always means a cache miss."""
from __future__ import annotations

import os
import tempfile
import uuid
from pathlib import Path

from ..paths import data_dir


def local_epoch(*, advance: bool = False) -> str | None:
    """Readers create a generation; writes rotate it only once caching is active."""
    path = data_dir("tool_cache_epoch")
    try:
        # A reader publishes the first generation before executing its read.
        # If no reader has done so, there is no result or in-flight read to
        # invalidate. Avoid durable cache writes on the default uncached path.
        if advance and not path.exists():
            return None
        path.parent.mkdir(parents=True, exist_ok=True)
        if not advance:
            try:
                token = path.read_text(encoding="ascii").strip()
                return token if len(token) == 32 and all(c in "0123456789abcdef" for c in token) else None
            except FileNotFoundError:
                token = uuid.uuid4().hex
                try:
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                except FileExistsError:
                    return local_epoch()
                with os.fdopen(fd, "w", encoding="ascii") as stream:
                    stream.write(token)
                    stream.flush()
                    os.fsync(stream.fileno())
                return token
        token = uuid.uuid4().hex
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="ascii", dir=path.parent, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(token)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return token
    except (OSError, UnicodeError):
        return None

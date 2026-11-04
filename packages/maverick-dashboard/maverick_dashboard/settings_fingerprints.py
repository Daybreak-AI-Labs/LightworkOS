"""Fingerprints for the ``fingerprint`` control on Settings > All settings.

A pinned program or file is trusted only while its fingerprint matches. The
page never asks anyone to type one: the person uploads the file (the server
works out its fingerprint as it arrives and keeps nothing), or, for a
fingerprint of files already installed with Lightwork, asks the server to work
it out from what is installed here -- with exactly the function the kernel
uses to check it later, so the pin always matches what the check computes.
"""
from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from pathlib import Path

# The kernel refuses to check program files larger than this.
MAX_UPLOAD_BYTES = 536_870_912


class Refused(ValueError):
    """A fingerprint that can't be worked out (plain sentence)."""


async def of_upload(chunks: AsyncIterator[bytes]) -> str:
    """The SHA-256 of an uploaded file, read as it arrives (nothing is stored)."""
    digest = hashlib.sha256()
    size = 0
    async for chunk in chunks:
        size += len(chunk)
        if size > MAX_UPLOAD_BYTES:
            raise Refused("That file is too large. Lightwork checks files up to 512 MB.")
        digest.update(chunk)
    if size == 0:
        raise Refused("That file is empty. Choose the program or file itself.")
    return digest.hexdigest()


def _installed_manifest(distribution: str) -> str:
    from maverick.ai_evidence_local_parsers import _distribution_manifest_sha256

    return _distribution_manifest_sha256(distribution)


def _library_manifest() -> str:
    from maverick.ai_evidence_local_parsers import _manifest_sha256
    from maverick.config import load_config

    ocr = (((load_config() or {}).get("ai_evidence_analysis") or {}).get("ocr") or {})
    paths = ocr.get("runtime_library_paths") if isinstance(ocr, dict) else None
    if not isinstance(paths, list) or not paths or \
            not all(isinstance(p, str) and p for p in paths):
        raise Refused("Save the program library locations first, then work out their "
                      "fingerprint.")
    return _manifest_sha256([Path(p) for p in paths], "OCR runtime libraries")


# What the server can work a fingerprint out from (``Setting.fingerprint_of``).
SERVER_SOURCES = {
    "pillow": lambda: _installed_manifest("Pillow"),
    "xlrd": lambda: _installed_manifest("xlrd"),
    "olefile": lambda: _installed_manifest("olefile"),
    "ocr_libraries": _library_manifest,
}


def of_server(source: str) -> str:
    """Work a fingerprint out from what is installed on this server."""
    compute = SERVER_SOURCES.get(source)
    if compute is None:
        raise Refused("This fingerprint can only be worked out from an uploaded file.")
    try:
        return compute()
    except Refused:
        raise
    except Exception as exc:  # noqa: BLE001 -- missing package or unreadable file
        raise Refused("Lightwork could not read those files on this server. Check that "
                      "they are installed, then try again.") from exc


def shown(fingerprint: str) -> str:
    """The first part of a fingerprint, grouped for reading aloud."""
    text = fingerprint.upper()
    return " ".join(text[i:i + 4] for i in range(0, 16, 4)) + " …"


__all__ = ["MAX_UPLOAD_BYTES", "Refused", "SERVER_SOURCES", "of_server", "of_upload", "shown"]

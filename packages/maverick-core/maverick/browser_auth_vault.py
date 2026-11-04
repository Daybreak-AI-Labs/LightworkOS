"""Browser auth vault: encrypted-at-rest storage for browser sessions/credentials.

A long-running agent that logs into sites needs somewhere safe to keep session
cookies / tokens between runs. This is an encrypted local vault: each named entry
(a dict of cookies / storage_state / credentials) is sealed with Fernet
(AES-128-CBC + HMAC) under a key that lives only in a ``0600`` key file (or the
``MAVERICK_VAULT_KEY`` env var), never in the data file. The data file holds only
ciphertext, so it's safe to sync/back up.

``encrypt_entry`` / ``decrypt_entry`` / ``Vault`` take an explicit key so they're
unit-testable; the ``browser_auth_vault`` tool resolves the key from the key file.
Requires the ``cryptography`` extra (``python -m pip install -e './packages/maverick-core[audit-signing]'``);
the tool degrades with an actionable error when it's missing.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path

from .file_lock import (
    atomic_create_bytes,
    atomic_read_bytes,
    atomic_read_text,
    atomic_write_bytes,
    cross_process_lock,
    ensure_private_directory,
    ensure_private_file,
    require_private_directory,
)
from .paths import current_tenant_id, data_dir

# Serializes the read-modify-write in store()/delete() so concurrent writers to
# the shared vault file can't clobber each other's entries (last os.replace won).
_VAULT_LOCK = threading.Lock()


def _authority_id(tenant: str | None, principal: str | None) -> str:
    """Opaque path tag for the exact tenant/client + principal authority."""
    # Do not strip/case-fold either identity. Authentication treats principal
    # strings as bounded opaque values, so normalisation here would collapse
    # distinct authorities onto one credential store.
    encoded = json.dumps(
        {
            "version": 1,
            "tenant": tenant,
            "principal": principal,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(b"maverick:browser-vault:authority:\0" + encoded).hexdigest()


def _default_store() -> Path:
    """Resolve the active authority's vault directory at call time.

    The tenant is already represented by :func:`data_dir`; the authority hash
    is still tenant-inclusive so a future explicit/shared storage backend
    cannot silently collapse two tenants. The legacy unbound/local authority
    keeps its historical location for single-user compatibility.
    """
    from .connections import current_principal

    tenant = current_tenant_id()
    principal = current_principal()
    # Pass the captured raw tenant explicitly rather than resolving active
    # context a second time inside data_dir().
    base = data_dir("vault", tenant=tenant or None)
    if principal is None:
        return base
    return base / "authorities" / _authority_id(tenant, principal)


def _default_paths() -> tuple[Path, Path]:
    store = _default_store()
    return store / "key", store / "browser.json"


def _require_fernet():
    try:
        from cryptography.fernet import Fernet
    except ImportError as e:  # knob exemption: optional dep
        raise RuntimeError(
            "browser auth vault needs the 'cryptography' package. Install it "
            "with: python -m pip install -e './packages/maverick-core[audit-signing]'") from e
    return Fernet


def generate_key() -> bytes:
    """A fresh url-safe base64 Fernet key."""
    return _require_fernet().generate_key()


def encrypt_entry(key: bytes, data: dict) -> str:
    """Seal ``data`` (a JSON-able dict) into a Fernet token string."""
    Fernet = _require_fernet()
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return Fernet(key).encrypt(payload).decode("ascii")


def decrypt_entry(key: bytes, token: str) -> dict:
    """Open a Fernet token back into a dict. Raises on a wrong/forged key."""
    Fernet = _require_fernet()
    from cryptography.fernet import InvalidToken
    try:
        raw = Fernet(key).decrypt(token.encode("ascii"))
    except InvalidToken as e:
        raise ValueError("cannot decrypt entry: wrong key or corrupted data") from e
    return json.loads(raw.decode("utf-8"))


class Vault:
    """A file-backed map of name -> encrypted entry, sealed under ``key``."""

    def __init__(
        self,
        key: bytes,
        path: str | Path,
        *,
        _owned_parent: bool = False,
    ):
        self.key = key
        self.path = Path(path)
        self._owned_parent = bool(_owned_parent)

    def _prepare_parent(self) -> None:
        if self._owned_parent or not self.path.parent.exists():
            ensure_private_directory(self.path.parent)
        else:
            require_private_directory(self.path.parent)

    def _read(self) -> dict[str, str]:
        self._prepare_parent()
        if not self.path.exists():
            return {}
        ensure_private_file(self.path)
        try:
            data = json.loads(atomic_read_text(self.path, encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError as e:
            # Do NOT silently return {}: a single corrupt/truncated byte would
            # drop the entire encrypted entry map, and the next store() would
            # overwrite the file with only the new entry -- destroying every
            # other credential. Surface the corruption instead.
            raise RuntimeError(
                f"vault file {self.path} is corrupt (invalid JSON); "
                "refusing to read (would risk overwriting all entries)"
            ) from e

    def _write(self, blob: dict[str, str]) -> None:
        self._prepare_parent()
        data = json.dumps(blob, indent=2).encode("utf-8")
        # Unique private temp + atomic publication avoids the fixed ``.tmp``
        # race and applies a protected Windows DACL before any metadata exists.
        atomic_write_bytes(self.path, data)

    def store(self, name: str, data: dict) -> None:
        with _VAULT_LOCK:
            self._prepare_parent()
            with cross_process_lock(self.path, strict=True):
                blob = self._read()
                blob[name] = encrypt_entry(self.key, data)
                self._write(blob)

    def load(self, name: str) -> dict:
        blob = self._read()
        if name not in blob:
            raise KeyError(f"no vault entry named {name!r}")
        return decrypt_entry(self.key, blob[name])

    def list_entries(self) -> list[str]:
        return sorted(self._read())

    def delete(self, name: str) -> bool:
        with _VAULT_LOCK:
            self._prepare_parent()
            with cross_process_lock(self.path, strict=True):
                blob = self._read()
                if name not in blob:
                    return False
                del blob[name]
                self._write(blob)
                return True


def _resolve_key(key_file: Path, *, owned_parent: bool) -> bytes:
    """Resolve one already-authority-bound key path."""
    env = os.environ.get("MAVERICK_VAULT_KEY", "").strip()
    if env:
        return env.encode("ascii")
    if owned_parent or not key_file.parent.exists():
        # The default authority directory (or a missing directory created here)
        # is Lightwork-owned and may be tightened.
        ensure_private_directory(key_file.parent)
    else:
        # An injected key path is an integrity boundary. Verify its parent but
        # never revoke permissions on an arbitrary caller-owned directory.
        require_private_directory(key_file.parent)
    if key_file.exists():
        ensure_private_file(key_file)
        return atomic_read_bytes(key_file).strip()
    key = generate_key()
    try:
        atomic_create_bytes(key_file, key)
    except FileExistsError:  # lost a create race — read the winner's key
        ensure_private_file(key_file)
        return atomic_read_bytes(key_file).strip()
    return key


def resolve_key(key_file: Path | None = None) -> bytes:
    """Key from ``MAVERICK_VAULT_KEY``, else a ``0600`` key file (created once).

    The key file is created **atomically** with ``O_CREAT|O_EXCL`` and mode
    ``0600`` so the secret never exists, even briefly, with default-umask
    permissions (a write-then-chmod leaves a TOCTOU window where it's
    group/world-readable). When omitted, ``key_file`` is resolved for the
    active tenant/client and exact principal at call time; no default argument
    can freeze a previous tenant's path in a long-lived process.
    """
    if key_file is None:
        default_key, _ = _default_paths()
        return _resolve_key(default_key, owned_parent=True)
    return _resolve_key(Path(key_file), owned_parent=False)


_SCHEMA = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["store", "load", "list", "delete"]},
        "name": {"type": "string", "description": "entry name (e.g. 'github')"},
        "data": {"type": "object",
                 "description": "session/credential dict to seal (store op)"},
    },
    "required": ["op"],
}


def _run(args: dict) -> str:
    op = args.get("op")
    try:
        key_file, data_file = _default_paths()
        # Resolve both paths from one captured authority and mark the dedicated
        # directory private before either key or encrypted metadata exists.
        ensure_private_directory(key_file.parent)
        key = _resolve_key(key_file, owned_parent=True)
    except RuntimeError as e:
        return f"ERROR: {e}"
    except (OSError, UnicodeError, ValueError):
        # Path/ACL details are host metadata; do not reflect them through a
        # remotely callable tool response.
        return "ERROR: browser auth vault storage is unavailable"
    vault = Vault(key, data_file, _owned_parent=True)
    name = args.get("name") or ""
    try:
        if op == "store":
            if not name:
                return "ERROR: store requires a name"
            vault.store(name, args.get("data") or {})
            return f"sealed entry {name!r}"
        if op == "load":
            data = vault.load(name)
            # Don't echo secrets back verbatim; report shape only.
            return (f"loaded {name!r}: {len(data)} field(s) "
                    f"({', '.join(sorted(data)[:10])})")
        if op == "list":
            entries = vault.list_entries()
            return "\n".join(entries) if entries else "(vault empty)"
        if op == "delete":
            return f"deleted {name!r}" if vault.delete(name) else f"no entry {name!r}"
    except (KeyError, ValueError, RuntimeError) as e:
        return f"ERROR: {e}"
    return f"ERROR: unknown op {op!r}"


def browser_auth_vault():
    from .tools import Tool
    return Tool(
        name="browser_auth_vault",
        description=(
            "Encrypted-at-rest vault for browser sessions / credentials. ops: "
            "store (name, data), load (name) -> field shape (never echoes "
            "secrets), list, delete. Sealed with Fernet under a 0600 key file; "
            "needs the cryptography extra."
        ),
        input_schema=_SCHEMA,
        fn=_run,
    )


__all__ = [
    "generate_key", "encrypt_entry", "decrypt_entry", "Vault", "resolve_key",
    "browser_auth_vault",
]

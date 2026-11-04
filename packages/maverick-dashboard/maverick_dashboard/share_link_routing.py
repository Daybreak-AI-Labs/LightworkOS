"""Private, opaque routing for public share capabilities across workspaces.

The locator supplies a storage address, never authority. The destination world
still verifies the random token, expiry, revocation and current release policy.
Anonymous misses perform no filesystem creation or tenant enumeration.
"""
from __future__ import annotations

import hashlib
import ipaddress
import itertools
import json
import math
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

_TOKEN = re.compile(r"(?:r1_)?[A-Za-z0-9_-]{43}\Z")
_MAX_RECORD_BYTES = 4096
_CLEANUP_LIMIT = 64


class ShareRouteError(RuntimeError):
    """A locator exists but does not establish a trustworthy routing address."""


@dataclass(frozen=True)
class ShareRoute:
    tenant: str | None
    expires_at: float


def share_base_url(request_base: str) -> tuple[str, bool]:
    """Use the installation's existing address setting, with bounded validation."""
    from .automation_queue import _public_base_url

    configured = _public_base_url()
    base = configured or request_base
    try:
        if configured:
            from .settings_catalog_access import _HTTPS_OR_LOCAL

            if re.fullmatch(_HTTPS_OR_LOCAL, configured) is None:
                raise ValueError("invalid public address")
        parsed = urlsplit(base)
        hostname = parsed.hostname or ""
        port = parsed.port  # reject malformed and out-of-range ports
        if (
            len(base) > 300 or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in base)
            or parsed.scheme not in {"http", "https"} or not hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment
            or "\\" in base
            or any(char in base for char in "\"'<>")
            or port == 0
        ):
            raise ValueError("invalid public address")
        local_only = hostname.lower() == "localhost"
        try:
            address = ipaddress.ip_address(hostname)
            local_only = address.is_private or address.is_loopback or address.is_link_local
        except ValueError:
            local_only = local_only or hostname.lower().endswith(".local")
    except ValueError as exc:
        raise ShareRouteError("invalid Lightwork address for others") from exc
    return base.rstrip("/"), local_only


def _root() -> Path:
    from maverick.paths import maverick_home

    # Control-plane state: deliberately independent of the active workspace.
    return maverick_home() / "dashboard-share-routes"


def _digest(token: str) -> str:
    if not isinstance(token, str) or _TOKEN.fullmatch(token) is None:
        raise ShareRouteError("invalid share token")
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _record(path: Path) -> dict:
    from maverick.file_lock import private_path_is_restricted, require_private_directory

    require_private_directory(path.parent.parent)
    require_private_directory(path.parent)
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or getattr(before, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
        or before.st_size > _MAX_RECORD_BYTES
        or not private_path_is_restricted(path)
    ):
        raise ShareRouteError("untrusted share locator")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ShareRouteError("share locator changed")
        raw = stream.read(_MAX_RECORD_BYTES + 1)
    after = path.lstat()
    if (
        len(raw) > _MAX_RECORD_BYTES
        or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
        or after.st_nlink != 1
    ):
        raise ShareRouteError("share locator changed")

    def object_pairs(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate locator field")
            out[key] = value
        return out

    record = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs)
    if not isinstance(record, dict) or set(record) != {
        "version", "token_sha256", "tenant", "expires_at",
    }:
        raise ShareRouteError("invalid share locator")
    expiry = record["expires_at"]
    if (
        type(record["version"]) is not int
        or record["version"] != 1
        or record["token_sha256"] != path.stem
        or isinstance(expiry, bool)
        or not isinstance(expiry, (int, float))
        or not math.isfinite(expiry)
        or expiry <= 0
    ):
        raise ShareRouteError("invalid share locator")
    tenant = record["tenant"]
    if tenant is not None:
        from maverick.paths import canonical_tenant_id

        if not isinstance(tenant, str) or canonical_tenant_id(tenant) != tenant:
            raise ShareRouteError("invalid share locator workspace")
    return record


def _prune_expired(root: Path, now: float) -> None:
    """Bounded retention cleanup runs only during authenticated link creation."""
    for path in itertools.islice(root.glob("*.json"), _CLEANUP_LIMIT):
        try:
            if _record(path)["expires_at"] <= now:
                path.unlink()
        except (OSError, ValueError, ShareRouteError):
            # Corrupt state is not a reason to delete an unverified pathname.
            continue


def register(token: str, *, expires_at: float) -> None:
    from maverick.file_lock import atomic_create_text, ensure_private_directory
    from maverick.paths import canonical_tenant_id, current_tenant_id_strict

    digest = _digest(token)
    if not math.isfinite(expires_at) or expires_at <= time.time():
        raise ShareRouteError("invalid share expiry")
    tenant = current_tenant_id_strict()
    if tenant is not None:
        tenant = canonical_tenant_id(tenant)
    root = _root()
    ensure_private_directory(root.parent)
    ensure_private_directory(root)
    _prune_expired(root, time.time())
    atomic_create_text(root / f"{digest}.json", json.dumps({
        "version": 1,
        "token_sha256": digest,
        "tenant": tenant,
        "expires_at": expires_at,
    }, separators=(",", ":")))


def resolve(token: str) -> ShareRoute | None:
    """None means an unprefixed legacy link; new links require their locator."""
    path = _root() / f"{_digest(token)}.json"
    try:
        path.lstat()
    except FileNotFoundError:
        # Missing routing state must not create files or an arbitrary tenant DB.
        if token.startswith("r1_"):
            raise ShareRouteError("new share locator is unavailable") from None
        return None
    try:
        record = _record(path)
        if record["expires_at"] <= time.time():
            raise ShareRouteError("expired share locator")
        return ShareRoute(record["tenant"], float(record["expires_at"]))
    except (OSError, ValueError, TypeError) as exc:
        raise ShareRouteError("untrusted share locator") from exc

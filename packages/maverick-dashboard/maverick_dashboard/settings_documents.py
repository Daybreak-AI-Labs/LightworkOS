"""Documents imported on Settings > All settings (the ``document`` control).

Some settings are a whole signed-off document a person receives from someone
else -- a benchmark coordinator's list of trusted signing keys, for example.
The page never asks anyone to type it: the person picks the file, the server
reads and checks it here, and the page shows what it contains in plain words
(version, how many keys, each key's short fingerprint).

Each checker enforces the document's own rules on the server: a newer
version only, keys once trusted are never silently replaced or dropped, and
nothing the kernel would refuse is ever stored.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

MAX_BYTES = 64 * 1024


class _Refused(ValueError):
    pass


def _error(setting, text: str):
    from .settings_catalog import SettingError

    return SettingError(f"{setting.label}: {text}")


def _fingerprint(hex_key: str) -> str:
    digest = hashlib.sha256(bytes.fromhex(hex_key)).hexdigest().upper()
    return " ".join(digest[i:i + 4] for i in range(0, 16, 4))


# ------------------------------------------------ benchmark trust roots
def _trust_roots(document: object) -> dict[str, Any]:
    """A coordinator trust document, validated exactly as the kernel reads it."""
    from maverick.ai_benchmark_exchange_transport import (
        BenchmarkTrustRootError,
        VersionedEd25519TrustRoots,
    )

    try:
        roots = VersionedEd25519TrustRoots.from_document(document)
    except (BenchmarkTrustRootError, TypeError, ValueError) as exc:
        raise _Refused("that file is not a trusted-keys document Lightwork can read.") from exc
    except ImportError as exc:  # pragma: no cover - cryptography ships with Lightwork
        raise _Refused("Lightwork can't check signing keys on this server.") from exc
    out = roots.as_document()
    for key in out["keys"]:
        if key.get("revoked_in") is None:
            key.pop("revoked_in", None)  # the settings file can't hold "nothing"
    return out


def _trust_roots_advance(old: object, new: dict[str, Any]) -> None:
    """A replacement must be a newer version that keeps every key it had."""
    if not isinstance(old, dict) or not old:
        return
    try:
        before = _trust_roots(old)
    except _Refused:
        return  # an unreadable saved document can only be replaced
    if new == before:
        return  # the same document again changes nothing
    if new["version"] <= before["version"]:
        raise _Refused("that document is not newer than the one in use. Import the latest "
                       "version your coordinator sent.")
    now = {key["key_id"]: key for key in new["keys"]}
    for key in before["keys"]:
        kept = now.get(key["key_id"])
        if kept is None:
            raise _Refused("that document drops a key the one in use trusts. Keys can only be "
                           "retired, never removed.")
        if (kept["public_key_hex"] != key["public_key_hex"]
                or kept["introduced_in"] != key["introduced_in"]):
            raise _Refused("that document changes a key the one in use trusts.")
        was = key.get("revoked_in")
        if was is not None and kept.get("revoked_in") != was:
            raise _Refused("that document brings back a key that was retired.")
        if was is None and kept.get("revoked_in") is not None \
                and kept["revoked_in"] <= before["version"]:
            raise _Refused("that document retires a key as of an older version.")
    for key_id, key in now.items():
        if key_id not in {k["key_id"] for k in before["keys"]} \
                and key["introduced_in"] <= before["version"]:
            raise _Refused("that document adds a key as of an older version.")


def _trust_roots_summary(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not value:
        return None
    try:
        doc = _trust_roots(value)
    except _Refused:
        return {"text": "The saved document can't be read. Import a new one.", "items": []}
    items = []
    for key in doc["keys"]:
        state = "Retired" if key.get("revoked_in") is not None \
            and key["revoked_in"] <= doc["version"] else "Trusted"
        items.append({"label": f"{state} key", "fingerprint": _fingerprint(key["public_key_hex"])})
    trusted = sum(1 for item in items if item["label"].startswith("Trusted"))
    return {"text": f"Version {doc['version']}: {trusted} trusted "
                    f"key{'' if trusted == 1 else 's'}", "items": items}


def _trust_roots_loosens(old: object, new: object) -> bool:
    """Trusting a key that was not trusted before, or dropping the whole list
    (results would then be checked differently), is confirmed."""
    if isinstance(old, dict) and old and not (isinstance(new, dict) and new):
        return True
    def active(value: object) -> set[str]:
        if not isinstance(value, dict) or not value:
            return set()
        try:
            doc = _trust_roots(value)
        except _Refused:
            return set()
        return {k["public_key_hex"] for k in doc["keys"]
                if k.get("revoked_in") is None or k["revoked_in"] > doc["version"]}
    return bool(active(new) - active(old))


CHECKERS: dict[str, tuple[Callable, Callable, Callable, Callable]] = {
    "benchmark_trust_roots": (_trust_roots, _trust_roots_advance, _trust_roots_summary,
                              _trust_roots_loosens),
}


# ------------------------------------------------------------ interface
def coerce(setting, value: object) -> dict[str, Any] | None:
    """The uploaded file's text -> the stored document (or ``None`` to unset)."""
    if value is None or value == "":
        return None
    parse, _advance, _summary, _loosens = CHECKERS[setting.document]
    if isinstance(value, dict):
        document: object = value
    elif isinstance(value, str):
        if len(value.encode("utf-8", "replace")) > MAX_BYTES:
            raise _error(setting, "that file is too large to be this kind of document.")
        try:
            document = json.loads(value)
        except ValueError as exc:
            raise _error(setting, "that file is not a document Lightwork can read.") from exc
    else:
        raise _error(setting, "choose the file to import.")
    try:
        return parse(document)
    except _Refused as exc:
        raise _error(setting, str(exc)) from exc


def check_replacement(setting, old: object, new: object) -> None:
    """Refuse a replacement the document's own rules forbid."""
    if not isinstance(new, dict):
        return
    _parse, advance, _summary, _loosens = CHECKERS[setting.document]
    try:
        advance(old, new)
    except _Refused as exc:
        raise _error(setting, str(exc)) from exc


def summary(setting, value: object) -> dict[str, Any] | None:
    return CHECKERS[setting.document][2](value)


def describe(setting, value: object) -> str:
    shown = summary(setting, value)
    return shown["text"] if shown else "Not set"


def loosens(setting, old: object, new: object) -> bool:
    return CHECKERS[setting.document][3](old, new)


__all__ = ["CHECKERS", "MAX_BYTES", "check_replacement", "coerce", "describe", "loosens",
           "summary"]

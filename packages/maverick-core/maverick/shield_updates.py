"""Federated shield rules updates.

Pull-based, signature-verified updates to the shield's RULES bundle. A
publisher signs ``{"version": N, "rules": [...]}`` with Ed25519 (the same
primitives as audit-log signing); deployments that opted in fetch the bundle,
verify it against the pinned publisher pubkey, refuse anything unsigned,
mis-signed, or older than what is already applied, and atomically stage the
verified rules at ``data_dir("shield_rules.json")`` (mode 0600).

Trust model -- signature verification fails CLOSED:
  - no ``[shield] update_pubkey`` configured  -> refused (no trust anchor);
  - ``cryptography`` not installed            -> refused (cannot verify);
  - bad/absent signature or malformed bundle  -> refused;
  - version <= the currently staged version   -> refused / no-op (no downgrade).

The shield itself stays optional (kernel rule 1): this module never imports
``maverick_shield`` -- it only stages the rules file for the shield to pick up
when (and if) it is installed. Reads of local state fail OPEN (a missing or
corrupt staged file just means "no current version").

Default OFF::

    [shield]
    federated_updates = false      # master switch
    update_url = "https://..."     # where the default fetcher pulls from
    update_pubkey = "<hex ed25519> publisher key"

Fetching goes through an INJECTED fetcher seam (``fetcher(url) -> text``);
tests never touch the network. The default fetcher is a lazy httpx GET.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

RULES_FILENAME = "shield_rules.json"
MAX_BUNDLE_BYTES = 1_000_000

# A fetcher maps the update URL to the bundle's JSON text.
Fetcher = Callable[[str], str]


class UpdateRefused(ValueError):
    """The bundle failed verification (unsigned / bad signature / downgrade)."""


def get_update_config() -> dict:
    """The ``[shield]`` federated-update knobs, defaults filled in (all off)."""
    try:
        from .config import load_config

        cfg = (load_config() or {}).get("shield") or {}
    except Exception:  # noqa: BLE001 -- config reads fail open
        cfg = {}
    return {
        "federated_updates": bool(cfg.get("federated_updates", False)),
        "update_url": str(cfg.get("update_url", "") or ""),
        "update_pubkey": str(cfg.get("update_pubkey", "") or ""),
    }


def rules_path() -> Path:
    """Tenant-aware staged-rules location: ``data_dir("shield_rules.json")``."""
    from .paths import data_dir

    return data_dir(RULES_FILENAME)


def _canonical_signed_bytes(version: int, rules: list) -> bytes:
    """The bytes a publisher signs: canonical JSON of {version, rules}."""
    return json.dumps(
        {"version": version, "rules": rules},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sign_bundle(version: int, rules: list, privkey_hex: str) -> dict:
    """Publisher-side helper: build a signed bundle dict.

    Requires ``cryptography`` (the [audit-signing] extra). Deployments only
    ever *verify*; this exists for the publisher pipeline and for tests.
    """
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(privkey_hex))
    sig = priv.sign(_canonical_signed_bytes(int(version), rules)).hex()
    return {"version": int(version), "rules": rules, "sig": sig}


def verify_bundle(bundle: Any, pubkey_hex: str) -> tuple[int, list]:
    """Validate shape + Ed25519 signature. Returns ``(version, rules)``.

    Raises :class:`UpdateRefused` on ANY problem -- signature verification
    fails closed, including when ``cryptography`` itself is missing.
    """
    if not isinstance(bundle, dict):
        raise UpdateRefused("bundle must be a JSON object")
    version = bundle.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version < 0:
        raise UpdateRefused("bundle version must be a non-negative integer")
    rules = bundle.get("rules")
    if not isinstance(rules, list):
        raise UpdateRefused("bundle rules must be a list")
    sig = bundle.get("sig")
    if not isinstance(sig, str) or not sig.strip():
        raise UpdateRefused("bundle is unsigned (missing 'sig')")
    if not pubkey_hex:
        raise UpdateRefused("no [shield] update_pubkey configured -- refusing to trust any bundle")
    from .audit import signing

    if not signing._have_crypto():
        raise UpdateRefused(
            "cryptography is not installed; cannot verify the bundle signature. "
            "Install 'maverick-agent[audit-signing]'."
        )
    if not signing.verify_ed25519(pubkey_hex, sig, _canonical_signed_bytes(version, rules)):
        raise UpdateRefused("bundle signature does not verify against the publisher pubkey")
    return version, rules


def current_version(path: Path | None = None) -> int | None:
    """Version of the currently staged rules file, or None. Fails OPEN: a
    missing/corrupt file reads as "nothing applied yet"."""
    p = path or rules_path()
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        v = data.get("version")
        return v if isinstance(v, int) and not isinstance(v, bool) else None
    except (OSError, json.JSONDecodeError, AttributeError):
        return None


def _rule_id(rule: Any) -> str:
    """A stable identifier for one rule: its ``id`` field when present, else a
    short content hash -- so the change report names what moved."""
    if isinstance(rule, dict) and isinstance(rule.get("id"), str) and rule["id"].strip():
        return rule["id"]
    canon = json.dumps(rule, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(canon.encode("utf-8")).hexdigest()[:12]


def _staged_rules(path: Path) -> list:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        rules = data.get("rules")
        return rules if isinstance(rules, list) else []
    except (OSError, json.JSONDecodeError, AttributeError):
        return []


@dataclass
class UpdateResult:
    """What an update attempt did. ``applied`` False = nothing changed."""

    applied: bool
    reason: str
    version: int | None = None
    previous_version: int | None = None
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    path: str = ""

    def summary(self) -> str:
        if not self.applied:
            return f"not applied: {self.reason}"
        return (
            f"applied rules v{self.version} "
            f"(was {self.previous_version if self.previous_version is not None else 'none'}): "
            f"+{len(self.added)} rule(s) {self.added}, -{len(self.removed)} rule(s) {self.removed}"
        )


def apply_update(
    bundle: Any, *, pubkey_hex: str | None = None, path: Path | None = None
) -> UpdateResult:
    """Verify ``bundle`` and atomically stage its rules. Refuses downgrades.

    ``pubkey_hex`` defaults to the configured ``[shield] update_pubkey``; the
    staged file keeps the verified version/rules/sig so it can be re-checked
    later. Same-version bundles are a no-op (not an error); older versions are
    REFUSED -- a downgrade would reopen holes newer rules closed.
    """
    if pubkey_hex is None:
        pubkey_hex = get_update_config()["update_pubkey"]
    version, rules = verify_bundle(bundle, pubkey_hex)
    _bounded_rules(rules)  # refuse a bundle the live shield would not use

    p = Path(path) if path is not None else rules_path()
    new_ids = {_rule_id(r) for r in rules}
    staged = {"version": version, "rules": rules, "sig": bundle["sig"]}
    content = json.dumps(staged, sort_keys=True, indent=2, ensure_ascii=False) + "\n"

    from .file_lock import (
        atomic_write_text,
        cross_process_lock,
        ensure_private_directory,
        prepare_private_directory,
    )

    if path is None:
        ensure_private_directory(p.parent)
    else:
        prepare_private_directory(p.parent)
    # Anti-rollback is a read-check-write transaction. Without one stable
    # cross-process lock, concurrent signed v3/v2 updates can both observe v1,
    # then publish in reverse order and leave the deployment downgraded to v2.
    with cross_process_lock(p, strict=True):
        cur = current_version(p)
        if cur is not None and version < cur:
            raise UpdateRefused(
                f"version downgrade refused: bundle v{version} < staged v{cur}"
            )
        if cur is not None and version == cur:
            return UpdateResult(
                applied=False,
                reason=f"already at v{cur}",
                version=version,
                previous_version=cur,
                path=str(p),
            )

        old_ids = {_rule_id(r) for r in _staged_rules(p)}
        atomic_write_text(p, content)
        result = UpdateResult(
            applied=True,
            reason="ok",
            version=version,
            previous_version=cur,
            added=sorted(new_ids - old_ids),
            removed=sorted(old_ids - new_ids),
            path=str(p),
        )
    log.info("shield rules update: %s", result.summary())
    return result


def _refuse_oversized_bundle(size: int) -> None:
    if size > MAX_BUNDLE_BYTES:
        raise UpdateRefused(f"bundle exceeds maximum size of {MAX_BUNDLE_BYTES} bytes")


def _decode_bundle_bytes(data: bytes) -> str:
    _refuse_oversized_bundle(len(data))
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise UpdateRefused(f"bundle is not valid UTF-8: {e}") from e


def _default_fetcher(url: str) -> str:
    """Lazy httpx GET with a hard response-size cap. Tests inject instead."""
    import httpx

    chunks = bytearray()
    with httpx.stream("GET", url, timeout=30.0, follow_redirects=True) as resp:
        resp.raise_for_status()
        content_length = resp.headers.get("content-length")
        if content_length is not None:
            try:
                _refuse_oversized_bundle(int(content_length))
            except ValueError:
                pass
        for chunk in resp.iter_bytes():
            chunks.extend(chunk)
            _refuse_oversized_bundle(len(chunks))
    return _decode_bundle_bytes(bytes(chunks))


def check_and_apply(*, fetcher: Fetcher | None = None) -> UpdateResult:
    """The pull entry point: fetch the configured bundle and stage it.

    Default OFF -- returns an unapplied result unless ``[shield]
    federated_updates`` is true and an ``update_url`` is configured. All
    verification failures raise :class:`UpdateRefused`.
    """
    cfg = get_update_config()
    if not cfg["federated_updates"]:
        return UpdateResult(
            applied=False,
            reason="disabled: [shield] federated_updates is off",
        )
    url = cfg["update_url"]
    if not url:
        return UpdateResult(applied=False, reason="no [shield] update_url configured")
    try:
        text = (fetcher or _default_fetcher)(url)
    except UpdateRefused:
        raise
    except Exception as e:  # noqa: BLE001 -- network failures refuse, not crash
        raise UpdateRefused(f"fetch failed: {type(e).__name__}: {e}") from e
    _refuse_oversized_bundle(len(text.encode("utf-8")))
    try:
        bundle = json.loads(text)
    except json.JSONDecodeError as e:
        raise UpdateRefused(f"bundle is not valid JSON: {e}") from e
    return apply_update(bundle, pubkey_hex=cfg["update_pubkey"])


# Bounds on what a verified bundle may add to the live shield. A signed bundle
# is trusted to ADD checks, never to make the shield slow: too many rules or a
# very long pattern is refused as a whole.
MAX_RULES = 500
MAX_PATTERN_CHARS = 2_000
_RULE_KEYS = {"id", "name", "pattern", "phrases", "severity"}


def _bounded_rules(rules: list) -> list[dict]:
    if len(rules) > MAX_RULES:
        raise UpdateRefused(f"bundle has {len(rules)} rules; at most {MAX_RULES} are used")
    out: list[dict] = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        pattern = rule.get("pattern")
        phrases = rule.get("phrases")
        size = len(pattern) if isinstance(pattern, str) else 0
        if isinstance(phrases, list):
            size += sum(len(str(p)) for p in phrases)
        if size > MAX_PATTERN_CHARS:
            raise UpdateRefused(f"rule {_rule_id(rule)} is longer than {MAX_PATTERN_CHARS} characters")
        clean = {k: v for k, v in rule.items() if k in _RULE_KEYS}
        clean.setdefault("name", _rule_id(rule))
        out.append(clean)
    return out


_loaded_cache: dict[tuple, list[dict]] = {}


def load_verified_rules(path: Path | None = None) -> list[dict]:
    """The staged rules the live shield adds to its own checks.

    Empty unless ``[shield] federated_updates`` is on. The staged file is
    re-verified against the configured publisher key every time it changes
    (a file edited on disk, or a key that no longer matches, adds nothing),
    and the bounds above apply. Rules are only ever ADDED to the operator's
    own ``[safety] constitution``; nothing here can remove or relax a check.
    Never raises: a problem is logged and adds nothing.
    """
    cfg = get_update_config()
    if not cfg["federated_updates"]:
        return []
    p = Path(path) if path is not None else rules_path()
    try:
        st = p.stat()
    except OSError:
        return []
    key = (str(p), st.st_mtime_ns, st.st_size, cfg["update_pubkey"])
    cached = _loaded_cache.get(key)
    if cached is not None:
        return list(cached)
    try:
        if st.st_size > MAX_BUNDLE_BYTES:
            raise UpdateRefused("staged rules file is too large")
        staged = json.loads(p.read_text(encoding="utf-8"))
        _version, rules = verify_bundle(staged, cfg["update_pubkey"])
        rules = _bounded_rules(rules)
    except (OSError, ValueError) as exc:
        log.warning("shared threat rules not used: %s", exc)
        rules = []
    _loaded_cache.clear()
    _loaded_cache[key] = rules
    return list(rules)


__all__ = [
    "MAX_BUNDLE_BYTES",
    "MAX_PATTERN_CHARS",
    "MAX_RULES",
    "RULES_FILENAME",
    "UpdateRefused",
    "UpdateResult",
    "apply_update",
    "check_and_apply",
    "current_version",
    "load_verified_rules",
    "get_update_config",
    "rules_path",
    "sign_bundle",
    "verify_bundle",
]

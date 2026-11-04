"""Signed tax-constants content channel: new law -> auto-applied tables.

``tax_prep``'s computation tables (federal ``TY2025``, ``STATE_TY2025``) are
SEASON CONTENT: when Congress or a state changes the law, the fix is new
constants, not new code. This module makes that a governed, automatic
update instead of a release wait:

* The publisher (Daybreak) ships a **signed constants bundle** (Ed25519,
  the same fail-closed posture as :mod:`maverick.insight_exchange`): an
  unsigned bundle, an unknown key, or a bad signature is rejected outright.
  Trust anchors live in ``[tax] trusted_constants_pubkeys`` — configured by
  the operator, never TOFU.
* Every bundle passes a **sanity validator** before it can replace the
  tables (rates in (0,1), ascending brackets, real state codes, monotonic
  version — downgrades/replays refused), so a malformed law update can
  never poison the deterministic math.
* With ``[tax] auto_update`` on and an ``update_url`` configured,
  ``maverick tax prepare``/``update`` checks for a newer bundle (throttled),
  applies it atomically with the previous bundle kept for ``--rollback``,
  and writes a CONTENT_UPDATE-tagged audit row. Air-gapped firms apply the
  same bundle from a file (``maverick tax update --file``).
* The review package states which constants computed it (built-in vs
  bundle vN), so a reviewer always knows the law revision behind a draft.

The ``tax_law_watch`` pack is the detection side: it monitors IRS / state
DOR guidance and alerts the firm — agents never edit constants themselves;
changes arrive only as signed publisher bundles through this gate.
"""
from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from urllib.parse import urlsplit

from .paths import data_dir
from .tax_prep import (
    FILING_STATUSES,
    STATE_CODES,
    STATE_TY2025,
    TY2025,
)

log = logging.getLogger(__name__)

SCHEMA_VERSION = 1
_LEGACY_DIR = data_dir()
_BUNDLE_NAME = "tax-constants.json"
_STAMP_NAME = ".tax-constants-check"
_MAX_BUNDLE_BYTES = 1024 * 1024
_UPDATE_TIMEOUT_SECONDS = 15.0


def _store_dir() -> Path:
    """Tenant-isolated storage (one firm's constants never leak to another's
    runs); single-tenant resolution keeps the legacy ~/.maverick location."""
    try:
        from .paths import current_tenant, data_dir
        if current_tenant():
            return data_dir()
    except Exception:  # pragma: no cover -- isolation never blocks resolution
        pass
    return _LEGACY_DIR


def bundle_path() -> Path:
    return _store_dir() / _BUNDLE_NAME


def _canonical_bytes(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")


def trusted_pubkeys() -> list[str]:
    try:
        from .config import get_tax
        return get_tax()["trusted_constants_pubkeys"]
    except Exception:  # pragma: no cover -- config never blocks
        return []


def _num(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _validate_brackets(label: str, brackets, errs: list[str]) -> None:
    """Validate one marginal bracket list: ascending tops, rates in (0,1), an
    open-ended last bracket. ``label`` is the dotted path used in any error."""
    if not isinstance(brackets, list) or not brackets:
        errs.append(f"{label} missing")
        return
    prev_top = 0.0
    for i, pair in enumerate(brackets):
        ok = (isinstance(pair, (list, tuple)) and len(pair) == 2
              and (pair[0] is None or _num(pair[0]))
              and _num(pair[1]) and 0 < pair[1] < 1)
        if not ok:
            errs.append(f"{label}[{i}] malformed")
            return
        top = pair[0]
        if top is None:
            if i != len(brackets) - 1:
                errs.append(f"{label}: open bracket must be last")
            return
        if top <= prev_top:
            errs.append(f"{label}: tops not ascending")
            return
        prev_top = float(top)
    errs.append(f"{label}: top bracket must be open-ended (null top)")


def _validate_federal(fed: dict, errs: list[str]) -> None:
    for table in ("standard_deduction", "ctc_phaseout_start"):
        vals = fed.get(table) or {}
        for status in FILING_STATUSES:
            if not _num(vals.get(status)) or vals[status] < 0:
                errs.append(f"federal.{table}.{status} missing/invalid")
    if not _num(fed.get("ctc_per_child")) or fed["ctc_per_child"] < 0:
        errs.append("federal.ctc_per_child missing/invalid")
    for status in FILING_STATUSES:
        _validate_brackets(f"federal.brackets.{status}",
                           (fed.get("brackets") or {}).get(status), errs)


def _validate_state(state: dict, errs: list[str]) -> None:
    for code in state.get("no_tax") or []:
        if code not in STATE_CODES:
            errs.append(f"state.no_tax: unknown state {code!r}")
    for code, flat in (state.get("flat") or {}).items():
        if code not in STATE_CODES:
            errs.append(f"state.flat: unknown state {code!r}")
            continue
        if not isinstance(flat, dict):
            errs.append(f"state.flat.{code} malformed")
            continue
        if not _num(flat.get("rate")) or not (0 < flat["rate"] < 1):
            errs.append(f"state.flat.{code}.rate out of range")
        if flat.get("basis") not in ("agi", "federal_taxable"):
            errs.append(f"state.flat.{code}.basis invalid")
        ded = flat.get("deduction") or {}
        for status in FILING_STATUSES:
            if not _num(ded.get(status)) or ded[status] < 0:
                errs.append(f"state.flat.{code}.deduction.{status} invalid")
    for code, grad in (state.get("graduated") or {}).items():
        if code not in STATE_CODES:
            errs.append(f"state.graduated: unknown state {code!r}")
            continue
        if not isinstance(grad, dict):
            errs.append(f"state.graduated.{code} malformed")
            continue
        if grad.get("basis") not in ("agi", "federal_taxable"):
            errs.append(f"state.graduated.{code}.basis invalid")
        gded = grad.get("deduction") or {}
        for status in FILING_STATUSES:
            if not _num(gded.get(status)) or gded[status] < 0:
                errs.append(f"state.graduated.{code}.deduction.{status} invalid")
        _validate_brackets(f"state.graduated.{code}.brackets",
                           grad.get("brackets"), errs)


def validate_payload(payload: dict) -> list[str]:
    """Sanity gates a constants bundle must clear before it can replace the
    tables. Returns a list of problems (empty = valid)."""
    errs: list[str] = []
    try:
        if int(payload.get("schema_version", -1)) != SCHEMA_VERSION:
            errs.append("unsupported schema_version")
        if not (2024 <= int(payload.get("year", 0)) <= 2100):
            errs.append("implausible tax year")
        if int(payload.get("version", 0)) < 1:
            errs.append("bundle version must be >= 1")
    except (TypeError, ValueError, OverflowError):
        return ["malformed header fields"]
    _validate_federal(payload.get("federal") or {}, errs)
    _validate_state(payload.get("state") or {}, errs)
    return errs


def _to_runtime(payload: dict) -> tuple[dict, dict]:
    """JSON payload -> the runtime shapes ``tax_prep`` computes from."""
    fed = payload["federal"]
    federal = {
        "year": int(payload["year"]),
        "standard_deduction": {s: float(fed["standard_deduction"][s])
                               for s in FILING_STATUSES},
        "brackets": {s: [(None if t is None else float(t), float(r))
                         for t, r in fed["brackets"][s]]
                     for s in FILING_STATUSES},
        "ctc_per_child": float(fed["ctc_per_child"]),
        "ctc_phaseout_start": {s: float(fed["ctc_phaseout_start"][s])
                               for s in FILING_STATUSES},
    }
    # Carry the 65+/blind additional standard deduction from the bundle when it
    # supplies a full table, so an applied signed bundle can update it rather
    # than tax_prep silently using the hardcoded TY2025 default. Omitted (not
    # partial) bundles fall back to that default.
    add = fed.get("additional_standard_deduction")
    if isinstance(add, dict) and all(add.get(s) is not None for s in FILING_STATUSES):
        federal["additional_standard_deduction"] = {
            s: float(add[s]) for s in FILING_STATUSES
        }
    st = payload.get("state") or {}
    state = {
        "year": int(payload["year"]),
        "no_tax": frozenset(st.get("no_tax") or ()),
        "flat": {code: {"rate": float(f["rate"]), "basis": f["basis"],
                        "deduction": {s: float(f["deduction"][s])
                                      for s in FILING_STATUSES}}
                 for code, f in (st.get("flat") or {}).items()},
        "graduated": {
            code: {
                "basis": g["basis"],
                "brackets": [(None if t is None else float(t), float(r))
                             for t, r in g["brackets"]],
                "deduction": {s: float(g["deduction"][s])
                              for s in FILING_STATUSES},
            }
            for code, g in (st.get("graduated") or {}).items()},
    }
    return federal, state


def active_constants() -> tuple[dict, dict, str]:
    """``(federal, state, provenance)`` — the applied bundle when one is
    present, currently trusted and signature-verified, else the built-in tables. Never raises: the
    shipped tables are the known-good floor."""
    p = bundle_path()
    try:
        env, payload = _read_verified_bundle(p)
        federal, state = _to_runtime(payload)
        prov = (f"bundle v{int(payload['version'])} "
                f"published {payload.get('published', '?')} "
                f"(key {str(env.get('publisher_key', ''))[:8]})")
        return federal, state, prov
    except FileNotFoundError:
        pass
    except Exception as e:
        log.warning("tax constants bundle unusable (%s); using built-ins", e)
    return TY2025, STATE_TY2025, "built-in defaults"


def active_version() -> int:
    """The currently trusted applied bundle's version (0 = built-ins only)."""
    try:
        _, payload = _read_verified_bundle(bundle_path())
        return int(payload["version"])
    except Exception:
        return 0


def export_bundle(out_path: Path | str, payload: dict) -> Path:
    """Publisher side: sign a constants payload with this instance's audit
    key (used by Daybreak's release pipeline and by tests)."""
    from .audit.signing import _have_crypto, _load_or_create_keypair
    if not _have_crypto():
        raise RuntimeError("constants export requires 'cryptography': "
                           "bundles are always signed.")
    from cryptography.hazmat.primitives.asymmetric import ed25519
    problems = validate_payload(payload)
    if problems:
        raise ValueError("refusing to sign an invalid payload: "
                         + "; ".join(problems))
    priv, pub, key_id = _load_or_create_keypair()
    sig = ed25519.Ed25519PrivateKey.from_private_bytes(priv).sign(
        _canonical_bytes(payload))
    env = {"schema_version": SCHEMA_VERSION, "payload": payload,
           "publisher_key": pub.hex(), "publisher_key_id": key_id,
           "sig": sig.hex()}
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(env, indent=2, default=str), encoding="utf-8")
    return out


def _verified_payload(envelope: dict, trusted: list[str] | None = None) -> dict:
    """Verify retained bytes against today's anchors, before trusting any field."""
    trusted = trusted if trusted is not None else trusted_pubkeys()
    if not trusted:
        raise ValueError("no trusted publisher keys are configured")
    if not isinstance(envelope, dict):
        raise ValueError("malformed envelope")
    key = str(envelope.get("publisher_key", "") or "")
    sig = str(envelope.get("sig", "") or "")
    payload = envelope.get("payload")
    if not key or not sig or not isinstance(payload, dict):
        raise ValueError("malformed envelope: missing publisher_key/sig/payload")
    if key not in trusted:
        raise ValueError("the publisher key is not currently trusted")
    from .audit.signing import _have_crypto, verify_ed25519
    if not _have_crypto():
        raise ValueError("cryptography not installed: cannot verify the bundle")
    if not verify_ed25519(key, sig, _canonical_bytes(payload)):
        raise ValueError("signature verification FAILED: bundle rejected")
    problems = validate_payload(payload)
    if problems:
        raise ValueError("bundle failed sanity validation: " + "; ".join(problems))
    return payload


def _read_verified_bundle(p: Path, trusted: list[str] | None = None) -> tuple[dict, dict]:
    with p.open("rb") as stream:
        raw = stream.read(_MAX_BUNDLE_BYTES + 1)
    if len(raw) > _MAX_BUNDLE_BYTES:
        raise ValueError("the constants bundle exceeds the size limit")
    envelope = json.loads(raw)
    return envelope, _verified_payload(envelope, trusted)


def apply_bundle(envelope: dict, *, trusted: list[str] | None = None,
                 path: Path | None = None) -> tuple[bool, str]:
    """Verify + validate + atomically apply one constants envelope.

    Fail-closed (no anchors / unknown key / bad signature = rejected),
    sanity-gated, and downgrade-protected (a bundle version <= the applied
    one is refused). The previous bundle is kept for ``rollback``.
    """
    try:
        serialized = json.dumps(envelope, indent=2, default=str)
        if len(serialized.encode("utf-8")) > _MAX_BUNDLE_BYTES:
            return False, "the constants bundle exceeds the size limit"
        payload = _verified_payload(envelope, trusted)
    except (ValueError, TypeError, AttributeError, OverflowError, RecursionError) as exc:
        return False, str(exc)
    key = envelope["publisher_key"]
    new_version = int(payload["version"])
    p = path if path is not None else bundle_path()
    # Serialize the downgrade-check + .prev backup + write across processes:
    # without it two concurrent applies can both pass the `new_version <=
    # current` gate and interleave the backup/rename, clobbering the .prev
    # rollback copy. The fixed ".tmp" likewise collides between two writers.
    from .file_lock import atomic_write_text, cross_process_lock
    with cross_process_lock(p):
        current = _file_version(p, trusted=trusted)
        if new_version <= current:
            return False, (f"bundle v{new_version} is not newer than the applied "
                           f"v{current} (downgrades are refused)")
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists():
            p.replace(p.with_suffix(p.suffix + ".prev"))
        atomic_write_text(p, serialized, mode=0o600)
    try:
        from .audit import EventKind, record
        record(EventKind.CONTENT_UPDATE, agent="tax_constants",
               content="tax_constants", version=new_version,
               year=int(payload["year"]), publisher=key[:16])
    except Exception:  # pragma: no cover -- audit never blocks the update
        pass
    return True, f"applied tax constants v{new_version} (TY{payload['year']})"


def _file_version(p: Path, *, trusted: list[str] | None = None) -> int:
    """The downgrade floor: the applied bundle's version.

    A bundle verified with the caller's keys is authoritative. Otherwise the
    retained bundle still pins the floor (by today's configured keys, or by its
    recorded version), so a key list that cannot verify the applied bundle
    never reopens a downgrade to an older version.
    """
    try:
        _, payload = _read_verified_bundle(p, trusted)
        return int(payload["version"])
    except Exception:
        pass
    try:
        _, payload = _read_verified_bundle(p)
        return int(payload["version"])
    except Exception:
        pass
    try:
        with p.open("rb") as stream:
            raw = stream.read(_MAX_BUNDLE_BYTES + 1)
        version = json.loads(raw)["payload"]["version"]
        return version if isinstance(version, int) and not isinstance(version, bool) and version > 0 else 0
    except Exception:
        return 0


def apply_bundle_file(bundle: Path | str, **kw) -> tuple[bool, str]:
    try:
        env, _ = _read_verified_bundle(Path(bundle), kw.get("trusted"))
    except (OSError, ValueError, TypeError, AttributeError, RecursionError) as e:
        return False, f"unreadable bundle: {e}"
    return apply_bundle(env, **kw)


def rollback() -> tuple[bool, str]:
    p = bundle_path()
    prev = p.with_suffix(p.suffix + ".prev")
    from .file_lock import atomic_write_text, cross_process_lock
    with cross_process_lock(p):
        if not prev.exists():
            return False, "no previous constants bundle to roll back to"
        try:
            envelope, payload = _read_verified_bundle(prev)
        except (OSError, ValueError, TypeError, AttributeError, RecursionError):
            return False, "the previous bundle is no longer trusted or could not be verified; nothing changed"
        atomic_write_text(p, json.dumps(envelope, indent=2, default=str), mode=0o600)
        try:
            prev.unlink()
        except OSError:
            log.warning("verified tax rollback applied; the previous copy could not be removed")
    return True, f"rolled back to tax constants v{payload['version']}"


def check_for_update(*, url: str | None = None, force: bool = False,
                     now: float | None = None) -> tuple[str, str]:
    """Fetch + apply a newer bundle from the configured channel.

    Returns ``(status, detail)``; status in ``applied | current | disabled |
    throttled | error``. Throttled to one network check per ``check_hours``;
    never raises (a dead channel must not block a prep run)."""
    try:
        from .config import get_tax
        cfg = get_tax()
    except Exception:  # pragma: no cover
        return "error", "config unavailable"
    url = (url or cfg["update_url"]).strip()
    if not url:
        return "disabled", "no [tax] update_url configured"
    now = now if now is not None else time.time()
    stamp = _store_dir() / _STAMP_NAME
    if not force:
        try:
            if now - float(stamp.read_text()) < cfg["check_hours"] * 3600.0:
                return "throttled", "checked recently"
        except (OSError, ValueError):
            pass
    try:
        stamp.parent.mkdir(parents=True, exist_ok=True)
        stamp.write_text(str(now), encoding="utf-8")
    except OSError:  # pragma: no cover
        pass
    try:
        from .enterprise import enterprise_egress_denial
        deny = enterprise_egress_denial(url, tool="tax_constants_update")
        if deny:
            return "error", deny
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return "error", "the tax update address must use HTTPS without sign-in details"
        from .tools._ssrf import safe_client
        deadline = time.monotonic() + _UPDATE_TIMEOUT_SECONDS
        with safe_client(url, require_public=True, timeout=_UPDATE_TIMEOUT_SECONDS,
                         follow_redirects=False) as client:
            with client.stream("GET", url, headers={"Accept": "application/json",
                                                    "Accept-Encoding": "identity"}) as response:
                if response.status_code != 200:
                    return "error", f"update channel returned {response.status_code}; no bundle was applied"
                if response.headers.get("content-encoding", "identity").strip().lower() not in ("", "identity"):
                    return "error", "the update channel returned a compressed bundle; no bundle was applied"
                body = bytearray()
                for chunk in response.iter_raw():
                    if time.monotonic() >= deadline:
                        return "error", "the update check took too long; no bundle was applied"
                    if len(body) + len(chunk) > _MAX_BUNDLE_BYTES:
                        return "error", "the update bundle exceeds the size limit; no bundle was applied"
                    body.extend(chunk)
                env = json.loads(body)
    except Exception as e:  # noqa: BLE001 -- the channel must never wedge prep
        log.warning("tax constants update check refused (%s)", type(e).__name__)
        return "error", "the tax update could not be read or verified; no bundle was applied"
    ok, reason = apply_bundle(env)
    if ok:
        return "applied", reason
    if "not newer" in reason:
        return "current", reason
    return "error", reason


__all__ = [
    "SCHEMA_VERSION", "bundle_path", "trusted_pubkeys", "validate_payload",
    "active_constants", "active_version", "export_bundle", "apply_bundle",
    "apply_bundle_file", "rollback", "check_for_update",
]

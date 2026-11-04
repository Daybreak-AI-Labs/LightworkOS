"""Shared trust gates for installable catalog items (skills and templates).

Both :mod:`maverick.skills` and :mod:`maverick.templates` install
publisher-supplied content fetched from an unauthenticated host, so both run
the same two-stage trust pipeline before persisting:

  1. an Ed25519 *signed-publisher* check (:func:`verify_signed_catalog_item`),
     anchored on the operator's ``[skills].trusted_pubkeys`` / ``require_signed*``
     policy; and
  2. a *Shield content scan* (:func:`shield_scan`) of the prompt surface, which
     fails open (with a warning) when the Shield is absent or errors.

Keeping them in one place stops the copies drifting apart (a diverging
canonical-bytes binding would break verification). The signing *policy*
genuinely differs between the two callers -- skills allow trust-on-first-use
for free-text installs, templates treat any configured trust anchor as
requiring a signature -- so the shared verifier takes the resolved policy
(``must_verify`` / ``require_anchor``) and the item's canonical signed bytes as
parameters rather than re-deriving config itself. That keeps a single
implementation of the *mechanism* while each caller keeps its own *policy*.
"""
from __future__ import annotations

import logging
from collections.abc import Callable

log = logging.getLogger(__name__)

__all__ = ["verify_signed_catalog_item", "shield_scan"]


def verify_signed_catalog_item(
    *,
    item: str,
    sig: str | None,
    pubkey: str | None,
    canonical_bytes_fn: Callable[[], bytes],
    trusted: list[str],
    must_verify: bool,
    require_anchor: bool,
    fields: str,
) -> bool:
    """Enforce the operator's signed-publisher policy on one catalog item.

    ``item`` is the noun used in error messages ("skill"/"template"). ``sig`` /
    ``pubkey`` are the item's claimed signature, ``canonical_bytes_fn`` produces
    the exact bytes the publisher signed over (each item type binds a different
    field set, named in ``fields`` for the error message), and ``trusted`` is the
    configured publisher allow-list.

    Two policy decisions are supplied by the caller so this stays mechanism-only:

      - ``must_verify`` -- reject an *unsigned* item (the caller's
        ``require_signed`` / ``require_signed_catalog`` / trust-anchor policy);
      - ``require_anchor`` -- reject a *signed* item when no ``trusted_pubkeys``
        anchor is configured (a self-asserted signature is integrity, not
        authenticity).

    Returns ``True`` iff a real Ed25519 signature verified against a trusted
    publisher (the genuine "verified" status); ``False`` means the item installs
    unsigned under trust-on-first-use. Raises ``ValueError`` on any policy
    violation. When ``cryptography`` is absent, a signed item is rejected because
    trust cannot be established safely.
    """
    from .audit import signing

    signed = bool(sig and pubkey)

    if not signed:
        if must_verify:
            raise ValueError(
                f"{item} rejected: it is unsigned, but a verified signature is "
                "required (require_signed / require_signed_catalog or trusted "
                "publishers configured; the file has no 'sig'/'pubkey')."
            )
        return False

    if not signing._have_crypto():
        raise ValueError(
            f"{item} rejected: cryptography is required to verify signed "
            f"{item}s. Install 'maverick-agent[audit-signing]' to enable "
            "signature verification."
        )

    # With no configured trust anchor a self-asserted pubkey verifies its own
    # signature -- integrity, not authenticity. Refuse only when the caller
    # demands an anchored signature; otherwise install unsigned (verified=False).
    if not trusted:
        if require_anchor:
            raise ValueError(
                f"{item} rejected: it is signed, but no [skills].trusted_pubkeys "
                "trust anchor is configured to verify authenticity. A "
                "self-asserted signature cannot be verified as authentic."
            )
        return False

    if pubkey not in trusted:
        raise ValueError(
            f"{item} rejected: signed by an untrusted publisher key "
            f"{pubkey[:16]!r} (not in [skills].trusted_pubkeys)."
        )

    if not signing.verify_ed25519(pubkey, sig, canonical_bytes_fn()):
        raise ValueError(
            f"{item} rejected: Ed25519 signature does not verify over the "
            f"{item}'s signed fields ({fields})."
        )
    return True


def shield_scan(text: str, *, label: str) -> None:
    """Scan untrusted catalog content through the Shield; reject if blocked.

    ``text`` is the prompt surface to scan and ``label`` is the noun used in the
    rejection message (e.g. ``"skill body"`` / ``"template"``). The Shield body
    of an installed item is concatenated into the agent's system prompt, so a
    block here prevents a jailbreak payload from landing verbatim.

    Fail-open by design: when the Shield package is absent, or
    ``Shield.from_config`` / ``scan_input`` raises anything other than a
    ``ValueError``, the scan is skipped with a warning rather than blocking
    installs on a scanner bug. A ``ValueError`` from the scan is a genuine
    rejection and is re-raised.
    """
    try:
        from maverick_shield import Shield  # type: ignore
    except ImportError:
        # Fail open per kernel rule 1, but NOT silently: without the shield
        # extra, this catalog body (skill/persona/template) is concatenated
        # into the agent system prompt UNSCANNED. Warn so operators can see the
        # content-trust control is inactive (matches shield_policy's fail-open
        # logging; the docstring promises fail-open-WITH-a-warning).
        log.warning(
            "content scanning unavailable: maverick_shield is not installed "
            "(install the shield extra); %s admitted unscanned",
            label,
        )
        return
    try:
        verdict = Shield.from_config().scan_input(text)
    except ValueError:
        raise
    except Exception as exc:  # pragma: no cover -- scanner bugs must not brick installs
        log.warning(
            "Shield raised %s while scanning %s; failing open",
            type(exc).__name__,
            label,
        )
        return
    if not verdict.allowed:
        raise ValueError(
            f"{label} rejected by Shield ({verdict.severity}): "
            f"{'; '.join(verdict.reasons)}"
        )

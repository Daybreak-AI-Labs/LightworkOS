"""Sigstore keyless signing for skill/plugin artifacts.

Ed25519 skill signing (``maverick.skills``) binds an artifact to a publisher
*key*; sigstore's keyless flow binds it to a publisher *identity* (an OIDC
account such as a CI workload or maintainer email) with the signature recorded
in a public transparency log. This module signs an artifact file and writes the
sigstore *bundle* (certificate + signature + log proof) alongside it, and
verifies an artifact against a bundle for an expected identity/issuer pair.

Opt-in and dependency-light: the real flow needs the ``sigstore`` package (the
the local ``packages/maverick-core[sigstore]`` extra) plus an OIDC identity (ambient CI
credential or interactive browser flow), and both entry points take an injected
``signer`` / ``verifier`` seam so tests (and embedders) run fully offline with
fakes -- the default implementations are thin lazy adapters over ``sigstore``.

Verification fails CLOSED: a missing artifact or bundle, an unreadable file, a
missing ``sigstore`` install, or any verifier exception (wrong identity, wrong
issuer, bad signature, untrusted log) yields a refusal, never a pass.

CLI::

    python -m maverick.sigstore_signing sign <artifact>
    python -m maverick.sigstore_signing verify <artifact> <bundle> \
        --identity dev@example.com --issuer https://github.com/login/oauth
"""
from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_INSTALL_HINT = (
    "From the reviewed checkout run: python -m pip install -e "
    "'./packages/maverick-core[sigstore]' to enable sigstore keyless signing."
)

# A signer turns artifact bytes into a sigstore bundle (JSON text).
Signer = Callable[[bytes], str]
# A verifier checks (artifact_bytes, bundle_json, identity, issuer) and
# raises on ANY failure; returning means the artifact verified.
Verifier = Callable[[bytes, str, str, str], None]


class SigstoreUnavailable(RuntimeError):
    """The ``sigstore`` package (the [sigstore] extra) is not installed."""


def bundle_path_for(artifact: Path | str) -> Path:
    """The default sibling bundle path: ``<artifact>.sigstore.json``."""
    p = Path(artifact)
    return p.with_name(p.name + ".sigstore.json")


def _default_signer(artifact: bytes) -> str:
    """Keyless-sign ``artifact`` via sigstore. Lazy adapter; never imported
    unless actually used, so the kernel runs without the extra installed.

    Identity comes from an ambient OIDC credential when one is detectable
    (e.g. GitHub Actions) and falls back to sigstore's interactive flow.
    """
    try:
        from sigstore.oidc import IdentityToken, Issuer, detect_credential
        from sigstore.sign import SigningContext
    except ImportError as e:
        raise SigstoreUnavailable(f"sigstore is not installed. {_INSTALL_HINT}") from e

    raw = detect_credential()
    token = IdentityToken(raw) if raw else Issuer.production().identity_token()
    ctx = SigningContext.production()
    with ctx.signer(token) as signer:
        bundle = signer.sign_artifact(artifact)
    return str(bundle.to_json())


def _default_verifier(artifact: bytes, bundle_json: str, identity: str, issuer: str) -> None:
    """Verify ``artifact`` against a sigstore bundle for ``identity``/``issuer``.

    Lazy adapter over ``sigstore``; raises on any failure (the caller treats
    every exception as a refusal -- fail closed).
    """
    try:
        from sigstore.models import Bundle
        from sigstore.verify import Verifier as _SigstoreVerifier
        from sigstore.verify.policy import Identity
    except ImportError as e:
        raise SigstoreUnavailable(f"sigstore is not installed. {_INSTALL_HINT}") from e

    _SigstoreVerifier.production().verify_artifact(
        artifact,
        Bundle.from_json(bundle_json),
        Identity(identity=identity, issuer=issuer),
    )


def sign_artifact(path: Path | str, *, signer: Signer | None = None) -> Path:
    """Keyless-sign the artifact at ``path``; write + return the bundle path.

    The bundle lands at ``bundle_path_for(path)`` next to the artifact, ready
    to ship with it. ``signer`` is the injected seam (offline tests pass a
    fake); the default is the lazy sigstore adapter, which raises
    :class:`SigstoreUnavailable` when the extra is not installed.
    """
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"artifact not found: {p}")
    bundle_json = (signer or _default_signer)(p.read_bytes())
    if not isinstance(bundle_json, str) or not bundle_json.strip():
        raise ValueError("signer returned an empty bundle")
    out = bundle_path_for(p)
    out.write_text(bundle_json, encoding="utf-8")
    return out


@dataclass
class VerificationResult:
    """Outcome of :func:`verify_artifact`. ``ok`` is True only on a real pass."""
    ok: bool
    reason: str
    identity: str
    issuer: str


def verify_artifact(
    path: Path | str,
    bundle_path: Path | str | None = None,
    *,
    identity: str,
    issuer: str,
    verifier: Verifier | None = None,
) -> VerificationResult:
    """Verify an artifact against its sigstore bundle. FAILS CLOSED.

    ``identity``/``issuer`` pin who must have signed (the OIDC subject and the
    issuer that vouched for it); an empty pin, a missing artifact or bundle,
    an unreadable file, and any verifier exception all refuse -- this gate
    never passes by default. ``bundle_path`` defaults to the sibling
    ``bundle_path_for(path)``. ``verifier`` is the injected seam for offline
    tests; the default is the lazy sigstore adapter.
    """
    ident = (identity or "").strip()
    iss = (issuer or "").strip()

    def refused(reason: str) -> VerificationResult:
        log.warning("sigstore verify refused: %s", reason)
        return VerificationResult(ok=False, reason=reason, identity=ident, issuer=iss)

    if not ident or not iss:
        return refused("identity and issuer must both be pinned (got empty)")
    p = Path(path)
    bp = Path(bundle_path) if bundle_path is not None else bundle_path_for(p)
    if not p.is_file():
        return refused(f"artifact not found: {p}")
    if not bp.is_file():
        return refused(f"bundle not found: {bp}")
    try:
        artifact = p.read_bytes()
        bundle_json = bp.read_text(encoding="utf-8")
    except OSError as e:
        return refused(f"unreadable artifact/bundle: {e}")
    try:
        (verifier or _default_verifier)(artifact, bundle_json, ident, iss)
    except Exception as e:  # noqa: BLE001 -- ANY verifier failure refuses (fail closed)
        return refused(f"{type(e).__name__}: {e}")
    return VerificationResult(ok=True, reason="verified", identity=ident, issuer=iss)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m maverick.sigstore_signing",
        description="Sigstore keyless signing for skill/plugin artifacts.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_sign = sub.add_parser("sign", help="keyless-sign an artifact (writes <artifact>.sigstore.json)")
    p_sign.add_argument("artifact", help="path to the artifact file to sign")

    p_verify = sub.add_parser("verify", help="verify an artifact against a sigstore bundle")
    p_verify.add_argument("artifact", help="path to the artifact file")
    p_verify.add_argument("bundle", help="path to the sigstore bundle (JSON)")
    p_verify.add_argument("--identity", required=True, help="expected signer identity (OIDC subject)")
    p_verify.add_argument("--issuer", required=True, help="expected OIDC issuer URL")

    args = parser.parse_args(argv)
    if args.cmd == "sign":
        try:
            out = sign_artifact(args.artifact)
        except (SigstoreUnavailable, FileNotFoundError, ValueError) as e:
            print(f"sign failed: {e}", file=sys.stderr)
            return 2
        print(f"signed: bundle written to {out}")
        return 0

    result = verify_artifact(
        args.artifact, args.bundle, identity=args.identity, issuer=args.issuer,
    )
    if result.ok:
        print(f"OK: verified for identity={result.identity} issuer={result.issuer}")
        return 0
    print(f"REFUSED: {result.reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":  # pragma: no cover -- exercised via main() in tests
    raise SystemExit(main())


__all__ = [
    "SigstoreUnavailable",
    "VerificationResult",
    "bundle_path_for",
    "sign_artifact",
    "verify_artifact",
    "main",
]

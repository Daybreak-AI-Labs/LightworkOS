"""Canonical product-guarantee proofs — the real roster through the real
enforcement code.

Each function drives the *shipped* domain packs through the *same* primitives
the production tool chokepoint (``agent._run_tool``) calls, and returns a
human-readable detail string (raising :class:`AssertionError` on a broken
guarantee). This is the single source of truth shared by two surfaces:

* ``proof/run_proof.py`` — the standalone scoreboard CLI.
* :mod:`maverick.proof_pack` — the signed, reproducible evidence bundle.

Five guarantees run anywhere; two cryptographic ones (Ed25519) need
``cryptography`` and are reported as CI-verified otherwise. :func:`run_all`
wraps them into structured :class:`GuaranteeResult` rows for the bundle.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass


def _crypto_ok() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: F401
        return True
    except BaseException:
        return False


def _finance(d):
    return {k: v for k, v in d.items() if k.startswith("finance_")}


def _check(condition: bool, message: object) -> None:
    """Raise even when Python assertions are disabled with -O/PYTHONOPTIMIZE."""
    if not condition:
        raise AssertionError(message)


# --- the guarantees -------------------------------------------------------

def claim_least_privilege():
    """A deployed specialist runs sealed + attenuated, never the parent's reach."""
    from .capability import Capability
    from .domain import builtin_dir, domain_capability, load_domains
    d = load_domains(builtin_dir())
    parent = Capability(principal="agent:finance_controller-0", max_risk="high")
    cap = domain_capability(d["finance_ap"], parent, "agent:finance_ap-1")
    _check(cap.max_risk != "high", "pack did not narrow the parent ceiling")
    _check(cap.permits("billdotcom_read"), "can't do its job (read AP)")
    _check(not cap.permits("shell"), "leaked the parent's arbitrary reach")
    _check(not cap.permits("release_payment"), "custody seal broken")
    return f"finance_ap runs at max_risk={cap.max_risk!r} (parent=high): reads AP, no shell, no payments"


def claim_no_money_without_a_human():
    """Across the WHOLE finance roster, no attenuated grant can move money/post."""
    from .capability import Capability
    from .domain import builtin_dir, domain_capability, load_domains
    money = ("wire_transfer", "release_payment", "post_journal_entry", "run_payroll",
             "ach_send", "send_payment", "file_with_sec", "place_trade")
    d = _finance(load_domains(builtin_dir()))
    parent = Capability(principal="agent:finance_controller-0", max_risk="high")
    for name, prof in d.items():
        cap = domain_capability(prof, parent, f"agent:{name}-1")
        for m in money:
            _check(not cap.permits(m), f"{name} permits money tool {m!r}")
    return f"no money/posting tool is permitted by any of {len(d)} finance packs"


def claim_dollar_tier_authority_gate():
    """The org policy's delegation-of-authority tiers actually fire."""
    from .governance import Decision, Policy, evaluate
    p = Policy(require_human_above={"release_payment": 5000.0},
               deny_above={"wire_transfer": 50000.0})
    auto = evaluate("release_payment", policy=p, amount=4000, currency="USD")
    human = evaluate("release_payment", policy=p, amount=6000, currency="USD")
    denied = evaluate("wire_transfer", policy=p, amount=60000, currency="USD")
    _check(auto.decision is Decision.ALLOW, auto)
    _check(human.decision is Decision.REQUIRE_HUMAN, human)
    _check(denied.decision is Decision.DENY, denied)
    return f"$4k release auto, $6k release -> REQUIRE_HUMAN, $60k wire -> DENY (rule={denied.rule})"


def claim_fleet_can_read_but_not_write():
    """A specialist can reach a real low-risk vendor READ seat; the write seat is denied."""
    from .capability import Capability
    from .domain import builtin_dir, domain_capability, load_domains
    from .tools.enterprise_connectors import enterprise_connectors
    tools = {t.name: t for t in enterprise_connectors()}
    refused = tools["billdotcom_read"].fn({"op": "post", "path": "/x", "confirm": True})
    _check("read-only" in refused, "read seat accepted a write")
    cap = domain_capability(load_domains(builtin_dir())["finance_ap"],
                            Capability(principal="agent:finance_controller-0", max_risk="high"),
                            "agent:finance_ap-1")
    _check(
        cap.permits("billdotcom_read") and not cap.permits("billdotcom"),
        "finance_ap capability grants unexpected Bill.com access",
    )
    return "finance_ap reaches billdotcom_read (GET-only); the write connector is refused + capability-denied"


def claim_segregation_of_duties_clean():
    """The finance roster is SoD-clean: no seal spans record/authorize/custody."""
    from .domain import builtin_dir, load_domains
    from .finance.sod_linter import lint_roster
    d = _finance(load_domains(builtin_dir()))
    conflicts = lint_roster(d)
    _check(not conflicts, f"{len(conflicts)} SoD conflict(s): {conflicts[:2]}")
    return f"all {len(d)} finance packs SoD-clean (no compartment unions incompatible duties)"


def claim_handoffs_are_verified():
    """A peer handoff is signed + verified; a tampered copy is rejected."""
    from .bus_handoff import HandoffAuthority
    from .capability import Capability
    auth = HandoffAuthority.for_run()
    grant = Capability(principal="agent:finance_fpa-1",
                       allow_tools=frozenset({"ap_read_invoice"}), max_risk="low")
    env = auth.mint(sender="agent:finance_ap-1", recipient="agent:finance_fpa-1",
                    grant=grant, task="read the invoice")
    ok = auth.verify(env)
    bad = auth.verify(dataclasses.replace(env, task="wire the funds out"))
    _check(ok.ok and ok.grant.permits("ap_read_invoice"), ok)
    _check(not bad.ok and bad.rule == "tampered", bad)
    return f"authentic handoff verifies (rule={ok.rule}); tampered copy rejected (rule={bad.rule})"


def claim_audit_is_tamper_evident():
    """The action ledger is a signed hash-chain: altering a row breaks verification.

    This probe detects an edited row whose signature was not recomputed. Both
    co-located and externally supplied private keys remain available to the
    signing process. Injection or local KMS unwrap does not establish isolated
    signing or exclude re-signing by an actor with access to that process.
    """
    import tempfile
    from pathlib import Path

    from .audit import signing
    # KEY_DIR is a module global; this guarantee runs IN-PROCESS (via proof_pack),
    # so restore it or the dangling temp path leaks into later tests' audit probes.
    saved_key_dir = signing.KEY_DIR
    try:
        with tempfile.TemporaryDirectory() as td:
            signing.KEY_DIR = Path(td) / "keys"
            path = Path(td) / "audit.ndjson"
            signer = signing.AuditSigner(path)
            signer.write({"event": "release_payment", "amount": 6000, "decision": "REQUIRE_HUMAN"})
            signer.write({"event": "human_approval", "by": "cfo", "decision": "approved"})
            clean = signing.verify_chain(path, signer.public_key_hex)
            _check(not clean, f"clean chain reported breaks: {clean}")
            rows = path.read_text().splitlines()
            path.write_text("\n".join(rows).replace('"amount": 6000', '"amount": 60') + "\n")
            broken = signing.verify_chain(path, signer.public_key_hex)
            _check(broken, "tampering an audited row was NOT detected")
            base = ("2-row signed chain verifies clean; altering an amount is "
                    f"caught ({broken[0].reason})")
            if signing.active_key_is_offhost():
                return (base + "; externally supplied private key remains available to "
                        "the signing process; this does not prove isolated signing. "
                        "Independently retained checkpoints can expose later history changes")
            return (base + " -- co-located key: detects non-privileged edits only, "
                    "NOT tamper-evidence vs a same-uid actor. Independently retained "
                    "checkpoints can expose later history changes")
    finally:
        signing.KEY_DIR = saved_key_dir


def _audit_ledger_label() -> str:
    """Label for the audit-ledger guarantee, honest about signing-key custody.

    External key sourcing avoids leaving a generated private key on local disk;
    it does not isolate the signing operation from the application process.
    """
    try:
        from .audit import signing
        offhost = signing.active_key_is_offhost()
    except BaseException:
        offhost = False
    if offhost:
        return "Audit ledger integrity (externally supplied key)"
    return "Audit ledger integrity (co-located key)"


# label, fn, needs_crypto
GUARANTEES = [
    ("Least privilege by construction", claim_least_privilege, False),
    ("No money without a human", claim_no_money_without_a_human, False),
    ("Delegation-of-authority $ gate", claim_dollar_tier_authority_gate, False),
    ("Fleet can read, not write", claim_fleet_can_read_but_not_write, False),
    ("Segregation of duties clean", claim_segregation_of_duties_clean, False),
    ("Verified peer handoffs", claim_handoffs_are_verified, True),
    ("Audit ledger integrity", claim_audit_is_tamper_evident, True),
]


@dataclass(frozen=True)
class GuaranteeResult:
    label: str
    passed: bool
    detail: str
    needs_crypto: bool
    skipped: bool = False  # crypto-gated and crypto absent: verified in CI, not here

    def to_dict(self) -> dict:
        return {
            "label": self.label, "passed": self.passed, "detail": self.detail,
            "needs_crypto": self.needs_crypto, "skipped": self.skipped,
        }


def run_all(*, crypto: bool | None = None) -> list[GuaranteeResult]:
    """Run every guarantee; return structured results (never raises).

    A crypto-gated guarantee with ``cryptography`` absent is recorded as
    ``skipped`` (verified in the CI matrix) — neither a pass nor a failure.
    """
    crypto = _crypto_ok() if crypto is None else crypto
    results: list[GuaranteeResult] = []
    for label, fn, needs_crypto in GUARANTEES:
        if needs_crypto and not crypto:
            # Not proven on THIS host (cryptography absent) -> passed=False +
            # skipped=True, matching this function's "neither a pass nor a
            # failure" contract. Consumers must treat `skipped` as a third state
            # (proof_pack does); the Ed25519 path is exercised in the CI matrix.
            results.append(GuaranteeResult(
                label, False,
                "SKIPPED on this host: cryptography not installed "
                "(Ed25519 path verified in the CI test matrix)",
                needs_crypto=True, skipped=True))
            continue
        try:
            detail = fn()
            # Key sourcing does not establish isolated signing. Describe the
            # observed integrity check without asserting same-host resistance.
            row_label = _audit_ledger_label() if fn is claim_audit_is_tamper_evident else label
            results.append(GuaranteeResult(row_label, True, detail, needs_crypto))
        except BaseException as e:  # a proof must report its own failure
            results.append(GuaranteeResult(
                label, False, f"{type(e).__name__}: {e}", needs_crypto))
    return results


__all__ = ["GuaranteeResult", "GUARANTEES", "run_all", "_crypto_ok", "_check"]

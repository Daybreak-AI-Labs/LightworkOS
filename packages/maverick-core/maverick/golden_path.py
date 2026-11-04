"""Golden path — a five-minute walkthrough of governance with its audit trail.

A seeded, no-LLM scenario that drives the REAL governance / capability / audit /
budget code through a treasury-ops storyline and emits a narrated transcript
plus the actual tamper-evident audit records. In one command it shows the
platform letting routine work through, STOPPING the dangerous move, and leaving
a signed, verifiable trail either way.

    python -m maverick.golden_path [-o OUTDIR]

Writes ``OUTDIR/GOLDEN_PATH.md`` (the narrated story) and ``OUTDIR/audit.ndjson``
(the signed hash-chain). Every verdict here comes from real enforcement code —
nothing is mocked and no model is called. Distinct from
:mod:`maverick.proof_pack` (which checks the guarantees in aggregate); this is
the human-readable walkthrough of the same behaviour.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

_PARENT = "agent:finance_controller-0"
_SPECIALIST = "agent:finance_ap-1"


@dataclass
class Step:
    scene: str
    request: str
    verdict: str
    evidence: str


@dataclass
class Scenario:
    steps: list[Step]
    chain_clean: bool
    break_reason: str
    pubkey_hex: str = ""


def run_scenario(audit_path: Path, *, key_dir: Path) -> Scenario:
    """Drive the real enforcement code, write signed audit rows, and return the
    narrated steps plus the tamper-evidence result."""
    from .audit import signing
    from .budget import Budget, BudgetExceeded
    from .capability import Capability
    from .domain import builtin_dir, domain_capability, load_domains
    from .governance import Policy, evaluate
    from .llm import MODEL_SONNET

    # KEY_DIR is a module global; restore it so an in-process call (e.g. the test)
    # never leaks this run's key dir into later audit probes.
    saved_key_dir = signing.KEY_DIR
    signing.KEY_DIR = key_dir
    try:
        signer = signing.AuditSigner(audit_path)
        steps: list[Step] = []

        # 1. The specialist boots sealed + attenuated (real capability narrowing).
        parent = Capability(principal=_PARENT, max_risk="high")
        cap = domain_capability(load_domains(builtin_dir())["finance_ap"], parent, _SPECIALIST)
        steps.append(Step(
            "An AP specialist boots under the controller",
            "inherit the controller's full reach",
            "SEALED",
            f"runs at max_risk={cap.max_risk!r} (parent was 'high'); can read AP "
            f"(billdotcom_read={cap.permits('billdotcom_read')}), cannot open a shell "
            f"({cap.permits('shell')}), cannot release payments "
            f"({cap.permits('release_payment')})",
        ))
        signer.write({"event": "agent_boot", "principal": _SPECIALIST,
                      "max_risk": cap.max_risk, "sealed": True})

        policy = Policy(require_human_above={"release_payment": 5000.0},
                        deny_above={"wire_transfer": 50000.0})

        # 2-4. Three money requests through the real delegation-of-authority gate.
        for action, amount, scene in [
            ("wire_transfer", 60000, "A 'vendor' asks for a $60,000 wire"),
            ("release_payment", 6000, "The agent moves to release a $6,000 invoice"),
            ("release_payment", 4000, "The agent moves to release a $4,000 invoice"),
        ]:
            d = evaluate(action, policy=policy, amount=float(amount), currency="USD")
            steps.append(Step(scene, f"{action} ${amount:,}", d.decision.name,
                              f"governance policy fired rule={d.rule!r}"))
            signer.write({"event": "governance_decision", "action": action,
                          "amount": amount, "decision": d.decision.name, "rule": d.rule})

        # 5. A runaway loop hits the hard budget ceiling (real BudgetExceeded).
        budget = Budget(max_dollars=0.10)
        budget.record_tokens(2000, 500, model=MODEL_SONNET)  # routine work, under cap
        capped = False
        try:
            budget.record_tokens(0, 2_000_000, model=MODEL_SONNET)  # a runaway
        except BudgetExceeded:
            capped = True
        steps.append(Step(
            "A runaway loop tries to keep spending",
            "burn past the $0.10 ceiling",
            "CAPPED" if capped else "NOT CAPPED",
            f"hard budget ceiling held ({budget.summary()})"))
        signer.write({"event": "budget_ceiling", "cap_held": capped})

        # 6. The receipts are tamper-evident.
        clean_breaks = signing.verify_chain(audit_path, signer.public_key_hex)
        tampered = audit_path.with_name("audit.tampered.ndjson")
        tampered.write_text(
            audit_path.read_text().replace('"amount": 60000', '"amount": 60'),
            encoding="utf-8")
        breaks = signing.verify_chain(tampered, signer.public_key_hex)
        tampered.unlink()
        reason = breaks[0].reason if breaks else "(none — UNEXPECTED)"
        steps.append(Step(
            "An auditor checks the trail",
            "verify the signed chain, then alter one amount",
            "TAMPER-EVIDENT",
            f"the authentic chain verifies clean ({not clean_breaks}); "
            f"silently changing $60,000 to $60 is caught ({reason})"))

        return Scenario(steps=steps, chain_clean=not clean_breaks, break_reason=reason,
                        pubkey_hex=signer.public_key_hex)
    finally:
        signing.KEY_DIR = saved_key_dir


def render(scenario: Scenario, audit_path: Path) -> str:
    lines = [
        "# Lightwork — Golden Path (the receipts)",
        "",
        "One seeded run of a finance specialist under governance. No model is "
        "called; every verdict below is the **real** enforcement code, and every "
        "step left a signed, verifiable audit row.",
        "",
        "| # | scene | the agent asks to… | verdict | receipt |",
        "|---|---|---|---|---|",
    ]
    for i, s in enumerate(scenario.steps, 1):
        ev = s.evidence.replace("|", "\\|")
        lines.append(f"| {i} | {s.scene} | {s.request} | **{s.verdict}** | {ev} |")
    verify_cmd = f"maverick audit verify --file {audit_path.name}"
    if scenario.pubkey_hex:
        verify_cmd += f" --pubkey {scenario.pubkey_hex}"
    lines += [
        "",
        "## What just happened",
        "- The specialist **booted sealed** — it physically cannot open a shell or "
        "move money, even though its parent could (least privilege by construction).",
        "- Routine work passed; the **$60k wire was DENIED** and the **$6k release "
        "required a human** — the dollar-tier authority gate, not a prompt.",
        "- A runaway loop **hit the hard budget ceiling** and stopped.",
        "- Every decision is a row in a **signed hash-chain**: altering one amount "
        f"is caught (`{scenario.break_reason}`).",
        "",
        f"Verify it yourself — from `{audit_path.parent.name}/`, a third party needs "
        f"only the public key (no access to Lightwork):\n\n    {verify_cmd}\n",
        "",
    ]
    return "\n".join(lines)


def _default_out_dir() -> Path:
    from .paths import data_dir
    return data_dir("golden_path")


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(
        prog="maverick.golden_path",
        description="Run the seeded governance walkthrough and emit the receipts.")
    p.add_argument("-o", "--out", default=None, help="output directory")
    args = p.parse_args(argv)

    out_dir = Path(args.out) if args.out else _default_out_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    audit_path = out_dir / "audit.ndjson"
    scenario = run_scenario(audit_path, key_dir=out_dir / "keys")
    md = render(scenario, audit_path)
    (out_dir / "GOLDEN_PATH.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"\nreceipts written to {out_dir}/ (story + signed audit.ndjson)")
    return 0


__all__ = ["Step", "Scenario", "run_scenario", "render", "main"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

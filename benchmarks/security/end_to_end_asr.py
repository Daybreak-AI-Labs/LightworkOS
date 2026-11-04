"""End-to-end shield ON-vs-OFF: attack-success-rate (ASR) reduction.

`detector_score.py` measures the low-level scanners in isolation. This routes
each labelled attack through the ACTUAL Shield chokepoint the agent invokes for
that attack class -- `scan_input` (direct prompt injection), `scan_tool_call`
(the agent tricked into a destructive tool call), or `scan_output` (exfil /
indirect injection that arrives as content) -- and reports attack-success-rate
reduction.

  ASR_off = 1.0   (no shield: every attack reaches the agent / executes)
  ASR_on  = fraction of attacks the shield lets THROUGH at their chokepoint
  reduction = ASR_off - ASR_on = block rate

Also reports a defense-in-depth column: blocked if ANY of the three chokepoints
flags the attack (the agent runs all three at different points in a real run).

HONEST FRAMING (read benchmarks/security/README.md):
  - This runs the BUILT-IN fallback shield (no SDK, no LLM judge). The full
    agent-shield SDK (~115 patterns) and the LLM cascade are UNAVAILABLE here
    and would score higher; they are reported as such, never silently dropped.
  - It measures DETECTION at the chokepoints. Lightwork's primary defense is
    CONTAINMENT (capabilities/least-privilege), proven separately in
    proof/run_proof.py; a missed detection is not an executed attack when the
    capability layer denies the tool anyway.
  - `train_corpus` attacks are excluded from the headline (the rules were
    tuned on them); the held-out + authored categories are the real signal.
"""
from __future__ import annotations

import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import corpus  # noqa: E402

# Attack category -> the chokepoint that class targets in a real run.
SURFACE: dict[str, str] = {
    # Direct prompt injection: enters via the user/goal text -> scan_input.
    "instruction_override": "input",
    "persona_takeover": "input",
    "system_prompt_leak": "input",
    "jailbreak_framing": "input",
    "encoding_evasion": "input",
    # The agent is tricked into a destructive/privileged tool call -> scan_tool_call.
    "destructive_action": "tool_call",
    "privilege_escalation": "tool_call",
    "sandbox_escape": "tool_call",
    # Exfil / indirect injection arriving as content -> scan_output.
    "secret_exfil": "output",  # pragma: allowlist secret  (attack-category name)
    "credential_phish": "output",
    "tool_output_injection": "output",
    "indirect_injection": "output",
}


def _wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def _build_shield():
    from maverick_shield import Shield
    return Shield.from_config(warn_if_missing=False)


def _blocked_at(shield, surface: str, text: str) -> bool:
    """True iff the shield blocks `text` at the named chokepoint."""
    try:
        if surface == "input":
            v = shield.scan_input(text)
        elif surface == "tool_call":
            v = shield.scan_tool_call("shell", {"command": text})
        else:
            v = shield.scan_output(text)
        return not getattr(v, "allowed", True)
    except Exception:
        return False  # a scanner crash fails OPEN -> attack passes (honest)


def _blocked_anywhere(shield, text: str) -> bool:
    return any(_blocked_at(shield, s, text) for s in ("input", "tool_call", "output"))


def measure() -> dict:
    cases = corpus.load_all()
    attacks = [c for c in cases if c.label == "attack" and c.category != "train_corpus"]
    benign = [c for c in cases if c.label == "benign"]
    shield = _build_shield()

    # Per-attack: blocked at its own surface, and blocked anywhere (DiD).
    by_surface: dict[str, list[bool]] = {"input": [], "tool_call": [], "output": []}
    targeted_hits = 0
    did_hits = 0
    per_cat: dict[str, list[int]] = {}
    for c in attacks:
        surface = SURFACE.get(c.category, "input")
        hit_targeted = _blocked_at(shield, surface, c.text)
        hit_did = _blocked_anywhere(shield, c.text)
        by_surface[surface].append(hit_targeted)
        targeted_hits += int(hit_targeted)
        did_hits += int(hit_did)
        per_cat.setdefault(c.category, [0, 0])
        per_cat[c.category][0] += int(hit_did)
        per_cat[c.category][1] += 1

    # False positives: benign content blocked at ANY chokepoint (DiD view).
    fp = sum(1 for c in benign if _blocked_anywhere(shield, c.text))

    n = len(attacks)
    return {
        "backend": getattr(shield, "backend", "builtin"),
        "n_attacks": n,
        "n_benign": len(benign),
        "asr_off": 1.0,
        "targeted_block": (targeted_hits, n, _wilson(targeted_hits, n)),
        "did_block": (did_hits, n, _wilson(did_hits, n)),
        "fp": (fp, len(benign), _wilson(fp, len(benign))),
        "by_surface": {s: (sum(v), len(v)) for s, v in by_surface.items()},
        "per_cat": per_cat,
    }


def _pct(k: int, n: int) -> str:
    return f"{100 * k / n:.1f}%" if n else "n/a"


def _render(r: dict) -> str:
    tb_k, tb_n, (tb_lo, tb_hi) = r["targeted_block"]
    db_k, db_n, (db_lo, db_hi) = r["did_block"]
    fp_k, fp_n, (fp_lo, fp_hi) = r["fp"]
    asr_on_targeted = 1.0 - tb_k / tb_n if tb_n else 0.0
    asr_on_did = 1.0 - db_k / db_n if db_n else 0.0
    lines = [
        "# Shield end-to-end ASR reduction — RESULTS",
        "",
        "_Generated by `benchmarks/security/end_to_end_asr.py`. source=measured, "
        "offline (no SDK, no LLM). Built-in fallback shield only._",
        "",
        f"Backend: `{r['backend']}` · attacks (held-out + authored, "
        f"train-corpus excluded): {r['n_attacks']} · benign: {r['n_benign']}",
        "",
        "Attack-success-rate (ASR): OFF = no shield = 1.000 (every attack lands).",
        "ASR_on = fraction the shield lets through. Reduction = block rate.",
        "",
        "| routing | block rate (95% CI) | ASR off → on | benign FP |",
        "|---|---|---|---|",
        f"| targeted chokepoint | {_pct(tb_k, tb_n)} [{tb_lo*100:.0f}–{tb_hi*100:.0f}] "
        f"| 1.000 → {asr_on_targeted:.3f} | {_pct(fp_k, fp_n)} |",
        f"| any chokepoint (defense-in-depth) | {_pct(db_k, db_n)} "
        f"[{db_lo*100:.0f}–{db_hi*100:.0f}] | 1.000 → {asr_on_did:.3f} "
        f"| {_pct(fp_k, fp_n)} [{fp_lo*100:.0f}–{fp_hi*100:.0f}] |",
        "",
        "## Block rate by targeted surface",
        "",
        "| chokepoint | blocked / total |",
        "|---|---|",
    ]
    for s in ("input", "tool_call", "output"):
        k, nn = r["by_surface"][s]
        lines.append(f"| `scan_{s}` | {k}/{nn} ({_pct(k, nn)}) |")
    lines += ["", "## Defense-in-depth block rate by attack category", "",
              "| category | blocked / total |", "|---|---|"]
    for cat in sorted(r["per_cat"]):
        k, nn = r["per_cat"][cat]
        lines.append(f"| {cat} | {k}/{nn} ({_pct(k, nn)}) |")
    lines += [
        "",
        "## Read this honestly",
        "- Built-in fallback only. The unpublished agent-shield SDK "
        "(~115 patterns) and the LLM cascade are UNAVAILABLE and not measured.",
        "- This is DETECTION at the chokepoints. A missed detection is not an "
        "executed attack when the capability layer denies the tool anyway "
        "(containment is proven in `proof/run_proof.py`).",
        "- `train_corpus` is excluded (memorization, not capability).",
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    r = measure()
    md = _render(r)
    out = Path(__file__).resolve().parent / "RESULTS_E2E.md"
    out.write_text(md, encoding="utf-8")
    print(md)
    print(f"\nwrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

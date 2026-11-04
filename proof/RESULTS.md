# Lightwork — Proof & Results

> These checks exercise Lightwork's governance properties against the shipped
> pack roster through the same enforcement code the runtime uses. They need no
> model provider. They are not an ROI figure or a capability benchmark (see
> [What these results do not show](#what-these-results-do-not-show)).

---

## 1. Platform guarantees — `python proof/run_proof.py`

Seven checks run against the **real shipped roster** through the **same
enforcement primitives** the production tool chokepoint calls:

```
  [PASS]  Least privilege by construction   finance_ap runs at max_risk='medium' (parent=high): reads AP, no shell, no payments
  [PASS]  No money without a human          no money/posting tool is permitted by any of 70 finance packs
  [PASS]  Delegation-of-authority $ gate    $4k release auto, $6k release -> REQUIRE_HUMAN, $60k wire -> DENY (rule=deny_above)
  [PASS]  Fleet can read, not write         finance_ap reaches billdotcom_read (GET-only); the write connector is refused + capability-denied
  [PASS]  Segregation of duties clean       all 70 finance packs SoD-clean (no compartment unions incompatible duties)
  [PASS]  Verified peer handoffs            authentic handoff verifies (rule=ok); tampered copy rejected (rule=tampered)
  [PASS]  Audit ledger integrity (co-located key)   2-row signed chain verifies clean; altering an amount is caught (bad_hash) -- co-located key: detects non-privileged edits only, NOT tamper-evidence vs a same-uid actor (set MAVERICK_AUDIT_SIGNING_KEY for off-host key custody)
  ----------------------------------------------------------------------------
  7 checks passed, 0 failed
```

> **Audit-ledger custody caveat.** The signed (Ed25519) hash-chain always
> *detects* an altered row, so the guarantee passes on integrity grounds. But by
> default the Ed25519 key is **co-located** on the host under
> `~/.maverick/audit/keys`, readable by the same uid that runs the agent — so it
> is tamper-evidence against accidental or non-privileged edits, **not** against
> an actor (a prompt-injected or self-modifying agent) running as the maverick
> uid, who can read the key and cleanly re-sign the chain. The headline upgrades
> to **"Tamper-evident audit ledger"** only when signing-key custody is moved
> **off-host** — set `MAVERICK_AUDIT_SIGNING_KEY` (a KMS / secrets-manager-sourced
> key) or `MAVERICK_AUDIT_SIGNING_KEY_WRAPPED` (a KMS-wrapped key), which
> enterprise mode requires. Third-party tamper-evidence additionally needs the
> verifier to hold the publisher's key out-of-band (see the verify commands
> below).

## 2. Signed evidence bundle — `python -m maverick.proof_pack`

One command emits an **Ed25519-signed, reproducible** bundle (`PROOF.md` +
`proof_manifest.json`). Verdict from a clean run:

```
**ALL HARD GUARANTEES HOLD.** Hard guarantees: governance, reliability, perf_sla.

| section            | status              | evidence |
|--------------------|---------------------|----------|
| governance (hard)  | PASS                | 7 checks passed     |
| reliability (hard) | PASS                | chaos game-day exit 0; plugin 1500 calls 88.8% success; 16 writers x 25 rows: 400 written, 0 errors |
| perf_sla (hard)    | PASS                | dispatch p95 0.475ms (<=5); compaction 0.687ms (<=250); world write p95 0.534ms (<=25); world read p95 19.1ms (<=25) |
| shield_asr         | SKIPPED             | offline shield-ASR harness is repo-only |
| learning_curve     | INSUFFICIENT DATA   | no recorded run history yet — populates after real goals + `maverick dream` |
| benchmarks         | NOT RUN (needs key) | competitive scores require a provider key — reported NOT_RUN, never fabricated |
```

**Why the SKIPPED / INSUFFICIENT / NOT-RUN lines matter:** the bundle reports
exactly what it can and cannot prove on a given machine, and **refuses to invent
a number**. The hard guarantees (governance, reliability, performance) gate the
verdict and pass on real code; the competitive and learning-curve sections are
honestly empty until a real deployment populates them.

## 3. Golden path — `python -m maverick.golden_path`

A seeded finance-ops storyline through the real governance/capability/audit/
budget code (no model), emitting a narrated story + a signed audit chain:

| # | scene | verdict | receipt |
|---|---|---|---|
| 1 | AP specialist boots under the controller | **SEALED** | max_risk high→medium · cannot shell · cannot release payments |
| 2 | $60,000 wire | **DENY** | rule = deny_above |
| 3 | $6,000 release | **REQUIRE_HUMAN** | rule = require_human_above |
| 4 | $4,000 release | **ALLOW** | rule = default |
| 5 | runaway loop | **CAPPED** | hard budget ceiling held |
| 6 | auditor alters $60,000 → $60 | **CAUGHT** | signed hash-chain broken (bad_hash) |

## Reproduce & verify (≈1 minute, no provider key)

```bash
# from a source checkout
python proof/run_proof.py                     # 7 platform checks
python -m maverick.golden_path -o ./gp        # narrated story + signed audit.ndjson
python -m maverick.proof_pack -o ./proof      # signed evidence bundle

# verify the signed audit chain offline (third-party tamper-evidence)
maverick audit verify --file ./gp/audit.ndjson --pubkey <publisher-ed25519-hex>
# verify the proof bundle's signature
python -m maverick.proof_pack --verify ./proof/proof_manifest.json --pubkey <publisher-ed25519-hex>
```

## What these results do not show

- **No competitive capability benchmark.** These proofs measure governance
  properties, not agent task success, so no leaderboard result is presented
  here.
- **No ROI figure** until a real deployment produces one — the
  `learning_curve` section stays `INSUFFICIENT DATA` rather than estimate.
- **No fabricated security score.** `shield_asr` measures the *built-in*
  fallback detector; the load-bearing defense is **containment** (least
  privilege), checked under §1.

> Environment for the runs above: Python 3.11 on Linux; `cryptography` present
> (Ed25519 guarantees ran live, not CI-deferred). Results are reproducible on
> any source checkout.

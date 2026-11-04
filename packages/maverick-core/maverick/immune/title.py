"""Discovery Title: evidence that a machine-assisted discovery can be owned.

US inventorship (USPTO revised guidance, Nov 2025) turns on *human conception*;
the AI is a tool. A swarm that produces a result nobody conceived yields
nothing to patent, and developing a secret on a third party's service can
defeat trade-secret protection. A title dossier records, as the work happens:

* **inputs** -- digests of every dataset, prompt and model, committed *before*
  the run (you cannot later prove what did not go in; you can prove what did);
* **priority** -- commit-reveal digests of intermediate ideas with timestamps,
  so priority can be shown without disclosing the idea;
* **conception gates** -- the human decisions (framing, selection, modification)
  and the claim elements each one conceived;
* **verification** -- independent checkers' results;
* **coverage** -- how much of the search space was actually examined.

:func:`problems` reports what would not survive scrutiny (an unconceived claim
element, a failed check, a late input commitment). It is evidence for counsel,
not a legal opinion. :func:`seal` signs the dossier; :func:`verify` checks it
offline against a public key.
"""
from __future__ import annotations

import hashlib
import secrets

from ..constant_time import text_equals
from . import _ledger

SCHEMA = "lightwork.discovery-title.v1"
# Recognising or accepting an AI output is not conception; shaping it is.
CONCEPTION_DECISIONS = frozenset({"framed", "selected", "modified", "conceived"})


def commit(content: str) -> dict[str, str]:
    """A hiding commitment. Publish ``commitment``; keep ``salt`` private."""
    salt = secrets.token_hex(32)
    digest = hashlib.sha256(bytes.fromhex(salt) + content.encode()).hexdigest()
    return {"commitment": digest, "salt": salt}


def opens(commitment: str, salt: str, content: str) -> bool:
    digest = hashlib.sha256(bytes.fromhex(salt) + content.encode()).hexdigest()
    return text_equals(digest, commitment)


def conception_map(dossier: dict) -> dict[str, list[str]]:
    """Claim element -> ids of the human gates that conceived it."""
    out = {e: [] for c in dossier["claims"] for e in c["elements"]}
    for gate in dossier["gates"]:
        if gate["decision"] in CONCEPTION_DECISIONS:
            for e in gate["elements"]:
                if e in out:
                    out[e].append(gate["id"])
    return out


def problems(dossier: dict) -> list[str]:
    """Everything a patent examiner, litigator or auditor could attack."""
    out = [f"claim element without human conception: {e}"
           for e, gates in sorted(conception_map(dossier).items()) if not gates]
    if not dossier.get("problem", {}).get("signed_off_by"):
        out.append("problem statement not signed off by a human")
    checks = dossier.get("verification", [])
    if not checks:
        out.append("no independent verification recorded")
    out += [f"verification failed: {v['checker']}" for v in checks if not v["passed"]]
    cov = dossier.get("coverage") or {}
    if not cov.get("total"):
        out.append("search coverage unknown")
    elif cov["examined"] < cov["total"]:
        out.append(f"search coverage {cov['examined']}/{cov['total']} "
                   f"({cov['examined'] / cov['total']:.0%})")
    out += [f"conception gate rests on an unverified research export: {g['id']}"
            for g in dossier.get("gates", [])
            if str(g.get("id", "")).startswith("research:") and g.get("verified") is not True]
    first = min((p["at"] for p in dossier.get("priority", [])), default=None)
    if first is not None and dossier.get("inputs_committed_at", float("inf")) > first:
        out.append("inputs were committed after the first recorded idea")
    return out


def _sha(obj: object) -> str:
    return hashlib.sha256(_ledger.canonical(obj)).hexdigest()


def research_run_evidence(run: dict, elements: list[str] = (), *,
                          verified: bool = False) -> dict:
    """Inputs and conception gates read from a governed research run.

    ``run`` is a run record (``ResearchRuns.inspect``) or its export. The run
    ledger already records, hash-chained, which named user planned each
    attempt and when; every ``planned`` event becomes a ``framed`` gate, and the
    plan's code, environment, datasets and model become inputs committed at
    the first plan. Execution events (queued, running, finished) are not
    conception and are not mapped. ``elements`` -- the claim elements those
    plans shaped -- is the caller's assertion; nothing infers it.

    The hash chain proves the history is internally consistent, not who wrote
    it: anyone can recompute it over an edited export. Gates are therefore
    marked ``verified`` only when the caller read ``run`` from the governed
    store itself (``ResearchRuns.inspect``); :func:`problems` reports every
    gate that rests on an export alone.
    """
    run = run.get("run", run)
    manifest = run["manifest"]
    if _sha(manifest) != run["manifest_sha256"]:
        raise ValueError(f"run {run['run_id']}: manifest does not match its digest")
    gates = []
    for attempt in run["attempts"]:
        previous = None
        for event in attempt["events"]:
            body = {k: v for k, v in event.items() if k != "event_sha256"}
            if event["previous_event_sha256"] != previous or _sha(body) != event["event_sha256"]:
                raise ValueError(f"run {run['run_id']}: event history does not verify")
            previous = event["event_sha256"]
            if event["state"] == "planned":
                gates.append({
                    "id": f"research:{run['run_id']}:{attempt['number']}:plan",
                    "human": event["actor"], "decision": "framed",
                    "elements": list(elements), "at": event["recorded_at"],
                    "evidence": event["event_sha256"], "verified": bool(verified)})
    if not gates:
        raise ValueError(f"run {run['run_id']}: no planning decision recorded")
    inputs = [
        {"name": f"code:{manifest['code_revision']}", "sha256": manifest["code_sha256"]},
        {"name": f"environment:{manifest['environment_id']}@{manifest['environment_version']}",
         "sha256": manifest["environment_sha256"]},
        *({"name": f"{r['kind']}:{r['asset_id']}@{r['version']}", "sha256": r["manifest_sha256"]}
          for r in [*manifest["dataset_refs"], *filter(None, [manifest["model_ref"]])]),
    ]
    return {"inputs": inputs, "inputs_committed_at": min(g["at"] for g in gates),
            "gates": gates}


def add_research_runs(dossier: dict, runs: list[dict], elements: list[str] = (), *,
                      verified: bool = False) -> dict:
    """``dossier`` with each run's inputs and gates merged in (by id, so adding
    a run twice is a no-op). ``inputs_committed_at`` becomes the LATEST input
    commitment: an idea predating any input is then reported by
    :func:`problems`."""
    out = {**dossier, "inputs": list(dossier.get("inputs", [])),
           "gates": list(dossier.get("gates", []))}
    committed = [dossier["inputs_committed_at"]] if "inputs_committed_at" in dossier else []
    for run in runs:
        ev = research_run_evidence(run, elements, verified=verified)
        out["inputs"] += [i for i in ev["inputs"] if i not in out["inputs"]]
        known = {g["id"] for g in out["gates"]}
        out["gates"] += [g for g in ev["gates"] if g["id"] not in known]
        committed.append(ev["inputs_committed_at"])
    if committed:
        out["inputs_committed_at"] = max(committed)
    return out


def seal(dossier: dict, *, sealed_by: str | None = None) -> dict:
    """Sign the dossier with the deployment's audit identity.

    The signature says who sealed the record and what :func:`problems` found
    at that moment, so a seal never vouches for an unchecked record."""
    from ..audit.signing import sign_detached_digest
    body = {**dossier, "schema": SCHEMA, "open_problems": problems(dossier)}
    if sealed_by:
        body["sealed_by"] = sealed_by
    digest = hashlib.sha256(_ledger.canonical(body)).hexdigest()
    return {"dossier": body, "signature": sign_detached_digest(digest)}


def verify(sealed: dict, pubkey_hex: str, reveals: dict[str, tuple[str, str]] | None = None) -> bool:
    """Offline check of the seal, plus any ``commitment -> (salt, content)``
    openings the holder chooses to reveal."""
    from ..audit.signing import verify_detached_digest
    digest = hashlib.sha256(_ledger.canonical(sealed["dossier"])).hexdigest()
    sig = sealed["signature"]
    if sig["digest"] != digest or not verify_detached_digest(pubkey_hex, digest, sig["signature"]):
        return False
    known = {p["commitment"] for p in sealed["dossier"].get("priority", [])}
    return all(c in known and opens(c, salt, text) for c, (salt, text) in (reveals or {}).items())

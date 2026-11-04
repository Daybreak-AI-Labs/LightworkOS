"""Durable, bounded knowledge-index rebuilds with no partial live publication."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import time
from pathlib import Path

from .budget import Budget
from .file_lock import (
    atomic_read_text,
    atomic_write_text,
    cross_process_lock,
    ensure_private_directory,
)
from .paths import data_dir

_TERMINAL = {"completed", "cancelled", "failed", "changed", "unconfirmed"}


def policy() -> dict:
    from .config import load_config
    cfg = load_config().get("knowledge", {})
    if cfg.get("reindex_jobs", False) is not True:
        raise ValueError("An administrator can enable bounded rebuild jobs in Knowledge settings.")
    dollars = cfg.get("reindex_max_dollars", 5.0)
    if isinstance(dollars, bool) or not isinstance(dollars, (int, float)) or not math.isfinite(dollars) or dollars < 0:
        raise ValueError("Set a finite, non-negative rebuild cost limit in Knowledge settings.")
    return {"max_chunks": min(100_000, max(1, int(cfg.get("reindex_max_chunks", 10_000)))),
            "max_wall_seconds": min(3600, max(1, int(cfg.get("reindex_max_wall_seconds", 300)))),
            "max_dollars": min(1000.0, float(dollars))}


def _sha(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _rows_sha(rows) -> str:
    return _sha([(row.chunk_id, row.text, row.meta) for row in rows])


def _configuration_revision() -> str:
    from .config import get_knowledge
    from .provider_cost_cap import authority_identity

    # Bind effective configuration, including credential rotation, without
    # exposing secrets or instantiating another model/provider at a checkpoint.
    overrides = {key: os.environ.get(key, "") for key in (
        "MAVERICK_EMBED_PROVIDER", "MAVERICK_EMBED_API_KEY", "COHERE_API_KEY",
        "MAVERICK_KNOWLEDGE_DSN", "MAVERICK_PG_DSN",
    )}
    return _sha([get_knowledge(), overrides, authority_identity()])


def _root(context: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{64}", context):
        raise ValueError("Reload this workspace before rebuilding.")
    root = data_dir() / "knowledge-reindex" / context
    ensure_private_directory(root)
    return root


def _path(context: str, job_id: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{32}", job_id):
        raise ValueError("Choose a recorded rebuild job.")
    return _root(context) / (job_id + ".json")


def _read(path):
    return json.loads(atomic_read_text(path, encoding="utf-8"))


def _save(path, value):
    atomic_write_text(path, json.dumps(value, sort_keys=True))


def _public(job):
    return {**{key: job[key] for key in ("job_id", "collection", "state", "count", "done", "message", "created", "updated", "max_wall_seconds", "cost_ceiling", "cancel_requested")},
            "observed_dollars": job.get("observed_dollars", 0.0),
            "unresolved_dollars": job.get("unresolved_dollars", 0.0),
            "price_basis": job.get("price_basis", ""),
            "may_resume": job["state"] in {"queued", "running", "publishing"}}


def _local_embedder(embedder) -> bool:
    from maverick_knowledge.embed import DeterministicEmbedder
    from maverick_knowledge.local_embed import LocalEmbedder
    return type(embedder) in {DeterministicEmbedder, LocalEmbedder}


def preview(kb, collection: str) -> dict:
    from maverick_knowledge.embedding_identity import identity
    limits = policy()
    if not callable(getattr(kb.store, "read_collection", None)) or not callable(getattr(kb.store, "replace_embeddings", None)):
        raise ValueError("This store cannot publish a complete replacement safely. Choose SQLite or pgvector in Knowledge settings before rebuilding.")
    if collection not in kb.collections():
        raise ValueError("This collection is no longer available. Refresh the knowledge library.")
    rows = kb.store.read_collection(collection, limit=limits["max_chunks"])
    if len(rows) > limits["max_chunks"]:
        raise ValueError("This collection exceeds the administrator's rebuild size limit.")
    descriptor, fingerprint = identity(kb.embedder)
    if sum(len(row.text) for row in rows) > 32 * 1024 * 1024 or len(rows) * descriptor["dimension"] > 2_000_000:
        raise ValueError("This rebuild exceeds the bounded text or vector workspace. Split the collection before reviewing a smaller rebuild.")
    billing = None
    cost = 0.0
    price_basis = "Local computation: no paid embedding requests. Hardware cost is not estimated."
    if not _local_embedder(kb.embedder):
        from .knowledge_reindex_billing import contract_for

        contract = contract_for(kb.embedder)
        billing = contract.metadata()
        cost = sum(contract.token_ceiling(len(rows[index:index + 64])) * contract.quote.input_per_mtok / 1_000_000
                   for index in range(0, len(rows), 64))
        cost = math.ceil(cost * 1_000_000) / 1_000_000
        if cost > limits["max_dollars"]:
            raise ValueError("The conservative rebuild reservation exceeds the administrator's cost limit. Review a smaller collection or the limit in Knowledge settings.")
        price_basis = (f"Reserved at the reviewed standard USD list rate (${contract.quote.input_per_mtok:g} per million input tokens, checked {contract.quote.as_of}). "
                       "Each batch reserves the provider's maximum accepted input, then records native billed usage. This is a rate-based admission ceiling, not a guarantee of the provider invoice; taxes and negotiated terms are excluded. Uncertain paid requests are never retried automatically.")
    material = {"collection": collection, "count": len(rows), "source_sha": _rows_sha(rows),
                "embedding": fingerprint, "limits": limits, "billing": billing,
                "configuration_revision": _configuration_revision()}
    return {**material, "review": _sha(material), "cost_ceiling": cost, "price_basis": price_basis,
            "model": descriptor.get("model", "Configured local model")}


def start(kb, *, context: str, job_id: str, collection: str, review: str) -> dict:
    from .connections import current_principal

    path = _path(context, job_id)
    with cross_process_lock(path, strict=True):
        if path.exists():
            prior = _read(path)
            if prior["review"] != review or prior["collection"] != collection:
                raise ValueError("This request already belongs to a different rebuild review.")
            return _public(prior)
        if sum(not _read(item).get("archived", False) for item in path.parent.glob("*.json")) >= 500:
            raise ValueError("Archive finished rebuilds in the Knowledge library before starting another job. Their operation receipts remain recorded.")
        current = preview(kb, collection)
        if current["review"] != review:
            raise ValueError("The collection, model or limits changed. Review the rebuild again.")
        now = time.time()
        job = {**current, "context": context, "job_id": job_id, "state": "queued", "done": 0,
               "message": "Ready to rebuild. The current index remains available.", "created": now,
               "updated": now, "cancel_requested": False, "max_wall_seconds": current["limits"]["max_wall_seconds"],
               "elapsed": 0.0, "observed_dollars": 0.0, "unresolved_dollars": 0.0,
               "input_tokens": 0, "pending_batch": None, "shadow_version": 2,
               "principal": current_principal() or "local"}
        _save(path, job)
        return _public(job)


def list_jobs(context: str, *, include_archived: bool = False) -> list[dict]:
    records = [_read(path) for path in _root(context).glob("*.json")]
    jobs = [_public(record) for record in records if include_archived or not record.get("archived", False)]
    return sorted(jobs, key=lambda job: job["created"], reverse=True)


def archive(context: str, job_id: str) -> dict:
    path = _path(context, job_id)
    with cross_process_lock(path, strict=True):
        job = _read(path)
        if job["state"] not in _TERMINAL:
            raise ValueError("Only a finished rebuild can be archived. Cancel active work first.")
        job.update(archived=True, updated=time.time())
        _save(path, job)
        shadow = path.with_suffix(".shadow")
        if shadow.exists():
            shadow.unlink()
        return _public(job)


def cancel(context: str, job_id: str) -> dict:
    path = _path(context, job_id)
    with cross_process_lock(path, strict=True):
        job = _read(path)
        if job["state"] not in _TERMINAL:
            job["cancel_requested"] = True
            job["message"] = "Cancellation requested; the current batch finishes before stopping."
            if job["state"] == "queued":
                job["state"] = "cancelled"
            job["updated"] = time.time()
            _save(path, job)
        return _public(job)


def _update(path, **changes):
    with cross_process_lock(path, strict=True):
        job = _read(path)
        job.update(changes, updated=time.time())
        _save(path, job)
        return job


def _checkpoint(path, authority, started, job):
    authority()
    _require_principal(job)
    limits = policy()
    current = _read(path)
    if job.get("configuration_revision") not in {None, _configuration_revision()}:
        raise ValueError("Knowledge settings or the cost authority changed. Review the rebuild again.")
    if current["cancel_requested"]:
        _update(path, state="cancelled", message="Rebuild cancelled. The previous live index was preserved.")
        return False
    elapsed = job["elapsed"] + time.monotonic() - started
    if elapsed >= min(job["max_wall_seconds"], limits["max_wall_seconds"]) or time.time() >= job.get("deadline", float("inf")):
        raise ValueError("The rebuild reached its elapsed-time limit; the live index was preserved.")
    if current["count"] > limits["max_chunks"]:
        raise ValueError("The administrator lowered the rebuild size limit.")
    if current["cost_ceiling"] > limits["max_dollars"]:
        raise ValueError("The administrator lowered the rebuild cost limit.")
    return True


def _require_principal(job):
    from .connections import current_principal

    if job.get("principal", "local") != (current_principal() or "local"):
        raise ValueError("The rebuild's requesting account changed.")


def run(kb, *, context: str, job_id: str, authority) -> dict:
    """An explicit start/resume owns the run lock; no startup or failure auto-retry."""
    path = _path(context, job_id)
    with cross_process_lock(path.with_suffix(".run"), strict=True):
        job = _read(path)
        _require_principal(job)
        if job["state"] in _TERMINAL:
            return _public(job)
        if "deadline" not in job:
            job = _update(path, deadline=time.time() + max(0, job["max_wall_seconds"] - job["elapsed"]))
        started = time.monotonic()
        try:
            _execute(kb, path, job, started, authority)
        except Exception:
            # Unknown store outcomes remain inspectable. A new review must not
            # silently retry an interrupted publish or provider operation.
            current = _read(path)
            pending = current.get("pending_batch") or {}
            uncertain = pending.get("state") == "dispatched"
            if current["state"] == "cancelled":
                return _public(current)
            _update(path, state="unconfirmed" if uncertain else "failed", message=(
                "A paid batch has no confirmed completion. Its cost receipt needs review; this job will not resend it. Review provider usage before starting a separately confirmed rebuild. The live index was preserved."
                if uncertain else "Rebuild stopped before a confirmed replacement. Inspect the collection and this job before starting a new review."))
        finally:
            _update(path, elapsed=job["elapsed"] + time.monotonic() - started)
        return _public(_read(path))


def _execute(kb, path, job, started, authority):
    from maverick_knowledge.embedding_identity import (
        FINGERPRINT_KEY,
        IDENTITY_KEY,
        identity,
        validate_batch,
    )

    from .world_model import _dec_field, _enc_field

    # Confirm a previous atomic publication without another paid admission,
    # even after its price snapshot or elapsed-time window has expired.
    if job.get("result_sha"):
        authority()
        _require_principal(job)
        published = kb.store.read_collection(job["collection"], limit=job["limits"]["max_chunks"])
        if job["result_sha"] == _rows_sha(published):
            _update(path, state="completed", done=job["count"], message="The complete replacement was verified after interruption.")
            return
    if not _checkpoint(path, authority, started, job):
        return
    current = preview(kb, job["collection"])
    rows = kb.store.read_collection(job["collection"], limit=job["limits"]["max_chunks"])
    if current["review"] != job["review"] or _rows_sha(rows) != job["source_sha"]:
        _update(path, state="changed", message="The collection, model or limits changed. The old rebuild will not overwrite it; begin a new review.")
        return
    descriptor, fingerprint = identity(kb.embedder)
    shadow_path = path.with_suffix(".shadow")
    shadow = json.loads(_dec_field(atomic_read_text(shadow_path, encoding="utf-8"))) if shadow_path.exists() else []
    if shadow_path.exists() and job.get("shadow_version") == 2:
        binding = {"job_id": job["job_id"], "context": job["context"], "review": job["review"],
                   "source_sha": job["source_sha"], "embedding": job["embedding"]}
        if not isinstance(shadow, dict) or shadow.get("binding") != binding:
            raise ValueError("The saved vectors do not belong to this reviewed rebuild.")
    vectors = shadow["vectors"] if isinstance(shadow, dict) else shadow
    if len(vectors) > len(rows):
        raise ValueError("Invalid shadow checkpoint")
    pending = job.get("pending_batch")
    if pending and (not isinstance(shadow, dict) or shadow.get("completed_batch") != pending["request_id"] or len(vectors) < pending["end"]):
        _update(path, state="unconfirmed", message="The interrupted paid batch has no sealed completion. Its cost receipt remains recorded and it will not be sent again. Review provider usage; the live index is unchanged.")
        return
    if isinstance(shadow, dict):
        job = _update(path, observed_dollars=shadow["observed_dollars"], input_tokens=shadow["input_tokens"], pending_batch=None, unresolved_dollars=0.0)
    budget = Budget(max_dollars=job["cost_ceiling"], dollars=job.get("observed_dollars", 0.0),
                    input_tokens=job.get("input_tokens", 0),
                    max_wall_seconds=max(0.1, job["max_wall_seconds"] - job["elapsed"]), max_tool_calls=max(1, (len(rows) + 63) // 64))
    if job.get("billing") is not None:
        from .tenant.provider_admission import bind_budget

        # Retain the exact native accounting scope across explicit restarts.
        budget._organization_run_id = job["job_id"]
        budget._organization_run_ids = [job["job_id"]]
        budget._organization_principal = job["principal"]
        budget._organization_scope = job["job_id"]
        bind_budget(budget, job["principal"], job["job_id"])
    _update(path, state="running", done=len(vectors), message="Building a replacement; the live index is unchanged.")
    for index in range(len(vectors), len(rows), 64):
        if not _checkpoint(path, authority, started, job):
            return
        budget.record_tool_call()
        batch = rows[index:index + 64]
        if job.get("billing") is None:
            result = kb.embedder.embed([row.text for row in batch])
        else:
            result = _paid_batch(kb, path, job, batch, index, budget, authority, started)
        validate_batch(result, len(batch), descriptor["dimension"])
        budget.check()
        vectors.extend(result)
        recorded = _read(path)
        checkpoint = {"vectors": vectors, "observed_dollars": recorded.get("observed_dollars", 0.0),
                      "input_tokens": recorded.get("input_tokens", 0),
                      "completed_batch": (recorded.get("pending_batch") or {}).get("request_id"),
                      "binding": {"job_id": job["job_id"], "context": job["context"], "review": job["review"],
                                  "source_sha": job["source_sha"], "embedding": job["embedding"]}}
        atomic_write_text(shadow_path, _enc_field(json.dumps(checkpoint)))
        if job.get("billing") is not None:
            _update(path, pending_batch=None, unresolved_dollars=0.0)
        _update(path, done=len(vectors))
    if not _checkpoint(path, authority, started, job):
        return
    if identity(kb.embedder)[1] != fingerprint:
        raise ValueError("Embedding identity changed")
    publication = _sha([job["context"], job["job_id"], job["review"], vectors])
    items = [(row.chunk_id, row.text, vector, {**row.meta, IDENTITY_KEY: descriptor, FINGERPRINT_KEY: fingerprint,
              "reindex_publication": publication}) for row, vector in zip(rows, vectors, strict=True)]
    result_sha = _sha([(item[0], item[1], item[3]) for item in items])
    # Hold cancellation lock through the atomic compare-and-publish boundary.
    with cross_process_lock(path, strict=True):
        authority()
        policy()
        if job.get("configuration_revision") not in {None, _configuration_revision()}:
            raise ValueError("Knowledge settings changed before publication.")
        latest = _read(path)
        if latest["cancel_requested"]:
            latest.update(state="cancelled", message="Rebuild cancelled. The previous live index was preserved.")
        else:
            latest.update(result_sha=result_sha, state="publishing", message="Publishing the complete replacement.")
            _save(path, latest)
            kb.store.replace_embeddings(job["collection"], rows, items)
            kb._require_embedding_identity(job["collection"], fingerprint)
            latest.update(state="completed", done=len(items), message="Rebuilt and verified the complete search index.")
        latest["updated"] = time.time()
        _save(path, latest)


def _paid_batch(kb, path, job, batch, index, budget, authority, started):
    from .knowledge_reindex_billing import contract_for, dispatch
    from .provider_cost_cap import work_item_scope

    contract = contract_for(kb.embedder)
    if contract.metadata() != job["billing"]:
        raise ValueError("Review the current embedding price before sending another batch.")
    request_id = _sha([job["context"], job["job_id"], index])
    pending = {"request_id": request_id, "start": index, "end": index + len(batch), "state": "admitting"}
    _update(path, pending_batch=pending)

    def admitted(reference, projected):
        if not _checkpoint(path, authority, started, job):
            raise ValueError("The rebuild was cancelled before dispatch.")
        if contract_for(kb.embedder).metadata() != job["billing"]:
            raise ValueError("The reviewed price expired or changed before dispatch.")
        current_rows = kb.store.read_collection(job["collection"], limit=job["limits"]["max_chunks"])
        if _rows_sha(current_rows) != job["source_sha"]:
            raise ValueError("The collection changed before paid dispatch.")
        _update(path, pending_batch={**pending, "state": "dispatched", "receipt": reference}, unresolved_dollars=projected)

    def accounted(dollars, tokens, reference):
        current = _read(path)
        _update(path, observed_dollars=current["observed_dollars"] + dollars,
                input_tokens=current["input_tokens"] + tokens, unresolved_dollars=0.0,
                pending_batch={**pending, "state": "accounted", "receipt": reference})

    with work_item_scope("knowledge-reindex:" + job["context"] + ":" + job["job_id"]):
        return dispatch(kb.embedder, [row.text for row in batch], contract=contract, budget=budget,
                        request_id=request_id, operation_id="knowledge-reindex-" + job["job_id"],
                        attempt_no=index // 64 + 1, deadline=job["deadline"],
                        before_dispatch=admitted, accounted=accounted)

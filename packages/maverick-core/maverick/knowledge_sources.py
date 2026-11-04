"""Saved remote Knowledge sources using native records, ingestion and registry.

Refreshes retain an exact item journal. An interrupted publication or paid
embedding request is never taken over or repeated by the scheduler.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import time
from contextlib import contextmanager
from dataclasses import asdict
from urllib.parse import urlsplit

from . import config, connections
from . import knowledge_source_readers as readers
from .authority_effects import authority_effect_fence
from .governed_records import GovernedRecordCapacityError, GovernedRecordStore
from .paths import canonical_tenant_id, tenant_scope
from .privacy_ops import RecordConflict

MAX_SOURCES, MAX_JOBS = 100, 10000
# The default refresh limit ([knowledge_sources] max_refresh_minutes = 5), in seconds.
DEFAULT_REFRESH_WALL_SECONDS = 300
SOURCE_STORE = GovernedRecordStore("knowledge-remote-sources", "KNS", "knowledge_remote_source")
JOB_STORE = GovernedRecordStore("knowledge-source-refreshes", "KNJ", "knowledge_source_refresh")
SNAPSHOT_STORE = GovernedRecordStore("knowledge-source-snapshots", "KNV", "knowledge_source_snapshot")
DECISION_STORE = GovernedRecordStore("knowledge-source-decisions", "KNO", "knowledge_source_decision")


def notice():
    """The saved-source limits, stated with this workspace's configured bounds."""
    bounds = config.get_knowledge_sources()
    return ("Refresh reads only the selected folder's direct files or the selected space's current pages. "
            f"Subfolders need separate sources. At most {bounds['max_items']} items, {bounds['max_download_mib']} MiB per download "
            f"and {bounds['max_text_kib']} KiB of extracted source text are supported. "
            f"Each refresh must finish within {bounds['max_refresh_minutes']} minutes. "
            "Changed items are screened and indexed through the native Knowledge writer. A complete snapshot requires a different authorized registry reviewer before specialists may use it. "
            "Connection sharing determines who can use its cached knowledge; attaching it never grants account or data-use rights. "
            "A dated refresh does not confirm future provider delivery or permanent deletion. Interrupted outcomes are kept and are never repeated automatically.")


def refresh_wall_seconds() -> float:
    """The wall-clock limit of one refresh, read from [knowledge_sources] when the refresh is queued.

    An invalid [knowledge_sources] value keeps the default here, and the refresh then
    reports that named setting when it runs, as its other limits do.
    """
    try:
        return config.get_knowledge_sources()["max_refresh_minutes"] * 60.0
    except config.KnowledgeSourcesConfigError:
        return float(DEFAULT_REFRESH_WALL_SECONDS)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def enabled():
    from . import config

    return bool(config.get_knowledge().get("enable")) and config.knowledge_access_enabled()


def source_id(tenant, actor, asset):
    return "KNS-" + digest([canonical_tenant_id(tenant), actor, asset])[:32]


def content_binding(plan):
    return digest({key: plan[key] for key in ("binding", "asset_id", "decision_id", "decision_sha256", "purpose", "permission_evidence_sha256")})


def source_ref(identifier, version):
    if not re.fullmatch(r"KNS-[a-f0-9]{32}", identifier) or not re.fullmatch(r"[a-f0-9]{32}", version):
        raise ValueError("Choose a recorded Knowledge source snapshot.")
    return f"catalog:remote-knowledge/{identifier}/{version}"


def _safe_error(exc):
    from .secrets import scrub

    # Transport errors can contain provider-signed URLs. Never journal them.
    # A refused [knowledge_sources] setting names only the setting, never its value.
    if isinstance(exc, (readers.SourceReadError, config.KnowledgeSourcesConfigError)):
        return scrub(str(exc))[:500]
    return "This item could not be confirmed (" + type(exc).__name__ + "). Review the saved account and source before a separate refresh."


def canonical_plan(tenant, actor, value, registry):
    if not isinstance(value, dict) or set(value) != {"name", "binding", "decision_id", "decision_sha256", "purpose", "interval_seconds", "max_dollars"}:
        raise ValueError("Use the complete saved Knowledge source form.")
    name = value["name"]
    if not isinstance(name, str) or not 1 <= len(name.strip()) <= 120:
        raise ValueError("Give this source a name between 1 and 120 characters.")
    interval, dollars = value["interval_seconds"], value["max_dollars"]
    if type(interval) is not int or interval not in {0, 3600, 21600, 86400}:
        raise ValueError("Choose manual, hourly, every six hours or daily refresh.")
    if type(dollars) not in {int, float} or not math.isfinite(dollars) or not 0 <= dollars <= 100:
        raise ValueError("Choose a maximum AI search preparation cost between $0 and $100 per refresh.")
    from .research_registry import DataUseAuthority

    authority = registry.data_use_resolver(tenant, value["decision_id"], value["decision_sha256"])
    if (type(authority) is not DataUseAuthority or authority.tenant != tenant or authority.action != "analyze"
            or value["purpose"] not in authority.purpose_codes or authority.expires_at <= SOURCE_STORE.authoritative_time()):
        raise PermissionError("Choose an actual current approval for analyzing this knowledge and purpose.")
    cfg = readers.validate(value["binding"])
    readers.account(cfg, actor)
    return {"name": name.strip(), "binding": cfg, "decision_id": authority.decision_id,
            "decision_sha256": authority.decision_sha256, "asset_id": authority.asset_id,
            "purpose": value["purpose"], "interval_seconds": interval, "max_dollars": float(dollars),
            "permission_evidence_sha256": authority.authority_sha256}


class KnowledgeSources:
    def __init__(self, tenant, actor, *, registry, authority, knowledge_base_factory=None,
                 sources=None, jobs=None, snapshots=None):
        self.tenant, self.actor = canonical_tenant_id(tenant), actor
        if not isinstance(actor, str) or not actor.startswith("user:"):
            raise PermissionError("A named source owner is required.")
        self.registry, self.authority = registry, authority
        self.knowledge_base_factory = knowledge_base_factory
        self.sources, self.jobs, self.snapshots = sources or SOURCE_STORE, jobs or JOB_STORE, snapshots or SNAPSHOT_STORE

    def _authority(self):
        if not enabled():
            raise PermissionError("Knowledge and governed Knowledge access must both be enabled.")
        self.authority()

    @staticmethod
    @contextmanager
    def publication_scope():
        with authority_effect_fence(), connections._mutation_lock():
            yield

    def owned(self, identifier):
        self._authority()
        row = self.sources.get(identifier)
        if not row or row.get("tenant") != self.tenant or row.get("owner") != self.actor:
            raise PermissionError("This saved Knowledge source belongs to a different account or workspace.")
        return row

    def _plan_guard(self, plan):
        self._authority()
        authority = self.registry.data_use_resolver(self.tenant, plan["decision_id"], plan["decision_sha256"])
        if (authority.asset_id != plan["asset_id"] or authority.action != "analyze" or plan["purpose"] not in authority.purpose_codes
                or authority.expires_at <= self.sources.authoritative_time() or authority.authority_sha256 != plan["permission_evidence_sha256"]):
            raise PermissionError("The actual data-use approval changed. Choose its current decision again.")
        readers.account(plan["binding"], self.actor)

    def catalog(self):
        self._authority()
        rows = self.sources.list(limit=MAX_SOURCES + 1)
        if len(rows) > MAX_SOURCES:
            raise ValueError("The saved source catalogue exceeds its supported bound.")
        result = [self.public(row) for row in rows if row.get("tenant") == self.tenant and row.get("owner") == self.actor]
        self._authority()
        return result

    def public(self, row):
        active = self.jobs.get(row["active_job"]) if row.get("active_job") else None
        snapshot = self.snapshots.get(row["snapshot"]) if row.get("snapshot") else None
        reference, approval = None, "No complete imported snapshot"
        if snapshot and snapshot.get("reference"):
            reference = snapshot["reference"]
            from .research_registry import ResearchAssetRef
            try:
                view = self.registry.inspect(self.tenant, ResearchAssetRef(**reference))
                approval = str(view.get("status") or view.get("state") or "Draft awaiting an independent reviewer")
            except Exception:
                approval = "Current registry state unavailable; use is blocked"
        bounds = config.get_knowledge_sources()
        needs_refresh = bool(_by_email(bounds) and snapshot and any(not isinstance(item.get("permissions"), dict) for item in snapshot.get("items", [])))
        return {"id": row["id"], "revision": row["revision"], "name": row["plan"]["name"], "plan": row["plan"],
                "permission_filter": bounds["permission_filter"], "permissions_need_refresh": needs_refresh,
                "state": row["state"], "paused": row.get("paused", False), "last_refresh": row.get("last_refresh"),
                "next_refresh": row.get("next_refresh"), "item_count": len(snapshot.get("items", [])) if snapshot else 0,
                "registry_state": approval, "reference": reference, "active_job": self.job_public(active) if active else None,
                "notice": notice(), "audit_pending": bool(row.get("_audit_pending"))}

    @staticmethod
    def job_public(row):
        if row is None:
            return None
        return {key: row.get(key) for key in ("id", "source", "state", "created_at", "updated_at", "deadline", "message", "items",
                                            "changed", "unchanged", "removed", "observed_dollars", "unresolved_dollars", "price_basis", "reference")}

    def history(self, identifier, *, offset=0):
        self.owned(identifier)
        if type(offset) is not int or not 0 <= offset <= MAX_JOBS:
            raise ValueError("Choose a retained refresh history page.")
        rows = self.jobs.list(limit=MAX_JOBS + 1)
        if len(rows) > MAX_JOBS:
            raise ValueError("The retained refresh history reached its supported capacity.")
        selected = sorted((row for row in rows if row.get("source") == identifier and row.get("owner") == self.actor and row.get("tenant") == self.tenant),
                          key=lambda row: (row.get("created_at", 0), row["id"]), reverse=True)
        return {"items": [self.job_public(row) for row in selected[offset:offset + 50]], "total": len(selected),
                "next_offset": offset + 50 if offset + 50 < len(selected) else None}

    def original_job(self, identifier):
        self._authority()
        row = self.jobs.get(identifier)
        if row is None:
            for source in self.sources.list(limit=MAX_SOURCES + 1):
                if source.get("active_job") == identifier and source.get("owner") == self.actor and source.get("tenant") == self.tenant:
                    return {"id": identifier, "source": source["id"], "state": "unconfirmed", "message": "The native source retains this original claim without a complete job receipt. Nothing is repeated automatically."}
        if not row or row.get("owner") != self.actor or row.get("tenant") != self.tenant:
            raise PermissionError("This original refresh belongs to another account or workspace.")
        self.owned(row["source"])
        result = self.job_public(row)
        if row["state"] in {"queued", "running", "publishing"} and row["deadline"] <= self.jobs.authoritative_time():
            result.update(state="unconfirmed", message="The worker stopped before its complete receipt. Some native content or provider usage may exist. Nothing will be repeated automatically.")
        return result

    @staticmethod
    def record_scheduled_error(source, exc):
        """Worker bookkeeping only: no document, credential or approval effect."""
        def same_source():
            current = SOURCE_STORE.get(source["id"])
            if not current or current.get("tenant") != source["tenant"] or current.get("owner") != source["owner"] or current["plan_sha256"] != source["plan_sha256"] or current.get("active_job"):
                raise RecordConflict("The scheduled source changed before its withheld receipt.")
        with KnowledgeSources.publication_scope():
            same_source()
            job_id, full = "KNJ-" + digest([source["id"], source.get("next_refresh")])[:32], None
            if JOB_STORE.get(job_id) is None:
                try:
                    JOB_STORE.create({"id": job_id, "source": source["id"], "tenant": source["tenant"], "owner": source["owner"],
                                      "state": "withheld", "message": _safe_error(exc), "items": [], "observed_dollars": 0.0, "unresolved_dollars": 0.0},
                                     action="knowledge_source.scheduled_refresh_withheld", actor="knowledge-source worker", max_records=MAX_JOBS, effect_guard=same_source)
                except GovernedRecordCapacityError as refused:
                    full = refused  # still back off: a full ledger must not mean a retry every scheduler cycle
            current = SOURCE_STORE.get(source["id"])
            SOURCE_STORE.update(source["id"], lambda row: row.update(state="withheld", projection_allowed=False, next_refresh=time.time() + max(3600, source["plan"]["interval_seconds"])),
                                expected_revision=current["revision"], action="knowledge_source.refresh_backed_off", actor="knowledge-source worker", effect_guard=same_source)
            if full is not None:
                raise full

    @staticmethod
    def withhold_queued(job, exc=None):
        """Worker bookkeeping only: a queued refresh refused before it started
        (its permit expired or changed, or its owner lost authority) is
        withheld and its source backs off, instead of being retried every
        worker cycle with the schedule stuck behind it. Only a job that is
        still queued, so nothing ran, is changed. A retained withheld receipt
        can finish releasing its source after an interrupted second write;
        recovery preserves the original receipt and never runs the job."""
        def still_claimed(state):
            current = JOB_STORE.get(job["id"])
            source = SOURCE_STORE.get(job["source"])
            if (not current or current.get("source") != job["source"] or current.get("state") != state
                    or current.get("_audit_pending") or not source or source.get("_audit_pending")
                    or source.get("active_job") != job["id"]):
                raise RecordConflict("The queued refresh changed before it was withheld.")
        with KnowledgeSources.publication_scope():
            current = JOB_STORE.get(job["id"])
            if current and current.get("state") == "queued":
                if exc is None:
                    raise RecordConflict("Only a refused queued refresh can be withheld.")
                still_claimed("queued")
                JOB_STORE.update(job["id"], lambda row: row.update(state="withheld", message=_safe_error(exc)),
                                 expected_revision=current["revision"], action="knowledge_source.queued_refresh_withheld",
                                 actor="knowledge-source worker", effect_guard=lambda: still_claimed("queued"))
            still_claimed("withheld")
            source = SOURCE_STORE.get(job["source"])
            interval = source["plan"]["interval_seconds"]
            SOURCE_STORE.update(source["id"], lambda row: row.update(
                active_job=None, state="withheld", projection_allowed=False,
                next_refresh=time.time() + max(3600, interval) if interval else None),
                expected_revision=source["revision"], action="knowledge_source.refresh_backed_off",
                actor="knowledge-source worker", effect_guard=lambda: still_claimed("withheld"))

    def original_save(self, operation):
        self._authority()
        row = DECISION_STORE.get("KNO-" + operation)
        if not row or row.get("tenant") != self.tenant or row.get("owner") != self.actor:
            return {"state": "not_established", "message": "No original save admission was found. This read did not save or refresh anything."}
        if row["state"] == "confirmed" and not row.get("_audit_pending"):
            return {"state": "confirmed", "source": row["result"], "message": "Read the retained original source-settings result. This read changed nothing."}
        source = self.sources.get(row["source"])
        if source and source.get("last_save_operation") == operation and source["plan_sha256"] == row["plan_sha256"] and source.get("paused") == row["paused"] and not source.get("_audit_pending"):
            return {"state": "confirmed", "source": self.public(source), "message": "The native source retains this exact original save marker. Its separate receipt may be incomplete; this read did not repeat the save."}
        return {"state": "unconfirmed", "message": "This original source-settings decision has no complete confirmation. The native plan may already exist; inspect current settings before a separate new intent."}

    def _save_intent(self, plan, expected_revision, paused, operation):
        if operation is None:
            return None
        if not re.fullmatch(r"[a-f0-9]{32}", operation):
            raise ValueError("A retained save intent is required.")
        identifier = "KNO-" + operation
        binding = digest([plan, expected_revision, paused])
        row = DECISION_STORE.get(identifier)
        if row:
            if row.get("binding") != binding or row.get("owner") != self.actor or row.get("tenant") != self.tenant:
                raise RecordConflict("This original save has different reviewed settings.")
            return self.original_save(operation)
        row = DECISION_STORE.create({"id": identifier, "tenant": self.tenant, "owner": self.actor, "source": source_id(self.tenant, self.actor, plan["asset_id"]),
                                     "plan_sha256": digest(plan), "paused": paused, "binding": binding, "state": "unconfirmed"},
                                    action="knowledge_source.save_admitted", actor=self.actor, max_records=MAX_JOBS,
                                    effect_guard=lambda: self._plan_guard(plan))
        return self.original_save(operation) if row.get("_audit_pending") else None

    def _save_receipt(self, result, plan, operation):
        if operation is not None:
            row = DECISION_STORE.get("KNO-" + operation)
            DECISION_STORE.update(row["id"], lambda current: current.update(state="confirmed", result=result), expected_revision=row["revision"],
                                  action="knowledge_source.save_confirmed", actor=self.actor, effect_guard=lambda: self._plan_guard(plan))
            return self.original_save(operation)
        return {"state": "confirmed", "source": result, "message": "Complete source settings saved. Remote delivery and dataset approval are separate."}

    def save(self, plan, *, expected_revision, paused=False, operation=None):
        self._plan_guard(plan)
        # An invalid [knowledge_sources] setting refuses the save before anything is
        # written: the receipt built after the write states the configured limits.
        config.get_knowledge_sources()
        existing_intent = self._save_intent(plan, expected_revision, paused, operation)
        if existing_intent is not None:
            return existing_intent
        identifier = source_id(self.tenant, self.actor, plan["asset_id"])
        binding = digest(plan)
        with tenant_scope(tenant=self.tenant), authority_effect_fence(), connections._mutation_lock():
            self._plan_guard(plan)
            prior = self.sources.get(identifier)
            if prior and prior.get("plan_sha256") == binding and prior.get("paused") == paused:
                return self._save_receipt(self.public(prior), plan, operation)
            for row in self.sources.list(limit=MAX_SOURCES + 1):
                if row.get("plan", {}).get("asset_id") == plan["asset_id"] and row["id"] != identifier:
                    raise ValueError("This governed asset already belongs to another saved source. Choose a separate approved asset.")
            values = {"tenant": self.tenant, "owner": self.actor, "plan": plan, "plan_sha256": binding,
                      "paused": paused, "state": "configured", "projection_allowed": False, "next_refresh": time.time() + plan["interval_seconds"] if plan["interval_seconds"] else None}
            if prior and content_binding(prior["plan"]) == content_binding(plan):
                values["projection_allowed"] = prior.get("projection_allowed", False)
            if operation is not None:
                values["last_save_operation"] = operation
            if prior is None:
                if expected_revision != 0:
                    raise RecordConflict("The saved source changed; review its current settings again.")
                row = self.sources.create({"id": identifier, **values, "active_job": None, "snapshot": None},
                                          action="knowledge_source.saved", actor=self.actor, max_records=MAX_SOURCES,
                                          effect_guard=lambda: self._plan_guard(plan))
            else:
                if prior.get("active_job"):
                    raise ValueError("Read the active refresh's original outcome before changing this source.")
                row = self.sources.update(identifier, lambda current: current.update(values), expected_revision=expected_revision,
                                          action="knowledge_source.updated", actor=self.actor, effect_guard=lambda: self._plan_guard(plan))
            if row.get("_audit_pending"):
                return self.original_save(operation) if operation is not None else {"state": "unconfirmed", "message": "The native source has a pending activity record. No refresh will run automatically."}
            return self._save_receipt(self.public(row), plan, operation)

    def refresh_review(self, identifier):
        row = self.owned(identifier)
        self._plan_guard(row["plan"])
        items = readers.inventory(row["plan"]["binding"], self.actor, lambda: self._plan_guard(row["plan"]))
        self._plan_guard(row["plan"])
        price = self._embedding_review(row["plan"])
        return {"source": identifier, "plan_sha256": row["plan_sha256"], "revision": row["revision"],
                "snapshot_at": time.time(), "inventory": items, "inventory_sha256": digest(items), "embedding": price,
                "previous": self.original_job(row["active_job"]) if row.get("active_job") else None}

    def _open(self):
        if self.knowledge_base_factory:
            return self.knowledge_base_factory(self.tenant)
        from .knowledge_admin import open_knowledge_base
        kb = open_knowledge_base(tenant=self.tenant)
        if kb is None:
            raise ValueError("Knowledge ingestion is unavailable in this workspace.")
        return kb

    def _embedding_review(self, plan):
        from maverick_knowledge.embedding_identity import identity

        from .knowledge_reindex_jobs import _configuration_revision, _local_embedder
        kb = self._open()
        try:
            descriptor, fingerprint = identity(kb.embedder)
            billing = None
            text = "Local embeddings; no paid embedding requests."
            if not _local_embedder(kb.embedder):
                from .knowledge_reindex_billing import contract_for
                billing = contract_for(kb.embedder).metadata()
                text = "Hosted embeddings use the native per-request reservation and billed-usage journal. The complete refresh stops at the reviewed dollar ceiling; an uncertain request is never retried."
                if plan["max_dollars"] <= 0:
                    raise ValueError("This workspace uses paid embeddings. Review an explicit dollar ceiling before refreshing, or select local embeddings in Knowledge settings.")
            return {"identity": descriptor, "fingerprint": fingerprint, "configuration": _configuration_revision(), "billing": billing,
                    "max_dollars": plan["max_dollars"], "price_basis": text}
        finally:
            kb.close()

    def start(self, prepared, operation, *, acknowledge_unknown=False):
        if not re.fullmatch(r"[a-f0-9]{32}", operation):
            raise ValueError("A retained refresh intent is required.")
        job_id = "KNJ-" + operation
        existing = self.jobs.get(job_id)
        if existing:
            if existing.get("binding") != digest(prepared):
                raise RecordConflict("This original request has different reviewed settings.")
            return self.original_job(job_id)
        # Read before the claim, so the deadline is fixed at the reviewed limit when the refresh is queued.
        wall_seconds = refresh_wall_seconds()
        row = self.owned(prepared["source"])
        if row.get("_audit_pending") or row["plan_sha256"] != prepared["plan_sha256"] or row["revision"] != prepared["revision"]:
            raise RecordConflict("The saved source changed. Read its original outcome or review a fresh refresh.")
        self._plan_guard(row["plan"])
        previous = self.original_job(row["active_job"]) if row.get("active_job") else None
        if previous and (previous["state"] != "unconfirmed" or not acknowledge_unknown):
            raise ValueError("Read the active original. A stopped uncertain refresh requires a separately acknowledged new intent.")
        if self._embedding_review(row["plan"]) != prepared["embedding"]:
            raise ValueError("The embedding setup or price changed. Review the current refresh again.")
        def guard():
            self._plan_guard(row["plan"])
        with authority_effect_fence(), connections._mutation_lock():
            guard()
            claimed = self.sources.update(row["id"], lambda current: current.update(active_job=job_id, state="queued", projection_allowed=False),
                                          expected_revision=row["revision"], action="knowledge_source.refresh_claimed", actor=self.actor, effect_guard=guard)
            if claimed.get("_audit_pending"):
                return {"id": job_id, "state": "unconfirmed", "message": "Refresh admission has a retained pending activity record. It will not run automatically."}
            try:
                job = self.jobs.create({"id": job_id, "source": row["id"], "tenant": self.tenant, "owner": self.actor, "plan": row["plan"],
                                        "plan_sha256": row["plan_sha256"], "binding": digest(prepared), "state": "queued",
                                        "deadline": time.time() + wall_seconds, "max_wall_seconds": wall_seconds,
                                        "prepared": prepared, "items": [], "changed": 0, "unchanged": 0, "removed": 0,
                                        "observed_dollars": 0.0, "unresolved_dollars": 0.0, "price_basis": prepared["embedding"]["price_basis"],
                                        "message": "Refresh queued. No document delivery or registry approval is yet confirmed."},
                                       action="knowledge_source.refresh_queued", actor=self.actor, max_records=MAX_JOBS, effect_guard=guard)
            except BaseException:
                # If no job record exists (for example the job ledger is full),
                # nothing can read or run this claim: give it back instead of
                # leaving the source claimed by a refresh that does not exist.
                # A create can also fail after saving its record; then the job
                # and its claim must stay together, so the claim is kept (and
                # kept too when the ledger cannot say which happened).
                try:
                    saved = self.jobs.get(job_id) is not None
                except Exception:  # noqa: BLE001 -- unknown: never orphan a saved job
                    saved = True
                if saved:
                    raise
                # A scheduled source backs off as a withheld refresh does, so
                # the scheduler does not retry it on every cycle.
                def release(current):
                    current.update(active_job=row.get("active_job"), state=row["state"], projection_allowed=row.get("projection_allowed", False))
                    if row["plan"]["interval_seconds"]:
                        current["next_refresh"] = time.time() + max(3600, row["plan"]["interval_seconds"])
                try:
                    self.sources.update(row["id"], release, expected_revision=claimed["revision"],
                                        action="knowledge_source.refresh_claim_released", actor=self.actor, effect_guard=guard)
                except Exception:  # noqa: BLE001 -- the original failure is what the caller must see
                    pass
                raise
            return self.job_public(job)

    def _job_guard(self, job):
        self._plan_guard(job["plan"])
        row = self.sources.get(job["source"])
        if (not row or row.get("active_job") != job["id"] or row["plan_sha256"] != job["plan_sha256"]
                or row.get("_audit_pending") or self.jobs.authoritative_time() >= job["deadline"]):
            raise PermissionError("This refresh's current source permit is unavailable or expired.")
        from .knowledge_reindex_jobs import _configuration_revision
        if _configuration_revision() != job["prepared"]["embedding"]["configuration"]:
            raise PermissionError("The reviewed Knowledge configuration changed during refresh.")

    def _job_update(self, job, **values):
        row = self.jobs.get(job["id"])
        return self.jobs.update(row["id"], lambda current: current.update(values), expected_revision=row["revision"],
                                action="knowledge_source.refresh_progress", actor=self.actor,
                                effect_guard=lambda: self._job_guard(job))

    def run(self, identifier):
        job = self.jobs.get(identifier)
        if not job or job.get("owner") != self.actor or job.get("tenant") != self.tenant or job["state"] != "queued" or job.get("_audit_pending"):
            return None
        self._job_guard(job)
        # CAS is the existing native claim: two workers can observe queued, but
        # only one can transition it. No expired running claim is taken over.
        job = self.jobs.update(identifier, lambda current: current.update(state="running"), expected_revision=job["revision"],
                               action="knowledge_source.refresh_started", actor=self.actor, effect_guard=lambda: self._job_guard(job))
        if job.get("_audit_pending"):
            return self.job_public(job)
        kb = None
        try:
            rows = readers.inventory(job["plan"]["binding"], self.actor, lambda: self._job_guard(job))
            if digest(rows) != job["prepared"]["inventory_sha256"]:
                raise ValueError("The dated source inventory changed. Review its current refresh before importing.")
            # The text bound is read at this refresh, so a changed setting applies to the next one.
            bounds = config.get_knowledge_sources()
            text_kib, filtered = bounds["max_text_kib"], _by_email(bounds)
            source = self.sources.get(job["source"])
            prior = self.snapshots.get(source["snapshot"]) if source.get("snapshot") else None
            previous = {row["remote_id"]: row for row in prior.get("items", [])} if prior else {}
            kb = self._open()
            self._prepare_embedder(kb, job)
            imported, outcomes, total, changed, unchanged = [], [], 0, 0, 0
            for item in rows:
                self._job_guard(job)
                if item["kind"] == "folder":
                    outcomes.append({"name": item["name"], "state": "excluded", "message": "Subfolder; add it as a separate source."})
                    continue
                old = previous.get(item["id"])
                collection = "remote-" + job["source"][4:] + "-" + digest(item["id"])[:16]
                # Permissions are read for every item on every refresh, because a sharing change alone never changes its revision.
                grants = readers.permissions(job["plan"]["binding"], self.actor, item, lambda: self._job_guard(job)) if filtered else None
                reused = bool(old and item["revision"] and old["provider_revision"] == item["revision"])
                if reused:
                    exact = kb.exact_document(collection, old["document_sha256"])
                    text_bytes = len(exact["text"].encode())
                    candidate = old
                    unchanged += 1
                else:
                    try:
                        text, raw_sha, extraction = readers.document(job["plan"]["binding"], self.actor, item, lambda: self._job_guard(job))
                        text_bytes = len(text.encode())
                        if total + text_bytes > text_kib * 1024:
                            raise readers.SourceReadError(f"The extracted source exceeds {text_kib} KiB. Choose a smaller source.")
                        document_sha = hashlib.sha256(text.encode()).hexdigest()
                        # KB's exact document digest owns immutable provenance.
                        # Mutable provider revision/byte-extraction commitments
                        # belong to the retained source snapshot, not that key.
                        provenance = {"remote_source_id": job["source"], "remote_item_id": item["id"]}
                        count = kb.ingest_text(collection, text, source="remote:" + job["source"] + ":" + item["id"],
                                               trust_tier=1, sensitivity="internal", ingested_by=self.actor,
                                               extra_meta=provenance, replace_source=True, effect_guard=lambda: self._job_guard(job),
                                               publication_scope=self.publication_scope)
                        if not count:
                            raise readers.SourceReadError("Native Knowledge screening refused this document; it was not imported.")
                        exact = kb.exact_document(collection, document_sha)
                        candidate = {"remote_id": item["id"], "name": item["name"], "provider_revision": item["revision"],
                                     "document_sha256": document_sha, "raw_sha256": raw_sha, "citation": _safe_citation(item.get("citation")),
                                     "collection": collection, "extraction": extraction, "text_bytes": len(exact["text"].encode()),
                                     "native_document_sha256": digest(_committed_document(exact))}
                        changed += 1
                    except Exception as exc:
                        current = self.jobs.get(job["id"])
                        if current.get("unresolved_dollars"):
                            raise
                        outcomes.append({"name": item["name"], "state": "error", "message": _safe_error(exc)})
                        self._job_update(job, items=outcomes, changed=changed, unchanged=unchanged)
                        continue
                total += text_bytes
                if total > text_kib * 1024:
                    raise ValueError("The exact source exceeds its complete text bound.")
                if grants is not None:
                    candidate = {**candidate, "permissions": grants}
                else:
                    # A reused item keeps the record of an earlier filtered refresh, which this refresh did not read.
                    candidate = {key: value for key, value in candidate.items() if key != "permissions"}
                imported.append(candidate)
                outcomes.append({"name": item["name"], "state": "unchanged" if reused else "imported", "message": "Exact extracted text retained; dataset approval is separate.",
                                 "coverage_notes": candidate["extraction"].get("warnings", [])})
                self._job_update(job, items=outcomes, changed=changed, unchanged=unchanged)
            removed = len(set(previous) - {row["id"] for row in rows})
            if any(row["state"] == "error" for row in outcomes) or not imported:
                return self._finish(job, "partial", "Refresh has file errors or no complete readable files. No new usable snapshot was published; inspect every item below.",
                                    items=outcomes, changed=changed, unchanged=unchanged, removed=removed)
            # Re-read current metadata before publishing. A moving or incomplete
            # listing cannot silently turn into a complete native source.
            verify = readers.inventory(job["plan"]["binding"], self.actor, lambda: self._job_guard(job))
            if digest(verify) != digest(rows):
                raise ValueError("The source changed while importing. Its native item outcomes are kept; review a new refresh.")
            self._job_update(job, state="publishing")
            with self.publication_scope():
                self._job_guard(job)
                snapshot = self._publish(job, imported, kb)
                self._job_guard(job)
            return self._finish(job, "completed", "Complete dated snapshot imported. A different authorized reviewer must approve this exact registry version before specialists can use it.",
                                items=outcomes, changed=changed, unchanged=unchanged, removed=removed,
                                reference=snapshot["reference"], snapshot=snapshot["id"])
        except Exception as exc:
            current = self.jobs.get(job["id"])
            uncertain = bool(current.get("unresolved_dollars")) or current["state"] == "publishing"
            return self._finish(job, "unconfirmed" if uncertain else "failed", _safe_error(exc), allow_expired=True)
        finally:
            if kb is not None:
                kb.close()

    def _publish(self, job, items, kb):
        from .knowledge_content_projection import inspect_existing_source
        payload = {"source": job["source"], "plan_sha256": content_binding(job["plan"]), "items": sorted(items, key=lambda row: row["remote_id"])}
        version = digest(payload)[:32]
        identifier = "KNV-" + digest([job["source"], version])[:32]
        row = self.snapshots.get(identifier)
        if row is None:
            row = self.snapshots.create({"id": identifier, "tenant": self.tenant, "owner": self.actor, "version": version,
                                         **payload, "binding": job["plan"]["binding"], "name": job["plan"]["name"], "observed_at": time.time(), "reference": None},
                                        action="knowledge_source.snapshot_retained", actor=self.actor, max_records=MAX_JOBS,
                                        effect_guard=lambda: self._job_guard(job))
        if row.get("_audit_pending"):
            raise ValueError("The exact source snapshot has a pending activity record; publication is unconfirmed.")
        plan = job["plan"]
        self.registry.preflight_dataset_ingestion(self.tenant, dataset_id=plan["asset_id"], allowed_purposes=(plan["purpose"],),
                                                data_use_action="analyze", data_use_decision_id=plan["decision_id"], data_use_decision_sha256=plan["decision_sha256"])
        ref = source_ref(job["source"], version)
        inspected = inspect_existing_source(self.tenant, ref, knowledge_base=kb)
        self._job_guard(job)
        reference = self.registry.register_dataset(self.tenant, self.actor, dataset_id=plan["asset_id"], version="remote-" + version,
                                                   source_ref=ref, content_sha256=inspected["content_sha256"],
                                                   license_id="governed-use-" + digest(plan["decision_id"])[:24],
                                                   license_evidence_sha256=plan["permission_evidence_sha256"],
                                                   allowed_purposes=(plan["purpose"],), usage_constraints=("current_named_account_grants", "dated_direct_container_snapshot", "analyze_only"),
                                                   data_use_action="analyze", data_use_decision_id=plan["decision_id"], data_use_decision_sha256=plan["decision_sha256"])
        row = self.snapshots.get(identifier)
        if row.get("reference") and row["reference"] != asdict(reference):
            raise RecordConflict("The retained snapshot has a different registry commitment.")
        if not row.get("reference"):
            row = self.snapshots.update(identifier, lambda current: current.update(reference=asdict(reference)), expected_revision=row["revision"],
                                        action="knowledge_source.snapshot_registered", actor=self.actor, effect_guard=lambda: self._job_guard(job))
        return row

    def _finish(self, job, state, message, *, allow_expired=False, **values):
        self._authority()
        current = self.jobs.get(job["id"])
        snapshot = values.pop("snapshot", None)
        def guard():
            self._authority()
            row = self.sources.get(job["source"])
            if not row or row.get("active_job") != job["id"] or row["plan_sha256"] != job["plan_sha256"]:
                raise RecordConflict("This refresh no longer owns the saved source.")
            if not allow_expired:
                self._job_guard(job)
        result = self.jobs.update(job["id"], lambda row: row.update(state=state, message=message, **values), expected_revision=current["revision"],
                                  action="knowledge_source.refresh_finished", actor=self.actor, effect_guard=guard)
        row = self.sources.get(job["source"])
        complete = state == "completed" and not result.get("_audit_pending")
        update = {"state": state, "last_refresh": time.time(), "projection_allowed": complete,
                  "active_job": None if state != "unconfirmed" and not result.get("_audit_pending") else job["id"],
                  "next_refresh": time.time() + job["plan"]["interval_seconds"] if job["plan"]["interval_seconds"] and state != "unconfirmed" else None}
        if complete:
            # A scheduled source keeps its hour of slack past the next refresh (scheduler or
            # refresh latency must not open a gap); a manual one stays fresh for a day.
            interval = job["plan"]["interval_seconds"]
            update.update(snapshot=snapshot, fresh_until=time.time() + (interval + 3600 if interval else 86400))
        with self.publication_scope():
            self.sources.update(row["id"], lambda source: source.update(update), expected_revision=row["revision"],
                                action="knowledge_source.refresh_recorded", actor=self.actor, effect_guard=guard)
        return self.job_public(result)

    def _prepare_embedder(self, kb, job):
        if job["prepared"]["embedding"]["billing"] is None:
            return
        from .budget import Budget
        from .tenant.provider_admission import bind_budget
        # The wall cap is the limit this refresh was queued with, the same one its deadline uses.
        budget = Budget(max_dollars=job["plan"]["max_dollars"], max_wall_seconds=job.get("max_wall_seconds", DEFAULT_REFRESH_WALL_SECONDS))
        budget._organization_run_id = job["id"]
        budget._organization_run_ids = [job["id"]]
        budget._organization_principal = job["owner"]
        budget._organization_scope = job["id"]
        bind_budget(budget, job["owner"], job["id"])
        kb.embedder = _AdmittedEmbedder(kb.embedder, self, job, budget)


class _AdmittedEmbedder:
    def __init__(self, native, service, job, budget):
        self.native, self.service, self.job, self.budget = native, service, job, budget
        self.dim, self.batch = native.dim, 0

    def embedding_identity(self):
        return self.native.embedding_identity()

    def embed(self, texts):
        from .knowledge_reindex_billing import contract_for, dispatch
        from .provider_cost_cap import work_item_scope
        vectors = []
        for offset in range(0, len(texts), 64):
            self.service._job_guard(self.job)
            self.batch += 1
            contract = contract_for(self.native)
            if contract.metadata() != self.job["prepared"]["embedding"]["billing"]:
                raise PermissionError("The reviewed embedding price changed.")
            def admitted(reference, projected):
                self.service._job_update(self.job, unresolved_dollars=projected, paid_request=reference)
            def accounted(dollars, _tokens, reference):
                current = self.service.jobs.get(self.job["id"])
                self.service._job_update(self.job, observed_dollars=current["observed_dollars"] + dollars,
                                         unresolved_dollars=0.0, paid_request=reference)
            with work_item_scope(self.job["id"]):
                vectors.extend(dispatch(self.native, texts[offset:offset + 64], contract=contract, budget=self.budget,
                                        request_id=digest([self.job["id"], self.batch]), operation_id=self.job["id"], attempt_no=self.batch,
                                        deadline=self.job["deadline"], before_dispatch=admitted, accounted=accounted))
        return vectors


def _safe_citation(value):
    if not isinstance(value, str) or len(value) > 2048:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        return ""
    return value


def _committed_document(record):
    committed = {key: value for key, value in record.items() if key != "text"}
    committed["metadata"] = {key: value for key, value in record["metadata"].items() if key not in {"embedding_identity", "embedding_fingerprint"}}
    return committed


def _by_email(bounds=None):
    return (bounds or config.get_knowledge_sources())["permission_filter"] == "by_email"


def _visible(item, email):
    """Under by_email: a verified signed-in address must match the item's recorded grants. Unknown, group-only,
    unrecorded (older snapshot) and no-address cases are withheld, never guessed."""
    permissions = item.get("permissions")
    if not email or not isinstance(permissions, dict) or permissions.get("unknown"):
        return False
    if permissions.get("anyone"):
        return True
    return email in permissions.get("emails", ()) or email.rpartition("@")[2] in permissions.get("domains", ())


def require_remote_document_authority(tenant, collection, document_sha256, authority):
    match = re.fullmatch(r"remote-([a-f0-9]{32})-[a-f0-9]{16}", collection)
    if not match:
        raise PermissionError("This remote collection has no native saved source identity.")
    with tenant_scope(tenant=tenant), KnowledgeSources.publication_scope():
        source = SOURCE_STORE.get("KNS-" + match[1])
        if (not source or source.get("tenant") != tenant or not source.get("projection_allowed") or source.get("_audit_pending")
                or source.get("fresh_until", 0) <= SOURCE_STORE.authoritative_time() or authority.action != "analyze"
                or authority.purpose != source["plan"]["purpose"]):
            raise PermissionError("Current saved remote source rights are unavailable.")
        snapshot = SNAPSHOT_STORE.get(source.get("snapshot"))
        match = [row for row in (snapshot or {}).get("items", ()) if row["collection"] == collection and row["document_sha256"] == document_sha256]
        if (not snapshot or snapshot.get("_audit_pending") or not match):
            raise PermissionError("This exact document is no longer in the current remote source.")
        if _by_email() and not _visible(match[0], getattr(authority, "verified_email", "")):
            raise PermissionError("This document is not shared with the signed-in person.")
        readers.account(source["plan"]["binding"], authority.principal)


def exact_source_snapshot(tenant, identifier, version, *, knowledge_base, authority=None):
    """Installed exact projector input, derived only from native sealed records."""
    with tenant_scope(tenant=canonical_tenant_id(tenant)), KnowledgeSources.publication_scope():
        source = SOURCE_STORE.get(identifier)
        snapshot_id = "KNV-" + digest([identifier, version])[:32]
        snapshot = SNAPSHOT_STORE.get(snapshot_id)
        if (not source or not snapshot or source.get("tenant") != tenant or snapshot.get("tenant") != tenant
                or source.get("_audit_pending") or snapshot.get("_audit_pending") or snapshot.get("source") != identifier
                or snapshot.get("version") != version or snapshot.get("plan_sha256") != content_binding(source["plan"])):
            raise PermissionError("The exact remote Knowledge snapshot is unavailable.")
        if authority is not None:
            if (not source.get("projection_allowed") or source.get("snapshot") != snapshot_id
                    or source.get("fresh_until", 0) <= SOURCE_STORE.authoritative_time()
                    or authority.action != "analyze" or authority.purpose != source["plan"]["purpose"]):
                raise PermissionError("The remote source needs a complete current refresh and use approval.")
            readers.account(source["plan"]["binding"], authority.principal)
        # A manifest keeps the item limit it was retained under, which may since have
        # been lowered, so it is checked against the hard ceiling rather than the
        # current setting. The text bound is the current setting, read at this use.
        items = snapshot.get("items")
        if not isinstance(items, list) or not 1 <= len(items) <= readers.MAX_ITEMS_CEILING:
            raise ValueError("The exact source item manifest is incomplete.")
        bounds = config.get_knowledge_sources()
        text_limit = bounds["max_text_kib"] * 1024
        records, total = [], 0
        for item in items:
            record = knowledge_base.exact_document(item["collection"], item["document_sha256"])
            metadata = record.get("metadata", {})
            if metadata.get("remote_source_id") != identifier or metadata.get("remote_item_id") != item["remote_id"]:
                raise PermissionError("The source document's actual provenance changed.")
            total += len(record["text"].encode())
            if total > text_limit:
                raise ValueError("The exact remote source exceeds its bounded text projection.")
            committed = _committed_document(record)
            if digest(committed) != item["native_document_sha256"]:
                raise PermissionError("The source document's exact native publication changed.")
            records.append({"item": item, "document": committed})
        # items keeps every record, so the commitment is the same for every reader. Only the
        # records this authority may see under the permission filter are projected to it;
        # with the filter on and no authority, none are.
        email = getattr(authority, "verified_email", "") if authority is not None else ""
        if _by_email(bounds):
            visible = [record for record in records if _visible(record["item"], email)] if authority is not None else []
        else:
            visible = records
        return {"source": identifier, "version": version, "plan_sha256": snapshot["plan_sha256"], "items": records,
                "visible_items": visible, "withheld_for_permissions": len(records) - len(visible),
                "observed_at": snapshot["observed_at"], "name": snapshot["name"], "text_bytes": total}

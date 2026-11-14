"""Cortex: the company brain.

One governed read/write surface over every memory the workforce has:

* **knowledge** -- the tenant's documents and data, retrieved with citations
  through a governed ``knowledge_reader`` the caller injects (without one the
  source is reported as denied; deposits go to :mod:`maverick.knowledge_admin`);
* **skills** -- the recipes learned on this operation (:mod:`maverick.skills`);
* **lessons** -- guidance mined from failures and proven on held-out work
  (:mod:`maverick.self_harness`);
* **record** -- the Operating Record: every decision and sign-off
  (:mod:`maverick.operating_record`); a named ``user:`` caller sees only the
  record of their own work;
* **fleet** -- what agents you didn't build deposited, roster-gated and
  Shield-scanned (:mod:`maverick.fleet_memory`).

Each source keeps its own store, its own gates and its own semantics. Cortex
adds what none of them had together: one query, one provenance envelope
(:class:`Hit`), one audit row per read across all of them
(``EventKind.CORTEX_RECALL``), one deposit path (``EventKind.CORTEX_DEPOSIT``),
and the Agent Trust Plane applied uniformly -- an external caller is gated
*before* any source is touched, not only on the fleet path.

Principles that are not negotiable and are enforced here:

* **Tenant-exact.** Every read is floored to the active tenant
  (:func:`maverick.paths.current_tenant_id`); the result carries the tenant it
  was answered for. Nothing is pooled across tenants.
* **Every read is audited.** The audit row records who asked, which sources
  answered with how many hits, which were denied and why, and a digest of the
  query -- never the query text itself.
* **Fail-open per source, never silently.** A source that is off or broken
  is reported in ``denied`` with its reason; the other sources still answer.
* **The knob wins.** ``[cortex] enable = false`` (or ``MAVERICK_CORTEX=0``)
  turns the whole surface off; each source's own toggle still applies.
"""
from __future__ import annotations

import hashlib
import logging
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

log = logging.getLogger(__name__)

#: The memory sources Cortex federates, in the order they are consulted.
SOURCES: tuple[str, ...] = ("knowledge", "skills", "lessons", "record", "fleet")

_WORD = re.compile(r"[a-z0-9][a-z0-9'-]{2,}")


def enabled() -> bool:
    """``[cortex] enable`` (default on) with the ``MAVERICK_CORTEX`` env override."""
    from .config import env_flag
    v = env_flag("MAVERICK_CORTEX")
    if v is not None:
        return v
    try:
        from .config import load_config
        return bool((load_config().get("cortex") or {}).get("enable", True))
    except Exception:  # pragma: no cover -- no config means the default
        return True


@dataclass(frozen=True)
class Caller:
    """Who is reading or writing. ``external`` callers are enrolled outside
    agents and are gated by the Agent Trust Plane before any source answers."""
    principal: str = "system"
    agent_id: str = ""
    vendor: str = ""
    external: bool = False


@dataclass
class Hit:
    """One recalled item under the common provenance envelope."""
    source: str            # one of SOURCES
    kind: str              # source-specific: collection, "skill", "lesson", record kind...
    text: str
    citation: str          # where it came from, rendered for a prompt or a person
    score: float = 1.0
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Result:
    query: str
    tenant: str | None
    sources: tuple[str, ...]
    hits: list[Hit] = field(default_factory=list)
    per_source: dict[str, int] = field(default_factory=dict)
    denied: dict[str, str] = field(default_factory=dict)
    took_ms: int = 0
    audited: bool = False

    def context(self, max_chars: int = 6000) -> str:
        """Render the hits as a prompt block, each with its citation."""
        blocks, used = [], 0
        for h in self.hits:
            block = f"[{h.source} · {h.citation}]\n{h.text.strip()}"
            if used + len(block) > max_chars:
                break
            blocks.append(block)
            used += len(block) + 2
        return "\n\n".join(blocks)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["hits"] = [h.to_dict() for h in self.hits]
        return d


# ---------------------------------------------------------------- helpers

def _tenant() -> str | None:
    try:
        from .paths import current_tenant_id
        return current_tenant_id()
    except Exception:  # pragma: no cover
        return None


def _digest(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()[:16]


def _audit(kind_name: str, **payload: Any) -> bool:
    """One row on the signed chain. Never blocks Cortex, never silently drops:
    a failed write is logged at WARNING and reported as ``audited=False``."""
    try:
        from . import audit
        return bool(audit.record(getattr(audit.EventKind, kind_name),
                                 agent="cortex", **payload))
    except Exception:  # pragma: no cover -- audit never blocks recall
        log.warning("cortex: audit write failed for %s", kind_name, exc_info=True)
        return False


def _gate(caller: Caller, domain: str | None) -> str | None:
    """The Agent Trust Plane decision for an external caller, or ``None``."""
    from . import fleet_memory

    bound = fleet_memory.current_caller()
    if bound and (not caller.external or caller.agent_id != bound):
        return "The authenticated fleet identity does not match."
    if not caller.external:
        return None
    try:
        from . import agent_trust
        decision = agent_trust.decide_memory_access(caller.agent_id, domain, enforced=True)
    except Exception as e:  # pragma: no cover -- a broken gate fails closed
        return f"trust plane unavailable: {e}"
    if getattr(decision, "allowed", False):
        return None
    return str(getattr(decision, "reason", "denied by the agent trust plane"))


def _tokens(text: str) -> set[str]:
    return set(_WORD.findall((text or "").lower()))


# ---------------------------------------------------------------- sources

def _recall_knowledge(query: str, k: int, tenant: str | None) -> list[Hit]:
    del query, k, tenant
    raise RuntimeError(
        "governed knowledge access is required; use the authenticated Lightwork app"
    )


def _recall_skills(query: str, k: int) -> list[Hit]:
    from . import skills as _skills
    found = _skills.relevant_skills(query, _skills.available_skills(), max_n=k)
    out = []
    for s in found:
        out.append(Hit("skills", "skill", (s.body or "").strip()[:800], s.name, 1.0,
                       {"triggers": list(s.triggers or ()), "verified": bool(getattr(s, "verified", False)),
                        "path": str(getattr(s, "path", ""))}))
    return out


def _recall_lessons(query: str, k: int, *, model_id: str | None,
                    domain: str | None, role: str | None) -> list[Hit]:
    from . import self_harness
    if model_id:
        block = self_harness.recall_addendum(model_id, domain=domain, role=role)
        return [Hit("lessons", "guidance", block, f"self-harness · {model_id}", 1.0,
                    {"model": model_id, "domain": domain, "role": role})] if block else []
    want = _tokens(query)
    scored: list[tuple[float, Hit]] = []
    for model, lines in (self_harness.list_learned() or {}).items():
        for line in lines:
            # list_learned() is a raw, unscreened read of the addenda store
            # (built for operator inspection). recall_addendum() re-screens
            # its own lines before they reach a prompt (_rescreen_block); this
            # fallback renders lines into a Hit the same way, so it needs the
            # exact same screen -- a legacy/tampered/policy-eroding line must
            # not reach a model here just because no model_id was given.
            screened = self_harness.screen_stored_line(line)
            if screened is None:
                continue
            overlap = len(want & _tokens(screened))
            if overlap:
                scored.append((overlap / max(1, len(want)),
                               Hit("lessons", "lesson", screened, f"self-harness · {model}",
                                   overlap / max(1, len(want)), {"model": model})))
    scored.sort(key=lambda t: t[0], reverse=True)
    return [h for _, h in scored[:k]]


def _record_owner(caller: Caller) -> str | None:
    """A named user reads only the record of their own work (as the dashboard
    lists goals); internal and operator callers keep the workspace view."""
    principal = caller.principal or ""
    return principal if principal.startswith("user:") else None


def _recall_record(query: str, k: int, *, domain: str | None, world: Any,
                   caller: Caller) -> list[Hit]:
    from . import operating_record as orec
    if world is None:
        from .world_model import open_world
        world = open_world()
    records = orec.assemble(world, limit=500, owner=_record_owner(caller))
    matched = orec.query(records, text=query, department=domain or "")
    out = []
    for r in matched[:k]:
        who = getattr(r, "decided_by", None) or getattr(r, "actor", "") or "unknown"
        when = time.strftime("%Y-%m-%d %H:%M", time.gmtime(float(getattr(r, "ts", 0) or 0)))
        out.append(Hit("record", str(getattr(r, "kind", "")), str(getattr(r, "subject", "")),
                       f"record · {getattr(r, 'kind', '')} · {who} · {when}", 1.0,
                       {"goal_id": getattr(r, "goal_id", None),
                        "department": getattr(r, "department", ""),
                        "outcome": getattr(r, "outcome", ""),
                        "actor": getattr(r, "actor", "")}))
    return out


def _recall_fleet(query: str, *, caller: Caller, domain: str | None,
                  shield: Any) -> tuple[list[Hit], str | None]:
    if not caller.external:
        return [], ("fleet memory answers enrolled external agents; internal runs "
                    "recall lessons through the orchestrator")
    from . import fleet_memory
    with fleet_memory.bind_verified_caller(caller.agent_id):
        context, reason = fleet_memory.recall(query, agent_id=caller.agent_id,
                                              vendor=caller.vendor, domain=domain,
                                              shield=shield)
    if not context:
        return [], reason or "no fleet context"
    return [Hit("fleet", "lessons", context, f"fleet memory · {caller.vendor}", 1.0,
                {"agent_id": caller.agent_id, "vendor": caller.vendor})], None


# ---------------------------------------------------------------- public API

def recall(
    query: str,
    *,
    caller: Caller | None = None,
    sources: Iterable[str] = SOURCES,
    domain: str | None = None,
    role: str | None = None,
    model_id: str | None = None,
    k: int = 5,
    world: Any = None,
    shield: Any = None,
    goal_id: int | None = None,
    knowledge_reader: Callable[[str, int], tuple[list[Hit], str | None]] | None = None,
) -> Result:
    """Recall from every requested source under one envelope, audited once.

    ``knowledge_reader`` lets a trusted service compose a stricter current-
    rights document boundary while retaining Cortex's single result and audit
    envelope. It must return bounded ``knowledge`` hits and an optional denial.
    ``model_id`` switches the lessons source from a lexical search over the
    learned lines to the exact guidance block the agent loop would inject for
    that model (scoped by ``domain``/``role``). ``world`` lets a caller reuse
    an open world model for the Operating Record source.
    """
    started = time.time()
    caller = caller or Caller()
    wanted = tuple(s for s in sources if s in SOURCES)
    res = Result(query=query, tenant=_tenant(), sources=wanted,
                 per_source=dict.fromkeys(wanted, 0))
    if not enabled():
        res.denied["cortex"] = "cortex is disabled ([cortex] enable = true)"
        res.audited = _audit("CORTEX_RECALL", caller=caller.principal, tenant=res.tenant,
                             sources=list(wanted), per_source=res.per_source,
                             denied=res.denied, query_sha=_digest(query),
                             query_len=len(query or ""), goal_id=goal_id)
        return res
    denial = _gate(caller, domain)
    if denial:
        for s in wanted:
            res.denied[s] = denial
    else:
        for s in wanted:
            if caller.external and s != "fleet":
                res.denied[s] = "This source is not available to external agents."
                continue
            try:
                if s == "knowledge":
                    if knowledge_reader is None:
                        hits = _recall_knowledge(query, k, res.tenant)
                    else:
                        resolved = knowledge_reader(query, k)
                        if not isinstance(resolved, tuple) or len(resolved) != 2:
                            raise RuntimeError("governed knowledge reader returned malformed material")
                        hits, why = resolved
                        if (
                            not isinstance(hits, list)
                            or len(hits) > k
                            or any(type(hit) is not Hit or hit.source != "knowledge" for hit in hits)
                            or (why is not None and not isinstance(why, str))
                        ):
                            raise RuntimeError("governed knowledge reader crossed its result boundary")
                        if why:
                            res.denied[s] = why
                elif s == "skills":
                    hits = _recall_skills(query, k)
                elif s == "lessons":
                    hits = _recall_lessons(query, k, model_id=model_id, domain=domain, role=role)
                elif s == "record":
                    hits = _recall_record(query, k, domain=domain, world=world,
                                          caller=caller)
                else:
                    hits, why = _recall_fleet(query, caller=caller, domain=domain, shield=shield)
                    if why:
                        res.denied[s] = why
            except Exception as e:
                log.warning("cortex: source %s unavailable: %s", s, e)
                res.denied[s] = f"unavailable: {e}"
                hits = []
            res.hits.extend(hits)
            res.per_source[s] = len(hits)
    res.took_ms = int((time.time() - started) * 1000)
    res.audited = _audit("CORTEX_RECALL", caller=caller.principal,
                         external=caller.external, vendor=caller.vendor or None,
                         tenant=res.tenant, domain=domain, sources=list(wanted),
                         per_source=res.per_source, denied=res.denied,
                         query_sha=_digest(query), query_len=len(query or ""),
                         hits=len(res.hits), took_ms=res.took_ms, goal_id=goal_id)
    return res


def deposit(
    text: str,
    *,
    kind: str = "knowledge",
    caller: Caller | None = None,
    collection: str = "cortex",
    source: str = "",
    domain: str | None = None,
    record: dict[str, Any] | None = None,
    shield: Any = None,
    goal_id: int | None = None,
) -> tuple[bool, str]:
    """Write to Cortex. ``kind`` is ``"knowledge"`` (a cited chunk in the
    tenant's knowledge base) or ``"fleet"`` (an enrolled external agent's
    experience, which goes through fleet memory's roster and Shield gates).
    External callers may only deposit into fleet memory. Returns
    ``(ok, reason)`` and leaves one audit row for every outcome it returns;
    an exception raised by the knowledge base or fleet memory propagates and
    is not audited here."""
    caller = caller or Caller()
    tenant = _tenant()

    def _done(ok: bool, reason: str, **extra: Any) -> tuple[bool, str]:
        _audit("CORTEX_DEPOSIT", caller=caller.principal, external=caller.external,
               vendor=caller.vendor or None, tenant=tenant, deposit_kind=kind, ok=ok,
               reason=reason, domain=domain, text_sha=_digest(text),
               text_len=len(text or ""), goal_id=goal_id, **extra)
        return ok, reason

    if not enabled():
        return _done(False, "cortex is disabled ([cortex] enable = true)")
    denial = _gate(caller, domain)
    if denial:
        return _done(False, denial)
    if caller.external and kind != "fleet":
        return _done(False, "external agents deposit into fleet memory only")
    if not (text or "").strip() and not record:
        return _done(False, "nothing to deposit")
    if kind == "knowledge":
        from . import knowledge_admin
        kb = knowledge_admin.open_knowledge_base(tenant=tenant)
        if kb is None:
            return _done(False, "knowledge base unavailable or disabled ([knowledge] enable)")
        try:
            chunks = kb.ingest_text(collection, text, source=source or caller.principal)
        finally:
            close = getattr(kb, "close", None)
            if callable(close):
                close()
        return _done(True, "ingested", collection=collection, chunks=int(chunks or 0),
                     source=source or caller.principal)
    if kind == "fleet":
        from . import fleet_memory
        payload = {"agent_id": caller.agent_id, "vendor": caller.vendor,
                   "goal_text": text, "reflection": text, "domain": domain or "",
                   "kind": "lesson"}
        payload.update(record or {})
        if caller.external:
            try:
                with fleet_memory.bind_verified_caller(caller.agent_id):
                    ok, reason = fleet_memory.ingest(payload, shield=shield)
            except PermissionError:
                return _done(False, "The authenticated fleet identity does not match.")
        else:
            ok, reason = fleet_memory.ingest(payload, shield=shield)
        return _done(bool(ok), reason)
    return _done(False, f"unknown deposit kind {kind!r}")


def status(*, world: Any = None) -> dict[str, Any]:
    """What Cortex holds for the active tenant, per source, plus the posture
    an auditor asks about: encryption at rest and tenant isolation."""
    tenant = _tenant()
    out: dict[str, Any] = {"enabled": enabled(), "tenant": tenant, "sources": {}}
    src = out["sources"]
    try:
        from . import knowledge_admin
        kb = knowledge_admin.open_knowledge_base(tenant=tenant)
        if kb is None:
            src["knowledge"] = {"available": False, "collections": []}
        else:
            try:
                src["knowledge"] = {"available": True, "collections": list(kb.collections())}
            finally:
                close = getattr(kb, "close", None)
                if callable(close):
                    close()
    except Exception as e:
        src["knowledge"] = {"available": False, "error": str(e)}
    try:
        from . import skills as _skills
        found = _skills.available_skills()
        src["skills"] = {"count": len(found), "verified": sum(1 for s in found if getattr(s, "verified", False))}
    except Exception as e:
        src["skills"] = {"count": 0, "error": str(e)}
    try:
        from . import self_harness
        learned = self_harness.list_learned() or {}
        src["lessons"] = {"models": len(learned), "lines": sum(len(v) for v in learned.values()),
                          "enabled": bool(self_harness.enabled())}
    except Exception as e:
        src["lessons"] = {"models": 0, "lines": 0, "error": str(e)}
    try:
        from . import operating_record as orec
        if world is None:
            from .world_model import open_world
            world = open_world()
        records = orec.assemble(world, limit=200)
        st = orec.stats(records)
        src["record"] = {"entries": len(records), **(st.to_dict() if hasattr(st, "to_dict") else asdict(st))}
    except Exception as e:
        src["record"] = {"entries": 0, "error": str(e)}
    try:
        from . import fleet_memory
        src["fleet"] = {"enabled": True, **fleet_memory.status()} if fleet_memory.enabled() else {"enabled": False}
    except Exception as e:
        src["fleet"] = {"enabled": False, "error": str(e)}
    try:
        from . import crypto_at_rest
        out["encryption"] = {"at_rest": bool(crypto_at_rest.at_rest_enabled()),
                             "per_tenant": bool(crypto_at_rest.per_tenant_at_rest())}
    except Exception:
        out["encryption"] = {"at_rest": False, "per_tenant": False}
    out["isolation"] = {
        "tenant_floored": tenant is not None,
        "pooled_across_tenants": False,
        "note": "every source is floored to the active tenant's data directory or namespace; "
                "nothing is learned or aggregated across tenants",
    }
    return out

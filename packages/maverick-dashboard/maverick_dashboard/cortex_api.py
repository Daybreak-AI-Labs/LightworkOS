"""Closed operator API for Cortex, the company brain (``/api/v1/cortex``).

Reads (``status``, ``recall``) sit at the page's ``view`` floor: every role
may ask the brain what it knows, and the kernel lands one audit row per read
whoever asked. Writes (``deposit``) need ``operate``. Every mutation passes
the dashboard's same-origin guard like the rest of ``/api/v1``; nothing here
is exempt. Dashboard callers are internal -- the Agent Trust Plane gate is
for enrolled outside agents -- and are named by their authenticated principal
so the audit row says who asked. Input is bounded at this boundary; the
kernel's own knob, source toggles and per-source denials come back inside the
envelope rather than as transport errors.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Request
from maverick import cortex
from maverick.knowledge_access import KnowledgeAccessDenied, KnowledgeAccessService
from maverick.paths import current_tenant_id_strict
from pydantic import BaseModel, ConfigDict, Field, StringConstraints
from starlette.concurrency import run_in_threadpool

from .auth import caller_principal, require_permission

STATUS_SCHEMA = "lightwork.cortex-status.v1"
RECALL_SCHEMA = "lightwork.cortex-recall.v1"
DEPOSIT_SCHEMA = "lightwork.cortex-deposit.v1"

#: Boundary bounds. A query is a question, not a document; a deposit is a
#: cited chunk, not a corpus; ``k`` is per source, and five sources at fifty
#: each is already more than a prompt can carry.
MAX_QUERY = 2_000
MAX_TEXT = 20_000
MAX_K = 50
DEFAULT_K = 5

QueryText = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=MAX_QUERY)]
DepositText = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=MAX_TEXT)]
Source = Annotated[str, StringConstraints(strict=True,
                                          pattern=r"^(" + "|".join(cortex.SOURCES) + r")$")]
Domain = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=64,
                                          pattern=r"^[A-Za-z0-9][A-Za-z0-9 _./-]{0,63}$")]
Collection = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=64,
                                              pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$")]
DepositKind = Annotated[str, StringConstraints(strict=True, pattern=r"^(knowledge|fleet)$")]
SourceLabel = Annotated[str, StringConstraints(strict=True, max_length=200)]


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RecallIn(_StrictModel):
    query: QueryText
    #: Which memories to consult, in this order; omitted means every source.
    sources: list[Source] | None = Field(default=None, min_length=1,
                                         max_length=len(cortex.SOURCES))
    domain: Domain | None = None
    k: int = Field(default=DEFAULT_K, ge=1, le=MAX_K)


class DepositIn(_StrictModel):
    text: DepositText
    kind: DepositKind = "knowledge"
    collection: Collection = "cortex"
    #: Where the text came from -- the citation later recalls carry.
    source: SourceLabel = ""
    domain: Domain | None = None


def _world_or_none() -> Any:
    """The dashboard's cached world model for the Operating Record source. A
    world that will not open is left to the kernel, which reports that source
    in ``denied`` instead of failing the whole read."""
    from ._shared import _world

    try:
        return _world()
    except Exception:
        return None


def _caller(request: Request) -> cortex.Caller:
    return cortex.Caller(principal=caller_principal(request) or "dashboard")


def _status() -> dict:
    return {"schema": STATUS_SCHEMA, **cortex.status(world=_world_or_none())}


def _governed_recall(
    body: RecallIn,
    caller: cortex.Caller,
    service: KnowledgeAccessService | None,
) -> dict:
    """Compose Cortex's non-document memories with APP10-governed knowledge.

    The legacy knowledge adapter is deliberately never called.  Exact source
    versions come from ``KnowledgeAccessService`` or the knowledge source is
    marked denied; an unavailable registry/projector cannot fall back to raw
    vector recall.
    """

    sources = tuple(dict.fromkeys(body.sources)) if body.sources else cortex.SOURCES
    def governed_knowledge(query: str, limit: int) -> tuple[list[cortex.Hit], str | None]:
        try:
            if service is None:
                raise KnowledgeAccessDenied("governed knowledge access is unavailable")
            tenant = current_tenant_id_strict()
            if not tenant or not caller.principal.startswith("user:"):
                raise KnowledgeAccessDenied(
                    "a named user and selected workspace are required"
                )
            governed = service.search(
                tenant,
                caller.principal,
                query=query,
                purpose="product_research",
                limit=limit,
            )
            knowledge_hits: list[cortex.Hit] = []
            for item in governed["items"]:
                reference = item["reference"]
                knowledge_hits.append(
                    cortex.Hit(
                        "knowledge",
                        str(item["source"]["provenance_kind"]),
                        str(item["summary"]),
                        str(item["source"]["source_ref"]),
                        1.0,
                        {
                            "title": str(item["title"]),
                            "registry_reference": dict(reference),
                            "claim_state": str(item["claim_state"]),
                            "fresh_until": item["eligibility"]["fresh_until"],
                            "actor_authorization_sha256": item["eligibility"][
                                "actor_authorization_sha256"
                            ],
                        },
                    )
                )
            return knowledge_hits, None
        except Exception:  # fail closed; never disclose adapter or registry internals
            return [], (
                "Current source access could not be revalidated. "
                "Open Knowledge and request fresh access or evidence."
            )
    result = cortex.recall(
        body.query.strip(),
        caller=caller,
        sources=sources,
        domain=body.domain,
        k=body.k,
        world=_world_or_none(),
        knowledge_reader=governed_knowledge,
    )
    return {"schema": RECALL_SCHEMA, **result.to_dict()}


def _deposit(body: DepositIn, caller: cortex.Caller) -> dict:
    ok, reason = cortex.deposit(body.text.strip(), kind=body.kind, caller=caller,
                                collection=body.collection, source=body.source.strip(),
                                domain=body.domain)
    return {"schema": DEPOSIT_SCHEMA, "ok": bool(ok), "reason": str(reason), "kind": body.kind}


async def _call(function, *args):
    try:
        return await run_in_threadpool(function, *args)
    except HTTPException:
        raise
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (OSError, RuntimeError) as exc:
        raise HTTPException(status_code=503, detail=f"cortex unavailable: {exc}") from exc


def create_cortex_router() -> APIRouter:
    router = APIRouter(prefix="/cortex", tags=["cortex"])

    @router.get("/status")
    async def status(request: Request):
        require_permission(request, "view")
        return await _call(_status)

    @router.post("/recall")
    async def recall(request: Request, body: RecallIn):
        # Recall remains a read operation.  The APP10 service independently
        # binds the named principal, selected tenant, purpose, and read action;
        # this route cannot turn a view grant into export or training authority.
        require_permission(request, "view")
        if not body.query.strip():
            raise HTTPException(status_code=422, detail="query is blank")
        from .knowledge_access_api import _service as knowledge_service

        try:
            service = knowledge_service(request)
        except Exception:  # source is marked denied inside the composition helper
            service = None

        return await _call(
            _governed_recall,
            body,
            _caller(request),
            service,
        )

    @router.post("/deposit")
    async def deposit(request: Request, body: DepositIn):
        require_permission(request, "operate")
        if not body.text.strip():
            raise HTTPException(status_code=422, detail="nothing to deposit")
        return await _call(_deposit, body, _caller(request))

    return router


router = create_cortex_router()

__all__ = ["DEFAULT_K", "MAX_K", "MAX_QUERY", "MAX_TEXT", "create_cortex_router", "router"]

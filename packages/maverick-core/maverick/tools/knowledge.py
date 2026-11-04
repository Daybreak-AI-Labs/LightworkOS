"""Governed ``knowledge_search`` for domain agents.

The tool never calls the legacy vector store directly. Every invocation resolves
the active tenant and actor, searches exact research-registry source versions for
one fixed purpose/action, and rematerializes selected content at that job's start
boundary before any text is returned to the agent.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence

from ..knowledge_access import KnowledgeAccessService
from ..knowledge_retrieval import render_evidence
from . import Tool


def knowledge_search_tool(
    service_resolver: KnowledgeAccessService | Callable[[], KnowledgeAccessService],
    source_selectors: Sequence[str],
    *,
    tenant_resolver: Callable[[], str | None] | None = None,
    actor_resolver: Callable[[], str] | None = None,
    purpose: str = "product_research",
    job_id_resolver: Callable[[], str] | None = None,
) -> Tool:
    """Bind an agent lookup to current APP10 authority and exact sources."""

    selectors = tuple(source_selectors)

    async def fn(args: dict) -> str:
        query = str(args.get("query", "")).strip()
        if not query:
            return "ERROR: 'query' is required."
        try:
            k = int(args.get("k", 5))
        except (TypeError, ValueError):
            k = 5
        k = min(50, max(1, k))
        try:
            service = (
                service_resolver
                if isinstance(service_resolver, KnowledgeAccessService)
                else service_resolver()
            )
            if not isinstance(service, KnowledgeAccessService):
                raise TypeError("governed knowledge service is unavailable")
            if tenant_resolver is None:
                from ..paths import current_tenant_id_strict

                tenant = current_tenant_id_strict()
            else:
                tenant = tenant_resolver()
            if not tenant:
                raise PermissionError("a selected knowledge workspace is required")
            result = service.search_at_job_start(
                tenant,
                (
                    actor_resolver()
                    if actor_resolver is not None
                    else "worker:knowledge-search"
                ),
                query=query,
                purpose=purpose,
                source_selectors=selectors,
                limit=k,
                cursor=args.get("cursor"),
                job_id=(
                    job_id_resolver()
                    if job_id_resolver is not None
                    else f"knowledge-{uuid.uuid4().hex}"
                ),
            )
            return render_evidence(result)
        except (KeyboardInterrupt, SystemExit):
            raise
        except ValueError:
            return "knowledge_search unavailable: invalid or changed search; restart without cursor."
        except Exception as exc:
            return f"knowledge_search unavailable: {type(exc).__name__}"

    return Tool(
        name="knowledge_search",
        description=(
            "Search exact currently eligible source versions assigned to this domain. "
            "Every result is tenant-, actor-, purpose-, action-, and job-start-bound."
        ),
        input_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "What to look for."},
                "k": {"type": "integer", "description": "Max passages (default 5)."},
                "cursor": {
                    "type": "string", "maxLength": 2048,
                    "description": "next_cursor from an incomplete result; keep query and k unchanged.",
                },
            },
            "required": ["query"],
        },
        fn=fn,
    )

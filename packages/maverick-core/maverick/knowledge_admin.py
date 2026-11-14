"""Governed administration of the knowledge plane: erasure, retention, and
verification over the per-domain vector store.

The kernel runs WITHOUT ``maverick-knowledge`` (it is an optional extra).
Disabled knowledge contributes no records unless a store from when it was
enabled still exists; erasure and residual counts still look at that store. Once configured, unavailable
storage raises ``KnowledgeUnavailable``; it cannot certify an erasure or zero
residual records. When knowledge IS enabled, a subject's
ingested documents are removed by provenance so a right-to-erasure request
reaches the vector store, not just the world model — closing the gap where a
subject's embedded document chunks would otherwise survive erasure.

The subject key mirrors the DSAR/erase convention exactly (``channel:user_id``,
each component percent-quoted) so "a chunk that would be erased is a chunk that
is counted" — the same invariant the world-model verifier relies on.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any
from urllib.parse import quote

log = logging.getLogger(__name__)


class KnowledgeUnavailable(RuntimeError):
    """A configured knowledge plane could not complete administration."""


def subject_key(channel: str, user_id: str) -> str:
    """The provenance ``subject`` stamped on a data subject's ingested chunks.

    Identical to :func:`maverick.dsar._fact_subject_token` so knowledge erasure
    and world-model erasure agree on what "this subject's data" means.
    """
    return f"{quote(channel, safe='')}:{quote(user_id, safe='')}"


def open_knowledge_base(
    *, tenant: str | None = None, require_existing: bool = False,
) -> Any | None:
    """Open the selected tenant's KnowledgeBase; ``None`` only when disabled.

    Explicit tenant identity wins over ambient context. A custom SQLite path
    in a tenant scope must remain under that workspace; shared legacy paths
    cannot silently administer another customer's records. Counting/erasure
    require an existing store so a lost database cannot become a new empty one.
    The caller closes the returned base (it holds a DB handle).
    """
    try:
        if tenant is not None and (not isinstance(tenant, str) or not tenant.strip()):
            raise KnowledgeUnavailable("knowledge administration requires a nonempty tenant")
        from .config import get_knowledge
        kcfg = get_knowledge()
        if not kcfg.get("enable"):
            return None
        kcfg, path = _store_config(kcfg, tenant)
        if require_existing and str(kcfg.get("store", "sqlite")).lower() == "sqlite":
            if not path.is_file():
                raise KnowledgeUnavailable("configured knowledge store is missing or unavailable")
        from maverick_knowledge import KnowledgeBase, build_embedder, build_store
        embedder = build_embedder(kcfg)
        return KnowledgeBase(store=build_store(kcfg), embedder=embedder)
    except KnowledgeUnavailable:
        raise
    except Exception as e:
        log.warning("knowledge admin: configured base unavailable: %s", type(e).__name__)
        raise KnowledgeUnavailable("configured knowledge store is unavailable") from e


def _store_config(kcfg: dict, tenant: str | None, *, confine: bool = True) -> tuple[dict, Path]:
    """``kcfg`` with its resolved store path, confined to the tenant workspace
    unless ``confine`` is false (an existence probe that opens nothing)."""
    from .workspace import Workspace
    workspace = Workspace(tenant) if tenant is not None else Workspace.current()
    configured_path = kcfg.get("path")
    path = Path(configured_path or workspace.knowledge_path).expanduser().resolve()
    if confine and workspace.tenant and configured_path and not path.is_relative_to(workspace.root.resolve()):
        raise KnowledgeUnavailable("knowledge path is outside the selected tenant workspace")
    return {**kcfg, "path": str(path)}, path


def _open_for_subject_admin(tenant: str | None) -> Any | None:
    """The knowledge base erasure and residual counting must look at.

    Turning ``[knowledge] enable`` off does not delete a populated store, so
    a disabled plane still opens one that exists for erasure and counting:
    the SQLite file at the resolved path, or pgvector rows for this workspace
    (found with a read-only query; no DDL runs). ``None`` when knowledge is
    disabled and no such store exists. A disabled Qdrant store is not
    contacted: Lightwork refuses ingestion into Qdrant, so it holds no
    documents this plane stamped with a subject. No embedder is built:
    erasure and counting match provenance only.
    """
    kb = open_knowledge_base(tenant=tenant, require_existing=True)
    if kb is not None:
        return kb
    from .config import get_knowledge
    raw = get_knowledge()
    kcfg, path = _store_config(raw, tenant, confine=False)
    store = str(kcfg.get("store", "sqlite")).lower()
    try:
        if store == "sqlite":
            if not path.is_file():
                return None
            _store_config(raw, tenant)  # an existing store must be this tenant's
            from maverick_knowledge import KnowledgeBase, build_store
            return KnowledgeBase(store=build_store(kcfg))
        if store == "pgvector":
            return _open_disabled_pgvector(raw, kcfg, tenant)
        return None
    except KnowledgeUnavailable:
        raise
    except Exception as e:
        log.warning("knowledge admin: disabled store unavailable: %s", type(e).__name__)
        raise KnowledgeUnavailable(
            "knowledge is turned off, but its existing store could not be opened to "
            "erase or count this subject's records"
        ) from e


def _open_disabled_pgvector(raw: dict, kcfg: dict, tenant: str | None) -> Any | None:
    """pgvector rows left for this workspace, or ``None`` without any DDL."""
    import os
    if not (kcfg.get("dsn") or os.environ.get("MAVERICK_KNOWLEDGE_DSN")
            or os.environ.get("MAVERICK_PG_DSN")):
        return None
    try:
        from maverick_knowledge import KnowledgeBase
        from maverick_knowledge.store import open_existing_pgvector
    except ModuleNotFoundError:
        return None  # without the package there is no reader for the table
    pg = open_existing_pgvector(kcfg)
    if pg is None:
        return None
    try:
        _store_config(raw, tenant)
    except KnowledgeUnavailable:
        pg.close()
        raise
    return KnowledgeBase(store=pg)


def erase_subject(channel: str, user_id: str, *,
                  tenant: str | None = None) -> dict[str, int]:
    """Delete a subject's document chunks from every knowledge collection.

    Returns ``{collection: chunks_removed}`` (empty when knowledge is off and
    no store exists, or the subject had no ingested documents) — the evidence
    the erase command folds into its signed audit event.
    """
    subject = _validated_subject(channel, user_id)
    kb = _open_for_subject_admin(tenant)
    if kb is None:
        _ensure_disabled()
        return {}
    try:
        return kb.erase_subject(subject)
    except Exception as e:
        raise KnowledgeUnavailable("knowledge erasure could not be completed") from e
    finally:
        _close(kb)


def count_subject(channel: str, user_id: str, *,
                  tenant: str | None = None) -> int:
    """Residual document chunks for a subject across all collections.

    The erasure-verify primitive: should be 0 after :func:`erase_subject`.
    Disabled knowledge with no existing store contributes 0; a store left on
    disk after knowledge was disabled is still counted. Unavailable or missing
    configured storage raises rather than claiming that the residual count was
    observed.
    """
    subject = _validated_subject(channel, user_id)
    kb = _open_for_subject_admin(tenant)
    if kb is None:
        _ensure_disabled()
        return 0
    try:
        count = kb.count_subject(subject)
        if type(count) is not int or count < 0:
            raise KnowledgeUnavailable("knowledge residual query returned an invalid count")
        return count
    except Exception as e:
        raise KnowledgeUnavailable("knowledge residual count is unavailable") from e
    finally:
        _close(kb)


def _ensure_disabled() -> None:
    from .config import get_knowledge
    if get_knowledge().get("enable"):
        raise KnowledgeUnavailable("configured knowledge store is unavailable")


def _validated_subject(channel: str, user_id: str) -> str:
    if any(not isinstance(value, str) or not value.strip() for value in (channel, user_id)):
        raise KnowledgeUnavailable("knowledge administration requires channel and user identity")
    return subject_key(channel, user_id)


def _close(kb: Any) -> None:
    try:
        kb.close()
    except Exception:  # pragma: no cover
        pass

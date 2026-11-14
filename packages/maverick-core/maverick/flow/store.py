"""Persistence for flow definitions and their (resumable) runs.

Definitions and bounded run previews live under the tenant-scoped data dir.
Complete execution data is inline when small, otherwise in a private encrypted
artifact referenced by the run row. Missing/corrupt execution data fails closed;
display truncation is never used as resume input.
"""
from __future__ import annotations

import json
import logging
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

from .ir import Flow, clamp_saved_numbers

log = logging.getLogger(__name__)

_MAX_FLOW_DEFINITION_BYTES = 1_000_000


def _flows_dir():
    return _flow_dir()


def _history_dir(flow_id: str):
    return _flow_dir("history", _safe_id(flow_id))


def _flow_dir(*parts: str) -> Path:
    import os

    from ..file_lock import _windows_extended_path
    from ..paths import data_dir

    path = data_dir("flows", *parts)
    # Keep every derived flow path on one spelling: definitions, history,
    # snapshots, release pointers, claims, checkpoint rows and SQLite journals.
    return Path(_windows_extended_path(path)) if os.name == "nt" else path


def _runs_dir():
    return _flow_dir("runs")


def _objects_dir():
    return _flow_dir("objects")


def _published_dir():
    return _flow_dir("published")


@contextmanager
def _activation_lock(flow_id: str):
    """Serialize release replacement/revocation with dispatch decisions.

    Draft writes do not need this lock: immutable published objects remain
    unchanged. A live worker holds this per-flow mutex only for its final release
    check. Mutation that wins first revokes queued work; work that wins first is
    considered started and runs without holding this lock through execution.
    """
    from ..file_lock import cross_process_lock

    path = _published_dir() / f".{_safe_id(flow_id)}.activation"
    with cross_process_lock(path, strict=True):
        yield


def _idempotency_dir():
    return _flow_dir("idempotency")


def _schema_dir():
    return _flow_dir("schema")


def load_flow_schema(flow_id: str) -> dict:
    """The accumulated per-output-key shape hints for a flow (empty if none).
    Field names + types only -- never values (see :mod:`.schema_infer`)."""
    return _read_json(_schema_dir() / f"{_safe_id(flow_id)}.json") or {}


def record_flow_schema(
    flow_id: str, shapes: dict, *, revision: str | None = None,
) -> None:
    """Merge freshly-observed output shapes into the flow's accumulated hints
    and persist them. Best-effort: any error is swallowed HERE, the one owner
    of that policy (a schema hint is never worth failing a run over)."""
    if not shapes:
        return
    try:
        # An old in-flight generation may finish after delete/recreate.  Couple
        # the revision check and write to the definition lock so its learned
        # field names cannot bleed into the replacement flow's designer.
        with _definitions_lock():
            current = load_flow(flow_id)
            if (revision is not None
                    and (current is None or current.revision != str(revision))):
                return
            from .schema_infer import merge_shapes
            merged = merge_shapes(load_flow_schema(flow_id), shapes)
            _write_json(_schema_dir() / f"{_safe_id(flow_id)}.json", merged)
    except Exception:  # pragma: no cover -- best-effort
        pass


def _write_json(path, obj: dict, *, effect_guard: Callable[[], None] | None = None) -> None:
    from ..file_lock import atomic_write_text
    text = json.dumps(obj, sort_keys=True)
    if effect_guard is None:
        atomic_write_text(path, text)
    else:
        atomic_write_text(path, text, effect_guard=effect_guard)


def _read_json(path) -> dict | None:
    try:
        from ..file_lock import atomic_read_text
        d = json.loads(atomic_read_text(path))
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


# ---- flow definitions -------------------------------------------------------

@contextmanager
def _definitions_lock():
    """Serialize definition edits with content-addressed run snapshots."""
    from ..file_lock import cross_process_lock
    with cross_process_lock(_flows_dir() / ".definitions", strict=True):
        yield


class FlowVersionConflict(RuntimeError):
    """A definition changed after the caller read its expected version."""


def _assert_safe_definition(payload: dict) -> None:
    """Refuse oversized definitions and raw credentials before persistence."""
    remaining = _MAX_FLOW_DEFINITION_BYTES

    def charge(value, *, depth: int = 0) -> None:
        nonlocal remaining
        if depth > 32:
            raise ValueError("flow definition nesting is too deep")
        remaining -= 8  # container/scalar JSON punctuation and type overhead
        if remaining < 0:
            raise ValueError("flow definition exceeds the storage limit")
        if isinstance(value, str):
            if len(value) > _MAX_FLOW_DEFINITION_BYTES:
                raise ValueError("flow definition exceeds the storage limit")
            remaining -= len(value.encode("utf-8"))
        elif isinstance(value, dict):
            for key, item in value.items():
                charge(str(key), depth=depth + 1)
                charge(item, depth=depth + 1)
        elif isinstance(value, (list, tuple)):
            for item in value:
                charge(item, depth=depth + 1)
        if remaining < 0:
            raise ValueError("flow definition exceeds the storage limit")

    charge(payload)
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    if len(raw.encode("utf-8")) > _MAX_FLOW_DEFINITION_BYTES:
        raise ValueError("flow definition exceeds the storage limit")
    from ..safety.secret_detector import scan

    def contains_secret(value) -> bool:
        if isinstance(value, str):
            return bool(scan(value))
        if isinstance(value, dict):
            return any(
                contains_secret(str(key)) or contains_secret(item)
                for key, item in value.items()
            )
        if isinstance(value, (list, tuple)):
            return any(contains_secret(item) for item in value)
        return False

    if contains_secret(payload):
        raise ValueError(
            "flow definitions may not contain raw credentials; "
            "review the account in Connections and use its authorized native connector action instead"
        )


def save_flow(
    flow: Flow,
    *,
    expected_version: int | None = None,
    expected_revision: str | None = None,
    effect_guard: Callable[[], None] | None = None,
) -> Flow:
    """Persist ``flow`` as the current definition, snapshotting the prior current
    into version history first so any earlier version can be rolled back to.

    The store owns the version number: each save stamps ``version = prior + 1``
    (a brand-new flow starts at 1). Returns the saved flow with its stamped
    version. Forward-only history -- a rollback is itself a new version, so
    nothing is ever destroyed."""
    # Reject unsafe content before any history/version side effect, then check
    # the exact stamped payload again under the definition lock.
    _assert_safe_definition(flow.to_dict())
    from .recipe_flow import check_persisted_lineage
    check_persisted_lineage(flow)
    with _definitions_lock():
        prior = load_flow(flow.id)
        actual_version = int(prior.version) if prior is not None else 0
        if expected_version is not None and actual_version != int(expected_version):
            raise FlowVersionConflict(
                f"flow {flow.id!r} changed (expected version {expected_version}, "
                f"current {actual_version})")
        actual_revision = str(getattr(prior, "revision", "") or "")
        if expected_revision is not None and actual_revision != str(expected_revision):
            raise FlowVersionConflict(
                f"flow {flow.id!r} was replaced or changed generation")
        if prior is not None:
            flow.version = int(prior.version) + 1
            # A generation token never changes during ordinary edits/rollbacks.
            # It closes the delete+recreate ABA hole that a resettable integer
            # version cannot detect.
            flow.revision = actual_revision or _new_revision()
        else:
            # Version numbers are store-owned. Never let a client create v-7 or
            # v999 and weaken the history/CAS invariants.
            flow.version = 1
            flow.revision = _new_revision()
        payload = flow.to_dict()
        _assert_safe_definition(payload)
        check_persisted_lineage(Flow.from_dict(payload))
        if prior is not None:
            # Snapshot the version being replaced under its own number, then advance.
            _write_json(
                _history_dir(flow.id) / f"v{int(prior.version)}.json",
                prior.to_dict(),
                effect_guard=effect_guard,
            )
        _write_json(_flows_dir() / f"{_safe_id(flow.id)}.json", payload, effect_guard=effect_guard)
    return flow


def _new_revision() -> str:
    from uuid import uuid4

    return uuid4().hex


def load_flow(flow_id: str) -> Flow | None:
    d = _read_json(_flows_dir() / f"{_safe_id(flow_id)}.json")
    return Flow.from_dict(d) if d else None


def list_versions(flow_id: str) -> list[Flow]:
    """Every stored version of a flow (history snapshots + the current), oldest
    first. Empty if the flow is unknown."""
    out: list[Flow] = []
    hist = _history_dir(flow_id)
    if hist.exists():
        for p in hist.glob("v*.json"):
            raw = _read_json(p)
            if raw:
                out.append(Flow.from_dict(raw))
    cur = load_flow(flow_id)
    if cur is not None:
        out.append(cur)
    out.sort(key=lambda f: f.version)
    return out


def load_version(flow_id: str, version: int) -> Flow | None:
    """A specific historical (or current) version of a flow."""
    cur = load_flow(flow_id)
    if cur is not None and int(cur.version) == int(version):
        return cur
    raw = _read_json(_history_dir(flow_id) / f"v{int(version)}.json")
    return Flow.from_dict(raw) if raw else None


def rollback_flow(
    flow_id: str,
    version: int | None = None,
    *,
    expected_version: int | None = None,
    expected_revision: str | None = None,
) -> Flow | None:
    """Restore a prior ``version`` (default: the one immediately before current)
    as a NEW current version -- non-destructive, so the rollback can itself be
    undone. Returns the new current flow, or ``None`` if the target is unknown."""
    cur = load_flow(flow_id)
    if cur is None:
        return None
    target_v = version if version is not None else int(cur.version) - 1
    target = load_version(flow_id, target_v)
    if target is None:
        return None
    return save_flow(
        target.copy(),
        expected_version=expected_version,
        expected_revision=expected_revision,
    )   # re-save the old content as a fresh version


def list_flows() -> list[Flow]:
    d = _flows_dir()
    if not d.exists():
        return []
    out = []
    for p in sorted(d.glob("*.json")):
        raw = _read_json(p)
        if raw:
            out.append(Flow.from_dict(raw))
    return out


def list_flow_summaries(*, owner: str | None = None, after=None, before=None, bounded=False) -> list[dict]:
    """Cheap listing for index pages -- id/name/node count/single-agent flag
    plucked from the raw JSON, WITHOUT building the full recursive Flow IR per
    file (list_flows constructs every nested body just to be counted)."""
    import time

    from ..metadata_history import check_scan
    started = time.monotonic()
    d = _flows_dir()
    if not d.exists():
        return []
    out = []
    for count, p in enumerate(sorted(d.glob("*.json")), 1):
        if bounded:
            check_scan(count, started)
        modified = p.stat().st_mtime
        if (after is not None and modified < after) or (before is not None and modified >= before):
            continue
        raw = _read_json(p) or {}
        if not raw.get("id") or (owner is not None and (raw.get("owner") or "") != owner):
            continue
        nodes = [n for n in (raw.get("nodes") or []) if isinstance(n, dict)]
        out.append({
            "id": str(raw["id"]), "name": str(raw.get("name") or ""),
            "nodes": len(nodes), "owner": str(raw.get("owner") or ""),
            "version": raw.get("version", 0), "revision": raw.get("revision", ""),
            "updated_at": modified,
            "single_agent": (len(nodes) == 1 and nodes[0].get("kind") == "agent"
                             and not nodes[0].get("next")),
        })
    return out


def delete_flow(
    flow_id: str,
    *,
    expected_version: int | None = None,
    expected_revision: str | None = None,
    expected_release_id: str | None = None,
) -> bool:
    """Revoke activation and delete one definition under one lock order."""
    with _activation_lock(flow_id):
        return _delete_flow_under_activation(
            flow_id,
            expected_version=expected_version,
            expected_revision=expected_revision,
            expected_release_id=expected_release_id,
        )


def _delete_flow_under_activation(
    flow_id: str,
    *,
    expected_version: int | None = None,
    expected_revision: str | None = None,
    expected_release_id: str | None = None,
) -> bool:
    """Delete one definition, optionally guarded by its exact generation.

    API callers must pass both CAS tokens read during authorization.  Checking
    them under the same definition lock as unlink closes the delete/recreate ABA
    race where a stale request could otherwise remove a new owner's flow.
    """
    with _definitions_lock():
        current = load_flow(flow_id)
        if current is None:
            return False
        if expected_version is not None and int(current.version) != int(expected_version):
            raise FlowVersionConflict(
                f"flow {flow_id!r} changed (expected version {expected_version}, "
                f"current {current.version})")
        if (expected_revision is not None
                and str(current.revision or "") != str(expected_revision)):
            raise FlowVersionConflict(
                f"flow {flow_id!r} was replaced or changed generation")
        if expected_release_id is not None:
            published = load_published_bundle(flow_id)
            active_id = str(published[1]["release_id"]) if published else ""
            if active_id != expected_release_id:
                raise FlowVersionConflict(f"published flow {flow_id!r} changed since review")
        with _activation_lock(flow_id):
            # Authorization must disappear before the draft does.  Moving the
            # pointer out of the live ``*.json`` namespace is atomic on the
            # same filesystem and leaves a retryable tombstone if a later
            # cleanup step fails or the process crashes.
            _revoke_published_pointer_locked(flow_id)
            p = _flows_dir() / f"{_safe_id(flow_id)}.json"
            try:
                p.unlink()
            except OSError as exc:
                raise FlowSnapshotError(
                    f"flow {flow_id!r} was revoked but its draft could not be deleted"
                ) from exc
            # Drop version history too, so a later flow re-created with this id
            # doesn't inherit stale snapshots (best-effort -- a missing history
            # dir is fine).
            import shutil
            shutil.rmtree(_history_dir(flow_id), ignore_errors=True)
            try:
                (_schema_dir() / f"{_safe_id(flow_id)}.json").unlink()
            except OSError:
                pass
            try:
                _revoked_pointer_path(flow_id).unlink()
            except OSError:
                pass
            return True


def _safe_id(flow_id: str) -> str:
    """An injective-enough filesystem key that cannot traverse or alias.

    Already-safe historical IDs keep their filename.  Any normalization or
    truncation receives a digest of the original value, so e.g. ``a/b`` can no
    longer address the same definition as ``a-b``.
    """
    import re
    raw = str(flow_id or "").strip()
    s = re.sub(r"[^A-Za-z0-9_-]+", "-", raw).strip("-") or "flow"
    if s == raw and len(s) <= 120:
        return s
    suffix = sha256(raw.encode("utf-8")).hexdigest()[:20]
    return f"{s[:99]}-{suffix}"


class FlowSnapshotError(RuntimeError):
    """An immutable execution-plan object is missing or fails its digest."""


def _published_pointer_path(flow_id: str):
    return _published_dir() / f"{_safe_id(flow_id)}.json"


def _revoked_pointer_path(flow_id: str):
    # Deliberately not JSON: live pointer enumeration only admits ``*.json``.
    return _published_dir() / f".{_safe_id(flow_id)}.revoked"


def _revoke_published_pointer_locked(flow_id: str) -> bool:
    """Atomically remove a pointer from the live namespace.

    The caller owns the activation and definition locks.  A rename failure is
    a hard failure: deleting the draft while executable authority remains would
    create an unmanageable live orphan.
    """
    import os

    pointer = _published_pointer_path(flow_id)
    try:
        os.replace(pointer, _revoked_pointer_path(flow_id))
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise FlowSnapshotError(
            f"published flow {flow_id!r} could not be revoked"
        ) from exc


def _canonical_flow_bytes(raw: dict) -> bytes:
    return json.dumps(
        raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


def release_digest_for(
    definition_digest: str,
    subflow_digests: dict[str, str | None],
) -> str:
    """Content identity for one complete immutable execution bundle.

    The root CAS digest alone is not a release identity: an unchanged parent
    may be republished after one of its referenced children changes.  Domain
    separation plus canonical JSON makes this stable across processes and
    insensitive to dictionary insertion order while binding missing children
    (``None``) just as strongly as present ones.
    """
    if not isinstance(subflow_digests, dict):
        raise FlowSnapshotError("published subflow manifest is invalid")
    manifest = {
        str(key): (str(value) if value is not None else None)
        for key, value in subflow_digests.items()
    }
    material = {
        "definition_digest": str(definition_digest or ""),
        "schema": "maverick.flow.release.v1",
        "subflow_digests": manifest,
    }
    return sha256(_canonical_flow_bytes(material)).hexdigest()


def release_id_for(
    definition_digest: str,
    subflow_digests: dict[str, str | None],
) -> str:
    """Backward-compatible name for the immutable bundle content digest.

    New authorization code must use the publication-scoped ``release_id`` from
    :func:`publish_flow`; identical content can be activated more than once.
    """
    return release_digest_for(definition_digest, subflow_digests)


def _valid_release_token(value: str) -> bool:
    import re

    return bool(re.fullmatch(r"[0-9a-f]{64}", str(value or "")))


def _store_flow_object(raw: dict) -> str:
    digest = sha256(_canonical_flow_bytes(raw)).hexdigest()
    path = _objects_dir() / f"{digest}.json"
    if path.exists():
        existing = _read_json(path)
        if existing is None or sha256(_canonical_flow_bytes(existing)).hexdigest() != digest:
            raise FlowSnapshotError(f"flow snapshot {digest} is corrupt")
        return digest
    _write_json(path, raw)
    return digest


def _snapshot_flow_bundle_locked(
    flow: Flow, *, validate_reachability: bool = False,
) -> tuple[str, int, dict[str, str | None]]:
    """Snapshot a root and its transitive children under ``_definitions_lock``."""
    # Unsaved dry-run drafts reach this boundary without passing save_flow.
    # Apply the same size/secret persistence policy before writing CAS objects.
    _assert_safe_definition(flow.to_dict())
    manifest: dict[str, str | None] = {}
    pending_objects: dict[str, dict] = {}
    # A subflow is executable code/data owned by its definition owner.  Flow ids
    # are not capabilities: an authenticated caller who guesses another user's
    # id must not be able to smuggle that private graph into an otherwise-owned
    # root.  Enforce the invariant at the immutable snapshot boundary so every
    # producer (manual, cron, event, retry, and direct execution) inherits it.
    # Ownerless definitions are a separate namespace in authenticated mode and
    # therefore may only compose with other ownerless definitions.
    root_owner = str(flow.owner or "")

    def walk(raw: dict) -> None:
        from .recipe_flow import check_persisted_lineage
        _assert_safe_definition(raw)
        check_persisted_lineage(Flow.from_dict(raw), owner=root_owner)
        for node in raw.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            body = node.get("body")
            if isinstance(body, dict):
                walk(body)
            for branch in node.get("branches") or []:
                if isinstance(branch, dict):
                    walk(branch)
            if str(node.get("kind")) != "subflow":
                continue
            ref = str(node.get("flow_ref") or "").strip()
            if not ref or ref in manifest:
                continue
            child = load_flow(ref)
            if child is None:
                manifest[ref] = None
                continue
            if str(child.owner or "") != root_owner:
                raise FlowSnapshotError(
                    f"subflow {ref!r} is unavailable to this flow owner"
                )
            if validate_reachability:
                errors = child.reachability_errors()
                if errors:
                    raise FlowSnapshotError(
                        f"subflow {ref!r} cannot be published: " + "; ".join(errors[:3])
                    )
            child_raw = child.to_dict()
            # Mark visited for cycles, but write no objects until the entire
            # selected graph passes persistence and lineage policy.
            manifest[ref] = None
            pending_objects[ref] = child_raw
            walk(child_raw)

    root = flow.to_dict()
    walk(root)
    root_digest = _store_flow_object(root)
    for ref, raw in pending_objects.items():
        manifest[ref] = _store_flow_object(raw)
    return root_digest, int(flow.version), manifest


def snapshot_flow_bundle(flow: Flow) -> tuple[str, int, dict[str, str | None]]:
    """Pin ``flow`` and every static subflow reference as immutable CAS objects.

    The manifest records missing children explicitly as ``None``.  That matters:
    a subflow created after a human reviewed/approved the parent must not become
    executable retroactively.  Definition writes/deletes share the same lock, so
    a bundle observes one coherent set of current definitions.
    """
    with _definitions_lock():
        return _snapshot_flow_bundle_locked(flow)


def snapshot_current_flow_bundle(flow_id: str) -> tuple[str, int, dict[str, str | None]]:
    """Atomically load and snapshot the current root plus its child graph.

    Loading the root before taking the definition lock can mix an old parent
    with newer child definitions. Queue producers use this helper so the entire
    execution plan is observed at one definition instant.
    """
    with _definitions_lock():
        flow = load_flow(flow_id)
        if flow is None:
            raise FlowSnapshotError(f"flow {flow_id!r} is unavailable")
        return _snapshot_flow_bundle_locked(flow)


def definition_cohort(revision: str, version: int) -> str:
    """Immutable evidence cohort for one saved definition.

    ``Flow.revision`` is deliberately stable across ordinary saves so it can
    detect delete/recreate ABA. Learning needs the narrower identity of one
    exact definition, hence the generation token plus store-owned version.
    """
    generation = str(revision or "")
    return f"{generation}:v{int(version or 0)}" if generation else ""


def flow_cohort(flow: Flow) -> str:
    return definition_cohort(flow.revision, flow.version)


def publish_flow(
    flow_id: str,
    *,
    expected_version: int,
    expected_revision: str,
    expected_release_id: str | None = None,
    activation_id: str | None = None,
    expected_bundle_digest: str | None = None,
    effect_guard: Callable[[], None] | None = None,
) -> dict:
    """Activate a coherent immutable release under the dispatch lock."""
    with _activation_lock(flow_id):
        if expected_release_id is not None:
            active = load_published_bundle(flow_id)
            if active is None or active[1]["release_id"] != expected_release_id:
                raise FlowSnapshotError("The published workflow changed. Review its current release again.")
        return _publish_flow_under_activation(
            flow_id,
            expected_version=expected_version,
            expected_revision=expected_revision,
            activation_id=activation_id,
            expected_bundle_digest=expected_bundle_digest,
            effect_guard=effect_guard,
        )


def restore_published_flow(
    flow_id: str, retained_release: dict, *, expected_release_id: str,
    expected_version: int, expected_revision: str,
    activation_id: str | None = None,
    effect_guard: Callable[[], None] | None = None,
) -> dict:
    """Restore retained content with a fresh activation, without editing the draft.

    Old waiting runs remain revoked: restoration must never revive a previous
    authorization epoch. The caller owns current permission and evidence checks.
    """
    import secrets

    with _activation_lock(flow_id), _definitions_lock():
        draft = load_flow(flow_id)
        active = load_published_bundle(flow_id)
        if (draft is None or draft.version != expected_version
                or draft.revision != expected_revision):
            raise FlowVersionConflict("The saved workflow changed. Review restoration again.")
        if active is None or active[1]["release_id"] != expected_release_id:
            raise FlowSnapshotError("The published workflow changed. Review restoration again.")
        prior = load_flow_snapshot(str(retained_release.get("definition_digest") or ""))
        manifest = retained_release.get("subflow_digests")
        if (prior.id != flow_id or prior.owner != draft.owner or prior.revision != draft.revision
                or retained_release.get("flow_id") != flow_id
                or prior.version != retained_release.get("definition_version")
                or prior.revision != retained_release.get("definition_revision")
                or not isinstance(manifest, dict)):
            raise FlowSnapshotError("The retained release no longer belongs to this workflow.")
        validate_snapshot_bundle_owners(prior, manifest)
        digest = release_digest_for(retained_release["definition_digest"], manifest)
        if digest != retained_release.get("release_digest"):
            raise FlowSnapshotError("The retained release failed its content check.")
        from .recipe_flow import check_persisted_lineage
        check_persisted_lineage(prior)
        if activation_id is not None and (not _valid_release_token(activation_id)
                or activation_id in {active[1]["release_id"], retained_release.get("release_id")}):
            raise FlowSnapshotError("The new activation identity is invalid.")
        restored = {**retained_release, "release_digest": digest,
                    "release_id": activation_id or secrets.token_hex(32), "published_at": time.time()}
        _write_json(_published_pointer_path(flow_id), restored, effect_guard=effect_guard)
        return restored


def save_and_publish_flow(
    flow: Flow,
    *,
    expected_version: int,
    expected_revision: str,
    expected_release_id: str,
) -> tuple[Flow, dict]:
    """Save an autonomous edit and replace the exact active publication.

    This is intentionally stricter than an ordinary save+publish sequence: the
    active release must still be the caller's predecessor *and* its content must
    match the current draft plus child graph. Thus autonomous learning cannot
    accidentally publish unrelated human draft/child edits, and a concurrent
    human publish wins by invalidating the activation CAS.
    """
    with _activation_lock(flow.id):
        with _definitions_lock():
            current = load_flow(flow.id)
            if current is None:
                raise FlowSnapshotError(f"flow {flow.id!r} is unavailable")
            if int(current.version) != int(expected_version):
                raise FlowVersionConflict(
                    f"flow {flow.id!r} changed (expected version {expected_version}, "
                    f"current {current.version})"
                )
            if str(current.revision or "") != str(expected_revision):
                raise FlowVersionConflict(
                    f"flow {flow.id!r} was replaced or changed generation"
                )
            published = load_published_bundle(flow.id)
            if published is None:
                raise FlowSnapshotError(f"flow {flow.id!r} is not published")
            _active_flow, active_release = published
            if str(active_release.get("release_id") or "") != str(expected_release_id):
                raise FlowSnapshotError(
                    f"published flow {flow.id!r} no longer matches the bound activation"
                )
            digest, _version, subflows = _snapshot_flow_bundle_locked(current)
            if release_digest_for(digest, subflows) != str(
                active_release.get("release_digest") or ""
            ):
                raise FlowSnapshotError(
                    "current draft or subflow graph diverged from the active release"
                )
            saved = save_flow(
                flow,
                expected_version=expected_version,
                expected_revision=expected_revision,
            )
            release = _publish_flow_under_activation(
                saved.id,
                expected_version=saved.version,
                expected_revision=saved.revision,
            )
            return saved, release


def _publish_flow_under_activation(
    flow_id: str,
    *,
    expected_version: int,
    expected_revision: str,
    activation_id: str | None = None,
    expected_bundle_digest: str | None = None,
    effect_guard: Callable[[], None] | None = None,
) -> dict:
    """Atomically activate the exact current draft as an immutable release.

    Saving a definition only advances its draft history. Publication is the
    separate activation boundary consumed by schedules and triggers. The
    pointer contains the content-addressed root and every pinned subflow digest,
    so later draft edits cannot alter an already-approved execution plan.
    """
    with _definitions_lock():
        flow = load_flow(flow_id)
        if flow is None:
            raise FlowSnapshotError(f"flow {flow_id!r} is unavailable")
        if int(flow.version) != int(expected_version):
            raise FlowVersionConflict(
                f"flow {flow_id!r} changed (expected version {expected_version}, "
                f"current {flow.version})"
            )
        if str(flow.revision or "") != str(expected_revision):
            raise FlowVersionConflict(
                f"flow {flow_id!r} was replaced or changed generation"
            )
        errors = flow.validate() + flow.reachability_errors()
        if errors:
            raise FlowSnapshotError(
                "flow cannot be published: " + "; ".join(errors[:3])
            )
        digest, version, subflows = _snapshot_flow_bundle_locked(
            flow, validate_reachability=True,
        )
        import secrets

        release_digest = release_digest_for(digest, subflows)
        if expected_bundle_digest is not None and release_digest != expected_bundle_digest:
            raise FlowSnapshotError("An included workflow changed after review. Prepare a new release review.")
        if activation_id is not None and not _valid_release_token(activation_id):
            raise FlowSnapshotError("The new activation identity is invalid.")
        release = {
            "flow_id": flow.id,
            "definition_digest": digest,
            "definition_version": version,
            "definition_revision": flow.revision,
            "subflow_digests": subflows,
            # Content identity answers "what will execute?".  Activation
            # identity answers "is this particular authorization still live?".
            # A fresh nonce prevents revoke/republish ABA for identical content.
            "release_digest": release_digest,
            "release_id": activation_id or secrets.token_hex(32),
            "published_at": time.time(),
        }
        # The definition lock makes the snapshot coherent; the activation lock
        # makes pointer replacement linearizable with final worker dispatch.
        with _activation_lock(flow.id):
            _write_json(_published_pointer_path(flow.id), release, effect_guard=effect_guard)
        return release


def load_published_bundle(flow_id: str) -> tuple[Flow, dict] | None:
    """Verified published flow and release metadata, or ``None`` if inactive.

    A malformed/tampered pointer is not treated as an unpublished draft: it is
    an integrity failure and therefore raises ``FlowSnapshotError``.
    """
    path = _published_pointer_path(flow_id)
    raw = _read_json(path)
    if raw is None:
        if path.exists():
            raise FlowSnapshotError("published flow pointer is unreadable")
        return None
    if str(raw.get("flow_id") or "") != str(flow_id):
        raise FlowSnapshotError("published flow identity does not match its pointer")
    flow = load_flow_snapshot(str(raw.get("definition_digest") or ""))
    if (
        flow.id != str(flow_id)
        or int(flow.version) != int(raw.get("definition_version") or 0)
        or str(flow.revision or "") != str(raw.get("definition_revision") or "")
    ):
        raise FlowSnapshotError("published flow metadata does not match its snapshot")
    manifest_raw = raw.get("subflow_digests") or {}
    if not isinstance(manifest_raw, dict):
        raise FlowSnapshotError("published subflow manifest is invalid")
    manifest = {
        str(key): (str(value) if value is not None else None)
        for key, value in manifest_raw.items()
    }
    validate_snapshot_bundle_owners(flow, manifest)
    expected_release_digest = release_digest_for(
        str(raw.get("definition_digest") or ""), manifest,
    )
    stored_release_digest = str(raw.get("release_digest") or "")
    stored_release_id = str(raw.get("release_id") or "")
    if stored_release_digest:
        if stored_release_digest != expected_release_digest:
            raise FlowSnapshotError(
                "published release content failed integrity verification"
            )
        # New-format pointers require an independent, well-formed activation.
        if not _valid_release_token(stored_release_id):
            raise FlowSnapshotError("published activation identity is invalid")
        activation_id = stored_release_id
    else:
        # Pre-activation-epoch pointers stored the content digest in release_id
        # (or omitted it).  Preserve that exact authority during migration.
        if stored_release_id and stored_release_id != expected_release_digest:
            raise FlowSnapshotError(
                "legacy published release identity failed integrity verification"
            )
        activation_id = expected_release_digest
    release = dict(raw)
    release["subflow_digests"] = manifest
    release["release_digest"] = expected_release_digest
    release["release_id"] = activation_id
    return flow, release


@contextmanager
def published_flow_guard(
    flow_id: str, *, expected_release_id: str = "", expected_digest: str = "",
):
    """Hold the published pointer stable while durably reserving a live run.

    Release mutations acquire the per-flow activation mutex and then this global
    definition lock before changing the pointer. A caller that re-verifies the
    release here and writes its run row before leaving therefore sees one exact
    pointer. Reservation is not execution authority: the worker separately uses
    :func:`active_release_guard` immediately before dispatch.
    """
    with _definitions_lock():
        published = load_published_bundle(flow_id)
        if published is None:
            raise FlowSnapshotError(f"flow {flow_id!r} is not published")
        _flow, release = published
        expected = str(expected_release_id or expected_digest or "")
        if expected and str(release.get("release_id") or "") != expected:
            raise FlowSnapshotError(
                f"published flow {flow_id!r} no longer matches the bound revision"
            )
        yield published


@contextmanager
def active_release_guard(flow_id: str, *, expected_release_id: str):
    """Linearize a final dispatch check against release mutation.

    Queue reservation is intentionally insufficient authority to execute: a
    client may revoke or replace a release while work is waiting in an outbox,
    concurrency queue, delay, or approval. Callers keep this short per-flow lock
    only through their execution-start decision, then release it before building
    or invoking a potentially long executor. Thus revocation that wins first
    refuses queued work, while revocation cannot interrupt a segment that has
    already crossed this linearization point.
    """
    expected = str(expected_release_id or "")
    if not expected:
        raise FlowSnapshotError("flow run has no immutable release identity")
    with _activation_lock(flow_id):
        published = load_published_bundle(flow_id)
        if published is None:
            raise FlowSnapshotError(f"flow {flow_id!r} is not published")
        _flow, release = published
        if str(release.get("release_id") or "") != expected:
            raise FlowSnapshotError(
                f"published flow {flow_id!r} no longer matches the bound revision"
            )
        yield published


def list_published_bundles() -> list[tuple[Flow, dict]]:
    """Every verified active release in the current tenant namespace."""
    directory = _published_dir()
    if not directory.exists():
        return []
    out: list[tuple[Flow, dict]] = []
    for path in sorted(directory.glob("*.json")):
        raw = _read_json(path)
        if raw is None:
            if not path.exists():
                continue
            raise FlowSnapshotError(
                f"published flow pointer {path.name!r} is unreadable"
            )
        if not raw.get("flow_id"):
            raise FlowSnapshotError(
                f"published flow pointer {path.name!r} has no flow identity"
            )
        bundle = load_published_bundle(str(raw["flow_id"]))
        if bundle is not None:
            out.append(bundle)
    return out


def unpublish_flow(
    flow_id: str,
    *,
    expected_version: int,
    expected_revision: str,
    expected_release_id: str | None = None,
) -> bool:
    """Revoke one active release under the live-dispatch lock."""
    with _activation_lock(flow_id):
        return _unpublish_flow_under_activation(
            flow_id,
            expected_version=expected_version,
            expected_revision=expected_revision,
            expected_release_id=expected_release_id,
        )


def _unpublish_flow_under_activation(
    flow_id: str,
    *,
    expected_version: int,
    expected_revision: str,
    expected_release_id: str | None = None,
) -> bool:
    """Deactivate a release without deleting its draft or immutable objects."""
    with _definitions_lock():
        current = load_flow(flow_id)
        if current is None:
            return False
        if int(current.version) != int(expected_version):
            raise FlowVersionConflict(
                f"flow {flow_id!r} changed (expected version {expected_version}, "
                f"current {current.version})"
            )
        if str(current.revision or "") != str(expected_revision):
            raise FlowVersionConflict(
                f"flow {flow_id!r} was replaced or changed generation"
            )
        if expected_release_id is not None:
            published = load_published_bundle(flow_id)
            active_id = str(published[1]["release_id"]) if published else ""
            if active_id != expected_release_id:
                raise FlowVersionConflict(f"published flow {flow_id!r} changed since review")
        with _activation_lock(flow_id):
            try:
                (_published_dir() / f"{_safe_id(flow_id)}.json").unlink()
                return True
            except FileNotFoundError:
                return False


def load_flow_snapshot(digest: str) -> Flow:
    """Load a CAS flow object and fail closed on deletion or tampering."""
    import re

    digest = str(digest or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise FlowSnapshotError("invalid flow snapshot digest")
    raw = _read_json(_objects_dir() / f"{digest}.json")
    if raw is None:
        raise FlowSnapshotError(f"flow snapshot {digest} is missing")
    actual = sha256(_canonical_flow_bytes(raw)).hexdigest()
    if actual != digest:
        raise FlowSnapshotError(f"flow snapshot {digest} failed integrity verification")
    try:
        flow = Flow.from_dict(raw)
    except Exception as exc:
        raise FlowSnapshotError(f"flow snapshot {digest} is invalid") from exc
    # Bounds added after a release was published must not make it unloadable.
    clamped = clamp_saved_numbers(flow)
    if clamped:
        log.warning("flow snapshot %s: clamped out-of-range values: %s",
                    digest, ", ".join(clamped[:10]))
    errors = flow.validate()
    if errors:
        raise FlowSnapshotError(
            "flow snapshot is structurally invalid: " + "; ".join(errors[:3]))
    return flow


def validate_snapshot_bundle_owners(
    root: Flow,
    manifest: dict[str, str | None],
) -> None:
    """Verify a pinned bundle is complete, identity-safe, and owner-contained.

    New bundles are checked while they are created, but durable paused runs may
    predate that invariant. Re-checking immutable child objects on delivery
    prevents an old crafted run from becoming a permanent authorization bypass.
    Missing children remain represented by ``None`` and fail later as before.
    """
    if not isinstance(manifest, dict):
        raise FlowSnapshotError("published subflow manifest is invalid")
    root_owner = str(root.owner or "")
    normalized = {
        str(ref): (str(digest) if digest is not None else None)
        for ref, digest in manifest.items()
    }
    required: set[str] = set()
    visited: set[str] = set()

    def walk(flow: Flow) -> None:
        raw = flow.to_dict()

        def walk_nodes(nodes) -> None:
            for node in nodes or []:
                if not isinstance(node, dict):
                    continue
                body = node.get("body")
                if isinstance(body, dict):
                    walk_nodes(body.get("nodes"))
                for branch in node.get("branches") or []:
                    if isinstance(branch, dict):
                        walk_nodes(branch.get("nodes"))
                if str(node.get("kind") or "") != "subflow":
                    continue
                ref = str(node.get("flow_ref") or "").strip()
                if ref:
                    required.add(ref)

        walk_nodes(raw.get("nodes"))

    pending = [root]
    while pending:
        current = pending.pop()
        walk(current)
        # Only resolve newly discovered references. Cycles are legal snapshot
        # data even though runtime cycle guards refuse their execution.
        for ref in sorted(required - visited):
            visited.add(ref)
            if ref not in normalized:
                raise FlowSnapshotError(
                    f"subflow snapshot manifest is missing {ref!r}"
                )
            digest = normalized[ref]
            if digest is None:
                continue
            child = load_flow_snapshot(digest)
            if child.id != ref:
                raise FlowSnapshotError(
                    f"subflow snapshot identity mismatch for {ref!r}"
                )
            if str(child.owner or "") != root_owner:
                raise FlowSnapshotError(
                    f"subflow {ref!r} is unavailable to this flow owner"
                )
            pending.append(child)
    extras = set(normalized) - required
    if extras:
        raise FlowSnapshotError(
            f"subflow snapshot manifest has unreferenced entry {sorted(extras)[0]!r}"
        )


# ---- runs (resumable state) -------------------------------------------------

@dataclass
class FlowRun:
    run_id: str
    flow_id: str
    status: str
    data: dict = field(default_factory=dict)
    cursor: str | None = None
    resume_at: float | None = None
    prompt: str = ""
    error: str = ""
    owner: str = ""
    created: float = 0.0
    updated: float = 0.0
    # Per-node run trace: {node_id: {status, outcome}} accumulated as the run
    # executes, so the designer can overlay live status/result on the canvas.
    nodes: dict = field(default_factory=dict)
    # The data the run STARTED with (the trigger payload), kept so a failed run
    # can be retried from scratch with the same inputs.
    input_data: dict = field(default_factory=dict)
    # Optional idempotency key (flow_id + a stable event id) so a re-delivered
    # trigger event doesn't spawn a duplicate run.
    idem_key: str = ""
    # What fired this run: "manual" | "cron:<flow>" |
    # "event:v2:<source>:<generation>:<trigger>" |
    # "form:<token>" | "retry:<run>" -- so a viewer can see why it ran and the
    # loop can learn which triggers produce value.
    origin: str = "manual"
    # Persisted on the reservation so an outbox repair can never recover a
    # mock/dry run as a real side-effecting execution.
    dry_run: bool = False
    # Agent spend reserved for this run (dollars), so a viewer can see run cost.
    cost_dollars: float = 0.0
    # Explicit operator increase applies to this run, without rewriting its
    # immutable graph or discarding already metered work.
    budget_limit_dollars: float | None = None
    # Snapshot of the paused human task (choices/form/assignee) taken AT PAUSE
    # time, like `prompt` -- so the run viewer renders what the paused node
    # actually declared, even if the flow is edited while the run waits.
    human: dict = field(default_factory=dict)
    # Durable identity of the principal who made the human approval decision.
    # This is intentionally separate from the run owner and queue producer.
    decided_by: str = ""
    # Content-addressed immutable execution plan captured when the run is
    # enqueued.  The run row stays small; graph bytes deduplicate in objects/.
    definition_digest: str = ""
    # Immutable content identity for the root plus complete pinned child graph.
    release_digest: str = ""
    # One publication/activation epoch.  It changes even when identical content
    # is revoked and republished and scopes dispatch plus idempotency authority.
    release_id: str = ""
    definition_version: int = 0
    # Stable definition-generation token.  Version resets after delete/recreate;
    # revision does not, so learning and diagnostics can never attribute an old
    # owner's evidence to a new flow that happens to reuse the same id.
    definition_revision: str = ""
    subflow_digests: dict[str, str | None] = field(default_factory=dict)
    # Execution identity is part of the durable reservation, not queue metadata.
    # This prevents an at-least-once delivery, delayed resume, or outbox repair
    # from dropping per-user tool ACL and specialist-suite restrictions.
    execution_channel: str = ""
    execution_user_id: str = ""
    allowed_suites: list[str] | None = None
    # A listing record is a projection, never a checkpoint that can be saved.
    metadata_only: bool = field(default=False, repr=False, compare=False)
    # Private execution frames, excluded from public to_dict projections.
    continuation: dict = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        from .payloads import preview

        return {
            "run_id": self.run_id, "flow_id": self.flow_id, "status": self.status,
            "data": preview(self.data), "cursor": self.cursor, "resume_at": self.resume_at,
            "prompt": self.prompt, "error": self.error, "owner": self.owner,
            "created": self.created, "updated": self.updated, "nodes": self.nodes,
            "input_data": preview(self.input_data), "idem_key": self.idem_key,
            "origin": self.origin, "dry_run": self.dry_run,
            "cost_dollars": self.cost_dollars,
            "budget_limit_dollars": self.budget_limit_dollars,
            "human": self.human,
            "decided_by": self.decided_by,
            "definition_digest": self.definition_digest,
            "release_digest": self.release_digest,
            "release_id": self.release_id,
            "definition_version": self.definition_version,
            "definition_revision": self.definition_revision,
            "subflow_digests": self.subflow_digests,
            "execution_channel": self.execution_channel,
            "execution_user_id": self.execution_user_id,
            "allowed_suites": self.allowed_suites,
        }

    @staticmethod
    def from_dict(d: dict) -> FlowRun:
        import math

        limit = d.get("budget_limit_dollars")
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, (int, float)) or not math.isfinite(limit) or limit <= 0:
                raise FlowSnapshotError("flow run spending allowance is invalid")
        definition_digest = str(d.get("definition_digest") or "")
        subflow_digests = {
            str(k): (str(v) if v is not None else None)
            for k, v in (d.get("subflow_digests") or {}).items()
        }
        expected_release_digest = (
            release_digest_for(definition_digest, subflow_digests)
            if definition_digest else ""
        )
        stored_release_digest = str(d.get("release_digest") or "")
        if stored_release_digest and stored_release_digest != expected_release_digest:
            raise FlowSnapshotError("flow run content identity failed integrity checks")
        stored_release_id = str(d.get("release_id") or "")
        activation_id = stored_release_id or expected_release_digest
        if activation_id and not _valid_release_token(activation_id):
            raise FlowSnapshotError("flow run activation identity is invalid")
        return FlowRun(
            run_id=str(d.get("run_id", "")), flow_id=str(d.get("flow_id", "")),
            status=str(d.get("status", "")), data=dict(d.get("data") or {}),
            cursor=d.get("cursor"), resume_at=d.get("resume_at"),
            continuation=dict(d.get("continuation") or {}),
            prompt=str(d.get("prompt", "")), error=str(d.get("error", "")),
            owner=str(d.get("owner", "")),
            created=float(d.get("created", 0.0)), updated=float(d.get("updated", 0.0)),
            nodes=dict(d.get("nodes") or {}),
            input_data=dict(d.get("input_data") or {}), idem_key=str(d.get("idem_key", "")),
            origin=str(d.get("origin", "manual") or "manual"),
            dry_run=bool(d.get("dry_run", False)),
            cost_dollars=float(d.get("cost_dollars", 0.0) or 0.0),
            budget_limit_dollars=float(limit) if limit is not None else None,
            human=dict(d.get("human") or {}),
            decided_by=str(d.get("decided_by") or "")[:500],
            definition_digest=definition_digest,
            release_digest=expected_release_digest,
            release_id=activation_id,
            definition_version=int(d.get("definition_version") or 0),
            definition_revision=str(d.get("definition_revision") or ""),
            subflow_digests=subflow_digests,
            execution_channel=str(d.get("execution_channel") or "")[:80],
            execution_user_id=str(d.get("execution_user_id") or "")[:500],
            allowed_suites=(
                sorted({str(v) for v in d.get("allowed_suites", []) if str(v)})
                if isinstance(d.get("allowed_suites"), list)
                else None
            ),
        )


def find_run_by_idem(
    flow_id: str,
    idem_key: str,
    *,
    within: int | None = 500,
    revision: str | None = None,
    definition_digest: str | None = None,
    release_id: str | None = None,
    owner: str | None = None,
) -> FlowRun | None:
    """The most recent run for ``flow_id`` with this idempotency key, if any --
    the dedup check that stops a re-delivered event from firing a second run.

    When ``release_id`` is supplied, deduplication is scoped to the exact root
    plus child bundle. ``definition_digest`` remains a backward-compatible root
    scope for callers that have not yet adopted composite releases.
    """
    if not idem_key:
        return None
    expected_digest = (
        None if definition_digest is None else str(definition_digest)
    )
    expected_release_id = None if release_id is None else str(release_id)
    claim = _read_json(_idempotency_claim_path(
        flow_id,
        idem_key,
        expected_digest or "",
        owner,
        release_id=expected_release_id or "",
    ))
    if claim is None and expected_digest and expected_release_id:
        # Pre-composite releases indexed claims by root digest. Read that index
        # only as a migration hint, then verify the referenced run's derived
        # composite identity below; a same-root/different-child run cannot alias.
        claim = _read_json(_legacy_idempotency_claim_path(
            flow_id, idem_key, expected_digest, owner,
        ))
    if claim:
        claimed = load_run(str(claim.get("run_id") or ""))
        if (claimed is not None
                and claimed.flow_id == flow_id
                and claimed.idem_key == idem_key
                and (revision is None or claimed.definition_revision == revision)
                and (expected_digest is None
                     or claimed.definition_digest == expected_digest)
                and (expected_release_id is None
                     or claimed.release_id == expected_release_id)
                and (owner is None or claimed.owner == owner)):
            return claimed
    for meta in list_run_metadata(flow_id=flow_id, owner=owner, idem_key=idem_key, limit=within):
        r = load_run(meta.run_id, owner=owner, flow_id=flow_id)
        if r is None:
            continue
        if (r.idem_key == idem_key
                and (revision is None or r.definition_revision == revision)
                and (expected_digest is None
                     or r.definition_digest == expected_digest)
                and (expected_release_id is None
                     or r.release_id == expected_release_id)
                and (owner is None or r.owner == owner)):
            return r
    return None


def _idempotency_claim_path(
    flow_id: str,
    idem_key: str,
    definition_digest: str = "",
    owner: str | None = None,
    *,
    release_id: str = "",
):
    material = f"{flow_id}\0{idem_key}".encode()
    release_scope = str(release_id or definition_digest or "")
    if release_scope or owner is not None:
        owner_scope = "<any-owner>" if owner is None else f"owner:{owner}"
        scope_version = "v2" if release_id else "v1"
        material += (
            f"\0exact-release-{scope_version}\0{release_scope}\0{owner_scope}"
        ).encode()
    return _idempotency_dir() / f"{sha256(material).hexdigest()}.json"


def _legacy_idempotency_claim_path(
    flow_id: str,
    idem_key: str,
    definition_digest: str,
    owner: str | None,
):
    material = f"{flow_id}\0{idem_key}".encode()
    owner_scope = "<any-owner>" if owner is None else f"owner:{owner}"
    material += (
        f"\0exact-release-v1\0{definition_digest}\0{owner_scope}"
    ).encode()
    return _idempotency_dir() / f"{sha256(material).hexdigest()}.json"


@contextmanager
def idempotency_lock(
    flow_id: str,
    idem_key: str,
    definition_digest: str = "",
    owner: str | None = None,
    *,
    release_id: str = "",
):
    """Serialize reservation for one owner/flow/key/exact release."""
    from ..file_lock import cross_process_lock
    with cross_process_lock(
        _idempotency_claim_path(
            flow_id, idem_key, definition_digest, owner, release_id=release_id,
        ),
        strict=True,
    ):
        yield


def save_idempotency_claim(
    flow_id: str,
    idem_key: str,
    run_id: str,
    *,
    definition_digest: str = "",
    release_id: str = "",
    owner: str | None = None,
    overwrite: bool = True,
) -> bool:
    if not idem_key:
        return False
    path = _idempotency_claim_path(
        flow_id, idem_key, definition_digest, owner, release_id=release_id,
    )
    if not overwrite and path.exists():
        return False
    _write_json(path, {
        "flow_id": flow_id,
        "run_id": run_id,
        "definition_digest": str(definition_digest),
        "release_id": str(release_id or definition_digest),
        "owner": "" if owner is None else str(owner),
    })
    return True


def new_run_id() -> str:
    from uuid import uuid4
    return uuid4().hex


def save_run(run: FlowRun) -> None:
    from . import payloads, run_index

    if run.metadata_only:
        raise payloads.FlowPayloadError("load complete execution data before saving a run")
    expected_release_digest = (
        release_digest_for(run.definition_digest, run.subflow_digests)
        if run.definition_digest else ""
    )
    if run.release_digest and run.release_digest != expected_release_digest:
        raise FlowSnapshotError("flow run content identity failed integrity checks")
    run.release_digest = expected_release_digest
    # Legacy/dry-run callers without a publication epoch receive a deterministic
    # synthetic identity. Live queue producers must pass the pointer's nonce.
    run.release_id = str(run.release_id or expected_release_digest)
    if run.release_id and not _valid_release_token(run.release_id):
        raise FlowSnapshotError("flow run activation identity is invalid")
    now = time.time()
    if not run.created:
        run.created = now
    run.updated = now
    values = payloads.prepare(run.data, run.input_data, continuation=run.continuation)
    d = run.to_dict()
    d["data"] = payloads.preview(values["data"])
    d["input_data"] = payloads.preview(values["input_data"])
    if d.get("error"):
        try:
            from ..safety.secret_detector import redact
            d["error"] = redact(str(d["error"]))[0][:2000]
        except Exception:
            # An exception string is untrusted and may contain connector
            # credentials. If the redactor is unavailable, preserve the fact of
            # failure without persisting the potentially secret details.
            d["error"] = "execution failed (details redacted)"
        run.error = str(d["error"])
    target = _runs_dir() / f"{_safe_id(run.run_id)}.json"
    artifact_root = _runs_dir().parent / "run_payloads"
    with _checkpoint_lock(run.run_id):
        prior = _read_json(target)
        if prior is None and target.exists():
            raise payloads.FlowPayloadError("existing flow checkpoint row is unreadable; restore it before saving")
        # Remove artifacts orphaned by a crash before publishing the row. This
        # keeps peak storage to the old and new checkpoint, not every save ever.
        payloads.reclaim(artifact_root, run.run_id, (prior or {}).get("data_state"))
        previous_ref = (prior or {}).get("data_state")
        if (previous_ref and prior.get("flow_id") == run.flow_id
                and prior.get("owner", "") == run.owner
                and payloads.decode(artifact_root, prior) == values):
            # Status/lease checkpoints reuse unchanged immutable data.
            d["data_state"] = previous_ref
        else:
            d["data_state"] = payloads.encode(artifact_root, d, values)
        if d["data_state"]["kind"] == "inline":
            d.update(values)
        with run_index.mutation(_runs_dir(), run.run_id):
            _write_json(target, d)
        # A committed row is the acknowledgement; cleanup failure must not
        # turn that successful transition into an apparent failed execution.
        try:
            payloads.reclaim(artifact_root, run.run_id, d["data_state"])
        except OSError:
            pass  # the next checkpoint retries orphan cleanup before writing
    run.data = values["data"]
    run.input_data = values["input_data"]
    run.continuation = values["continuation"]


@contextmanager
def _checkpoint_lock(run_id: str):
    """Short publication/read lock, independent of the whole execution lock."""
    from ..file_lock import cross_process_lock

    with cross_process_lock(_runs_dir() / f".{_safe_id(run_id)}.checkpoint", strict=True):
        yield


def load_run(run_id: str, *, owner: str | None = None,
             flow_id: str | None = None) -> FlowRun | None:
    """Load complete data only after optional metadata access filters match."""
    from .payloads import FlowPayloadError, decode

    with _checkpoint_lock(run_id):
        target = _runs_dir() / f"{_safe_id(run_id)}.json"
        d = _read_json(target)
        if not d:
            if owner is not None or flow_id is not None:
                # A malformed row cannot establish access to its private data.
                return None
            if target.exists():
                raise FlowPayloadError("flow checkpoint row is unreadable; restore it before resuming")
            return None
        if owner is not None and d.get("owner", "") != owner:
            return None
        if flow_id is not None and d.get("flow_id") != flow_id:
            return None
        if d.get("run_id") != run_id:
            raise FlowPayloadError("flow checkpoint belongs to a different run")
        d.update(decode(_runs_dir().parent / "run_payloads", d))
        return FlowRun.from_dict(d)


def delete_run(run_id: str) -> bool:
    from . import run_index
    from .payloads import reclaim

    with _checkpoint_lock(run_id):
        try:
            with run_index.mutation(_runs_dir(), run_id):
                (_runs_dir() / f"{_safe_id(run_id)}.json").unlink()
        except OSError:
            return False
        try:
            reclaim(_runs_dir().parent / "run_payloads", run_id, None)
        except OSError:
            pass
        return True


@contextmanager
def run_lock(run_id: str):
    """Serialize a run's state transition across threads and processes.

    Resume is a compare-and-act operation: load the paused row, verify it is
    resumable, execute downstream work, then publish the new state.  Locking
    only the final JSON write still lets two workers both observe ``paused`` and
    perform the same external side effect.  The stable sidecar used here spans
    that whole transition on POSIX and Windows.
    """
    from ..file_lock import cross_process_lock

    target = _runs_dir() / f"{_safe_id(run_id)}.json"
    with cross_process_lock(target, strict=True):
        yield


def list_run_metadata(*, flow_id: str | None = None, owner: str | None = None,
                      limit: int | None = 50, statuses=None, due_before=None,
                      cursor=None, idem_key=None, release_id: str | None = None) -> list[FlowRun]:
    """Indexed bounded previews; callers must load_run before executing/saving."""
    from . import run_index

    rows = run_index.query(_runs_dir(), flow_id=flow_id, owner=owner, limit=limit,
                           statuses=statuses, due_before=due_before, cursor=cursor,
                           idem_key=idem_key, release_id=release_id)
    runs = [FlowRun.from_dict(row) for row in rows]
    for run in runs:
        run.metadata_only = True
    return runs


def iter_run_metadata(*, batch_size: int = 200, **filters):
    """Keyset paging for recovery; no newest-N cutoff hides old due runs."""
    cursor = None
    while True:
        batch = list_run_metadata(limit=max(1, batch_size), cursor=cursor, **filters)
        if not batch:
            return
        yield from batch
        last = batch[-1]
        cursor = (last.resume_at if filters.get("due_before") is not None else last.updated,
                  last.run_id)


def rebuild_run_index() -> None:
    from . import run_index

    run_index.rebuild(_runs_dir())


def list_runs(*, flow_id: str | None = None, owner: str | None = None,
              limit: int | None = 50) -> list[FlowRun]:
    runs = []
    for meta in list_run_metadata(flow_id=flow_id, owner=owner, limit=limit):
        run = load_run(meta.run_id, owner=owner, flow_id=flow_id)
        if run is None:
            continue
        runs.append(run)
    return runs


__all__: list[str] = [
    "save_flow", "load_flow", "list_flows", "delete_flow",
    "list_versions", "load_version", "rollback_flow",
    "FlowVersionConflict", "FlowSnapshotError", "snapshot_flow_bundle",
    "snapshot_current_flow_bundle", "load_flow_snapshot",
    "definition_cohort", "flow_cohort", "release_digest_for", "release_id_for",
    "publish_flow", "save_and_publish_flow", "restore_published_flow",
    "unpublish_flow", "load_published_bundle", "list_published_bundles",
    "published_flow_guard", "active_release_guard",
    "FlowRun", "new_run_id", "save_run", "load_run", "delete_run", "run_lock",
    "list_runs", "list_run_metadata", "iter_run_metadata", "rebuild_run_index",
    "find_run_by_idem", "idempotency_lock", "save_idempotency_claim",
    "load_flow_schema", "record_flow_schema",
]

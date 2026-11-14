"""Private, native single-run result for automation; never inferred from logs."""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import stat
from dataclasses import asdict
from pathlib import Path

from ..authority_effects import authority_effect_fence
from ..file_lock import (
    _validate_open_lock_file,
    _windows_open_private_file_is_restricted,
    atomic_create_text,
    require_private_directory,
)

SCHEMA = "lightwork.cli-run-result.v1"
STATUSES = {"pending", "draft", "active", "running", "blocked", "done", "failed", "cancelled", "paused", "waiting"}


def prepare_result_target(value, *, repeat, dry_cost, key_file=None):
    if value is None:
        if key_file is not None:
            import click
            raise click.UsageError("--result-key-file requires --result-file.")
        return None
    import click
    if dry_cost or repeat != 1:
        raise click.UsageError("--result-file requires one actual run; it cannot be used with --dry-cost or --repeat.")
    try:
        return result_target(value)
    except (ValueError, OSError) as exc:
        raise click.BadParameter(str(exc), param_hint="--result-file") from exc


def read_result_key(path):
    """Verify a caller-owned key without claiming its file or directory."""
    if path is None:
        return None
    path = Path(path)
    parent = require_private_directory(path.parent).stat()
    if os.name != "nt" and parent.st_uid != os.getuid():
        raise PermissionError("The result key directory must belong to the current user.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        def inspect_key():
            info = _validate_open_lock_file(path, fd)
            if os.name == "nt":
                mode = 0o600 if info.st_mode & stat.S_IWRITE else 0o400
                private = _windows_open_private_file_is_restricted(path, info, mode)
            else:
                private = (info.st_uid == os.getuid() and not info.st_mode & 0o077
                           and bool(info.st_mode & stat.S_IRUSR))
            if not private:
                raise PermissionError("The result key must already be private.")
            return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)

        before = inspect_key()
        key = os.read(fd, 33)
        if inspect_key() != before:
            raise PermissionError("The result key changed while being read.")
        current_parent = require_private_directory(path.parent).stat()
        if (parent.st_dev, parent.st_ino) != (current_parent.st_dev, current_parent.st_ino):
            raise PermissionError("The result key directory changed while being read.")
    finally:
        os.close(fd)
    if len(key) != 32:
        raise ValueError("The private result key is unavailable or invalid.")
    return key


def result_target(value: str | Path) -> Path:
    """Require a new file under existing real directories before paid work."""
    target = Path(os.path.abspath(value))
    if os.path.lexists(target):
        raise ValueError("The result file must be a new file; existing files are never replaced.")
    for parent in target.parents:
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
            raise ValueError("The result file requires existing directories without redirected links.")
    return target


def _source_authority(goal):
    from ..connections import current_principal
    from ..knowledge_task_context import require_read
    if goal.owner:
        if current_principal() != goal.owner:
            raise PermissionError("The original account is required to release this task.")
        # Named dashboard-source work retains its current rights. Ordinary CLI
        # goals have no named owner and do not require dashboard installation.
        from ..conversation_inbox import current_authority
        current_authority(goal)
    require_read(goal, goal.owner or None)


def _release(world, goal_id: int, requested_domain: str | None):
    from ..chat_message_actions import require_copy_sources
    from ..domain import available_domains, deliverable_release_allowed
    from ..paths import current_tenant_id_strict
    from ..tenant.registry import assert_tenant_active

    assert_tenant_active(current_tenant_id_strict())
    goal = world.get_goal(goal_id)
    if goal is None:
        raise ValueError("The saved task is unavailable.")
    _source_authority(goal)
    require_copy_sources(world, goal_id, authorize=_source_authority)
    domain = goal.domain or requested_domain
    profile = available_domains().get(domain) if domain else None
    signoff = world.signoff_for(goal_id) if profile is not None else None
    state = {"goal": asdict(goal), "profile": asdict(profile) if profile is not None else None,
             "signoff": signoff,
             "tenant": current_tenant_id_strict()}
    if goal.status != "done" or not isinstance(goal.result, str):
        return state, "not_completed", None
    if domain and profile is None:
        return state, "policy_unavailable", None
    if profile is not None and not deliverable_release_allowed(profile, signoff):
        return state, "pending_signoff", None
    return state, "released", goal.result


def write_run_result(target: Path, world, goal_id: int, budget, *, domain=None, key=None) -> dict:
    """Publish once, with current release/source checks on both sides of I/O.

    Recorded Budget usage is not a provider invoice or an assertion that all
    interrupted provider attempts have known cost. No arbitrary artifact path
    from model text is accepted as a deliverable.
    """
    with authority_effect_fence():
        goal = world.get_goal(goal_id)
        if goal is None:
            raise ValueError("The saved task is unavailable.")
        with budget._lock:
            budget._validate_integrity()
            amount = budget.dollars
        if isinstance(amount, bool) or not isinstance(amount, (int, float)) or not math.isfinite(amount) or amount < 0:
            raise ValueError("Recorded spending is unavailable.")
        try:
            state, release, answer = _release(world, goal_id, domain)
        except (PermissionError, ValueError, RuntimeError, OSError, ImportError):
            state, release, answer = None, "policy_unavailable", None
        result = {"schema": SCHEMA, "goal_id": goal.id,
                  "status": goal.status if goal.status in STATUSES else "unavailable",
                  "spend_recorded_usd": amount, "release_status": release, "answer": answer}
        encoded = json.dumps(result, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        result["signature"] = hmac.new(key, encoded, hashlib.sha256).hexdigest() if key is not None else None
        # Revalidate the target after the run as well; exclusive native
        # publication refuses a file/link planted while the task was running.
        result_target(target)
        atomic_create_text(target, json.dumps(result, ensure_ascii=False, allow_nan=False) + "\n", mode=0o600)
        written = target.lstat()
        try:
            if state is not None and _release(world, goal_id, domain) != (state, release, answer):
                raise ValueError("Task output or release permission changed during export.")
            if asdict(world.get_goal(goal_id)) != asdict(goal):
                raise ValueError("The saved task changed during export.")
        except BaseException:
            current = target.lstat()
            if (current.st_dev, current.st_ino) == (written.st_dev, written.st_ino):
                target.unlink()
            raise
        return result


def write_if_requested(target, world, goal_id, budget, *, domain=None, key=None):
    if target is not None:
        return write_run_result(target, world, goal_id, budget, domain=domain, key=key)
    return None

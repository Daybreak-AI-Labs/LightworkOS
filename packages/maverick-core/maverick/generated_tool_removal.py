"""Owned generated-source lifecycle inspection; never import generated code."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import learning_content, self_learning
from .file_lock import atomic_read_text, cross_process_lock, ensure_private_file
from .paths import current_tenant_id

MAX_TOOLS = 512


def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def target(name):
    if not isinstance(name, str) or not self_learning._NAME_RE.fullmatch(name):
        raise ValueError("Choose a currently owned tool.")
    directory = self_learning.generated_tools_dir().resolve()
    path = directory / (name + ".py")
    if path.is_symlink() or path.resolve().parent != directory:
        raise ValueError("This tool's retained files are unavailable.")
    return path


def _physical(path):
    if not path.exists():
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError("This tool's retained file is unavailable.")
    stat = path.stat()
    return [stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns]


def ownership(path, owner):
    metadata = learning_content.metadata_path(path)
    ensure_private_file(metadata)
    if metadata.stat().st_size > 4096:
        raise ValueError("This tool's ownership cannot be verified.")
    record = json.loads(atomic_read_text(metadata))
    if (type(record) is not dict or record.get("content_version") != 1
            or owner is None or record.get("owner") != owner
            or set(record) != {"content_version", "owner", "goal_id", "sha256"}
            or not isinstance(record.get("sha256"), str)
            or not re.fullmatch(r"[a-f0-9]{64}", record["sha256"])):
        raise PermissionError("This retained tool is unavailable to this owner.")
    goal = record.get("goal_id")
    if goal is not None and (type(goal) is not int or goal <= 0):
        raise PermissionError("This retained tool's source cannot be verified.")
    return record


def inspect(name, owner, budget, *, absent_record=None):
    """Return metadata only, including stopped and source-withdrawn owned files."""
    budget.check()
    path = target(name)
    metadata = learning_content.metadata_path(path)
    with cross_process_lock(path, strict=True):
        try:
            record = ownership(path, owner)
        except FileNotFoundError:
            if path.exists() or absent_record is None or absent_record.get("owner") != owner:
                raise
            record = dict(absent_record)
        source = _physical(path)
        if source is not None:
            ensure_private_file(path)
            # Tightening an older broad file changes its ctime; report the
            # tightened identity so the next read of it matches.
            source = _physical(path)
            if source[2] > self_learning._MAX_GENERATED_SOURCE_BYTES:
                raise ValueError("The complete tool exceeds the supported removal review limit.")
            # Match the native publisher/loader's normalized UTF-8 source digest,
            # while retaining the physical file identity and timestamps as well.
            source_text = self_learning._read_generated_source(path)
            if hashlib.sha256(source_text.encode("utf-8")).hexdigest() != record["sha256"]:
                raise ValueError("The current tool no longer matches its retained ownership.")
        tenant = current_tenant_id() or "shared"
        try:
            consent = runtime_permission(tenant, name, record["sha256"])
        except (OSError, RuntimeError, ValueError):
            consent = None
        permitted = learning_content.allowed(record, owner=owner)
        value = {"name": name, "owner": owner, "ownership": record, "source_sha256": record["sha256"],
                 "source_file": source, "ownership_file": _physical(metadata), "consent": consent,
                 "source_permitted": permitted, "tenant": tenant, "key": _hash([tenant, owner, name])}
        value["binding"] = _hash(value)
    budget.check()
    return value


def inventory(owner, budget):
    directory = self_learning.generated_tools_dir()
    if not directory.exists():
        return []
    paths = sorted(directory.glob("*.ownership.json"))
    if len(paths) > MAX_TOOLS:
        raise ValueError("The complete tool inventory exceeds 512 retained entries. Nothing was silently omitted.")
    rows = []
    for path in paths:
        budget.check()
        name = path.name[:-len(".ownership.json")]
        try:
            rows.append(inspect(name, owner, budget))
        except (PermissionError, FileNotFoundError):
            continue
    return rows


def require_owned(path: Path, digest: str, owner: str | None):
    record = ownership(path, owner)
    if record["sha256"] != digest:
        raise PermissionError("The retained tool ownership changed.")
    return record


def runtime_permission(tenant, name, digest):
    from .safety import consent

    with consent._locked_ledger() as path:
        key = consent._ledger_key(path, create=False)
        records = consent._load_records_unlocked(path, key)
        return bool(consent._generated_bindings(records, "register-generated-tool", self_learning._generated_consent_scope(tenant, name, digest)))

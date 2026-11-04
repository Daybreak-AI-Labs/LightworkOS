"""Bounded read-only inventory of already installed local Linux practice images.

Only Docker context metadata, engine information and image metadata are read.
Nothing is downloaded, built, started or removed; cache admission never permits a
save. A selected immutable image is inspected again through the current local
engine before the existing configuration writer can accept it.
"""
from __future__ import annotations

import json
import re
import shutil
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .research import _capture, _host_environment, _local_endpoint

_IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")
_CONTEXT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")
_TAG = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:@-]{0,255}\Z")
_FORMAT = '{"id":{{json .Id}},"os":{{json .Os}},"created":{{json .Created}},"tags":{{json .RepoTags}},"volumes":{{json (index .Config "Volumes")}}}'
_MAX_IMAGES = 128
_CACHE_SECONDS = 30
_LOCK = threading.Lock()
_CACHE = None


class LocalImageUnavailable(ValueError):
    """The current local runtime or selected image cannot be verified."""


@dataclass(frozen=True)
class LocalImage:
    id: str
    label: str


@contextmanager
def _inventory_lock():
    if not _LOCK.acquire(timeout=2):
        raise LocalImageUnavailable("The installed environment list is already being read. Your choice has been kept; refresh again shortly.")
    try:
        yield
    finally:
        _LOCK.release()


def _read(args, env, deadline, *, limit=256 * 1024):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LocalImageUnavailable("Reading local practice environments timed out. Keep your current choice and try refreshing later.")
    try:
        result = _capture(args, env, timeout=min(4, remaining), limit=limit)
    except (OSError, RuntimeError) as exc:
        raise LocalImageUnavailable("Local practice environments could not be read. Start Docker Desktop with Linux containers, then refresh the installed environments.") from exc
    if result.code or result.reason != "completed":
        raise LocalImageUnavailable("Local practice environments could not be read. Start Docker Desktop with Linux containers, then refresh the installed environments.")
    try:
        return result.out.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise LocalImageUnavailable("The installed environment information could not be read. Nothing was selected or changed.") from exc


def _engine(deadline):
    executable = shutil.which("docker")
    if not executable:
        raise LocalImageUnavailable("Docker Desktop is unavailable on this installation. Ask your installation administrator to provide an approved local practice environment.")
    env = _host_environment()
    base = [str(Path(executable).resolve())]
    name = _read([*base, "context", "show"], env, deadline, limit=4096).strip()
    if not _CONTEXT.fullmatch(name):
        raise LocalImageUnavailable("The current Docker setup could not be verified. No remote environment will be contacted.")
    try:
        descriptors = json.loads(_read([*base, "context", "inspect", name], env, deadline, limit=16384))
        if not isinstance(descriptors, list) or len(descriptors) != 1:
            raise ValueError
        endpoint = descriptors[0]["Endpoints"]["docker"]["Host"]
    except (ValueError, TypeError, KeyError, IndexError) as exc:
        raise LocalImageUnavailable("The current Docker setup could not be verified. No remote environment will be contacted.") from exc
    if not _local_endpoint(endpoint):
        raise LocalImageUnavailable("The selected Docker setup connects to another computer. Choose a local Linux environment in Docker Desktop; Lightwork will not inventory a remote computer.")
    base += ["--host", endpoint]
    if _read([*base, "info", "--format", "{{.OSType}}"], env, deadline, limit=4096).strip() != "linux":
        raise LocalImageUnavailable("These practice checks require Linux containers. Switch Docker Desktop to Linux containers, then refresh the installed environments.")
    return base, env


def _metadata(value, expected):
    if (not isinstance(value, dict) or set(value) != {"id", "os", "created", "tags", "volumes"}
            or value["id"] != expected or not _IMAGE.fullmatch(expected)
            or value["os"] != "linux" or value["volumes"] not in (None, {})):
        raise LocalImageUnavailable("This installed environment is unavailable or does not meet the restricted practice checks. Choose another approved local environment; nothing was saved.")
    created, tags = value["created"], value["tags"]
    if (not isinstance(created, str) or len(created) > 100 or not isinstance(tags, (list, type(None)))
            or (tags is not None and (len(tags) > 64 or any(not isinstance(tag, str) or not _TAG.fullmatch(tag) for tag in tags)))):
        raise LocalImageUnavailable("This installed environment's name or creation date could not be verified. Nothing was saved.")
    try:
        normalized = re.sub(r"(\.\d{6})\d+", r"\1", created).replace("Z", "+00:00")
        date = datetime.fromisoformat(normalized)
        if date.tzinfo is None:
            raise ValueError
        display_date = date.astimezone(timezone.utc).strftime("%b %d, %Y %H:%M UTC")
    except (ValueError, OverflowError) as exc:
        raise LocalImageUnavailable("This installed environment's creation date could not be verified. Nothing was saved.") from exc
    name = sorted(tags)[0] if tags else "Unnamed local environment"
    return LocalImage(expected, name + " · created " + display_date)


def inventory(*, refresh=False):
    """At most 128 locally inspected choices, cached for 30 seconds."""
    global _CACHE
    with _inventory_lock():
        if not refresh and _CACHE is not None and time.monotonic() - _CACHE[0] < _CACHE_SECONDS:
            return _CACHE[1], _CACHE[2]
        deadline = time.monotonic() + 12
        base, env = _engine(deadline)
        text = _read([*base, "image", "ls", "--quiet", "--no-trunc"], env, deadline, limit=32 * 1024)
        ids = sorted(set(text.splitlines()))
        if any(not _IMAGE.fullmatch(identity) for identity in ids):
            raise LocalImageUnavailable("The installed environment list could not be verified. Nothing was selected or changed.")
        choices = []
        for offset in range(0, min(len(ids), _MAX_IMAGES), 16):
            selected = ids[offset: min(offset + 16, _MAX_IMAGES)]
            text = _read([*base, "image", "inspect", "--format", _FORMAT, "--", *selected], env, deadline)
            lines = text.splitlines()
            if len(lines) != len(selected):
                raise LocalImageUnavailable("The installed environment list changed during refresh. Refresh it again before choosing.")
            for identity, line in zip(selected, lines, strict=True):
                try:
                    choices.append(_metadata(json.loads(line), identity))
                except LocalImageUnavailable:
                    continue  # Unsupported local images are not offered as practice choices.
                except (ValueError, TypeError) as exc:
                    raise LocalImageUnavailable("The installed environment list could not be verified. Nothing was selected or changed.") from exc
        choices.sort(key=lambda item: (item.label.lower(), item.id))
        labels = {}
        for item in choices:
            labels[item.label] = labels.get(item.label, 0) + 1
        positions = {}
        unique = []
        for item in choices:
            positions[item.label] = positions.get(item.label, 0) + 1
            unique.append(LocalImage(item.id, item.label + " · local copy " + str(positions[item.label]) if labels[item.label] > 1 else item.label))
        notice = "Only already installed Linux environments without automatic writable storage are offered. Choosing one does not run a check or prove plugin readiness. The list is cached for up to 30 seconds; saving rechecks your exact choice."
        if len(ids) > _MAX_IMAGES:
            notice += " This bounded list checked the first 128 installed images. A previously selected environment is verified separately."
        _CACHE = (time.monotonic(), tuple(unique), notice)
        return _CACHE[1], notice


def selected(identity):
    """Fresh current-local-engine and exact immutable metadata check; never cached."""
    if not isinstance(identity, str) or not _IMAGE.fullmatch(identity):
        raise LocalImageUnavailable("Choose a named installed practice environment from the list. No other environment was selected.")
    deadline = time.monotonic() + 10
    base, env = _engine(deadline)
    try:
        text = _read([*base, "image", "inspect", "--format", _FORMAT, "--", identity], env, deadline, limit=16384)
        lines = text.splitlines()
        if len(lines) != 1:
            raise ValueError
        return _metadata(json.loads(lines[0]), identity)
    except (ValueError, TypeError, UnicodeDecodeError) as exc:
        raise LocalImageUnavailable("The selected practice environment is missing or could not be verified. Refresh the installed environments and choose an available one. Nothing was saved.") from exc


def validate_choice(value):
    if value == "":
        return ""
    selected(value)
    return value


def cached_label(value):
    """Readable configured value without opening Docker on unrelated settings reads."""
    if not value:
        return "No practice environment selected"
    cache = _CACHE
    if cache is not None and time.monotonic() - cache[0] < _CACHE_SECONDS:
        match = next((item for item in cache[1] if item.id == value), None)
        return match.label if match else "Previously selected practice environment · unavailable in this list"
    return "Previously selected practice environment · availability not checked"

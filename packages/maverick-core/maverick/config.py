"""Configuration loader for Lightwork.

Reads ``~/.maverick/config.toml`` (or the path set by ``$MAVERICK_CONFIG``).
Supports environment variable interpolation in string values: ``${VAR_NAME}``
is replaced with the env value, or the empty string if unset. Only
operator-owned files interpolate: the dashboard Settings overlay and per-tenant
``config.toml`` files keep ``${VAR}`` literally, because their authors have no
authority to read process secrets.

This is the surface the installer wizard writes to. Users can also edit
the TOML by hand. The kernel falls back to sensible defaults if no
config file exists, so research / dev use doesn't require running the
wizard first.

Schema overview::

    [providers.<name>]
    api_key = "${ANTHROPIC_API_KEY}"
    base_url = "..."  # optional

    [models]
    orchestrator = "anthropic:claude-opus-4-7"
    researcher   = "anthropic:claude-sonnet-4-6"
    # ...

    [budget]
    max_dollars = 5.0
    strict_pricing = true  # false => explicit legacy estimate-only accounting

    [safety]
    profile = "balanced"
"""
from __future__ import annotations

import copy
import errno
import hashlib
import io
import logging
import math
import os
import re
import stat
import threading
import time
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

# Initialize encryption before a worker resolves sealed dashboard settings.
from . import crypto_at_rest
from ._envparse import coerce_bool
from .config_contracts import BOOLEAN_SETTINGS, INTEGER_SETTINGS
from .file_lock import _windows_extended_path, atomic_read_bytes

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

# Note: do not cache the default at module import time. Both the platform home
# and the documented MAVERICK_HOME override can change in test/embedded
# processes, so resolve them dynamically inside config_path().
DEFAULT_CONFIG_BASENAME = (".maverick", "config.toml")


def _default_config_path() -> Path:
    from .paths import maverick_home

    return maverick_home() / DEFAULT_CONFIG_BASENAME[1]


def __getattr__(name: str):
    # Back-compat: `DEFAULT_CONFIG_PATH` stays importable, but caching it as a
    # module-level constant would bind Path.home() at import time (stale under
    # HOME changes / monkeypatch — exactly what the comment above warns
    # against). Resolve it lazily on attribute access so every read reflects
    # the current HOME.
    if name == "DEFAULT_CONFIG_PATH":
        return _default_config_path()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


CONFIG_OVERLAY_ENV = "MAVERICK_CONFIG_OVERLAY"

# Governed, in-process learning is the product baseline. High-authority
# actuation remains independently gated: code self-modification, live workflow
# auto-apply, generated-code execution, external MCP acquisition and model
# weight adoption do not inherit this default.
GOVERNED_LEARNING_DEFAULT = True

# Dashboard Settings overlay for config-read settings (provider keys,
# capability/feature toggles). Deep-merged over config.toml on every
# load_config() — always-on at a fixed path next to config.toml — so UI edits
# take effect on the next read without rewriting the user's config.toml. The
# dashboard owns this file (maverick_dashboard.settings_store). Distinct from
# runtime-overrides.toml (denied_tools / models / budget, read via own hooks).
DASHBOARD_OVERRIDES_BASENAME = "dashboard-config.toml"

# Accept lower/mixed-case names too, so a hand-edited config referencing a
# lowercase env var (`${my_token}`) is substituted rather than left as the
# literal `${my_token}`. The docstring promises "${VAR_NAME} is replaced" with
# no case restriction.
_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _interp(value: Any) -> Any:
    """Recursively replace ``${VAR}`` with environment values."""
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _interp(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_interp(v) for v in value]
    return value


def config_path() -> Path:
    override = os.environ.get("MAVERICK_CONFIG")
    if override:
        return Path(override).expanduser()
    # Resolve dynamically so monkeypatch.setenv("HOME", ...) takes effect
    # mid-process — the prior `return DEFAULT_CONFIG_PATH` was evaluated
    # at import time and stayed stale.
    return _default_config_path()


# Parsed-TOML cache keyed by absolute path -> (mtime_ns, size, raw_dict, digest).
# Only the expensive part (file read + TOML parse) is memoized; env-var
# interpolation and the overlay deep-merge still run on every load_config()
# call, so a changed ${VAR} or edited overlay is always reflected. Invalidated
# when the file's mtime OR size changes (a rewrite), or its content digest does
# where st_ctime cannot show a rewrite (see _CTIME_IS_CHANGE_TIME). load_config()
# is on many hot paths (a single inbound A2A delegate triggers ~6-10 full
# parses); on POSIX this removes the redundant I/O + tokenize while preserving
# exact semantics. On Windows the digest reads the file on every check, so only
# the tokenize is saved there (not measured on Windows).
_toml_cache: dict[str, tuple[int, int, dict, bytes | None]] = {}
# General configuration remains fail-soft, but security boundaries need to
# distinguish "file absent" from "present but unreadable/corrupt". Track the
# latter alongside the parsed cache so trust/auth callers can fail closed.
_toml_errors: dict[str, str] = {}
# The dashboard overlay's decryption failures, kept apart from its parse
# errors: a clean parse of a file whose values still cannot be opened must not
# clear them.
_unseal_errors: dict[str, str] = {}
# How many errors have been recorded for each source, ever (never reset). A
# read notes it before touching the file and clears an error only if none was
# recorded meanwhile: a slower read must not erase what a newer one found (a
# replaced file's corruption, a passing permission failure, a key that stopped
# working). It leaves that error for the next read to settle instead.
_toml_gen: dict[str, int] = {}
# A cache entry and its error change together, so a reader never re-reports an
# error another thread has just cleared with a fresh parse, nor the reverse.
# Nothing touches the filesystem while holding it.
_toml_lock = threading.RLock()
# What Path.exists() treats as absent: no such file, or a path through a file.
_ABSENT = (FileNotFoundError, NotADirectoryError)


class _UnreadableTable(dict):
    """The empty table a corrupt file is cached as; every hit reports it again."""

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message


# The errors one read itself ran into (see ``single_read``). _toml_errors is
# process-wide: another thread's reset or successful read can clear an entry
# while a read is in flight, so it cannot tell whether *this* read was clean.
_READ_ERRORS: ContextVar[dict[str, str] | None] = ContextVar("maverick_config_read_errors", default=None)


def _record_source_error(key: str, message: str, table: dict[str, str] | None = None) -> None:
    """Report an unreadable source to config_source_errors() and to this read."""
    (_toml_errors if table is None else table)[key] = message
    _toml_gen[key] = _toml_gen.get(key, 0) + 1
    noted = _READ_ERRORS.get()
    if noted is not None:
        noted[key] = message


def _forget_absent(key: str, since: int) -> None:
    """Drop a source found absent, unless an error was recorded for it after
    ``since`` was noted: that came from a read of a file created meanwhile."""
    with _toml_lock:
        if _toml_gen.get(key, 0) == since:
            _toml_cache.pop(key, None)
            _toml_errors.pop(key, None)
            _unseal_errors.pop(key, None)


# Bound the cache so a deployment with many per-tenant config paths
# (~/.maverick/tenants/<t>/config.toml) can't grow it without limit. Entries
# are cheap to rebuild (a stat + parse), so a simple oldest-first cap is enough.
_TOML_CACHE_MAX = 512


def reset_config_cache() -> None:
    """Drop the parsed-TOML and .env-file caches (test hook; prod files rarely
    change)."""
    global _env_last_check
    with _toml_lock:
        _toml_cache.clear()
        _toml_errors.clear()
        _unseal_errors.clear()
    _env_file_cache.clear()
    _env_last_check = None
    kept = _KEPT_READ.get()
    if kept is not None:
        kept.entry = None
    shared = _SINGLE_READ.get()
    if shared is not None:
        shared.noted = {}  # this decision's errors; enclosing ones keep theirs
    while shared is not None:  # this decision and every one it is nested in
        shared.tree = None  # the next read starts again
        shared = shared.outer


# Wizard-persisted secrets: the installer writes every collected key to
# ``~/.maverick/.env`` (next to config.toml) and references it from config
# values as ``${VAR}``. Docker-compose (``env_file``) and the systemd unit
# (``EnvironmentFile=``) inject that file, but a bare pip/CLI install had no
# injector at all, so ``${VAR}`` interpolated to "" and a freshly validated
# key could never reach the runtime (`maverick start` exited 2 right after
# `maverick init` said "Setup complete"). load_config() exports the file
# itself -- an explicitly exported variable always wins; a value the loader
# set itself follows later edits and removals of the file -- memoized by
# mtime+size so a change is a re-read, not a re-load.
# The freshness re-check itself is throttled to once per second: load_config()
# sits on per-row hot paths (e.g. _dec_field on every sealed column read), and
# an unconditional config_path()+stat() per call measurably breached the
# world_read perf SLA. A wizard-written key still lands within a second.
_ENV_FILE_BASENAME = ".env"
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_WIZARD_FORBIDDEN_AUTHORITY_ENV = frozenset({
    "MAVERICK_APPROVER_KEYS", "MAVERICK_REQUIRE_SIGNED_APPROVAL",
    "MAVERICK_AUDIT_TRUSTED_PUBLIC_KEYS", "MAVERICK_AUDIT_SIGNING_KEY",
    "MAVERICK_AUDIT_SIGNING_KEY_WRAPPED", "MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY",
})
_ENV_RECHECK_SECONDS = 1.0
_env_file_cache: dict[str, tuple[int, int, bytes | None]] = {}
# Values this loader put into os.environ, so a later change to .env replaces
# them while an explicitly exported variable still always wins.
_env_file_exported: dict[str, str] = {}
_env_file_lock = threading.Lock()
_env_last_check: float | None = None
# Bound at import: tests that monkeypatch time.monotonic (a process-global
# patch) to drive their OWN timeout logic must not have the values consumed
# by this unrelated guard on every load_config() call.
_monotonic = time.monotonic


def _load_wizard_env() -> None:
    """Throttled wrapper: re-check ``~/.maverick/.env`` at most once per
    :data:`_ENV_RECHECK_SECONDS` (first call always loads)."""
    global _env_last_check
    now = _monotonic()
    if _env_last_check is not None and now - _env_last_check < _ENV_RECHECK_SECONDS:
        return
    _env_last_check = now
    _load_env_file(config_path().parent / _ENV_FILE_BASENAME)


def _load_env_file(path: Path) -> None:
    """Export ``KEY=value`` lines from ``path`` into ``os.environ`` without
    overriding variables that were set by anyone but this loader."""
    with _env_file_lock:  # load_config() runs on many threads
        _load_env_file_locked(path)


def _drop_env_exports(keep: set[str]) -> None:
    """Stop exporting values this loader set for names not in ``keep``, unless
    someone else replaced the value meanwhile."""
    for name in [n for n in _env_file_exported if n not in keep]:
        if os.environ.get(name) == _env_file_exported.pop(name, None):
            os.environ.pop(name, None)


def _load_env_file_locked(path: Path) -> None:
    try:
        st = path.stat()
    except _ABSENT:
        _env_file_cache.pop(str(path), None)
        _drop_env_exports(set())  # .env deleted: what it exported goes too
        return
    except OSError:
        return  # unreadable .env -> keep what was loaded
    key = str(path)
    digest = _content_digest(path, st)  # None (never a hit) when the content is unreadable
    if digest is not None and _env_file_cache.get(key) == (st.st_mtime_ns, st.st_size, digest):
        return
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    _env_file_cache[key] = (st.st_mtime_ns, st.st_size, digest)
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, value = line.partition("=")
        name = name.strip()
        canonical = ("MAVERICK_" + name[len("LIGHTWORK_"):]
                     if name.startswith("LIGHTWORK_") else name)
        if not sep or not _ENV_NAME_RE.match(name) or canonical in _WIZARD_FORBIDDEN_AUTHORITY_ENV:
            continue
        value = value.strip()
        # Tolerate hand-edited quoting (systemd EnvironmentFile strips it too).
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        if name not in os.environ or os.environ[name] == _env_file_exported.get(name):
            os.environ[name] = value  # first load, or a value this loader set: follow the file
            _env_file_exported[name] = value
        seen.add(name)
    _drop_env_exports(seen)  # a line removed from the file stops being exported


def _read_toml_raw(path: Path) -> dict:
    """Parsed TOML for ``path`` (NO interpolation), memoized by mtime+size.
    Returns ``{}`` for a missing file, and ``{}`` + a warning for a corrupt one."""
    key = str(path)
    since = _toml_gen.get(key, 0)
    try:
        st = path.stat()
    except _ABSENT:
        _forget_absent(key, since)
        return {}  # an absent optional config legitimately means defaults
    except OSError as e:
        with _toml_lock:
            _toml_cache.pop(key, None)
            _record_source_error(key, f"{type(e).__name__}: {e}")
        return {}  # general callers stay fail-soft; security callers inspect health
    # Taken before the parse below: a rewrite after this is seen by the next read.
    digest = _content_digest(path, st)  # None (never a hit) when the content is unreadable
    with _toml_lock:
        cached = _toml_cache.get(key)
        if (digest is not None and cached is not None and cached[0] == st.st_mtime_ns
                and cached[1] == st.st_size and cached[3] == digest):
            if isinstance(cached[2], _UnreadableTable):
                # A reset may have cleared the entry while the corrupt table
                # stayed cached: report it on every hit.
                _record_source_error(key, cached[2].message)
            return cached[2]
    error = None
    cache = True
    try:
        # Private Windows publication retains the verified write handle until
        # rename completes. A reader can see the name before that handle closes.
        with io.BytesIO(atomic_read_bytes(path)) as f:
            raw = tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError, UnicodeDecodeError) as e:
        # The kernel must tolerate a missing config (returns {} above); a
        # corrupt/unreadable one is the adjacent case. Fail soft to defaults
        # with a warning instead of crashing the agent loop / every
        # get_role_model / get_safety caller on a hand-edited TOML typo.
        logging.getLogger(__name__).warning(
            "ignoring unreadable %s (%s: %s); using defaults",
            path, type(e).__name__, e,
        )
        error = f"{type(e).__name__}: {e}"
        # A sharing/permission failure is not parsed file content. Keep
        # health fail-closed now, but retry the next read even when this
        # complete file's mtime and size have not changed.
        cache = not isinstance(e, OSError)
        raw = _UnreadableTable(error) if cache else {}
    with _toml_lock:
        if error is not None:
            # Its caller gets no policy from this source, so it is always
            # reported, even if the file was replaced meanwhile; a later read
            # of the new file clears it.
            _record_source_error(key, error)
        elif _toml_gen.get(key, 0) != since:
            # Another read found this source unreadable while this one ran,
            # perhaps in a newer file: keep its error and its cache entry.
            return raw
        else:
            _toml_errors.pop(key, None)
        _toml_cache.pop(key, None)
        if not cache:
            return raw
        # Evict oldest entries first when over the cap (dicts preserve
        # insertion order); ``key`` is re-inserted as the newest. An evicted
        # source keeps its error: only a clean read or its absence clears it.
        while len(_toml_cache) >= _TOML_CACHE_MAX:
            _toml_cache.pop(next(iter(_toml_cache)))
        _toml_cache[key] = (st.st_mtime_ns, st.st_size, raw, digest)
    return raw


def _tree_contains_sealed_value(value: object) -> bool:
    """Whether a parsed config tree contains an at-rest ciphertext token.

    Keep this marker-only preflight independent from ``crypto_at_rest`` so an
    ordinary plaintext config load does not import the encryption stack or
    resolve key paths.  ``is_sealed_str`` performs the authenticated structural
    check before any token is actually decrypted below.
    """
    if isinstance(value, str):
        return value.startswith("MVKAR1:")
    if isinstance(value, dict):
        return any(_tree_contains_sealed_value(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_tree_contains_sealed_value(item) for item in value)
    return False


# True while this thread/task is inside ``_unseal_config_tree``. Opening the
# overlay imports the encryption stack and resolves key material, and both can
# resolve the active tenant -> client id -> ``load_config()`` -> this overlay
# again. A nested load only ever needs plaintext keys (``[client] id`` is never
# sealed), so it gets the tree with its tokens left opaque instead of a second
# unseal. Without this guard that is an import cycle that stops every
# production task at boot, and otherwise unbounded recursion. A ContextVar, not a global: concurrent requests on other tasks
# must not observe one another's in-progress unseal.
_UNSEALING: ContextVar[bool] = ContextVar("maverick_config_unsealing", default=False)


def _unseal_config_tree(value: object) -> object:
    """Return a detached config tree with authenticated ciphertext opened.

    Dashboard-managed credentials are deployment-global configuration, so they
    must use the process/deployment key even when a request currently carries a
    tenant context.  Legacy plaintext remains readable; a genuine ciphertext
    that cannot be authenticated fails closed through ``unseal_many_from_str``.
    Each key is resolved once within this read, never cached across config
    reads, so rotations and key-file permission changes remain observable.
    Re-entrant loads (see ``_UNSEALING``) receive the tokens unopened.
    """
    if not _tree_contains_sealed_value(value) or _UNSEALING.get():
        return value
    token = _UNSEALING.set(True)
    try:
        sealed: dict[str, None] = {}

        def collect(item: object) -> None:
            if isinstance(item, str) and crypto_at_rest.is_sealed_str(item):
                sealed[item] = None
            elif isinstance(item, dict):
                for child in item.values():
                    collect(child)
            elif isinstance(item, (list, tuple)):
                for child in item:
                    collect(child)

        def walk(item: object) -> object:
            if isinstance(item, str):
                return opened.get(item, item)
            if isinstance(item, dict):
                return {key: walk(child) for key, child in item.items()}
            if isinstance(item, list):
                return [walk(child) for child in item]
            if isinstance(item, tuple):
                return tuple(walk(child) for child in item)
            return item

        with crypto_at_rest.deployment_key_scope():
            collect(value)
            opened = dict(zip(sealed, crypto_at_rest.unseal_many_from_str(list(sealed)), strict=True))
            return walk(value)
    finally:
        _UNSEALING.reset(token)


def _is_tenant_config_path(path: Path) -> bool:
    from .paths import maverick_home
    try:
        root = maverick_home() / "tenants"
        for candidate, parent in ((Path(os.path.abspath(path)), Path(os.path.abspath(root))),
                                  (Path(path).resolve(strict=False), root.resolve(strict=False))):
            try:
                relative = candidate.relative_to(parent)
            except ValueError:
                continue
            if len(relative.parts) == 2 and relative.name == "config.toml":
                return True
        return False
    except (OSError, RuntimeError):
        return True  # ambiguous paths must not gain env access


def _load_config_file(path: Path, *, interpolate: bool = True) -> dict:
    # Dashboard and tenant authors do not have authority to read process
    # secrets. Only operator-owned configuration layers can interpolate env.
    raw = _read_toml_raw(path)
    # An empty source has no values to interpolate. Avoid resolving filesystem
    # paths on this common hot path; a later nonempty read still checks scope.
    loaded = (_interp(raw) if (raw and interpolate and path.name != DASHBOARD_OVERRIDES_BASENAME
                               and not _is_tenant_config_path(path))
              else copy.deepcopy(raw))
    if path.name == DASHBOARD_OVERRIDES_BASENAME:
        key = str(path)
        since = _toml_gen.get(key, 0)
        try:
            unsealed = _unseal_config_tree(loaded)
        except Exception as exc:
            # An undecryptable sealed overlay value (e.g. after a
            # MAVERICK_ENCRYPTION_KEY rotation leaves dashboard-config.toml
            # sealed under the old key) must NOT crash every config read.
            # Fail soft exactly like a corrupt-TOML source: record the error so
            # config_source_errors() surfaces it (health goes red and security
            # callers fail closed), and drop the overlay so callers fall back to
            # base/env config instead of load_config() raising process-wide.
            with _toml_lock:
                _record_source_error(key, f"{type(exc).__name__}: {exc}", _unseal_errors)
            logging.getLogger(__name__).warning(
                "dashboard overlay %s could not be decrypted; dropping it "
                "(rotate keys / re-save provider settings to restore): %s",
                path, exc,
            )
            return {}
        try:
            from .config_resets import _specs
            for _ in _specs(unsealed):
                pass
        except ValueError as exc:
            # Malformed reset metadata (hand edit, another version) would make
            # every merge raise; drop the overlay and report it like above.
            with _toml_lock:
                _record_source_error(key, f"{type(exc).__name__}: {exc}", _unseal_errors)
            logging.getLogger(__name__).warning(
                "dashboard overlay %s has unreadable reset metadata; dropping it", path,
            )
            return {}
        # A corrected key can recover the same cached TOML without a file
        # edit, and a tree with nothing sealed has nothing left to open. Only a
        # complete read clears a decryption error (a recursive one returns the
        # tokens unopened), only while the tree it opened is still the cached
        # one, and only if no error was recorded while it was being opened.
        if not _UNSEALING.get():
            with _toml_lock:
                cached = _toml_cache.get(key)
                if cached is not None and cached[2] is raw and _toml_gen.get(key, 0) == since:
                    _unseal_errors.pop(key, None)
        return unsealed  # type: ignore[return-value]
    return loaded


def _deep_merge_config(base: dict, overlay: dict) -> dict:
    merged = dict(base)
    for key, value in overlay.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge_config(merged[key], value)
        else:
            merged[key] = value
    return merged


def dashboard_overrides_path() -> Path:
    """Path to the dashboard-owned config overlay (next to config.toml)."""
    return config_path().parent / DASHBOARD_OVERRIDES_BASENAME


def load_governed_records_config() -> dict:
    """Load only sources allowed to select the governed-record backend.

    Tenant overlays must not select a deployment-global persistence plane.
    The deployment-global sources do: config.toml, the dashboard settings
    overlay (written only by a global administrator on Settings > All
    settings), then the operator overlay; environment variables still win in
    the readers. This is :func:`load_global_config`, which never merges a
    tenant overlay.
    """
    return load_global_config()


def governed_records_config_source_errors() -> dict[str, str]:
    """Unreadable sources participating in governed-backend selection."""
    return config_source_errors(include_tenant=False)


def _source_errors(paths: list[Path]) -> dict[str, str]:
    """Return current parse/I/O errors for exactly ``paths``."""
    # Optional overlays are skipped by ``load_config`` once they disappear, so
    # a parse error cached while the file existed would otherwise remain
    # security-significant forever. Clear it only when the filesystem
    # definitively reports that the source is absent. Permission failures and
    # every other I/O error remain fail-closed: they may mean policy exists but
    # cannot be inspected.
    for path in paths:
        key = str(path)
        if key in _toml_errors or key in _unseal_errors:
            since = _toml_gen.get(key, 0)
            try:
                path.stat()
            except _ABSENT:
                _forget_absent(key, since)
            except OSError:
                pass
    errors = {}
    with _toml_lock:
        for path in paths:
            key = str(path)
            message = _toml_errors.get(key)
            if message is None:
                message = _unseal_errors.get(key)
            if message is not None:
                errors[key] = message
    shared = _SINGLE_READ.get()
    if shared is not None and shared.open and shared.noted:
        # A source this decision found unreadable stays reported until the
        # decision ends, even if another thread clears the process-wide entry.
        for path in paths:
            if str(path) in shared.noted:
                errors.setdefault(str(path), shared.noted[str(path)])
    return errors


def config_source_errors(*, include_tenant: bool = True) -> dict[str, str]:
    """Unreadable/corrupt files among the active config sources.

    ``load_config`` intentionally returns defaults for malformed TOML so a typo
    does not crash ordinary model-selection calls. Authentication and trust
    callers inspect this seam immediately after loading and deny remote control
    if policy may have been lost.
    """
    paths = [config_path(), dashboard_overrides_path()]
    overlay = os.environ.get(CONFIG_OVERLAY_ENV)
    if overlay:
        paths.append(Path(overlay).expanduser())
    if include_tenant:
        tenant = tenant_config_path()
        if tenant is not None:
            paths.append(tenant)
    return _source_errors(paths)


def governed_learning_default() -> bool:
    """Default-on only when every active configuration source is trustworthy.

    The fail-soft TOML loader deliberately maps both an absent file and a
    malformed file to ``{}``. Mutating learning must distinguish them: absence
    gets the product default, while an unreadable/corrupt policy fails closed.
    """
    try:
        return GOVERNED_LEARNING_DEFAULT and not bool(config_source_errors())
    except Exception:  # pragma: no cover -- uncertainty cannot enable mutation
        return False


def governed_learning_env_flag(name: str) -> bool | None:
    """Tri-state learning override that cannot bypass corrupt policy.

    An explicit ``VAR=0`` remains a reliable opt-out. ``VAR=1`` is honored only
    after every active configuration source parses successfully.
    """
    try:
        load_config()
        if config_source_errors():
            return False
        value = env_flag(name)
        # ``env_flag`` intentionally treats absent and malformed values alike
        # for general feature switches. Default-on learning cannot: a present
        # but unrecognized value must never fall through and enable mutation.
        if value is None and name in os.environ:
            return False
        return value
    except Exception:  # pragma: no cover -- uncertainty cannot enable mutation
        return False


def tenant_config_path() -> Path | None:
    """Path to the active tenant's config overlay, or None in single-tenant mode.

    Resolves to ``~/.maverick/tenants/<tenant>/config.toml`` when a tenant is
    active via an explicit ``set_tenant`` scope or the ``MAVERICK_TENANT`` env
    var, and None otherwise. Deliberately config-free: it reads only the tenant
    ContextVar and env var, NOT ``current_tenant_id()`` (whose client-binding
    branch reads config and would recurse back into ``load_config`` on every
    call -- a hot-path blow-up). A client-bound single deployment already loads
    its own ``config.toml``, so it needs no separate per-tenant overlay.
    """
    try:
        from .paths import _TENANT, _tenant_segment, maverick_home
        tid = _TENANT.get() or os.environ.get("MAVERICK_TENANT", "").strip() or None
        if not tid:
            return None
        path = maverick_home() / "tenants" / _tenant_segment(tid) / "config.toml"
        # Keep ordinary paths stable in config fingerprints and UI context
        # tokens; only deep tenant paths need the Win32 extended spelling.
        if os.name == "nt" and len(os.path.abspath(path)) >= 240:
            return Path(_windows_extended_path(path))
        return path
    except Exception:  # pragma: no cover -- config resolution never blocks a run
        return None


_TRUTHY = {"1", "true", "yes", "on"}
_FALSY = {"0", "false", "no", "off"}


def env_flag(name: str) -> bool | None:
    """Parse an env var as a tri-state boolean: ``True``/``False`` for a
    recognized truthy/falsy value, ``None`` when unset or unrecognized. Lets the
    module ``enabled()`` gates share one parser instead of re-spelling the
    ``{"1","true","yes","on"}`` literal set (and its inverse) each time.

    Positive-only callers use ``if env_flag(name): ...``; tri-state callers use
    ``v = env_flag(name); if v is not None: return v``."""
    raw = os.environ.get(name, "").strip().lower()
    if raw in _TRUTHY:
        return True
    if raw in _FALSY:
        return False
    return None


def _strict_config_bool(
    cfg: dict, key: str, default: bool, *, invalid: bool = False,
) -> bool:
    """Read a policy boolean without Python's string-truthiness footgun.

    TOML normally supplies a real bool, but dashboard overlays and callers may
    provide malformed values. Missing uses the documented default; a present
    non-bool uses the caller's fail-closed posture.
    """
    if key not in cfg:
        return bool(default)
    value = cfg.get(key)
    return value if isinstance(value, bool) else bool(invalid)


class _SharedRead:
    __slots__ = ("open", "fresh", "tree", "noted", "outer")

    def __init__(self, fresh: bool, outer: _SharedRead | None) -> None:
        self.open = True
        self.fresh = fresh
        self.tree: dict | None = None
        self.noted: dict[str, str] = {}  # sources this decision found unreadable
        self.outer = outer  # the open decision this one is nested in, if any


# One authorization decision asks a dozen questions of the deployment-global
# configuration (the sign-in methods, the profile, the client binding, the
# dashboard token). Without sharing, each would read the files again and, once
# a secret has been saved from Settings, resolve the at-rest key and decrypt
# it: about 15 reads per decision and 350 per dashboard page. Inside
# ``single_read()`` the
# first clean read is shared and every caller gets its own copy. A read that
# itself ran into an unreadable, corrupt or undecryptable source (recorded in
# ``_READ_ERRORS`` as it happens, never inferred from process-wide state) is
# used once: the next caller reads the files again, exactly as before, and
# config_source_errors() keeps reporting that source until the scope ends.
# reset_config_cache() inside the scope also starts a fresh read.
#
# A plain scope (a page render, a roster audit) joins any open scope. A gate
# opens ``single_read(fresh=True)``: it reads the current files even inside a
# render, joining only another gate's read. No scope outlives its decision.
_SINGLE_READ: ContextVar[_SharedRead | None] = ContextVar("maverick_config_single_read", default=None)


@contextmanager
def single_read(*, fresh: bool = False):
    """Read the deployment-global configuration once for one decision."""
    current = _SINGLE_READ.get()
    if current is not None and current.open and (current.fresh or not fresh):
        yield  # already inside this decision: share its read
        return
    shared = _SharedRead(fresh, current if current is not None and current.open else None)
    token = _SINGLE_READ.set(shared)
    try:
        yield
    finally:
        shared.open = False
        shared.tree = None
        _SINGLE_READ.reset(token)


def _copy_tree(value):
    if isinstance(value, dict):
        return {key: _copy_tree(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_copy_tree(child) for child in value]
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    import copy

    return copy.deepcopy(value)


def load_global_config() -> dict:
    """Load deployment-global config without a per-tenant overlay.

    Repo-global control planes such as DGM must not change authority depending
    on whichever tenant happens to be active in the current request context.
    The dashboard overlay remains writable by the global admin; the optional
    operator-owned config overlay still has higher precedence.
    """
    if _UNSEALING.get():
        return _read_global_config()
    shared = _SINGLE_READ.get()
    if shared is not None and not shared.open:
        shared = None
    if shared is not None and shared.tree is not None:
        return _copy_tree(shared.tree)
    kept = _KEPT_READ.get()
    if shared is None and kept is None:
        return _read_global_config()
    witness = _read_witness() if kept is not None else None
    entry = kept.entry if kept is not None else None
    if (entry is not None and witness is not None and entry[1] == witness
            and _monotonic() - entry[2] <= _KEEP_READ_SECONDS and _same_environment(entry[3])):
        if shared is not None:
            shared.tree = entry[0]
        return _copy_tree(entry[0])
    started = _monotonic()
    environment = _environment() if kept is not None else None
    with _collecting_read_errors() as noted:
        tree = _read_global_config()
    if noted:
        if shared is not None:
            shared.noted.update(noted)
        return tree
    clean = _copy_tree(tree)  # only a read that met no error itself is shared
    if shared is not None and shared.open:
        shared.tree = clean
    if kept is not None and witness is not None:
        kept.entry = (clean, witness, started, environment)
    return tree


class _KeptRead:
    __slots__ = ("entry",)

    def __init__(self) -> None:
        self.entry: tuple[dict, tuple, float, dict] | None = None  # (tree, files, read at, environment)


# Within one request, a decision whose inputs are provably unchanged since the
# request's last clean read uses that read: a page asked about 29 times, each
# reading the files, resolving the at-rest key and decrypting the saved
# secrets again. "Unchanged" is the whole environment and the identity
# (modification and change times, size, device, inode, links, mode, owner, and
# on Windows a content digest, see _CTIME_IS_CHANGE_TIME) of every file a read
# depends on: config.toml, the Settings overlay, the
# operator overlay, the wizard's .env, the at-rest key, its folder and its
# keyring (their own entries, so a link put in their place shows too). A saved
# policy, a rotated key or a changed permission changes one of them and the
# next decision reads again. A Windows ACL change is not visible to stat, so
# a kept read is used for at most _KEEP_READ_SECONDS after the read that fully
# checked the key folder.
_KEEP_READ_SECONDS = 2.0
_KEPT_READ: ContextVar[_KeptRead | None] = ContextVar("maverick_config_kept_read", default=None)


@contextmanager
def kept_reads():
    """Let the decisions of one request share a read while its inputs are unchanged."""
    token = _KEPT_READ.set(_KeptRead())
    try:
        yield
    finally:
        _KEPT_READ.reset(token)


def discard_kept_reads() -> None:
    """Drop a request's kept read from a context copied into a background worker."""
    _KEPT_READ.set(None)


# st_ctime is the change time on POSIX but the creation time on Windows ("Changed
# in version 3.12: st_ctime is deprecated on Windows", os.stat_result). An
# in-place rewrite that restores the modification time and keeps the size then
# changes nothing a stat reports, so there a file's fingerprint also carries a
# SHA-256 of its content (one read of the file per check; not measured on
# Windows). Module-level so a test can patch the platform choice.
_CTIME_IS_CHANGE_TIME = os.name != "nt"


def _content_digest(path: Path, st: os.stat_result) -> bytes | None:
    """The content digest of a regular file where stat cannot show a rewrite,
    ``b""`` (and no file read) everywhere else. None when that content cannot be
    read; the caller must then treat the file as changed, never as unchanged."""
    if _CTIME_IS_CHANGE_TIME or not stat.S_ISREG(st.st_mode):
        return b""
    try:
        # No retry: a denied read only forces a miss, and the read that
        # follows it keeps its own retry.
        return hashlib.sha256(atomic_read_bytes(path, retry_seconds=0.0)).digest()
    except OSError:
        return None


def _file_state(path: Path, *, key_material: bool = False, rechmodded: bool = False) -> object:
    try:
        # The key's own entries, not what they point to: a read refuses a
        # key file or folder replaced by a link, or a hard-linked key file.
        st = os.lstat(path) if key_material else os.stat(path)
    except OSError as e:
        return type(e).__name__
    # Every read re-applies the key folder's private mode, which moves its
    # change time; its mode, owner and link count still show any change.
    changed = None if rechmodded else st.st_ctime_ns
    digest = _content_digest(path, st)
    if digest is None:
        return None  # unreadable content: _read_witness takes no witness
    return (st.st_mtime_ns, changed, st.st_size, st.st_dev, st.st_ino, st.st_nlink,
            st.st_mode, st.st_uid, st.st_gid, digest)


def _environment() -> dict:
    data = getattr(os.environ, "_data", None)
    return dict(data) if isinstance(data, dict) else dict(os.environ)


def _same_environment(kept: dict) -> bool:
    data = getattr(os.environ, "_data", None)
    return (data if isinstance(data, dict) else dict(os.environ)) == kept


def _read_witness() -> tuple | None:
    """The files a deployment-global read depends on, as cheap facts (the
    environment is compared separately, against a copy taken at the read).
    None when they cannot be stated: that read is neither kept nor reused."""
    token = _UNSEALING.set(True)  # resolving the key path may read [client] id once
    try:
        key = crypto_at_rest._key_path()
    except Exception:  # e.g. an invalid [client] id: the read itself reports it
        return None
    finally:
        _UNSEALING.reset(token)
    keyring = key.parent / "at_rest.d"
    base = config_path()
    paths = [base, dashboard_overrides_path(), base.parent / _ENV_FILE_BASENAME, keyring]
    overlay = os.environ.get(CONFIG_OVERLAY_ENV)
    if overlay:
        paths.append(Path(overlay).expanduser())
    keys = [key]
    try:
        with os.scandir(keyring) as entries:
            keys.extend(sorted(keyring / e.name for e in entries if e.name.endswith(".key")))
    except OSError:
        pass
    files = tuple(_file_state(path) for path in paths)
    key_folder = _file_state(key.parent, key_material=True, rechmodded=True)
    key_files = tuple(_file_state(path, key_material=True) for path in keys)
    if key_folder is None or None in files or None in key_files:
        return None  # a file whose content cannot be read is never the same as before
    return (tuple(str(path) for path in [*paths, key.parent, *keys]),
            files, key_folder, key_files,
            crypto_at_rest._FORCE_EXTERNAL_FLEET_KEY.get())


@contextmanager
def _collecting_read_errors():
    noted: dict[str, str] = {}
    token = _READ_ERRORS.set(noted)
    try:
        yield noted
    finally:
        _READ_ERRORS.reset(token)


def _present(path: Path) -> bool:
    """``Path.exists`` for an optional source, except that a symlink loop is
    read so the read reports it: ``exists`` treats a loop as absent and
    silently dropped the policy. A permission error still raises, as callers
    such as the workspace IP allowlist rely on it."""
    if path.exists():
        return True
    try:
        path.stat()
    except OSError as e:
        return e.errno == errno.ELOOP or getattr(e, "winerror", None) == 1921  # a loop
    except ValueError:
        return False
    return True  # created since


def _read_global_config() -> dict:
    # Wizard-persisted secrets must be in the environment BEFORE interpolation,
    # or every "${ANTHROPIC_API_KEY}" the wizard wrote resolves to "" on a bare
    # pip/CLI install. setdefault semantics: a real export always wins.
    _load_wizard_env()
    cfg = _load_config_file(config_path())
    # Dashboard Settings overlay (always-on, fixed path): UI-edited provider
    # keys / capability+feature toggles merge over config.toml without touching it.
    dash = dashboard_overrides_path()
    if _present(dash):
        from .config_resets import merge_dashboard
        cfg = merge_dashboard(cfg, _load_config_file(dash), _deep_merge_config)
    overlay = os.environ.get(CONFIG_OVERLAY_ENV)
    if overlay:
        cfg = _deep_merge_config(cfg, _load_config_file(Path(overlay).expanduser()))
    from .runtime_configuration import remember
    remember(cfg, valid=not bool(config_source_errors(include_tenant=False)))
    return cfg


def load_config(path: Path | None = None) -> dict:
    if path is not None:
        return _load_config_file(path)

    cfg = load_global_config()
    # Per-tenant overlay (highest precedence): when a tenant is active, its own
    # config.toml wins, so each client supplies its own provider API keys, model
    # choices and budget without sharing one global credential set. Skipped in
    # single-tenant mode, so the legacy path is byte-for-byte unchanged.
    tcfg = tenant_config_path()
    if tcfg is not None and _present(tcfg):
        shared = _SINGLE_READ.get()
        if shared is None or not shared.open:
            return _deep_merge_config(cfg, _load_config_file(tcfg, interpolate=False))
        with _collecting_read_errors() as noted:
            tenant = _load_config_file(tcfg, interpolate=False)
        shared.noted.update(noted)  # reported for the rest of the decision
        cfg = _deep_merge_config(cfg, tenant)
    return cfg


class AgentStepConfigError(ValueError):
    """An invalid task-step setting, with no configured value in the message."""


def get_agent_max_steps(fallback: int | None = None) -> int | None:
    """Resolve the current task-step limit; malformed limits never become unlimited.

    Preserve environment precedence, the explicit agent fallback, and the native
    unlimited default. The ordinary Settings writer separately bounds its form.
    """
    message = (
        "The task-step limit must be a positive whole number. "
        "An administrator can review ‘Most steps an agent may take’ in All settings."
    )
    raw = os.environ.get("MAVERICK_MAX_STEPS")
    if raw is None or not raw.strip():
        table = load_config().get("agent", {})
        if not isinstance(table, dict):
            raise AgentStepConfigError(message)
        raw = table.get("max_steps")
    value = fallback
    if raw is not None and not (isinstance(raw, str) and not raw.strip()):
        if type(raw) not in (str, int):
            raise AgentStepConfigError(message)
        try:
            value = int(raw)
        except (TypeError, ValueError, OverflowError):
            raise AgentStepConfigError(message) from None
    if value is not None and (type(value) is not int or value < 1):
        raise AgentStepConfigError(message)
    return value


def get_role_model(
    role: str,
    *,
    config: dict[str, Any] | None = None,
) -> str | None:
    """Return the model spec ("provider:model-id") for a role, or None.

    A per-tenant override (the dashboard roles editor, persisted to roles.toml)
    wins over the global [models] config; absent one, the config value is used.

    ``config`` lets deterministic callers reuse an already-admitted snapshot
    instead of loading configuration twice.  The role override is still read
    through the same authority path, so offline preflight and live execution
    cannot disagree about a tenant's ``roles.toml`` selection.
    """
    try:
        from .role_edit import override_model
        ov = override_model(role)
        if ov:
            return ov
    except Exception:  # role layer is optional; never block model resolution
        pass
    cfg = load_config() if config is None else config
    spec = cfg.get("models", {}).get(role)
    return spec if isinstance(spec, str) and spec else None


def get_provider_config(provider: str) -> dict:
    cfg = load_config()
    return cfg.get("providers", {}).get(provider, {})


def provider_configuration_state(provider: str) -> dict[str, Any]:
    """Return a redacted, field-level provenance snapshot for one provider.

    Runtime provider clients prefer the effective config table (base config,
    dashboard overlay, operator overlay, then tenant overlay) and use provider
    environment variables only when the corresponding config field is empty.
    Settings, Permissions, and credential-rotation UI use this one resolver so
    they cannot claim a dashboard key is active while a higher-precedence
    tenant/operator value still wins. No credential value is returned.
    """
    name = str(provider or "").strip().lower()
    _load_wizard_env()
    layers: list[tuple[str, Path | None]] = [
        ("config.toml", config_path()),
        ("dashboard", dashboard_overrides_path()),
    ]
    operator_overlay = os.environ.get(CONFIG_OVERLAY_ENV, "").strip()
    if operator_overlay:
        layers.append(("operator overlay", Path(operator_overlay).expanduser()))
    layers.append(("tenant config", tenant_config_path()))

    effective: dict[str, Any] = {}
    field_sources: dict[str, str] = {}
    dashboard_set = False
    dashboard_path = dashboard_overrides_path()
    dashboard_layer = _load_config_file(dashboard_path) if dashboard_path.exists() else {}
    for source, path in layers:
        if path is None or not path.exists():
            continue
        loaded = (dashboard_layer if source == "dashboard" else
                  _load_config_file(path, interpolate=source != "tenant config"))
        if source == "config.toml" and dashboard_layer:
            # A dashboard reset masks the installer's value before the normal
            # merge. Reflect that same effective source in Settings and health.
            from .config_resets import apply_to_base

            loaded = apply_to_base(loaded, dashboard_layer)
        providers = loaded.get("providers") if isinstance(loaded, dict) else None
        table = providers.get(name) if isinstance(providers, dict) else None
        if not isinstance(table, dict):
            continue
        if source == "dashboard" and table:
            dashboard_set = True
        for field, value in table.items():
            effective[field] = value
            field_sources[str(field)] = source

    def _text(value: object) -> str:
        if isinstance(value, str):
            return value.strip()
        return str(value).strip() if value else ""

    key_present = bool(_text(effective.get("api_key")))
    key_source = field_sources.get("api_key") if key_present else None
    key_env = None
    if not key_present:
        for env_name in PROVIDER_KEY_ENV_MAP.get(name, ()):
            if os.environ.get(env_name, "").strip():
                key_present = True
                key_env = env_name
                key_source = f"environment:{env_name}"
                break

    base_url = _text(effective.get("base_url"))
    base_source = field_sources.get("base_url") if base_url else None
    if not base_url:
        for env_name in PROVIDER_BASE_URL_ENV_MAP.get(name, ()):
            value = os.environ.get(env_name, "").strip()
            if value:
                base_url = value
                base_source = f"environment:{env_name}"
                break

    # Vertex AI has no key: its configured project is the set-up, so it counts.
    project_present = name == "vertex" and bool(_text(effective.get("project_id")))
    project_source = field_sources.get("project_id") if project_present else None
    sources = [source for source in (key_source, base_source, project_source) if source]
    via = " + ".join(dict.fromkeys(sources)) or None
    protected_sources = {"operator overlay", "tenant config"}
    return {
        "name": name,
        "configured": bool(key_present or base_url or project_present),
        "api_key_configured": key_present,
        "api_key_source": key_source,
        "api_key_env": key_env,
        "base_url_configured": bool(base_url),
        "base_url": base_url,
        "base_url_source": base_source,
        "via": via,
        "dashboard_set": dashboard_set,
        "dashboard_can_set_api_key": key_source not in protected_sources,
        "dashboard_can_set_base_url": base_source not in protected_sources,
        "source_errors": config_source_errors(),
    }


# Canonical provider -> API-key env var(s). These values are safe to pass as
# the provider client's ``api_key`` argument; non-key credentials (for example
# Azure's pre-fetched Entra token) belong in PROVIDER_CREDENTIAL_ENV_MAP below.
# Aliases (GROK/GOOGLE) are included.
PROVIDER_KEY_ENV_MAP: dict[str, tuple[str, ...]] = {
    "anthropic": ("ANTHROPIC_API_KEY",),
    "openai": ("OPENAI_API_KEY",),
    "gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
    "openrouter": ("OPENROUTER_API_KEY",),
    "moonshot": ("MOONSHOT_API_KEY",),
    "deepseek": ("DEEPSEEK_API_KEY",),
    "xai": ("XAI_API_KEY", "GROK_API_KEY"),
    "tgi": ("TGI_API_KEY",),
    "vllm": ("VLLM_API_KEY",),
    "azure": ("AZURE_OPENAI_API_KEY",),
    "bedrock": ("BEDROCK_API_KEY",),
    "openai_compatible": ("OPENAI_COMPATIBLE_API_KEY",),
    # ChatGPT/Codex access token for the codex_cli provider. Consumed by
    # `codex login --with-access-token` (fed on STDIN, never argv/logs).
    "codex_cli": ("CODEX_ACCESS_TOKEN",),
}

PROVIDER_KEY_ENV_VARS = tuple(
    dict.fromkeys(v for vs in PROVIDER_KEY_ENV_MAP.values() for v in vs)
)

# Every environment credential that can authenticate a provider, including
# credentials that are deliberately not API keys. Security boundaries such as
# the GitHub Action output sanitizer and the "is anything configured?" probe
# use this broader map; client construction continues to use the key-only map.
PROVIDER_CREDENTIAL_ENV_MAP: dict[str, tuple[str, ...]] = {
    **PROVIDER_KEY_ENV_MAP,
    "azure": (*PROVIDER_KEY_ENV_MAP["azure"], "AZURE_OPENAI_AD_TOKEN"),
    # Vertex AI signs in with Google Application Default Credentials, which
    # have no provider variable. GOOGLE_APPLICATION_CREDENTIALS is deliberately
    # not listed: it is shared with other Google tooling, so listing it here
    # would make such a host look configured. The GitHub Action sanitizer
    # registry still tracks it as a secret file.
    "vertex": (),
}
PROVIDER_CREDENTIAL_ENV_VARS = tuple(
    dict.fromkeys(v for vs in PROVIDER_CREDENTIAL_ENV_MAP.values() for v in vs)
)

# Self-hosted endpoints configured by env var (the mechanism each provider's
# docstring documents). Ollama has no env var: its only custom-URL surface is
# ``[providers.ollama] base_url`` in config, covered below.
PROVIDER_BASE_URL_ENV_MAP: dict[str, tuple[str, ...]] = {
    "anthropic": ("ANTHROPIC_BASE_URL",),
    "openai": ("OPENAI_BASE_URL",),
    "moonshot": ("MOONSHOT_BASE_URL",),
    "deepseek": ("DEEPSEEK_BASE_URL",),
    "xai": ("XAI_BASE_URL",),
    "tgi": ("TGI_BASE_URL",),
    "vllm": ("VLLM_BASE_URL",),
    "azure": ("AZURE_OPENAI_ENDPOINT",),
    "openai_compatible": ("OPENAI_COMPATIBLE_BASE_URL",),
}
PROVIDER_BASE_URL_ENV_VARS = tuple(
    dict.fromkeys(value for values in PROVIDER_BASE_URL_ENV_MAP.values() for value in values)
)


# --- Per-tenant provider keys (BYOK) --------------------------------------
#
# When enabled, an active tenant may run on its OWN provider API key instead of
# the deployment-global one -- "bring your own key" for LLM/provider credentials
# (distinct from per-tenant [kms] BYOK, which is envelope-encryption key custody).
# Default OFF: with the knob off, or when no tenant is active, provider-key
# resolution is byte-for-byte the historical global-key behavior. This is BYOK
# only -- no resale, metering, or markup lives here.


def providers_per_tenant_keys() -> bool:
    """Whether a tenant may override the deployment-global provider key with its
    own (``[providers] per_tenant_keys``; ``MAVERICK_PER_TENANT_KEYS`` wins).

    Read from the GLOBAL config (not a per-tenant overlay) so a tenant cannot
    flip its own master switch -- this is a deployment-owner policy. **Default
    off.** Never raises."""
    flag = env_flag("MAVERICK_PER_TENANT_KEYS")
    if flag is not None:
        return flag
    try:
        providers = load_global_config().get("providers") or {}
    except Exception:  # pragma: no cover -- config never blocks a run
        return False
    if not isinstance(providers, dict):
        return False
    return _strict_config_bool(providers, "per_tenant_keys", False)


def provider_test_receipt_max_age_days() -> int:
    """How many days a passing provider connection test stays valid
    (``[providers] test_receipt_max_age_days``; env
    ``MAVERICK_PROVIDER_TEST_RECEIPT_MAX_AGE_DAYS`` wins). Default 30, at
    least 1. After that the provider reads "not tested yet" again with the
    age of the last test, so a green badge can never be older than this.
    Never raises."""
    raw = os.environ.get("MAVERICK_PROVIDER_TEST_RECEIPT_MAX_AGE_DAYS", "").strip()
    if not raw:
        try:
            providers = load_global_config().get("providers") or {}
        except Exception:  # pragma: no cover -- config never blocks a run
            providers = {}
        raw = providers.get("test_receipt_max_age_days", 30) if isinstance(providers, dict) else 30
    try:
        days = int(raw)
    except (TypeError, ValueError, OverflowError):
        return 30
    return max(1, days)


def tenant_provider_key_env(tenant_id: str, provider: str) -> str:
    """The secret-provider name that holds ``tenant_id``'s own API key for
    ``provider``.

    Convention: ``MAVERICK_TENANT_<digest>_<PROVIDER>_API_KEY`` where ``digest``
    is derived from the tenant's canonical namespace key -- the same
    collision-safe identity the filesystem isolation uses -- so two distinct
    tenants can never resolve to the same secret name (a plain uppercased slug
    would alias ``acme-1`` and ``acme_1`` onto one name and leak a key across
    tenants). ``provider`` is canonicalized through the provider registry so an
    alias (``claude`` -> ``anthropic``) maps to one name.

    The value is resolved through :mod:`maverick.secret_provider` (process env
    or a mounted vault / secret file); the key bytes are NEVER written to config,
    the repo, the tenant record, or logs. The name ends in ``_API_KEY`` so the
    GitHub Action output sanitizer redacts it by pattern. Raises for an invalid
    tenant id (callers on the runtime path use :func:`tenant_provider_api_key`,
    which is fail-soft)."""
    from .paths import _tenant_namespace_key
    from .providers import _canonical

    namespace_key = _tenant_namespace_key(tenant_id)
    digest = hashlib.sha256(namespace_key.encode("utf-8")).hexdigest()[:16]
    return f"MAVERICK_TENANT_{digest}_{_canonical(provider).upper()}_API_KEY"


def tenant_sets_provider_endpoint_without_key(provider: str) -> bool:
    """Whether the active tenant overlay points ``[providers.<provider>]`` at
    its own ``base_url`` without supplying its own ``api_key``.

    The tenant layer is merged field by field over the deployment layers, so
    such a table would pair the deployment's key with the tenant's endpoint.
    An unreadable overlay counts as setting one (callers refuse)."""
    path = tenant_config_path()
    if path is None or not _present(path):
        return False
    try:
        table = (_load_config_file(path, interpolate=False).get("providers") or {}).get(provider)
    except Exception:
        return True
    if not isinstance(table, dict):
        return False
    base_url, key = table.get("base_url"), table.get("api_key")
    return (bool(str(base_url).strip()) if base_url is not None else False) and not (
        isinstance(key, str) and key.strip())


def tenant_provider_api_key(provider: str) -> str | None:
    """The ACTIVE tenant's own provider key, or ``None`` to defer to the global
    key.

    Returns a key only when ALL hold: the deployment enabled per-tenant keys
    (:func:`providers_per_tenant_keys`), a tenant is active, that tenant's record
    opted in (``byok``), and the tenant secret is present. Otherwise ``None`` --
    and the caller falls back to the deployment-global key, byte-for-byte the
    historical path.

    Fail-safe: any resolution problem (unknown tenant, unreadable registry,
    invalid id) returns ``None`` and never raises, so a BYOK misconfiguration
    can never take an agent offline -- it degrades to the global key."""
    if not provider:
        return None
    try:
        if not providers_per_tenant_keys():
            return None
        from .paths import current_tenant_id

        tenant_id = current_tenant_id()
        if not tenant_id:
            return None
        from .tenant import registry

        record = registry.get_tenant(tenant_id)
        if record is None or not getattr(record, "byok", False):
            return None
        from .secret_provider import get_secret

        key = get_secret(tenant_provider_key_env(tenant_id, provider))
    except Exception:  # pragma: no cover -- BYOK must never break the call path
        return None
    if isinstance(key, str) and key.strip():
        return key.strip()
    return None


def azure_provider_configuration_missing(
    provider_config: dict[str, Any] | None = None,
) -> tuple[str, ...]:
    """Return Azure OpenAI's missing non-network prerequisites.

    Keep this in the configuration layer because both the generic
    ``any_provider_configured`` gate and the route-specific operator preflight
    need the exact same answer.  In particular, a bare Entra token is not a
    runnable Azure route, while managed identity needs no literal secret when
    Entra authentication is selected explicitly.

    Authentication resolution mirrors ``LLM._provider_client_config`` and
    ``providers.azure_openai_provider._azure_auth``: a non-empty
    ``[providers.azure].auth_mode`` overrides ``AZURE_OPENAI_AUTH``, a
    configured API key overrides the environment key, and ambiguous or unknown
    authentication selections fail closed.
    """
    table = provider_config if isinstance(provider_config, dict) else {}

    def present(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    def normalized_secret(value: object) -> str:
        if isinstance(value, str):
            return value.strip()
        return str(value).strip() if value else ""

    endpoint = present(table.get("base_url")) or present(
        os.environ.get("AZURE_OPENAI_ENDPOINT")
    )
    key = normalized_secret(table.get("api_key"))
    if not key:
        key = os.environ.get("AZURE_OPENAI_API_KEY", "").strip()
    ad_token = os.environ.get("AZURE_OPENAI_AD_TOKEN", "").strip()

    configured_auth_mode = table.get("auth_mode")
    auth_mode = (
        configured_auth_mode.strip().lower()
        if isinstance(configured_auth_mode, str) and configured_auth_mode.strip()
        else os.environ.get("AZURE_OPENAI_AUTH", "").strip().lower()
    )
    if auth_mode not in {"", "api_key", "entra_id"} or (key and ad_token):
        authentication = False
    elif auth_mode == "api_key":
        authentication = bool(key)
    elif auth_mode == "entra_id":
        # A static token is optional: without one the runtime intentionally
        # constructs DefaultAzureCredential after the SDK preflight.
        authentication = not key
    else:
        authentication = bool(key) ^ bool(ad_token)

    deployment = present(os.environ.get("AZURE_OPENAI_DEPLOYMENT")) or present(
        table.get("deployment")
    )
    return tuple(
        item
        for item, configured in (
            ("endpoint", endpoint),
            ("authentication", authentication),
            ("deployment", deployment),
        )
        if not configured
    )


def any_provider_configured() -> bool:
    """The ONE predicate for "can this install reach some LLM provider?".

    Three legitimate configuration surfaces, all honored:
      1. a well-known credential env var (hosted providers);
      2. a self-hosted base-URL env var (vLLM / TGI / OpenAI-compatible);
      3. a ``[providers.<name>]`` config table carrying a non-empty
         ``api_key`` or ``base_url`` (``${VAR}`` interpolates to "" when
         unset, so an empty interpolation does not count).
      4. an existing Codex CLI login at ``$CODEX_HOME/auth.json``.

    The CLI preflight, the LLM clients and the dashboard all use this one
    helper, so a keyless self-hosted setup is accepted or rejected the same
    way everywhere. Use it instead of writing another variant.
    """
    # Read config FIRST: load_config() also exports the wizard-persisted
    # ~/.maverick/.env into the environment (setdefault), so the env-var checks
    # below see installer-collected keys even when config.toml carries no
    # [providers] table.
    providers = load_config().get("providers") or {}
    # Azure is the exception to the useful "a credential is enough" shortcut:
    # its dedicated client also requires an endpoint and deployment, and
    # DefaultAzureCredential can be intentionally selected without a literal
    # secret.  Do not let a lone token unblock the CLI or reject a complete
    # managed-identity route.
    non_azure_credentials = (
        name
        for provider, names in PROVIDER_CREDENTIAL_ENV_MAP.items()
        if provider != "azure"
        for name in names
    )
    if any(os.environ.get(v) for v in non_azure_credentials):
        return True
    if any(os.environ.get(v) for v in PROVIDER_BASE_URL_ENV_VARS):
        return True
    try:
        from .providers.codex_cli_provider import _auth_file_present

        if _auth_file_present():
            return True
    except Exception:  # pragma: no cover -- optional provider must not break probe
        pass
    azure_table = providers.get("azure") if isinstance(providers, dict) else None
    if not azure_provider_configuration_missing(azure_table):
        return True
    for provider, pcfg in providers.items():
        if provider == "azure":
            continue
        if not isinstance(pcfg, dict):
            continue
        if str(pcfg.get("api_key", "")).strip() or str(pcfg.get("base_url", "")).strip():
            return True
        # Bedrock signing with AWS IAM credentials carries no key at all: the
        # explicit auth_mode is the configuration.
        if provider == "bedrock" and str(pcfg.get("auth_mode", "")).strip().lower() == "iam":
            return True
        # Vertex AI signs in with Google Application Default Credentials: the
        # configured project is the configuration (no key exists).
        if provider == "vertex" and str(pcfg.get("project_id", "")).strip():
            return True
    return False


def get_budget_overrides() -> dict:
    return load_config().get("budget", {})


def get_deferred_tools(*, config: dict | None = None, default: bool = True) -> bool:
    """Resolve the one tool-discovery policy, including its older config name.

    An explicit environment true/false wins. The current capabilities key then
    wins over the legacy tools key; saving the current key can therefore turn
    off an inherited legacy choice. Standalone registries retain their older
    absent-setting default by passing ``default=False``.
    """
    environment = env_flag("MAVERICK_DEFERRED_TOOLS")
    if environment is not None:
        return environment
    cfg = load_config() if config is None else config
    capabilities = cfg.get("capabilities", {})
    if isinstance(capabilities, dict) and "deferred_tools" in capabilities:
        return _strict_config_bool(capabilities, "deferred_tools", default, invalid=True)
    legacy = cfg.get("tools", {})
    if isinstance(legacy, dict) and "deferred_loading" in legacy:
        return _strict_config_bool(legacy, "deferred_loading", default, invalid=True)
    return bool(default)


def get_capabilities() -> dict:
    """Return the [capabilities] section (computer_use / browser / web_search /
    mobile_tools / ros / code_exec / deferred_tools). These gate the optional
    high-impact tools in ``tools.base_registry``; all default off except
    ``deferred_tools``, which defaults on."""
    current = load_config()
    cfg = current.get("capabilities", {}) or {}
    return {
        "computer_use": coerce_bool(cfg.get("computer_use"), False),
        "browser": coerce_bool(cfg.get("browser"), False),
        "web_search": coerce_bool(cfg.get("web_search"), False),
        "mobile_tools": coerce_bool(cfg.get("mobile_tools"), False),
        "ros": coerce_bool(cfg.get("ros"), False),
        # Programmatic tool calling: a sandboxed Python script that orchestrates
        # declared tool calls (also enableable via MAVERICK_CODE_EXEC).
        "code_exec": coerce_bool(cfg.get("code_exec"), False),
        # Deferred connector loading (default on); agent.py reads it from this
        # dict, so without it here the documented knob could never turn it off.
        "deferred_tools": get_deferred_tools(config=current),
    }


TOOL_EXPOSURE_MODES = ("core", "full")


def get_tool_exposure() -> dict:
    """Return ``[tools] exposure`` and ``core_extra``.

    ``exposure`` is how much of the tool catalog every model turn describes up
    front: ``"core"`` (default) shows a short role-aware set (plus a selected
    pack's ``allow_tools``) and lets the model look the rest up with
    ``find_tools``; ``"full"`` offers every tool except the SaaS-connector long
    tail up to the model's tool ceiling (overflow stays discoverable).
    ``core_extra`` pins extra tool names into
    the visible set. ``MAVERICK_TOOL_EXPOSURE`` overrides ``exposure``. An
    unknown mode or a malformed list falls back to the lean default.
    """
    cfg = load_config().get("tools", {}) or {}
    mode = os.environ.get("MAVERICK_TOOL_EXPOSURE", "").strip().lower() or str(
        cfg.get("exposure", "core") or "core").strip().lower()
    if mode not in TOOL_EXPOSURE_MODES:
        mode = "core"
    raw = cfg.get("core_extra", [])
    extra = [str(t).strip() for t in raw if isinstance(t, str) and str(t).strip()] \
        if isinstance(raw, list) else []
    return {"exposure": mode, "core_extra": extra}


def signing_identity_transition_enabled() -> bool:
    """Whole-installation trust admission requires a healthy global opt-in."""
    try:
        features = load_global_config().get("features") or {}
        return (not config_source_errors(include_tenant=False) and isinstance(features, dict)
                and features.get("signing_identity_transition") is True)
    except Exception:
        return False


def get_features() -> dict:
    """Return the [features] section. These toggle agent-facing behaviors that
    are otherwise always on:

    - ``skills``      inject distilled/installed skills into agent prompts.
                      The MAVERICK_USE_SKILLS env var, when set, overrides this.
    - ``world_model`` inject persisted world-model facts (cross-run memory)
                      into the orchestrator brief. Off = run without prior
                      stored facts; the per-run goal/event/checkpoint store
                      (world.db) still functions regardless.
    - ``streaming``   stream live progress to the terminal during `maverick
                      start`. The MAVERICK_NO_PROGRESS env var / non-TTY output
                      still suppress it.
    - ``pack_editing`` allow editing/overriding domain packs (agents) from the
                      dashboard editor. Off = the editor is read-only and the
                      mutating REST endpoints return 403, so an operator can
                      lock the agent roster in a governed deployment. Writing
                      override TOML on the host is unaffected.
    - ``role_editing`` allow editing the core agent roles (orchestrator, coder,
                      ...) from the dashboard -- a per-tenant system-prompt
                      addendum plus model/effort overrides per role (which win
                      over the global [models]/[effort] config). Off = the roles
                      editor is read-only and its mutating endpoints 403.
    - ``scheduling`` allow arming recurring schedules (cron) from the dashboard
                      workflow builder -- each fire enqueues a ``start_goal`` job
                      run by ``maverick worker``. Off = the schedule endpoints
                      return 403 and the UI hides; the ``maverick schedule`` CLI
                      on the host is unaffected.
    - ``triggers`` allow binding a saved template to an inbound webhook (POST
                      /webhook/run) so an external event runs it as a goal. The
                      inbound route is HMAC-signed exactly like /webhook/start
                      and fails closed without a [webhooks] secret. Off = the
                      /api/v1/triggers editor and the /webhook/run route 404/403
                      and the builder panel hides.

    Draft recovery, record search, Action Center, guided onboarding and workflow
    readiness default on. Workspace recovery, project reviews and outcome
    measurement and employee companions require explicit opt-in. The older
    switches default on. Employee companions expose the enrolled person's task
    status, private companion history controls and optional administrator-permitted
    AI drafts through the existing writer role. Drafts may use eligible retained
    history and currently permitted own-task titles/status; they do not enable
    model tools, task actions, connected sources or learned memory.
    """
    cfg = load_config().get("features", {}) or {}
    return {
        "skills": coerce_bool(cfg.get("skills"), True),
        "world_model": coerce_bool(cfg.get("world_model"), True),
        "streaming": coerce_bool(cfg.get("streaming"), True),
        "pack_editing": coerce_bool(cfg.get("pack_editing"), True),
        "role_editing": coerce_bool(cfg.get("role_editing"), True),
        "draft_recovery": cfg.get("draft_recovery", True) is True,
        "personal_preferences": cfg.get("personal_preferences", True) is True,
        "configuration_profiles": cfg.get("configuration_profiles", True) is True,
        "employee_task_diagnostics": cfg.get("employee_task_diagnostics", True) is True,
        "employee_activation": cfg.get("employee_activation", True) is True,
        "support_center": cfg.get("support_center", True) is True,
        "record_search": cfg.get("record_search", True) is True,
        "workspace_recovery": cfg.get("workspace_recovery", False) is True,
        "signing_identity_transition": signing_identity_transition_enabled(),
        "action_center": cfg.get("action_center", True) is True,
        "guided_onboarding": cfg.get("guided_onboarding", True) is True,
        "workflow_readiness": cfg.get("workflow_readiness", True) is True,
        "project_reviews": cfg.get("project_reviews", False) is True,
        "deliverable_bundles": cfg.get("deliverable_bundles", False) is True,
        "project_workspaces": cfg.get("project_workspaces", False) is True,
        "task_handoffs": cfg.get("task_handoffs", False) is True,
        "human_conversation_handoffs": cfg.get("human_conversation_handoffs", False) is True,
        "outcome_measurement": cfg.get("outcome_measurement", False) is True,
        "commitment_viability": cfg.get("commitment_viability", False) is True,
        "commitment_capability_learning": cfg.get("commitment_capability_learning", False) is True,
        "semantic_rule_reuse": cfg.get("semantic_rule_reuse", False) is True,
        "procedure_interactions": cfg.get("procedure_interactions", False) is True,
        "operational_competence_acquisition": cfg.get("operational_competence_acquisition", False) is True,
        "request_program": cfg.get("request_program", False) is True,
        "commitment_economic_alternatives": cfg.get("commitment_economic_alternatives", False) is True,
        "workflow_step_checks": cfg.get("workflow_step_checks", False) is True,
        "applicability_regions": cfg.get("applicability_regions", False) is True,
        "governed_rule_evolution": cfg.get("governed_rule_evolution", False) is True,
        "recovery_visibility": cfg.get("recovery_visibility", False) is True,
        "private_task_computation": cfg.get("private_task_computation", False) is True,
        "portable_competence": cfg.get("portable_competence", False) is True,
        "work_restructuring": cfg.get("work_restructuring", False) is True,
        "shared_decision_evidence": cfg.get("shared_decision_evidence", False) is True,
        "employee_companions": (
            not config_source_errors() and cfg.get("employee_companions", False) is True
        ),
        "employee_content_access_requests": (
            not config_source_errors() and cfg.get("employee_content_access_requests", False) is True
        ),
        "permission_access_requests": (
            not config_source_errors() and cfg.get("permission_access_requests", False) is True
        ),
        "employee_departures": (
            not config_source_errors() and cfg.get("employee_departures", False) is True
        ),
        "personal_data_controls": (
            not config_source_errors() and cfg.get("personal_data_controls", False) is True
        ),
        "copilot_operations": (not config_source_errors() and cfg.get("copilot_operations", False) is True),
        "scheduling": coerce_bool(cfg.get("scheduling"), True),
        "triggers": coerce_bool(cfg.get("triggers"), True),
    }


def get_chat_message_actions() -> dict:
    """Conversation alternatives respect both workspace and organization controls."""
    workspace = load_config().get("chat_message_actions", {})
    organization = load_global_config().get("chat_message_actions", {})
    return {"enabled": (
        not config_source_errors(include_tenant=True)
        and isinstance(workspace, dict) and isinstance(organization, dict)
        and workspace.get("enabled", True) is True
        and organization.get("enabled", True) is True
    )}


def get_first_outcome() -> dict:
    """Return the ``[first_outcome]`` section written by setup: which
    department's sample first task the user picked and whether its sample
    workspace was created. Absent = nothing picked yet."""
    cfg = load_config().get("first_outcome", {}) or {}
    department = cfg.get("department")
    return {
        "department": str(department) if department else None,
        "sample_workspace_created": cfg.get("sample_workspace_created", False) is True,
    }


def get_safety() -> dict:
    """Return safety section with sensible defaults filled in."""
    cfg = load_config().get("safety", {})
    profile = str(cfg.get("profile", "balanced")).strip().lower()
    default_threshold = {"strict": "medium", "permissive": "critical"}.get(profile, "high")
    return {
        "profile": cfg.get("profile", "balanced"),
        "block_threshold": cfg.get("block_threshold", default_threshold),
        "scan_input": cfg.get("scan_input", True),
        "scan_tool_calls": cfg.get("scan_tool_calls", True),
        "scan_output": cfg.get("scan_output", True),
        # Operator-defined policy rules consumed by Shield.from_config().
        "constitution": cfg.get("constitution", []),
        # Agent compartments: a swarm-shared threat ledger so one agent's
        # blocked threat immunizes the rest for the run. Off by default.
        "compartments": cfg.get("compartments", False),
        # Who may clear a latched Rung-2 sector seal: "human" | "orchestrator"
        # | "both". Default human-only (safest for a security boundary).
        "compartment_unseal": cfg.get("compartment_unseal", "human"),
    }


# RFC 8176 authentication-method values that mean a second factor was used,
# plus "fido" (Okta/Auth0 emit it for WebAuthn). "pwd", "pin", "kba", "user"
# and the plain biometric hints are single factors and deliberately absent;
# an administrator extends this list in [auth.mfa] amr_values.
DEFAULT_MFA_AMR_VALUES: tuple[str, ...] = (
    "mfa", "mca", "otp", "hwk", "swk", "fido", "pop", "sms", "tel", "sc",
)
# SAML AuthnContextClassRef values that mean a second factor was used.
DEFAULT_MFA_SAML_CONTEXTS: tuple[str, ...] = (
    "http://schemas.microsoft.com/claims/multipleauthn",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI",
    "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard",
    "urn:okta:loa:2fa:any",
)
DEFAULT_STEP_UP_MINUTES = 15


def _str_list(value: object, default: tuple[str, ...]) -> list[str]:
    if isinstance(value, str):
        value = [part for part in value.split(",")]
    if not isinstance(value, (list, tuple)):
        return list(default)
    return [str(v).strip() for v in value if str(v).strip()]


def get_auth_mfa() -> dict:
    """``[auth.mfa]``: require a second factor at sign-in, and step-up.

    Off by default. ``require`` (``MAVERICK_MFA_REQUIRE``) accepts an OIDC
    session only when the ID token's ``amr`` names one of ``amr_values`` or
    its ``acr`` is in ``acr_values``, and a SAML session only when the
    assertion's authentication context is in ``saml_authn_contexts``.
    ``acr_values`` is also sent on the authorization request.
    ``step_up_minutes`` (``MAVERICK_MFA_STEP_UP_MINUTES``) is how recent that
    second factor must be for a sensitive action while ``require`` is on.
    A workspace's own config.toml overlays these keys for its members.
    """
    cfg = (load_config().get("auth") or {}).get("mfa") or {}
    if not isinstance(cfg, dict):
        cfg = {}
    require = env_flag("MAVERICK_MFA_REQUIRE")
    if require is None:
        # A present non-bool is uncertainty about a security policy: on.
        require = _strict_config_bool(cfg, "require", False, invalid=True)
    minutes_raw: object = os.environ.get("MAVERICK_MFA_STEP_UP_MINUTES") or cfg.get(
        "step_up_minutes", DEFAULT_STEP_UP_MINUTES)
    try:
        minutes = int(float(str(minutes_raw)))
    except (TypeError, ValueError, OverflowError):  # OverflowError: ``inf`` / ``1e999``
        # An unusable window is invalid like any other: the documented default
        # applies. Raising here would read as "policy unreadable" downstream and
        # reject every named sign-in as missing a second factor.
        minutes = DEFAULT_STEP_UP_MINUTES
    if isinstance(minutes_raw, bool) or minutes < 1:
        minutes = DEFAULT_STEP_UP_MINUTES
    return {
        "require": bool(require),
        "step_up_minutes": minutes,
        "amr_values": _str_list(cfg.get("amr_values"), DEFAULT_MFA_AMR_VALUES),
        "acr_values": _str_list(cfg.get("acr_values"), ()),
        "saml_authn_contexts": _str_list(
            cfg.get("saml_authn_contexts"), DEFAULT_MFA_SAML_CONTEXTS),
    }


LOCAL_OWNER_TOTP_MODES: tuple[str, ...] = ("optional", "required", "off")


def _unrecognised_local_owner_totp(value: object) -> None:
    """Log that a mode was read as optional. A short plain word is named; anything else is not written out."""
    shown = f'"{value}"' if isinstance(value, str) and re.fullmatch(r"[a-z]{1,20}", value) else "a value"
    logging.getLogger(__name__).warning(
        "[auth.local_owner] totp is %s, which is not one of optional, required or off; "
        "reading it as optional. Fix the setting.", shown)


def get_auth_local_owner_totp() -> str:
    """``[auth.local_owner] totp``: the owner's authenticator app at local sign-in.

    ``"optional"`` (the default): the owner may turn it on; nothing changes until
    they do. ``"required"``: the owner must set it up right after the next
    password sign-in, before anything else. ``"off"``: the option is hidden.
    An unreadable or unrecognised value is read as ``"optional"``, and a
    warning says so (``maverick config-lint`` reports it too).

    This never turns off a second factor the owner already has: an enrolled
    owner is asked for a code whatever this says.
    """
    try:
        table = (load_global_config().get("auth") or {}).get("local_owner") or {}
    except Exception:
        return "optional"
    if not isinstance(table, dict):
        logging.getLogger(__name__).warning(
            "[auth.local_owner] is not a table; reading the owner's authenticator app setting as optional.")
        return "optional"
    value = table.get("totp", "optional")
    if isinstance(value, str) and value.strip().lower() in LOCAL_OWNER_TOTP_MODES:
        return value.strip().lower()
    _unrecognised_local_owner_totp(value)
    return "optional"


def get_ip_allowlist() -> dict:
    """``[auth.ip_allowlist]``: network addresses allowed to use the dashboard.

    ``cidrs`` (``MAVERICK_IP_ALLOWLIST``, comma-separated) is the installation
    list, checked before sign-in; ``workspace_cidrs`` is read after a
    workspace is chosen, so a workspace's own config.toml can narrow it for
    its members. An empty list allows every address. Unparsable entries are
    kept here as text; the dashboard's checker rejects them, never skips them.
    A value of the wrong type raises ``ValueError``: the dashboard treats an
    unreadable allowlist as allowing only the computer Lightwork runs on.
    """
    cfg = (load_config().get("auth") or {}).get("ip_allowlist")
    if cfg is None:
        cfg = {}
    if not isinstance(cfg, dict):
        raise ValueError("auth.ip_allowlist must be a table with cidrs and workspace_cidrs")

    def entries(key: str) -> list[str]:
        # An empty list allows every address, so a value of the wrong type is an
        # unreadable policy (callers fail closed), never an empty one.
        value = cfg.get(key)
        if value is not None and not isinstance(value, (str, list, tuple)):
            raise ValueError(f"auth.ip_allowlist.{key} must be a list of addresses or ranges")
        return _str_list(value, ())

    env = os.environ.get("MAVERICK_IP_ALLOWLIST")
    cidrs = _str_list(env, ()) if env is not None and env.strip() else entries("cidrs")
    if env is not None and env.strip() and not cidrs:
        # "," lists nothing; an empty list would allow every address.
        raise ValueError("MAVERICK_IP_ALLOWLIST lists no addresses or ranges")
    return {
        "cidrs": cidrs,
        "workspace_cidrs": entries("workspace_cidrs"),
    }


def get_auth_sessions() -> dict:
    """Installation-wide browser limits and ended-session retention."""
    if config_source_errors(include_tenant=False):
        raise ValueError("Sign-in settings cannot be read.")
    loaded = load_global_config()
    if config_source_errors(include_tenant=False):  # the load itself may have found it
        raise ValueError("Sign-in settings cannot be read.")
    authentication = loaded.get("auth", {})
    if not isinstance(authentication, dict):
        raise ValueError("Sign-in settings must contain named choices.")
    cfg = authentication.get("sessions", {})
    if not isinstance(cfg, dict):
        raise ValueError("Sign-in settings must contain named choices.")
    raw = cfg.get("retention_days", 30)
    try:
        days = int(raw) if not isinstance(raw, bool) else 30
    except (TypeError, ValueError, OverflowError):
        days = 30
    limits = {}
    for name, maximum in (("company_hours", 168), ("idle_minutes", 1440)):
        value = cfg.get(name, 0)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            raise ValueError(f"auth.sessions.{name} must be an integer from zero to {maximum}")
        limits[name] = value
    return {"retention_days": max(1, min(days, 3650)), **limits}


def get_skills() -> dict:
    """Return the ``[skills]`` section with signing defaults filled in.

    ``trusted_pubkeys`` is a list of hex-encoded Ed25519 publisher keys; a
    signed skill is only accepted if its ``pubkey`` is in this list (when
    the list is non-empty). ``require_signed`` rejects unsigned skills.
    Catalog skills and templates always require a trusted publisher signature;
    ``require_signed_catalog`` reports that effective policy for compatibility.
    It cannot be disabled through configuration or environment variables.
    """
    cfg = load_config().get("skills", {})
    pubkeys = cfg.get("trusted_pubkeys", [])
    return {
        "trusted_pubkeys": [str(k) for k in pubkeys] if isinstance(pubkeys, list) else [],
        "require_signed": (cfg.get("require_signed") is not None
            and coerce_bool(cfg.get("require_signed"), True)),  # an unrecognized value keeps the check on
        "require_signed_catalog": True,
        # Recall the shipped first-party skills library at runtime (opt-out).
        "builtin": coerce_bool(cfg.get("builtin"), True),
        # Relevance GATES on skill recall. Precision >> recall for agent memory:
        # weakly-relevant retrieved context regresses the agent (hard negatives
        # flip answers -- GSM-DC/GSM-IC; large/noisy memory degrades -- Lifelong-
        # AgentBench). The embedding path keeps a skill only above this cosine;
        # the lexical fallback keeps one only at/above this RAW score (a real
        # two-word or phrase match), so noise is never injected -> warm is never
        # worse than cold.
        "embed_threshold": float(cfg.get("embed_threshold", 0.35)),
        "lexical_min_relevance": float(cfg.get("lexical_min_relevance", 4.0)),
    }


def get_document_tools() -> dict:
    """Explicit opt-ins for macro-preserving edits and offline native engines."""
    cfg = load_config().get("documents", {})
    if not isinstance(cfg, dict):
        cfg = {}
    image = cfg.get("engine_image", "lightwork-documents:local")
    if not isinstance(image, str) or not image or image.startswith("-") or any(c.isspace() for c in image):
        raise ValueError("documents.engine_image must be a single container image reference")
    language = cfg.get("ocr_language", "eng")
    if not isinstance(language, str) or not re.fullmatch(r"[A-Za-z0-9_]+(?:\+[A-Za-z0-9_]+)*", language):
        raise ValueError("documents.ocr_language must name installed Tesseract language packs")
    def bounded(key, default, low, high):
        value = cfg.get(key, default)
        if type(value) is not int or not low <= value <= high:
            raise ValueError(f"documents.{key} must be an integer between {low} and {high}")
        return value
    return {
        "macro_cell_edits": _strict_config_bool(cfg, "macro_cell_edits", False),
        "native_recalculation": _strict_config_bool(cfg, "native_recalculation", False),
        "pdf_ocr": _strict_config_bool(cfg, "pdf_ocr", False),
        "engine_image": image,
        "ocr_language": language,
        "ocr_max_pages": bounded("ocr_max_pages", 20, 1, 100),
        "timeout": bounded("timeout", 120, 10, 600),
    }


def get_sandbox() -> dict:
    cfg = load_config().get("sandbox", {})
    return {
        "backend": "kubernetes" if os.environ.get("MAVERICK_DEPLOYMENT_ISOLATION") == "kubernetes" else cfg.get("backend", "local"),
        "workdir": cfg.get("workdir", os.environ.get("MAVERICK_WORKDIR") or "~/maverick-workspace"),
        "timeout": cfg.get("timeout", 60),
    }


def get_knowledge() -> dict:
    """Return the ``[knowledge]`` section (per-domain vector RAG).

    Off by default; the agent kernel never requires the maverick-knowledge
    package. ``embedder`` selects hosted/local/deterministic; ``store`` selects
    sqlite/pgvector for ingestion, or qdrant for existing-corpus reads/erasure.
    Provider details (model/base_url/dim/path/url) are read by
    maverick_knowledge.build_embedder / build_store.
    """
    cfg = load_config().get("knowledge", {}) or {}
    return {
        "enable": coerce_bool(cfg.get("enable"), False),
        "embedder": cfg.get("embedder", "hosted"),
        "store": cfg.get("store", "sqlite"),
        "model": cfg.get("model", "voyage-3"),
        "revision": cfg.get("revision"),
        "base_url": cfg.get("base_url", "https://api.voyageai.com/v1"),
        "dim": int(cfg.get("dim", 1024)),
        "path": cfg.get("path", ""),
        "url": cfg.get("url", ""),
        # DSN for the pgvector scale backend (falls back to env in build_store).
        "dsn": cfg.get("dsn", ""),
        # Key for the hosted indexing service (build_embedder falls back to
        # MAVERICK_EMBED_API_KEY); without it here the documented setting was lost.
        "api_key": cfg.get("api_key", ""),
        # Never reuse the embedding provider's key for the vector store.
        "store_api_key": cfg.get("store_api_key", ""),
    }


class KnowledgeSourcesConfigError(ValueError):
    """An invalid [knowledge_sources] limit, named without its configured value."""


def get_knowledge_sources() -> dict:
    """Return the ``[knowledge_sources]`` bounds for saved company folders and spaces.

    ``max_items`` (default 64, 1-1000) bounds the direct items one refresh reads,
    ``max_pages`` (default 16, 1-200) the provider listing pages read to find them,
    ``max_download_mib`` (default 4, 1-32) one downloaded document and
    ``max_text_kib`` (default 256, 1-8192) the extracted text one refresh keeps,
    and ``max_refresh_minutes`` (default 5, 1-60) the wall-clock time one refresh may run.
    ``permission_filter`` (default "off") set to "by_email" reads each item's sharing
    permissions at refresh and shows an item only to a signed-in person whose verified
    email, or whose email domain, the item is shared with, or to anyone when it is shared
    by link. The verified email is an OIDC ``email`` claim the provider marks
    ``email_verified``; SAML sign-ins have none, so they see no items. Group grants are
    not expanded, so group-only items are withheld.
    The defaults are the historical bounds. A malformed value raises instead of
    falling back, so a reviewed bound never changes silently.
    """
    cfg = load_config().get("knowledge_sources", {})
    if not isinstance(cfg, dict):
        raise KnowledgeSourcesConfigError("knowledge_sources must be a table of whole-number limits")

    def bounded(key: str, default: int, low: int, high: int) -> int:
        value = cfg.get(key, default)
        if type(value) is not int or not low <= value <= high:
            raise KnowledgeSourcesConfigError(
                f"knowledge_sources.{key} must be a whole number from {low} to {high}"
            )
        return value

    mode = cfg.get("permission_filter", "off")
    if mode not in ("off", "by_email"):
        raise KnowledgeSourcesConfigError('knowledge_sources.permission_filter must be "off" or "by_email"')
    return {
        "permission_filter": mode,
        "max_items": bounded("max_items", 64, 1, 1000),
        "max_pages": bounded("max_pages", 16, 1, 200),
        "max_download_mib": bounded("max_download_mib", 4, 1, 32),
        "max_text_kib": bounded("max_text_kib", 256, 1, 8192),
        "max_refresh_minutes": bounded("max_refresh_minutes", 5, 1, 60),
    }


def get_automation_import() -> dict:
    """Return the ``[automation_import]`` section with defaults filled in.

    Importing clients' existing automations (n8n/Make/Workato/Power Automate/
    UiPath definitions, plus connect-and-trigger for Zapier/Notion) is OFF by
    default: it reaches out to third-party platforms and writes user templates,
    so the operator opts in. ``create_schedules`` lets a recovered cron trigger
    auto-create a Lightwork schedule; off by default so an import never starts
    spending on a recurring run without an explicit second step.
    Env override: ``MAVERICK_AUTOMATION_IMPORT``.
    """
    cfg = load_config().get("automation_import", {})
    return {
        "enable": _strict_config_bool(cfg, "enable", BOOLEAN_SETTINGS["automation_import.enable"].default),
        "create_schedules": _strict_config_bool(cfg, "create_schedules", BOOLEAN_SETTINGS["automation_import.create_schedules"].default),
    }


_EKKO_DEFAULT_BLOCKED_APPS = (
    "email",
    "outlook",
    "gmail",
    "chat",
    "teams",
    "slack",
    "crm",
    "salesforce",
    "erp",
    "sap",
    "database",
)


def get_ekko() -> dict:
    """Return the client-controlled ``[ekko]`` work-discovery policy.

    Ekko observes *application metadata*, not screen, clipboard, keystroke, or
    document content.  It is deliberately OFF until a client enrolls a device,
    and it does not inherit the default-on governed-learning posture.  An empty
    ``allowed_apps`` list is deny-all: the deployment must authorize apps
    before a device can enroll. ``blocked_apps`` always wins.

    ``MAVERICK_EKKO`` is the only environment override.  It controls only the
    master switch; an invalid value fails closed instead of falling through to
    a potentially-enabled config file. Provider egress is reserved and forced
    off because this release has no reviewed network path for Ekko data.
    """
    cfg = load_config().get("ekko", {}) or {}
    if not isinstance(cfg, dict):
        cfg = {}

    def _bounded_int(key: str, default: int, low: int, high: int) -> int:
        try:
            raw = cfg.get(key, default)
            # Do not silently treat TOML booleans as integers.
            value = default if isinstance(raw, bool) else int(raw)
        except (TypeError, ValueError, OverflowError):
            value = default
        return max(low, min(high, value))

    def _app_list(key: str, default: tuple[str, ...] = ()) -> list[str]:
        from .work_discovery import KNOWN_APPS

        raw = cfg.get(key, list(default))
        if not isinstance(raw, (list, tuple)):
            return list(default)
        result: list[str] = []
        seen: set[str] = set()
        invalid = False
        for item in raw[:128]:
            if not isinstance(item, str):
                invalid = True
                continue
            name = item.strip().casefold()
            if (
                not name
                or len(name) > 128
                or any(ord(char) < 32 or ord(char) == 127 for char in name)
                or name not in KNOWN_APPS
            ):
                invalid = True
                continue
            if name not in seen:
                seen.add(name)
                result.append(name)
        # A misspelled sensitive-app blocklist must not silently erase the
        # defense-in-depth defaults. The caller also unions this result with
        # the immutable sensitive-app floor, including for an explicit [].
        if key == "blocked_apps" and raw and invalid:
            return list(default)
        return result

    retention_days = _bounded_int("retention_days", 14, 2, 30)
    min_distinct_days = min(
        retention_days,
        _bounded_int("min_distinct_days", 2, 2, 30),
    )
    capture_level = cfg.get("capture_level", "application_metadata")
    if capture_level not in {"application_metadata", "guided"}:
        capture_level = "application_metadata"

    enabled = _strict_config_bool(cfg, "enable", False)
    if "MAVERICK_EKKO" in os.environ:
        # Invalid values are not "unset": fail closed even if config says on.
        enabled = env_flag("MAVERICK_EKKO") is True

    configured_blocks = _app_list("blocked_apps", _EKKO_DEFAULT_BLOCKED_APPS)
    blocked_apps = list(dict.fromkeys(
        (*_EKKO_DEFAULT_BLOCKED_APPS, *configured_blocks)
    ))
    blocked = set(blocked_apps)
    allowed_apps = [
        name for name in _app_list("allowed_apps") if name not in blocked
    ]
    return {
        "enable": enabled,
        "planning_enabled": _strict_config_bool(cfg, "planning_enabled", False),
        "build_enabled": _strict_config_bool(cfg, "build_enabled", False),
        "retention_days": retention_days,
        "enrollment_days": _bounded_int("enrollment_days", 30, 1, 90),
        "min_occurrences": _bounded_int("min_occurrences", 3, 2, 100),
        "min_distinct_days": min_distinct_days,
        "poll_interval_seconds": _bounded_int(
            "poll_interval_seconds", 5, 1, 300,
        ),
        "capture_level": capture_level,
        "allowed_apps": allowed_apps,
        "blocked_apps": blocked_apps,
        # Reserved for a future separately-audited summary path. The current
        # local discovery implementation has no provider path, so config may
        # not arm one pre-emptively.
        "provider_egress": False,
    }


def get_ekko_policy(*, allowed_apps: list[str] | tuple[str, ...] | None = None):
    """Build Ekko's canonical :class:`CapturePolicy` under the admin ceiling.

    ``[ekko].allowed_apps`` is the deployment-wide ceiling. Enrollment may
    narrow it, never widen it; omitting ``allowed_apps`` selects the whole
    configured ceiling. Unknown canonical IDs are rejected so CLI, dashboard,
    and daemon compute the exact same policy fingerprint.
    """
    from .work_discovery import (
        ACTION_KINDS,
        APPLICATION_METADATA_ACTIONS,
        APPLICATION_METADATA_OBJECT_TYPES,
        GUIDED_OBJECT_KINDS,
        KNOWN_APPS,
        CapturePolicy,
    )

    cfg = get_ekko()
    ceiling = frozenset(cfg["allowed_apps"])
    if allowed_apps is None:
        selected = ceiling
    else:
        normalized = frozenset(str(app).strip().casefold() for app in allowed_apps)
        unknown = normalized - KNOWN_APPS
        if unknown:
            raise ValueError(
                "unknown canonical application IDs: " + ", ".join(sorted(unknown))
            )
        outside = normalized - ceiling
        if outside:
            raise ValueError(
                "applications exceed [ekko].allowed_apps ceiling: "
                + ", ".join(sorted(outside))
            )
        selected = normalized
    policy = CapturePolicy(
        enabled=cfg["enable"],
        capture_level=cfg["capture_level"],
        allowed_apps=selected,
        blocked_apps=frozenset(cfg["blocked_apps"]),
        allowed_actions=(
            ACTION_KINDS
            if cfg["capture_level"] == "guided"
            else APPLICATION_METADATA_ACTIONS
        ),
        allowed_object_types=(
            GUIDED_OBJECT_KINDS
            if cfg["capture_level"] == "guided"
            else APPLICATION_METADATA_OBJECT_TYPES
        ),
        retention_days=cfg["retention_days"],
        min_occurrences=cfg["min_occurrences"],
        min_distinct_days=cfg["min_distinct_days"],
        poll_interval_seconds=cfg["poll_interval_seconds"],
        provider_egress=False,
    )
    policy.require_valid(require_enabled=True)
    return policy


def validate_ekko_policy_ceiling(policy) -> None:
    """Fail closed when an enrolled policy no longer fits current config.

    App selection may be a strict subset. Every other capture/retention field
    and the sensitive-app blocklist must still match the current admin policy;
    config changes therefore require an explicit re-enrollment.
    """
    from .work_discovery import CapturePolicy

    if not isinstance(policy, CapturePolicy):
        raise TypeError("policy must be a CapturePolicy")
    ceiling = get_ekko_policy()
    if not policy.allowed_apps <= ceiling.allowed_apps:
        raise ValueError("enrolled application scope exceeds the current config ceiling")
    comparable = (
        "enabled",
        "capture_level",
        "blocked_apps",
        "allowed_actions",
        "allowed_object_types",
        "retention_days",
        "min_occurrences",
        "min_distinct_days",
        "poll_interval_seconds",
        "provider_egress",
    )
    if any(getattr(policy, name) != getattr(ceiling, name) for name in comparable):
        raise ValueError("Ekko policy config changed; re-enrollment is required")


def get_governed_connectors() -> dict:
    """Return the ``[governed_connectors]`` section with defaults filled in.

    Every compatible connector write tool is always routed through a governed
    Action (simulate -> approve -> commit -> lineage) instead of a bare
    confirm-gated tool call; configuration cannot remove that boundary (see
    :func:`maverick.governed_tools.governance_enabled`). ``enable`` (OFF by
    default in the standard profile) only registers the reference REST
    connectors named in ``connectors`` (see
    :data:`maverick.governed_rest.GOVERNED_REST_FACTORIES`); enterprise mode
    registers them regardless. Env override for ``enable``:
    ``MAVERICK_GOVERNED_CONNECTORS`` (standard mode only).
    """
    cfg = load_config().get("governed_connectors", {}) or {}
    raw = cfg.get("connectors", [])
    if isinstance(raw, str):
        names = [s.strip() for s in raw.split(",") if s.strip()]
    elif isinstance(raw, (list, tuple)):
        names = [str(s).strip() for s in raw if str(s).strip()]
    else:
        names = []
    env_restore = os.environ.get("MAVERICK_GOVERNED_RESTORE_POINTS")
    restore_points = (
        env_restore.strip().lower() in ("1", "true", "yes", "on")
        if env_restore is not None
        else coerce_bool(cfg.get("restore_points"), True)
    )
    return {
        "enable": coerce_bool(cfg.get("enable"), False),
        "connectors": names,
        # Standing approver of record for governed connector writes in the live
        # tool path (the agent can't self-approve). Env: MAVERICK_GOVERNED_APPROVER.
        "approver": str(cfg.get("approver", "")).strip(),
        # Let maverick.connector_previews.plan_write issue ONE read-only GET to
        # capture prior state before an in-place update, so the write earns a
        # real undo. Without it every update is irreversible and routes to a
        # human -- correct, but the autonomy dial never earns anything. Turn it
        # off for a write-only service account. Env:
        # MAVERICK_GOVERNED_RESTORE_POINTS.
        "restore_points": restore_points,
    }


def get_self_learning(*, config: dict[str, Any] | None = None) -> dict:
    """Return the ``[self_learning]`` section with defaults filled in.

    Governed capability learning is on by default. Catalog-skill preflight,
    pack provisioning and local lexical distillation are safe defaults;
    generating executable tools and starting third-party MCP processes remain
    separate, explicit authority decisions.

    Back-compat: a config that still carries the retired ``add_mcp_servers``
    key is tolerated (it is simply ignored): agent-driven MCP acquisition is
    not supported, so the knob does nothing.

    ``config`` lets a caller reuse an already-loaded config snapshot; see
    :func:`get_calibration` for the same pattern.
    """
    cfg = (load_config() if config is None else config).get("self_learning", {})
    try:
        max_acq = int(cfg.get("max_acquisitions", 5))
    except (TypeError, ValueError, OverflowError):
        max_acq = 5
    return {
        "enable": _strict_config_bool(
            cfg, "enable", governed_learning_default()),
        "preflight": _strict_config_bool(cfg, "preflight", True),
        # High-authority booleans are intentionally strict: a string such as
        # ``"false"`` is truthy in Python and must never arm executable-code
        # generation through a malformed overlay.
        "create_tools": cfg.get("create_tools") is True,
        # The agent factory equips a freshly approved pack with the catalog
        # skills + synthesized tools its workflow needs (maverick.provision).
        # On by default once self-learning is accepted; still bounded by
        # ``max_acquisitions`` and the per-tool consent gate.
        "provision_packs": coerce_bool(cfg.get("provision_packs"), True),
        # Agent-proposed MCP-server acquisition is the highest-trust knob:
        # even gated behind catalog-pinning + operator consent it can start
        # a third-party subprocess, so it ships OFF independently of the
        # self-learning master switch. Env override:
        # MAVERICK_ALLOW_MCP_ACQUISITION.
        "allow_mcp_acquisition": cfg.get("allow_mcp_acquisition") is True,
        # Extra learning-only model calls may select a different configured
        # provider/role and can expose task or child-result text. Keep that
        # egress a separate explicit authority even though the local learning
        # engines themselves default on.
        "allow_provider_egress": cfg.get("allow_provider_egress") is True,
        "distill_local": _strict_config_bool(cfg, "distill_local", True),
        # A model writes a recallable skill straight from each finished run.
        # Run text is untrusted, so this stays a strict, default-off opt-in
        # (MAVERICK_AUTO_DISTILL, when set, decides instead).
        "auto_distill": cfg.get("auto_distill") is True,
        "max_acquisitions": max(1, max_acq),
    }


def get_self_harness() -> dict:
    """Return the ``[self_harness]`` section with defaults filled in.

    ON by default under the conservative ``risk_limited`` profile. The loop
    still cannot promote without held-out evidence, calibration and its
    promotion-controller gates:

    - ``risk_limited``: select the conservative unattended-promotion profile
      (held-out/effect/confidence floors, sealed best-of-3 selection, replicated
      judge votes, durable holdout accounting, operational caps, recent judge
      calibration, metamorphic checks, and canary staging). Safety-critical
      constituent settings may tighten but cannot weaken this contract.
    - ``min_support``: recurring failures before a weakness is mined (>=1).
    - ``require_held_out`` / ``min_held_out`` / ``min_delta``: the validation
      evidence floors (off / 0 / 0.0 on their own; the default ``risk_limited``
      profile raises them, to on / 8 / 0.02 on a pristine install) -- never promote on only the mined
      examples, an unseen-sample floor, an effect-size floor.
    - ``semantic_mining``: cluster failure diagnoses by embedding similarity
      when embeddings are available (default off -> deterministic Jaccard).
    - ``candidates_per_signature``: best-of-N proposing -- generate this many
      candidate lines per weakness and promote the strongest validated one
      (>=1; default 1 = single candidate, only matters with a stochastic
      proposer, a deterministic one collapses to 1).
    - ``mine_bucket_by``: extra dimensions to bucket mining by, beyond the
      always-on (model, failure_class). Allowlisted (``domain``) so a weakness
      can be mined -- and its guidance scoped -- per department; default empty
      (model-wide). Unknown dims are dropped.
    - ``retire_after_days``: auto-retire lines not active within this many days
      (0 = never; only acted on when a driver/CLI runs retirement).
    """
    cfg = load_config().get("self_harness", {})
    # A deployment with no harness policy gets the new conservative default-on
    # profile. An existing partial [self_harness] table keeps its historical
    # constituent defaults unless the operator (or dashboard/installer)
    # explicitly selects risk_limited/auto_run. This prevents an upgrade from
    # silently rewriting evaluation thresholds or starting scheduled spend.
    pristine_default = not cfg
    # One explicit profile for unattended, research-grade promotion.  It changes
    # defaults plus non-weakenable safety floors/ceilings. Constituent knobs may
    # still be tightened deliberately.
    risk_limited = _strict_config_bool(
        cfg, "risk_limited", pristine_default, invalid=True)

    def _num(key, default, cast):
        try:
            value = cast(cfg.get(key, default))
            if isinstance(value, float) and not math.isfinite(value):
                return cast(default)
            return value
        except (OverflowError, TypeError, ValueError):
            return default

    def _holdout_image() -> str | None:
        if "holdout_container_image" not in cfg:
            return None
        value = cfg.get("holdout_container_image")
        if (type(value) is not str
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", value.strip())):
            raise ValueError(
                "holdout_container_image must be an immutable local sha256 image ID"
            )
        return value.strip()

    raw_by_class = cfg.get("min_support_by_class", {})
    by_class = {}
    if isinstance(raw_by_class, dict):
        for k, v in raw_by_class.items():
            try:
                by_class[str(k)] = max(3 if risk_limited else 1, int(v))
            except (OverflowError, TypeError, ValueError):
                continue

    # Mining bucket dimensions: keep only allowlisted reflexion dims
    # (mirrors self_harness._BUCKET_DIMS) and de-dupe, preserving order.
    _allowed_dims = ("domain", "tool", "role")
    raw_dims = cfg.get("mine_bucket_by", [])
    if isinstance(raw_dims, str):
        raw_dims = [raw_dims]
    elif not isinstance(raw_dims, (list, tuple)):
        raw_dims = []
    bucket_by = tuple(dict.fromkeys(
        d for d in (raw_dims or []) if isinstance(d, str) and d in _allowed_dims))

    def _factor(key, default=None):
        v = cfg.get(key)
        try:
            value = float(v) if v is not None else default
            # NaN defeats every ``> cap`` comparison and infinity silently
            # disables a cap. In the risk profile, an invalid override must
            # fall back to the conservative default rather than turn it off.
            return value if value is None or math.isfinite(value) else default
        except (OverflowError, TypeError, ValueError):
            return default

    def _risk_cap(key: str, ceiling: float) -> float | None:
        value = _factor(key, ceiling if risk_limited else None)
        if not risk_limited:
            return value
        if value is None or value <= 0.0:
            return ceiling
        return min(value, ceiling)

    raw_family_alpha = _num("holdout_family_alpha", 0.05, float)
    raw_query_alpha = _num(
        "holdout_query_alpha", 0.025 if risk_limited else 0.05, float)
    raw_max_queries = max(1, _num(
        "holdout_max_queries", 2 if risk_limited else 1, int))
    if risk_limited:
        family_alpha = (
            min(raw_family_alpha, 0.05)
            if 1e-12 <= raw_family_alpha < 1.0 else 0.05)
        holdout_max_queries = min(raw_max_queries, 2)
        query_alpha = (
            min(raw_query_alpha, 0.025)
            if 1e-12 <= raw_query_alpha < 1.0 else 0.025)
        # A stricter family budget must also tighten each allocated query so the
        # fixed policy remains internally valid instead of failing at runtime.
        query_alpha = min(
            query_alpha, family_alpha / holdout_max_queries)
    else:
        family_alpha = raw_family_alpha
        query_alpha = raw_query_alpha
        holdout_max_queries = raw_max_queries

    raw_calibration_age = max(
        0.0, _num(
            "calibration_max_age_hours", 24.0 if risk_limited else 0.0, float))
    calibration_max_age = (
        min(raw_calibration_age, 24.0)
        if risk_limited and raw_calibration_age > 0.0
        else (24.0 if risk_limited else raw_calibration_age)
    )
    raw_eval_budget_value = cfg.get(
        "eval_budget_dollars", 5.0 if risk_limited else None)
    eval_budget_valid = True
    if "eval_budget_dollars" in cfg:
        eval_budget_valid = (
            isinstance(raw_eval_budget_value, (int, float))
            and not isinstance(raw_eval_budget_value, bool)
            and math.isfinite(float(raw_eval_budget_value))
        )
    raw_eval_budget = (
        float(raw_eval_budget_value)
        if eval_budget_valid and raw_eval_budget_value is not None
        else (5.0 if risk_limited else None)
    )
    if risk_limited:
        eval_budget = (
            min(raw_eval_budget, 5.0)
            if raw_eval_budget is not None and raw_eval_budget > 0.0 else 5.0)
    else:
        eval_budget = (
            raw_eval_budget
            if raw_eval_budget is not None and raw_eval_budget > 0.0 else None)

    return {
        "enable": _strict_config_bool(
            cfg, "enable", governed_learning_default()),
        "risk_limited": risk_limited,
        # Run the governed cycle for every configured role model as part of
        # `maverick dream` (the nightly learning beat), so the harness operates
        # itself without a second cron entry. A pristine deployment defaults on;
        # an existing partial section retains its historical off default.
        "auto_run": (
            _strict_config_bool(cfg, "auto_run", pristine_default)
            and eval_budget_valid
        ),
        "min_support": (
            max(3, _num("min_support", 3, int)) if risk_limited
            else max(1, _num("min_support", 3, int))),
        "min_support_by_class": by_class,
        "require_held_out": (
            True if risk_limited else _strict_config_bool(
                cfg, "require_held_out", False)),
        "min_held_out": (
            max(8, _num("min_held_out", 8, int)) if risk_limited
            else max(0, _num("min_held_out", 0, int))),
        "min_delta": (
            max(0.02, _num("min_delta", 0.02, float)) if risk_limited
            else max(0.0, _num("min_delta", 0.0, float))),
        "confidence_z": (
            max(1.96, _num("confidence_z", 1.96, float)) if risk_limited
            else max(0.0, _num("confidence_z", 0.0, float))),
        "max_cost_factor": _risk_cap("max_cost_factor", 1.25),
        "max_latency_factor": _risk_cap("max_latency_factor", 1.25),
        "max_tool_calls_factor": _risk_cap("max_tool_calls_factor", 1.10),
        "semantic_mining": _strict_config_bool(cfg, "semantic_mining", False),
        # Keep the risk study's search multiplicity fixed. More proposals are
        # not a tighter control: they increase selection pressure and compute.
        "candidates_per_signature": (
            3 if risk_limited else max(
                1, _num("candidates_per_signature", 1, int))),
        # A risk-limited pass may activate at most one isolated winner.  A
        # second candidate must be evaluated in a new cycle against a freshly
        # snapshotted deployed prompt, rather than being composed onto a stale
        # baseline that never included the first winner.
        "max_promotions_per_cycle": (
            1 if risk_limited else max(
                0, _num("max_promotions_per_cycle", 0, int))),
        # Cross-validate a candidate across this many holdout-fold rotations
        # before promoting (1 = single fixed split, the historical behavior; >1
        # requires the lift to generalize across every rotation).
        "holdout_rotations": (
            1 if risk_limited else max(
                1, _num("holdout_rotations", 1, int))),
        # A sealed holdout is a consumable statistical resource. Risk-limited
        # evaluation requires an explicitly provisioned durable query ledger;
        # runtime code never creates it because deletion must not reset budget.
        "holdout_ledger": (str(cfg["holdout_ledger"])
                           if cfg.get("holdout_ledger") else None),
        # Local container evaluation is development evidence unless a separate
        # evaluator custodian is installed.  Keep this as a strict boolean so a
        # malformed dashboard/config value cannot accidentally disable a
        # deployment's fail-closed confirmatory posture.
        "holdout_require_independent_custody": _strict_config_bool(
            cfg,
            "holdout_require_independent_custody",
            False,
            invalid=True,
        ),
        # An operator may pin the already-reviewed local evaluator image in
        # config instead of relying on the environment-only override. A present
        # malformed value must not silently select an environment/default image.
        "holdout_container_image": _holdout_image(),
        "holdout_family_alpha": family_alpha,
        "holdout_query_alpha": query_alpha,
        "holdout_max_queries": holdout_max_queries,
        # Self-consistency for the LLM-as-judge in the auto-built evaluator: ask
        # the judge this many times (diverse framings) and take the majority vote
        # (1 = single call, the historical behavior).
        "judge_samples": (
            max(3, _num("judge_samples", 3, int)) if risk_limited
            else max(1, _num("judge_samples", 1, int))),
        # Feed the auto-built LLM judge's verdicts into the calibration
        # interlock: each corpus-labeled verdict is recorded as a
        # (vote-share confidence, agrees-with-label) sample, so
        # calibration.learning_frozen can detect THIS loop's judge drifting.
        # Default off -- telemetry only, never load-bearing.
        "calibrate_judge": (
            True if risk_limited else _strict_config_bool(
                cfg, "calibrate_judge", False)),
        # A conservative run requires a recent adequate calibration receipt;
        # collecting judge telemetry alone is not an interlock.
        "calibration_max_age_hours": calibration_max_age,
        # Nightly cross-model transfer: after the dream-beat cycles, try each
        # fleet model's graduated lines on the rest of the fleet (gated,
        # canaried, budget-capped; the tried-memory keeps steady-state spend
        # near zero). Default off -- transfer runs only via the CLI.
        "transfer_auto": _strict_config_bool(cfg, "transfer_auto", False),
        # Where the learning stores (addenda, provenance, transfer memory)
        # live: "files" = per-host JSON under ~/.maverick (default); "world" =
        # tables in the shared world database, so a fleet spanning hosts
        # learns as one. Unknown values mean "files".
        "store": (lambda v: v if v in ("files", "world") else "files")(
            str(cfg.get("store", "files")).strip().lower()),
        # Corpus bootstrapping from hindsight pairs (a failed goal whose wording
        # later ran to done): "propose" stages candidates for operator review
        # (`self-harness corpus review`); "auto" merges them straight into the
        # live corpus. Anything else = "off" -- the corpus stays hand-authored.
        "corpus_harvest": (lambda v: v if v in ("propose", "auto") else "off")(
            str(cfg.get("corpus_harvest", "off")).strip().lower()),
        # Relapse recency guard: re-probate (back to canary) a graduated line
        # whose recent-outcomes window carries at least this failing share
        # (0 = off, the default; clamped to (0, 1]). relapse_min_outcomes is
        # the evidence floor before the window is judged at all.
        "relapse_failure_share": (lambda v: v if v is not None and 0 < v <= 1 else 0.0)(
            _factor("relapse_failure_share")),
        "relapse_min_outcomes": max(1, _num("relapse_min_outcomes", 5, int)),
        # Metamorphic validation on the auto path: paraphrase the held-out cases
        # (summarizer-role model) and require the candidate's lift to survive
        # the rewording -- rejects lines overfit to exact phrasing. Default off;
        # tolerance allows a small slip on the paraphrases.
        "metamorphic": (
            True if risk_limited else _strict_config_bool(
                cfg, "metamorphic", False)),
        "metamorphic_tolerance": (
            0.0 if risk_limited
            else max(0.0, _num("metamorphic_tolerance", 0.0, float))),
        "mine_bucket_by": bucket_by,
        # Stage every promotion as a CANARY (on probation): still recalled, but
        # graduated to permanent / demoted from real run outcomes by the cycle's
        # canary review, rather than permanent on arrival (default off -- a
        # promotion lands permanent, the historical behavior).
        "promote_as_canary": (
            True if risk_limited else _strict_config_bool(
                cfg, "promote_as_canary", False)),
        "retire_after_days": max(0.0, _num("retire_after_days", 0.0, float)),
        # Re-measure each existing line's live A/B lift each cycle and DEMOTE
        # dead weight (default off -- a general corpus can under-credit a line
        # that helps only its own failure class, so this is operator opt-in).
        "efficacy_review": _strict_config_bool(cfg, "efficacy_review", False),
        # Path to an eval corpus ({model|domain: [{goal, expected}]}) JSON. When
        # set, the driver auto-builds the LIVE A/B (model generates, verifier
        # judges) so a scheduled pass can actually PROMOTE; unset -> dry pass.
        "eval_corpus": (str(cfg["eval_corpus"]) if cfg.get("eval_corpus") else None),
        # Spend ceiling (in dollars) for ONE auto-evaluated cycle's LLM calls
        # (runner + judge share the pot; kernel rule 3). None/<=0 = uncapped,
        # the historical behavior. An exhausted budget fails the evaluation
        # CLOSED -- candidates are rejected, never promoted on partial scores.
        "eval_budget_dollars": eval_budget,
        "eval_budget_valid": eval_budget_valid,
    }


def get_autonomy() -> dict:
    """Return the ``[autonomy]`` section with defaults filled in.

    The autonomy gate (``maverick.autonomy``) is OFF by default so the kernel
    runs unchanged out of the box. When enabled, the sub-toggles default ON:
    ``escalate_verification`` runs the cross-family ensemble verifier on FINAL
    answers when the swarm disagreed (Loop 1); ``tighten_on_low_trust`` drops
    the effective risk ceiling for high-risk tools when run trust is low (Loop
    2). ``disagreement_high`` is the swarm-entropy threshold above which both
    fire; ``min_confidence`` is the verifier-confidence floor below which the
    ceiling tightens. Both are clamped to [0, 1].
    """
    cfg = load_config().get("autonomy", {})

    def _clamp01(key: str, default: float) -> float:
        try:
            v = float(cfg.get(key, default))
        except (TypeError, ValueError, OverflowError):
            v = default
        return max(0.0, min(1.0, v))

    return {
        "enable": (cfg.get("enable") is not None
                   and coerce_bool(cfg.get("enable"), True)),  # protective: unrecognized keeps it on
        # Plan confirmation: show the plan and wait for a person before a task's first
        # action with an outside effect. Independent of ``enable``; off by default.
        "confirm_plan": cfg.get("confirm_plan", False) is True,
        "min_confidence": _clamp01("min_confidence", 0.5),
        "disagreement_high": _clamp01("disagreement_high", 0.5),
        "escalate_verification": coerce_bool(cfg.get("escalate_verification"), True),
        "tighten_on_low_trust": coerce_bool(cfg.get("tighten_on_low_trust"), True),
        # Independent axis (resolved without ``enable``): assume-and-proceed
        # instead of blocking on ``ask_user`` when no human can answer
        # (headless / batch / benchmark runs). Default off.
        "headless_assume": coerce_bool(cfg.get("headless_assume"), False),
    }


def get_workforce() -> dict:
    """Return the ``[workforce]`` section: per-agent autonomy levels.

    This is the client's control over how much rope each hired agent gets (see
    :mod:`maverick.agent_autonomy`). OFF by default (kernel rule 1): when
    ``levels`` is not enabled, every agent resolves to ``suggest`` (draft, a
    human commits) -- the platform's historical behavior.

    ``[workforce]
       levels = true
       [[workforce.agents]]
       name = "fin_ap_clerk"
       default = "auto"          # this hire acts autonomously by default
       high = "human"            # ...but high-risk actions stay human-in-loop
       onboarding = false        # graduated past the supervised phase``

    Returns ``{"levels": bool, "data_grounding": bool,
    "auto_graduate": bool, "agents": {name: {default, low, medium, high,
    onboarding}}}``. Agent overrides contain only keys an operator set (the
    resolver layers them over each pack's declared ``[autonomy]`` default).
    Authority-widening booleans are strict: a present non-boolean value never
    enables autonomy, connector grants, automatic graduation, or removal of the
    onboarding clamp. Never raises.
    """
    cfg = load_config().get("workforce", {})
    if not isinstance(cfg, dict):
        return {
            "levels": False,
            "data_grounding": False,
            "auto_graduate": False,
            "agents": {},
        }
    agents: dict[str, dict] = {}
    raw = cfg.get("agents")
    if isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            if not name:
                continue
            override = {
                k: entry[k] for k in ("default", "low", "medium", "high", "onboarding")
                if k in entry
            }
            if "onboarding" in override and not isinstance(
                override["onboarding"], bool
            ):
                # Malformed supervision policy tightens to onboarding. In
                # particular, ``0`` must not silently graduate an agent.
                override["onboarding"] = True
            agents[name] = override
    return {
        "levels": _strict_config_bool(cfg, "levels", False),
        "data_grounding": _strict_config_bool(
            cfg, "data_grounding", True, invalid=False),
        "auto_graduate": _strict_config_bool(
            cfg, "auto_graduate", False, invalid=False),
        "agents": agents,
    }


def get_calibration(*, config: dict[str, Any] | None = None) -> dict:
    """Return the ``[calibration]`` section with defaults filled in.

    The verifier-calibration interlock (``maverick.calibration``) is OFF by
    default: ``enforce`` must be true for a failed assessment to freeze
    self-improvement (trajectory donation). ``min_samples`` is the minimum
    labeled samples before an assessment is trusted; ``min_discrimination`` is
    the floor on mean(confidence|correct) - mean(confidence|incorrect) below
    which the verifier is judged to have drifted.

    ``config`` lets a caller that already loaded config once (e.g. a gate
    checking two sections back to back) reuse that snapshot instead of
    calling :func:`load_config` again, the same pattern :func:`get_role_model`
    already uses.
    """
    cfg = (load_config() if config is None else config).get("calibration", {})

    def _int(key: str, default: int) -> int:
        try:
            return max(1, int(cfg.get(key, default)))
        except (TypeError, ValueError, OverflowError):
            return default

    try:
        min_disc = float(cfg.get("min_discrimination", 0.15))
    except (TypeError, ValueError, OverflowError):
        min_disc = 0.15
    try:
        min_res = float(cfg.get("min_resistance", 0.0))
    except (TypeError, ValueError, OverflowError):
        min_res = 0.0
    return {
        "enforce": (cfg.get("enforce") is not None
            and coerce_bool(cfg.get("enforce"), True)),  # an unrecognized value keeps the check on
        "min_samples": _int("min_samples", 20),
        "min_discrimination": max(0.0, min(1.0, min_disc)),
        "collect_from_coding": coerce_bool(cfg.get("collect_from_coding"), False),
        # Reward-laundering interlock floor: freeze learning when the verifier's
        # edge on adversarial probes falls below this fraction of its edge on
        # natural traffic. 0.0 = advisory (measured, never freezes).
        "min_resistance": max(0.0, min(1.0, min_res)),
    }


def get_credit() -> dict:
    """Return the ``[credit]`` section (counterfactual swarm credit assignment).

    ON by default but budget-limited: CSCA costs N+1 verifier passes per swarm. ``max_children``
    caps the swarm size it will attribute (skip larger ones); ``min_budget_
    headroom`` is the fraction of budget that must remain before it runs.
    """
    cfg = load_config().get("credit", {})
    try:
        maxc = max(2, int(cfg.get("max_children", 6)))
    except (TypeError, ValueError, OverflowError):
        maxc = 6
    try:
        head = float(cfg.get("min_budget_headroom", 0.4))
    except (TypeError, ValueError, OverflowError):
        head = 0.4
    return {
        "enable": _strict_config_bool(
            cfg, "enable", governed_learning_default()),
        "max_children": maxc,
        "min_budget_headroom": max(0.0, min(1.0, head)),
    }


def get_adaptive_compute() -> dict:
    """Return the ``[adaptive_compute]`` section (SOTA: spend compute on
    uncertainty). OFF by default. ``low_uncertainty`` is the threshold below
    which fan-out width is scaled down; ``min_width`` is the floor."""
    cfg = load_config().get("adaptive_compute", {})
    try:
        low = float(cfg.get("low_uncertainty", 0.2))
    except (TypeError, ValueError, OverflowError):
        low = 0.2
    try:
        minw = max(1, int(cfg.get("min_width", 1)))
    except (TypeError, ValueError, OverflowError):
        minw = 1
    return {
        "enable": coerce_bool(cfg.get("enable"), False),
        "low_uncertainty": max(0.0, min(1.0, low)),
        "min_width": minw,
    }


def get_search() -> dict:
    """Return the ``[search]`` section (verifier-guided best-of-N generation).
    OFF by default. ``n`` is the number of candidate answers to sample."""
    cfg = load_config().get("search", {})
    try:
        n = max(1, int(cfg.get("n", 3)))
    except (TypeError, ValueError, OverflowError):
        n = 3
    return {"enable": coerce_bool(cfg.get("enable"), False), "n": n}


def get_skill_synthesis() -> dict:
    """Return the ``[skill_synthesis]`` section (test-time task-specific skills).
    ON by default; spend remains metered by the run budget."""
    cfg = load_config().get("skill_synthesis", {})
    return {"enable": _strict_config_bool(
        cfg, "enable", governed_learning_default())}


def get_my_work() -> dict:
    """Return the ``[my_work]`` section with defaults filled in.

    The personal "My work" page (``/me``) is always on. The daily summary it
    feeds is OFF by default (``digest_enable``): it sends messages to people
    on a timer, so the operator opts in. ``digest_hour`` is the default local
    hour (each person can change it on /me), ``digest_poll_seconds`` how often
    the scheduler looks for people whose summary is due, and
    ``monthly_spend_limit_dollars`` the per-person monthly spending figure the
    page compares against (0 = no limit shown). Env override:
    ``MAVERICK_DAILY_DIGEST``.
    """
    cfg = load_config().get("my_work", {})
    if not isinstance(cfg, dict):
        cfg = {}
    env = env_flag("MAVERICK_DAILY_DIGEST")
    enable = env if env is not None else _strict_config_bool(cfg, "digest_enable", False)

    def _number(key: str, default: float, *, low: float, high: float) -> float:
        raw = cfg.get(key, default)
        if isinstance(raw, bool) or not isinstance(raw, (int, float)):
            raise ValueError(f"[my_work] {key} must be a number")
        return float(min(high, max(low, raw)))

    return {
        "digest_enable": enable,
        "digest_hour": int(_number("digest_hour", 8, low=0, high=23)),
        "digest_poll_seconds": _number("digest_poll_seconds", 300, low=30, high=3600),
        "monthly_spend_limit_dollars": _number(
            "monthly_spend_limit_dollars", 0, low=0, high=1_000_000),
        "send_when_empty": _strict_config_bool(cfg, "send_when_empty", False),
    }


_SUPPORT_URL_RE = re.compile(r"https://[^\s\"'<>]{1,300}\Z")
_SUPPORT_EMAIL_RE = re.compile(r"[^@\s\"'<>,;]{1,64}@[^@\s\"'<>,;]{1,190}\.[A-Za-z]{2,24}\Z")


def get_support() -> dict:
    """Return the ``[support]`` section: where people go for help.

    ``status_page_url`` is a public service-status page linked from the Help
    menu (empty = no link). ``contact_email`` is the vendor or help-desk
    address a "Get help from a person" request is addressed to (empty = the
    request is for the workspace's administrators). Anything that is not a
    secure web address or a plain email address reads as empty, so a bad
    value hides the link rather than sending people somewhere unexpected.
    """
    cfg = load_config().get("support", {})
    if not isinstance(cfg, dict):
        cfg = {}
    url = str(cfg.get("status_page_url") or "").strip()
    email = str(cfg.get("contact_email") or "").strip()
    return {"status_page_url": url if _SUPPORT_URL_RE.fullmatch(url) else "",
            "contact_email": email if _SUPPORT_EMAIL_RE.fullmatch(email) else ""}


_CONTACT_CENTRE_PROVIDERS = ("off", "zendesk", "webhook")
_CONTACT_CENTRE_SUBDOMAIN_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
_CONTACT_CENTRE_EMAIL_RE = re.compile(r"[^@\s\"'<>,;]{1,64}@[^@\s\"'<>,;]{1,190}\.[A-Za-z]{2,24}")


def _https_or_empty(value: object) -> str:
    """An https address without credentials, or ``""``."""
    from urllib.parse import urlsplit
    text = str(value or "").strip()
    try:
        parts = urlsplit(text)
        _ = parts.port  # raises ValueError for an out-of-range port
    except ValueError:
        return ""
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password:
        return ""
    return text


def get_contact_centre() -> dict:
    """Return the ``[contact_centre]`` section: where a conversation goes when a person takes it over.

    ``provider`` is ``off`` (default: nothing is sent), ``zendesk`` or ``webhook``.
    An unknown provider reads as ``off``. The Zendesk subdomain must be a single
    host label; the email must look like an address; the webhook and dashboard
    addresses must be https without credentials. Anything else reads as empty so
    the setting is reported as incomplete rather than sent somewhere unexpected.
    Secrets (the Zendesk API token and webhook signing secret) are not returned
    here; :mod:`maverick.contact_centre` reads them from the environment or the
    sealed settings value.
    """
    cfg = load_config().get("contact_centre", {})
    if not isinstance(cfg, dict):
        cfg = {}
    provider = str(cfg.get("provider") or "off").strip().lower()
    if provider not in _CONTACT_CENTRE_PROVIDERS:
        provider = "off"
    subdomain = str(cfg.get("zendesk_subdomain") or "").strip()
    email = str(cfg.get("zendesk_email") or "").strip()
    raw_max = cfg.get("max_messages", 20)
    max_messages = raw_max if type(raw_max) is int and 1 <= raw_max <= 50 else 20
    return {
        "provider": provider,
        "zendesk_subdomain": subdomain if _CONTACT_CENTRE_SUBDOMAIN_RE.fullmatch(subdomain) else "",
        "zendesk_email": email if _CONTACT_CENTRE_EMAIL_RE.fullmatch(email) else "",
        "webhook_url": _https_or_empty(cfg.get("webhook_url")),
        "dashboard_url": _https_or_empty(cfg.get("dashboard_url")).rstrip("/"),
        "max_messages": max_messages,
    }


def get_fleet_memory() -> dict:
    """Return the ``[fleet_memory]`` section (agent-agnostic learning plane).
    OFF by default: exposing governed memory to third-party agents is an
    explicit trust decision."""
    cfg = load_config().get("fleet_memory", {})
    return {"enable": coerce_bool(cfg.get("enable"), False)}


def get_codebase() -> dict:
    """Return the ``[codebase]`` section (:mod:`maverick.codebase`).

    ``enable`` turns on the code vault and feature swarms (OFF by default: it
    stores a company's source). ``default_protect`` is the information-flow
    mode a newly registered repository enforces on every run over it:
    ``block`` (default), ``approve`` or ``audit``."""
    cfg = load_config().get("codebase", {})
    if not isinstance(cfg, dict):
        cfg = {}
    protect = str(cfg.get("default_protect", "block")).strip().lower()
    return {"enable": _strict_config_bool(cfg, "enable", False),
            "default_protect": protect if protect in ("audit", "approve", "block") else "block"}


def get_ifc() -> dict:
    """Return the ``[ifc]`` section: runtime information-flow control (:mod:`maverick.ifc`).

    ``mode``: ``off`` | ``audit`` (default: record labelled data reaching an
    external sink, allow it) | ``approve`` (a human approves each new
    sink/label pair through the consent path) | ``block``. ``scope``:
    ``context`` (default: an agent that has seen labelled data is labelled) or
    ``explicit`` (act only when the data appears literally in the call).
    ``allow_sinks``: external tools exempt from the check (e.g. ``web_search``).
    ``MAVERICK_IFC_MODE`` overrides ``mode``; a malformed override is ignored
    so it cannot replace a stricter configured mode, and a malformed
    configured ``mode`` falls back to the default."""
    cfg = load_config().get("ifc", {})
    if not isinstance(cfg, dict):
        cfg = {}
    modes = ("off", "audit", "approve", "block")
    mode = str(os.environ.get("MAVERICK_IFC_MODE") or "").strip().lower()
    if mode not in modes:  # an unset or mistyped override never replaces the configured mode
        mode = str(cfg.get("mode", "audit")).strip().lower()
    scope = str(cfg.get("scope", "context")).strip().lower()
    sinks = cfg.get("allow_sinks", [])
    return {
        "mode": mode if mode in modes else "audit",
        "scope": scope if scope in ("context", "explicit") else "context",
        "allow_sinks": sorted({str(t) for t in sinks}) if isinstance(sinks, list) else [],
    }


def get_swarm() -> dict:
    """Return the ``[swarm]`` section: how large one goal's swarm may grow.

    ``max_total_spawns`` bounds the agents a single goal may create (default
    64; ``MAVERICK_MAX_TOTAL_SPAWNS`` wins). ``max_concurrent_model_calls``
    bounds how many of the goal's agents are inside a model call at once
    (0 = unbounded, the historical behaviour); set it when raising the spawn
    cap so a large swarm queues for the provider instead of tripping its rate
    limits. The budget still caps total spend whatever the size.
    ``finding_post_max_chars`` is how much of a helper's final answer is
    posted to the shared board (default 1500, floor 200;
    ``MAVERICK_FINDING_POST_MAX_CHARS`` wins)."""
    cfg = load_config().get("swarm", {})
    if not isinstance(cfg, dict):
        cfg = {}

    def _int(key: str, default: int, floor: int) -> int:
        try:
            return max(floor, int(cfg.get(key, default)))
        except (TypeError, ValueError, OverflowError):
            return default

    return {"max_total_spawns": _int("max_total_spawns", 64, 1),
            "max_concurrent_model_calls": _int("max_concurrent_model_calls", 0, 0),
            "finding_post_max_chars": _int("finding_post_max_chars", 1500, 200)}


def get_immune() -> dict:
    """Return the ``[immune]`` section (:mod:`maverick.immune`).

    ``canaries`` lets operators seed known-flawed approvals into the real queue
    to measure whether reviewers catch them. OFF by default: it is an explicit
    decision to test your people. ``twin_record`` records every goal's tool
    results (sealed, tenant-scoped) so the goal can be replayed as a production
    twin (:mod:`maverick.immune.twin`); OFF by default because it retains tool
    output. A malformed value stays off."""
    cfg = load_config().get("immune", {})
    if not isinstance(cfg, dict):
        cfg = {}
    return {"canaries": _strict_config_bool(cfg, "canaries", False),
            "twin_record": _strict_config_bool(cfg, "twin_record", False)}


def get_commerce() -> dict:
    """Return the ``[commerce]`` section (shopper + merchant agent surface over
    the governed storefront/merchant backends, :mod:`maverick.commerce`).
    OFF by default: exposing cart-building and store-change proposals is an
    explicit opt-in, like ``[fleet_memory]``. Also honored via
    ``MAVERICK_COMMERCE=1``. The caps are read as numbers; a malformed or
    non-positive cap falls back to its (tighter) default rather than to "no
    cap"."""
    cfg = load_config().get("commerce", {})
    if not isinstance(cfg, dict):
        cfg = {}
    backend = cfg.get("backend", "demo")
    out: dict = {
        "enable": _strict_config_bool(cfg, "enable", False),
        "backend": backend.strip() if isinstance(backend, str) and backend.strip() else "demo",
    }
    for key, default, cast in (
        ("max_session_spend", 500.0, float),
        ("max_line_quantity", 10, int),
        ("max_cart_lines", 25, int),
    ):
        raw = cfg.get(key, default)
        try:
            value = cast(raw) if not isinstance(raw, bool) else default
        except (TypeError, ValueError, OverflowError):
            value = default
        out[key] = value if value > 0 and math.isfinite(value) else default
    return out


def get_billing_stripe() -> dict:
    """Return the ``[billing.stripe]`` section (platform billing collection via
    Stripe, :mod:`maverick.billing_stripe`).

    OFF by default: turning real charges on is an explicit operator decision,
    like ``[commerce]``. Also honored via ``MAVERICK_STRIPE_ENABLE=1``. The
    Stripe secret + webhook signing key are never returned here -- they come
    from ``MAVERICK_STRIPE_SECRET_KEY`` / ``MAVERICK_STRIPE_WEBHOOK_SECRET`` via
    the secret provider, else from the sealed values saved on the All settings
    page (read only by :mod:`maverick.billing_stripe`) -- so this returns only
    the enable flag, the metered-usage flag (default off: only the platform
    fee is billed), the currency, and the
    per-plan ``prices`` map of Stripe recurring price ids for the platform
    subscription fee."""
    billing = load_config().get("billing", {})
    if not isinstance(billing, dict):
        billing = {}
    cfg = billing.get("stripe", {})
    if not isinstance(cfg, dict):
        cfg = {}
    prices = cfg.get("prices", {})
    if not isinstance(prices, dict):
        prices = {}
    currency = cfg.get("currency", "usd")
    return {
        "enable": _strict_config_bool(cfg, "enable", False),
        # The metered-usage flag: when off (default) only the recurring
        # platform fee is billed; the metered model-usage line items are computed
        # but NOT pushed to Stripe. No markup is hardcoded here -- the rate is
        # whatever RateCard the operator supplies when generating the invoice.
        "bill_metered_usage": _strict_config_bool(cfg, "bill_metered_usage", False),
        "currency": (
            currency.strip().lower()
            if isinstance(currency, str) and currency.strip() else "usd"
        ),
        # plan id -> Stripe recurring price id (e.g. "pro" or "enterprise" ->
        # "price_...").
        "prices": {
            str(k): v.strip()
            for k, v in prices.items()
            if isinstance(v, str) and v.strip()
        },
    }


def get_external_agents() -> dict:
    """Return the ``[external_agents]`` section (bring-your-own-agent gateway:
    enrollment, run ingest onto the Operating Record, pre-action screening).
    OFF by default: admitting foreign runtimes is an explicit trust decision,
    made per-agent in the trust registry once the plane is on. Also honored
    via ``MAVERICK_EXTERNAL_AGENTS=1``."""
    cfg = load_config().get("external_agents", {})
    raw = cfg.get("connectors", [])
    if isinstance(raw, str):
        raw = raw.split(",")
    return {
        "enable": coerce_bool(cfg.get("enable"), False),
        # Signed-identity enforcement on the gateway: when on, an agent
        # enrolled with a strong credential (pinned Ed25519 pubkey or JWT
        # issuer) may no longer authenticate with its minted bearer alone —
        # it must present that credential. Agents holding only bearers are
        # unaffected. Strict bool; a malformed value engages the refusal
        # (fail closed — this is a tightening switch).
        "require_signed": _strict_config_bool(
            cfg, "require_signed", False, invalid=True),
        # Governed-REST connectors external agents may EXECUTE through (the
        # enforcement tier above screening). Empty = screen-only; naming one
        # here is the operator's explicit decision to let foreign agents act
        # through Lightwork's egress-guarded, receipted connector path.
        "connectors": [str(p).strip().lower() for p in raw if str(p).strip()],
        # Step-up re-auth on credential minting: when on, ``mint_token`` parks
        # a world approval (dual-control quorum at "high" risk) and refuses to
        # mint until a decision-maker approves; each approval mints exactly
        # one credential. Strict bool; a malformed value engages the gate
        # (fail closed — this is a tightening switch).
        "mint_approval": _strict_config_bool(
            cfg, "mint_approval", False, invalid=True),
    }


def _finite_or(value: float, default: float) -> float:
    """``value``, or ``default`` when it is infinite or NaN (TOML accepts ``inf``)."""
    return value if math.isfinite(value) else default


def get_repl() -> dict:
    """Return the ``[repl]`` section (governed code execution).

    A session kernel lets an agent write Python instead of composing fixed
    tool schemas — the Prime-Agent-style substrate — but every statement runs
    through ``sandbox.exec`` and lands a tamper-evident receipt, so the code
    IS the audited artifact. OFF by default: this is arbitrary code execution
    and admitting it is an explicit operator decision. Also honored via
    ``MAVERICK_REPL=1``."""
    import os
    cfg = load_config().get("repl", {})
    enable = _strict_config_bool(cfg, "enable", False, invalid=False)
    if str(os.environ.get("MAVERICK_REPL", "")).strip() == "1":
        enable = True
    return {
        "enable": enable,
        # Per-statement wall ceiling, output cap, and the size of the carried
        # namespace. All bounded: an unbounded kernel is a denial-of-service
        # surface and an unbounded transcript is an audit liability.
        "max_seconds": _finite_or(max(1.0, float(cfg.get("max_seconds", 30.0) or 30.0)), 30.0),
        "max_output_chars": max(
            256, int(cfg.get("max_output_chars", 8000) or 8000)),
        "max_state_bytes": max(
            1024, int(cfg.get("max_state_bytes", 262_144) or 262_144)),
        "max_statements": max(1, int(cfg.get("max_statements", 200) or 200)),
    }


def get_harness_refine() -> dict:
    """Return the ``[harness_refine]`` section (governed self-refinement).

    The agent may PROPOSE changes to its own operating instructions from an
    observed failure; applying one is snapshotted, audited, and reversible.
    OFF by default, and ``require_approval`` defaults ON so a proposal never
    self-applies — ungoverned self-modification is precisely what an audited
    deployment cannot run. Also honored via ``MAVERICK_HARNESS_REFINE=1``."""
    import os
    cfg = load_config().get("harness_refine", {})
    enable = _strict_config_bool(cfg, "enable", False, invalid=False)
    if str(os.environ.get("MAVERICK_HARNESS_REFINE", "")).strip() == "1":
        enable = True
    return {
        "enable": enable,
        # Fail CLOSED on a malformed value: a typo must never disarm the gate.
        "require_approval": _strict_config_bool(
            cfg, "require_approval", True, invalid=True),
        "max_pending": max(1, int(cfg.get("max_pending", 20) or 20)),
    }


def get_session_tree() -> dict:
    """Return the ``[session_tree]`` section (run forking + provenance).

    Forking a run at a decision point lets Oversight hold the counterfactual
    beside what actually happened. ON by default — it only records lineage
    between runs that already exist and never changes execution."""
    cfg = load_config().get("session_tree", {})
    return {
        "enable": _strict_config_bool(cfg, "enable", True, invalid=True),
        "max_depth": max(1, int(cfg.get("max_depth", 10) or 10)),
    }


def get_memory() -> dict:
    """Return the ``[memory]`` section. ``temporal`` keeps a bitemporal history
    of every fact value (validity windows) instead of overwriting, so the
    Operating Record can answer "what did we believe on date X, and why".
    OFF by default (one extra append per fact change); the live-value read path
    is unchanged when off. Also honored via ``MAVERICK_TEMPORAL_MEMORY=1``."""
    cfg = load_config().get("memory", {})
    return {"temporal": coerce_bool(cfg.get("temporal"), False)}


def get_memory_guard() -> dict:
    """Return the ``[memory_guard]`` section (OWASP ASI06 controls). OFF by
    default. When on, every memory write is screened for injection/poisoning and
    stamped with provenance + a trust tier, and memory below ``min_recall_trust``
    is filtered out of the agent's standing brief (trust-aware retrieval).
    ``min_recall_trust`` is a :class:`maverick.memory_guard.TrustTier` value
    (default 1 = drop only EXTERNAL/untrusted memory). Also honored via
    ``MAVERICK_MEMORY_GUARD=1``."""
    cfg = load_config().get("memory_guard", {})
    return {
        "enable": (cfg.get("enable") is not None
                   and coerce_bool(cfg.get("enable"), True)),  # protective: unrecognized keeps it on
        "min_recall_trust": int(cfg.get("min_recall_trust", 1)),
    }


def get_fairness_monitor() -> dict:
    """Return the ``[fairness_monitor]`` section (continuous group-fairness
    monitoring, ISO/IEC 42001 A.6.2.6). OFF by default: a deployment opts in by
    feeding decision outcomes to :class:`maverick.fairness_monitor.FairnessMonitor`.
    ``threshold`` is the four-fifths cutoff, ``window`` the rolling number of
    outcomes retained, ``min_samples`` the noise floor before evaluating, and
    ``drift_tolerance`` how far the minimum impact ratio may fall below baseline
    before a drift alert. Also honored via ``MAVERICK_FAIRNESS_MONITOR=1``."""
    cfg = load_config().get("fairness_monitor", {})
    enabled = coerce_bool(cfg.get("enable"), False)
    flag = env_flag("MAVERICK_FAIRNESS_MONITOR")
    if flag is not None:
        enabled = flag
    return {
        "enable": enabled,
        "threshold": float(cfg.get("threshold", 0.8)),
        "window": int(cfg.get("window", 1000)),
        "min_samples": int(cfg.get("min_samples", 30)),
        "drift_tolerance": float(cfg.get("drift_tolerance", 0.1)),
    }


def get_domains() -> dict:
    """Return the ``[domains]`` section with defaults filled in.

    ``discipline`` appends the per-suite operating-discipline block to every
    domain pack's persona at spawn (ON by default — it is pack content, not a
    new capability; see :mod:`maverick.domain_discipline`). ``memory`` injects
    the department's recalled lessons into a specialist's brief at spawn —
    only meaningful when reflexion/dreaming are themselves enabled.
    """
    cfg = load_config().get("domains", {})
    return {
        "discipline": coerce_bool(cfg.get("discipline"), True),
        "memory": coerce_bool(cfg.get("memory"), True),
    }


def get_experience() -> dict:
    """Return the ``[experience]`` section (outcome-guided orchestration).
    ON by default."""
    cfg = load_config().get("experience", {})
    return {"enable": _strict_config_bool(
        cfg, "enable", governed_learning_default())}


def get_tax() -> dict:
    """Return the ``[tax]`` section (signed tax-constants content channel).

    ``auto_update`` is ON by default but a no-op until the operator
    configures both ``update_url`` and ``trusted_constants_pubkeys`` —
    updates are fail-closed against those anchors (see
    :mod:`maverick.tax_constants`). ``check_hours`` throttles the network
    check."""
    cfg = load_config().get("tax", {})
    try:
        check_hours = max(1.0, float(cfg.get("check_hours", 20.0)))
    except (TypeError, ValueError, OverflowError):
        check_hours = 20.0
    keys = cfg.get("trusted_constants_pubkeys", [])
    if not isinstance(keys, list):
        keys = []
    return {
        "auto_update": coerce_bool(cfg.get("auto_update"), True),
        "update_url": str(cfg.get("update_url", "") or "").strip(),
        "check_hours": check_hours,
        "trusted_constants_pubkeys": [str(k).strip() for k in keys
                                      if str(k).strip()],
    }


def get_dreaming() -> dict:
    """Return the ``[dreaming]`` section (offline experience consolidation).

    ON by default. ``min_cluster`` is the evidence floor before a recurring
    pattern is consolidated (a one-off is noise); ``max_insights`` caps the
    persisted insight store; ``prune`` lets a dream cycle compact the
    reflexion log down to ``keep_reflexions`` deduplicated entries.
    """
    cfg = load_config().get("dreaming", {})

    def _int(key: str, default: int) -> int:
        try:
            return max(1, int(cfg.get(key, default)))
        except (TypeError, ValueError, OverflowError):
            return default

    def _ratio(key: str, default: float) -> float:
        try:
            return max(0.0, min(1.0, float(cfg.get(key, default))))
        except (TypeError, ValueError, OverflowError):
            return default

    def _nonneg_int(key: str, default: int) -> int:
        try:
            return max(0, int(cfg.get(key, default)))
        except (TypeError, ValueError, OverflowError):
            return default

    def _nonneg_float(key: str, default: float) -> float:
        try:
            return max(0.0, float(cfg.get(key, default)))
        except (TypeError, ValueError, OverflowError):
            return default

    return {
        "enable": _strict_config_bool(
            cfg, "enable", governed_learning_default()),
        "min_cluster": _int("min_cluster", 2),
        "max_insights": _int("max_insights", 100),
        "prune": coerce_bool(cfg.get("prune"), True),
        "keep_reflexions": _int("keep_reflexions", 500),
        # Shared promotion is disabled by default: department-scoped failures
        # must not be written into globally recallable insights.
        "promote_shared": coerce_bool(cfg.get("promote_shared"), False),
        # Mine verifier critiques out of donated trajectory records (empty
        # unless [telemetry] donate_trajectories has produced any).
        "mine_critiques": coerce_bool(cfg.get("mine_critiques"), True),
        # Insights unconfirmed for this many days retire; 0 = never expire.
        "insight_ttl_days": _nonneg_int("insight_ttl_days", 90),
        # Retire a failure insight once this many NEWER similar successes
        # contradict it ("we now reliably do X").
        "contradiction_successes": _int("contradiction_successes", 2),
        # Fact consolidation deletes operator data, so it remains a separate
        # opt-in inside default-on dreaming.
        "prune_facts": coerce_bool(cfg.get("prune_facts"), False),
        "facts_max_age_days": _nonneg_int("facts_max_age_days", 180),
        "facts_cap": _nonneg_int("facts_cap", 2000),
        # Distill explicit user-preference statements into per-user notes.
        # Verbatim cross-conversation preference persistence is a separate
        # privacy decision, not inherited from default-on consolidation.
        "user_notes": coerce_bool(cfg.get("user_notes"), False),
        # Quarantine this cycle's NEW skills while the continuously-tracked
        # benchmark suite is regressing (learning-side canary).
        "benchmark_gate": coerce_bool(cfg.get("benchmark_gate"), True),
        # Learning rollback: snapshot every learned store before a CLI dream
        # cycle mutates it, keeping the last N snapshots.
        "snapshots": coerce_bool(cfg.get("snapshots"), True),
        "snapshot_keep_last": _int("snapshot_keep_last", 5),
        # Dream-time rehearsal (maverick-evolve harness) is a separate trust
        # decision from consolidation: it spends real agent runs. Default off.
        "rehearse": coerce_bool(cfg.get("rehearse"), False),
        "max_rehearsals": _int("max_rehearsals", 3),
        # Forgetting loop: retire learned skills whose recall track record
        # decayed below the floor (after enough attempts to judge).
        "retire_skills": coerce_bool(cfg.get("retire_skills"), True),
        "retire_min_uses": _int("retire_min_uses", 5),
        "retire_below": _ratio("retire_below", 0.25),
        # LLM-in-the-loop consolidation: when on (and a provider/key is
        # configured), the cheap "summarizer" role rewrites each clustered
        # failure into a transferable lesson instead of the deterministic
        # template. Inputs AND the model's output are secret-redacted +
        # Shield-scanned, the call is budget-metered, and it FAILS OPEN to the
        # deterministic text. OFF by default -- the LLM-free path is the
        # injection-safe baseline. `llm_consolidation_budget` caps the spend
        # one dream cycle may use enriching insights.
        "llm_consolidation": coerce_bool(cfg.get("llm_consolidation"), False),
        "llm_consolidation_budget": _nonneg_float(
            "llm_consolidation_budget", 1.0
        ),
    }


def get_self_improvement() -> dict:
    """Return the ``[self_improvement]`` section (governed learning promotion).

    ON by default for governed prompt/policy learning. When ``enable`` is false,
    the Self-Improvement Controller never promotes a self-change. ``min_improvement``
    is the eval margin a candidate
    must beat its own baseline by before any rung is eligible; ``max_auto_rung``
    is the highest rung that may be promoted without a human (anything above it
    -- e.g. ``code``/``weights`` -- always requires explicit approval).
    """
    cfg = load_config().get("self_improvement", {})

    raw_margin = cfg.get("min_improvement", 0.0)
    margin_valid = (
        isinstance(raw_margin, (int, float))
        and not isinstance(raw_margin, bool)
        and math.isfinite(float(raw_margin))
        and 0.0 <= float(raw_margin) <= 1.0
    )
    # A negative sentinel is intentionally outside the controller's accepted
    # domain.  A present malformed policy must freeze promotion, never collapse
    # to the permissive zero-margin default used only when the key is absent.
    min_improvement = float(raw_margin) if margin_valid else -1.0

    def _ratio(key: str, default: float) -> float:
        try:
            return max(0.0, float(cfg.get(key, default)))
        except (TypeError, ValueError, OverflowError):
            return default

    raw_keys = cfg.get("approver_keys")
    keys_valid = (
        "approver_keys" not in cfg
        or (
            isinstance(raw_keys, list)
            and all(isinstance(key, str) for key in raw_keys)
        )
    )
    approver_keys = (
        [key.strip() for key in raw_keys if key.strip()]
        if keys_valid and isinstance(raw_keys, list) else [])
    raw_keys_dir = cfg.get("approver_keys_dir")
    keys_dir_valid = (
        "approver_keys_dir" not in cfg
        or raw_keys_dir is None
        or isinstance(raw_keys_dir, str)
    )
    require_signed_valid = (
        "require_signed_approval" not in cfg
        or isinstance(cfg.get("require_signed_approval"), bool)
    )

    return {
        "enable": _strict_config_bool(
            cfg, "enable", governed_learning_default()),
        "min_improvement": min_improvement,
        "promotion_policy_valid": margin_valid,
        "max_auto_rung": str(cfg.get("max_auto_rung", "policy")).strip().lower() or "policy",
        # Phase-0 capture fuels the default-on flywheel. Raw-text donation and
        # provider egress remain separate opt-ins.
        "capture": _strict_config_bool(cfg, "capture", True),
        "prm_guidance": _strict_config_bool(
            cfg, "prm_guidance", governed_learning_default()),
        # Counterfactual promotion: judge a self-change on its confounder-adjusted
        # CAUSAL effect (maverick.promotion_effect) rather than a correlational
        # baseline/candidate diff. On by default; set false to use the direct
        # baseline/candidate evidence path.
        "causal_promotion": _strict_config_bool(
            cfg, "causal_promotion", True, invalid=True),
        # Self-improving agent factory (maverick.factory_learning): mine recurring
        # pack-generation gaps into proposer corrections and promote them through
        # this same gate. Sub-toggle of the master switch -- on once
        # self-improvement is accepted; set false to keep the generator static.
        "factory_learning": _strict_config_bool(
            cfg, "factory_learning", True),
        # Evaluator co-evolution (maverick.evaluator_evolution): instead of only
        # FREEZING learning when the judge drifts, promote a better judge --
        # a challenger evaluator replaces the incumbent only when its agreement
        # with a fixed ground-truth ANCHOR (by the epsilon-best-belief lower bound)
        # beats it, on the dedicated ``evaluator`` rung. On by default; the
        # anchor is the guardrail (immutable, checksum-locked) so a weak anchor
        # cannot launder drift. ``evaluator_eps`` is the confidence level of the
        # lower bound (lower = more conservative). After arXiv 2606.26294.
        "evaluator_evolution": _strict_config_bool(
            cfg, "evaluator_evolution", True),
        "evaluator_eps": _ratio("evaluator_eps", 0.05),
        # Cryptographic approval of code/weights promotions
        # (maverick.approval_signing): trusted approver Ed25519 public keys (hex)
        # and an optional dir of raw ``*.pub`` files, plus a strict flag that
        # requires a signed approval even before keys are provisioned. Empty
        # (default) keeps the legacy self-settable boolean-approval path.
        "approver_keys": approver_keys,
        "approver_keys_dir": (
            raw_keys_dir.strip() or None
            if isinstance(raw_keys_dir, str) else None
        ),
        "approval_policy_valid": (
            keys_valid and keys_dir_valid and require_signed_valid
        ),
        "require_signed_approval": _strict_config_bool(
            cfg, "require_signed_approval", False, invalid=True),
    }


def get_reasoning_reward() -> dict:
    """Return the ``[reasoning_reward]`` section (structured, auditable rewards).

    ON by default: the verifier judges FINAL answers with the multi-faceted
    rubric reward (maverick.reasoning_reward, Agent-RRM) -- per-dimension scores
    with a safety veto, attached to the verdict for the learning audit -- and
    falls back to the scalar verdict for any non-rubric reply. Set
    ``enable = false`` (or MAVERICK_REASONING_REWARD=0) to force the scalar
    verifier."""
    cfg = load_config().get("reasoning_reward", {})
    return {
        "enable": _strict_config_bool(
            cfg, "enable", governed_learning_default()),
        # Sign each structured reward into the tamper-evident audit chain
        # (provable learning). ON by default; set false to suppress these audit
        # rows. See reasoning_reward.audit_rewards_enabled.
        "audit_rewards": _strict_config_bool(
            cfg, "audit_rewards", governed_learning_default()),
    }


def get_jit_rl() -> dict:
    """Return the ``[jit_rl]`` section (gradient-free test-time adaptation).

    ON by default, but a no-op with a cold store: it records verifier-guided
    best-of-N outcomes and factors learned advantage into candidate selection
    (maverick.jit_rl), reducing to the pure verifier choice until experience
    accumulates. ``k`` is the k-NN neighbourhood size and ``beta`` the steering
    gain; ``max_experiences`` bounds the (state, action, return) buffer. Defaults
    mirror ``jit_rl.DEFAULT_K`` / ``DEFAULT_BETA`` / ``DEFAULT_MAX_EXPERIENCES``
    (kept literal here to avoid a config->jit_rl import cycle). Set
    ``enable = false`` (or MAVERICK_JIT_RL=0) to disable."""
    cfg = load_config().get("jit_rl", {})

    def _int(key: str, default: int) -> int:
        try:
            return max(1, int(cfg.get(key, default)))
        except (TypeError, ValueError, OverflowError):
            return default

    try:
        beta = float(cfg.get("beta", 1.0))
    except (TypeError, ValueError, OverflowError):
        beta = 1.0
    return {
        "enable": _strict_config_bool(
            cfg, "enable", governed_learning_default()),
        "k": _int("k", 8),
        "beta": beta,
        "max_experiences": _int("max_experiences", 5000),
    }


def get_self_modify() -> dict:
    """Return the ``[self_modify]`` section (governed code self-modification).

    OFF by default AND inert until an editable allowlist is set: the engine
    (maverick.self_modify) refuses any patch outside ``editable_paths`` and every
    control-plane path unconditionally. ``editable_paths`` is a list of
    repo-relative fnmatch globs the agent MAY propose changes to; empty (the
    default) means nothing is editable."""
    cfg = load_global_config().get("self_modify", {})
    paths = cfg.get("editable_paths")
    editable = ([str(p).strip() for p in paths if str(p).strip()]
                if isinstance(paths, list) else [])
    return {"enable": cfg.get("enable") is True, "editable_paths": editable}


def get_adapter_rung() -> dict:
    """Return the ``[adapter_rung]`` section (governed in-tenant weights adaptation).

    OFF by default AND inert until ``base_model`` is set: the rung trains LoRA
    adapters on tenant-provenance data and promotes them through the existing
    ``weights`` rung (evidence + non-escalation + Ed25519 approval + rollback,
    maverick.adapter_rung). ``base_model`` is an operator-chosen local spec
    (e.g. ``ollama:<model-id>``; never hard-coded). Auto-serving of a promoted
    adapter is wired for the ``ollama``/``local`` providers (via the Ollama
    Modelfile ``ADAPTER`` directive); other providers promote and ledger
    normally but are served by operator wiring. For the ``dpo-lora`` trainer the
    provider prefix is stripped and the remaining id must resolve for
    ``transformers.from_pretrained`` (an HF id or local path) -- the Ollama
    serving tag and the HF training id are not always the same string, so pick a
    ``base_model`` valid for both, or a local path. ``allow_model_output`` opts
    in to training on frontier-model completions -- refused by default (the
    distillation-ToS guard); ``allow_synthetic`` likewise for generated data.
    ``trainer`` is ``stub`` (deterministic, proof/test path) or ``dpo-lora``
    (real QLoRA via the [training] extra)."""
    cfg = load_config().get("adapter_rung", {})
    return {
        "enable": _strict_config_bool(cfg, "enable", False),
        "base_model": (str(cfg.get("base_model", "")).strip() or None),
        "store_dir": (str(cfg.get("store_dir", "")).strip() or None),
        "trainer": (str(cfg.get("trainer", "")).strip() or "stub"),
        "allow_synthetic": _strict_config_bool(cfg, "allow_synthetic", False),
        "allow_model_output": _strict_config_bool(
            cfg, "allow_model_output", False),
    }


def get_model_improvement() -> dict:
    """Return fail-closed specialist-model improvement settings.

    This is the control plane for environment exports and training runs, not a
    runtime model selector. It is inert by default. Hosted execution requires a
    second opt-in; cross-tenant training is a reserved setting and the v1 data
    boundary still refuses it. Promotion requires a signed, digest-bound
    training receipt. Family floors cannot be configured below the shipped
    anti-leak minimum.
    """
    raw = load_config().get("model_improvement", {})
    cfg = raw if isinstance(raw, dict) else {}

    def _family_floor(key: str) -> int:
        value = cfg.get(key, 20)
        if not isinstance(value, int) or isinstance(value, bool):
            return 20
        return max(20, min(value, 1_000_000))

    return {
        "enable": _strict_config_bool(cfg, "enable", False),
        "allow_hosted": _strict_config_bool(cfg, "allow_hosted", False),
        "allow_cross_tenant": _strict_config_bool(
            cfg, "allow_cross_tenant", False,
        ),
        "require_signed_receipt": _strict_config_bool(
            cfg, "require_signed_receipt", True, invalid=True,
        ),
        "minimum_train_families": _family_floor("minimum_train_families"),
        "minimum_holdout_families": _family_floor("minimum_holdout_families"),
    }


class ModelImprovementConfigError(ValueError):
    """The active model-improvement policy cannot safely authorize mutation."""


_MODEL_IMPROVEMENT_BOOL_KEYS = frozenset({
    "enable",
    "allow_hosted",
    "allow_cross_tenant",
    "require_signed_receipt",
})
_MODEL_IMPROVEMENT_FAMILY_KEYS = frozenset({
    "minimum_train_families",
    "minimum_holdout_families",
})
_MODEL_IMPROVEMENT_KEYS = (
    _MODEL_IMPROVEMENT_BOOL_KEYS | _MODEL_IMPROVEMENT_FAMILY_KEYS
)
_MODEL_IMPROVEMENT_DEFAULTS: dict[str, bool | int] = {
    "enable": False,
    "allow_hosted": False,
    "allow_cross_tenant": False,
    "require_signed_receipt": True,
    "minimum_train_families": 20,
    "minimum_holdout_families": 20,
}


def _strict_model_improvement_section(
    snapshot: dict,
    *,
    source: str,
) -> dict[str, bool | int]:
    """Validate one unmerged policy source without silently using fallbacks."""
    if not isinstance(snapshot, dict):
        raise ModelImprovementConfigError(
            f"model-improvement policy source is invalid: {source} must be a table"
        )
    raw = snapshot.get("model_improvement", {})
    if not isinstance(raw, dict):
        raise ModelImprovementConfigError(
            "model-improvement policy source is invalid: "
            f"{source}.model_improvement must be a table"
        )

    unknown = sorted(
        str(key) for key in raw if key not in _MODEL_IMPROVEMENT_KEYS
    )
    if unknown:
        raise ModelImprovementConfigError(
            "model-improvement policy source is invalid: "
            f"{source}.model_improvement has unknown key(s): "
            + ", ".join(unknown)
        )

    policy = dict(_MODEL_IMPROVEMENT_DEFAULTS)
    for key in _MODEL_IMPROVEMENT_BOOL_KEYS:
        if key not in raw:
            continue
        value = raw[key]
        if not isinstance(value, bool):
            raise ModelImprovementConfigError(
                "model-improvement policy source is invalid: "
                f"{source}.model_improvement.{key} must be true or false"
            )
        policy[key] = value

    for key in _MODEL_IMPROVEMENT_FAMILY_KEYS:
        if key not in raw:
            continue
        value = raw[key]
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 20 <= value <= 1_000_000
        ):
            raise ModelImprovementConfigError(
                "model-improvement policy source is invalid: "
                f"{source}.model_improvement.{key} must be an integer "
                "between 20 and 1000000"
            )
        policy[key] = value

    if policy["allow_cross_tenant"] is True:
        raise ModelImprovementConfigError(
            "model-improvement policy source is invalid: "
            f"{source}.model_improvement.allow_cross_tenant is unsupported "
            "and must remain false"
        )
    return policy


def _model_improvement_policy_sources() -> tuple[dict, dict | None]:
    """Load the global and active-tenant policy snapshots without merging them."""
    _load_wizard_env()
    paths = [config_path(), dashboard_overrides_path()]
    global_snapshot = _load_config_file(paths[0])
    global_snapshot = _deep_merge_config(
        global_snapshot,
        _load_config_file(paths[1]),
    )

    overlay = os.environ.get(CONFIG_OVERLAY_ENV)
    if overlay:
        overlay_path = Path(overlay).expanduser()
        paths.append(overlay_path)
        global_snapshot = _deep_merge_config(
            global_snapshot,
            _load_config_file(overlay_path),
        )

    tenant_snapshot: dict | None = None
    tenant_path = tenant_config_path()
    if tenant_path is not None:
        paths.append(tenant_path)
        # Missing is a valid empty tenant policy. It therefore cannot provide
        # the explicit opt-in required by the resolver below.
        tenant_snapshot = _load_config_file(tenant_path, interpolate=False)

    errors = _source_errors(paths)
    if errors:
        details = "; ".join(
            f"{path}: {error}" for path, error in sorted(errors.items())
        )
        raise ModelImprovementConfigError(
            "model-improvement policy source is invalid: " + details
        )
    return global_snapshot, tenant_snapshot


def get_model_improvement_mutation_policy() -> dict[str, bool | int]:
    """Resolve the strictest effective policy for training or promotion.

    Unlike :func:`get_model_improvement`, this mutation-boundary API never
    silently normalizes a malformed active source. Global ``enable`` and
    ``allow_hosted`` are ceilings; an active tenant must independently opt in.
    Receipt requirements use logical OR, family floors use ``max``, and
    cross-tenant model improvement is unconditionally unavailable.
    """
    global_snapshot, tenant_snapshot = _model_improvement_policy_sources()
    global_policy = _strict_model_improvement_section(
        global_snapshot,
        source="global",
    )

    if tenant_snapshot is None:
        enable = bool(global_policy["enable"])
        if enable and global_policy["require_signed_receipt"] is not True:
            raise ModelImprovementConfigError(
                "enabled model improvement requires "
                "model_improvement.require_signed_receipt = true",
            )
        return {
            "enable": enable,
            "allow_hosted": (
                enable and bool(global_policy["allow_hosted"])
            ),
            "allow_cross_tenant": False,
            "require_signed_receipt": bool(
                global_policy["require_signed_receipt"]
            ),
            "minimum_train_families": int(
                global_policy["minimum_train_families"]
            ),
            "minimum_holdout_families": int(
                global_policy["minimum_holdout_families"]
            ),
        }

    tenant_policy = _strict_model_improvement_section(
        tenant_snapshot,
        source="tenant",
    )
    enable = bool(global_policy["enable"] and tenant_policy["enable"])
    require_signed_receipt = bool(
        global_policy["require_signed_receipt"]
        or tenant_policy["require_signed_receipt"]
    )
    if enable and not require_signed_receipt:
        raise ModelImprovementConfigError(
            "enabled model improvement requires "
            "model_improvement.require_signed_receipt = true",
        )
    return {
        "enable": enable,
        "allow_hosted": bool(
            enable
            and global_policy["allow_hosted"]
            and tenant_policy["allow_hosted"]
        ),
        "allow_cross_tenant": False,
        "require_signed_receipt": require_signed_receipt,
        "minimum_train_families": max(
            int(global_policy["minimum_train_families"]),
            int(tenant_policy["minimum_train_families"]),
        ),
        "minimum_holdout_families": max(
            int(global_policy["minimum_holdout_families"]),
            int(tenant_policy["minimum_holdout_families"]),
        ),
    }


def get_rehearsal() -> dict:
    """Return the ``[rehearsal]`` prediction settings.

    Predictions are observed by default: they do not authorize or stop tools.
    The explicit ``mode = "hold"`` setting retains the old experimental gate,
    which has no in-product approval route. Shield, capabilities, consent, and
    other tool policy checks remain independent of this setting.
    """
    cfg = load_config().get("rehearsal", {})

    mode = str(cfg.get("mode", "observe")).strip().lower()
    if mode not in {"observe", "hold"}:
        mode = "observe"

    def _num(key: str, default: float, cast=float):
        try:
            return cast(cfg.get(key, default))
        except (TypeError, ValueError, OverflowError):
            return default

    return {
        "enable": _strict_config_bool(
            cfg, "enable", governed_learning_default()),
        "mode": mode,
        "outcome_floor": _num("outcome_floor", 0.5),
        "min_support": _num("min_support", 5, int),
        "max_uncertainty": _num("max_uncertainty", 0.25),
        "horizon": _num("horizon", 8, int),
        "rollouts": _num("rollouts", 200, int),
    }


def get_speculative() -> dict:
    """Return the ``[speculative]`` section (speculative agent execution).

    Draft a turn with a cheap model when the Operating Twin's world-model is
    confident the turn is predictable, reserving the frontier model for novel /
    uncertain turns. OFF by default and fail-open -- when ``enable`` is false (or
    no ``draft_model`` is configured) the agent always uses its normal model.
    ``draft_model`` is an operator-chosen cheap model spec (never hard-coded);
    ``min_confidence``/``min_support`` set how dominant + well-observed an action
    must be before its turn is drafted.
    """
    cfg = load_config().get("speculative", {})

    def _num(key: str, default: float, cast=float):
        try:
            return cast(cfg.get(key, default))
        except (TypeError, ValueError, OverflowError):
            return default

    return {
        "enable": coerce_bool(cfg.get("enable"), False),
        "draft_model": (str(cfg.get("draft_model", "")).strip() or None),
        "min_confidence": _num("min_confidence", 0.85),
        "min_support": _num("min_support", 8, int),
    }


def get_data_engine() -> dict:
    """Return the ``[data_engine]`` section (the Cognitive Data Engine).

    The Tesla-style improvement flywheel for the agent workforce: production
    failures are causally triaged, a fix is mined + validated in the world-model,
    promoted through the safety ladder, and measured against real outcomes. ON
    by default; empty or insufficient evidence produces no candidate.
    ``failure_threshold`` is the outcome below which an
    episode counts as a failure; ``min_support`` is the evidence a causal-impact
    estimate needs before a failure class is ranked.
    """
    cfg = load_config().get("data_engine", {})

    def _num(key: str, default: float, cast=float):
        try:
            return cast(cfg.get(key, default))
        except (TypeError, ValueError, OverflowError):
            return default

    return {
        "enable": _strict_config_bool(
            cfg, "enable", governed_learning_default()),
        "failure_threshold": _num("failure_threshold", 0.5),
        "min_support": _num("min_support", 8, int),
        "top_k": _num("top_k", 10, int),
    }


def get_consequence() -> dict:
    """Return the ``[consequence]`` section (the Consequence Engine).

    Reality as the reward: real downstream outcomes (invoice paid, contract
    renewed, ticket stayed closed), reported by a system-of-record connector and
    joined back to the episode that acted, become the grounded learning signal.
    ON by default -- when ``enable`` is false the data-engine join keeps using
    the verifier-confidence proxy, so an opted-out deployment is unaffected;
    recording outcomes is always harmless (it just stores).
    """
    cfg = load_config().get("consequence", {})
    return {"enable": _strict_config_bool(
        cfg, "enable", governed_learning_default())}


def get_earned_autonomy() -> dict:
    """Return the ``[earned_autonomy]`` section (consequence-proven trust).

    Agents earn policy-auto-approval per action type by proving they predict
    consequences correctly (maverick.earned_autonomy). OFF by default: enabling
    it only records evidence; ``auto_graduate`` is the separate authority-
    widening arming switch and is strict-parsed -- a truthy string never arms
    it. ``max_auto_risk`` defaults to ``medium`` so graduating irreversible
    high-risk action types is an explicit operator decision; an unknown value
    fails closed (nothing graduates). Never raises.
    """
    cfg = load_config().get("earned_autonomy", {})

    def _num(key: str, default: float, cast=float, lo: float = 0.0, hi: float | None = None):
        raw = cfg.get(key, default)
        if isinstance(raw, bool):
            # bool is an int subclass; `min_streak = true` must not collapse
            # the graduation bar to 1 -- numeric policy keys demand numbers.
            return default
        try:
            value = cast(raw)
        except (TypeError, ValueError, OverflowError):
            return default
        if not math.isfinite(float(value)) or value < lo:
            return default
        if hi is not None and value > hi:
            return default
        return value

    return {
        "enable": _strict_config_bool(cfg, "enable", False),
        # Authority-widening: only a real TOML `true` arms graduation.
        "auto_graduate": cfg.get("auto_graduate") is True,
        "min_streak": _num("min_streak", 10, int, lo=1),
        "min_samples": _num("min_samples", 10, int, lo=1),
        "min_accuracy": _num("min_accuracy", 0.9, float, lo=0.0, hi=1.0),
        "tolerance": _num("tolerance", 0.25, float, lo=0.0, hi=1.0),
        "max_auto_risk": str(cfg.get("max_auto_risk", "medium")).strip().lower() or "medium",
        # Malformed value restores the guarantee (invalid=True tightens).
        "require_reversible": _strict_config_bool(
            cfg, "require_reversible", True, invalid=True),
    }


def get_deployment() -> dict:
    """Return the ``[deployment]`` section (install provenance).

    Written by the installer wizard to record where Lightwork runs
    (desktop/docker/vps/phone). Read back so a re-run of ``maverick init``
    can default to the prior choice. ``type`` is empty when never recorded.
    """
    cfg = load_config().get("deployment", {}) or {}
    return {"type": str(cfg.get("type", "")).strip()}


def vendor_reviewed_uploads_enabled(cfg: dict | None = None) -> bool:
    """Local preview and reviewed Office/transcription upload, within onboarding."""
    current = load_global_config() if cfg is None else cfg
    section = current.get("vendor_onboarding") or {}
    return section.get("reviewed_uploads", True) is True


def data_use_governance_enabled(cfg: dict | None = None) -> bool:
    """Whether the Data Use Governance module is on.

    ``MAVERICK_DATA_USE_GOVERNANCE`` wins when set (the same env-first contract
    as the flow engine's ``MAVERICK_FLOWS``), so a hosted deployment whose
    config file lives on ephemeral storage can still turn the module on.
    Otherwise ``[data_use_governance] enable`` decides. OFF by default; never
    raises.
    """
    try:
        loaded = cfg if cfg is not None else load_config()
        if config_source_errors():
            return False
        v = env_flag("MAVERICK_DATA_USE_GOVERNANCE")
        if v is not None:
            return v
        section = loaded.get("data_use_governance", {})
    except Exception:  # pragma: no cover -- config must never block
        return False
    return isinstance(section, dict) and section.get("enable") is True


def knowledge_access_enabled(cfg: dict | None = None) -> bool:
    """Whether the governed in-app organizational-memory surface is enabled.

    Existing installations keep the feature available when the section is
    absent.  An explicit false disables it, and malformed or unreadable active
    configuration fails closed. ``MAVERICK_KNOWLEDGE_ACCESS`` has the same
    deployment override semantics as other product feature gates.
    """

    try:
        with single_read(fresh=True):  # this read's own errors, not a later clean one's
            loaded = cfg if cfg is not None else load_config()
            if cfg is None and config_source_errors():
                return False
        override = env_flag("MAVERICK_KNOWLEDGE_ACCESS")
        if override is not None:
            return override
        if "knowledge_access" not in loaded:
            return True
        section = loaded.get("knowledge_access")
    except Exception:  # pragma: no cover - authority reads fail closed
        return False
    return isinstance(section, dict) and section.get("enable", True) is True


API_KEY_DEFAULTS: dict = {
    "enabled": True,
    "default_days": 90,
    "max_days": 365,
    "rotation_grace_hours": 24,
    "prefix": "lwk_",
}

_API_KEY_PREFIX_RE = re.compile(r"^[a-z][a-z0-9]{1,7}_$")


def api_key_settings(cfg: dict | None = None) -> dict:
    """Personal and service-account API keys for scripts and integrations.

    Read from ``[dashboard]``: ``api_keys`` (on by default; a key only exists
    once a signed-in person creates one), ``api_key_default_days`` (how long a
    new key lasts unless the person picks a shorter time), ``api_key_max_days``
    (the longest a key may last), ``api_key_rotation_grace_hours`` (how long
    the old secret keeps working after a rotation) and ``api_key_prefix`` (the
    first characters of every key, so logs and scanners recognise one).
    ``MAVERICK_DASHBOARD_API_KEYS`` overrides the on/off switch. Malformed or
    unreadable configuration fails closed: keys are off and every limit is
    the default.
    """
    out = dict(API_KEY_DEFAULTS)
    try:
        with single_read(fresh=True):  # this read's own errors, not a later clean one's
            loaded = cfg if cfg is not None else load_config()
            if cfg is None and config_source_errors():
                out["enabled"] = False
                return out
        table = loaded.get("dashboard") if isinstance(loaded, dict) else None
        table = table if isinstance(table, dict) else {}
        enabled = table.get("api_keys", True)
        out["enabled"] = enabled is True
        for key, name, low, high in (
            ("api_key_default_days", "default_days", 1, 3650),
            ("api_key_max_days", "max_days", 1, 3650),
            ("api_key_rotation_grace_hours", "rotation_grace_hours", 0, 24 * 30),
        ):
            raw = table.get(key)
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                continue
            if low <= raw <= high:
                out[name] = int(raw)
        prefix = table.get("api_key_prefix")
        if isinstance(prefix, str) and _API_KEY_PREFIX_RE.match(prefix):
            out["prefix"] = prefix
        if out["default_days"] > out["max_days"]:
            out["default_days"] = out["max_days"]
        override = env_flag("MAVERICK_DASHBOARD_API_KEYS")
        if override is not None:
            out["enabled"] = override
    except Exception:  # pragma: no cover - authority reads fail closed
        out = dict(API_KEY_DEFAULTS)
        out["enabled"] = False
    return out


def candidate_promotion_enabled(cfg: dict | None = None) -> bool:
    """Whether guarded research-candidate promotion is enabled.

    Promotion can change production state, so the capability is opt-in and
    malformed or unreadable active configuration fails closed. The deployment
    override follows the same environment-first convention as other feature
    gates.
    """

    try:
        loaded = cfg if cfg is not None else load_config()
        if cfg is None and config_source_errors():
            return False
        override = env_flag("MAVERICK_CANDIDATE_PROMOTION")
        if override is not None:
            return override
        section = loaded.get("candidate_promotion", {})
    except Exception:  # pragma: no cover - authority reads fail closed
        return False
    return isinstance(section, dict) and section.get("enable") is True


def get_flows() -> dict:
    """Return the ``[flows]`` section (the flow engine).

    A flow is a deterministic control-flow skeleton (branch / foreach / parallel /
    approval / delay) over agentic + tool steps -- the "do both" model that keeps
    a migrated workflow's structure while any node can still be a full agentic
    goal. OFF by default -- when ``enable`` is false the engine never runs, so a
    default deployment is unaffected.
    """
    cfg = load_config().get("flows", {})
    if not isinstance(cfg, dict):
        cfg = {}
    try:
        max_node_retries = int(cfg.get("max_node_retries", 5))
    except (TypeError, ValueError, OverflowError):
        max_node_retries = 5
    return {
        "enable": coerce_bool(cfg.get("enable"), False),
        # Opt-in autonomous self-correction: a scheduled pass reverts an applied
        # node-kind rewrite whose grounded outcomes measurably regressed. OFF by
        # default -- surfacing proposals + human apply works without it; this only
        # governs whether the loop is allowed to *undo* a bad change on its own.
        "auto_evolve": coerce_bool(cfg.get("auto_evolve"), False),
        # Retired: autonomous forward apply no longer runs (see
        # automation_queue and docs/configuration.md); the key is still read so
        # an old config parses and the setting can be reported.
        "auto_apply": coerce_bool(cfg.get("auto_apply"), False),
        # Reviewed, bounded pure operators may replace an agent result only on
        # agreement inside their declared input domain. Explicit boolean opt-in.
        "learned_operators": _strict_config_bool(cfg, "learned_operators", False),
        # Composed pure expressions need a separate runtime opt-in.
        "composed_operators": _strict_config_bool(cfg, "composed_operators", False),
        # Reviewed action sequences keep native authorization and explicit gates.
        "action_recipes": _strict_config_bool(cfg, "action_recipes", False),
        # Expressions learned across action results require an independent opt-in.
        "action_recipe_transforms": _strict_config_bool(cfg, "action_recipe_transforms", False),
        # Inferring control flow needs its own opt-in in addition to expressions.
        "action_recipe_choices": _strict_config_bool(cfg, "action_recipe_choices", False),
        "action_recipe_teaching": _strict_config_bool(cfg, "action_recipe_teaching", False),
        # Bounded next-action/completion learning requires verified lineage and
        # strict signed execution receipts; enabling it never enables signing.
        "action_workflow_learning": _strict_config_bool(cfg, "action_workflow_learning", False),
        # Inferred integer history accumulators need a separate explicit opt-in.
        "action_workflow_memory_learning": _strict_config_bool(cfg, "action_workflow_memory_learning", False),
        # Retaining native business examples requires a separate explicit opt-in.
        "action_episode_capture": _strict_config_bool(cfg, "action_episode_capture", False),
        "action_recipe_lineage": _strict_config_bool(cfg, "action_recipe_lineage", False),
        # Malformed restrictions must not quietly enable unprovenanced recipes.
        "require_action_recipe_lineage": _strict_config_bool(
            cfg, "require_action_recipe_lineage", False, invalid=True),
        # Preserve malformed policy for the trust validator to reject. Silently
        # discarding a malformed revocation list would restore revoked keys.
        "action_evidence_issuer": cfg.get("action_evidence_issuer", ""),
        "action_evidence_revoked_keys": cfg.get("action_evidence_revoked_keys", []),
        # Stored distinguishing questions and reviewed answers are a separate
        # opt-in; preparing a draft does not enable its execution/publication.
        "learned_operator_questions": _strict_config_bool(
            cfg, "learned_operator_questions", False),
        # Per-node action/agent retries are useful for transient failures, but
        # must stay bounded because every retry may invoke tools/providers. Env
        # MAVERICK_FLOW_MAX_NODE_RETRIES can override this at runtime; the flow
        # IR also hard-caps the effective value defensively.
        "max_node_retries": max_node_retries,
    }


def get_operations_scientist() -> dict:
    """Return the ``[operations_scientist]`` section (the discovery engine).

    An agent that discovers a better process and proves it causally: it pairs a
    harmful action with the beneficial habit that should replace it, validates the
    swap in the world-model, then (downstream) runs a real experiment and ships
    the proven win. ON by default; it remains evidence- and promotion-gated.
    """
    cfg = load_config().get("operations_scientist", {})
    return {"enable": _strict_config_bool(
        cfg, "enable", governed_learning_default())}


def get_emergent_protocol() -> dict:
    """Return the ``[emergent_protocol]`` section (learned coordination shorthand).

    The swarm evolves short codes for the boilerplate it repeats, paying frontier
    tokens only for what's new -- but every code decodes exactly back to English
    (the auditable translation layer). OFF by default -- when ``enable`` is false
    the codec is the identity transform, so a default deployment is unaffected.
    """
    cfg = load_config().get("emergent_protocol", {})
    return {"enable": coerce_bool(cfg.get("enable"), False)}


def get_emergent_codec() -> dict:
    """Return the ``[emergent_codec]`` section (live token-aware compression).

    The token-aware codec (``maverick.emergent_tokens``) is the implementation that
    actually saves *frontier tokens*, not just bytes -- byte-stuffed ~2-token codes
    instead of the ~5-token sentinels. When ``enable`` is true the blackboard
    measures, on the real coordination stream, what the codec would save (telemetry
    only -- the rendered text agents see is unchanged, so the audit/Shield path is
    untouched). OFF by default: a default deployment measures nothing and pays
    nothing. Flipping agents to actually *read* codes is a separate, stricter step.
    """
    cfg = load_config().get("emergent_codec", {})
    return {"enable": coerce_bool(cfg.get("enable"), False)}


def get_durable() -> dict:
    """Return the ``[durable]`` section with defaults filled in.

    Durable execution (checkpoint/resume) is OFF by default so the kernel
    keeps current warm-restart behavior out of the box. ``keep_last`` caps how
    many checkpoints are retained per agent for rewind/history.
    """
    cfg = load_config().get("durable", {})
    contract = INTEGER_SETTINGS["durable.keep_last"]
    try:
        keep = int(cfg.get("keep_last", contract.default))
    except (TypeError, ValueError, OverflowError):
        keep = contract.default
    return {
        "enabled": coerce_bool(cfg.get("enabled"), BOOLEAN_SETTINGS["durable.enabled"].default),
        "keep_last": max(contract.minimum, keep),
    }


def get_control_plane() -> dict:
    """Return the ``[control_plane]`` section (the Agent Control Plane).

    ``enable`` arms the mutating verbs of ``maverick.agent_control_plane``
    (suspend / resume / contain / release / attenuate / halt) on the dashboard
    console and ``maverick control-plane``; the roster, status and ledger
    reads work regardless. Off by default so a deployment that never opted in
    cannot have a principal revoked from a stray click. Env override:
    ``MAVERICK_CONTROL_PLANE=1`` enables.
    """
    import os
    cfg = load_config().get("control_plane", {}) or {}
    enable = coerce_bool(cfg.get("enable"), False)
    if os.environ.get("MAVERICK_CONTROL_PLANE", "").strip() == "1":
        enable = True
    return {"enable": enable}


def get_assessments() -> dict:
    """Return the ``[assessments]`` section (assessment flow assists).

    ``doc_discovery`` lets the assessment flow search CONNECTED document
    sources (Microsoft Graph, Slack, Google Drive) for the SOW/contract/DPA
    related to the subject and attach them as evidence -- default on, but it
    only activates when a source actually has credentials (env or a named
    connection), so a default deployment reaches nothing. ``sources`` orders
    which sources to try. ``learn`` turns on assessment memory: suggestions
    and precedents distilled from the org's OWN past assessments (and the
    knowledge plane when enabled) -- advisory only, the human review gate is
    untouched. Env overrides: ``MAVERICK_ASSESS_DISCOVERY`` /
    ``MAVERICK_ASSESS_LEARN`` (0 disables either).
    """
    import os
    cfg = load_config().get("assessments", {}) or {}
    raw = cfg.get("sources", ["msgraph", "slack", "gdrive"])
    if isinstance(raw, str):
        sources = [s.strip() for s in raw.split(",") if s.strip()]
    elif isinstance(raw, (list, tuple)):
        sources = [str(s).strip() for s in raw if str(s).strip()]
    else:
        sources = ["msgraph", "slack", "gdrive"]

    def _env_off(var: str) -> bool:
        return os.environ.get(var, "").strip().lower() in ("0", "false", "no")

    return {
        "doc_discovery": (coerce_bool(cfg.get("doc_discovery"), True)
                          and not _env_off("MAVERICK_ASSESS_DISCOVERY")),
        "sources": sources,
        "learn": (coerce_bool(cfg.get("learn"), True)
                  and not _env_off("MAVERICK_ASSESS_LEARN")),
    }


def get_value(*, config: dict | None = None) -> dict:
    """Return the ``[value]`` section: the client's own cost/value assumptions
    for the savings (ROI) report.

    This is what makes the savings dashboard the CLIENT's number, not ours: the
    fully-loaded human hourly rate and the human hours one comparable
    deliverable would take by hand. The report reads REAL completed work from
    the world model and computes, per department,
    ``(human_hours x hourly_rate) - actual agent spend`` -- money saved vs the
    typical human cost.

    ``departments`` holds optional per-department overrides
    (``[value.departments.<name>]`` tables with ``hourly_rate`` /
    ``hours_per_task``) so legal work can be priced differently from support.
    ``enable`` only shows/hides the dashboard page; the numbers are always safe
    (read-only, they never tune anything -- cost
    pressure must not defund safety). Defaults are deliberately conservative so
    an out-of-box ROI claim is defensible, not inflated.
    Env override: ``MAVERICK_VALUE_HOURLY_RATE`` / ``MAVERICK_VALUE_HOURS``.
    """
    # ``config`` lets control-plane callers compare the deployment-global
    # assumptions with the active tenant's effective view without changing
    # tenant context or duplicating the normalization rules below.
    cfg = (load_config() if config is None else config).get("value", {}) or {}

    def _pos(v: object, default: float) -> float:
        try:
            f = float(v)  # type: ignore[arg-type]
        except (TypeError, ValueError, OverflowError):
            return default
        return f if f >= 0 else default

    import os
    rate = _pos(os.environ.get("MAVERICK_VALUE_HOURLY_RATE")
                or cfg.get("hourly_rate"), 75.0)
    hours = _pos(os.environ.get("MAVERICK_VALUE_HOURS")
                 or cfg.get("hours_per_task"), 2.0)
    departments: dict[str, dict] = {}
    raw = cfg.get("departments", {}) or {}
    if isinstance(raw, dict):
        for name, ov in raw.items():
            if not isinstance(ov, dict):
                continue
            departments[str(name)] = {
                "hourly_rate": _pos(ov.get("hourly_rate"), rate),
                "hours_per_task": _pos(ov.get("hours_per_task"), hours),
            }
    return {
        "enable": coerce_bool(cfg.get("enable"), True),
        "hourly_rate": rate,
        "hours_per_task": hours,
        "currency": str(cfg.get("currency", "USD") or "USD").upper()[:8],
        "departments": departments,
    }


EMPLOYEE_ACTIVATION_JOBS = {
    "weekly_update": "Write a useful weekly update", "project_plan": "Turn notes into a project plan",
    "privacy_evidence": "Prepare a privacy evidence summary", "security_review": "Prepare a security review brief",
    "finance_variance": "Explain a simple budget variance",
}


def get_employee_activation_jobs() -> set[str]:
    """Organization-approved first-job guides; a workspace may only narrow."""
    key = "employee_activation_jobs"
    ceiling = load_global_config().get("dashboard", {}).get(key, list(EMPLOYEE_ACTIVATION_JOBS))
    selected = load_config().get("dashboard", {}).get(key, ceiling)
    if not isinstance(ceiling, list) or not isinstance(selected, list):
        return set()
    if not all(isinstance(item, str) for item in [*ceiling, *selected]):
        return set()
    return set(ceiling) & set(selected) & EMPLOYEE_ACTIVATION_JOBS.keys()

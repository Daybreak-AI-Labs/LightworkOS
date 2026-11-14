"""Federated swarm protocol.

Two Lightwork swarms peer and delegate goals to each other. The wire contract
is ``grpc_api/federation.proto`` (Hello / DelegateGoal / GoalStatus); this
module is the protocol layer behind it:

* :class:`FederationNode` — the client half: the registry of configured peers
  plus ``hello()`` (discovery: the peer's A2A Agent Card, validated via
  :func:`maverick.a2a.parse_remote_card`) and ``delegate()`` / ``status()``.
* :class:`FederationService` — the serve half: authenticates the caller,
  narrows the requested capabilities against a local grant
  (:func:`maverick.capability_boot.negotiate_boot` — narrow-only, a peer can
  never obtain authority this node wouldn't grant), and accepts a delegation
  by creating a local goal through the injected world/dispatcher seam
  (:class:`maverick.grpc_api.service.GoalService`; the orchestrator is never
  imported).

Auth is a shared per-peer token, fail-CLOSED: the receiver constant-time
compares the presented token against each configured peer's token, and the
matching ``[federation]`` entry *identifies* the caller — audit rows name the
peer from local config, never from the wire. Missing/unknown token = refused.

**Signed identity.** When the Agent Trust Plane is engaged and a peer
has a pinned Ed25519 key in ``[agent_trust]``, the shared token is no longer
sufficient: the caller signs the canonical delegation envelope
(:data:`DELEGATE_SCHEMA`) with its audit key and the receiver verifies it
against the pinned key (:func:`maverick.agent_trust.verify_identity`), with a
freshness window and a replay-nonce cache. ``[agent_trust] require_signed``
extends this to refuse shared-token-only peers. Node names used as signing
origins must be valid lowercase origins (``federation_envelope`` charset), which
the registry ids already are.

Both halves of every delegation are recorded with matching fields — the
caller logs ``{peer_node, correlation_id, direction: "sent"}``, the receiver
``{..., direction: "received"}`` (kind :data:`EventKind.FEDERATION_DELEGATE`)
— so comparing the two nodes' signed audit logs shows a dropped half.

Transport seam: anything with ``call(method, payload_dict) -> payload_dict``.
``FederationService.call`` itself satisfies it, so tests (or an in-process
loopback) wire client to service with no gRPC at all; the gRPC binding
(:func:`serve` + the default client transport) is a thin adapter over the same
dicts, lazy behind the ``[grpc]`` extra.

Off by default. Opt in::

    [federation]
    enabled = true                 # serve side; outbound needs peers only
    node = "atlas"                 # this node's name in its peers' configs
    peers = [
      { name = "vega", target = "vega.internal:50061", token = "${FED_VEGA_TOKEN}" },
    ]
"""
from __future__ import annotations

import atexit
import contextlib
import functools
import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from collections import OrderedDict, deque
from collections.abc import Iterable, Iterator
from concurrent import futures
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .a2a import build_agent_card, parse_remote_card
from .audit.events import EventKind
from .capability_boot import negotiate_boot
from .constant_time import text_equals

log = logging.getLogger(__name__)

PROTOCOL = "maverick-federation/1"
# Schema of the signed delegation envelope (signed identity). The caller
# signs it with its audit Ed25519 key; the receiver verifies against the pinned
# key in [agent_trust]. Possession of a leaked shared token alone no longer
# impersonates a peer that has a pinned key.
DELEGATE_SCHEMA = "maverick-federation-delegate/1"
_SIGN_FRESHNESS_S = 300.0  # accept a signature within ±5 min of now (replay window)
# Module-level cache of verified signatures already seen (sig -> first-seen ts),
# oldest-first, so a captured valid delegation can't be replayed within the
# freshness window. Pruned by AGE (see _replay_seen), so a still-fresh nonce is
# never evicted early.
_seen_sigs: OrderedDict[tuple[str, str, str], float] = OrderedDict()
# Guards every read/mutate of _seen_sigs. The federation gRPC server runs a
# ThreadPoolExecutor, so concurrent DelegateGoal RPCs hit _replay_seen at once.
# Without this lock the check-then-insert is not atomic (two threads could both
# admit the same captured signature — a replay), and the iterate-and-pop prune
# can raise "OrderedDict mutated during iteration". Replay protection is
# security-critical, so serialise the whole check-and-remember.
_seen_sigs_lock = threading.Lock()

# Per-peer request-rate limiter for inbound delegations. The sibling gRPC API
# (maverick.grpc_api.server) pairs maximum_concurrent_rpcs (an in-flight cap)
# with a per-caller request-rate cap at the auth chokepoint; federation had only
# the former. DelegateGoal is heavier than a typical RPC -- every accepted call
# launches a real goal run -- so one authenticated-but-misbehaving peer could
# spawn goals as fast as it can call, exhausting workers/budget even though each
# run is individually budget-capped. This sliding 60s window bounds delegations
# per peer; idle buckets are swept when the map grows so a long-running server
# can't leak one entry per distinct peer forever.
_fed_rate_hits: dict[str, deque[float]] = {}
_fed_rate_lock = threading.Lock()
_FED_RATE_MAX_KEYS = 8192
_FED_STATE_CONNECTION = threading.local()
# Every connection _FederationState._connect caches, in any thread, so that a release can close
# them all. Each entry is (owning thread, connection), keyed by id(connection). A cached
# connection is used only by the thread that cached it, but a release closes it from another
# thread, so each one is opened with check_same_thread=False. That is safe only because a
# release waits for every running state call (see _STATE_FILE_GATE) before it closes anything.
_FED_STATE_REGISTRY_LOCK = threading.Lock()
_FED_STATE_REGISTRY: dict[int, tuple[threading.Thread, sqlite3.Connection]] = {}
# Connections the parent process cached, kept referenced in a forked child so that finalizing
# them there cannot close the parent's file descriptor (see _reset_after_fork).
_INHERITED_FED_STATE_CONNECTIONS: list[sqlite3.Connection] = []
# Bumped by every release; a thread's cache is valid only for the generation it was opened in,
# so every thread reopens after a release.
_FED_STATE_GENERATION = 0


class _StateFileGate:
    """Lets state calls run together, and makes a close or a file replacement wait for them.

    A state call holds the gate shared from before it opens its connection until it has
    finished using it. close_cached_connections() and hold_state_file_closed() hold it
    exclusively: they wait for running calls to finish, so no connection is closed while a
    call uses it, and calls that start meanwhile wait for them, so no connection opens while
    the state file is being replaced. A thread that asks for the gate exclusively from inside
    one of its own state calls, or asks for it shared while it holds it exclusively, would wait
    on itself, so that raises RuntimeError instead.
    """

    def __init__(self) -> None:
        self._condition = threading.Condition(threading.Lock())
        self._readers = 0
        self._waiting_writers = 0
        self._writer: int | None = None
        self._local = threading.local()

    @contextlib.contextmanager
    def shared(self) -> Iterator[None]:
        local = self._local
        if getattr(local, "writing", 0):
            raise RuntimeError("the federation state file is held closed by this thread")
        nested = getattr(local, "reading", 0)
        with self._condition:
            # A nested call already counts as a reader, and a writer can only be running once
            # every reader has left, so waiting here could only wait on this thread.
            if not nested:
                while self._writer is not None or self._waiting_writers:
                    self._condition.wait()
            self._readers += 1
        local.reading = nested + 1
        try:
            yield
        finally:
            local.reading = nested
            with self._condition:
                self._readers -= 1
                if not self._readers:
                    self._condition.notify_all()

    @contextlib.contextmanager
    def exclusive(self) -> Iterator[None]:
        local = self._local
        if getattr(local, "reading", 0):
            raise RuntimeError("the federation state file cannot be closed inside a state call")
        outer = getattr(local, "writing", 0)
        if not outer:
            with self._condition:
                self._waiting_writers += 1
                try:
                    while self._writer is not None or self._readers:
                        self._condition.wait()
                    self._writer = threading.get_ident()
                finally:
                    self._waiting_writers -= 1
                    self._condition.notify_all()
        local.writing = outer + 1
        try:
            yield
        finally:
            local.writing = outer
            if not outer:
                with self._condition:
                    self._writer = None
                    self._condition.notify_all()


_STATE_FILE_GATE = _StateFileGate()

_DEFAULT_ADDR = "127.0.0.1:50061"  # one port up from the goal API (50051)
_DEFAULT_RPC_TIMEOUT_S = 10.0
_MAX_CORRELATION_ID_BYTES = 256
# Bounds on retained delegation admissions (federation_admission reads them).
_CORRELATION_CACHE_MAX = 250_000
_CORRELATION_PER_PEER_MAX = 50_000

# Sentinel: "no grant injected" (build from config) vs an explicit None
# (capability enforcement off -> delegations run unrestricted).
_UNSET = object()


class FederationError(ValueError):
    """A peer/request the federation layer refuses to deal with."""


class FederationAuthError(FederationError):
    """Missing or invalid shared token (fail-closed)."""


def _state_call(method):
    """Run a state method inside the gate, so its connection is not closed while it uses it."""

    @functools.wraps(method)
    def call(self, *args, **kwargs):
        with _STATE_FILE_GATE.shared():
            return method(self, *args, **kwargs)

    return call


class _FederationState:
    """Tenant-scoped durable replay, rate, and correlation authority."""

    def __init__(self, path: Path | None = None):
        if path is None:
            from .paths import data_dir

            path = data_dir("federation", "inbound_state.sqlite3")
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        """Return this thread's cached connection, opening the state file on first use.

        The caller must be inside a state call (_STATE_FILE_GATE.shared()) for as long as it
        uses the connection. The public state methods below are wrapped with _state_call.
        """
        from .file_lock import (
            ensure_private_directory,
            ensure_private_file,
            harden_path_permissions,
        )

        canonical = str(self.path.resolve())
        current_pid = os.getpid()
        cached_path = getattr(_FED_STATE_CONNECTION, "path", None)
        cached_conn = getattr(_FED_STATE_CONNECTION, "conn", None)
        cached_pid = getattr(_FED_STATE_CONNECTION, "pid", None)
        cached_generation = getattr(_FED_STATE_CONNECTION, "generation", None)
        if (
            cached_path == canonical
            and cached_conn is not None
            and cached_pid == current_pid
            and cached_generation == _FED_STATE_GENERATION
        ):
            return cached_conn
        if cached_conn is not None:
            _release_registered(cached_conn)
            _FED_STATE_CONNECTION.conn = None
            _FED_STATE_CONNECTION.path = None
            _FED_STATE_CONNECTION.pid = None

        ensure_private_directory(self.path.parent)
        existed = self.path.exists()
        if existed:
            ensure_private_file(self.path)
        conn = sqlite3.connect(
            str(self.path), timeout=10.0, isolation_level=None,
            check_same_thread=False,
        )
        try:
            if not existed:
                harden_path_permissions(self.path, 0o600)
            conn.execute("PRAGMA synchronous=FULL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS replay_claims (
                    scope TEXT NOT NULL,
                    signature_hash TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (scope, signature_hash)
                );
                CREATE TABLE IF NOT EXISTS rate_hits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    peer_key TEXT NOT NULL,
                    seen_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS rate_hits_peer_time
                    ON rate_hits(peer_key, seen_at);
                CREATE INDEX IF NOT EXISTS rate_hits_seen_at
                    ON rate_hits(seen_at);
                CREATE TABLE IF NOT EXISTS correlations (
                    peer TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    status TEXT NOT NULL,
                    owner_token TEXT NOT NULL,
                    result_json TEXT,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (peer, correlation_id)
                );
            """)
            generation = _register_cached_connection(conn)
            _FED_STATE_CONNECTION.path = canonical
            _FED_STATE_CONNECTION.conn = conn
            _FED_STATE_CONNECTION.pid = current_pid
            _FED_STATE_CONNECTION.generation = generation
            return conn
        except BaseException:
            conn.close()
            raise

    @_state_call
    def claim_replay(
        self, scope: str, sig: str, *, expires_at: float, now: float,
    ) -> bool:
        signature_hash = hashlib.sha256(sig.encode("utf-8")).hexdigest()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "DELETE FROM replay_claims WHERE scope = ? AND expires_at < ?",
                (scope, now),
            )
            row = conn.execute(
                "SELECT 1 FROM replay_claims "
                "WHERE scope = ? AND signature_hash = ?",
                (scope, signature_hash),
            ).fetchone()
            if row is not None:
                return True
            count = int(conn.execute(
                "SELECT COUNT(*) FROM replay_claims WHERE scope = ?",
                (scope,),
            ).fetchone()[0])
            if count >= 10_000:
                raise ValueError("federation replay ledger capacity reached")
            conn.execute(
                "INSERT INTO replay_claims(scope, signature_hash, expires_at) "
                "VALUES (?, ?, ?)",
                (scope, signature_hash, expires_at),
            )
            return False

    @_state_call
    def rate_ok(self, key: str, *, now: float, limit: int) -> bool:
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cutoff = now - 60.0
            conn.execute("DELETE FROM rate_hits WHERE seen_at < ?", (cutoff,))
            count = int(conn.execute(
                "SELECT COUNT(*) FROM rate_hits "
                "WHERE peer_key = ? AND seen_at >= ?",
                (key, cutoff),
            ).fetchone()[0])
            if count >= limit:
                return False
            conn.execute(
                "INSERT INTO rate_hits(peer_key, seen_at) VALUES (?, ?)",
                (key, now),
            )
            return True

    @_state_call
    def correlation_result(
        self, peer: str, corr: str, digest: str,
    ) -> tuple[str, dict[str, Any] | None]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT digest, status, result_json FROM correlations "
                "WHERE peer = ? AND correlation_id = ?",
                (peer, corr),
            ).fetchone()
        if row is None:
            return "missing", None
        existing_digest, status, result_json = row
        if not hmac.compare_digest(str(existing_digest), digest):
            return "conflict", None
        if status != "complete":
            return "busy", None
        result = json.loads(str(result_json or "{}"))
        if not isinstance(result, dict):
            raise ValueError("invalid federation correlation result")
        return "cached", result

def _register_cached_connection(connection: sqlite3.Connection) -> int:
    """Track a newly cached connection; return the generation it is valid for.

    A thread that has ended never uses its cached connection again, so the connections of
    ended threads are closed here rather than kept until process exit. Called inside a state
    call, so no release can run at the same time.
    """
    owner = threading.current_thread()
    with _FED_STATE_REGISTRY_LOCK:
        ended = []
        for key, (thread, stale) in list(_FED_STATE_REGISTRY.items()):
            if not thread.is_alive():
                del _FED_STATE_REGISTRY[key]
                ended.append(stale)
        _FED_STATE_REGISTRY[id(connection)] = (owner, connection)
        generation = _FED_STATE_GENERATION
    for stale in ended:
        _close_registered(stale)
    return generation


def _close_registered(connection: sqlite3.Connection) -> None:
    with contextlib.suppress(sqlite3.Error):
        connection.close()


def _release_registered(connection: sqlite3.Connection) -> None:
    """Close one cached connection, unless a release has already closed it."""
    with _FED_STATE_REGISTRY_LOCK:
        entry = _FED_STATE_REGISTRY.get(id(connection))
        if entry is None or entry[1] is not connection:
            return
        del _FED_STATE_REGISTRY[id(connection)]
    _close_registered(connection)


def _close_all_cached() -> None:
    """Close every registered connection and invalidate every thread's cache.

    The caller holds _STATE_FILE_GATE exclusively, so no connection is in use.
    """
    global _FED_STATE_GENERATION
    with _FED_STATE_REGISTRY_LOCK:
        _FED_STATE_GENERATION += 1
        entries = list(_FED_STATE_REGISTRY.values())
        _FED_STATE_REGISTRY.clear()
    for _thread, connection in entries:
        _close_registered(connection)
    _FED_STATE_CONNECTION.conn = None
    _FED_STATE_CONNECTION.path = None
    _FED_STATE_CONNECTION.pid = None
    _FED_STATE_CONNECTION.generation = None


def close_cached_connections() -> None:
    """Close every federation state connection cached by any thread, and invalidate the caches.

    A state call that is running in another thread is waited for, not interrupted: the close
    starts once those calls have finished, and calls that start meanwhile wait for it. Each
    thread's cache is invalidated, so its next state call opens a fresh connection. Raises
    RuntimeError when called from inside a state call, because that call would wait on itself.

    The release reaches only this process. A dashboard or MCP server in another process keeps
    its own connection, so a restore or purge run there can still fail on Windows, and on POSIX
    that process keeps writing to a replaced file. Not verified on Windows.

    To keep the file closed for a whole replacement, use hold_state_file_closed() instead.
    """
    with _STATE_FILE_GATE.exclusive():
        _close_all_cached()


@contextlib.contextmanager
def hold_state_file_closed() -> Iterator[None]:
    """Close the cached state connections, and keep new ones from opening until the block exits.

    Wrap every deletion, replacement or restore of the federation state file in it, so that no
    connection can open the file between the close and the replacement. The same limits as
    close_cached_connections() apply, and the block must not make federation state calls.
    """
    with _STATE_FILE_GATE.exclusive():
        _close_all_cached()
        yield


def _close_calling_thread_at_exit() -> None:
    """At interpreter exit, close only the calling thread's connection.

    Other threads may still be running then, so their connections are left to end with the
    process.
    """
    connection = getattr(_FED_STATE_CONNECTION, "conn", None)
    _FED_STATE_CONNECTION.conn = None
    if connection is not None:
        _release_registered(connection)


atexit.register(_close_calling_thread_at_exit)


def _reset_after_fork() -> None:
    """In a forked child, forget the parent's registry and gate without closing its connections.

    The child's copies of those connection objects stay referenced, so that finalizing them in
    the child cannot close file descriptors that the parent still uses.
    """
    global _FED_STATE_REGISTRY_LOCK, _STATE_FILE_GATE
    _INHERITED_FED_STATE_CONNECTIONS.extend(
        connection for _thread, connection in _FED_STATE_REGISTRY.values()
    )
    _FED_STATE_REGISTRY.clear()
    cached = getattr(_FED_STATE_CONNECTION, "conn", None)
    if cached is not None:
        _INHERITED_FED_STATE_CONNECTIONS.append(cached)
    _FED_STATE_CONNECTION.conn = None
    _FED_STATE_CONNECTION.path = None
    _FED_STATE_CONNECTION.pid = None
    _FED_STATE_CONNECTION.generation = None
    _FED_STATE_REGISTRY_LOCK = threading.Lock()
    _STATE_FILE_GATE = _StateFileGate()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)


def _federation_state(path: Path | None = None) -> _FederationState:
    return _FederationState(path)


# -- config ----------------------------------------------------------------

def federation_enabled() -> bool:
    """Opt-in gate for the serving surface. Off by default (outward-facing)."""
    env = os.environ.get("MAVERICK_FEDERATION_ENABLED")
    if env is not None:
        return env.strip().lower() in {"1", "true", "yes", "on"}
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("federation") or {}
        val = cfg.get("enabled", False)
    except Exception:
        return False
    if isinstance(val, str):
        return val.strip().lower() in {"1", "true", "yes", "on"}
    return bool(val)


def node_name() -> str:
    """This node's name — what its peers call it in *their* configs."""
    env = (os.environ.get("MAVERICK_FEDERATION_NODE") or "").strip()
    if env:
        return env
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("federation") or {}
        name = str(cfg.get("node") or "").strip()
    except Exception:
        name = ""
    return name or "maverick"


@dataclass(frozen=True)
class Peer:
    """One ``[federation] peers`` entry."""
    name: str    # the peer's node name (must match what it calls itself)
    target: str  # host:port its federation server listens on
    token: str = ""  # shared secret for this pair; "" can never authenticate


def load_peers(cfg: dict | None = None) -> list[Peer]:
    """Parse ``[federation] peers``. Forgiving: junk entries are skipped,
    duplicates keep the first occurrence, and nothing here ever raises."""
    if cfg is None:
        try:
            from .config import load_config
            cfg = load_config() or {}
        except Exception:
            return []
    fed = cfg.get("federation")
    raw = fed.get("peers") if isinstance(fed, dict) else None
    if not isinstance(raw, list):
        return []
    peers: list[Peer] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        target = str(entry.get("target") or "").strip()
        if not name or not target or name in seen:
            continue
        seen.add(name)
        peers.append(Peer(name=name, target=target,
                          token=str(entry.get("token") or "")))
    token_counts: dict[str, int] = {}
    for peer in peers:
        if peer.token:
            token_counts[peer.token] = token_counts.get(peer.token, 0) + 1
    return [
        Peer(
            name=peer.name,
            target=peer.target,
            token=peer.token if token_counts.get(peer.token, 0) == 1 else "",
        )
        for peer in peers
    ]


def _match_token(peers: Iterable[Peer], token: str) -> Peer | None:
    """Constant-time token -> peer; ``None`` when nothing matches (fail-closed).

    Scans every peer without an early exit so timing doesn't reveal which
    entry matched; a peer configured with an empty token never authenticates.
    """
    presented = token or ""
    matched: Peer | None = None
    matches = 0
    for p in peers:
        if p.token and text_equals(p.token, presented):
            matches += 1
            if matched is None:
                matched = p
    return matched if matches == 1 else None


def _to_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _default_record(kind: str, **kw: Any) -> None:
    """Default audit seam -> :func:`maverick.audit.record`. Never raises:
    an audit-path failure must not break a delegation (the writer itself is
    already fail-safe; this also covers a stripped/vendored audit package)."""
    try:
        from .audit import record
        record(kind, **kw)
    except Exception as e:
        log.warning("federation: audit record failed: %s", e)


def _acceptance_record(kind: str, *, agent="federation", goal_id=None, **payload) -> bool:
    """An actual sink acknowledgment, with no fallback from configured signing."""
    from .audit import AuditEvent, default_audit_log
    sink = default_audit_log()
    event = AuditEvent(ts=time.time(), kind=kind, agent=agent, goal_id=goal_id, payload=payload)
    if sink.signing_enabled:
        return sink.record_strict_signed(event)
    return sink.record(event)


def _redact(text: str) -> str:
    """Strip detectable secrets from one field or fail closed."""
    try:
        from .safety.secret_detector import redact
        out, _ = redact(str(text or ""))
        return out
    except Exception as e:
        # This value is about to cross a trust boundary. Returning the original
        # text on detector failure is a silent data-loss-prevention bypass.
        raise FederationError("federation egress redaction unavailable") from e


def _shield_block(text: str) -> str | None:
    """Shield-scan external agent text; a block reason, or ``None`` to allow.

    Delegates to :func:`maverick.shield_policy.scan_block`, so the
    fail-toward-gate behaviour (scan error blocks; a *missing* shield blocks only
    when the shield is required — enterprise/`require_shield`) is consistent
    across every external surface. Callers invoke this only when the trust plane
    is engaged.
    """
    from .shield_policy import scan_block
    return scan_block(text)


def _screen_result(result: str) -> str:
    """Screen a delegated goal's result before it is returned to the peer.

    The result was produced here and may quote local tools or files, so when
    the trust plane is engaged it gets the same egress screening as outbound
    delegation text: Shield-scanned, then redacted. A block, a detector
    failure or an unreadable trust state withholds the result (fail closed);
    disengaged keeps the pass-through behaviour (kernel rule 1).
    """
    if not result:
        return result
    from . import agent_trust
    try:
        enforced, _ = agent_trust.load_trust_state()
    except Exception:
        return "result withheld: the agent trust configuration could not be read"
    if not enforced:
        return result
    try:
        block = _shield_block(result)
        if block:
            return f"result withheld: blocked by the safety screen ({block})"
        return _redact(result)
    except Exception:
        return "result withheld: the outbound safety screen is unavailable"


# -- signed identity -------------------------------------------------------

def require_signed() -> bool:
    """Must inbound delegations carry a valid signature against the peer's
    pinned key? On via ``MAVERICK_FEDERATION_REQUIRE_SIGNED`` or
    ``[agent_trust] require_signed = true``. Independent of having a pinned key:
    a peer WITH a pinned key is always signature-checked; this knob additionally
    refuses peers that have *no* pinned key (closing the shared-token-only path)."""
    env = os.environ.get("MAVERICK_FEDERATION_REQUIRE_SIGNED")
    if env is not None and env.strip() != "":
        value = env.strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
        if value in {"0", "false", "no", "off"}:
            return False
        return True
    try:
        from .config import config_source_errors, load_config

        loaded = load_config() or {}
        if config_source_errors():
            return True
        section = loaded.get("agent_trust") or {}
        if not isinstance(section, dict):
            return True
        value = section.get("require_signed", False)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on"}:
                return True
            if normalized in {"0", "false", "no", "off"}:
                return False
        return True
    except Exception:
        return True


def _delegate_envelope(
    node: str, audience: str, corr: str, title: str, description: str,
    requested_tools: Iterable[str], max_risk: str | None, deadline_ms: int,
    created_at: float,
) -> dict[str, Any]:
    """The canonical delegation body both halves sign/verify byte-for-byte.

    ``origin`` is the SIGNER's node name and ``audience`` is the intended
    receiver node. The receiver reconstructs both from local configuration, so a
    signature only verifies for the configured caller/recipient pair and cannot
    be replayed to a different trusting node.
    """
    return {
        "schema": DELEGATE_SCHEMA,
        "origin": node,
        "audience": audience,
        "created_at": created_at,
        "correlation_id": corr,
        "goal_title": title,
        "goal_description": description,
        "requested_tools": sorted(str(t) for t in requested_tools),
        "max_risk": max_risk or "",
        "deadline_ms": _to_int(deadline_ms),
    }


def _fresh(created_at: float, *, now: float | None = None) -> bool:
    if not created_at or created_at <= 0:
        return False
    now = time.time() if now is None else now
    return abs(now - created_at) <= _SIGN_FRESHNESS_S


def _replay_seen(
    sig: str,
    *,
    created_at: float | None = None,
    now: float | None = None,
    scope: str = "delegation",
    state: _FederationState | None = None,
) -> bool:
    """Check-and-remember a verified signature; True if already seen (replay).

    Retain each signature until the signed envelope can no longer pass
    :func:`_fresh`. Since freshness accepts small positive clock skew, pruning
    by first-seen time can evict a future-dated signature while it is still
    acceptable. Store the last acceptable timestamp (``created_at`` plus the
    freshness window) instead, so an in-window nonce is never dropped.
    """
    if not sig:
        return False
    now = time.time() if now is None else now
    retain_until = (
        created_at if created_at and created_at > 0 else now
    ) + _SIGN_FRESHNESS_S
    state = state or _federation_state()
    cache_key = (
        str(state.path.resolve()),
        scope,
        hashlib.sha256(sig.encode("utf-8")).hexdigest(),
    )
    with _seen_sigs_lock:
        while _seen_sigs:
            _oldest, expires_at = next(iter(_seen_sigs.items()))
            if expires_at >= now:
                break
            _seen_sigs.popitem(last=False)
        if cache_key in _seen_sigs:
            return True
    try:
        replayed = state.claim_replay(
            scope, sig, expires_at=retain_until, now=now,
        )
    except (OSError, sqlite3.Error, ValueError):
        log.error("federation: durable signature replay protection unavailable")
        return True
    with _seen_sigs_lock:
        if replayed:
            return True
        _seen_sigs[cache_key] = retain_until
        return False


def _fed_rate_limit_per_min() -> int:
    """Inbound delegations/minute per peer. Default 60; 0 disables. Mirrors
    ``MAVERICK_GRPC_RATE_LIMIT`` on the sibling gRPC API."""
    raw = os.environ.get("MAVERICK_FEDERATION_RATE_LIMIT")
    if raw is None or raw.strip() == "":
        try:
            from .config import load_config
            raw = ((load_config() or {}).get("federation") or {}).get("rate_limit", 60)
        except Exception:
            raw = 60
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return 60


def _fed_rate_ok(key: str, *, now: float | None = None) -> bool:
    """Sliding-window per-peer rate gate for inbound delegations. True to admit.

    Returns True (no-op) when the limit is 0/disabled. Sweeps idle buckets once
    the tracked-peer map exceeds ``_FED_RATE_MAX_KEYS`` so the map can't grow
    without bound on a long-running server."""
    limit = _fed_rate_limit_per_min()
    if limit <= 0:
        return True
    now = time.time() if now is None else now
    try:
        durable_allowed = _federation_state().rate_ok(key, now=now, limit=limit)
    except (OSError, sqlite3.Error, ValueError):
        log.error("federation: durable inbound rate limiter unavailable")
        return False
    if not durable_allowed:
        return False
    with _fed_rate_lock:
        cutoff = now - 60.0
        dq = _fed_rate_hits.setdefault(key, deque())
        while dq and dq[0] < cutoff:
            dq.popleft()
        if len(_fed_rate_hits) > _FED_RATE_MAX_KEYS:
            for k in [k for k, d in _fed_rate_hits.items()
                      if k != key and (not d or d[-1] < cutoff)]:
                del _fed_rate_hits[k]
        # This process-local mirror exists for diagnostics/backward-compatible
        # tests; the SQLite transaction above is the cross-worker authority.
        dq.append(now)
        return True


def _fed_auth_rate_ok(peer: str, *, now: float | None = None) -> bool:
    """Cheap token-authenticated abuse gate before signature/state work."""
    configured = _fed_rate_limit_per_min()
    if configured <= 0:
        return True
    limit = max(60, configured * 10)
    timestamp = time.time() if now is None else now
    try:
        return _federation_state().rate_ok(
            f"authenticated:{peer}", now=timestamp, limit=limit,
        )
    except (OSError, sqlite3.Error, ValueError):
        log.error("federation: durable authentication rate limiter unavailable")
        return False


def _sign_delegation(
    node: str, audience: str, corr: str, title: str, description: str,
    requested_tools: Iterable[str], max_risk: str | None, deadline_ms: int,
) -> dict[str, Any]:
    """Return ``{sig, pubkey, key_id, created_at}`` for a delegation, or ``{}``
    when signing is unavailable (no ``cryptography``) — an unsigned delegation
    is still sent (a receiver that requires a signature will refuse it)."""
    created_at = time.time()
    try:
        from . import federation_envelope
        env = _delegate_envelope(node, audience, corr, title, description,
                                 requested_tools, max_risk, deadline_ms,
                                 created_at)
        signed = federation_envelope.sign_envelope(env)
        return {"sig": signed["sig"], "pubkey": signed["pubkey"],
                "key_id": signed["key_id"], "created_at": created_at}
    except Exception as e:  # signing optional; receiver policy decides
        log.debug("federation: delegation signing unavailable: %s", e)
        return {}


# -- client half -----------------------------------------------------------

@dataclass(frozen=True)
class DelegateOutcome:
    """What :meth:`FederationNode.delegate` resolves to."""
    peer: str
    correlation_id: str
    accepted: bool
    goal_id: int | None = None  # the PEER-local goal id, when accepted
    reason: str = ""
    outcome_state: str = "rejected"
    audit_state: str = "unknown"
    execution_state: str = "unknown"


class FederationNode:
    """The client half: this node's registry of peers + outbound operations.

    ``transport_factory(peer)`` returns the transport for one peer — anything
    with ``call(method, payload) -> payload``. The default is the gRPC adapter
    behind the ``[grpc]`` extra; tests inject fakes (a
    :class:`FederationService` instance itself satisfies the seam, giving an
    in-process loopback federation). ``record`` is the audit seam (defaults to
    ``maverick.audit.record``).
    """

    def __init__(
        self,
        *,
        node: str | None = None,
        peers: list[Peer] | None = None,
        transport_factory: Any | None = None,
        record: Any | None = None,
    ):
        self.node = (node or node_name()).strip()
        self.peers: dict[str, Peer] = {
            p.name: p for p in (load_peers() if peers is None else peers)
        }
        self._transport_factory = transport_factory or _grpc_transport
        self._transports: dict[str, Any] = {}
        self._record = record or _default_record

    def peer(self, name: str) -> Peer:
        p = self.peers.get(name)
        if p is None:
            raise FederationError(f"unknown federation peer: {name!r}")
        return p

    def _call(self, peer: Peer, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        transport = self._transports.get(peer.name)
        if transport is None:
            transport = self._transport_factory(peer)
            self._transports[peer.name] = transport
        return dict(transport.call(method, payload) or {})

    def _assert_outbound(self, peer: Peer) -> None:
        """Refuse to dial a peer the trust plane forbids outbound.

        Covers ``hello``/``status`` too — not just ``delegate`` — so a peer
        marked ``direction="inbound"`` (must not be dialed) can't be probed for
        its agent card or polled. No-op when the plane is disengaged; records an
        attributed denial and raises :class:`FederationError` when engaged.
        """
        from . import agent_trust
        out = agent_trust.decide_outbound(peer.name)
        if out.denied:
            agent_trust.record_denied(peer.name, out, direction="outbound")
            raise FederationError(f"outbound to peer {peer.name!r} refused: {out.reason}")

    def hello(self, peer_name: str) -> dict[str, Any]:
        """Discovery handshake -> the peer's parsed A2A agent card.

        Refuses (raises) a peer that speaks a different protocol version or
        whose card fails A2A validation (:func:`a2a.parse_remote_card` raises
        ``ValueError``) — never delegate against a card you couldn't read.
        """
        peer = self.peer(peer_name)
        self._assert_outbound(peer)
        reply = self._call(peer, "Hello", {
            "node": self.node, "protocol": PROTOCOL, "auth_token": peer.token,
        })
        proto = str(reply.get("protocol") or "")
        if proto != PROTOCOL:
            raise FederationError(
                f"peer {peer.name!r} speaks {proto or 'no protocol'!r}, "
                f"expected {PROTOCOL!r}")
        try:
            card = json.loads(str(reply.get("agent_card_json") or ""))
        except json.JSONDecodeError as e:
            raise FederationError(
                f"peer {peer.name!r} sent an unparseable agent card: {e}") from e
        return parse_remote_card(card)

    def delegate(
        self,
        peer_name: str,
        title: str,
        description: str = "",
        *,
        requested_tools: Iterable[str] = (),
        max_risk: str | None = None,
        correlation_id: str | None = None,
        deadline_ms: int = 0,
    ) -> DelegateOutcome:
        """Delegate one goal to a peer swarm and record our "sent" audit half.

        ``requested_tools`` are REQUIRED capabilities: the peer refuses unless
        its local grant can supply every one (narrow-only on its side). The
        ``correlation_id`` (auto-generated when omitted) links the two audit
        halves; ``deadline_ms`` rides as both the RPC deadline and the peer's
        wall-clock cap for the run. Transport failures resolve to a refused
        outcome (fail-honest, like the gRPC dispatcher) — and still record the
        attempt, so a half the peer never logged shows up in reciprocity checks.
        """
        peer = self.peer(peer_name)
        if correlation_id is not None and not isinstance(correlation_id, str):
            raise FederationError("correlation_id must be a string")
        corr = (correlation_id or "").strip() or uuid.uuid4().hex
        try:
            correlation_size = len(corr.encode("utf-8"))
        except UnicodeError as e:
            raise FederationError("correlation_id is invalid") from e
        if correlation_size > _MAX_CORRELATION_ID_BYTES:
            raise FederationError("correlation_id is too long")
        # Egress control: a company governs which outside agents its agents may
        # *dial*. Disengaged -> no-op; engaged -> a peer absent from the trust
        # registry (or not permitted outbound) is refused before any connection
        # opens, and the refusal is still recorded for reciprocity.
        from . import agent_trust
        enforced, registry = agent_trust.load_trust_state()
        out = agent_trust.decide_outbound(peer.name, registry=registry,
                                          enforced=enforced)
        if out.denied:
            agent_trust.record_denied(
                peer.name, out, direction="outbound", correlation_id=corr)
            self._record(
                EventKind.FEDERATION_DELEGATE, agent="federation",
                peer_node=peer.name, correlation_id=corr, direction="sent",
                accepted=False, reason=out.reason,
            )
            return DelegateOutcome(peer=peer.name, correlation_id=corr,
                                   accepted=False, reason=out.reason)
        # Data-egress screening: delegating a goal ships its title/description to
        # a third-party swarm — the same exposure tier as a cloud LLM call. When
        # the plane is engaged, redact detectable secrets and shield-scan the
        # text before it leaves the boundary, refusing (fail-toward-gate) on a
        # block. Disengaged keeps the prior pass-through behaviour (rule 1).
        if enforced:
            block = _shield_block(title) or _shield_block(description)
            if block:
                reason = f"outbound delegation blocked by safety screen: {block}"
                agent_trust.record_denied(
                    peer.name, direction="outbound", correlation_id=corr,
                    rule="egress_screen", reason=reason)
                self._record(
                    EventKind.FEDERATION_DELEGATE, agent="federation",
                    peer_node=peer.name, correlation_id=corr, direction="sent",
                    accepted=False, reason=reason,
                )
                return DelegateOutcome(peer=peer.name, correlation_id=corr,
                                       accepted=False, reason=reason)
            try:
                title, description = _redact(title), _redact(description)
            except Exception:
                reason = "outbound delegation refused: egress redaction unavailable"
                agent_trust.record_denied(
                    peer.name, direction="outbound", correlation_id=corr,
                    rule="egress_redaction", reason=reason)
                self._record(
                    EventKind.FEDERATION_DELEGATE, agent="federation",
                    peer_node=peer.name, correlation_id=corr, direction="sent",
                    accepted=False, reason=reason,
                )
                return DelegateOutcome(
                    peer=peer.name, correlation_id=corr,
                    accepted=False, reason=reason,
                )
        tools_sorted = sorted({str(t) for t in requested_tools})
        # Sign the (post-redaction) delegation so a receiver can verify our
        # identity against our pinned key, not just our shared token. Best-effort
        # — an unsigned delegation is still sent and a receiver decides whether
        # to require the signature.
        deadline_i = _to_int(deadline_ms)
        signed = _sign_delegation(self.node, peer.name, corr, title, description,
                                  tools_sorted, max_risk, deadline_i)
        signed_complete = all(
            signed.get(field) for field in ("sig", "pubkey", "key_id", "created_at")
        )
        if require_signed() and not signed_complete:
            # A signed-required sender must not silently downgrade to the
            # shared-token-only migration path when its signer is unavailable.
            reason = "outbound signed delegation required but signing is unavailable"
            agent_trust.record_denied(
                peer.name, direction="outbound", correlation_id=corr,
                rule="signing", reason=reason)
            self._record(
                EventKind.FEDERATION_DELEGATE, agent="federation",
                peer_node=peer.name, correlation_id=corr, direction="sent",
                accepted=False, reason=reason,
            )
            return DelegateOutcome(
                peer=peer.name, correlation_id=corr,
                accepted=False, reason=reason,
            )
        payload = {
            "goal_title": title,
            "goal_description": description,
            "correlation_id": corr,
            "requested_tools": tools_sorted,
            "max_risk": max_risk or "",
            "deadline_ms": deadline_i,
            "auth_token": peer.token,
            **signed,
        }
        try:
            reply = self._call(peer, "DelegateGoal", payload)
        except Exception as e:
            log.warning("federation: delegation to %s failed: %s", peer.name, e)
            reply = {"accepted": False, "reason": f"transport error: {e}",
                     "outcome_state": "unknown"}
        accepted = bool(reply.get("accepted"))
        goal_id = _to_int(reply.get("goal_id")) or None
        reason = str(reply.get("reason") or "")
        outcome_state = str(reply.get("outcome_state") or ("accepted" if accepted else "rejected"))
        if outcome_state not in {"accepted", "rejected", "pending", "unknown"}:
            outcome_state = "unknown"
        if (not isinstance(reply.get("accepted"), bool) or
                (outcome_state == "accepted" and (not accepted or goal_id is None))):
            outcome_state = "unknown"
        accepted = accepted and outcome_state == "accepted"
        audit_state = str(reply.get("audit_state") or "unknown")
        execution_state = str(reply.get("execution_state") or "unknown")
        self._record(
            EventKind.FEDERATION_DELEGATE, agent="federation",
            peer_node=peer.name, correlation_id=corr, direction="sent",
            accepted=accepted if outcome_state in {"accepted", "rejected"} else None,
            remote_goal_id=goal_id, reason=reason, outcome_state=outcome_state,
            audit_state=audit_state, execution_state=execution_state, phase="response_observed",
        )
        return DelegateOutcome(peer=peer.name, correlation_id=corr,
                               accepted=accepted, goal_id=goal_id, reason=reason,
                               outcome_state=outcome_state, audit_state=audit_state,
                               execution_state=execution_state)

    def status(self, peer_name: str, goal_id: int) -> tuple[str, str]:
        """Poll a delegated goal -> ``(status, result)``; ``("unknown", "")``
        when the peer has no such goal."""
        peer = self.peer(peer_name)
        self._assert_outbound(peer)
        reply = self._call(peer, "GoalStatus", {
            "goal_id": _to_int(goal_id), "auth_token": peer.token,
        })
        return str(reply.get("status") or "unknown"), str(reply.get("result") or "")


# -- serve half ------------------------------------------------------------

class FederationService:
    """The serve half. Transport-agnostic: :meth:`call` takes and returns
    plain dicts, so it satisfies the same seam the client consumes (pass a
    service AS the transport for an in-process loopback federation).

    Dependency seams (all injected; production defaults in parentheses):

    * ``peers`` — who may call us + their tokens (``load_peers()``).
    * ``local_grant`` — the ``Capability`` ceiling delegations narrow against
      (``capability_from_config("federation:<node>")``); pass ``None``
      explicitly to run unrestricted (capability enforcement off).
    * ``goal_service`` — creates/dispatches/reports local goals
      (:class:`maverick.grpc_api.service.GoalService` — the world/dispatcher
      seam; the orchestrator is never imported).
    * ``record`` — the audit writer (``maverick.audit.record``).
    """

    def __init__(
        self,
        *,
        node: str | None = None,
        peers: list[Peer] | None = None,
        local_grant: Any = _UNSET,
        goal_service: Any | None = None,
        record: Any | None = None,
        state_path: Path | None = None,
    ):
        self.node = (node or node_name()).strip()
        self._peers = load_peers() if peers is None else list(peers)
        self._grant = local_grant
        self._goal_service = goal_service
        self._record = record or _default_record
        self._acceptance_record = record if record is not None else _acceptance_record
        self._state = _federation_state(state_path)

    @staticmethod
    def _delegation_digest(payload: dict[str, Any]) -> str:
        semantic = {
            "goal_title": str(payload.get("goal_title") or ""),
            "goal_description": str(payload.get("goal_description") or ""),
            "requested_tools": sorted(
                str(tool) for tool in (payload.get("requested_tools") or [])
            ),
            "max_risk": str(payload.get("max_risk") or ""),
            "deadline_ms": _to_int(payload.get("deadline_ms")),
        }
        encoded = json.dumps(
            semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _validated_correlation(
        payload: dict[str, Any],
    ) -> tuple[str, str | None]:
        raw = payload.get("correlation_id")
        corr = raw.strip() if isinstance(raw, str) else ""
        if not corr:
            return "", "correlation_id is required"
        try:
            valid = len(corr.encode("utf-8")) <= _MAX_CORRELATION_ID_BYTES
        except UnicodeError:
            valid = False
        if not valid:
            return "", "correlation_id is invalid or too long"
        return corr, None

    # Lazy so constructing the service never touches config/world unless used.
    def _local_grant(self) -> Any:
        if self._grant is _UNSET:
            try:
                from .capability import capability_from_config
                self._grant = capability_from_config(f"federation:{self.node}")
            except Exception:
                from .capability import deny_all_capability

                log.error("federation: capability policy unavailable; denying tools")
                self._grant = deny_all_capability(f"federation:{self.node}")
        return self._grant

    def _goals(self) -> Any:
        if self._goal_service is None:
            from .grpc_api.service import GoalService
            self._goal_service = GoalService()
        return self._goal_service

    def _authenticate(self, payload: dict[str, Any]) -> Peer | None:
        return _match_token(self._peers, str(payload.get("auth_token") or ""))

    def _verify_signed(
        self, peer: Peer, agent: Any, payload: dict[str, Any],
        registry: dict[str, Any], enforced: bool,
    ) -> str | None:
        """Verify the delegation's signature against the peer's pinned key.

        Returns a refusal reason, or ``None`` to proceed. Only active when the
        trust plane is engaged and the peer is registered. A peer WITH a pinned
        key is always checked (a leaked token isn't enough); a peer WITHOUT one
        is allowed through on the shared token alone unless ``require_signed`` —
        the migration path. Freshness + replay-cache guard captured signatures.
        """
        signed_required = require_signed()
        if not enforced or agent is None:
            if signed_required:
                return (
                    "signed delegation required but no enforced trust record "
                    f"with a pinned key is available for peer {peer.name!r}"
                )
            return None
        pinned = bool(getattr(agent, "pubkey", ""))
        if not pinned:
            if signed_required:
                return ("signed delegation required but no pinned key is "
                        f"configured for peer {peer.name!r}")
            return None  # migration: shared-token-only peer
        sig = str(payload.get("sig") or "")
        if not sig:
            return "signed delegation required: no signature present"
        created_at = float(payload.get("created_at") or 0)
        if not _fresh(created_at):
            return "delegation signature is stale or future-dated"
        env = _delegate_envelope(
            peer.name, self.node, str(payload.get("correlation_id") or ""),
            str(payload.get("goal_title") or ""),
            str(payload.get("goal_description") or ""),
            payload.get("requested_tools") or [],
            str(payload.get("max_risk") or "") or None,
            _to_int(payload.get("deadline_ms")),
            created_at,
        )
        env["pubkey"] = str(payload.get("pubkey") or "")
        env["key_id"] = str(payload.get("key_id") or "")
        env["sig"] = sig
        from . import agent_trust
        ok, reason = agent_trust.verify_identity(
            peer.name, env, expected_schema=DELEGATE_SCHEMA, registry=registry)
        if not ok:
            return f"delegation signature rejected: {reason}"
        if _replay_seen(
            sig,
            created_at=created_at,
            scope=f"delegation:{self.node}:{peer.name}",
            state=self._state,
        ):
            return "replayed delegation signature"
        return None

    @staticmethod
    def _governance_block(peer: Peer, decision: Any, req_risk: str | None) -> str | None:
        """Org-policy gate for accepting a delegation. Returns a refusal reason
        or ``None``. Pure no-op when no ``[governance]`` policy is configured.

        ``capability=None`` is passed deliberately: the *tool* ceiling was
        already enforced by boot negotiation, so this evaluates the org policy
        (deny/require-human action lists + risk floors) against the synthetic
        ``federation_delegate`` action, not against the agent's tool grant.
        """
        try:
            from .governance import Decision, evaluate
            verdict = evaluate("federation_delegate", risk=req_risk, capability=None)
        except Exception as e:
            log.warning("federation: governance evaluation unavailable: %s", e)
            return "org governance policy unavailable"
        if verdict.decision is Decision.DENY:
            return f"denied by org governance policy ({verdict.rule}): {verdict.reason}"
        if verdict.decision is Decision.REQUIRE_HUMAN:
            return (f"delegation requires human approval ({verdict.rule}): "
                    f"{verdict.reason} — refused (no synchronous approval path)")
        return None

    def call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Transport-seam entry point — same signature the client consumes."""
        payload = payload or {}
        if method == "Hello":
            return self.hello(payload)
        if method == "DelegateGoal":
            return self.delegate_goal(payload)
        if method == "GoalStatus":
            return self.goal_status(payload)
        raise FederationError(f"unknown federation method: {method!r}")

    def hello(self, payload: dict[str, Any]) -> dict[str, Any]:
        if self._authenticate(payload) is None:
            raise FederationAuthError("federation: missing or invalid token")
        return {
            "node": self.node,
            "protocol": PROTOCOL,
            "agent_card_json": json.dumps(build_agent_card()),
        }

    def delegate_goal(self, payload: dict[str, Any]) -> dict[str, Any]:  # noqa: C901
        corr, correlation_error = self._validated_correlation(payload)
        peer = self._authenticate(payload)
        if peer is None:
            # Forensic row, deliberately unattributed: a name offered by an
            # unauthenticated caller can't be trusted, and a row without a
            # peer field never pairs in reciprocity checks.
            self._record(
                EventKind.FEDERATION_DELEGATE, agent="federation",
                correlation_id=corr, direction="received",
                accepted=False, reason="unauthorized",
            )
            return self._refuse("unauthorized: missing or invalid token")
        if not _fed_auth_rate_ok(peer.name):
            return self._refuse_recorded(
                peer, corr, "authenticated federation rate limit exceeded",
            )
        if correlation_error:
            # Authenticate and charge malformed requests before recording them,
            # while still refusing to retain an attacker-sized identifier.
            return self._refuse_recorded(peer, corr, correlation_error)

        requested = {str(t) for t in (payload.get("requested_tools") or [])
                     if str(t).strip()}
        req_risk = str(payload.get("max_risk") or "") or None

        # Agent Trust Plane: the single gate for *external* agents. Disengaged
        # (the default) this is a no-op ALLOW with no ceiling, so behaviour is
        # unchanged. Engaged (enterprise mode or [agent_trust] enforce), a peer
        # absent from the registry is refused here even though it presented a
        # valid shared token — registry membership, direction, and the tool/risk
        # ceiling are all checked before we equip a delegation.
        from . import agent_trust
        enforced, registry = agent_trust.load_trust_state()
        decision = agent_trust.decide_inbound(
            peer.name, requested_tools=requested, max_risk=req_risk,
            registry=registry, enforced=enforced)
        if decision.denied:
            agent_trust.record_denied(
                peer.name, decision, direction="inbound", correlation_id=corr)
            return self._refuse_recorded(peer, corr, decision.reason)

        # Signed-identity: prove the caller holds the peer's pinned private key,
        # not merely a copyable shared token. No-op when disengaged or the peer
        # has no pinned key (unless require_signed). Fail-closed on bad/stale/
        # replayed signatures.
        sig_reason = self._verify_signed(peer, decision.agent, payload,
                                         registry, enforced)
        if sig_reason:
            agent_trust.record_denied(
                peer.name, direction="inbound", correlation_id=corr,
                rule="unsigned", reason=sig_reason)
            return self._refuse_recorded(peer, corr, sig_reason)

        # Org governance: accepting a delegation is itself a consequential action
        # an org policy may gate. When engaged, run it through the same PDP that
        # gates tool calls: DENY refuses; REQUIRE_HUMAN refuses fail-closed (a
        # synchronous delegation can't pause for sign-off, so it is rejected
        # pending human approval rather than silently auto-accepted). No-op with
        # no [governance] policy configured, so non-governed deployments are
        # unaffected across the board.
        if enforced:
            gov_reason = self._governance_block(peer, decision, req_risk)
            if gov_reason:
                agent_trust.record_denied(
                    peer.name, direction="inbound", correlation_id=corr,
                    rule="governance", reason=gov_reason)
                return self._refuse_recorded(peer, corr, gov_reason)

        # Screen inbound external goal text for prompt-injection before it runs
        # in our orchestrator (fail-toward-gate). Only when engaged, so the
        # default personal-agent path is unchanged (kernel rule 1).
        if enforced:
            block = (_shield_block(payload.get("goal_title"))
                     or _shield_block(payload.get("goal_description")))
            if block:
                return self._refuse_recorded(
                    peer, corr, f"inbound goal blocked by safety screen: {block}")

        # Narrow-only: the peer's request can only restrict this node's own
        # grant, and every requested tool is REQUIRED — a delegation this node
        # can't fully equip is refused rather than run half-equipped. When the
        # trust plane is engaged, the peer's registry ceiling tightens the local
        # grant too (intersection, never a broadening).
        parent = self._local_grant()
        if decision.capability is not None:
            parent = (decision.capability if parent is None
                      else parent.intersect(decision.capability,
                                            principal=f"federation:{peer.name}"))
        negotiation = negotiate_boot(
            parent,
            principal=f"federation:{peer.name}",
            requested_tools=requested or None,
            required_tools=requested or None,
            max_risk=req_risk,
        )
        if not negotiation.ok:
            return self._refuse_recorded(peer, corr, negotiation.reason)

        try:
            request_digest = self._delegation_digest(payload)
        except (TypeError, ValueError, UnicodeError):
            return self._refuse_recorded(peer, corr, "delegation payload is invalid")
        # Old completed/in-progress receipts must never be reinterpreted as a
        # fresh held reservation after upgrading. They cannot prove the audit
        # or pinned dispatch contract that this version now requires.
        try:
            legacy, cached = self._state.correlation_result(peer.name, corr, request_digest)
        except (OSError, sqlite3.Error, ValueError):
            return {"accepted": False, "goal_id": 0, "outcome_state": "unknown",
                    "reason": "legacy correlation state unavailable; retry the same correlation_id"}
        if legacy == "cached":
            return {**cached, "outcome_state": "accepted" if cached.get("accepted") else "rejected",
                    "audit_state": "unknown", "execution_state": "unknown"}
        if legacy == "conflict":
            return self._refuse_recorded(
                peer, corr,
                "correlation_id was already used with different delegation content",
            )
        if legacy == "busy":
            return {"accepted": False, "goal_id": 0, "outcome_state": "unknown",
                    "reason": "legacy execution outcome unknown; automatic replay is prohibited"}

        deadline_ms = _to_int(payload.get("deadline_ms"))
        from .federation_admission import FederationAdmissionRejected
        # Clamp the run's budget to the peer's registry ceiling (down only):
        # both wall-clock AND dollars. The parsed max_dollars is enforced on
        # the delegated run, not only advertised.
        try:
            capped_dollars, capped_wall = agent_trust.clamp_budget(
                decision.agent,
                max_wall_seconds=(deadline_ms / 1000.0) if deadline_ms > 0 else None,
            )
            return self._goals().accept_federation(
                peer=peer.name, correlation=corr, digest=request_digest,
                title=str(payload.get("goal_title") or ""),
                description=str(payload.get("goal_description") or ""),
                max_dollars=capped_dollars,
                max_wall_seconds=capped_wall,
                capability=negotiation.granted,
                record=self._acceptance_record,
                admit_new=lambda: _fed_rate_ok(f"peer:{peer.name}"),
            )
        except FederationAdmissionRejected as e:
            return self._refuse_recorded(peer, corr, str(e))
        except Exception:
            log.exception(
                "federation: delegated goal creation failed for peer %s",
                peer.name,
            )
            return {"accepted": False, "goal_id": 0, "outcome_state": "unknown",
                    "reason": "delegation admission unavailable; retry the same correlation_id"}

    def goal_status(self, payload: dict[str, Any]) -> dict[str, Any]:
        peer = self._authenticate(payload)
        if peer is None:
            raise FederationAuthError("federation: missing or invalid token")
        st = self._goals().status(_to_int(payload.get("goal_id")))
        if st is None:
            return {"status": "unknown", "result": ""}
        # Owner-scope the poll: a peer may only read the status/result of goals
        # IT delegated. A goal owned by a different peer (or a locally created
        # goal with no federation owner) is reported as "unknown" — identical to
        # a non-existent id, so cross-peer probing can't even confirm existence.
        if getattr(st, "owner", "") != f"federation:{peer.name}":
            return {"status": "unknown", "result": ""}
        return {"status": str(st.status), "result": _screen_result(str(st.result or ""))}

    @staticmethod
    def _refuse(reason: str) -> dict[str, Any]:
        return {"accepted": False, "goal_id": 0, "reason": reason, "outcome_state": "rejected"}

    def _refuse_recorded(self, peer: Peer, corr: str, reason: str) -> dict[str, Any]:
        """Refuse, recording our "received" half so the caller's "sent" row
        still reciprocates (a refusal is a cross-swarm event too)."""
        self._record(
            EventKind.FEDERATION_DELEGATE, agent="federation",
            peer_node=peer.name, correlation_id=corr, direction="received",
            accepted=False, reason=reason,
        )
        return self._refuse(reason)


# -- gRPC binding (thin adapter over the dict seam; [grpc] extra, all lazy) --

_PROTO = Path(__file__).with_name("grpc_api") / "federation.proto"


def _require_grpc():
    try:
        import grpc
    except ImportError as e:
        raise ImportError(
            "grpc not installed (needed for federated swarms over gRPC). "
            "Run: python -m pip install -e './packages/maverick-core[grpc]'"
        ) from e
    return grpc


def _validate_stub_contract(pb2) -> None:
    """Refuse an old installed descriptor before opening any transport.

    Numeric field types are the protobuf descriptor wire constants (bool=8,
    int64=3, string=9). Checking descriptors requires no protobuf import and
    never tries to replace a message already registered in its default pool.
    """
    descriptor = getattr(getattr(pb2, "DelegateResult", None), "DESCRIPTOR", None)
    fields = getattr(descriptor, "fields_by_name", {})
    required = (
        ("accepted", 1, 8), ("goal_id", 2, 3), ("reason", 3, 9),
        ("outcome_state", 4, 9), ("audit_state", 5, 9), ("execution_state", 6, 9),
    )
    for name, number, field_type in required:
        field = fields.get(name)
        # Older descriptors expose label; newer implementations expose the
        # equivalent boolean cardinality properties without label.
        label = getattr(field, "label", None)
        optional = label == 1 if label is not None else (
            getattr(field, "is_repeated", None) is False
            and getattr(field, "is_required", None) is False
        )
        if (getattr(field, "number", None) != number or
                getattr(field, "type", None) != field_type or not optional):
            raise FederationError(
                "incompatible generated federation stubs: DelegateResult schema is stale or invalid; "
                "rebuild with `maverick gen-stubs` and restart the process before serving or dialing peers"
            )


def _load_stubs():
    """Import the generated pb2 modules, generating them first if absent.

    Same scheme as ``grpc_plugin_host``: stubs compile on demand from the
    bundled ``federation.proto``, rooted at the directory containing
    ``maverick/`` so the generated pair imports package-qualified
    (``from maverick.grpc_api import federation_pb2 ...``) from anywhere.
    """
    try:
        from .grpc_api import federation_pb2  # type: ignore
    except ImportError:
        from .grpc_stubs import guard_runtime_generation
        guard_runtime_generation("federation.proto")
        _generate_stubs()
        from .grpc_api import federation_pb2  # type: ignore
    _validate_stub_contract(federation_pb2)
    # Validate an existing message module even when its companion grpc module
    # is missing. Generating first could overwrite files under an old message
    # already registered in protobuf's process-global descriptor pool.
    from .grpc_api import federation_pb2_grpc  # type: ignore
    return federation_pb2, federation_pb2_grpc


def _generate_stubs() -> None:
    try:
        from grpc_tools import protoc
    except ImportError as e:
        raise ImportError(
            "grpcio-tools not installed (needed to generate stubs). "
            "Run: python -m pip install -e './packages/maverick-core[grpc]'"
        ) from e
    root = _PROTO.parents[2]
    rc = protoc.main([
        "protoc",
        f"-I{root}",
        f"--python_out={root}",
        f"--grpc_python_out={root}",
        str(_PROTO),
    ])
    if rc != 0:  # pragma: no cover -- only on a broken protoc toolchain
        raise RuntimeError(f"protoc failed to generate federation stubs (rc={rc})")


def _grpc_code():
    import grpc
    return grpc.StatusCode


def _abort(context, code, details: str):
    context.abort(code, details)
    raise PermissionError(details)  # pragma: no cover -- grpc abort always raises


class _GrpcTransport:
    """``transport.call`` over a real channel — the default client adapter."""

    def __init__(self, peer: Peer):
        self.peer = peer
        self._stub = None
        self._pb2 = None

    def _bind(self):
        if self._stub is None:
            grpc = _require_grpc()
            pb2, pb2_grpc = _load_stubs()
            from .grpc_tls import (
                _insecure_grpc_allowed,
                _is_loopback_address,
                channel_credentials,
                tls_required,
            )
            creds = channel_credentials("federation")
            if creds is not None:
                channel = grpc.secure_channel(self.peer.target, creds)
            else:
                # Refuse to ship cross-swarm data in the clear when TLS is
                # required (client-bound/enterprise). Even when optional,
                # plaintext is limited to loopback or an explicit trusted-net
                # override, symmetric with grpc_tls.bind_port on the server.
                if tls_required("federation"):
                    raise FederationError(
                        f"refusing to dial peer {self.peer.name!r} without TLS: "
                        "[federation] tls is required but not configured")
                if (
                    not _is_loopback_address(self.peer.target)
                    and not _insecure_grpc_allowed()
                ):
                    raise FederationError(
                        f"refusing to dial peer {self.peer.name!r} over plaintext "
                        f"on non-loopback target {self.peer.target!r}: configure "
                        "[federation] TLS, or set MAVERICK_ALLOW_INSECURE_GRPC=1 "
                        "for an explicitly trusted network"
                    )
                channel = grpc.insecure_channel(self.peer.target)
            self._stub = pb2_grpc.MaverickFederationStub(channel)
            self._pb2 = pb2
        return self._stub, self._pb2

    def call(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        stub, pb2 = self._bind()
        payload = payload or {}
        deadline_ms = _to_int(payload.get("deadline_ms"))
        timeout = (deadline_ms / 1000.0) if deadline_ms > 0 else _DEFAULT_RPC_TIMEOUT_S
        token = str(payload.get("auth_token") or "")
        if method == "Hello":
            r = stub.Hello(pb2.HelloRequest(
                node=str(payload.get("node") or ""),
                protocol=str(payload.get("protocol") or ""),
                auth_token=token,
            ), timeout=timeout)
            return {"node": r.node, "protocol": r.protocol,
                    "agent_card_json": r.agent_card_json}
        if method == "DelegateGoal":
            r = stub.DelegateGoal(pb2.DelegateRequest(
                goal_title=str(payload.get("goal_title") or ""),
                goal_description=str(payload.get("goal_description") or ""),
                correlation_id=str(payload.get("correlation_id") or ""),
                requested_tools=[str(t) for t in payload.get("requested_tools") or []],
                max_risk=str(payload.get("max_risk") or ""),
                deadline_ms=deadline_ms,
                auth_token=token,
                sig=str(payload.get("sig") or ""),
                pubkey=str(payload.get("pubkey") or ""),
                key_id=str(payload.get("key_id") or ""),
                created_at=float(payload.get("created_at") or 0.0),
            ), timeout=timeout)
            return {"accepted": r.accepted, "goal_id": r.goal_id, "reason": r.reason,
                    "outcome_state": getattr(r, "outcome_state", ""),
                    "audit_state": getattr(r, "audit_state", ""),
                    "execution_state": getattr(r, "execution_state", "")}
        if method == "GoalStatus":
            r = stub.GoalStatus(pb2.StatusRequest(
                goal_id=_to_int(payload.get("goal_id")), auth_token=token,
            ), timeout=timeout)
            return {"status": r.status, "result": r.result}
        raise FederationError(f"unknown federation method: {method!r}")


def _grpc_transport(peer: Peer) -> _GrpcTransport:
    return _GrpcTransport(peer)


def _servicer(service: FederationService, pb2, pb2_grpc):
    """Map protobuf messages <-> the dict payloads :class:`FederationService`
    speaks. Auth refusals on Hello/GoalStatus abort UNAUTHENTICATED;
    DelegateGoal refusals are in-band per the proto contract."""

    class MaverickFederationServicer(pb2_grpc.MaverickFederationServicer):
        def Hello(self, request, context):
            try:
                reply = service.call("Hello", {
                    "node": request.node,
                    "protocol": request.protocol,
                    "auth_token": request.auth_token,
                })
            except FederationAuthError as e:
                _abort(context, _grpc_code().UNAUTHENTICATED, str(e))
                raise  # if context.abort() didn't raise (mocks), don't fall
                # through to reference the unbound `reply`
            return pb2.PeerInfo(
                node=reply["node"], protocol=reply["protocol"],
                agent_card_json=reply["agent_card_json"],
            )

        def DelegateGoal(self, request, context):
            del context  # refusals are in-band
            reply = service.call("DelegateGoal", {
                "goal_title": request.goal_title,
                "goal_description": request.goal_description,
                "correlation_id": request.correlation_id,
                "requested_tools": list(request.requested_tools),
                "max_risk": request.max_risk,
                "deadline_ms": request.deadline_ms,
                "auth_token": request.auth_token,
                # Optional signed-identity fields (additive proto fields); use
                # getattr so an older stub or a partial message degrades to
                # unsigned rather than raising.
                "sig": getattr(request, "sig", ""),
                "pubkey": getattr(request, "pubkey", ""),
                "key_id": getattr(request, "key_id", ""),
                "created_at": getattr(request, "created_at", 0.0),
            })
            return pb2.DelegateResult(
                accepted=bool(reply.get("accepted")),
                goal_id=_to_int(reply.get("goal_id")),
                reason=str(reply.get("reason") or ""),
                outcome_state=str(reply.get("outcome_state") or ""),
                audit_state=str(reply.get("audit_state") or ""),
                execution_state=str(reply.get("execution_state") or ""),
            )

        def GoalStatus(self, request, context):
            try:
                reply = service.call("GoalStatus", {
                    "goal_id": request.goal_id,
                    "auth_token": request.auth_token,
                })
            except FederationAuthError as e:
                _abort(context, _grpc_code().UNAUTHENTICATED, str(e))
                raise  # if context.abort() didn't raise (mocks), don't fall
                # through to reference the unbound `reply`
            return pb2.StatusReply(status=reply["status"], result=reply["result"])

    return MaverickFederationServicer()


def _fed_int_setting(env: str, key: str, default: int | None) -> int | None:
    """An int federation-server setting from ``env`` or ``[federation] <key>``."""
    raw = os.environ.get(env)
    if raw is None:
        try:
            from .config import load_config
            val = ((load_config() or {}).get("federation") or {}).get(key)
            raw = None if val is None else str(val)
        except Exception:
            raw = None
    if raw is None or str(raw).strip() == "":
        return default
    try:
        return max(1, int(raw))
    except ValueError:
        return default


def serve(
    address: str = _DEFAULT_ADDR,
    *,
    service: FederationService | None = None,
    max_workers: int | None = None,
):
    """Start the federation gRPC server. Returns the server handle.

    Opt-in and fail-closed twice over: refuses to start unless
    :func:`federation_enabled`, and a service with no configured peers (or
    peers without tokens) refuses every call.

    ``max_workers`` defaults to ``MAVERICK_FEDERATION_MAX_WORKERS`` /
    ``[federation] max_workers`` (then 8); ``MAVERICK_FEDERATION_MAX_CONCURRENT``
    / ``[federation] max_concurrent_rpcs`` caps in-flight RPCs and defaults to
    the worker count, preventing an unbounded executor queue.
    """
    if not federation_enabled():
        raise RuntimeError(
            "federation is disabled. Opt in with MAVERICK_FEDERATION_ENABLED=1 "
            "or [federation] enabled = true in ~/.maverick/config.toml."
        )
    # Fail closed: a client-bound deployment must not serve unbound.
    from .client import require_client_binding
    require_client_binding()
    grpc = _require_grpc()
    pb2, pb2_grpc = _load_stubs()
    if service is None:
        service = FederationService()
    if max_workers is None:
        max_workers = _fed_int_setting(
            "MAVERICK_FEDERATION_MAX_WORKERS", "max_workers", 8)
    max_concurrent = _fed_int_setting(
        "MAVERICK_FEDERATION_MAX_CONCURRENT", "max_concurrent_rpcs", max_workers)
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=max_workers),
        maximum_concurrent_rpcs=max_concurrent,
    )
    pb2_grpc.add_MaverickFederationServicer_to_server(
        _servicer(service, pb2, pb2_grpc), server
    )
    # TLS when configured; fail closed if required (client-bound/enterprise).
    from .grpc_tls import bind_port
    secure = bind_port(server, address, "federation")
    server.start()
    log.info("Lightwork federation listening on %s (node=%s, %s)", address,
             service.node, "TLS" if secure else "plaintext")
    return server


__all__ = [
    "PROTOCOL",
    "Peer",
    "DelegateOutcome",
    "FederationError",
    "FederationAuthError",
    "FederationNode",
    "FederationService",
    "federation_enabled",
    "load_peers",
    "node_name",
    "serve",
]

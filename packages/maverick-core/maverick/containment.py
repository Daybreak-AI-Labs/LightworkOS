"""Containment mode: a no-egress, ephemeral-filesystem run profile
.

For goals that handle untrusted input (a suspicious attachment, a scraped
repo, an unvetted plugin) the safe posture is "nothing leaves, nothing
persists": no network egress and a workspace that vanishes with the run. The
kernel already has every individual seam — this module only *composes* them
into one switchable profile; it deliberately modifies no sandbox backend.

What enforces "no egress":

* **Container backends** deny at the engine level: ``DockerBackend`` /
  ``PodmanBackend`` default to ``allow_network=False`` (``--network none``)
  and ``FirecrackerBackend`` to ``network="egress-deny"`` — containment
  relies on those defaults and never weakens them.
* **In-process tools** are the real egress path on the default
  ``LocalBackend`` (which has no packet-level deny — documented in
  ``tools/shell.py``). The hard mechanism here is the registry ACL:
  :func:`apply` denies the exfil-capable tools (http_fetch, web_search,
  browser, websocket, the send-ish connectors, the named service clients in
  :data:`DEFAULT_DENY_TOOLS` and every deferrable REST connector the registry
  holds) via ``registry.set_acl``. The list is by name: a tool that is not
  named and not deferrable stays allowed.
* **Egress policy layers** (``sandbox/network_policy.py``,
  ``tenant_egress.py``, ``enterprise.py``) are *config*-driven in-process
  checks — there is no ``MAVERICK_EGRESS_*`` env var to flip. The only
  env-mediated lever subprocess tooling actually respects is the standard
  proxy convention, so :func:`assert_no_network_env` black-holes
  ``HTTP(S)_PROXY``/``ALL_PROXY`` to an unroutable sink and strips
  ``NO_PROXY`` — best-effort for host subprocesses (curl/pip/requests honor
  it; a hostile raw socket does not), which is why the ACL denial above and
  the container backends carry the hard guarantee. It also sets
  ``MAVERICK_CONTAINMENT=1`` so a nested Lightwork process self-applies the
  profile.

Registry-ACL composition note: ``ToolRegistry.set_acl`` **replaces** the ACL
(see ``tools/__init__.py``), so :func:`apply` first reads the registry's
current ``_acl_allowed`` / ``_acl_denied`` / ``_acl_max_risk`` and re-submits
them with the containment denials unioned in — existing denials are
preserved, never dropped. Reading those private fields is deliberate: the
registry exposes no getter, and replacing the ACL blind would *widen* it.

Opt-in and default OFF: enable with ``MAVERICK_CONTAINMENT=1`` (env wins) or
``[containment] enabled = true``. Config may extend (never shrink) the
denied-tool set. Stdlib-only. When on, the run path applies it: the tool
registry denies the exfil tools (``tools.base_registry``), commands get no
network and a throwaway folder (``sandbox.build_sandbox`` / ``LocalBackend``)
and the task budget is capped at ``max_wall_seconds`` (``budget``).
"""
from __future__ import annotations

import logging
import math
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ._envparse import coerce_bool
from .file_lock import ensure_private_directory

log = logging.getLogger(__name__)

# An unroutable proxy sink: 127.0.0.1:9 ("discard") is refused on any sane
# host, so proxy-honoring clients (curl, wget, pip, requests, httpx, git)
# fail fast instead of egressing. Advisory by nature — see module docstring.
NO_EGRESS_PROXY = "http://127.0.0.1:9"

_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
               "http_proxy", "https_proxy", "all_proxy")
_PROXY_BYPASS_VARS = ("NO_PROXY", "no_proxy")

# Tools whose purpose is to reach another host: generic HTTP/web/browser/
# websocket/DNS, the send-ish messaging connectors, and the built-in service
# clients that are not part of the deferred connector long tail. :func:`apply`
# also denies every name the registry marks deferrable (the REST connector
# long tail, all of which call a remote API). A tool outside both sets is
# allowed, so a new network tool must be added here.
DEFAULT_DENY_TOOLS = frozenset({
    "http_fetch", "web_search", "browser", "websocket", "webrtc",
    "email", "gmail", "ses", "sns", "twilio",
    "slack_bot", "discord_bot", "teams", "notify",
    "dns_lookup", "web_archive", "openapi_runner",
    "github_issues", "github_search", "github_actions", "github_repo_search",
    "gitlab", "gitlab_issues", "jira", "linear", "notion", "stripe",
    "wikipedia", "arxiv", "semantic_scholar", "hackernews", "huggingface",
    "youtube", "geocode", "translate", "currency",
})

_DEFAULT_MAX_WALL_SECONDS = 1800.0


@dataclass(frozen=True)
class ContainmentProfile:
    """What a contained run is locked down to. Frozen: a profile is policy."""

    no_network: bool = True
    ephemeral_workspace: bool = True
    deny_tools: frozenset[str] = DEFAULT_DENY_TOOLS
    # Contained runs are for untrusted input; an untrusted payload that can
    # stall forever still burns budget, so the profile carries a wall cap the
    # runner clamps its Budget.max_wall_seconds to.
    max_wall_seconds: float = _DEFAULT_MAX_WALL_SECONDS


@dataclass(frozen=True)
class ContainmentReport:
    """What :func:`apply` actually did, for the audit record."""

    denied_tools: frozenset[str]          # containment's denials
    preserved_denials: frozenset[str]     # ACL denials that already existed
    no_network: bool
    env_keys_set: tuple[str, ...]         # sandbox_env keys written
    ephemeral_workspace: bool             # caller must mount make_ephemeral_workdir()
    max_wall_seconds: float


def _containment_cfg() -> dict:
    try:
        from .config import load_config
        return (load_config() or {}).get("containment") or {}
    except Exception:  # config must never block a safety profile
        return {}


def _unreadable_containment_sources() -> list[str]:
    """Unreadable configuration sources whose raw text mentions containment.

    The fail-soft loader replaced such a file with defaults, so a
    ``[containment]`` table it held may have been lost. Only those files are
    evidence that containment was configured: the bytes are searched, never
    parsed. A source whose bytes cannot be read gives no evidence.
    """
    try:
        from .config import config_source_errors
        errors = config_source_errors(include_tenant=True)
    except Exception:
        return []
    found = []
    for source in errors:
        try:
            raw = Path(source).read_bytes()
        except OSError:
            continue
        if b"containment" in raw.lower():
            found.append(str(source))
    return found


def status() -> dict:
    """Whether containment is on and why, for status surfaces.

    ``reason`` is ``"environment"``, ``"configuration"``,
    ``"unreadable_configuration"`` (on because a source that mentions
    containment could not be read; ``sources`` names it) or ``"off"``.
    ``message`` is a plain sentence for people, empty when it is off.
    """
    env = os.environ.get("MAVERICK_CONTAINMENT", "").strip()
    if env:
        on = coerce_bool(env, default=True)
        return {"enabled": on, "reason": "environment" if on else "off", "sources": [],
                "message": "Locked-down mode is on (MAVERICK_CONTAINMENT)." if on else ""}
    cfg = _containment_cfg()  # loads first: the loader records unreadable sources
    sources = _unreadable_containment_sources()
    if sources:
        return {"enabled": True, "reason": "unreadable_configuration", "sources": sources,
                "message": (f"Locked-down mode is on because {', '.join(sources)} could not "
                            "be read; fix that file to restore your setting.")}
    value = cfg.get("enabled")
    on = False if value is None else coerce_bool(value, default=True)
    return {"enabled": on, "reason": "configuration" if on else "off", "sources": [],
            "message": "Locked-down mode is on ([containment] enabled)." if on else ""}


def enabled() -> bool:
    """Opt-in, off by default. ``MAVERICK_CONTAINMENT=1`` (env wins) or
    ``[containment] enabled = true``.

    Fails closed: an env value that is neither a recognised true nor false
    token, a non-boolean config value, and an unreadable configuration source
    whose text mentions containment (its table may have been lost) all turn
    containment on. Another unreadable source leaves the readable result.
    """
    current = status()
    if current["reason"] == "unreadable_configuration":
        log.warning("%s", current["message"])
    return bool(current["enabled"])


def profile_from_config() -> ContainmentProfile:
    """Build the profile from ``[containment]`` (fail-soft; defaults intact).

    ``deny_tools`` in config *extends* :data:`DEFAULT_DENY_TOOLS` — a config
    list can add a deployment's own connectors but can never re-open the
    built-in exfil set (weakening containment takes code, not a typo).
    """
    cfg = _containment_cfg()
    deny = set(DEFAULT_DENY_TOOLS)
    extra = cfg.get("deny_tools")
    if isinstance(extra, (list, tuple, set)):
        deny.update(str(t) for t in extra if str(t).strip())
    try:
        wall = float(cfg.get("max_wall_seconds", _DEFAULT_MAX_WALL_SECONDS))
    except (TypeError, ValueError):
        wall = _DEFAULT_MAX_WALL_SECONDS
    if not math.isfinite(wall) or wall <= 0:
        wall = _DEFAULT_MAX_WALL_SECONDS
    return ContainmentProfile(
        no_network=bool(cfg.get("no_network", True)),
        ephemeral_workspace=bool(cfg.get("ephemeral_workspace", True)),
        deny_tools=frozenset(deny),
        max_wall_seconds=wall,
    )


def active_profile() -> ContainmentProfile | None:
    """The profile every run is locked to now, or ``None`` when containment is
    off. The run path consults this at its three seams: the tool registry
    (denied tools), the work area (no network, throwaway folder) and the task
    budget (wall-clock cap)."""
    return profile_from_config() if enabled() else None


def assert_no_network_env(env: dict) -> dict:
    """Return a copy of ``env`` asserting the no-egress property for children.

    Black-holes the standard proxy variables to :data:`NO_EGRESS_PROXY`,
    strips the proxy-bypass vars, and marks ``MAVERICK_CONTAINMENT=1`` so a
    nested Lightwork self-applies containment. This is the *only* env-mediated
    egress mechanism the codebase's subprocess paths respect (the policy
    modules are config-driven, the container backends engine-driven); it is
    best-effort for arbitrary host subprocesses — the registry ACL denial in
    :func:`apply` and the container backends' ``--network none`` defaults are
    the load-bearing layers.
    """
    out = dict(env)
    for var in _PROXY_VARS:
        out[var] = NO_EGRESS_PROXY
    for var in _PROXY_BYPASS_VARS:
        out.pop(var, None)
    out["MAVERICK_CONTAINMENT"] = "1"
    return out


def apply(profile: ContainmentProfile, *, registry, sandbox_env: dict) -> ContainmentReport:
    """Apply ``profile`` to a run's seams; return what was done.

    * Tool surface: unions ``profile.deny_tools`` and the registry's
      deferrable connector names into the registry ACL.
      ``set_acl`` replaces the whole ACL, so the existing allowed/denied/
      max_risk are read back first and preserved (see module docstring).
    * Network: when ``profile.no_network``, updates ``sandbox_env`` in place
      with :func:`assert_no_network_env`'s variables (the caller passes this
      env to its sandbox / subprocesses).
    * Workspace: not created here — the caller mounts
      :func:`make_ephemeral_workdir`; the report records that obligation.
    """
    preserved = frozenset(getattr(registry, "_acl_denied", set()) or set())
    # Why the tools are denied, for the registry's denial message; set only
    # when containment is on because configuration could not be read.
    current = status()
    registry.acl_denial_note = (current["message"]
                                if current["reason"] == "unreadable_configuration" else "")
    connectors = frozenset(getattr(registry, "deferrable_names", set()) or set())
    denied = frozenset(profile.deny_tools) | connectors
    if denied:
        allowed = set(getattr(registry, "_acl_allowed", set()) or set())
        max_risk = getattr(registry, "_acl_max_risk", None)
        registry.set_acl(
            allowed=allowed,
            denied=set(preserved) | set(denied),
            max_risk=max_risk,
        )
    env_keys: tuple[str, ...] = ()
    if profile.no_network:
        hardened = assert_no_network_env(sandbox_env)
        sandbox_env.clear()
        sandbox_env.update(hardened)
        env_keys = tuple(sorted((*_PROXY_VARS, "MAVERICK_CONTAINMENT")))
    report = ContainmentReport(
        denied_tools=denied,
        preserved_denials=preserved,
        no_network=profile.no_network,
        env_keys_set=env_keys,
        ephemeral_workspace=profile.ephemeral_workspace,
        max_wall_seconds=profile.max_wall_seconds,
    )
    log.info(
        "containment applied: %d tools denied (%d pre-existing preserved), "
        "no_network=%s, ephemeral_workspace=%s, max_wall=%.0fs",
        len(report.denied_tools), len(preserved),
        profile.no_network, profile.ephemeral_workspace, profile.max_wall_seconds,
    )
    return report


@dataclass
class EphemeralWorkdir:
    """A throwaway workspace. ``path`` exists (0700) until :meth:`cleanup`.

    Backed by :class:`tempfile.TemporaryDirectory`, so even without an
    explicit ``cleanup()`` the directory is removed at interpreter exit
    (finalizer) — "ephemeral" must not depend on the happy path.
    """

    path: Path
    _tmp: tempfile.TemporaryDirectory = field(repr=False)

    def cleanup(self) -> None:
        """Remove the workspace tree. Idempotent."""
        try:
            self._tmp.cleanup()
        except OSError:  # already gone / exotic FS race
            pass


def make_ephemeral_workdir(prefix: str = "maverick-contained-") -> EphemeralWorkdir:
    """Create the throwaway workspace a contained run mounts as its workdir.

    Lives under the system temp dir — never under ``~/.maverick`` or the real
    workspace, so nothing the goal writes can land in persistent state. Mode
    is forced to 0700 (``mkdtemp`` default, asserted anyway: a permissive
    umask or exotic tempdir must not open the contained scratch to other
    users).
    """
    tmp = tempfile.TemporaryDirectory(prefix=prefix)
    path = Path(tmp.name)
    # Nothing is placed in the scratch directory until its effective Windows
    # DACL / POSIX mode has been verified as owner-only.
    ensure_private_directory(path)
    return EphemeralWorkdir(path=path, _tmp=tmp)


__all__ = [
    "ContainmentProfile",
    "ContainmentReport",
    "EphemeralWorkdir",
    "DEFAULT_DENY_TOOLS",
    "NO_EGRESS_PROXY",
    "active_profile",
    "enabled",
    "profile_from_config",
    "status",
    "apply",
    "assert_no_network_env",
    "make_ephemeral_workdir",
]

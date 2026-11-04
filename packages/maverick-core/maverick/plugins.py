"""Plugin SDK: discover and load third-party extensions via entry_points.

External packages can register Tools, Channels, Skills, or Personas by
declaring entry_points in their ``pyproject.toml``::

    [project.entry-points."maverick.tools"]
    weather = "myplugin:weather_tool"

    [project.entry-points."maverick.channels"]
    discordv2 = "myplugin:DiscordV2Channel"

    [project.entry-points."maverick.skills"]
    weather = "myplugin:WEATHER_SKILL"

    [project.entry-points."maverick.personas"]
    pirate = "myplugin:render_pirate"

Each loader is forgiving: a plugin that raises at load time logs the
error and is skipped -- one broken plugin can't take the swarm down.

The loader used to execute every installed
entry_point on first agent run. Anyone who `pip install`-ed a package
declaring `[project.entry-points."maverick.tools"]` got arbitrary
in-process code execution before any shield was built. Plugins now
require an explicit allowlist in config -- set ``MAVERICK_PLUGINS_ALLOW``
or ``[plugins] enabled = ["weather", ...]`` in ``~/.maverick/config.toml``.
Set ``MAVERICK_PLUGINS_ALLOW=*`` (or ``[plugins] enabled = ["*"]``) to
load everything (matches the pre-0.2 behavior). Empty / unset = no
plugins loaded.

Two further load-time controls layer on top of the allowlist:

  - **Name-squat defense.** The allowlist matches entry-point *names*, but
    any installed package can register a given name. If two distributions
    both publish the same name (e.g. an attacker shadowing ``weather``), the
    loader refuses to load it ambiguously -- the user must pin the trusted
    provider as ``[plugins] enabled = ["weather@trusted-dist"]``.
  - **Manifest permissions.** A plugin may ship a ``maverick-plugin.toml``
    (see ``plugin_manifest``) declaring the permissions it needs
    (``network`` / ``fs_write`` / ``subprocess`` / ``sensitive_envs``). The
    user grants permissions via ``[plugins] grant = [...]``. A plugin that
    requests an ungranted permission is **skipped** by default; downgrade to a
    load-with-warning with ``[plugins] enforce_permissions = false`` (or
    ``MAVERICK_PLUGINS_ENFORCE=0``).

Each plugin entry must conform to a contract:

  - ``maverick.tools``: callable that returns a ``maverick.tools.Tool``
    when invoked with no args. The tool is registered in every agent's
    base registry under its declared name.
  - ``maverick.channels``: a ``Channel`` subclass (NOT an instance --
    `maverick serve` constructs one with the handler bound).
  - ``maverick.skills``: a ``maverick.skills.Skill`` instance.
  - ``maverick.personas``: callable returning a system-prompt suffix
    string, addressed by name via ``[persona] name = "..."``.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

from .embeddable import no_cli
from .runtime_overrides import RuntimeOverridesSecurityError

log = logging.getLogger(__name__)

# Grantable permission names a manifest can request (see plugin_manifest).
_KNOWN_PERMISSIONS = ("network", "fs_write", "subprocess", "sensitive_envs")


def _plugins_config() -> dict:
    """Return the ``[plugins]`` config section, or {} (defensive)."""
    try:
        from .config import load_config
        cfg = load_config().get("plugins", {})
        return cfg if isinstance(cfg, dict) else {}
    except Exception as exc:
        log.warning(
            "plugin config read failed (%s: %s); treating as empty",
            type(exc).__name__, exc,
        )
        return {}


def _config_allowed_plugin_names() -> set[str] | None:
    """Return the set of enabled plugin names, or None if all are enabled.

    Resolution order:
      1. ``MAVERICK_PLUGINS_ALLOW`` env var (comma-separated; ``*`` = all)
      2. ``[plugins] enabled = [...]`` in ~/.maverick/config.toml
      3. Default: empty set (no plugins loaded)

    Entries may be a bare name (``weather``) or a dist-pinned ``name@dist``
    used to disambiguate a name published by more than one package.
    """
    raw = os.environ.get("MAVERICK_PLUGINS_ALLOW")
    # Treat an exported-but-blank env var as unset (common from CI/systemd/shell
    # wrappers) so it falls through to the config allowlist instead of silently
    # disabling every configured plugin.
    if raw is not None and not raw.strip():
        raw = None
    if raw is None:
        # A bare except here would swallow TOML parse errors, silently
        # disabling every plugin with no diagnostic. _plugins_config
        # logs + returns {} on failure, so a misconfigured user has something
        # to grep and we fall through to the empty (no-plugins) default.
        enabled = _plugins_config().get("enabled")
        if enabled is None:
            return set()
        if isinstance(enabled, str):
            raw = enabled
        else:
            items = {str(x).strip() for x in enabled if str(x).strip()}
            return None if "*" in items else items
    items = {p.strip() for p in raw.split(",") if p.strip()}
    if "*" in items:
        return None
    return items


def _all_installed_names() -> set[str]:
    """Every installed plugin entry-point name across the discovered groups.
    Used to concretise the allowlist when config enables all (``*``) but the
    dashboard has force-disabled one or more."""
    names: set[str] = set()
    for group in ("maverick.tools", "maverick.channels",
                  "maverick.skills", "maverick.personas"):
        try:
            for ep in _entry_points(group):
                names.add(ep.name)
        except Exception:
            pass
    return names


def _allowed_plugin_names() -> set[str] | None:
    """The config/env allowlist with the dashboard ``[plugins]`` overlay applied:
    ``enabled`` adds to it, ``disabled`` removes from it (disable wins). The
    overlay lives in ~/.maverick/runtime-overrides.toml (the dashboard plugins
    page), never config.toml."""
    base = _config_allowed_plugin_names()
    try:
        from .runtime_overrides import plugin_overlay
        on, off = plugin_overlay()
    except RuntimeOverridesSecurityError:
        raise
    except Exception:  # pragma: no cover -- overlay never breaks discovery
        on, off = set(), set()
    if not on and not off:
        return base
    if base is None:
        # config enables all; a disable is the only thing that narrows it.
        return (_all_installed_names() - off) if off else None
    return (base | on) - off


def _permission_policy() -> tuple[set[str], bool]:
    """Return ``(granted_permissions, enforce)``.

    Default is "nothing granted, ENFORCE": a plugin requesting a permission the
    operator hasn't granted is *skipped*. Manifest-less plugins declare no
    permissions, so the large body of existing plugins is unaffected. Grant with
    ``[plugins] grant = ["network", ...]``; set
    ``[plugins] enforce_permissions = false`` (or ``MAVERICK_PLUGINS_ENFORCE=0``)
    to downgrade enforcement to a warning instead of a skip.
    """
    cfg = _plugins_config()
    grant = cfg.get("grant")
    if isinstance(grant, str):
        granted = {grant.strip().lower()} if grant.strip() else set()
    elif isinstance(grant, (list, tuple, set)):
        granted = {str(x).strip().lower() for x in grant if str(x).strip()}
    else:
        granted = set()
    enforce = bool(cfg.get("enforce_permissions", True))
    env = os.environ.get("MAVERICK_PLUGINS_ENFORCE")
    if env is not None and env.strip():
        enforce = env.strip().lower() in ("1", "true", "yes")
    return granted, enforce


def _entry_points(group: str):
    """Iterate entry_points for a group. Empty iterable if none registered.

    Wrapper handles the stdlib API drift between Python 3.10 and 3.12+.
    """
    try:
        from importlib.metadata import entry_points
    except ImportError:  # pragma: no cover -- 3.10+ always has this
        return []
    try:
        eps = entry_points(group=group)
    except TypeError:
        # 3.9 fallback (we don't support it but keep this defensive)
        eps = entry_points().get(group, [])  # type: ignore[attr-defined]
    return eps


# A workbench pin must describe the module actually loaded, not newer disk bytes
# beneath an old Python import-cache object. Reload is an explicit admin action.
_PINNED_IMPORTS: dict[tuple[str, str], tuple[object, str]] = {}


def _load_current_entry(ep):
    if _plugins_config().get("workbench", False) is not True:
        return ep.load()
    import sys

    from .plugin_lock import _dist_content_hash

    distribution = _ep_dist_name(ep)
    value = str(getattr(ep, "value", "") or "")
    module_name = value.split(":", 1)[0]
    digest = _dist_content_hash(distribution) if distribution else None
    if not digest or not module_name:
        raise ValueError("Plugin has no inspectable installed bytes; no code was imported.")
    key = (distribution, module_name)
    cached = sys.modules.get(module_name)
    previous = _PINNED_IMPORTS.get(key)
    if cached is not None and (previous is None or previous != (cached, digest)):
        raise ValueError("Plugin import cache does not match reviewed bytes. Stop affected work and explicitly reload the plugin.")
    group = str(getattr(ep, "group", ""))
    if group in _PLUGIN_GROUPS:
        from .plugin_execution_pins import check_pin
        check_pin(group, ep.name, distribution, digest)
    target = ep.load()
    if _dist_content_hash(distribution) != digest:
        raise ValueError("Plugin bytes changed during import. Reload its reviewed version before dispatch.")
    _PINNED_IMPORTS[key] = (sys.modules.get(module_name), digest)
    return target


def _load(ep, what: str) -> Any | None:
    """Resolve an entry point's target with logging on failure."""
    try:
        return _load_current_entry(ep)
    except Exception as e:
        log.warning("plugin %s.%s failed to load: %s", what, ep.name, e)
        return None


def _ep_dist_name(ep) -> str | None:
    """Best-effort distribution (package) name that provides ``ep``.

    None when it can't be determined (older metadata, test stubs). We only
    flag a name-squat when the providing distribution is *known*, so an
    unidentifiable entry point is never blocked on ambiguity grounds.
    """
    dist = getattr(ep, "dist", None)
    if dist is None:
        return None
    name = getattr(dist, "name", None)
    if name:
        return str(name)
    try:  # 3.10 fallback: name via metadata
        return str(dist.metadata["Name"])
    except Exception:
        return None


def _name_dist_map(eps) -> dict[str, set[str]]:
    """Map entry-point name -> set of distinct *known* distributions providing it.

    Used to detect name-squatting: a name backed by 2+ distributions is
    ambiguous. Entry points with an unknown distribution are not counted, so
    only proven collisions are flagged.
    """
    out: dict[str, set[str]] = {}
    for ep in eps:
        dist = _ep_dist_name(ep)
        if dist is None:
            continue
        out.setdefault(ep.name, set()).add(dist)
    return out


def _is_allowed(ep_name: str, allowlist: set[str] | None) -> bool:
    """Name-only allowlist check. allowlist=None means 'all allowed'.

    Kept for callers (e.g. ``hooks``) that gate by name without distribution
    context. The plugin loaders below use ``_allowed`` for dist-aware checks.
    """
    if allowlist is None:
        return True
    return ep_name in allowlist


def _allowed(ep_name: str, dist_name: str | None, allowlist: set[str] | None) -> bool:
    """Dist-aware allowlist check. allowlist=None means 'all allowed'.

    Matches either the bare ``name`` or the pinned ``name@dist`` form, so a
    user can disambiguate a squatted name by pinning the provider they trust.
    """
    if allowlist is None:
        return True
    if ep_name in allowlist:
        return True
    return bool(dist_name) and f"{ep_name}@{dist_name}" in allowlist


def _manifest_details(ep):
    """Return the parsed manifest and whether a file declares that contract."""
    dist = getattr(ep, "dist", None)
    if dist is None:
        return None, False
    try:
        files = list(dist.files or [])
    except Exception:
        return None, False
    for f in files:
        if getattr(f, "name", "") != "maverick-plugin.toml":
            continue
        text = None
        try:
            text = f.read_text(encoding="utf-8")
        except Exception:
            try:
                text = dist.locate_file(f).read_text(encoding="utf-8")
            except Exception:
                text = None
        if text is None:
            return None, True
        from .plugin_manifest import parse_text
        try:
            return parse_text(text, source=_ep_dist_name(ep) or "<plugin>"), True
        except Exception as exc:
            log.warning("plugin manifest could not be parsed (%s)", type(exc).__name__)
            return None, True
    return None, False


def _find_manifest(ep):
    """Return the parsed manifest, preserving legacy metadata-reader callers."""
    return _manifest_details(ep)[0]


def _requested_permissions(manifest) -> list[str]:
    """Permission names the manifest declares (regardless of grant)."""
    if manifest is None:
        return []
    perms = manifest.permissions
    requested: list[str] = []
    if perms.network:
        requested.append("network")
    if perms.fs_write:
        requested.append("fs_write")
    if perms.subprocess:
        requested.append("subprocess")
    if perms.sensitive_envs:
        requested.append("sensitive_envs")
    # RFC ``requires`` entries with no permission of their own must be
    # granted by exactly their name (``[plugins] grant``).
    requested.extend(str(r) for r in getattr(perms, "requires", ()) or ())
    return requested


def _permission_violations(manifest, granted: set[str]) -> list[str]:
    """Permissions the manifest requests that aren't in the granted set."""
    return [r for r in _requested_permissions(manifest) if r not in granted]


def _warn_permissions_advisory(ep, group: str, manifest, dist: str | None) -> None:
    """Warn that declared permissions are not operating-system confinement."""
    requested = _requested_permissions(manifest)
    if not requested:
        return
    from .plugin_isolation import isolation_mode
    log.warning(
        "plugin %s.%s (%s) declares permission(s) %s; these permissions are "
        "ADVISORY, not OS-enforced. Isolation mode %r does not confine plugin "
        "import, factory, filesystem or network access. Install trusted plugins only.",
        group, ep.name, dist or "unknown-dist", requested, isolation_mode(),
    )


def _plugin_signing_policy() -> tuple[str | None, bool, set[str]]:
    """Resolve the plugin-signing policy: ``(ca_root_pubkey, require, revoked)``.

    Driven by ``[plugins] ca_root_pubkey`` / ``require_signing`` / ``ca_revoked``
    in config, and forced on by enterprise mode. A configured root pubkey implies
    verification is required (otherwise it would be set for nothing). Default
    config sets none of these, so ``require`` is False and signing is a no-op --
    behavior is unchanged unless an operator opts in.
    """
    root = ""
    require = False
    revoked: set[str] = set()
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("plugins") or {}
        root = str(cfg.get("ca_root_pubkey") or "").strip()
        require = bool(cfg.get("require_signing"))
        rev = cfg.get("ca_revoked") or []
        if isinstance(rev, (list, tuple)):
            revoked = {str(s) for s in rev}
    except Exception:  # pragma: no cover -- config never blocks discovery
        pass
    try:
        from .enterprise import enterprise_enabled
        if enterprise_enabled():
            require = True
    except Exception:  # pragma: no cover
        pass
    # Honor the CA's *signed* CRL (maverick plugin-ca revoke), not just the
    # config list -- otherwise revoking a compromised publisher via the CA had
    # zero effect at load time. A present-but-unverifiable CRL (tampered sig /
    # bad JSON) is a security event: we can't prove a cert ISN'T revoked, so
    # fail closed (revoked=None -> verify_artifact refuses every signed plugin).
    # A genuinely-absent CRL just means "no CA revocations yet" -> config-only.
    if root:
        try:
            from .plugin_ca import PluginCA
            ca = PluginCA()
            if ca._crl_path.exists():
                revoked |= ca.revoked_serials(root_pub=root)
        except Exception:
            return (root or None, True, None)
    return (root or None, require or bool(root), revoked)


def _ep_module_name(ep) -> str:
    module = (getattr(ep, "value", "") or "").split(":", 1)[0].strip()
    if not module:
        module = getattr(ep, "module", "") or ""
    return module


def _ep_module_file(ep):
    """On-disk path of the entry point's module WITHOUT importing it."""
    from pathlib import Path
    module = _ep_module_name(ep)
    dist = getattr(ep, "dist", None)
    if not module or dist is None:
        return None
    rel = module.replace(".", "/")
    candidates = {rel + ".py", rel + "/__init__.py"}
    try:
        files = list(dist.files or [])
    except Exception:
        return None
    for f in files:
        if str(f).replace("\\", "/") in candidates:
            try:
                return Path(dist.locate_file(f))
            except Exception:
                return None
    return None


# Non-source distribution files that still execute (or steer execution) once
# the package is importable: native extensions, byte-compiled code, and .pth
# startup hooks. Hashing only ``.py`` left these OUTSIDE the signature, so a
# swapped ``.so`` ran as "verified" native code under a signed plugin. The
# on-disk coverage scan (``_ondisk_files_covered``) flags any of these that a
# tamperer dropped next to signed modules without touching the dist RECORD.
_SIGNED_ONDISK_SUFFIXES = (".so", ".pyd", ".dylib", ".pth")


def _ep_importable_files(ep) -> dict[str, str] | None:
    """Return the signed file set (relpath -> sha256) without importing code.

    Covers EVERY distribution file under the plugin's package root -- not just
    ``.py``. Native extensions (``.so``/``.pyd``/``.dylib``), byte-compiled
    ``.pyc``, and shipped data files all execute or steer execution once the
    package is importable, so a signature that hashed only ``.py`` left them
    swappable under a "verified" plugin. Also hashes any top-level ``.pth`` the
    dist ships (a site-packages ``.pth`` runs code at interpreter startup). The
    signing and verify paths both call this, so the recomputed manifest mirrors
    the signed one exactly -- an added, changed, or removed distribution file
    makes the manifests differ and verification fails closed. The signature
    bundle itself is excluded (it embeds this manifest, so it cannot hash
    itself).
    """
    module = _ep_module_name(ep)
    dist = getattr(ep, "dist", None)
    if not module or dist is None:
        return None
    top = module.split(".", 1)[0]
    module_rel = module.replace(".", "/")
    try:
        dist_files = list(dist.files or [])
    except Exception:
        return None
    files: dict[str, str] = {}
    for f in dist_files:
        rel = str(f).replace("\\", "/")
        if rel.rsplit("/", 1)[-1] == "maverick_plugin.sig.json":
            continue
        is_module = rel in {module_rel + ".py", module_rel + "/__init__.py"}
        under_pkg = rel.startswith(top + "/")
        # A .pth at the site-packages root (outside the package dir) injects
        # code at interpreter startup -- bring it inside the signature too.
        is_pth = rel.endswith(".pth") and "/" not in rel
        if not (is_module or under_pkg or is_pth):
            continue
        try:
            data = Path(dist.locate_file(f)).read_bytes()
        except Exception:
            return None
        files[rel] = hashlib.sha256(data).hexdigest()
    if module_rel + ".py" not in files and module_rel + "/__init__.py" not in files:
        return None
    return dict(sorted(files.items()))


def _ondisk_files_covered(ep, signed_rels: dict) -> bool:
    """Fail-closed: refuse if the on-disk package tree carries an auto-loading
    or native file (``.so``/``.pyd``/``.dylib``/``.pth``) absent from the signed
    manifest.

    The manifest is recomputed from the dist RECORD, which is itself an on-disk,
    editable text file -- a tamperer could drop a rogue extension next to signed
    modules WITHOUT listing it in RECORD, and RECORD-based enumeration alone
    would miss it. This walks the actual package directory as a second, RECORD-
    independent check. ``__pycache__`` is skipped (its ``.pyc`` files are
    generated at import time and are legitimately absent from the manifest).
    Returns False (deny) on any uncertainty.
    """
    module = _ep_module_name(ep)
    dist = getattr(ep, "dist", None)
    if not module or dist is None:
        return False
    top = module.split(".", 1)[0]
    try:
        pkg_dir = Path(dist.locate_file(top))
        base = pkg_dir.parent
    except Exception:
        return False
    if not pkg_dir.is_dir():
        # Single-module plugin (top.py, no package dir): nothing extra to walk.
        return True
    try:
        for p in pkg_dir.rglob("*"):
            if "__pycache__" in p.parts or not p.is_file():
                continue
            if p.suffix.lower() not in _SIGNED_ONDISK_SUFFIXES:
                continue
            rel = str(p.relative_to(base)).replace("\\", "/")
            if rel not in signed_rels:
                log.warning(
                    "plugin package %r carries un-signed file %s on disk; "
                    "refusing to load (not covered by the signed manifest)",
                    top, rel,
                )
                return False
    except Exception:
        return False
    return True


def _plugin_manifest_digest(manifest: dict) -> str:
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _expected_plugin_signature_manifest(ep) -> dict | None:
    files = _ep_importable_files(ep)
    if not files:
        return None
    return {
        "schema": "maverick-plugin-signature-manifest-v1",
        "dist": _ep_dist_name(ep) or "",
        "entry_point": getattr(ep, "name", "") or "",
        "module": _ep_module_name(ep),
        "files": files,
    }


def _ep_signature_bundle(ep):
    """The plugin's signing bundle (plugin_ca: digest/sig/cert), or ``None``.

    Convention: the publisher ships ``maverick_plugin.sig.json`` -- a
    :func:`maverick.plugin_ca.sign_digest` bundle over a manifest that binds the
    distribution, entry point, module path, and importable package file digests.
    """
    from pathlib import Path
    dist = getattr(ep, "dist", None)
    if dist is None:
        return None
    try:
        files = list(dist.files or [])
    except Exception:
        return None
    for f in files:
        if Path(str(f)).name == "maverick_plugin.sig.json":
            try:
                import json
                return json.loads(Path(dist.locate_file(f)).read_text("utf-8"))
            except Exception:
                return None
    return None


def _plugin_signature_ok(ep, root_pub: str | None, revoked: set[str]) -> bool:
    """Fail-closed plugin-artifact verification against the configured CA root.

    Returns True only when the plugin distribution carries a manifest bundle that
    chains to ``root_pub`` (cert signed by root, unexpired, unrevoked, artifact
    digest + signature valid). require_signing with no root anchor (``root_pub``
    None) cannot be satisfied safely, so it returns False.
    """
    if not root_pub:
        return False
    from .plugin_ca import verify_digest
    bundle = _ep_signature_bundle(ep)
    manifest = _expected_plugin_signature_manifest(ep)
    if not bundle or not manifest or bundle.get("manifest") != manifest:
        return False
    # The equality above proves the RECORD-listed file set matches the signed
    # manifest byte-for-byte. RECORD is itself editable on disk, so also refuse
    # if the package directory carries a native/.pth file NOT in the signed set.
    if not _ondisk_files_covered(ep, manifest.get("files", {})):
        return False
    try:
        res = verify_digest(
            _plugin_manifest_digest(manifest), bundle, root_pub=root_pub, revoked=revoked
        )
    except Exception as e:  # pragma: no cover -- verifier bug must fail closed
        log.warning("plugin signature verification error: %s", e)
        return False
    return bool(getattr(res, "ok", False))


def _compatibility_error(manifest, *, declared: bool = False) -> str:
    """Explain a declared unsupported contract without importing its add-on."""
    if (manifest is None and not declared) or (manifest is not None and manifest.is_compatible()):
        return ""
    return (
        "This add-on does not work with this version of Lightwork, or its "
        "compatibility details are invalid. Ask its publisher for a compatible release."
    )


def _entry_compatibility_error(ep) -> str:
    """Read a compatibility refusal without importing the add-on."""
    manifest, declared = _manifest_details(ep)
    return _compatibility_error(manifest, declared=declared)


def _gate(ep, group: str, allow, name_dists, granted, enforce) -> bool:
    """Decide whether ``ep`` may load: allowlist, name-squat, compatibility,
    permission and signature gates.

    Returns True to load. Never invokes the entry point, so a rejected plugin's
    code never executes.
    """
    name = ep.name
    dist = _ep_dist_name(ep)
    if not _allowed(name, dist, allow):
        log.debug("plugin %s.%s not in allowlist; skipping", group, name)
        return False
    # Name-squat: a name backed by 2+ distinct distributions is ambiguous.
    # Refuse unless the allowlist pins the exact provider as 'name@dist'.
    providers = name_dists.get(name, set())
    if len(providers) > 1:
        pinned = (
            allow is not None and dist is not None and f"{name}@{dist}" in allow
        )
        if not pinned:
            log.warning(
                "plugin name %r is provided by multiple packages %s; refusing to "
                'load ambiguously -- pin the one you trust with [plugins] '
                'enabled = ["%s@<dist>"]',
                name, sorted(providers), name,
            )
            return False
    # A declared contract must be usable before importing any add-on code.
    manifest, declared = _manifest_details(ep)
    compatibility_error = _compatibility_error(manifest, declared=declared)
    if compatibility_error:
        log.warning("plugin %s.%s (%s): %s", group, name,
                    dist or "unknown-dist", compatibility_error)
        return False
    violations = _permission_violations(manifest, granted)
    if violations:
        if enforce:
            log.warning(
                "plugin %s.%s (%s) requests ungranted permission(s) %s; skipping. "
                "Grant via [plugins] grant=[...], or set enforce_permissions=false "
                "to downgrade to a warning.",
                group, name, dist or "unknown-dist", violations,
            )
            return False
        log.warning(
            "plugin %s.%s (%s) requests permission(s) %s not in [plugins] grant; "
            "loading anyway (enforce_permissions is off).",
            group, name, dist or "unknown-dist", violations,
        )
    # Version-pinning lockfile ([plugins] lock_policy): a dist whose installed
    # version drifted from plugins.lock is refused under "enforce" (that
    # plugin only), warned under "warn", ignored under "off" (default).
    from .plugin_lock import dist_allowed_by_lock
    if not dist_allowed_by_lock(dist):
        return False
    # Plugin signing CA ([plugins] ca_root_pubkey / require_signing, or enterprise
    # mode): the entry point's module file must carry a bundle that chains to the
    # configured root. Fail-closed -- a missing/invalid signature (or
    # require_signing with no root anchor) refuses the load, so the plugin's code
    # never runs. Default config enables none of this, so it's a no-op. This is
    # the gate that makes plugin_ca.verify_artifact actually enforce trust.
    root_pub, require_sig, revoked = _plugin_signing_policy()
    if require_sig and not _plugin_signature_ok(ep, root_pub, revoked):
        log.warning(
            "plugin %s.%s (%s) failed signature verification; refusing to load. "
            "Ship a signed maverick_plugin.sig.json bundle that chains to "
            "[plugins] ca_root_pubkey, or disable require_signing for unsigned "
            "plugins.",
            group, name, dist or "unknown-dist",
        )
        return False
    # Tool-call proxies do not enforce OS permissions, and imports/factories
    # run in the host process. Declared grants are advisory in every mode.
    _warn_permissions_advisory(ep, group, manifest, dist)
    return True


def _iter_loaded(group: str, what: str):
    """Yield ``(name, target)`` for entry points in ``group`` that pass the
    allowlist + name-squat + permission gates and load successfully.

    Embedded mode (``MAVERICK_NO_CLI=1``) skips third-party auto-discovery
    entirely: a library embedder drives the toolset programmatically and
    shouldn't inherit whatever plugins happen to be installed/allowlisted in
    the host environment. The kernel's own tools/channels are unaffected.
    """
    if no_cli():
        return
    eps = list(_entry_points(group))
    if not eps:
        return
    name_dists = _name_dist_map(eps)
    allow = _allowed_plugin_names()
    granted, enforce = _permission_policy()
    for ep in eps:
        if not _gate(ep, group, allow, name_dists, granted, enforce):
            continue
        target = _load(ep, what)
        if target is None:
            continue
        yield ep.name, target


def _isolated_factory(name: str, ep_value: str, target: Callable[[], Any], *, mode: str):
    """Wrap a plugin tool factory so its CALLS run under plugin isolation.

    The factory runs in-process once and is therefore trusted code, not
    sandboxed metadata. The returned Tool's ``fn`` is replaced with a
    proxy that executes the real call via :mod:`maverick.plugin_isolation`
    (fresh subinterpreter or scrubbed subprocess, per ``[plugins] isolation``).
    """
    def factory():
        tool = target()
        from .plugin_isolation import run_isolated

        def _isolated_fn(args: dict) -> str:
            return run_isolated(ep_value, args or {}, factory=True, mode=mode)

        try:
            tool.fn = _isolated_fn
            if tool.fn is not _isolated_fn:
                raise ValueError("plugin ignored isolation wrapper")
        except Exception as exc:
            raise RuntimeError(f"plugin tool {name} cannot be isolated; refusing to load") from exc
        return tool
    return factory


def discover_tools() -> list[Any]:
    """Return a list of (name, factory) tuples for installed tool plugins.

    The factory is called with no args; it must return a Tool. We delay
    invocation because Tool constructors may need access to the
    sandbox/world that only exists per-run. With ``[plugins] isolation``
    enabled, each discovered tool's calls are routed through the isolation
    seam (see :mod:`maverick.plugin_isolation`).
    """
    from .plugin_isolation import isolation_mode
    from .plugin_telemetry import enabled as telemetry_enabled
    from .plugin_telemetry import wrap_factory as telemetry_wrap
    mode = isolation_mode()
    isolate = mode != "none"
    count = telemetry_enabled()
    out: list[tuple[str, Callable[[], Any]]] = []
    for name, target, ep_value, dist in _iter_loaded_with_value("maverick.tools", "tools"):
        if not callable(target):
            log.warning("plugin tool %s is not callable; skipping", name)
            continue
        factory = target
        if isolate:
            if not ep_value:
                log.warning("plugin tool %s has no isolation entry point; skipping", name)
                continue
            factory = _isolated_factory(name, ep_value, factory, mode=mode)
        if count:
            # Applied last so the tick covers isolated calls too.
            factory = telemetry_wrap(name, dist, factory)
        from .config import load_config
        if (load_config().get("plugins") or {}).get("workbench", False) is True:
            from .plugin_workbench import pinned_factory

            try:
                factory = pinned_factory(name, dist, factory)
            except (ValueError, PermissionError):
                log.warning("plugin tool %s has no inspectable pin; skipping this tool", name)
                continue
        out.append((name, factory))
    return out


def _iter_loaded_with_value(group: str, what: str):
    """Like _iter_loaded, but also yields the entry point's ``value``
    ("pkg.mod:attr") and dist name so callers can re-resolve the target
    out-of-process / attribute telemetry."""
    if no_cli():
        return
    eps = list(_entry_points(group))
    if not eps:
        return
    name_dists = _name_dist_map(eps)
    allow = _allowed_plugin_names()
    granted, enforce = _permission_policy()
    for ep in eps:
        if not _gate(ep, group, allow, name_dists, granted, enforce):
            continue
        target = _load(ep, what)
        if target is None:
            continue
        yield (ep.name, target, str(getattr(ep, "value", "") or ""),
               _ep_dist_name(ep))


def discover_channels() -> list[tuple[str, Any]]:
    """Return (name, Channel subclass) tuples for installed channel plugins."""
    out: list[tuple[str, Any]] = []
    for name, target, _value, dist in _iter_loaded_with_value("maverick.channels", "channels"):
        # Heuristic: anything truthy + not a string passes; we don't import
        # the Channel base here to avoid a hard dep on maverick-channels.
        if isinstance(target, str):
            log.warning("plugin channel %s loaded a string; skipping", name)
            continue
        if _plugins_config().get("workbench", False) is True:
            from .plugin_execution_pins import bind_entry
            try:
                target = bind_entry("maverick.channels", name, dist, target)
            except (ValueError, TypeError, PermissionError):
                log.warning("plugin channel %s cannot retain an exact version pin; skipping", name)
                continue
        out.append((name, target))
    return out


def discover_skills() -> list[Any]:
    """Return a list of plugin-provided Skill objects."""
    result = []
    for name, target, _value, dist in _iter_loaded_with_value("maverick.skills", "skills"):
        if _plugins_config().get("workbench", False) is True:
            from .plugin_execution_pins import bind_entry
            try:
                target = bind_entry("maverick.skills", name, dist, target)
            except (ValueError, TypeError, AttributeError, PermissionError):
                log.warning("plugin skill %s cannot retain an exact version pin; skipping", name)
                continue
        result.append(target)
    return result


def discover_personas() -> dict[str, Callable[[], str]]:
    """Return {name: renderer} for installed persona plugins."""
    out: dict[str, Callable[[], str]] = {}
    for name, target, _value, dist in _iter_loaded_with_value("maverick.personas", "personas"):
        if not callable(target):
            log.warning("plugin persona %s is not callable; skipping", name)
            continue
        if _plugins_config().get("workbench", False) is True:
            from .plugin_execution_pins import bind_entry
            try:
                target = bind_entry("maverick.personas", name, dist, target)
            except (ValueError, PermissionError):
                log.warning("plugin persona %s cannot retain an exact version pin; skipping", name)
                continue
        out[name] = target
    return out


_STATUS_GROUPS = (
    ("tools", "maverick.tools"),
    ("channels", "maverick.channels"),
    ("skills", "maverick.skills"),
    ("personas", "maverick.personas"),
)


def _status_error(exc: BaseException) -> str:
    """A bounded, secret-scrubbed plugin diagnostic safe for admin surfaces."""
    from .secrets import scrub

    detail = scrub(str(exc)).strip() or "plugin import failed"
    return f"{type(exc).__name__}: {detail}"[:500]


def _target_contract_error(group: str, target: Any) -> str:
    """Mirror the public discovery functions' post-import contract checks."""
    if target is None:
        return "the entry point loaded no object"
    if group == "maverick.tools" and not callable(target):
        return "tool entry point must be callable"
    if group == "maverick.channels" and isinstance(target, str):
        return "channel entry point must load a channel class"
    if group == "maverick.personas" and not callable(target):
        return "persona entry point must be callable"
    return ""


def _plugin_denial_status(row, ep) -> None:
    compatibility_error = _entry_compatibility_error(ep)
    row["state"] = "invalid_contract" if compatibility_error else "policy_denied"
    row["load_error"] = compatibility_error or "Blocked by the effective plugin trust policy."


def plugin_status_snapshot() -> dict[str, Any]:
    """Truthful discovery, policy, configuration, and import state.

    ``discovered`` means package metadata exposed an entry point;
    ``configured`` means the effective config/env/dashboard allowlist selected
    it; ``allowed`` means the selected entry point passed every trust gate; and
    ``loaded`` means its target imported and satisfied the same kind-specific
    contract used by ``discover_*``. Tool factories are intentionally not
    invoked here because construction belongs to a per-run sandbox/world.
    """
    allow = _allowed_plugin_names()
    try:
        from .runtime_overrides import plugin_overlay

        forced_on, forced_off = plugin_overlay()
    except RuntimeOverridesSecurityError:
        raise
    except Exception:
        forced_on, forced_off = set(), set()

    groups: dict[str, list[dict[str, Any]]] = {
        kind: [] for kind, _group in _STATUS_GROUPS
    }
    discovery_errors: list[dict[str, str]] = []
    granted, enforce = _permission_policy()
    embedded_disabled = no_cli()
    for kind, group in _STATUS_GROUPS:
        try:
            eps = list(_entry_points(group))
        except Exception as exc:
            discovery_errors.append({"kind": kind, "error": _status_error(exc)})
            continue
        name_dists = _name_dist_map(eps)
        for ep in eps:
            name = str(getattr(ep, "name", "") or "")
            dist = _ep_dist_name(ep)
            configured = _allowed(name, dist, allow)
            row: dict[str, Any] = {
                "name": name,
                "module": str(getattr(ep, "value", str(ep))),
                "distribution": dist or "",
                "discovered": True,
                "configured": configured,
                "allowed": False,
                "loaded": False,
                "state": "not_configured",
                "load_error": "",
                "forced": (
                    "on" if name in forced_on else "off" if name in forced_off else None
                ),
            }
            groups[kind].append(row)
            if not configured:
                row["load_error"] = "Not selected by the effective plugin allowlist."
                continue
            if embedded_disabled:
                row["state"] = "runtime_disabled"
                row["load_error"] = "Third-party loading is disabled in embedded mode."
                continue
            try:
                row["allowed"] = _gate(
                    ep, group, allow, name_dists, granted, enforce
                )
            except Exception as exc:
                row["state"] = "policy_error"
                row["load_error"] = _status_error(exc)
                continue
            if not row["allowed"]:
                _plugin_denial_status(row, ep)
                continue
            try:
                target = _load_current_entry(ep)
            except Exception as exc:
                row["state"] = "import_failed"
                row["load_error"] = _status_error(exc)
                continue
            contract_error = _target_contract_error(group, target)
            if contract_error:
                row["state"] = "invalid_contract"
                row["load_error"] = contract_error
                continue
            row["loaded"] = True
            row["state"] = "loaded"

    return {
        "plugins": groups,
        "allowlist_active": allow is not None,
        "discovery_errors": discovery_errors,
    }


def installed_plugins() -> dict[str, list[str]]:
    """Snapshot of all plugin slots. Used by `maverick version --plugins`."""
    return {
        "tools":     [name for name, _ in discover_tools()],
        "channels":  [name for name, _ in discover_channels()],
        "skills":    [getattr(s, "name", "<unnamed>") for s in discover_skills()],
        "personas":  list(discover_personas()),
    }


def installable_plugins() -> list[str]:
    """Plugin *packages* the operator has pre-approved for dashboard install
    (``[plugins] installable = ["pkg-a", "pkg-b"]``).

    This is the install allowlist, deliberately separate from the *load*
    allowlist (``enabled``): an empty/absent list means the dashboard installs
    nothing (fail closed). The dashboard offers exactly these as one-click
    installs -- never a free-text package name -- so a compromised token can
    only pull packages an operator already vetted, not arbitrary code."""
    raw = _plugins_config().get("installable")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [s for s in (str(x).strip() for x in raw) if s]


# A conservative dist name: no URLs, version specifiers, or shell metacharacters.
# The allowlist is matched verbatim and pip runs with argv (no shell), so an
# entry can't smuggle extra arguments even if config were tampered with.
_SAFE_PKG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")


def install_plugin(name: str, *, timeout: float = 300.0) -> dict[str, list[str]]:
    """``pip install`` an operator-allowlisted plugin package, then return the
    refreshed plugin-slot snapshot (new entry points are discoverable in this
    process immediately; their code loads on the next agent run).

    Bounded by :func:`installable_plugins`: ``name`` MUST be on the
    ``[plugins] installable`` allowlist and a plain package name (no URL /
    version spec / metacharacters). Raises ``ValueError`` otherwise or if pip
    fails. pip runs as argv (never a shell), so nothing here is injectable."""
    import subprocess
    import sys

    name = (name or "").strip()
    allow = installable_plugins()
    if not allow:
        raise ValueError(
            "plugin install is disabled: set [plugins] installable to a package "
            "allowlist in ~/.maverick/config.toml"
        )
    if name not in allow:
        raise ValueError(f"{name!r} is not on the [plugins] installable allowlist")
    if not _SAFE_PKG.match(name):
        raise ValueError(f"unsafe package name: {name!r}")
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--no-input", name],
        capture_output=True, text=True, timeout=timeout, check=False,
    )
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()[-500:]
        raise ValueError(f"pip install of {name!r} failed: {tail}")
    return installed_plugins()


# ---- hot plugin reload --------------------------

_PLUGIN_GROUPS = ("maverick.tools", "maverick.channels", "maverick.skills",
                  "maverick.personas")


def _plugin_modules(dist_name: str) -> set[str]:
    """Top-level module paths declared by ``dist_name``'s maverick entry points."""
    mods: set[str] = set()
    for group in _PLUGIN_GROUPS:
        for ep in _entry_points(group):
            if _ep_dist_name(ep) != dist_name:
                continue
            value = getattr(ep, "value", "") or ""
            module = value.split(":", 1)[0].strip()
            if module:
                mods.add(module)
    return mods


def reload_plugin(dist_name: str) -> list[str]:
    """Hot-reload one plugin distribution's code without restarting the process.

    Drops the distribution's entry-point modules (and their submodules) from
    ``sys.modules`` so the next discovery pass re-imports the *current* code on
    disk — the edit-reload-retry loop for plugin authors. Returns the module
    names dropped (empty when the dist declares no maverick entry points).

    Scope honesty: already-instantiated objects (a registered Tool from the old
    module, a running Channel) keep running old code until their owner rebuilds
    them; discovery (``discover_*``) after this returns fresh objects. The
    allowlist / name-squat / permission gates apply to the re-import exactly as
    they did to the first import.
    """
    import importlib
    import sys
    mods = _plugin_modules(dist_name)
    if not mods:
        return []
    dropped: list[str] = []
    for name in list(sys.modules):
        if any(name == m or name.startswith(m + ".") for m in mods):
            del sys.modules[name]
            dropped.append(name)
    for key in list(_PINNED_IMPORTS):
        if key[0] == dist_name:
            del _PINNED_IMPORTS[key]
    # The path finders cache directory listings (and .pyc staleness checks);
    # without this a just-edited file can re-import as the old code.
    importlib.invalidate_caches()
    log.info("hot-reloaded plugin %s: dropped %d module(s)", dist_name, len(dropped))
    return sorted(dropped)

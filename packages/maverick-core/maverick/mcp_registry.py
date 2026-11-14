"""MCP server registry: discover + install external MCP servers by name.

The remote-HTTP client transport (`mcp_client.StreamableHttpMCPClient`) and the
stdio client let Lightwork *consume* MCP servers once they're in
``[mcp_servers.<name>]``; this module is the missing **discovery + install**
layer. It reuses the generic federated catalog
(`catalog.load_catalog("mcp")`) so a registry is just a self-hostable
``<base>/mcp/index.json`` — point ``[mcp_registries] indexes`` at your own.

Unlike skills (whose installable artifact is a fetched ``SKILL.md`` verified by
``sha256``), an MCP server's installable artifact is *configuration*: a spec
(command/args/env or url/headers). A registry entry carries that spec inline.
An executable hash does not authenticate its arguments or child workloads, so
registry-sourced local commands are refused; administrators must independently
review and configure servers. Registry-provided HTTP entries are also refused
until their complete configuration can be authenticated by a trusted publisher.

Install validates the spec through `MCPServerSpec.from_config` (the same
subprocess-injection / url checks the kernel applies to hand-written config),
then applies registry-specific hardening before writing it to
``~/.maverick/config.toml`` under ``[mcp_servers.<name>]``.
"""
from __future__ import annotations

import logging
import re

from . import catalog
from .mcp_client import MCPServerSpec

log = logging.getLogger(__name__)

# Default registry host: the same awesome-maverick base the skills catalog uses
# (it serves ``/mcp/index.json`` alongside ``/skills/index.json``). Override with
# ``[mcp_registries] indexes`` in config or by passing ``indexes=`` explicitly.
DEFAULT_MCP_REGISTRIES = catalog.DEFAULT_INDEXES

_REGISTRY_EVAL_FLAGS = {
    "sh": {"-c"},
    "bash": {"-c"},
    "dash": {"-c"},
    "zsh": {"-c"},
    "fish": {"-c"},
    "ksh": {"-c"},
    "csh": {"-c"},
    "tcsh": {"-c"},
    "python": {"-c"},
    "python2": {"-c"},
    "python3": {"-c"},
    "node": {"-e", "--eval", "-p", "--print"},
    "perl": {"-e", "-E"},
    "ruby": {"-e"},
    "php": {"-r", "-B", "-R", "-E"},
    "lua": {"-e"},
    "powershell": {"-command", "-encodedcommand", "-enc"},
    "pwsh": {"-command", "-encodedcommand", "-enc"},
    "cmd": {"/c", "/k"},
}

# Commands whose pinned argv[0] is only a general-purpose interpreter,
# package/image manager, shell, or process wrapper. Its hash does not
# authenticate the script/module/package/image selected by argv. Network-fed
# registry and autonomous-learning paths must require a directly pinnable MCP
# executable instead.
_INDIRECT_STDIO_COMMANDS = frozenset({
    # Shells and Windows script hosts.
    "sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh",
    "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta",
    # Language / VM launchers.
    "python", "python2", "python3", "py", "node", "nodejs", "perl",
    "ruby", "php", "lua", "java", "javaw", "dotnet", "mono", "deno",
    "bun",
    # Package, build, and environment launchers.
    "npx", "npm", "pnpm", "yarn", "bunx", "uv", "uvx", "pip", "pip3",
    "pipx", "pipenv", "poetry", "hatch", "rye", "go", "cargo", "make",
    "cmake", "env", "busybox", "xargs", "nice", "nohup", "timeout",
    "setsid", "chroot", "sudo", "doas", "su", "systemd-run",
    # Container / remote execution front ends pin the client, not workload.
    "docker", "podman", "nerdctl", "kubectl", "flatpak", "snap", "ssh",
})

_BARE_KEY_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _configured_mcp_registries() -> list[str]:
    """Registry base URLs from ``[mcp_registries] indexes``, else the default.

    Kept separate from skills' ``[catalogs] indexes`` because MCP registries are
    typically different hosts (e.g. the official MCP registry vs an awesome-list).
    """
    try:
        from .config import load_config
        cfg = (load_config() or {}).get("mcp_registries") or {}
        indexes = cfg.get("indexes")
        if isinstance(indexes, list) and indexes:
            return [str(i).rstrip("/") for i in indexes]
    except Exception as e:  # pragma: no cover -- never block discovery on config
        log.debug("mcp registry: config read failed: %s", e)
    return [i.rstrip("/") for i in DEFAULT_MCP_REGISTRIES]


def load_mcp_registry(*, indexes: list[str] | None = None) -> list[catalog.CatalogEntry]:
    """Return merged MCP server entries across all configured registries."""
    return catalog.load_catalog(
        "mcp", indexes=indexes if indexes is not None else _configured_mcp_registries())


def resolve_mcp(name: str, *, indexes: list[str] | None = None) -> catalog.CatalogEntry | None:
    """Find a single MCP registry entry by name, or None."""
    return catalog.resolve(
        name, "mcp", indexes=indexes if indexes is not None else _configured_mcp_registries())


def _command_basename(command: str) -> str:
    """Return a normalized executable basename for registry policy checks."""
    base = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat", ".com", ".ps1"):
        if base.endswith(suffix):
            return base[:-len(suffix)]
    return base


def is_indirect_stdio_command(command: str) -> bool:
    """Whether ``command`` selects an unpinned second-stage artifact."""
    base = _command_basename(command)
    if base in _INDIRECT_STDIO_COMMANDS:
        return True
    # Version-suffixed interpreters/package launchers (python3.12, php8.3,
    # ruby3.3, node20, pip3.12) are equivalent to their unsuffixed forms.
    return bool(re.fullmatch(
        r"(?:pythonw?|node(?:js)?|perl|ruby|php|lua|pip)(?:\d+(?:\.\d+)*)?",
        base,
    ))


def _validate_registry_spec(spec: MCPServerSpec) -> None:
    """Apply extra policy for untrusted registry-sourced stdio specs.

    Operator-authored config may intentionally launch arbitrary local commands,
    but registry entries are network-fed data. Require stdio registry entries to
    pin a directly executable MCP artifact. General-purpose interpreters,
    package/image managers, remote runners, and wrappers are rejected because
    their argv[0] pin does not authenticate the selected second-stage workload.
    """
    if spec.is_http:
        return
    if spec.inherit_env or spec.env:
        raise ValueError(
            "Registry-provided stdio servers may not inherit or set process "
            "environment variables; an operator must configure them explicitly."
        )
    if not spec.pin_sha256:
        raise ValueError(
            f"MCP registry entry {spec.name!r} uses stdio command {spec.command!r} "
            "without pin_sha256; registry-installed commands must pin the "
            "executable hash"
        )
    if not re.fullmatch(r"[0-9a-f]{64}", spec.pin_sha256):
        raise ValueError(
            f"MCP registry entry {spec.name!r} requires a canonical lowercase "
            "64-hex pin_sha256"
        )
    if is_indirect_stdio_command(spec.command):
        raise ValueError(
            f"MCP registry entry {spec.name!r} uses indirect launcher "
            f"{_command_basename(spec.command)!r}; pin_sha256 authenticates "
            "argv[0], not the script, module, package, image, or remote workload"
        )
    # Reject inline-eval whether the interpreter is the command itself
    # (``sh -c``) or smuggled through argv by a wrapper (``busybox sh -c``,
    # ``env sh -c``, ``xargs sh -c``, ``nice sh -c``). Treat the command and
    # every arg position as a potential interpreter and scan the tokens that
    # follow it for that interpreter's eval flag.
    argv = [spec.command, *spec.args]
    for i, token in enumerate(argv):
        eval_flags = _REGISTRY_EVAL_FLAGS.get(_command_basename(token))
        if not eval_flags:
            continue
        lowered_flags = {flag.lower() for flag in eval_flags}
        # Single-char short eval flags (``-c``, ``-e``) can be CLUSTERED by the
        # shell/interpreter: ``sh -ec`` is exactly ``sh -e -c`` and ``python -Bc``
        # is ``python -B -c``. An exact-token check misses those, so also treat a
        # single-dash cluster that contains such a flag's letter as inline eval.
        short_flag_letters = {
            f[1] for f in lowered_flags if len(f) == 2 and f[0] == "-"
        }
        for arg in argv[i + 1:]:
            key = arg.split("=", 1)[0].lower()
            clustered = (
                key.startswith("-")
                and not key.startswith("--")
                and any(letter in key[1:] for letter in short_flag_letters)
            )
            if key in lowered_flags or clustered:
                raise ValueError(
                    f"MCP registry entry {spec.name!r} reaches interpreter "
                    f"{token!r} with inline execution flag {arg!r}; registry "
                    "entries must reference a directly pinned MCP executable"
                )


def spec_from_entry(entry: catalog.CatalogEntry) -> MCPServerSpec:
    """Build a validated MCPServerSpec from a registry entry's inline spec.

    Raises CatalogError if the entry has no inline spec, and ValueError if the
    spec is malformed or violates registry-specific untrusted-input policy."""
    if not entry.spec:
        raise catalog.CatalogError(
            f"MCP registry entry {entry.name!r} has no inline spec to install")
    # from_config applies the baseline subprocess-injection + url checks used
    # for hand-written config; registry entries then get stricter supply-chain
    # policy because they are untrusted network-fed data.
    spec = MCPServerSpec.from_config(entry.name, entry.spec)
    _validate_registry_spec(spec)
    if not spec.is_http:
        raise ValueError(
            "Registry-provided local commands cannot be authenticated as a complete "
            "workload. Configure and review local MCP servers directly instead."
        )
    raise ValueError(
        "Registry-provided MCP server configuration is not authenticated. "
        "Independently review and configure the server directly instead."
    )


def install_mcp_from_registry(name: str, *, indexes: list[str] | None = None) -> MCPServerSpec:
    """Resolve ``name`` in the registry and return a validated spec to install.

    Pure lookup + validation; the caller writes it to config (so a dry-run /
    preview is possible). Raises ValueError if the name isn't in the registry."""
    entry = resolve_mcp(name, indexes=indexes)
    if entry is None:
        raise ValueError(f"no MCP server {name!r} in the registry")
    return spec_from_entry(entry)


# ---- config mutation (dependency-free TOML, append/scan) ---------------------
#
# Python ships no stdlib TOML *writer*, and tomli_w isn't a declared dependency,
# so we emit the one ``[mcp_servers.<name>]`` table by hand (append on add,
# text-scan on remove). This is also the least-destructive approach: it leaves
# the rest of a hand-edited config.toml — comments, ordering — untouched.


def _toml_basic_string(s: str) -> str:
    out = s.replace("\\", "\\\\").replace('"', '\\"')
    out = out.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return f'"{out}"'


def _toml_value(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return _toml_basic_string(v)
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(_toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        # Inline table (env / headers are small string maps).
        inner = ", ".join(f"{_toml_key(k)} = {_toml_value(val)}" for k, val in v.items())
        return "{" + inner + "}"
    raise ValueError(f"cannot serialize {type(v).__name__} to TOML")


def _toml_key(k: str) -> str:
    return k if _BARE_KEY_RE.match(k) else _toml_basic_string(k)


def _emit_server_block(name: str, spec_dict: dict) -> str:
    lines = [f"[mcp_servers.{_toml_key(name)}]"]
    for key, val in spec_dict.items():
        if key == "name":  # the table key already carries the name
            continue
        lines.append(f"{key} = {_toml_value(val)}")
    return "\n".join(lines) + "\n"


def _load_config_dict(path):
    try:
        import tomllib  # 3.11+
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib  # type: ignore[no-redef]
    if not path.exists():
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except Exception:  # a malformed config is the caller's problem to surface
        return {}


def _config_path(path=None):
    if path is not None:
        return path
    from .config import config_path
    return config_path()


def add_mcp_server_to_config(name: str, spec_dict: dict, *, path=None) -> None:
    """Append a ``[mcp_servers.<name>]`` table to config.toml.

    Raises ValueError if a server of that name is already configured (so an
    install never silently shadows a hand-tuned entry)."""
    p = _config_path(path)
    existing = _load_config_dict(p).get("mcp_servers") or {}
    if name in existing:
        raise ValueError(
            f"MCP server {name!r} is already in config; remove it first "
            f"(maverick mcp-registry remove {name})")
    p.parent.mkdir(parents=True, exist_ok=True)
    block = _emit_server_block(name, spec_dict)
    if p.exists():
        prior = p.read_text(encoding="utf-8")
        sep = "" if prior.endswith("\n\n") else ("\n" if prior.endswith("\n") else "\n\n")
        p.write_text(prior + sep + block, encoding="utf-8")
    else:
        p.write_text(block, encoding="utf-8")


def remove_mcp_server_from_config(name: str, *, path=None) -> bool:
    """Remove the ``[mcp_servers.<name>]`` table (and any subtables) from
    config.toml by text scan. Returns True if it was present and removed.

    Text-scan (not a full TOML round-trip) so the rest of the file — comments,
    ordering, unrelated tables — is preserved byte-for-byte. The result is
    parsed before it is written: if the server is still declared (for example
    inline under ``[mcp_servers]``) or the file would no longer parse, nothing
    is written and ``ValueError`` asks the operator to edit the file."""
    p = _config_path(path)
    if not p.exists():
        return False
    if name not in (_load_config_dict(p).get("mcp_servers") or {}):
        return False
    header_re = re.compile(r"^\s*\[")
    # Matches [mcp_servers.<name>] and [mcp_servers.<name>.<sub>] (and their
    # [[...]] array forms), with the name optionally quoted, tolerating inner
    # whitespace.
    key = re.escape(name)
    target_re = re.compile(
        rf'^\s*\[\[?\s*mcp_servers\s*\.\s*(?:{key}|"{key}"|\'{key}\')\s*(?:\..*)?\]')
    out: list[str] = []
    skipping = False
    for line in p.read_text(encoding="utf-8").splitlines(keepends=True):
        if header_re.match(line):
            skipping = bool(target_re.match(line))
        if not skipping:
            out.append(line)
    text = "".join(out)
    try:
        import tomllib  # 3.11+
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib  # type: ignore[no-redef]
    try:
        remaining = tomllib.loads(text).get("mcp_servers") or {}
    except tomllib.TOMLDecodeError:
        remaining = None
    if remaining is None or name in remaining:
        raise ValueError(
            f"MCP server {name!r} could not be removed automatically; "
            f"edit {p} by hand (the file was not changed)")
    from .file_lock import atomic_write_text
    atomic_write_text(p, text, mode=0o600)
    return True


__all__ = [
    "DEFAULT_MCP_REGISTRIES",
    "load_mcp_registry",
    "resolve_mcp",
    "is_indirect_stdio_command",
    "spec_from_entry",
    "install_mcp_from_registry",
    "add_mcp_server_to_config",
    "remove_mcp_server_from_config",
]

"""Domain packs -- the unit the agent factory emits.

A :class:`DomainProfile` describes one specialist domain (finance, legal,
privacy/compliance, generic, ...): its persona, the capability envelope its
agents run under, the tools / MCP servers it may use, model overrides, and the
knowledge sources (uploaded docs) it draws on. Two authoring paths feed the
same schema:

  * hand-authored TOML packs under ``<pkg>/domains/`` (built-in) or
    ``~/.maverick/domains/`` (operator-provided), and
  * intake-generated packs (a business describes itself; we synthesize a
    profile) -- the same dataclass, marked ``authoring="generated"``.

The ``compartment`` tag is the hinge between the factory and the safety
substrate: every agent spawned from a profile inherits that tag, so a Rung-2
sector seal can quarantine an entire domain at once (see
:mod:`maverick.quarantine`).
"""
from __future__ import annotations

import functools
import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib  # 3.11+
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from ._envparse import coerce_bool
from .agent_autonomy import AutonomyProfile
from .safety.tool_risk import risk_rank, tool_risk

# Keys we accept from a pack's TOML. Unknown keys are ignored so a newer pack
# can't crash an older loader.
_FIELDS = frozenset({
    "compartment", "description", "persona", "allow_tools", "deny_tools",
    "max_risk", "allow_paths", "allow_hosts", "mcp_servers", "models",
    "knowledge_sources", "authoring", "extends", "workflow", "output", "effort",
    "refuse", "autonomy",
})

_MAX_DOMAIN_FILE_BYTES = 256 * 1024
_DOMAIN_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _unsafe_domain_alias(info) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & _REPARSE_ATTRIBUTE
    )


def _domain_file_identity(info) -> tuple:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        getattr(info, "st_mtime_ns", None),
    )


def _load_domain_toml(path: Path) -> dict:
    """Bounded, no-follow read of one identity-bound domain TOML file."""
    path = Path(path)
    before = path.lstat()
    if (
        _unsafe_domain_alias(before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
    ):
        raise ValueError("domain pack must be a private regular file")
    if before.st_size > _MAX_DOMAIN_FILE_BYTES:
        raise ValueError("domain pack exceeds the file-size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        expected = _domain_file_identity(before)
        if (
            _unsafe_domain_alias(opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _domain_file_identity(opened) != expected
        ):
            raise ValueError("domain pack changed during open")
        chunks: list[bytes] = []
        remaining = _MAX_DOMAIN_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if sum(len(chunk) for chunk in chunks) > _MAX_DOMAIN_FILE_BYTES:
            raise ValueError("domain pack exceeds the file-size limit")
        if _domain_file_identity(os.fstat(fd)) != expected:
            raise ValueError("domain pack changed during read")
    finally:
        os.close(fd)
    try:
        data = tomllib.loads(b"".join(chunks).decode("utf-8", errors="strict"))
    except UnicodeDecodeError as exc:
        raise ValueError("domain pack is not valid UTF-8") from exc
    if not isinstance(data, dict):
        raise ValueError("domain pack must contain a TOML table")
    name = data.get("name", path.stem)
    if not isinstance(name, str) or not _DOMAIN_ID_RE.fullmatch(name):
        raise ValueError("domain pack has an invalid identity")
    return data


@dataclass
class WorkflowStep:
    """One step in a pack's editable *playbook* -- the ordered procedure a
    specialist follows for its task.

    This is human-authored *guidance* (rendered into the agent's system prompt
    by :func:`render_workflow_prompt`), deliberately distinct from
    :class:`maverick.workflow.Workflow`, which *executes* a tool DAG. A client
    edits these steps to tailor how an agent works; the LLM follows them.

    A ``gate`` on an intermediate step is therefore a *prompt declaration*,
    not an executable pause point.  A gate on the terminal step is special:
    the goal release layer promotes it to the durable deliverable sign-off
    enforced by :func:`enforced_gate`.
    """
    name: str
    instruction: str = ""          # what the agent does at this step
    tools: list[str] = field(default_factory=list)  # optional tool hints
    gate: str | None = None        # prompt-declared gate: "approval" | "review"


@dataclass
class OutputContract:
    """The *consumption* side of a pack: what the specialist delivers, to whom,
    how often, and what sign-off the deliverable needs before it is acted on.

    Distinct from the capability envelope (what the agent *may do*) and the
    workflow playbook (how it *works*): this declares the *deliverable*. The
    dashboard reads it to render a result as the right kind of artifact (a
    forecast grid vs. a memo), route it to the people who consume it, and gate
    it before it is used. Absent/empty means today's behaviour exactly -- a
    free-text result with no declared consumer, rendered as prose.
    """
    shape: str = "prose"           # render archetype: prose|report|table|forecast
    deliverable: str = ""          # human label, e.g. "13-week cash forecast"
    consumers: list[str] = field(default_factory=list)  # persona roles who receive it
    cadence: str = ""              # "on-demand"|"daily"|"weekly"|"monthly"|...
    gate: str | None = None        # sign-off before the deliverable is used


@dataclass
class DomainProfile:
    name: str
    compartment: str = ""          # seal boundary; defaults to ``name``
    description: str = ""
    persona: str = ""              # system-prompt specialization
    allow_tools: list[str] = field(default_factory=list)
    deny_tools: list[str] = field(default_factory=list)
    max_risk: str | None = None
    allow_paths: list[str] = field(default_factory=list)
    allow_hosts: list[str] = field(default_factory=list)
    mcp_servers: list[str] = field(default_factory=list)
    models: dict[str, str] = field(default_factory=dict)
    knowledge_sources: list[str] = field(default_factory=list)
    authoring: str = "manual"      # "manual" | "generated"
    effort: str | None = None      # reasoning tier (applied only when [effort] on)
    refuse: list[str] = field(default_factory=list)  # pack-specific hard refusals
    extends: str = ""              # overlay base: inherit a pack, patch the rest
    workflow: list[WorkflowStep] = field(default_factory=list)  # editable playbook
    output: OutputContract = field(default_factory=OutputContract)  # the deliverable
    autonomy: AutonomyProfile | None = None  # explicit [autonomy] block; None -> suite default

    def __post_init__(self) -> None:
        if not self.compartment:
            self.compartment = self.name

    def capability(self, principal: str):
        """Build the Capability envelope agents in this domain run under.

        Ties the factory to the identity layer: the profile's tool / risk /
        path / host scopes become an attenuating grant (:mod:`maverick.capability`).
        """
        from .capability import Capability
        return Capability(
            principal=principal,
            allow_tools=frozenset(self.allow_tools),
            deny_tools=frozenset(self.deny_tools),
            max_risk=self.max_risk,
            allow_paths=frozenset(self.allow_paths),
            allow_hosts=frozenset(self.allow_hosts),
        )


def _coerce_workflow(raw: object) -> list[WorkflowStep]:
    """Turn a pack's ``[[workflow]]`` array-of-tables into ``WorkflowStep``s.

    Forgiving: a step without a name, or a non-list ``workflow``, is dropped
    rather than raising -- a malformed playbook must not break pack discovery.
    """
    steps: list[WorkflowStep] = []
    if not isinstance(raw, list):
        return steps
    for item in raw:
        if not isinstance(item, dict) or not str(item.get("name") or "").strip():
            continue
        tools = item.get("tools")
        steps.append(WorkflowStep(
            name=str(item["name"]),
            instruction=str(item.get("instruction") or ""),
            tools=[str(t) for t in tools] if isinstance(tools, list) else [],
            gate=(str(item["gate"]) if item.get("gate") else None),
        ))
    return steps


def _coerce_output(raw: object) -> OutputContract:
    """Turn a pack's ``[output]`` table into an :class:`OutputContract`.

    Forgiving like :func:`_coerce_workflow`: a missing/non-table ``output`` (or
    a stray non-list ``consumers``) yields the empty contract rather than
    raising, so a malformed block can't break pack discovery."""
    if not isinstance(raw, dict):
        return OutputContract()
    consumers = raw.get("consumers")
    return OutputContract(
        shape=str(raw.get("shape") or "prose"),
        deliverable=str(raw.get("deliverable") or ""),
        consumers=[str(c) for c in consumers] if isinstance(consumers, list) else [],
        cadence=str(raw.get("cadence") or ""),
        gate=(str(raw["gate"]) if raw.get("gate") else None),
    )


def _coerce(name: str, data: dict) -> DomainProfile:
    fields = {k: v for k, v in data.items() if k in _FIELDS}
    if "workflow" in fields:
        fields["workflow"] = _coerce_workflow(fields["workflow"])
    if "output" in fields:
        fields["output"] = _coerce_output(fields["output"])
    if "refuse" in fields:
        raw = fields["refuse"]
        fields["refuse"] = ([str(r) for r in raw] if isinstance(raw, list) else [])
    if "autonomy" in fields:
        fields["autonomy"] = AutonomyProfile.from_toml(fields["autonomy"])
    return DomainProfile(name=name, **fields)


def load_domain(path: str | Path) -> DomainProfile:
    """Parse a single domain pack from TOML."""
    path = Path(path)
    data = _load_domain_toml(path)
    return _coerce(data.get("name") or path.stem, data)


def load_domains(directory: str | Path) -> dict[str, DomainProfile]:
    """Load every ``*.toml`` pack in ``directory``. A malformed pack is skipped
    (it must not break discovery of the rest)."""
    directory = Path(directory)
    out: dict[str, DomainProfile] = {}
    if not directory.is_dir():
        return out
    for p in sorted(directory.glob("*.toml")):
        try:
            prof = load_domain(p)
        except Exception:
            continue
        out[prof.name] = prof
    return out


@functools.lru_cache(maxsize=8)
def _load_builtin_domains(directory: str, _mtime_ns: int) -> dict[str, DomainProfile]:
    """Cached load of the shipped built-in pack catalog (2,000+ packs).

    Keyed by ``(path, directory mtime)`` so adding/removing a pack invalidates
    the entry; the catalog is otherwise static for a process, so this turns the
    repeated ~700ms parse (paid on every ``available_domains()`` call, e.g. each
    /agents and /workflows render) into a one-time cost. Tenant overrides are
    NOT cached here — ``available_domains`` re-reads them live every call.
    """
    return load_domains(Path(directory))


def builtin_domains() -> dict[str, DomainProfile]:
    """The built-in catalog, memoised by the built-in dir's mtime."""
    d = builtin_dir()
    try:
        mtime_ns = d.stat().st_mtime_ns
    except OSError:
        mtime_ns = 0
    return _load_builtin_domains(str(d), mtime_ns)


def builtin_dir() -> Path:
    return Path(__file__).parent / "domains"


def user_dir() -> Path:
    """The active workspace's domains directory.

    An explicit ``MAVERICK_DOMAINS_DIR`` override still wins (tests / custom
    layouts); otherwise this is the current tenant's domains dir (per-business
    isolation), falling back to ~/.maverick/domains for the single-tenant default."""
    override = os.environ.get("MAVERICK_DOMAINS_DIR")
    if override:
        return Path(override).expanduser()
    from .workspace import Workspace
    return Workspace.current().domains_dir


def _load_raw_domains(
    directory: str | Path, *, rejected: dict[str, list[str]] | None = None,
) -> dict[str, dict]:
    """Parse every ``*.toml`` in ``directory`` to its raw dict (keys as written).

    Unlike :func:`load_domains`, this keeps *which keys a file actually set* --
    the basis for a field-level overlay, where an override patches only what it
    touched and inherits the rest. Malformed files are skipped."""
    directory = Path(directory)
    out: dict[str, dict] = {}
    if not directory.is_dir():
        return out
    for p in sorted(directory.glob("*.toml")):
        try:
            data = _load_domain_toml(p)
            if str(data.get("name") or p.stem) != p.stem:
                raise ValueError("domain pack identity does not match its file")
        except Exception:
            if rejected is not None:
                rejected[p.stem] = ["agent setup file cannot be read or parsed"]
            continue
        out[str(data.get("name") or p.stem)] = data
    return out


# A tenant override may patch any pack field except its identity (``name``,
# which selects the base) and ``extends`` (the link itself, not patched in).
_OVERLAYABLE = _FIELDS - {"extends"}


def overridden_fields(patch: dict) -> set[str]:
    """The set of pack fields a raw override dict actually customizes."""
    return {k for k in patch if k in _OVERLAYABLE}


def overlay_profile(base: DomainProfile, patch: dict) -> DomainProfile:
    """Field-level override: start from ``base`` and replace only the keys the
    override sets, so a client inherits everything it didn't touch.

    ``patch`` is the raw TOML dict of an override pack. The result keeps the
    base's ``name`` (identity is not overlaid). This is the upgrade from the old
    whole-file replacement: a tenant can change just a persona line or one
    workflow step and keep the rest of the built-in pack."""
    data: dict = {
        "compartment": base.compartment,
        "description": base.description,
        "persona": base.persona,
        "allow_tools": list(base.allow_tools),
        "deny_tools": list(base.deny_tools),
        "max_risk": base.max_risk,
        "allow_paths": list(base.allow_paths),
        "allow_hosts": list(base.allow_hosts),
        "mcp_servers": list(base.mcp_servers),
        "models": dict(base.models),
        "knowledge_sources": list(base.knowledge_sources),
        "authoring": base.authoring,
        "effort": base.effort,
        "refuse": list(base.refuse),
        "workflow": list(base.workflow),
        "output": base.output,
        "autonomy": base.autonomy,
    }
    for k in overridden_fields(patch):
        data[k] = patch[k]
    if "workflow" in patch:
        data["workflow"] = _coerce_workflow(patch["workflow"])
    if "output" in patch:
        data["output"] = _coerce_output(patch["output"])
    # autonomy is a structured field, so coerce the raw TOML table the same way
    # _coerce does on the load path. Without this the override loop above stored
    # patch["autonomy"] as a bare dict, so downstream code expecting an
    # AutonomyProfile broke; and without seeding it from base above, an overlay
    # that didn't set [autonomy] silently dropped the base pack's autonomy.
    if "autonomy" in patch:
        data["autonomy"] = AutonomyProfile.from_toml(patch["autonomy"])
    return DomainProfile(name=base.name, **data)


_RISK_RANK = {"low": 0, "medium": 1, "high": 2}


def _envelope_errors(base: DomainProfile | None, merged: DomainProfile) -> list[str]:
    """Reject an overlay that broadens the pack it inherits from."""
    if base is None:
        return []
    errors: list[str] = []
    added_tools = sorted(set(merged.allow_tools) - set(base.allow_tools))
    if added_tools:
        errors.append("allow_tools cannot add tools beyond the built-in pack: "
                      + ", ".join(added_tools))
    missing_denies = sorted(set(base.deny_tools) - set(merged.deny_tools))
    if missing_denies:
        errors.append("deny_tools cannot remove built-in denied tools: "
                      + ", ".join(missing_denies))
    base_rank = _RISK_RANK.get(str(base.max_risk or ""))
    merged_rank = _RISK_RANK.get(str(merged.max_risk or ""))
    if base_rank is not None and merged_rank is not None and merged_rank > base_rank:
        errors.append(f"max_risk cannot be raised above the built-in pack ({base.max_risk})")
    if merged.compartment != base.compartment:
        errors.append("compartment cannot differ from the built-in pack")
    for field_name in ("allow_paths", "allow_hosts"):
        inherited = set(getattr(base, field_name))
        current = set(getattr(merged, field_name))
        # Empty path/host scopes mean unrestricted. Dropping a non-empty
        # inherited scope broadens it; adding a scope to an empty one narrows.
        if inherited and (not current or not current <= inherited):
            errors.append(f"{field_name} cannot broaden the built-in pack's scope")
    added_servers = sorted(set(merged.mcp_servers) - set(base.mcp_servers))
    if added_servers:
        errors.append("mcp_servers cannot add entries beyond the built-in pack: "
                      + ", ".join(added_servers))
    return errors


def render_workflow_prompt(workflow: list[WorkflowStep]) -> str:
    """A pack's playbook as a system-prompt block (``""`` when there is none,
    so packs without a workflow behave exactly as before)."""
    if not workflow:
        return ""
    lines = ["", "", "Workflow -- follow these steps in order:"]
    for i, step in enumerate(workflow, 1):
        line = f"{i}. {step.name}"
        if step.instruction:
            line += f": {step.instruction}"
        if step.tools:
            line += f"  [tools: {', '.join(step.tools)}]"
        if step.gate:
            line += f"  [gate: {step.gate}]"
        lines.append(line)
    return "\n".join(lines)


def extends_errors(name: str, patch: dict, base: DomainProfile | None,
                   builtin_names) -> list[str]:
    """Reject an ``extends`` link that would move or drop the envelope check.

    An override that shares a built-in pack's name is always held to that
    built-in, so it cannot name another base; and a base that cannot be
    resolved must not turn the override into an unchecked standalone pack.
    """
    parent = str(patch.get("extends") or name)
    if parent == name:
        return []
    if name in builtin_names:
        return [f"{name!r} is a built-in agent; its override cannot extend {parent!r}"]
    if base is None:
        return [f"extends names {parent!r}, which is not an available agent"]
    return []


_MAX_EXTENDS_DEPTH = 32


def _resolved_catalog() -> tuple[dict[str, DomainProfile], dict[str, list[str]]]:
    """Resolve workspace packs, retaining rejected names for lint diagnostics.

    A pack is resolved after the workspace pack it extends, whatever the file
    names, so a fork always inherits its base's restrictions.
    """
    builtin = builtin_domains()
    resolved = dict(builtin)
    rejected: dict[str, list[str]] = {}
    raw = _load_raw_domains(user_dir(), rejected=rejected)
    for name in rejected:
        resolved.pop(name, None)
    done: set[str] = set()

    def resolve(name: str, depth: int) -> None:
        if name in done:
            return
        done.add(name)
        patch = raw[name]
        parent = str(patch.get("extends") or name)
        if parent != name and parent in raw and depth < _MAX_EXTENDS_DEPTH:
            resolve(parent, depth + 1)
        try:
            base = resolved.get(parent)
            profile = overlay_profile(base, patch) if base else _coerce(name, patch)
            errors = extends_errors(name, patch, base, builtin)
            if not errors:
                errors, _ = lint_profile(profile)
            if base is not None and not errors:
                errors.extend(_envelope_errors(base, profile))
        except Exception:
            # A hand-edited pack with malformed field types must not interrupt
            # discovery or become active through the workspace catalog.
            rejected[name] = ["malformed domain pack fields"]
            resolved.pop(name, None)
            return
        if errors:
            # Editor saves already apply this lint gate. Apply it to files
            # placed or synced into the workspace directory as well.
            rejected[name] = errors
            resolved.pop(name, None)
            return
        resolved[name] = profile

    for name in raw:
        resolve(name, 0)
    return resolved, rejected


def available_domains() -> dict[str, DomainProfile]:
    """Built-in packs plus lint-clean workspace packs and field-level overlays.

    A user pack matching a built-in (or declaring ``extends``) inherits fields
    it does not set. Unsafe files remain inactive until corrected.
    """
    return _resolved_catalog()[0]


def rejected_workspace_domains() -> dict[str, list[str]]:
    """Why parseable workspace packs were excluded from the active catalog."""
    return _resolved_catalog()[1]


# A pack's name prefix maps it to a business *suite* (finance, operations, legal,
# ...), so an operator can enable/disable a whole suite at once. The installer
# wizard writes the choices to ``[suites]`` in config.toml; ``enabled_domains``
# applies them.
SUITE_PREFIXES: dict[str, str] = {
    "finance_": "finance",
    "ops_": "operations",
    "legal_": "legal",
    "itgrc_": "it_grc",
    "gtm_": "sales_gtm",
    "hr_": "hr",
    "pe_": "product_engineering",
    "strat_": "strategy",
    "cx_": "customer_experience",
    "mkt_": "marketing",
    "proc_": "procurement",
    "data_": "data_analytics",
    "sec_": "security_ops",
    "exec_": "executive_office",
    "ehs_": "facilities_ehs",
    "hc_": "healthcare",
    "ins_": "insurance",
    "bank_": "banking",
    "ret_": "retail",
    "mfg_": "manufacturing_vertical",
    "con_": "construction",
    "log_": "logistics",
    "ps_": "professional_services",
    "gov_": "government_contracting",
    "edu_": "education_nonprofit",
    "tax_": "tax",
    # 2026 expansion verticals: new business suites the factory can
    # spawn from. Each maps to a SUITE_DISCIPLINE block (domain_discipline) and
    # a wizard AGENT_SUITES entry, so a Rung-2 seal + the [suites] toggle reach
    # the whole vertical at once.
    "util_": "utilities",
    "re_": "real_estate",
    "pharma_": "pharma_lifesciences",
    "tmt_": "telecom_media",
    "hosp_": "hospitality",
    "cap_": "capital_markets",
    # New industry suites (2026 build-out).
    "oilgas_": "oil_gas",
    "auto_": "automotive",
    "pubsec_": "public_sector",
    "ag_": "agriculture",
    "aero_": "aerospace_defense",
    "mar_": "maritime",
    "trv_": "travel_aviation",
    "min_": "mining_metals",
    "crypto_": "crypto_digital_assets",
    "chem_": "chemicals",
    "fbcpg_": "food_beverage_cpg",
    "meddev_": "medical_devices",
    "pevc_": "private_equity_vc",
    "water_": "water_utilities",
    "clean_": "renewables_cleantech",
    "semi_": "semiconductors",
    # New horizontal-function suites (2026 build-out).
    "esg_": "esg_sustainability",
    "risk_": "enterprise_risk",
    "km_": "knowledge_management",
    "tns_": "trust_safety",
    "bpa_": "process_automation",
    # Commerce suite: shopper-side (com_shop_*) and merchant-side (com_merch_*)
    # agents over the governed storefront/merchant backends (maverick.commerce).
    "com_": "commerce",
}


@functools.lru_cache(maxsize=8192)
def suite_for(name: str) -> str | None:
    """The business suite a domain pack belongs to, or ``None`` (legacy/generic).

    Memoised: the roster pages ask it about 6,000 times per render and
    ``SUITE_PREFIXES`` is fixed at import (clear the cache after changing it).
    """
    for prefix, suite in SUITE_PREFIXES.items():
        if name.startswith(prefix):
            return suite
    return None


_UNAVAILABLE_DOMAIN_SUITE = "__unavailable_specialist__"


def suites_for_domain(name: str, profile: DomainProfile | None = None) -> frozenset[str]:
    """Suites governing a roster name and any specialist it inherits from.

    A custom fork can have a generic public name while retaining a built-in
    specialist's profile name. Both suites must be allowed at every boundary.
    Callers with a resolved catalog should pass its profile to avoid a second
    workspace read. A persisted record can outlive a generic-named custom
    pack. In that case its inherited suite cannot be reconstructed, so return
    a non-grantable scope rather than treating the record as unrestricted.
    """
    if not name:
        return frozenset()
    if profile is None:
        profile = available_domains().get(name)
    if profile is None:
        # A named fork may have inherited a *second* suite that its own prefix
        # cannot reveal. Keep the visible prefix but deny scoped principals
        # until the missing pack can be recovered.
        return frozenset({suite for suite in (suite_for(name), _UNAVAILABLE_DOMAIN_SUITE) if suite})
    return frozenset(
        suite for suite in (suite_for(name), suite_for(profile.name) if profile else None)
        if suite is not None
    )


def _disabled_suites(cfg: dict | None = None) -> set[str]:
    """Suites turned OFF in the ``[suites]`` table (``suite = false``).

    Opt-out: a suite is enabled unless explicitly set false, so an empty/absent
    ``[suites]`` table leaves every suite on (behaviour unchanged). A value
    that is not a recognised true turns its suite off, and an unreadable
    configuration turns every suite off."""
    every_suite = set(SUITE_PREFIXES.values())
    try:
        if cfg is None:
            from .config import config_source_errors, load_config
            cfg = load_config() or {}
            # Unreadable TOML loads as defaults; a suite the operator turned
            # off must not come back on, so every suite stays off instead.
            if config_source_errors(include_tenant=True):
                return every_suite
        table = cfg.get("suites") or {}
    except Exception:
        return every_suite
    return {str(k) for k, v in table.items() if not coerce_bool(v, default=False)}


def enabled_domains(cfg: dict | None = None) -> dict[str, DomainProfile]:
    """:func:`available_domains` minus the packs of any suite disabled in ``[suites]``.

    Backward compatible: with no ``[suites]`` config every domain is returned.
    Legacy/generic packs (no recognized suite prefix) are always kept."""
    domains = available_domains()
    disabled = _disabled_suites(cfg)
    if not disabled:
        return domains
    return {
        name: prof for name, prof in domains.items()
        if not suites_for_domain(name, prof) & disabled
    }


# Governed office actions a hire may EXECUTE once per-agent autonomy levels are
# on -- comms and scheduling, every one classified high-risk so the autonomy
# dial + governance gate hold them to the agent's authority (staged or approved
# per rung; never raw). This is the dial-coupled grant that turns a read-only
# specialist into one that can actually take governed actions. Domain-specific
# governed writes (update a record, file a doc) are layered per suite on top.
_GOVERNED_ACTION_BUNDLE = frozenset({"email", "notify", "calendar"})


def data_grounding_enabled(override: bool | None = None) -> bool:
    """Whether packs are granted their suite's primary-source data connectors.

    ON by default (these are GET-only, LOW-risk public/government data readers,
    deferred so they cost no context until ``find_tools`` surfaces them, and
    inert without their env key). ``MAVERICK_WORKFORCE_DATA_GROUNDING`` overrides
    the ``[workforce] data_grounding`` config either way. ``override`` (a what-if
    analysis) takes the environment override's place for this one call, with
    the same fail-closed rules, and changes nothing global. Never raises."""
    import os
    if override is None:
        env = os.environ.get("MAVERICK_WORKFORCE_DATA_GROUNDING", "").strip().lower()
    else:
        env = "1" if override else "0"
    if env in {"0", "false", "no", "off"}:
        return False
    try:
        from .config import config_source_errors, get_workforce

        settings = get_workforce()
        # ``load_config`` deliberately maps unreadable TOML to defaults. At an
        # additive capability boundary, policy loss must not restore the
        # default-on connector grant or let a positive env flag bypass it.
        if config_source_errors():
            return False
        if env in {"1", "true", "yes", "on"}:
            return True
        if env:
            return False
        return settings.get("data_grounding") is True
    except Exception:  # pragma: no cover -- config must never block a run
        return False


def domain_capability(profile: DomainProfile, parent_cap, principal: str, *,
                      levels: bool | None = None, grounding: bool | None = None,
                      mcp_tool_names=()):
    """The Capability a domain agent runs under.

    With a parent grant present, attenuate it by the profile's scopes (never
    broaden); otherwise mint the profile's own envelope. Empty profile fields
    pass ``None`` so they inherit the parent's scope rather than emptying it --
    an empty allow-set means "all", which would *broaden* the grant.

    When the client has enabled per-agent autonomy levels (``[workforce]
    levels``), a non-empty allowlist is expanded with the governed action bundle
    so the hire can execute its job's output -- gated by its autonomy rung. Off
    by default (kernel rule 1): no grant, the pack stays exactly read-only.

    ``levels`` / ``grounding`` override those two dials for this one call (an
    analysis of "what if levels were on"); ``None`` reads the deployment's
    setting. Nothing global changes either way.
    """
    allow = set(profile.allow_tools)
    # Only the factory supplies exact validated names from selected, currently
    # connected clients. Extend an explicit list before risk/parent attenuation;
    # an empty profile list must continue inheriting the existing parent grant.
    if allow:
        allow.update(mcp_tool_names)
    max_risk = profile.max_risk
    if allow:  # only a real allowlist is expanded (empty == inherit, untouched)
        try:
            from .agent_autonomy import levels_enabled
            if levels_enabled() if levels is None else levels_enabled(levels):
                # The governed action bundle is high-risk, so packs with a
                # low/medium ceiling need a high runtime ceiling for those
                # actions to pass through to the autonomy gate. Keep that lift
                # scoped to the new governed tools: tools that were already in
                # the pack but above its declared ceiling were not reachable
                # before levels were enabled and must not become reachable just
                # because email/notify/calendar were added.
                if max_risk in ("low", "medium"):
                    allow = {
                        tool for tool in allow
                        if risk_rank(tool_risk(tool)) <= risk_rank(max_risk)
                    }
                    max_risk = "high"
                allow = allow | _GOVERNED_ACTION_BUNDLE
        except Exception:  # pragma: no cover -- never block capability build
            pass
        # Grant the pack's suite its primary-source data connectors (GET-only,
        # LOW risk, deferred) so the analyst reaches for FRED/SEC EDGAR/openFDA/
        # etc. by default. Additive to the allowlist; the LOW risk keeps them
        # under a read-only pack's ceiling. allow_hosts is deliberately NOT
        # widened -- a host-restricted pack stays restricted (the connector
        # returns a graceful egress error) until an operator opts the host in.
        try:
            if (data_grounding_enabled() if grounding is None
                    else data_grounding_enabled(grounding)):
                from .tools.enterprise_connectors import data_connectors_for_suite
                allow = allow | set(data_connectors_for_suite(suite_for(profile.name)))
        except Exception:  # pragma: no cover -- never block capability build
            pass
    allow = allow or None
    deny = set(profile.deny_tools) or None
    paths = set(profile.allow_paths) or None
    hosts = set(profile.allow_hosts) or None
    if parent_cap is not None:
        return parent_cap.attenuate(
            principal=principal, allow=allow, deny=deny,
            max_risk=max_risk, allow_paths=paths, allow_hosts=hosts,
        )
    from .capability import Capability
    return Capability(
        principal=principal,
        allow_tools=frozenset(allow or ()),
        deny_tools=frozenset(deny or ()),
        max_risk=max_risk,
        allow_paths=frozenset(paths or ()),
        allow_hosts=frozenset(hosts or ()),
    )


_VALID_RISKS = frozenset({"low", "medium", "high"})
# Reasoning-effort tiers a pack may declare (mirrors maverick.effort._LEVELS).
_VALID_EFFORTS = frozenset({"low", "medium", "high", "xhigh", "max"})
_VALID_GATES = frozenset({"approval", "review"})
# Sign-off strength: a deliverable must not claim a lighter gate than the
# human-handoff its own playbook ends on (approval > review > none).
_GATE_RANK = {None: 0, "review": 1, "approval": 2}
# Render archetypes the dashboard knows how to present a deliverable as. An
# unknown shape is a warning, not an error: it falls back to prose rendering, so
# a newer pack naming a future shape still loads on an older dashboard.
_VALID_SHAPES = frozenset({"prose", "report", "table", "forecast"})
# Below this, a persona is a label, not a working instruction set.
_MIN_PERSONA_CHARS = 200
# The state-mutating tools a read-only specialist (one that doesn't allow
# ``shell``/``code_exec``) must explicitly DENY, even though its tool allowlist
# already excludes them: defense-in-depth, so a later edit that loosens the
# allowlist can't silently hand a drafting agent a shell or a file writer.
_READONLY_DENY_FLOOR = ("shell", "write_file")


def _strongest_gate(gates) -> str | None:
    """Return the strongest valid gate in ``gates`` (approval > review)."""
    valid = [gate for gate in gates if gate in _VALID_GATES]
    return max(valid, key=lambda gate: _GATE_RANK[gate], default=None)


def declared_prompt_gate(profile: DomainProfile) -> str | None:
    """Strongest gate written in the prompt-only workflow playbook.

    This deliberately says nothing about enforcement.  Use
    :func:`enforced_gate` for release decisions and governance claims.
    """
    return _strongest_gate(step.gate for step in profile.workflow)


def enforced_gate(profile: DomainProfile) -> str | None:
    """The persisted sign-off gate protecting terminal deliverable release.

    ``output.gate`` has always described the deliverable sign-off.  A terminal
    workflow gate is also safe to enforce at this goal-level boundary, so it is
    promoted here.  Intermediate playbook gates cannot honestly be promoted:
    the prompt playbook has no executable step cursor or pause/resume point.
    """
    terminal = profile.workflow[-1].gate if profile.workflow else None
    # A gate value that is set but not recognised (a misspelling) still means
    # someone asked for sign-off, so it is enforced as the strongest gate.
    gates = [gate if not gate or gate in _VALID_GATES else "approval"
             for gate in (profile.output.gate, terminal)]
    return _strongest_gate(gates)


def deliverable_release_allowed(
    profile: DomainProfile, signoff: dict | None,
) -> bool:
    """Whether a terminal deliverable may cross an external release boundary."""
    return enforced_gate(profile) is None or bool(
        signoff and signoff.get("decision") == "approved"
    )


def _lint_output(out: OutputContract) -> list[str]:
    """Quality-gate a pack's output contract. Returns warnings only -- a
    misdeclared deliverable degrades the consumption surface (it renders as
    prose, doesn't route) but never weakens the safety envelope, so nothing
    here is a hard error."""
    warnings: list[str] = []
    if out.shape and out.shape not in _VALID_SHAPES:
        warnings.append(f"output.shape {out.shape!r} is not one of "
                        f"{sorted(_VALID_SHAPES)} (it will render as prose)")
    if out.gate and out.gate not in _VALID_GATES:
        warnings.append(f"output.gate {out.gate!r} is not one of "
                        f"{sorted(_VALID_GATES)} (it is enforced as approval)")
    if out.deliverable and not out.consumers:
        warnings.append("output declares a deliverable but no consumers: name "
                        "the roles who receive it so it can be routed")
    return warnings


def _lint_workflow(profile: DomainProfile) -> tuple[list[str], list[str]]:
    """Quality-gate a pack's editable playbook. Returns ``(errors, warnings)``.

    A nameless or duplicate step is an error (it breaks the ordered procedure);
    an unknown gate or a step naming a tool the pack doesn't allow is a warning."""
    errors: list[str] = []
    warnings: list[str] = []
    seen: set[str] = set()
    for i, step in enumerate(profile.workflow, 1):
        name = (step.name or "").strip()
        if not name:
            errors.append(f"workflow step {i} has no name")
        elif name in seen:
            errors.append(f"duplicate workflow step name {name!r}")
        seen.add(name)
        if step.gate and step.gate not in _VALID_GATES:
            warnings.append(f"workflow step {name or i!r}: unknown gate "
                            f"{step.gate!r} (expected {sorted(_VALID_GATES)})")
        elif step.gate and i < len(profile.workflow):
            warnings.append(
                f"workflow step {name or i!r}: gate {step.gate!r} is "
                "prompt-declared only; intermediate playbook steps have no "
                "durable pause/resume checkpoint"
            )
        stray = [t for t in step.tools if profile.allow_tools and t not in profile.allow_tools]
        if stray:
            warnings.append(f"workflow step {name or i!r} names tools not in "
                            f"allow_tools: {', '.join(stray)}")
    return errors, warnings


_STRING_LIST_FIELDS = (
    "allow_tools", "deny_tools", "allow_paths", "allow_hosts",
    "mcp_servers", "knowledge_sources", "refuse",
)


def _profile_field_type_errors(profile: DomainProfile) -> list[str]:
    """Reject malformed TOML fields before list/set coercion can change policy."""
    errors: list[str] = []
    for field_name in _STRING_LIST_FIELDS:
        value = getattr(profile, field_name)
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item.strip() for item in value
        ):
            errors.append(f"{field_name} must be a list of non-empty strings")
    if not isinstance(profile.models, dict) or any(
        not isinstance(key, str) or not key.strip()
        or not isinstance(value, str) or not value.strip()
        for key, value in profile.models.items()
    ):
        errors.append("models must map non-empty role names to model names")
    return errors


def lint_profile(profile: DomainProfile) -> tuple[list[str], list[str]]:
    """Quality-gate one pack. Returns ``(errors, warnings)``.

    Errors are problems that weaken the safety envelope or make the
    specialist unreliable (no tool allowlist = ALL tools; an unknown
    ``max_risk`` silently fails open to "no ceiling"). Warnings are quality
    gaps a pack author should look at. Pure, for tests and the CLI."""
    errors: list[str] = []
    warnings: list[str] = []
    type_errors = _profile_field_type_errors(profile)
    if type_errors:
        return type_errors, warnings
    if not profile.allow_tools:
        errors.append("allow_tools is empty: an empty allowlist grants ALL "
                      "tools -- name the tools this pack needs")
    if profile.max_risk is None:
        errors.append("max_risk is unset: the pack has no risk ceiling")
    elif profile.max_risk not in _VALID_RISKS:
        errors.append(f"max_risk {profile.max_risk!r} is not one of "
                      f"{sorted(_VALID_RISKS)}")
    if profile.effort is not None and profile.effort not in _VALID_EFFORTS:
        errors.append(f"effort {profile.effort!r} is not one of "
                      f"{sorted(_VALID_EFFORTS)}")
    overlap = set(profile.allow_tools) & set(profile.deny_tools)
    if overlap:
        warnings.append("tools both allowed and denied (deny wins): "
                        + ", ".join(sorted(overlap)))
    if len((profile.persona or "").strip()) < _MIN_PERSONA_CHARS:
        warnings.append(f"persona under {_MIN_PERSONA_CHARS} chars: a label, "
                        "not a working instruction set")
    if not (profile.description or "").strip():
        warnings.append("description is empty (the roster shows it to "
                        "operators and the orchestrator)")
    if not profile.knowledge_sources:
        warnings.append("no knowledge_sources: the pack can't ground "
                        "answers in company documents")
    if not profile.deny_tools:
        warnings.append("no deny_tools: consider explicitly denying the "
                        "tools this role must never touch")
    allow = set(profile.allow_tools)
    if not (allow & {"shell", "code_exec"}):
        # A read-only/drafting pack: it should pin the mutators shut.
        deny = set(profile.deny_tools)
        ungated = [t for t in _READONLY_DENY_FLOOR if t not in deny and t not in allow]
        if ungated:
            warnings.append(
                "read-only pack doesn't explicitly deny "
                f"{', '.join(ungated)}: add to deny_tools for defense-in-depth "
                "(the allowlist already excludes them, but an explicit deny "
                "survives a later allowlist change)")
    warnings.extend(_lint_output(profile.output))
    wf_errors, wf_warnings = _lint_workflow(profile)
    errors.extend(wf_errors)
    warnings.extend(wf_warnings)
    # The runtime promotes a terminal playbook gate into the persisted
    # deliverable sign-off even when output.gate is missing.  Keep warning on a
    # mismatched declaration so pack authors and exported contracts remain
    # self-explanatory, without pretending the lighter contract weakens runtime.
    if profile.output.deliverable and profile.workflow:
        final_gate = profile.workflow[-1].gate
        if _GATE_RANK.get(final_gate, 0) > _GATE_RANK.get(profile.output.gate, 0):
            warnings.append(
                f"output.gate {profile.output.gate!r} is lighter than the final "
                f"workflow step's gate {final_gate!r}: runtime enforces "
                f"{final_gate!r}, but raise output.gate so the deliverable "
                "contract matches its playbook")
    errors.extend(tool_compatibility_errors(profile))
    return errors, warnings


def tool_compatibility_errors(
    profile: DomainProfile, available_tools: set[str] | None = None,
    *, risk_overrides: dict[str, str] | None = None,
) -> list[str]:
    """Check declared operations before deployment without expanding authority.

    Registry-aware callers can also check names. Parent grants and runtime
    policies may narrow access further; this checks the pack's own contract.
    """
    from fnmatch import fnmatchcase

    errors: list[str] = []
    declared = set(profile.allow_tools) | {t for step in profile.workflow for t in step.tools}
    for name in sorted(declared):
        if available_tools is not None and name not in available_tools:
            errors.append(f"declared tool {name!r} is not available in the installed registry")
        if any(fnmatchcase(name, deny) for deny in profile.deny_tools):
            errors.append(f"declared tool {name!r} is denied by this pack")
        if profile.max_risk in _VALID_RISKS:
            risk = tool_risk(name, overrides=risk_overrides)
            if risk_rank(risk) > risk_rank(profile.max_risk):
                errors.append(f"declared tool {name!r} ({risk}) exceeds max_risk={profile.max_risk!r}; "
                              "use a scoped read tool or provide an approved export")
    for step in profile.workflow:
        for name in step.tools:
            if profile.allow_tools and name not in profile.allow_tools:
                errors.append(f"workflow tool {name!r} is not in allow_tools")
    return errors


def _department_memory(profile: DomainProfile, task: str, *,
                       channel: str | None = None, user_id: str | None = None,
                       shield=None) -> str:
    """The department's recalled lessons, formatted for a specialist's brief.

    Pre-run context layers only run at the orchestrator root; a specialist
    spawned mid-run via ``spawn_specialist`` used to start blank. This gives
    every pack its department memory at ANY spawn depth: same-department
    reflexion lessons scoped to the current channel/user and consolidated
    dream insights, both already sanitized/bounded by their formatters. Empty
    (and free) unless the operator enabled those loops; never raises into a
    spawn.
    """
    try:
        from .config import get_domains
        if not get_domains()["memory"]:
            return ""
    except Exception:  # pragma: no cover -- config never blocks a spawn
        pass
    blocks: list[str] = []
    try:
        from . import reflexion
        if reflexion.enabled():
            recalled = reflexion.recall(
                task, k=2, domain=profile.name,
                channel=channel, user_id=user_id,
            )
            block = reflexion.format_context(recalled, shield=shield)
            if block:
                blocks.append(block)
    except Exception:  # pragma: no cover -- recall never blocks a spawn
        pass
    try:
        from . import dreaming
        if dreaming.enabled():
            insights = dreaming.recall_insights(
                task, domain=profile.name,
                channel=channel, user_id=user_id,
            )
            block = dreaming.format_context(insights, shield=shield)
            if block:
                blocks.append(block)
    except Exception:  # pragma: no cover -- recall never blocks a spawn
        pass
    return "\n".join(blocks)


def agent_from_profile(profile: DomainProfile, ctx, task: str, *,
                       parent=None, depth: int = 0, principal: str | None = None):
    """Spawn a live agent from a domain pack -- the factory's "spit out an agent".

    Sets the agent's role, persona, **compartment tag** (so a Rung-2 sector seal
    reaches it and its sub-tree), and a capability envelope derived from the
    profile (attenuated against the parent's grant when one exists). A domain
    agent therefore always runs inside its pack's tool/risk/host envelope, even
    when global capability enforcement is off -- the pack is a hard boundary.

    The pack persona is augmented with the suite's operating discipline
    (:mod:`maverick.domain_discipline`), and the department's recalled
    lessons are appended to the task brief -- so every specialist, at every
    spawn depth, works like a professional with its department's memory.
    """
    from .agent import Agent
    from .agent_autonomy import default_profile_for, render_autonomy_prompt
    from .domain_discipline import augment_persona
    from .domain_refusals import render_refusals
    type_errors = _profile_field_type_errors(profile)
    if type_errors:
        raise ValueError(f"Domain {profile.name!r} has malformed fields: "
                         + "; ".join(type_errors))
    # Parsing helpers may hand a profile directly to the factory without
    # passing through available_domains(). An absent allowlist means ALL tools
    # and an absent ceiling means no cap, so neither is safe to spawn.
    if (not isinstance(profile.allow_tools, list) or not profile.allow_tools
            or any(not isinstance(tool, str) or not tool for tool in profile.allow_tools)):
        raise ValueError(f"Domain {profile.name!r} requires non-empty allow_tools")
    if not isinstance(profile.max_risk, str) or profile.max_risk not in _VALID_RISKS:
        raise ValueError(f"Domain {profile.name!r} requires valid max_risk")
    compatibility = tool_compatibility_errors(profile)
    if compatibility:
        raise ValueError(f"Domain {profile.name!r} has incompatible tool requirements: "
                         + "; ".join(compatibility))
    run_principal = principal
    principal = principal or f"agent:{profile.name}-{depth}"
    if parent is not None and hasattr(parent, "_effective_capability"):
        parent_cap = parent._effective_capability("spawn_specialist")
    else:
        parent_cap = getattr(parent, "capability", None)
        if parent is None and parent_cap is None:
            # A root specialist has no parent agent, but the run may still
            # carry a grant of its own (a fleet agent's role + the caller's
            # grant). Bound the pack's envelope by it -- never widen it back
            # out -- and keep that run's principal so the oversight control
            # plane keeps governing the work as the agent that was dispatched.
            parent_cap = getattr(ctx, "capability", None)
            if parent_cap is not None and run_principal is None:
                principal = parent_cap.principal
    selected_mcp, mcp_guards, registry = [], {}, {}
    if profile.mcp_servers:
        from .mcp_tools import selected_tools_from_mcp
        selected_mcp = selected_tools_from_mcp(
            getattr(ctx, "mcp_clients", ()), profile.mcp_servers,
            authorize=lambda name: bool(registry.get("tools") and registry["tools"]._acl_allows(name)),
            binding_guards=mcp_guards,
        )
    cap = domain_capability(profile, parent_cap, principal,
                            mcp_tool_names=(tool.name for tool in selected_mcp))
    memory = _department_memory(
        profile, task,
        channel=getattr(ctx, "channel", None),
        user_id=getattr(ctx, "user_id", None),
        shield=getattr(ctx, "shield", None),
    )
    agent = Agent(
        ctx=ctx, role=profile.name, brief=task + ("\n" + memory if memory else ""),
        depth=depth, parent=parent,
        domain=profile.compartment,
        persona=(augment_persona(profile.name, profile.persona)
                 + render_refusals(profile.name, profile.refuse)
                 + render_autonomy_prompt(profile.name, profile.autonomy)
                 + render_workflow_prompt(profile.workflow)),
        capability=cap,
        knowledge_sources=profile.knowledge_sources,
        domain_effort=profile.effort,
        domain_models=profile.models,
        autonomy=profile.autonomy or default_profile_for(profile.name),
        # The depth-0 call (parent is None -- run_goal's domain-routed
        # root) owns this goal's FINAL just like the plain "orchestrator"
        # role does; a nested domain spawn (depth > 0, from spawn.py) does
        # not. role stays profile.name either way -- this only affects the
        # kernel mechanics keyed on "am I this goal's root", not the persona.
        is_goal_root=(depth == 0 and parent is None),
    )
    registry["tools"] = agent.tools
    for tool in selected_mcp:
        agent.tools.register(tool)
        if tool.name in mcp_guards:
            agent.tools._mcp_bindings[tool.name] = mcp_guards[tool.name]
    # Validate the *assembled* instance, including operator plugins and MCP
    # bindings. The plain base catalog cannot establish deployment readiness.
    names = {tool.name for tool in agent.tools.all()}
    missing = sorted({name for step in profile.workflow for name in step.tools} - names)
    from .chat_message_actions import answer_only_runtime
    if missing and not answer_only_runtime():
        raise ValueError(
            f"Domain {profile.name!r} cannot deploy: required workflow tools unavailable: "
            + ", ".join(missing)
            + ". Configure/enable the named adapter or MCP connection, or revise the "
            "workflow to read an operator-approved workspace export with read_file. "
            "No model work has started."
        )
    agent.deployment_prerequisites = sorted(set(profile.allow_tools) - names)
    return agent

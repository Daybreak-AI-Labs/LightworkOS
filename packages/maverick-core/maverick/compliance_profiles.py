"""Compliance mode profiles for the shipped regulatory compiler library.

Cross-domain runtime postures you turn on the way the finance suite turns on
``[finance] regimes``: each profile asserts the safeguards it stands for, names
the protection *floors* it requires to be live (redaction, encryption-at-rest,
egress lock, audit), and compiles to a governance :class:`~maverick.governance.Policy`
(what must pause for a human). Selecting several unions them strictest-wins via
the same helper the finance regimes use.

HIPAA is a PHI-handling posture; GDPR and the EU AI Act supply legal-runtime
overlays. NIST AI RMF, ISO/IEC 42001, SOC 2, and the SR 11-7 compatibility
profile are intentionally bounded compatibility postures: they enforce only
the tool-gate controls named here. They do not assert full framework coverage,
organizational adoption, certification, attestation, or regulatory acceptance.
Pure data + pure functions makes every compilation unit-testable.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace

from .finance.regimes import union_policies  # generic strictest-wins policy union
from .governance import Policy
from .regulatory_compiler import compile_obligations

# Protection floors a profile can require. Active compliance profiles make
# these floors mandatory: runtime readers treat a required floor as enabled so
# selecting a regulated-data profile cannot silently run below its asserted
# safeguards.
FLOOR_PII_REDACTION = "pii_redaction"
FLOOR_ENCRYPTION_AT_REST = "encryption_at_rest"
FLOOR_EGRESS_LOCK = "egress_lock"
FLOOR_AUDIT_LOG = "audit_log"
ALL_REQUIRED_FLOORS = frozenset({
    FLOOR_PII_REDACTION,
    FLOOR_ENCRYPTION_AT_REST,
    FLOOR_EGRESS_LOCK,
    FLOOR_AUDIT_LOG,
})

_PROFILE_ENV = "MAVERICK_COMPLIANCE_PROFILES"
_UNSET = object()
log = logging.getLogger(__name__)


class ComplianceProfileError(RuntimeError):
    """The active compliance posture cannot be trusted or interpreted."""


@dataclass(frozen=True)
class ComplianceProfile:
    key: str
    name: str
    asserts: str
    required_floors: frozenset[str] = frozenset()
    policy: Policy = field(default_factory=Policy)


PROFILES: dict[str, ComplianceProfile] = {
    "hipaa": ComplianceProfile(
        "hipaa",
        "HIPAA Security Rule (45 CFR Part 164)",
        "PHI minimum-necessary; access controls; encryption at rest and in "
        "transit; audit controls; breach-notification readiness; BAAs with "
        "processors. Any high-risk action pauses for a human.",
        required_floors=frozenset({
            FLOOR_PII_REDACTION, FLOOR_ENCRYPTION_AT_REST,
            FLOOR_EGRESS_LOCK, FLOOR_AUDIT_LOG,
        }),
        # PHI handling warrants human oversight on every high-risk action.
        # The minimum-necessary clause (45 CFR 164.502(b)) is compiled by
        # regulatory_compiler as a capability attenuation, not a policy rule.
        policy=Policy(require_human_min_risk="high"),
    ),
    # The two profiles below are compiled from regulatory_compiler's obligation
    # library, so the same citation that tags the audit row is the one that
    # produced the rule. Floors are the minimum a regulator would expect the
    # runtime to already have; the gates are what the regulation adds.
    "gdpr": ComplianceProfile(
        "gdpr",
        "GDPR (Regulation (EU) 2016/679)",
        "Erasure only through the governed path (Art. 17); a human confirms "
        "every outbound transfer of personal data (Art. 32); no solely "
        "automated high-impact decision -- every high-risk action pauses for a "
        "human (Art. 22).",
        required_floors=frozenset({FLOOR_PII_REDACTION, FLOOR_AUDIT_LOG}),
        policy=compile_obligations(["gdpr"]).policy,
    ),
    "eu_ai_act": ComplianceProfile(
        "eu_ai_act",
        "EU AI Act (Regulation (EU) 2024/1689)",
        "Effective human oversight of a high-risk AI system: every high-risk "
        "action pauses for a human (Art. 14). Conduct prohibitions (Art. 5) "
        "remain the packs' hard refusals.",
        required_floors=frozenset({FLOOR_AUDIT_LOG}),
        policy=compile_obligations(["eu_ai_act"]).policy,
    ),
    "nist_ai_rmf": ComplianceProfile(
        "nist_ai_rmf",
        "NIST AI RMF (bounded runtime compatibility)",
        "Bounded MANAGE control only: every high-risk tool action pauses for "
        "a human. This does not establish complete AI RMF coverage or a "
        "NIST profile.",
        required_floors=frozenset({FLOOR_AUDIT_LOG}),
        policy=compile_obligations(["nist_ai_rmf"]).policy,
    ),
    "iso_42001": ComplianceProfile(
        "iso_42001",
        "ISO/IEC 42001:2023 (bounded runtime compatibility)",
        "Bounded A.9.2 human-oversight control only: every high-risk tool "
        "action pauses for a human. This does not establish full AIMS coverage "
        "or ISO certification.",
        required_floors=frozenset({FLOOR_AUDIT_LOG}),
        policy=compile_obligations(["iso_42001"]).policy,
    ),
    "soc2": ComplianceProfile(
        "soc2",
        "SOC 2 Trust Services Criteria (bounded runtime compatibility)",
        "Bounded CC6.1 least-privilege control only: known outbound side-effect "
        "tools are attenuated from capabilities. This is not a SOC 2 "
        "attestation.",
        required_floors=frozenset({
            FLOOR_ENCRYPTION_AT_REST, FLOOR_EGRESS_LOCK, FLOOR_AUDIT_LOG,
        }),
        policy=compile_obligations(["soc2"]).policy,
    ),
    "sr_11_7": ComplianceProfile(
        "sr_11_7",
        "SR 11-7 compatibility (current SR 26-2 successor)",
        "Bounded high-risk human-review control by analogy only. SR 26-2 "
        "supersedes SR 11-7 and expressly excludes generative and agentic AI "
        "from its stated scope; this does not establish model approval, "
        "validation, or supervisory acceptance.",
        required_floors=frozenset({FLOOR_AUDIT_LOG}),
        policy=compile_obligations(["sr_11_7"]).policy,
    ),
}


def list_profiles() -> list[ComplianceProfile]:
    return list(PROFILES.values())


def get_profile(key: str) -> ComplianceProfile | None:
    return PROFILES.get(str(key).strip().lower())


def _validated_profile_keys(values, *, source: str) -> list[str]:
    """Strict, deduplicated profile keys from one already-list-shaped source."""
    if not isinstance(values, list):
        raise ComplianceProfileError(f"{source} must be a list of non-empty strings")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ComplianceProfileError(
                f"{source} must be a list of non-empty strings"
            )
        key = value.strip().lower()
        if key not in PROFILES:
            raise ComplianceProfileError(
                f"{source} contains unknown profile {key!r}; expected one of "
                f"{', '.join(sorted(PROFILES))}"
            )
        if key not in normalized:
            normalized.append(key)
    return normalized


def resolve_profiles(
    config: object = _UNSET,
    *,
    source_errors: object = _UNSET,
) -> list[str]:
    """Resolve the one active compliance profile set from config plus env.

    This is the authority-bearing resolver shared by policy compilation,
    capability attenuation, protection floors, and regulatory evidence.  It
    distinguishes an intentionally absent profile list from an unreadable or
    malformed policy source; the latter raises instead of becoming default-open.

    ``config``/``source_errors`` let callers that already admitted one config
    snapshot reuse it, closing the policy/evidence TOCTOU created by reloading.
    ``MAVERICK_COMPLIANCE_PROFILES`` adds comma-separated keys to the configured
    list and is validated under the same strict rules.
    """
    if config is _UNSET:
        try:
            from .config import config_source_errors, load_config

            config = load_config()
            source_errors = config_source_errors()
        except Exception as exc:
            raise ComplianceProfileError(
                "compliance profile source is unavailable"
            ) from exc
    elif source_errors is _UNSET:
        # A supplied snapshot has already been admitted by its caller.  Callers
        # that also have the error registry (for example deployment admission)
        # pass it explicitly so source and parse status remain one observation.
        source_errors = {}

    if source_errors:
        raise ComplianceProfileError("compliance profile source is invalid")
    if not isinstance(config, Mapping):
        raise ComplianceProfileError("compliance config root must be a table")

    configured: list[str] = []
    if "compliance" in config:
        section = config.get("compliance")
        if not isinstance(section, Mapping):
            raise ComplianceProfileError("[compliance] must be a configuration table")
        if "profiles" in section:
            configured = _validated_profile_keys(
                section.get("profiles"), source="compliance.profiles"
            )

    env_raw = os.environ.get(_PROFILE_ENV)
    env_keys: list[str] = []
    if env_raw is not None and env_raw.strip():
        # Empty comma-separated entries are malformed, not harmless. Silently
        # dropping ``gdpr,,hipaa`` would give environment activation a looser
        # grammar than the configuration list and undermine this resolver's
        # role as the single policy boundary.
        values = [part.strip() for part in env_raw.split(",")]
        env_keys = _validated_profile_keys(values, source=_PROFILE_ENV)

    return list(dict.fromkeys([*configured, *env_keys]))


def compile_policy(keys) -> Policy:
    """Compile selected profile keys into one Policy (strictest-wins).

    Explicit callers receive the same validation as runtime activation: a typo
    cannot silently compile to an empty, default-open policy.
    """
    normalized = _validated_profile_keys(list(keys or []), source="profile keys")
    policy = union_policies(PROFILES[key].policy for key in normalized)
    return replace(policy, compliance_profiles=tuple(normalized))


def required_floors(keys) -> frozenset[str]:
    """Union of the protection floors the selected profiles require."""
    normalized = _validated_profile_keys(list(keys or []), source="profile keys")
    out: set[str] = set()
    for key in normalized:
        out |= set(PROFILES[key].required_floors)
    return frozenset(out)


def configured_profiles(
    config: object = _UNSET,
    *,
    source_errors: object = _UNSET,
) -> list[str]:
    """Strict active keys from config plus ``MAVERICK_COMPLIANCE_PROFILES``."""
    return resolve_profiles(config, source_errors=source_errors)


def configured_required_floors() -> frozenset[str]:
    """Protection floors required by the active compliance profiles.

    Missing configuration means no profile was selected.  Unreadable, malformed,
    or unknown configuration is different: policy intent is uncertain, so every
    known protection floor is required until the source is repaired.
    """
    try:
        return required_floors(configured_profiles())
    except Exception:
        log.exception(
            "compliance profile policy is unavailable; requiring every safety floor"
        )
        return ALL_REQUIRED_FLOORS


def requires_floor(floor: str) -> bool:
    """True when an active compliance profile requires ``floor``."""
    return str(floor).strip().lower() in configured_required_floors()


def profile_posture(keys) -> str:
    """Human-readable posture report for the selected profiles."""
    normalized = _validated_profile_keys(list(keys or []), source="profile keys")
    known = [PROFILES[key] for key in normalized]
    if not known:
        return "compliance profiles: none active"
    lines = [f"compliance profiles: {', '.join(p.key for p in known)}"]
    for p in known:
        lines.append(f"- {p.name}")
        lines.append(f"    asserts: {p.asserts}")
        if p.required_floors:
            lines.append(f"    required floors: {', '.join(sorted(p.required_floors))}")
    pol = compile_policy([p.key for p in known])
    if pol.require_human_min_risk:
        lines.append(f"enforcement: require-human at/above risk '{pol.require_human_min_risk}'")
    return "\n".join(lines)


__all__ = [
    "ALL_REQUIRED_FLOORS", "ComplianceProfile", "ComplianceProfileError",
    "PROFILES", "list_profiles", "get_profile", "resolve_profiles",
    "compile_policy", "required_floors", "configured_profiles",
    "configured_required_floors", "requires_floor", "profile_posture",
    "FLOOR_PII_REDACTION", "FLOOR_ENCRYPTION_AT_REST", "FLOOR_EGRESS_LOCK",
    "FLOOR_AUDIT_LOG",
]

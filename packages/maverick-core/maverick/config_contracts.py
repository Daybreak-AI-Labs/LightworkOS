"""Shared, presentation-independent contracts for configuration values.

The installer and dashboard must accept the same syntax for a setting.  Keep
these patterns in the kernel, which both packages already depend on; contextual
checks such as secret handling and provider-specific validation stay with the
caller that has that context.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class TextSettingContract:
    """Shared syntax and defaults for one text setting.

    The dashboard's display default can intentionally be empty when the
    reader supplies a runtime fallback. Installer and dashboard validation
    may add contextual checks (for example a provider-specific key format).
    """

    setting: str
    pattern: str
    default: str = ""
    runtime_default: str = ""
    dashboard_max_length: int = 200
    dashboard_env: tuple[str, ...] = ()

    def matches(self, value: str) -> bool:
        """Check syntax alone; the caller owns optional-value rules."""
        return re.fullmatch(self.pattern, value) is not None


@dataclass(frozen=True)
class IntegerSettingContract:
    """A stored integer default and the bounds exposed by the settings page."""

    setting: str
    default: int
    minimum: int
    maximum: int
    dashboard_env: tuple[str, ...] = ()


@dataclass(frozen=True)
class BooleanSettingContract:
    setting: str
    default: bool
    dashboard_env: tuple[str, ...] = ()


@dataclass(frozen=True)
class ChoiceSettingContract:
    setting: str
    default: str
    options: tuple[str, ...]
    dashboard_env: tuple[str, ...] = ()


@dataclass(frozen=True)
class NumberListSettingContract:
    """Limits and immutable defaults for an ordered numeric setting list."""

    setting: str
    default: tuple[float, ...]
    max_items: int
    minimum_exclusive: float
    maximum: float
    dashboard_max_length: int = 20


HTTPS = r"https://[^\s\"'<>?#]{1,300}"
COLLECTOR_ADDRESS = (r"(" + HTTPS + r"|http://(localhost|127\.0\.0\.1|\[::1\])"
                     r"(:[0-9]{1,5})?(/[^\s\"'<>?#]{0,300})?)?")
KEY_ID = r"[A-Za-z0-9:/._-]{1,300}"
REGION = r"[a-z]{2}(-[a-z]+)+-[0-9]{1,2}"
VAULT_MOUNT = r"[A-Za-z0-9._-]{1,64}"
SIEM_ADDRESS = r"(https?|tcp|udp|datadog|sentinel)://[^\s\"'<>]{1,300}"

_CONTRACTS = (
    TextSettingContract("observability.otel_endpoint", COLLECTOR_ADDRESS,
                        runtime_default="http://localhost:4318/v1/traces",
                        dashboard_max_length=320, dashboard_env=("MAVERICK_OTEL_ENDPOINT",)),
    TextSettingContract("kms.key_id", KEY_ID, dashboard_max_length=300,
                        dashboard_env=("MAVERICK_KMS_KEY_ID",)),
    TextSettingContract("kms.region", REGION),
    TextSettingContract("kms.address", HTTPS, dashboard_max_length=300),
    TextSettingContract("kms.mount", VAULT_MOUNT, default="transit", runtime_default="transit"),
    TextSettingContract("audit.siem_dest", SIEM_ADDRESS, dashboard_max_length=300,
                        dashboard_env=("MAVERICK_SIEM_DEST",)),
)
TEXT_SETTINGS: Mapping[str, TextSettingContract] = MappingProxyType(
    {contract.setting: contract for contract in _CONTRACTS}
)

_INTEGER_CONTRACTS = (
    IntegerSettingContract("approval.undo_grace_seconds", 30, 0, 3600,
                           ("MAVERICK_APPROVAL_UNDO_GRACE_SECONDS",)),
    IntegerSettingContract("approval.check_retention_days", 90, 1, 3650),
    IntegerSettingContract("agent_tests.max_cases_per_specialist", 20, 1, 200),
    IntegerSettingContract("agent_tests.canary_percent", 0, 0, 50),
    IntegerSettingContract("durable.keep_last", 5, 1, 100),
)
INTEGER_SETTINGS: Mapping[str, IntegerSettingContract] = MappingProxyType(
    {contract.setting: contract for contract in _INTEGER_CONTRACTS}
)
_BOOLEAN_CONTRACTS = (
    BooleanSettingContract("approval.require_acknowledgement", True,
                           ("MAVERICK_APPROVAL_REQUIRE_ACKNOWLEDGEMENT",)),
    BooleanSettingContract("approval.record_checks", True),
    BooleanSettingContract("budget.strict_pricing", True, ("MAVERICK_BILLING_STRICT",)),
    BooleanSettingContract("budget.guidance", True),
    BooleanSettingContract("budget.warnings", True),
    BooleanSettingContract("agent_tests.require_for_new_specialists", False),
    BooleanSettingContract("agent_tests.bypass_requires_second_person", False),
    BooleanSettingContract("agent_tests.tool_checks", False),
    BooleanSettingContract("agent_tests.canary_auto_rollback", False),
    BooleanSettingContract("automation_import.enable", False, ("MAVERICK_AUTOMATION_IMPORT",)),
    BooleanSettingContract("automation_import.create_schedules", False),
    BooleanSettingContract("durable.enabled", False),
)
BOOLEAN_SETTINGS: Mapping[str, BooleanSettingContract] = MappingProxyType(
    {contract.setting: contract for contract in _BOOLEAN_CONTRACTS}
)
_CHOICE_CONTRACTS = (
    ChoiceSettingContract("approval.separate_approver", "when_available",
                          ("when_available", "always", "never"),
                          ("MAVERICK_SEPARATE_APPROVER",)),
)
CHOICE_SETTINGS: Mapping[str, ChoiceSettingContract] = MappingProxyType(
    {contract.setting: contract for contract in _CHOICE_CONTRACTS}
)

_NUMBER_LIST_CONTRACTS = (
    NumberListSettingContract("budget.warning_thresholds", (0.8, 0.95, 1.0), 10, 0.0, 1.0),
)
NUMBER_LIST_SETTINGS: Mapping[str, NumberListSettingContract] = MappingProxyType(
    {contract.setting: contract for contract in _NUMBER_LIST_CONTRACTS}
)

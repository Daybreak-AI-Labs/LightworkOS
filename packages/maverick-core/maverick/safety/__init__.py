"""Safety utilities for Lightwork.

Currently:
  - ``secret_detector``: regex-based credential scrubbing for tool outputs.
  - ``consent``: prompt the user before destructive actions; ledger
    of granted approvals.
  - ``tool_acl``: allow-list / deny-list filtering of registered tools.

This package is intentionally lightweight (no fancy ML deps). Heavier
classifiers live behind optional extras and are loaded on demand.
"""
from .canaries import (  # noqa: F401
    SandboxCanaryFired,
    plant_session_canaries,
    verify_canaries,
)
from .consent import (  # noqa: F401
    ConsentDecision,
    ConsentDenied,
    ConsentPermit,
    consume_operation_consent,
    grant_persistent,
    list_grants,
    require_consent,
    require_operation_consent,
    revoke,
)
from .pii_detector import PIIMatch  # noqa: F401
from .pii_detector import redact as pii_redact  # noqa: F401
from .pii_detector import scan as pii_scan  # noqa: F401
from .remote_scan import RemoteScanResult, scan_remote_content  # noqa: F401
from .secret_detector import SecretMatch, redact, scan  # noqa: F401
from .tool_acl import (  # noqa: F401
    apply_to_registry,
    filter_tools,
    resolve_lists,
    resolve_max_risk,
)
from .tool_risk import tool_risk, tools_exceeding  # noqa: F401
from .unicode_filter import (  # noqa: F401
    UnicodeScanResult,
    has_dangerous_unicode,
)
from .unicode_filter import (
    normalize as unicode_normalize,
)

__all__ = [
    "redact", "scan", "SecretMatch",
    "pii_redact", "pii_scan", "PIIMatch",
    "ConsentDecision", "ConsentDenied", "ConsentPermit", "require_consent",
    "require_operation_consent", "consume_operation_consent",
    "grant_persistent", "revoke", "list_grants",
    "filter_tools", "apply_to_registry", "resolve_max_risk",
    "tool_risk", "tools_exceeding",
    "UnicodeScanResult", "unicode_normalize", "has_dangerous_unicode",
    "RemoteScanResult", "scan_remote_content",
]

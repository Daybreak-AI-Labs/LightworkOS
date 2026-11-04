"""Plain names and choices for the security pages (threat monitoring)."""
from __future__ import annotations

SOC_CONNECTOR_LABELS: dict[str, str] = {
    "cloudtrail": "Amazon Web Services activity (CloudTrail)",
    "guardduty": "Amazon Web Services threat alerts (GuardDuty)",
    "syslog": "Server logs (syslog)",
    "edr": "Laptop and server protection",
    "splunk": "Splunk",
    "elastic": "Elastic",
    "sentinel": "Microsoft Sentinel",
    "kubernetes_audit": "Kubernetes activity",
    "okta": "Okta sign-ins",
    "entra": "Microsoft Entra ID sign-ins",
}


FRAMEWORK_LABELS: dict[str, str] = {
    "soc2": "SOC 2", "iso27001": "ISO 27001", "nist_csf": "NIST CSF 2.0",
    "nist_800_53": "NIST 800-53", "cis_v8": "CIS v8.1", "pci_dss": "PCI DSS 4.0.1",
    "hipaa": "HIPAA", "cmmc_l2": "CMMC L2", "fedramp_moderate": "FedRAMP Class C",
    "all": "All frameworks",
}

ATTACK_NAMES: dict[str, str] = {
    "T1078": "Using stolen or valid accounts", "T1098": "Changing accounts to keep access",
    "T1110": "Guessing passwords", "T1566": "Phishing", "T1190": "Attacking a public app",
    "T1059": "Running commands or scripts", "T1486": "Encrypting data for ransom",
    "T1041": "Sending data out over an existing connection", "T1567": "Sending data to a web service",
    "T1530": "Taking data from cloud storage", "T1562": "Switching off defences",
    "T1021": "Remote access", "T1136": "Creating new accounts", "T1485": "Deleting data",
    "T1548": "Gaining higher permissions", "T1552": "Finding stored passwords or keys",
}


def attack_choices() -> list[dict]:
    return [{"value": key, "label": f"{name} ({key})"} for key, name in ATTACK_NAMES.items()]


# Plainer names for the built-in checks (the kernel's titles are for analysts).
CURATED_TITLES: dict[str, str] = {
    "LW-SIGMA-001": "Someone signed in to the cloud console without a second sign-in step",
    "LW-SIGMA-002": "A new cloud access key was created",
    "LW-SIGMA-003": "Someone was given full control of a Kubernetes cluster",
    "LW-SIGMA-004": "A large upload left a laptop or server",
    "LW-SIGMA-005": "A new app was given access through your sign-in provider",
}


def soc_connector_choices() -> tuple[list[str], list[str]]:
    """``(readable now, file upload allowed)`` connector names for this workspace.

    A system is readable when it is switched on AND has a registered read-only
    transport; file upload follows the separate, stronger upload switch."""
    from maverick import env_hunt

    from .security_api import _configured_environment_connector_factory

    try:
        statuses = _configured_environment_connector_factory(env_hunt).statuses()
    except Exception:  # noqa: BLE001 -- nothing readable rather than a broken page
        statuses = {}
    try:
        push = env_hunt.connector_push_enablement()
    except Exception:  # noqa: BLE001
        push = {}
    order = list(env_hunt.CONNECTOR_NAMES)
    pull = [n for n in order if (statuses.get(n) or {}).get("available")]
    upload = [n for n in order if push.get(n)]
    return pull, upload


__all__ = ["ATTACK_NAMES", "CURATED_TITLES", "FRAMEWORK_LABELS", "attack_choices", "SOC_CONNECTOR_LABELS", "soc_connector_choices"]

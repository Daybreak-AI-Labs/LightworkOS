"""Closed configuration for the bounded vendor onboarding application."""
from __future__ import annotations

import math
from dataclasses import dataclass


@dataclass(frozen=True)
class VendorOnboardingSettings:
    enable: bool = False
    resource_owner: str = ""
    document_connection: str = "gdrive"
    ticket_connection: str = "jira"
    reviewed_uploads: bool = True
    safe_read_attempts: int = 3
    safe_read_backoff_seconds: float = 0.25

    @classmethod
    def from_config(cls, config: dict) -> VendorOnboardingSettings:
        raw = config.get("vendor_onboarding", {})
        if not isinstance(raw, dict) or set(raw) - set(cls.__dataclass_fields__):
            raise ValueError("vendor_onboarding must be a closed configuration table")
        settings = cls(**raw)
        if type(settings.enable) is not bool or type(settings.reviewed_uploads) is not bool:
            raise ValueError("vendor_onboarding.enable and reviewed_uploads must be booleans")
        if (
            isinstance(settings.safe_read_attempts, bool)
            or not isinstance(settings.safe_read_attempts, int)
            or not 1 <= settings.safe_read_attempts <= 5
        ):
            raise ValueError("vendor_onboarding.safe_read_attempts must be from 1 through 5")
        if (
            isinstance(settings.safe_read_backoff_seconds, bool)
            or not isinstance(settings.safe_read_backoff_seconds, int | float)
            or not math.isfinite(float(settings.safe_read_backoff_seconds))
            or not 0 <= float(settings.safe_read_backoff_seconds) <= 5
        ):
            raise ValueError(
                "vendor_onboarding.safe_read_backoff_seconds must be from 0 through 5"
            )
        for key in ("resource_owner", "document_connection", "ticket_connection"):
            value = getattr(settings, key)
            if not isinstance(value, str) or len(value) > 256 or value != value.strip():
                raise ValueError(f"vendor_onboarding.{key} must be a bounded string")
            if settings.enable and not value:
                raise ValueError(f"vendor_onboarding.{key} is required when enabled")
        if settings.document_connection == settings.ticket_connection:
            raise ValueError("document and ticket credentials must be separately enrolled")
        return settings

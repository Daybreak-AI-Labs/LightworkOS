"""Validated, versioned state-licensing data packs.

Version 1 is intentionally a fail-closed source-routing matrix, not legal
advice.  A row cannot claim that a license is required (or not required) until
it carries a dated, jurisdiction-specific primary citation.  This lets the
regulatory-change engine safely feed all fifty state register records today
without manufacturing legal conclusions while counsel-reviewed overrides are
added as later pack versions.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from datetime import date
from types import MappingProxyType
from typing import Any

JURISDICTIONS: Mapping[str, str] = MappingProxyType(dict((
    ("AL", "Alabama"), ("AK", "Alaska"), ("AZ", "Arizona"), ("AR", "Arkansas"),
    ("CA", "California"), ("CO", "Colorado"), ("CT", "Connecticut"),
    ("DE", "Delaware"), ("FL", "Florida"), ("GA", "Georgia"), ("HI", "Hawaii"),
    ("ID", "Idaho"), ("IL", "Illinois"), ("IN", "Indiana"), ("IA", "Iowa"),
    ("KS", "Kansas"), ("KY", "Kentucky"), ("LA", "Louisiana"), ("ME", "Maine"),
    ("MD", "Maryland"), ("MA", "Massachusetts"), ("MI", "Michigan"),
    ("MN", "Minnesota"), ("MS", "Mississippi"), ("MO", "Missouri"),
    ("MT", "Montana"), ("NE", "Nebraska"), ("NV", "Nevada"),
    ("NH", "New Hampshire"), ("NJ", "New Jersey"), ("NM", "New Mexico"),
    ("NY", "New York"), ("NC", "North Carolina"), ("ND", "North Dakota"),
    ("OH", "Ohio"), ("OK", "Oklahoma"), ("OR", "Oregon"),
    ("PA", "Pennsylvania"), ("RI", "Rhode Island"), ("SC", "South Carolina"),
    ("SD", "South Dakota"), ("TN", "Tennessee"), ("TX", "Texas"), ("UT", "Utah"),
    ("VT", "Vermont"), ("VA", "Virginia"), ("WA", "Washington"),
    ("WV", "West Virginia"), ("WI", "Wisconsin"), ("WY", "Wyoming"),
)))

_DETERMINATIONS = frozenset({
    "required", "not_required", "conditional", "source_check_required",
})
_SUPPORTS = frozenset({"licensing", "renewal", "both"})
_SEMVER = re.compile(r"^[1-9]\d*\.\d+\.\d+$")


class LicensingPackError(ValueError):
    """A licensing pack lacks coverage, provenance, or a safe determination."""


@dataclass(frozen=True)
class LicensingCitation:
    label: str
    url: str
    supports: str
    primary: bool
    jurisdiction_specific: bool
    published_or_accessed: str


@dataclass(frozen=True)
class RenewalRule:
    rule_kind: str
    filing_system: str
    opens: str | None
    closes: str | None
    reinstatement: str
    note: str
    source_check_required: bool = True


@dataclass(frozen=True)
class StateLicensingRequirement:
    jurisdiction: str
    state_name: str
    authority_name: str
    license_name: str
    determination: str
    scope_note: str
    renewal: RenewalRule
    citations: tuple[LicensingCitation, ...]
    legal_review_required: bool = True
    verified_on: str | None = None


@dataclass(frozen=True)
class LicensingRegisterRecord:
    """Stable projection consumed by an obligation/register integration."""

    record_id: str
    vertical: str
    jurisdiction: str
    state_name: str
    determination: str
    license_name: str
    authority_name: str
    renewal: RenewalRule
    legal_review_required: bool
    citation_urls: tuple[str, ...]
    pack_version: str
    pack_sha256: str
    pack_as_of: str


@dataclass(frozen=True)
class LicensingDataPack:
    schema_version: int
    vertical: str
    version: str
    as_of: str
    title: str
    methodology: str
    requirements: tuple[StateLicensingRequirement, ...]

    def for_state(self, jurisdiction: str) -> StateLicensingRequirement:
        code = jurisdiction.strip().upper()
        for requirement in self.requirements:
            if requirement.jurisdiction == code:
                return requirement
        raise KeyError(code)

    @property
    def content_sha256(self) -> str:
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def register_records(self) -> tuple[LicensingRegisterRecord, ...]:
        """Project all rows into stable, provenance-bound register records."""
        digest = self.content_sha256
        return tuple(LicensingRegisterRecord(
            record_id=f"licensing:{self.vertical}:{row.jurisdiction}",
            vertical=self.vertical,
            jurisdiction=row.jurisdiction,
            state_name=row.state_name,
            determination=row.determination,
            license_name=row.license_name,
            authority_name=row.authority_name,
            renewal=row.renewal,
            legal_review_required=row.legal_review_required,
            citation_urls=tuple(citation.url for citation in row.citations),
            pack_version=self.version,
            pack_sha256=digest,
            pack_as_of=self.as_of,
        ) for row in self.requirements)


def _valid_iso_date(value: str) -> bool:
    try:
        date.fromisoformat(value)
    except (TypeError, ValueError):
        return False
    return True


def validate_licensing_pack(pack: LicensingDataPack) -> None:
    """Fail closed on missing states or uncited legal conclusions."""
    if pack.schema_version != 1:
        raise LicensingPackError("unsupported licensing-pack schema version")
    if not _SEMVER.fullmatch(pack.version):
        raise LicensingPackError("pack version must be semantic versioning")
    if not _valid_iso_date(pack.as_of):
        raise LicensingPackError("pack as_of must be an ISO date")
    codes = [row.jurisdiction for row in pack.requirements]
    if len(codes) != len(set(codes)) or set(codes) != set(JURISDICTIONS):
        raise LicensingPackError("pack must cover exactly the 50 states once")
    for row in pack.requirements:
        if row.state_name != JURISDICTIONS[row.jurisdiction]:
            raise LicensingPackError(f"incorrect state name for {row.jurisdiction}")
        if row.determination not in _DETERMINATIONS:
            raise LicensingPackError(f"invalid determination for {row.jurisdiction}")
        if not row.authority_name.strip() or not row.license_name.strip():
            raise LicensingPackError(f"missing authority or license for {row.jurisdiction}")
        if not row.renewal.rule_kind or not row.renewal.filing_system:
            raise LicensingPackError(f"missing renewal routing for {row.jurisdiction}")
        if not row.citations:
            raise LicensingPackError(f"missing citations for {row.jurisdiction}")
        for citation in row.citations:
            if not citation.label.strip() or not citation.url.startswith("https://"):
                raise LicensingPackError(f"invalid citation for {row.jurisdiction}")
            if citation.supports not in _SUPPORTS:
                raise LicensingPackError(f"invalid citation scope for {row.jurisdiction}")
            if not _valid_iso_date(citation.published_or_accessed):
                raise LicensingPackError(f"citation date missing for {row.jurisdiction}")
        if row.determination != "source_check_required":
            supported = any(
                citation.primary
                and citation.jurisdiction_specific
                and citation.supports in {"licensing", "both"}
                for citation in row.citations
            )
            if not supported or not row.verified_on or not _valid_iso_date(row.verified_on):
                raise LicensingPackError(
                    f"{row.jurisdiction} legal conclusion requires a dated "
                    "jurisdiction-specific primary citation"
                )
        if row.determination == "source_check_required" and not row.legal_review_required:
            raise LicensingPackError(f"unverified row must require legal review: {row.jurisdiction}")


def load_licensing_pack(vertical: str, version: str | None = None) -> LicensingDataPack:
    """Load a built-in immutable pack; unknown verticals/versions fail closed."""
    key = vertical.strip().lower()
    selected = version or "1.0.0"
    if (key, selected) == ("money_transmitter", "1.0.0"):
        from .licensing_packs.money_transmitter_v1 import PACK
    elif (key, selected) == ("insurance_producer", "1.0.0"):
        from .licensing_packs.insurance_producer_v1 import PACK
    else:
        raise KeyError(f"unknown licensing pack: {key}@{selected}")
    validate_licensing_pack(PACK)
    return PACK


def ingest_pack_into_regulatory_register(
    engine: Any,
    pack: LicensingDataPack,
    *,
    enabled_domains: Iterable[str],
    fetched_at: str | None = None,
):
    """Persist one pack as versioned, cited regulatory-register documents.

    The projection uses each state's jurisdiction-specific operational source
    as the record citation.  Pack versions and content digests live inside the
    normalized document, so a later pack produces field-level diffs and reopens
    human review through the ordinary regulatory-change workflow.
    """
    validate_licensing_pack(pack)
    from .regulatory_change import FeedSource, RegulatoryChangeEngine

    if not isinstance(engine, RegulatoryChangeEngine):
        raise TypeError("engine must be a RegulatoryChangeEngine")
    source_urls = {
        "money_transmitter": (
            "https://mortgage.nationwidelicensingsystem.org/knowledge/Products/"
            "nmls/stateresourcecenter/SitePages/Home.aspx"
        ),
        "insurance_producer": "https://nipr.com/licensing-center/state-requirements",
    }
    source_url = source_urls.get(pack.vertical)
    if source_url is None:
        raise LicensingPackError("licensing pack vertical has no regulatory source route")
    digest = pack.content_sha256
    engine.bind_source_release(
        f"licensing-pack-{pack.vertical}",
        pack.version,
        digest,
    )
    items = []
    for requirement in pack.requirements:
        citation = next(
            (item for item in requirement.citations if item.jurisdiction_specific),
            requirement.citations[0],
        )
        items.append({
            "id": f"licensing:{pack.vertical}:{requirement.jurisdiction}",
            "title": (
                f"{requirement.state_name} {requirement.license_name} "
                f"requirements ({pack.version})"
            ),
            "summary": {
                "authority_name": requirement.authority_name,
                "determination": requirement.determination,
                "scope_note": requirement.scope_note,
                "renewal": asdict(requirement.renewal),
                "legal_review_required": requirement.legal_review_required,
                "verified_on": requirement.verified_on,
                "citation_urls": [item.url for item in requirement.citations],
                "pack_version": pack.version,
                "pack_sha256": digest,
            },
            "published_at": pack.as_of,
            "jurisdiction": f"US-{requirement.jurisdiction}",
            "url": citation.url,
            "citation": (
                f"{citation.label}; pack {pack.vertical}@{pack.version}; "
                f"sha256:{digest}"
            ),
            "tags": ["state licensing", "renewal", requirement.state_name],
            "domains": [pack.vertical],
        })
    payload = json.dumps(
        {"items": items},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return engine.ingest(
        FeedSource(
            key=f"licensing-pack-{pack.vertical}",
            name=f"Lightwork cited {pack.title}",
            jurisdiction="US",
            url=source_url,
            format="json",
            default_domains=(pack.vertical,),
        ),
        payload,
        enabled_domains=enabled_domains,
        fetched_at=fetched_at,
        acquisition="pack_generated",
        acquired_by="system:finance-licensing-pack",
    )


__all__ = [
    "JURISDICTIONS", "LicensingCitation", "LicensingDataPack", "LicensingPackError",
    "LicensingRegisterRecord", "RenewalRule", "StateLicensingRequirement",
    "ingest_pack_into_regulatory_register", "load_licensing_pack",
    "validate_licensing_pack",
]

"""Insurance-producer state source-routing matrix, edition 1.0.0.

NIPR states that renewal costs, periods, eligibility, and continuing-education
requirements are state-specific.  This pack therefore routes all fifty states
to that live requirements workflow without inventing a universal deadline.
"""
from __future__ import annotations

from ..licensing import (
    JURISDICTIONS,
    LicensingCitation,
    LicensingDataPack,
    RenewalRule,
    StateLicensingRequirement,
)

_AS_OF = "2026-07-22"
_NIPR_RENEWAL = LicensingCitation(
    label="NIPR Renew an Insurance License",
    url="https://nipr.com/licensing-center/apply-for-a-license/renew-your-license",
    supports="renewal",
    # NIPR is the operational licensing route, not the controlling state-law
    # authority for an applicability conclusion.
    primary=False,
    jurisdiction_specific=False,
    published_or_accessed=_AS_OF,
)
_NIPR_REQUIREMENTS = LicensingCitation(
    label="NIPR State Requirements",
    url="https://nipr.com/licensing-center/state-requirements",
    supports="both",
    primary=False,
    jurisdiction_specific=False,
    published_or_accessed=_AS_OF,
)

_AUTHORITIES = {
    "AL": "Alabama Department of Insurance",
    "AK": "Alaska Division of Insurance",
    "AZ": "Arizona Department of Insurance and Financial Institutions",
    "AR": "Arkansas Insurance Department",
    "CA": "California Department of Insurance",
    "CO": "Colorado Division of Insurance",
    "CT": "Connecticut Insurance Department",
    "DE": "Delaware Department of Insurance",
    "FL": "Florida Department of Financial Services",
    "GA": "Georgia Office of Commissioner of Insurance and Safety Fire",
    "HI": "Hawaii Insurance Division",
    "ID": "Idaho Department of Insurance",
    "IL": "Illinois Department of Insurance",
    "IN": "Indiana Department of Insurance",
    "IA": "Iowa Insurance Division",
    "KS": "Kansas Department of Insurance",
    "KY": "Kentucky Department of Insurance",
    "LA": "Louisiana Department of Insurance",
    "ME": "Maine Bureau of Insurance",
    "MD": "Maryland Insurance Administration",
    "MA": "Massachusetts Division of Insurance",
    "MI": "Michigan Department of Insurance and Financial Services",
    "MN": "Minnesota Department of Commerce",
    "MS": "Mississippi Insurance Department",
    "MO": "Missouri Department of Commerce and Insurance",
    "MT": "Montana Commissioner of Securities and Insurance",
    "NE": "Nebraska Department of Insurance",
    "NV": "Nevada Division of Insurance",
    "NH": "New Hampshire Insurance Department",
    "NJ": "New Jersey Department of Banking and Insurance",
    "NM": "New Mexico Office of Superintendent of Insurance",
    "NY": "New York State Department of Financial Services",
    "NC": "North Carolina Department of Insurance",
    "ND": "North Dakota Insurance Department",
    "OH": "Ohio Department of Insurance",
    "OK": "Oklahoma Insurance Department",
    "OR": "Oregon Division of Financial Regulation",
    "PA": "Pennsylvania Insurance Department",
    "RI": "Rhode Island Department of Business Regulation",
    "SC": "South Carolina Department of Insurance",
    "SD": "South Dakota Division of Insurance",
    "TN": "Tennessee Department of Commerce and Insurance",
    "TX": "Texas Department of Insurance",
    "UT": "Utah Insurance Department",
    "VT": "Vermont Department of Financial Regulation",
    "VA": "Virginia State Corporation Commission, Bureau of Insurance",
    "WA": "Washington State Office of the Insurance Commissioner",
    "WV": "West Virginia Offices of the Insurance Commissioner",
    "WI": "Wisconsin Office of the Commissioner of Insurance",
    "WY": "Wyoming Department of Insurance",
}


def _state_source(state: str) -> LicensingCitation:
    slug = state.lower().replace(" ", "-")
    return LicensingCitation(
        label=f"NIPR {state} Resident Renewal Individual Requirements",
        url=(
            "https://nipr.com/licensing-center/state-requirements/"
            f"{slug}-resident-renewal-individual"
        ),
        supports="both",
        # A jurisdiction-specific NIPR page is valuable routing evidence, but
        # promotion requires a separate state-authority primary citation.
        primary=False,
        jurisdiction_specific=True,
        published_or_accessed=_AS_OF,
    )


def _row(code: str, state: str) -> StateLicensingRequirement:
    return StateLicensingRequirement(
        jurisdiction=code,
        state_name=state,
        authority_name=_AUTHORITIES[code],
        license_name="Insurance producer license",
        determination="source_check_required",
        scope_note=(
            "Select the state, applicant type, residency, and lines of authority in NIPR; "
            "confirm the resulting regulator requirements and primary state authority."
        ),
        renewal=RenewalRule(
            rule_kind="state_specific_expiration",
            filing_system="NIPR",
            opens=None,
            closes=None,
            reinstatement="state_specific",
            note=(
                "Renewal period, expiration date, fees, eligibility, continuing education, "
                "and reinstatement are state- and license-specific; refresh through NIPR "
                "and the issuing regulator before use."
            ),
        ),
        citations=(_state_source(state), _NIPR_RENEWAL, _NIPR_REQUIREMENTS),
    )


PACK = LicensingDataPack(
    schema_version=1,
    vertical="insurance_producer",
    version="1.0.0",
    as_of=_AS_OF,
    title="United States insurance-producer licensing source matrix",
    methodology=(
        "Fifty-state authority and resident-individual renewal matrix. Every row links "
        "directly to the jurisdiction-specific NIPR requirement page and remains "
        "source-check-required until its live rules are reviewed for the target lines of "
        "authority, residency, fees, continuing education, and reinstatement scenario."
    ),
    requirements=tuple(_row(code, state) for code, state in JURISDICTIONS.items()),
)

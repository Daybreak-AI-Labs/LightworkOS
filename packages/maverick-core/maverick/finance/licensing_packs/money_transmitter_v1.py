"""Money-transmitter state source-routing matrix, edition 1.0.0.

NMLS explicitly requires the state-specific checklist because requirements and
reinstatement vary by agency.  Accordingly this first edition encodes the
supported common renewal window and an official source route for every state,
but no unsupported state-law applicability conclusion.
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
_NMLS_RENEWAL = LicensingCitation(
    label="NMLS Annual Renewal Overview for Companies",
    url=("https://mortgage.nationwidelicensingsystem.org/knowledge/Products/nmls/"
         "pubs/ugCompState/licensing/company/topics/"
         "licComp_renew_nmlsAnnualRenewalOverviewForCompanies.html"),
    supports="renewal",
    # NMLS is the operational filing system, not by itself the controlling
    # state-law authority for an applicability conclusion.
    primary=False,
    jurisdiction_specific=False,
    published_or_accessed=_AS_OF,
)
_NMLS_STATE_CHECKLIST = LicensingCitation(
    label="NMLS Annual Renewal Checklist Compiler",
    url=("https://mortgage.nationwidelicensingsystem.org/knowledge/Products/nmls/"
         "stateresourcecenter/SitePages/Annual-Renewal-Checklist-Compiler.aspx"),
    supports="renewal",
    primary=False,
    jurisdiction_specific=False,
    published_or_accessed=_AS_OF,
)
_MMLA = LicensingCitation(
    label="NMLS Multistate MSB Licensing Agreement Program",
    url=("https://mortgage.nationwidelicensingsystem.org/knowledge/Products/nmls/"
         "stateresourcecenter/SitePages/MultistateMSBLicensingAgreementProgram.aspx"),
    supports="licensing",
    primary=False,
    jurisdiction_specific=False,
    published_or_accessed=_AS_OF,
)

_AUTHORITIES = {
    "AL": "Alabama Securities Commission",
    "AK": "Alaska Division of Banking and Securities",
    "AZ": "Arizona Department of Insurance and Financial Institutions",
    "AR": "Arkansas Securities Department",
    "CA": "California Department of Financial Protection and Innovation",
    "CO": "Colorado Division of Banking",
    "CT": "Connecticut Department of Banking",
    "DE": "Delaware Office of the State Bank Commissioner",
    "FL": "Florida Office of Financial Regulation",
    "GA": "Georgia Department of Banking and Finance",
    "HI": "Hawaii Division of Financial Institutions",
    "ID": "Idaho Department of Finance",
    "IL": "Illinois Department of Financial and Professional Regulation",
    "IN": "Indiana Department of Financial Institutions",
    "IA": "Iowa Division of Banking",
    "KS": "Kansas Office of the State Bank Commissioner",
    "KY": "Kentucky Department of Financial Institutions",
    "LA": "Louisiana Office of Financial Institutions",
    "ME": "Maine Bureau of Consumer Credit Protection",
    "MD": "Maryland Office of Financial Regulation",
    "MA": "Massachusetts Division of Banks",
    "MI": "Michigan Department of Insurance and Financial Services",
    "MN": "Minnesota Department of Commerce",
    "MS": "Mississippi Department of Banking and Consumer Finance",
    "MO": "Missouri Division of Finance",
    "MT": "Montana Division of Banking and Financial Institutions",
    "NE": "Nebraska Department of Banking and Finance",
    "NV": "Nevada Financial Institutions Division",
    "NH": "New Hampshire Banking Department",
    "NJ": "New Jersey Department of Banking and Insurance",
    "NM": "New Mexico Financial Institutions Division",
    "NY": "New York State Department of Financial Services",
    "NC": "North Carolina Office of the Commissioner of Banks",
    "ND": "North Dakota Department of Financial Institutions",
    "OH": "Ohio Division of Financial Institutions",
    "OK": "Oklahoma State Banking Department",
    "OR": "Oregon Division of Financial Regulation",
    "PA": "Pennsylvania Department of Banking and Securities",
    "RI": "Rhode Island Department of Business Regulation",
    "SC": "South Carolina Office of the Attorney General",
    "SD": "South Dakota Division of Banking",
    "TN": "Tennessee Department of Financial Institutions",
    "TX": "Texas Department of Banking",
    "UT": "Utah Department of Financial Institutions",
    "VT": "Vermont Department of Financial Regulation",
    "VA": "Virginia State Corporation Commission, Bureau of Financial Institutions",
    "WA": "Washington State Department of Financial Institutions",
    "WV": "West Virginia Division of Financial Institutions",
    "WI": "Wisconsin Department of Financial Institutions",
    "WY": "Wyoming Division of Banking",
}


def _state_source(code: str, state: str) -> LicensingCitation:
    return LicensingCitation(
        label=f"NMLS {state} Annual Renewal Checklist route",
        url=(
            "https://mortgage.nationwidelicensingsystem.org/knowledge/Products/"
            "nmls/stateresourcecenter/SitePages/"
            f"Annual-Renewal-Checklist-Compiler.aspx?StateID={code}"
        ),
        supports="both",
        # Keep the state-specific route useful without allowing a later row to
        # promote itself to a legal conclusion absent a state-authority source.
        primary=False,
        jurisdiction_specific=True,
        published_or_accessed=_AS_OF,
    )


def _row(code: str, state: str) -> StateLicensingRequirement:
    return StateLicensingRequirement(
        jurisdiction=code,
        state_name=state,
        authority_name=_AUTHORITIES[code],
        license_name="Money transmitter / money services business license",
        determination="source_check_required",
        scope_note=(
            "Determine activity coverage, exemptions, application requirements, and "
            "state-law authority from the current state-specific NMLS checklist before use."
        ),
        renewal=RenewalRule(
            rule_kind="nmls_annual_window",
            filing_system="NMLS",
            opens="11-01",
            closes="12-31",
            reinstatement="state_specific",
            note=(
                "The NMLS common company renewal period is November 1 through December 31; "
                "eligibility, fees, external steps, and reinstatement are state-specific "
                "and must be refreshed from the agency checklist."
            ),
        ),
        citations=(
            _state_source(code, state),
            _NMLS_RENEWAL,
            _NMLS_STATE_CHECKLIST,
            _MMLA,
        ),
    )


PACK = LicensingDataPack(
    schema_version=1,
    vertical="money_transmitter",
    version="1.0.0",
    as_of=_AS_OF,
    title="United States money-transmitter licensing source matrix",
    methodology=(
        "Fifty-state authority and state-resource matrix. Each row records the named "
        "state supervisor, a jurisdiction-specific NMLS resource, the NMLS common renewal "
        "window, and a fail-closed legal-review requirement before an applicability, "
        "exemption, fee, deadline, or reinstatement conclusion is promoted."
    ),
    requirements=tuple(_row(code, state) for code, state in JURISDICTIONS.items()),
)

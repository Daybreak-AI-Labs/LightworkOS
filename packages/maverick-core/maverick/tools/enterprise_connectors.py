"""Enterprise connector specs (the long tail), built on ``make_rest_tool``.

Each entry is a thin authenticated-REST tool: explicit-env auth, the agent
supplies the path, writes are confirm-gated. Add a system by appending one
spec here — no new module per connector. Systems that need a bespoke shape
(specific ops, GraphQL, CSRF, SQL result parsing) keep their own module
(servicenow_tool, snowflake_tool, sap_tool, ...).
"""
from __future__ import annotations

from functools import lru_cache

from ..catalog_schema import index_connector_specs
from . import Tool
from ._connector_specs import _GRAPHQL_SPECS, _SPECS
from ._rest_connector import _build_auth_headers


def _fill_env(spec: dict) -> dict:
    """Default a spec's env-var names from its ``name``.

    Almost every connector follows the ``<NAME>_BASE_URL`` / ``<NAME>_TOKEN``
    convention, so a spec only spells those out when it deviates (e.g.
    ``salesforce_commerce`` -> ``SFCC_*``). Filling them here keeps the spec
    list free of that mechanical, typo-prone repetition.
    """
    n = spec["name"].upper()
    spec.setdefault("base_url_env", f"{n}_BASE_URL")
    spec.setdefault("token_env", f"{n}_TOKEN")
    return spec


for _spec in (*_SPECS, *_GRAPHQL_SPECS):
    _fill_env(_spec)

# Compile the authoritative catalog once. Duplicate names or invalid credential
# metadata would otherwise silently overwrite a connector during setup.
_CONNECTOR_INDEX = index_connector_specs((*_SPECS, *_GRAPHQL_SPECS))
_REST_SPEC_INDEX = {spec["name"]: spec for spec in _SPECS}

# Read-only (GET-only) variants for finance vendors -- the bridge that
# lets a read-only pack (max_risk <= medium) pull narrowly-scoped data without
# handing it a write-capable seat. Same env/creds as the write connector; writes
# are structurally unreachable, and reads are constrained by explicit endpoint
# allowlists (allowed_read_paths). Risk is tracked explicitly in
# READ_CONNECTOR_RISKS so read-only seats for sensitive systems do not bypass
# low-risk ceilings.
_READ_SPECS: list[dict] = [
    dict(name="modern_treasury_read", base_url_env="MODERN_TREASURY_BASE_URL",
         token_env="MODERN_TREASURY_TOKEN", basic=True,
         allowed_read_paths=(
             "/api/internal_accounts",
             "/api/transactions",
             "/api/ledger_account_balances",
         ),
         description="Modern Treasury REST, READ-ONLY (GET) for cash-positioning paths "
         "only: /api/internal_accounts, /api/transactions, "
         "/api/ledger_account_balances. Auth: MODERN_TREASURY_BASE_URL "
         "(https://app.moderntreasury.com) + MODERN_TREASURY_TOKEN "
         "(Basic org_id:api_key)."),
]
_READ_CONNECTOR_RISKS: dict[str, str] = {"modern_treasury_read": "low"}


def _read_specs_for(vendors: list[str]) -> list[dict]:
    """Derive GET-only read specs from existing write connectors -- same base URL,
    token env, and auth mode (so creds + auth are correct by construction); only
    the name (``<vendor>_read``) and a read-only description differ. Unknown
    vendors are skipped rather than wedging import."""
    out: list[dict] = []
    for v in vendors:
        src = _REST_SPEC_INDEX.get(v)
        if src is None:
            continue
        spec = {k: val for k, val in src.items() if k not in ("name", "description")}
        spec["name"] = f"{v}_read"
        spec["description"] = (
            f"{v} REST, READ-ONLY (GET) -- read records/balances; the agent supplies "
            f"the path. Reuses {src['base_url_env']} + {src['token_env']} (same creds "
            f"and auth as the '{v}' connector)."
        )
        out.append(spec)
    return out


# Finance vendors whose read-only/draft packs need to pull data: each gets a
# GET-only, LOW-risk variant (wired into the matching pack's allow_tools), so the
# whole CFO office can read its systems while money tools stay denied.
_FINANCE_READ_VENDORS: list[str] = [
    "billdotcom", "coupa", "ariba", "chargebee", "netsuite", "carta",
    "concur", "ramp", "adp", "gusto", "workiva", "avalara",
]
_FINANCE_READ_SPECS = _read_specs_for(_FINANCE_READ_VENDORS)
_READ_SPECS += _FINANCE_READ_SPECS
_READ_CONNECTOR_RISKS.update({s["name"]: "low" for s in _FINANCE_READ_SPECS})

# Tax-engine read seats: the tax_ suite's read-only packs may check narrow
# operational status/locator endpoints in the firm's professional tax engine
# (CCH Axcess / GoSystem). They must not inherit unrestricted GET access from
# the write connector because tax-engine APIs also expose taxpayer documents and
# full returns. Submitting or modifying a return stays on the write connector
# (high risk, confirm-gated, unreachable from the low-risk packs by construction).
_TAX_READ_ALLOWLISTS: dict[str, tuple[str, ...]] = {
    "cch_axcess_read": (
        "/api/TaxService/v1.0/eFileStatus",
        "/api/TaxService/v1.0/locators",
    ),
    "gosystem_tax_read": (
        "/e-file-status",
        "/efile-status",
        "/locators",
    ),
}
_TAX_READ_VENDORS: list[str] = ["cch_axcess", "gosystem_tax"]
_TAX_READ_SPECS = _read_specs_for(_TAX_READ_VENDORS)
for _spec in _TAX_READ_SPECS:
    _allowed = _TAX_READ_ALLOWLISTS.get(_spec["name"], ())
    _spec["allowed_read_paths"] = _allowed
    _spec["description"] += (
        " Low-risk seat is restricted to these status/locator prefixes: "
        + ", ".join(_allowed)
        + ". Use the high-risk write connector for broader tax-engine access."
    )
_READ_SPECS += _TAX_READ_SPECS
_READ_CONNECTOR_RISKS.update({s["name"]: "low" for s in _TAX_READ_SPECS})

# Read seats for the OTHER suites' systems, derived the same way (GET-only,
# reuse the write connector's creds). These systems often contain high-confidentiality
# identity, HR, security, CI/CD, legal, and customer data, so the read seats are
# fail-closed as high risk unless an operator deliberately overrides them.
# Bespoke-module vendors (Salesforce, HubSpot,
# Jira, GitHub, Datadog, ...) aren't in _SPECS, so they're skipped here -- this
# covers the spec'd long-tail systems each suite reads.
_SUITE_READ_VENDORS: list[str] = [
    # GTM / Sales -- sales engagement, marketing, enrichment, CS, analytics
    "salesloft", "outreach", "gong", "clari", "apollo", "zoominfo", "clearbit",
    "marketo", "klaviyo", "braze", "mailchimp", "sfmc", "iterable", "segment",
    "amplitude", "gainsight", "pendo", "pipedrive", "sugarcrm", "eventbrite",
    "cvent", "sprinklr",
    # Legal -- CLM, e-signature, practice management
    "ironclad", "contractbook", "clio", "docusign",
    # Operations / supply chain -- logistics, fleet, shipping (coupa/ariba reuse finance)
    "flexport", "samsara", "easypost", "shippo",
    # HR / People -- HRIS, recruiting, performance (gusto/adp reuse finance)
    "bamboohr", "greenhouse", "lever", "rippling", "smartrecruiters", "workable",
    "deel", "paylocity", "paychex", "lattice", "cornerstone", "icims", "hibob",
    "ukg", "successfactors",
    # IT / GRC / Security -- identity, EDR/SIEM, vuln, GRC automation
    "okta", "auth0", "onelogin", "pingone", "duo", "cyberark", "sailpoint",
    "crowdstrike", "splunk", "zscaler", "tenable", "qualys", "rapid7",
    "sentinelone", "proofpoint", "snyk", "fortinet", "vanta", "drata", "logicgate",
    "netskope", "cisco_umbrella", "defender", "qradar", "palo_alto", "jamf",
    "secureframe", "sumologic", "logicmonitor", "appdynamics",
    # Product / Engineering -- CI/CD, code quality, feature flags, observability
    "jenkins", "circleci", "jfrog", "sonarqube", "azure_devops", "launchdarkly",
    "split", "argocd", "harness", "octopus_deploy", "dockerhub", "newrelic",
    "dynatrace", "grafana", "opsgenie",
    # Strategy / CorpDev -- market intel, BI / analytics, EPM
    "crunchbase", "tableau", "powerbi", "looker", "qlik", "thoughtspot",
    "sisense", "domo", "mode", "metabase", "anaplan", "microstrategy", "cognos",
]
_SUITE_READ_SPECS = _read_specs_for(_SUITE_READ_VENDORS)
_READ_SPECS += _SUITE_READ_SPECS
_READ_CONNECTOR_RISKS.update({s["name"]: "high" for s in _SUITE_READ_SPECS})

# --- Primary-source / public-reference data connectors ----------------------
# Authoritative GOVERNMENT and public data APIs that ground the analyst-style
# packs (finance, banking, insurance, legal, GRC, gov-contracting, healthcare,
# utilities, ESG, strategy) in primary sources instead of model memory. All are
# GET-only and LOW risk: they read public reference data, mutate nothing, and
# carry no customer/tenant secrets. Most are keyless (a fixed public host, no
# credential); some take a free API key delivered either as a header or a query
# param (never from the prompt -- it comes from the connector's env var).
#
# ``_pub`` fills the standard env names so a spec is one line. A keyless spec
# ships a ``default_base_url`` so it works with zero config; a keyed spec needs
# only its ``*_API_KEY`` env var (the base URL still defaults).
def _pub(name: str, default_base_url: str, description: str, **kw) -> dict:
    return dict(
        name=name,
        base_url_env=f"{name.upper()}_BASE_URL",
        token_env=f"{name.upper()}_API_KEY",
        default_base_url=default_base_url,
        description=description,
        **kw,
    )


_PUBLIC_DATA_SPECS: list[dict] = [
    # --- Financial markets & macroeconomic data ---
    _pub("fred", "https://api.stlouisfed.org", query_auth="api_key",
         description="FRED (St. Louis Fed) economic data, READ-ONLY. e.g. "
         "/fred/series/observations?series_id=GDP&file_type=json. Key as query "
         "param. Auth: FRED_API_KEY (free)."),
    _pub("sec_edgar", "https://data.sec.gov", keyless=True,
         description="SEC EDGAR company filings & XBRL facts, READ-ONLY, keyless. "
         "e.g. /submissions/CIK0000320193.json, "
         "/api/xbrl/companyconcept/CIK0000320193/us-gaap/Revenues.json. "
         "Send a descriptive User-Agent via SEC_EDGAR_* if required."),
    _pub("treasury_fiscaldata", "https://api.fiscaldata.treasury.gov", keyless=True,
         description="U.S. Treasury Fiscal Data, READ-ONLY, keyless. e.g. "
         "/services/api/fiscal_service/v2/accounting/od/avg_interest_rates."),
    _pub("world_bank", "https://api.worldbank.org", keyless=True,
         description="World Bank Open Data, READ-ONLY, keyless. e.g. "
         "/v2/country/US/indicator/NY.GDP.MKTP.CD?format=json."),
    _pub("imf", "https://www.imf.org/external/datamapper/api", keyless=True,
         description="IMF DataMapper, READ-ONLY, keyless. e.g. /v1/NGDP_RPCH/USA."),
    _pub("fdic", "https://banks.data.fdic.gov", keyless=True,
         description="FDIC BankFind (institutions & financials), READ-ONLY, keyless. "
         "e.g. /api/financials?filters=STNAME:Texas&fields=REPDTE,ASSET."),
    _pub("bea", "https://apps.bea.gov", query_auth="UserID",
         description="Bureau of Economic Analysis, READ-ONLY. e.g. "
         "/api/data?method=GetData&datasetname=NIPA&... UserID as query param. "
         "Auth: BEA_API_KEY (free)."),
    _pub("census", "https://api.census.gov", query_auth="key",
         description="U.S. Census Bureau data, READ-ONLY. e.g. "
         "/data/2022/acs/acs5?get=NAME,B01001_001E&for=state:*. Key as query "
         "param. Auth: CENSUS_API_KEY (free)."),
    _pub("bls", "https://api.bls.gov", keyless=True,
         description="Bureau of Labor Statistics v1, READ-ONLY, keyless. e.g. "
         "/publicAPI/v1/timeseries/data/CUUR0000SA0 (CPI series)."),
    _pub("eia", "https://api.eia.gov", query_auth="api_key",
         description="EIA energy data, READ-ONLY. e.g. "
         "/v2/electricity/rto/region-data/data?... Key as query param. "
         "Auth: EIA_API_KEY (free)."),
    _pub("alphavantage", "https://www.alphavantage.co", query_auth="apikey",
         description="Alpha Vantage market data, READ-ONLY. e.g. "
         "/query?function=TIME_SERIES_DAILY&symbol=IBM. Key as query param. "
         "Auth: ALPHAVANTAGE_API_KEY (free)."),
    _pub("finnhub", "https://finnhub.io", token_header="X-Finnhub-Token", scheme="",
         description="Finnhub market data, READ-ONLY. e.g. /api/v1/quote?symbol=AAPL, "
         "/api/v1/stock/profile2?symbol=AAPL. Auth: FINNHUB_API_KEY (X-Finnhub-Token)."),
    _pub("polygon", "https://api.polygon.io",
         description="Polygon.io market data, READ-ONLY (Bearer). e.g. "
         "/v3/reference/tickers, /v2/aggs/ticker/AAPL/range/1/day/2024-01-01/2024-02-01. "
         "Auth: POLYGON_API_KEY (Bearer)."),
    _pub("openfigi", "https://api.openfigi.com", token_header="X-OPENFIGI-APIKEY", scheme="",
         description="OpenFIGI security-identifier mapping, READ-ONLY. POST-style "
         "mapping is read-shaped; e.g. GET /v3/search. Auth: OPENFIGI_API_KEY."),
    # --- Regulatory / legal / government ---
    _pub("federal_register", "https://www.federalregister.gov", keyless=True,
         description="U.S. Federal Register, READ-ONLY, keyless. e.g. "
         "/api/v1/documents.json?conditions[term]=privacy&per_page=20."),
    _pub("ecfr", "https://www.ecfr.gov", keyless=True,
         description="Electronic Code of Federal Regulations, READ-ONLY, keyless. "
         "e.g. /api/versioner/v1/titles.json, /api/search/v1/results?query=."),
    _pub("regulations_gov", "https://api.regulations.gov",
         token_header="X-Api-Key", scheme="",
         description="Regulations.gov dockets & comments, READ-ONLY. e.g. "
         "/v4/documents?filter[searchTerm]=. Auth: REGULATIONS_GOV_API_KEY "
         "(X-Api-Key; free via api.data.gov)."),
    _pub("courtlistener", "https://www.courtlistener.com", scheme="Token",
         description="CourtListener case law & dockets, READ-ONLY. e.g. "
         "/api/rest/v4/search/?q=, /api/rest/v4/opinions/. Auth: "
         "COURTLISTENER_API_KEY (Authorization: Token <key>)."),
    _pub("govinfo", "https://api.govinfo.gov", query_auth="api_key",
         description="GovInfo (bills, CFR, public laws), READ-ONLY. e.g. "
         "/collections, /packages/{id}/summary. Key as query param. "
         "Auth: GOVINFO_API_KEY (free via api.data.gov)."),
    _pub("usaspending", "https://api.usaspending.gov", keyless=True,
         description="USAspending federal awards/spending, READ-ONLY, keyless. e.g. "
         "/api/v2/search/spending_by_award/ (POST search is read-shaped)."),
    _pub("sam_gov", "https://api.sam.gov", query_auth="api_key",
         description="SAM.gov entity registration & exclusions, READ-ONLY. e.g. "
         "/entity-information/v3/entities?ueiSAM=. Key as query param. "
         "Auth: SAM_GOV_API_KEY (free via api.data.gov)."),
    _pub("openstates", "https://v3.openstates.org", token_header="X-API-KEY", scheme="",
         description="Open States (state legislatures), READ-ONLY. e.g. /bills?jurisdiction=, "
         "/people. Auth: OPENSTATES_API_KEY (X-API-KEY)."),
    _pub("patentsview", "https://search.patentsview.org", keyless=True,
         description="PatentsView (USPTO patent data), READ-ONLY, keyless. e.g. "
         "/api/v1/patent/?q={...}&f={...}."),
    # --- Company / legal-entity registries ---
    _pub("gleif", "https://api.gleif.org", keyless=True,
         description="GLEIF Legal Entity Identifier (LEI) registry, READ-ONLY, keyless. "
         "e.g. /api/v1/lei-records?filter[entity.legalName]=Apple."),
    _pub("opencorporates", "https://api.opencorporates.com", query_auth="api_token",
         description="OpenCorporates company registry, READ-ONLY. e.g. "
         "/v0.4/companies/search?q=. Token as query param. Auth: OPENCORPORATES_API_KEY."),
    _pub("companies_house", "https://api.company-information.service.gov.uk", basic=True,
         description="UK Companies House, READ-ONLY (basic: API key as username). e.g. "
         "/search/companies?q=, /company/{number}. Auth: COMPANIES_HOUSE_API_KEY."),
    # --- Health / life sciences ---
    _pub("openfda", "https://api.fda.gov", keyless=True,
         description="openFDA (drug/device/food adverse events, recalls, labels), "
         "READ-ONLY, keyless. e.g. /drug/event.json?search=&limit=5, "
         "/device/recall.json?search=."),
    _pub("nppes", "https://npiregistry.cms.hhs.gov", keyless=True,
         description="NPPES NPI Registry (US healthcare providers), READ-ONLY, keyless. "
         "e.g. /api/?version=2.1&number=&first_name=&state=."),
    _pub("clinicaltrials", "https://clinicaltrials.gov", keyless=True,
         description="ClinicalTrials.gov v2, READ-ONLY, keyless. e.g. "
         "/api/v2/studies?query.term=diabetes&pageSize=10."),
    _pub("rxnorm", "https://rxnav.nlm.nih.gov", keyless=True,
         description="RxNorm/RxNav drug normalization, READ-ONLY, keyless. e.g. "
         "/REST/rxcui.json?name=ibuprofen, /REST/interaction/interaction.json?rxcui=."),
    _pub("pubmed", "https://eutils.ncbi.nlm.nih.gov", keyless=True,
         description="PubMed/NCBI E-utilities, READ-ONLY, keyless. e.g. "
         "/entrez/eutils/esearch.fcgi?db=pubmed&term=&retmode=json."),
    # --- Geo / weather / energy / environment (ESG) ---
    _pub("nws_weather", "https://api.weather.gov", keyless=True,
         description="US National Weather Service, READ-ONLY, keyless. e.g. "
         "/points/{lat},{lon}, /gridpoints/{office}/{x},{y}/forecast, /alerts/active."),
    _pub("noaa_climate", "https://www.ncdc.noaa.gov", token_header="token", scheme="",
         description="NOAA Climate Data Online, READ-ONLY. e.g. "
         "/cdo-web/api/v2/data?datasetid=GHCND&... Auth: NOAA_CLIMATE_API_KEY (token header)."),
    _pub("openweather", "https://api.openweathermap.org", query_auth="appid",
         description="OpenWeather, READ-ONLY. e.g. /data/2.5/weather?q=London. "
         "Key as query param (appid). Auth: OPENWEATHER_API_KEY."),
    _pub("epa_envirofacts", "https://data.epa.gov", keyless=True,
         description="EPA Envirofacts environmental data, READ-ONLY, keyless. e.g. "
         "/efservice/{table}/{column}/{value}/JSON."),
    _pub("climatiq", "https://api.climatiq.io",
         description="Climatiq carbon-emission factors/estimates, READ-ONLY (Bearer). "
         "e.g. /data/v1/search?query=electricity. Auth: CLIMATIQ_API_KEY (Bearer)."),
    _pub("carbon_interface", "https://www.carboninterface.com",
         description="Carbon Interface emission estimates, READ-ONLY (Bearer). e.g. "
         "GET /api/v1/estimates/{id}. Auth: CARBON_INTERFACE_API_KEY (Bearer)."),
]
_READ_SPECS += _PUBLIC_DATA_SPECS
_READ_CONNECTOR_RISKS.update({s["name"]: "low" for s in _PUBLIC_DATA_SPECS})
# Names of just the primary-source data connectors, for docs/tests.
PUBLIC_DATA_CONNECTOR_NAMES: list[str] = [s["name"] for s in _PUBLIC_DATA_SPECS]

# The public host each data connector reaches (from its default base URL). Used
# when an operator wants to widen a host-restricted pack's egress to admit a
# granted data connector -- the grant itself (see domain.py) never loosens a
# pack's allow_hosts automatically.
from urllib.parse import urlsplit as _urlsplit  # noqa: E402

PUBLIC_DATA_CONNECTOR_HOSTS: dict[str, str] = {
    s["name"]: _urlsplit(s["default_base_url"]).netloc for s in _PUBLIC_DATA_SPECS
}


# --- Suite -> primary-source data connectors --------------------------------
# Which public-data connectors each business suite's packs get in their
# capability envelope, so an analyst pack reaches for FRED/SEC EDGAR/openFDA/etc.
# by default instead of guessing. All are GET-only and LOW risk, so they sit
# under a read-only pack's ceiling. Layered centrally in domain.domain_capability
# (additive to allow_tools; deferred, so no context cost until find_tools).
#
# Reusable bundles, composed per suite below. Keep a suite's set curated -- the
# few sources its work actually grounds in, not the whole catalogue.
_MARKETS_CORE = frozenset({
    "fred", "sec_edgar", "treasury_fiscaldata", "world_bank", "bls",
    "alphavantage", "finnhub", "polygon", "openfigi",
})
_ENTITY = frozenset({"gleif", "opencorporates", "companies_house"})
_REG_FED = frozenset({"federal_register", "ecfr", "regulations_gov", "govinfo"})
_GOV_SPEND = frozenset({"usaspending", "sam_gov"})
_HEALTH = frozenset({"openfda", "nppes", "clinicaltrials", "rxnorm", "pubmed"})
_CLIMATE = frozenset({
    "nws_weather", "noaa_climate", "openweather", "epa_envirofacts",
    "climatiq", "carbon_interface",
})
_STATS = frozenset({"census", "bls", "fred", "world_bank"})

SUITE_DATA_CONNECTORS: dict[str, frozenset[str]] = {
    # --- Finance / capital / deals / banking / insurance / tax ---
    "finance": _MARKETS_CORE | _ENTITY | frozenset({"bea"}),
    "capital_markets": _MARKETS_CORE | frozenset({"imf", "bea", "gleif", "openfigi"}),
    "private_equity_vc": _MARKETS_CORE | _ENTITY | frozenset({"sam_gov", "usaspending"}),
    "banking": frozenset({
        "fdic", "fred", "treasury_fiscaldata", "sec_edgar", "bls", "census",
    }) | _ENTITY,
    "insurance": frozenset({
        "nws_weather", "noaa_climate", "fred", "treasury_fiscaldata", "sec_edgar",
        "bls", "census", "fdic", "epa_envirofacts",
    }),
    "tax": _REG_FED | frozenset({"courtlistener", "sec_edgar", "bls", "census", "fred"}),
    # --- Legal / GRC / risk / trust&safety / IP ---
    "legal": frozenset({"courtlistener", "patentsview"}) | _REG_FED | _ENTITY
             | frozenset({"sec_edgar", "sam_gov"}),
    "it_grc": _REG_FED | frozenset({"sec_edgar"}),
    "security_ops": frozenset({"federal_register", "regulations_gov"}),
    "enterprise_risk": frozenset({
        "fred", "world_bank", "imf", "sec_edgar", "nws_weather", "noaa_climate",
    }) | _REG_FED | _ENTITY,
    "trust_safety": frozenset({"federal_register", "regulations_gov", "courtlistener"}),
    # --- Government / public sector / aero-defense / education ---
    "government_contracting": _GOV_SPEND | _REG_FED | frozenset({"sec_edgar"}),
    "public_sector": _GOV_SPEND | _REG_FED
                     | frozenset({"openstates", "census", "bls"}),
    "aerospace_defense": _GOV_SPEND | frozenset({
        "sec_edgar", "federal_register", "patentsview", "world_bank", "bls",
    }),
    "education_nonprofit": frozenset({
        "census", "bls", "fred", "federal_register", "world_bank",
    }) | _GOV_SPEND,
    # --- Health / life sciences / devices ---
    "healthcare": _HEALTH | frozenset({"federal_register", "regulations_gov"}),
    "medical_devices": frozenset({
        "openfda", "clinicaltrials", "pubmed", "patentsview",
        "federal_register", "regulations_gov",
    }),
    "pharma_lifesciences": frozenset({
        "openfda", "clinicaltrials", "pubmed", "rxnorm", "patentsview",
        "federal_register", "regulations_gov", "sec_edgar",
    }),
    # --- Energy / utilities / environment / ESG / ag ---
    "utilities": frozenset({
        "eia", "nws_weather", "noaa_climate", "epa_envirofacts",
        "federal_register", "fred",
    }),
    "water_utilities": frozenset({
        "epa_envirofacts", "nws_weather", "noaa_climate", "eia", "federal_register",
    }),
    "oil_gas": frozenset({
        "eia", "epa_envirofacts", "nws_weather", "noaa_climate",
        "federal_register", "sec_edgar", "world_bank",
    }),
    "renewables_cleantech": frozenset({
        "eia", "climatiq", "carbon_interface", "epa_envirofacts",
        "nws_weather", "noaa_climate", "fred",
    }),
    "esg_sustainability": _CLIMATE | frozenset({
        "eia", "sec_edgar", "federal_register", "world_bank",
    }),
    "agriculture": frozenset({
        "nws_weather", "noaa_climate", "epa_envirofacts", "eia",
        "world_bank", "census", "fred", "climatiq",
    }),
    "facilities_ehs": frozenset({
        "epa_envirofacts", "nws_weather", "noaa_climate", "eia",
        "federal_register", "regulations_gov",
    }),
    # --- Industrials / materials / mobility ---
    "manufacturing_vertical": frozenset({
        "bls", "fred", "census", "eia", "epa_envirofacts", "world_bank", "patentsview",
    }),
    "chemicals": frozenset({
        "epa_envirofacts", "federal_register", "regulations_gov", "eia",
        "patentsview", "nws_weather",
    }),
    "mining_metals": frozenset({
        "world_bank", "fred", "eia", "epa_envirofacts", "nws_weather", "sec_edgar",
    }),
    "automotive": frozenset({
        "bls", "fred", "census", "epa_envirofacts", "patentsview", "world_bank",
    }),
    "semiconductors": frozenset({
        "sec_edgar", "world_bank", "census", "bls", "patentsview", "fred", "finnhub",
    }),
    "construction": frozenset({
        "bls", "fred", "census", "nws_weather", "epa_envirofacts", "eia", "world_bank",
    }),
    # --- Logistics / maritime / travel ---
    "logistics": frozenset({
        "nws_weather", "noaa_climate", "eia", "census", "world_bank",
        "federal_register", "usaspending",
    }),
    "maritime": frozenset({
        "nws_weather", "noaa_climate", "world_bank", "eia", "federal_register",
    }),
    "travel_aviation": frozenset({
        "nws_weather", "noaa_climate", "bls", "fred", "world_bank",
        "eia", "federal_register",
    }),
    # --- Consumer / retail / media ---
    "retail": frozenset({
        "census", "bls", "fred", "world_bank", "openfda", "epa_envirofacts",
    }),
    "food_beverage_cpg": frozenset({
        "openfda", "epa_envirofacts", "census", "bls", "fred",
        "nws_weather", "federal_register", "regulations_gov",
    }),
    "hospitality": frozenset({"bls", "fred", "census", "nws_weather", "world_bank"}),
    "telecom_media": frozenset({
        "federal_register", "regulations_gov", "sec_edgar",
        "census", "bls", "fred", "patentsview",
    }),
    "crypto_digital_assets": frozenset({
        "sec_edgar", "federal_register", "regulations_gov", "courtlistener",
        "fred", "finnhub", "world_bank",
    }),
    "real_estate": frozenset({
        "fred", "census", "fdic", "treasury_fiscaldata", "nws_weather",
        "epa_envirofacts", "world_bank", "bls",
    }),
    # --- Cross-functional horizontals ---
    "strategy": _MARKETS_CORE | _ENTITY | frozenset({
        "imf", "census", "patentsview", "federal_register",
    }),
    "operations": frozenset({"bls", "fred", "census", "eia", "nws_weather", "world_bank"}),
    "procurement": _GOV_SPEND | _ENTITY | frozenset({"sec_edgar", "fred", "bls"}),
    "professional_services": frozenset({
        "sec_edgar", "courtlistener", "federal_register", "fred", "bls",
    }) | _ENTITY,
    "hr": frozenset({"bls", "census", "fred", "federal_register", "regulations_gov"}),
    "sales_gtm": frozenset({"sec_edgar", "fred", "bls"}) | _ENTITY,
    "marketing": frozenset({"census", "bls", "fred", "world_bank"}),
    "data_analytics": frozenset({"census", "bls", "fred", "world_bank", "eia", "sec_edgar"}),
    "executive_office": frozenset({"sec_edgar", "fred", "world_bank", "bls", "federal_register"}),
    "knowledge_management": frozenset({"pubmed", "patentsview", "federal_register", "sec_edgar"}),
    "product_engineering": frozenset({"patentsview", "federal_register", "sec_edgar"}),
}


def data_connectors_for_suite(suite: str | None) -> frozenset[str]:
    """The primary-source data connectors a suite's packs are granted (read-only,
    low-risk). Empty for an unmapped/None suite."""
    if not suite:
        return frozenset()
    return SUITE_DATA_CONNECTORS.get(suite, frozenset())

READ_CONNECTOR_NAMES: list[str] = [s["name"] for s in _READ_SPECS]
READ_CONNECTOR_RISKS: dict[str, str] = {
    name: _READ_CONNECTOR_RISKS.get(name, "high") for name in READ_CONNECTOR_NAMES
}

ENTERPRISE_CONNECTOR_NAMES: list[str] = (
    [s["name"] for s in _SPECS] + [s["name"] for s in _GRAPHQL_SPECS]
)


def auth_headers_for(
    connector: str, token: str, *, include_extra_headers_env: bool = True,
) -> dict[str, str]:
    """Auth headers for probing ``connector`` with ``token``.

    By default this mirrors the connector tool's bearer/basic/custom-scheme
    translation, including any operator-provided auxiliary env headers used by
    trusted connector calls. User-controlled saved-connection tests must pass
    ``include_extra_headers_env=False`` so environment secrets are not sent to
    arbitrary ``base_url`` values. Unknown connectors fall back to standard
    Bearer.
    """
    spec = next((s for s in _SPECS + _READ_SPECS + _GRAPHQL_SPECS
                 if s.get("name") == connector), {})
    return _build_auth_headers(
        token, basic=bool(spec.get("basic")),
        token_header=str(spec.get("token_header", "Authorization")),
        scheme=str(spec.get("scheme", "Bearer")),
        extra_headers_env=(spec.get("extra_headers_env")
                           if include_extra_headers_env else None),
    )


@lru_cache(maxsize=1)
def enterprise_connector_descriptors():
    """Process-shared immutable catalog; no factory or credential resolution."""
    from ._lazy import ToolDescriptor, freeze
    from ._rest_connector import _GQL_SCHEMA, _READ_SCHEMA, _SCHEMA

    schemas = [freeze(schema) for schema in (_SCHEMA, _GQL_SCHEMA, _READ_SCHEMA)]
    groups = ((_SPECS, "make_rest_tool", schemas[0], {}),
              (_GRAPHQL_SPECS, "make_graphql_tool", schemas[1], {}),
              (_READ_SPECS, "make_rest_tool", schemas[2], {"read_only": True}))
    return tuple(
        ToolDescriptor(name=spec["name"], description=spec["description"],
                       input_schema=schema, factory_module="maverick.tools._rest_connector",
                       factory_name=factory, factory_kwargs={**spec, **extra})
        for specs, factory, schema, extra in groups for spec in specs
    )


def enterprise_connectors() -> list[Tool]:
    """Bind cheap tool views; instantiate each connector only on first use."""
    from ._lazy import LazyTool

    return [LazyTool(descriptor) for descriptor in enterprise_connector_descriptors()]


# Bespoke (hand-written) strategic connectors live in their own modules, not in
# _SPECS, and some use a non-uniform env shape (account/project/location rather
# than base-URL + token). List their env vars here so the installer wizard can
# collect them too. Each env entry is (ENV_NAME, is_secret).
_BESPOKE_CATALOG: list[dict] = [
    {"name": "servicenow", "label": "ServiceNow",
     "env": [("SERVICENOW_INSTANCE_URL", False), ("SERVICENOW_TOKEN", True)]},
    {"name": "snowflake", "label": "Snowflake",
     "env": [("SNOWFLAKE_ACCOUNT", False), ("SNOWFLAKE_TOKEN", True)]},
    {"name": "databricks", "label": "Databricks",
     "env": [("DATABRICKS_HOST", False), ("DATABRICKS_TOKEN", True),
             ("DATABRICKS_WAREHOUSE_ID", False)]},
    {"name": "onetrust", "label": "OneTrust",
     "env": [("ONETRUST_HOSTNAME", False), ("ONETRUST_TOKEN", True)]},
    {"name": "vertex", "label": "Google Vertex AI",
     "env": [("VERTEX_PROJECT", False), ("VERTEX_LOCATION", False),
             ("VERTEX_ACCESS_TOKEN", True)]},
    {"name": "oracle", "label": "Oracle (ORDS)",
     "env": [("ORACLE_ORDS_URL", False), ("ORACLE_ORDS_TOKEN", True)]},
    {"name": "sap", "label": "SAP (OData)",
     "env": [("SAP_BASE_URL", False), ("SAP_TOKEN", True)]},
    {"name": "workday", "label": "Workday",
     "env": [("WORKDAY_BASE_URL", False), ("WORKDAY_TOKEN", True)]},
    {"name": "bigquery", "label": "Google BigQuery",
     "env": [("BIGQUERY_PROJECT", False), ("BIGQUERY_ACCESS_TOKEN", True)]},
    {"name": "dynamics", "label": "Microsoft Dynamics 365",
     "env": [("DYNAMICS_RESOURCE_URL", False), ("DYNAMICS_TOKEN", True),
             ("DYNAMICS_API_VERSION", False)]},
    {"name": "database", "label": "Relational database (SQLAlchemy URL)",
     "env": [("DATABASE_URL", True)]},
    # Other always-registered bespoke connectors (headline SaaS). (AWS s3/lambda/
    # dynamodb/ses/sns and airtable/asana/clickup/vercel/gdrive are gated behind
    # MAVERICK_ENABLE_CRED_TOOLS, so they're documented there, not offered here.)
    {"name": "salesforce", "label": "Salesforce",
     "env": [("SALESFORCE_INSTANCE_URL", False), ("SALESFORCE_ACCESS_TOKEN", True)]},
    {"name": "hubspot", "label": "HubSpot", "env": [("HUBSPOT_TOKEN", True)]},
    {"name": "stripe", "label": "Stripe", "env": [("STRIPE_SECRET_KEY", True)]},
    {"name": "shopify", "label": "Shopify",
     "env": [("SHOPIFY_STORE", False), ("SHOPIFY_ACCESS_TOKEN", True)]},
    {"name": "twilio", "label": "Twilio",
     "env": [("TWILIO_ACCOUNT_SID", False), ("TWILIO_AUTH_TOKEN", True),
             ("TWILIO_FROM_NUMBER", False)]},
    {"name": "sentry", "label": "Sentry",
     "env": [("SENTRY_HOST", False), ("SENTRY_AUTH_TOKEN", True)]},
    {"name": "datadog", "label": "Datadog",
     "env": [("DATADOG_API_KEY", True), ("DATADOG_APP_KEY", True)]},
    {"name": "pagerduty", "label": "PagerDuty",
     "env": [("PAGERDUTY_API_TOKEN", True), ("PAGERDUTY_EVENTS_KEY", True)]},
    {"name": "bitbucket", "label": "Bitbucket",
     "env": [("BITBUCKET_ACCESS_TOKEN", True)]},
    {"name": "cloudflare", "label": "Cloudflare",
     "env": [("CLOUDFLARE_API_TOKEN", True), ("CLOUDFLARE_ZONE_ID", False)]},
    {"name": "confluence", "label": "Confluence",
     "env": [("CONFLUENCE_URL", False), ("CONFLUENCE_USER", False),
             ("CONFLUENCE_API_TOKEN", True)]},
    {"name": "elasticsearch", "label": "Elasticsearch",
     "env": [("ES_URL", False), ("ES_API_KEY", True)]},
    {"name": "plaid", "label": "Plaid",
     "env": [("PLAID_CLIENT_ID", False), ("PLAID_SECRET", True)]},
    {"name": "calendly", "label": "Calendly", "env": [("CALENDLY_TOKEN", True)]},
    {"name": "trello", "label": "Trello",
     "env": [("TRELLO_KEY", True), ("TRELLO_TOKEN", True)]},
    {"name": "replicate", "label": "Replicate",
     "env": [("REPLICATE_API_TOKEN", True)]},
    {"name": "mixpanel", "label": "Mixpanel",
     "env": [("MIXPANEL_PROJECT_ID", False), ("MIXPANEL_PROJECT_TOKEN", True),
             ("MIXPANEL_SERVICE_SECRET", True)]},
    {"name": "posthog", "label": "PostHog",
     "env": [("POSTHOG_HOST", False), ("POSTHOG_PROJECT_ID", False),
             ("POSTHOG_API_KEY", True), ("POSTHOG_PERSONAL_API_KEY", True)]},
    {"name": "plausible", "label": "Plausible",
     "env": [("PLAUSIBLE_HOST", False), ("PLAUSIBLE_SITE_ID", False),
             ("PLAUSIBLE_API_KEY", True)]},
    {"name": "ga4", "label": "Google Analytics 4",
     "env": [("GA4_PROPERTY_ID", False), ("GA4_MEASUREMENT_ID", False),
             ("GA4_ACCESS_TOKEN", True), ("GA4_API_SECRET", True)]},
    {"name": "zoom", "label": "Zoom",
     "env": [("ZOOM_USER_ID", False), ("ZOOM_OAUTH_TOKEN", True)]},
    {"name": "teams", "label": "Microsoft Teams",
     "env": [("TEAMS_WEBHOOK_URL", True)]},
]


def _label_from_desc(desc: str) -> str:
    head = desc.split(". ")[0].strip().rstrip(".")
    for suffix in (" GraphQL", " OData REST", " REST"):
        if head.endswith(suffix):
            return head[: -len(suffix)].strip()
    return head


def connector_catalog() -> list[dict]:
    """The installer's source of truth for every connector and the env vars it
    needs. Each entry is ``{"name", "label", "env": [(ENV_NAME, is_secret), ...]}``.

    Connectors are always registered in the kernel; they only need their env
    vars set to work. The wizard reads this to know what to prompt for, and
    ``docs/connectors.md`` is generated from it.
    """
    out: list[dict] = []
    for spec in _SPECS + _GRAPHQL_SPECS:
        env = [(spec["base_url_env"], False), (spec["token_env"], True)]
        # Second credentials (APIM subscription keys etc.) are secrets too.
        env += [(e, True) for e in (spec.get("extra_headers_env") or {}).values()]
        out.append({
            "name": spec["name"],
            "label": _label_from_desc(spec["description"]),
            "env": env,
        })
    out.extend(_BESPOKE_CATALOG)
    out.sort(key=lambda e: e["name"])
    return out


def connection_setup_catalog() -> list[dict]:
    """Describe existing adapters without resolving credentials or calling providers."""
    specs = {**_CONNECTOR_INDEX, **{spec["name"]: spec for spec in _READ_SPECS}}
    specs.update({spec["name"]: spec for spec in _GRAPHQL_SPECS})
    rows = []
    for item in connector_catalog():
        spec = specs.get(item["name"])
        supported = spec is not None and not spec.get("extra_headers_env")
        auth = ("Username and API key" if spec.get("basic") else
                str(spec.get("scheme") or "API key") + " token") if spec is not None else "Dedicated integration"
        rows.append({"name": item["name"], "label": item["label"], "auth_method": auth,
                     "key_setup_supported": supported,
                     "prerequisites": ("Service API address and a credential with only the permissions your task needs."
                                       if supported else "This adapter requires its dedicated administrator setup; a single saved key is insufficient."),
                     "live_provider_verified": False})
    for spec in _PUBLIC_DATA_SPECS:
        if spec.get("keyless"):
            continue
        rows.append({"name": spec["name"],
                     "label": spec["description"].split(", READ-ONLY", 1)[0],
                     "auth_method": "Key from the reference service",
                     "key_setup_supported": True, "reference_data": True,
                     "default_base_url": spec["default_base_url"],
                     "prerequisites": "Paste a key issued by this service. Lightwork fills in its address and "
                                      "keeps the key encrypted. These tools read reference data; they do not change it. "
                                      "Saving does not contact the service or establish that its data is current. "
                                      "The service's own access and usage limits still apply.",
                     "live_provider_verified": False})
    # Definition imports use these protected named credentials. Preserve the
    # existing tool labels; UiPath has no generic connector catalog entry.
    for name, label, auth, location in (
        ("n8n", "n8n workflow import", "n8n API key", "The HTTPS address of your n8n instance"),
        ("make", "Make workflow import", "Make API token", "The HTTPS address of your Make region, such as https://eu1.make.com"),
        ("workato", "Workato workflow import", "Workato API token", "The HTTPS address of your Workato region"),
        ("uipath", "UiPath workflow import", "UiPath bearer token", "The HTTPS address of your UiPath service, such as https://cloud.uipath.com"),
    ):
        row = next((row for row in rows if row["name"] == name), None)
        if row is None:
            row = {"name": name, "label": label, "live_provider_verified": False}
            rows.append(row)
        row.update(auth_method=auth, key_setup_supported=True,
                   prerequisites=location + ". For workflow imports, enter the service address only, without a path or query. "
                                 "Use access that can read the definitions you want to import. "
                                 + ("Choose your organization and tenant separately on the workflow import page. " if name == "uipath" else "")
                                 + "Saving does not contact the service or import or run a workflow.")
    # These credentials belong to the closed read-only evidence collectors,
    # not the generic REST tool. Source selection and checks stay in Evidence.
    for name, label, auth in (
        ("aws_security_hub", "Evidence: AWS Security Hub", "AWS access key and secret key"),
        ("aws_config", "Evidence: AWS Config", "AWS access key and secret key"),
        ("azure_defender", "Evidence: Microsoft Defender for Cloud", "Microsoft access token"),
        ("azure_policy", "Evidence: Azure Policy", "Microsoft access token"),
        ("gcp_security_command_center", "Evidence: Google Cloud Security Command Center", "Google access token"),
        ("github_security", "Evidence: GitHub security alerts", "GitHub access token"),
        ("okta_posture", "Evidence: Okta policies", "Okta API token"),
    ):
        rows.append({"name": name, "label": label, "auth_method": auth,
                     "key_setup_supported": True, "live_provider_verified": False,
                     "prerequisites": "Use access that can read the selected security source. "
                                      "Saving only keeps the encrypted credential; choose and check the exact source in Continuous evidence."})
    return rows

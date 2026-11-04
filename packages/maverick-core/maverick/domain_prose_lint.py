"""Prose lint for the specialist packs: the words, not the envelope.

``maverick domains-lint`` (``domain.lint_profile``) answers "is the envelope
safe?". This answers "is the text a practitioner would read fit to ship?".
It fails on the defect classes a content teardown found across the roster:

* quote corruption -- a straight double quote where an apostrophe belongs
  (``company"s``), and smart-quote / mojibake damage;
* the wrong article before a curated list of terms (``a IT/GRC``,
  ``a HR``, ``an SaaS`` ...);
* two packs sharing one persona (a copy-pasted specialist is not two
  specialists);
* a persona or description too short to be a working instruction set;
* an empty TOML field (a declared-but-blank contract);
* a tool name (allowed, used in a workflow step, or denied) that exists
  nowhere: not in the built-in registry, not in the risk catalog, not one of
  the audited operator-provisioned adapters, not a deny-only tool name such as
  ``self_edit``; and a deny written against a module name
  (``str_edit``) instead of the registered tool (``str_replace_editor``).

``--fix`` rewrites the mechanical classes (quotes, articles) in place without
re-serialising the TOML, so comments and layout survive. Everything else needs
an author. Runs inside ``maverick domains-lint`` (the CI catalog gate) and on
its own as ``python -m maverick.domain_prose_lint --ci``.
"""
from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover -- Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from .domain import DomainProfile, builtin_dir, load_domains

# A persona shorter than this is a label, not a working instruction set; a
# description shorter than this is a heading ("UX research.") rather than a
# sentence the roster and the router can act on.
MIN_PERSONA_CHARS = 300
MIN_DESCRIPTION_CHARS = 30

# ``company"s`` / ``customer"s`` / ``don"t``: a letter, a straight double
# quote, then a contraction or possessive suffix ending at a word boundary.
# No valid TOML or prose contains that sequence, so it is safe to rewrite.
QUOTE_CORRUPTION = re.compile(r"(?<=[A-Za-z])\"(?=(?:s|t|re|ll|ve|d|m)\b)")

# Smart quotes (fixable) and the mojibake / replacement characters that mark
# an encoding round-trip gone wrong (not fixable mechanically).
SMART_QUOTES = {"‘": "'", "’": "'", "“": '"', "”": '"'}
ENCODING_DAMAGE = re.compile("[�]|â€|Ã[\u0080-¿]")

# Curated article table: term -> (article it takes, canonical spelling).
# Acronyms are pronounced letter by letter ("an IT", "an HR", "a UX"), so the
# rule is by sound, not by the first letter. Matched case-sensitively so
# ``it`` in running prose is never touched; the lowercase entries are the
# suite-boilerplate words the teardown found miswritten.
ARTICLES: dict[str, tuple[str, str]] = {
    "AI": ("an", "AI"),
    "API": ("an", "API"),
    "FRIA": ("a", "FRIA"),
    "GRC": ("a", "GRC"),
    "HR": ("an", "HR"),
    "hr": ("an", "HR"),
    "IT": ("an", "IT"),
    "LLM": ("an", "LLM"),
    "MCP": ("an", "MCP"),
    "SaaS": ("a", "SaaS"),
    "SDR": ("an", "SDR"),
    "SOC": ("a", "SOC"),
    "UX": ("a", "UX"),
    "education": ("an", "education"),
    "executive": ("an", "executive"),
    "insurance": ("an", "insurance"),
    "operations": ("an", "operations"),
}
_ARTICLE_RE = re.compile(
    r"\b([Aa]n?)([ \t]+)(" + "|".join(sorted(ARTICLES, key=len, reverse=True)) + r")\b"
)

# Tool names every pack may reference without appearing in the registry:
# the swarm/spawn tools the agent loop registers itself, plus the
# operator-provisioned read adapters the audited catalog documents as
# deployment prerequisites.
# This is a ratchet: a new adapter name is a deliberate addition here, not a
# typo that slips through.
# Tool names that no built-in tool carries but that a pack may (and builders
# must) name in deny_tools: ``self_edit`` (editing Lightwork's own source or
# controls) stays denied by name, so a plugin that registers it is still blocked.
UNREGISTERED_TOOLS = frozenset({"self_edit"})
# Deny-list names that were written against a module name or an abbreviation
# instead of the registered tool name. A deny of a name that no tool carries
# is a no-op, so the fix is mechanical and the lint fails until it is applied.
TOOL_RENAMES: dict[str, str] = {"str_edit": "str_replace_editor"}
_RENAME_RE = re.compile(r'"(' + "|".join(map(re.escape, TOOL_RENAMES)) + r')"')
SWARM_TOOLS = frozenset({
    "send_to_agent", "recv_from_agent", "delegate_to_agent", "spawn_subagent",
    "spawn_swarm", "spawn_specialist", "list_specialists", "learn_capability",
    "code_exec", "knowledge_search", "find_tools",
})
ABSTRACT_ADAPTERS = frozenset({
    "actuarial_model_read", "appraisal_read", "asset_registry_read", "audit_read",
    "availability_read", "balance_read", "batch_record_read", "benefits_read",
    "billing_read", "billing_record_read", "billing_records_read", "bom_read",
    "budget_read", "capa_record_read", "carbon_ledger_read", "case_read",
    "case_record_read", "casework_read", "cems_read", "chain_explorer_read",
    "chain_metrics_read", "chain_read", "change_record_read", "claim_file_read",
    "claims_read", "clause_library_read", "collateral_read", "comp_band_read",
    "complaint_record_read", "comps_read", "contract_audit_read", "cost_model_read",
    "covenant_read", "credit_bureau_read", "credit_report_read", "crew_schedule_read",
    "crm_read", "custodian_read", "deductions_read", "defi_protocol_read",
    "delivery_read", "disclosure_register_read", "dms_read", "docs_read",
    "document_read", "document_search", "ehr_read", "elasticity_read",
    "emission_factor_read", "emissions_data_read", "emissions_inventory_read",
    "emissions_monitoring_read", "escrow_read", "evm_read", "fare_read",
    "fare_rules_read", "filing_archive_read", "filings_read", "financials_read",
    "fleet_schedule_read", "forecast_read", "get_account_positions",
    "get_account_summary", "get_positions", "get_price_history", "get_price_snapshot",
    "gis_layer_read", "gis_read", "grid_model_read", "holdings_read", "hris_read",
    "incident_log_read", "incident_record_read", "inspection_read",
    "inspection_records_read", "inspection_report_read", "invoice_read",
    "lab_results_read", "labeling_read", "lease_abstract_read", "ledger_read",
    "license_read", "lims_read", "load_plan_read", "loan_origination_read",
    "loan_terms_read", "loss_history_read", "lot_trace_read", "loyalty_read",
    "market_data_read", "menu_read", "meter_data_read", "mls_read", "model_read",
    "model_score_read", "ncr_record_read", "network_metrics_read", "onchain_read",
    "outage_read", "permit_status_read", "plm_read", "pnr_read", "policy_read",
    "policy_record_read", "position_read", "qms_read", "queue_status_read",
    "rate_parity_read", "reg_dossier_read", "register_read", "regulatory_db_read",
    "remittance_read", "restricted_list_read", "rights_catalog_read",
    "risk_score_read", "rma_record_read", "safety_db_read", "sales_records_read",
    "schedule_read", "search_contracts", "sensor_data_read", "sensor_read",
    "signoff_report_read", "spec_read", "stability_read", "switching_order_read",
    "tank_gauge_read", "tariff_read", "test_records_read", "trade_doc_read",
    "transaction_read", "usage_records_read", "valuation_read", "voter_roll_read",
    "waste_manifest_read", "zoning_read",
})


@dataclass(frozen=True)
class Finding:
    pack: str
    field: str
    message: str

    def __str__(self) -> str:
        return f"{self.pack}: {self.field}: {self.message}"


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def persona_hash(persona: str) -> str:
    """Whitespace-insensitive fingerprint of a persona, for duplicate checks."""
    return hashlib.sha256(_norm(persona).encode("utf-8")).hexdigest()[:16]


def prose_fields(profile: DomainProfile):
    """``(field, text)`` for every human-readable string in a pack."""
    yield "description", profile.description or ""
    yield "persona", profile.persona or ""
    for i, step in enumerate(profile.workflow, 1):
        yield f"workflow[{i}].name", step.name or ""
        yield f"workflow[{i}].instruction", step.instruction or ""
    yield "output.deliverable", profile.output.deliverable or ""
    for i, item in enumerate(profile.refuse, 1):
        yield f"refuse[{i}]", item


def known_tool_names() -> set[str]:
    """Every tool name a pack may legitimately declare.

    The built-in registry (assembled offline, no provider keys), the safety
    risk catalog (which classifies the optional tools such as ``web_search``
    and every read/enterprise connector), the swarm tools, and the audited
    abstract adapters.
    """
    import importlib

    from .tools import base_tool_names

    _risk = importlib.import_module("maverick.safety.tool_risk")

    names = set(base_tool_names() or ())
    names |= set(_risk._DEFAULT_RISK)
    names |= set(_risk._read_connector_names())
    names |= set(_risk._enterprise_connector_names())
    return names | SWARM_TOOLS | ABSTRACT_ADAPTERS | UNREGISTERED_TOOLS


# --- per-field text checks ---------------------------------------------------

def text_findings(text: str) -> list[str]:
    """Defects in one prose string (pure)."""
    out: list[str] = []
    for m in QUOTE_CORRUPTION.finditer(text):
        out.append(f"quote corruption {text[max(0, m.start() - 8):m.end() + 3]!r}")
    smart = sorted({ch for ch in text if ch in SMART_QUOTES})
    if smart:
        out.append("smart quote(s) " + ", ".join(f"U+{ord(c):04X}" for c in smart))
    if ENCODING_DAMAGE.search(text):
        out.append("encoding damage (mojibake or U+FFFD)")
    for m in _ARTICLE_RE.finditer(text):
        article, term = m.group(1), m.group(3)
        want, canonical = ARTICLES[term]
        if article.lower() != want or term != canonical:
            out.append(f"article {m.group(0)!r} should be {_fix_article(m)!r}")
    return out


def _fix_article(m: re.Match) -> str:
    article, gap, term = m.group(1), m.group(2), m.group(3)
    want, canonical = ARTICLES[term]
    if article[0].isupper():
        want = want.capitalize()
    return f"{want}{gap}{canonical}"


def fix_text(text: str) -> str:
    """Apply the mechanical fixes (quotes, smart quotes, articles). Pure."""
    text = QUOTE_CORRUPTION.sub("'", text)
    for bad, good in SMART_QUOTES.items():
        text = text.replace(bad, good)
    text = _RENAME_RE.sub(lambda m: f'"{TOOL_RENAMES[m.group(1)]}"', text)
    return _ARTICLE_RE.sub(_fix_article, text)


# --- per-pack and cross-pack checks -----------------------------------------

def _empty_fields(raw: dict, prefix: str = "") -> list[str]:
    out: list[str] = []
    for key, value in raw.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out.extend(_empty_fields(value, path + "."))
        elif isinstance(value, list):
            if not value:
                out.append(path)
            for i, item in enumerate(value, 1):
                if isinstance(item, dict):
                    out.extend(_empty_fields(item, f"{path}[{i}]."))
        elif isinstance(value, str) and not value.strip():
            out.append(path)
    return out


def lint_pack(profile: DomainProfile, *, known_tools: set[str] | None = None,
              raw: dict | None = None) -> list[Finding]:
    """Findings for one pack in isolation (no cross-pack checks)."""
    name = profile.name
    out: list[Finding] = []
    for field, text in prose_fields(profile):
        out.extend(Finding(name, field, msg) for msg in text_findings(text))
    if len(_norm(profile.persona)) < MIN_PERSONA_CHARS:
        out.append(Finding(name, "persona",
                           f"under {MIN_PERSONA_CHARS} chars: a label, not a working "
                           "instruction set"))
    if len(_norm(profile.description)) < MIN_DESCRIPTION_CHARS:
        out.append(Finding(name, "description",
                           f"under {MIN_DESCRIPTION_CHARS} chars: write the sentence "
                           "the roster and router act on"))
    if raw is not None:
        out.extend(Finding(name, path, "empty field") for path in _empty_fields(raw))
    for tool in sorted(set(profile.deny_tools) & set(TOOL_RENAMES)):
        out.append(Finding(name, "deny_tools", f"{tool!r} is not a tool name; deny "
                           f"{TOOL_RENAMES[tool]!r} (--fix renames it)"))
    if known_tools is not None:
        declared = set(profile.allow_tools) | {t for s in profile.workflow for t in s.tools}
        for tool in sorted(declared - known_tools):
            out.append(Finding(name, "allow_tools", f"unknown tool {tool!r}: not in the "
                               "registry, the risk catalog, or ABSTRACT_ADAPTERS"))
        # A deny of a name no tool carries is a no-op that reads like a control.
        for tool in sorted(set(profile.deny_tools) - known_tools - set(TOOL_RENAMES)):
            out.append(Finding(name, "deny_tools", f"unknown tool {tool!r}: denying a "
                               "name nothing is registered under denies nothing"))
    return out


def lint_profiles(profiles: dict[str, DomainProfile], *,
                  known_tools: set[str] | None = None,
                  raws: dict[str, dict] | None = None) -> list[Finding]:
    """All findings across a roster, including the duplicate-persona check."""
    out: list[Finding] = []
    by_hash: dict[str, list[str]] = defaultdict(list)
    for key in sorted(profiles):
        profile = profiles[key]
        out.extend(lint_pack(profile, known_tools=known_tools,
                             raw=(raws or {}).get(key)))
        if _norm(profile.persona):
            by_hash[persona_hash(profile.persona)].append(profile.name)
    for names in by_hash.values():
        if len(names) > 1:
            for name in names:
                others = ", ".join(n for n in names if n != name)
                out.append(Finding(name, "persona", f"identical to {others}: two packs "
                                   "sharing one persona are one specialist twice"))
    return sorted(out, key=lambda f: (f.pack, f.field, f.message))


def _load_raws(directory: Path) -> dict[str, dict]:
    raws: dict[str, dict] = {}
    for path in sorted(directory.glob("*.toml")):
        with open(path, "rb") as fh:
            raws[path.stem] = tomllib.load(fh)
    return raws


def lint_dir(directory: Path | None = None, *,
             known_tools: set[str] | None = None) -> list[Finding]:
    """Lint every pack in ``directory`` (default: the built-in roster)."""
    directory = Path(directory) if directory else builtin_dir()
    profiles = load_domains(directory)
    return lint_profiles(profiles, known_tools=known_tools, raws=_load_raws(directory))


def fix_dir(directory: Path | None = None) -> list[Path]:
    """Rewrite the mechanical defects in place; returns the files changed."""
    directory = Path(directory) if directory else builtin_dir()
    changed: list[Path] = []
    for path in sorted(directory.glob("*.toml")):
        before = path.read_text(encoding="utf-8")
        after = fix_text(before)
        if after != before:
            tomllib.loads(after)  # never write a file the loader would reject
            path.write_text(after, encoding="utf-8")
            changed.append(path)
    return changed


def main(argv: list[str] | None = None) -> int:  # pragma: no cover -- CLI shell
    import argparse
    p = argparse.ArgumentParser(prog="maverick.domain_prose_lint",
                                description="Prose lint for the specialist packs.")
    p.add_argument("--ci", action="store_true",
                   help="Exit non-zero on any finding.")
    p.add_argument("--fix", action="store_true",
                   help="Rewrite the mechanical classes (quotes, articles) in place.")
    p.add_argument("--dir", default=None, help="Pack directory (default: built-in).")
    p.add_argument("--no-registry", action="store_true",
                   help="Skip the tool-name check (no registry assembly).")
    args = p.parse_args(argv)
    directory = Path(args.dir) if args.dir else builtin_dir()
    if args.fix:
        for path in fix_dir(directory):
            print(f"fixed  {path.name}")
    known = None if args.no_registry else known_tool_names()
    findings = lint_dir(directory, known_tools=known)
    for f in findings:
        print(f"ERROR  {f}")
    n_packs = len(list(directory.glob("*.toml")))
    print(f"{n_packs} pack(s): {len(findings)} prose finding(s)")
    return 1 if (args.ci and findings) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

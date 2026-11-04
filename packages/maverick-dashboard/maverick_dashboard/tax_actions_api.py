"""The tax preparation suite on the Finance page (``maverick tax prepare /
onboard / backtest / update``).

* a first draft of a client's federal and state return from uploaded text
  copies of their documents, every line cited to its document (``operate``
  on the Finance department, like the page);
* a firm readiness check built from a form instead of a hand-written file
  (``view`` on Finance);
* accuracy on returns a firm already filed, from an uploaded ``.zip``
  (``operate`` on Finance);
* the signed tax tables: status, apply an update file, check the publisher,
  go back (installation-wide, so the global ``admin`` permission; recorded
  with the person who made the change).

Each route calls the kernel functions the terminal commands call. Unlike the
terminal, preparing a draft never contacts the update publisher on its own:
that is the separate "Check for newer tables" button. Uploads are bounded and
unpacked only into a private temporary folder; nothing is ever filed.
"""
from __future__ import annotations

import io
import json
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from starlette.concurrency import run_in_threadpool

from .auth import require_global_permission, require_permission
from .feature_actions_api import _TEXT, _body, _record, _same_origin, _technical

router = APIRouter()

# ---- Tax preparation (maverick tax prepare / onboard / backtest / update) ---

_TAX_DOC_LIMIT = 200 * 1024
_TAX_DOCS = 50
_TAX_ZIP_LIMIT = 10 * 1024 * 1024
_MONEY = Field(default=0.0, ge=0, le=100_000_000)


def _tax_reader(request: Request, permission: str = "view") -> None:
    from .auth import require_suite
    require_permission(request, permission)
    require_suite(request, "finance")


def _previous_tables() -> Path:
    from maverick import tax_constants
    current = tax_constants.bundle_path()
    return current.with_suffix(current.suffix + ".prev")  # where rollback() looks


def _tax_status() -> dict[str, Any]:
    from maverick import tax_constants
    from maverick.config import get_tax
    from maverick.tax_prep import DOC_TYPES, STATE_CODES
    federal, _, provenance = tax_constants.active_constants()
    version = tax_constants.active_version()
    cfg = get_tax()
    return {
        "tax_year": int(federal["year"]),
        "tables": (f"Signed update {version}" if version else "Built-in tables"),
        "can_roll_back": _previous_tables().exists(),
        "update_channel": bool(cfg["update_url"] and cfg["trusted_constants_pubkeys"]),
        "states": sorted(STATE_CODES),
        "document_types": list(DOC_TYPES),
        "technical": _technical([provenance]),
    }


@router.get("/api/v1/tax")
async def tax_status(request: Request) -> dict:
    _tax_reader(request)
    return await run_in_threadpool(_tax_status)


class TaxDocIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    text: str = Field(min_length=1, max_length=_TAX_DOC_LIMIT)


class TaxPrepareIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    documents: list[TaxDocIn] = Field(min_length=1, max_length=_TAX_DOCS)
    filing_status: Literal["single", "mfj", "hoh"] = "single"
    dependents: int = Field(default=0, ge=0, le=20)
    state: str = Field(default="", max_length=2)
    estimated_payments: float = _MONEY
    prior_year_overpayment: float = _MONEY
    taxpayer_65: bool = False
    spouse_65: bool = False
    taxpayer_blind: bool = False
    spouse_blind: bool = False


def _tax_prepare(body: TaxPrepareIn) -> dict[str, Any]:
    from maverick import tax_constants, tax_prep
    federal, state_tables, _ = tax_constants.active_constants()
    docs = [tax_prep.extract(d.text, label=d.name) for d in body.documents]
    wp = tax_prep.Workpaper(
        filing_status=body.filing_status, dependents_under_17=body.dependents, docs=docs,
        state=body.state.strip().upper(), estimated_payments=body.estimated_payments,
        prior_year_overpayment=body.prior_year_overpayment,
        taxpayer_65_or_older=body.taxpayer_65, spouse_65_or_older=body.spouse_65,
        taxpayer_blind=body.taxpayer_blind, spouse_blind=body.spouse_blind)
    draft = tax_prep.compute_first_pass(wp, constants=federal)
    state = tax_prep.compute_state_first_pass(wp, tax_prep.infer_state(wp), federal=draft,
                                              constants=state_tables)
    package = tax_prep.review_package_dict(draft, state)
    fed = package["federal"]
    return {
        "tax_year": package["tax_year"],
        "documents": [{"name": d.label, "type": d.doc_type, "check": bool(d.review_required)} for d in docs],
        "lines": [{"label": ln["description"], "amount": ln["amount"], "source": ln["source"]}
                  for ln in fed["lines"]][:100],
        "total_income": fed["total_income"],
        "taxable_income": fed["taxable_income"],
        "tax": fed["tax_after_credits"],
        "paid": round(fed["federal_withholding"] + fed["estimated_payments"] + fed["prior_year_overpayment"], 2),
        "balance": fed["balance"],
        "refund": bool(fed["is_refund"]),
        "state": ({"code": package["state"]["state"], "computed": bool(package["state"]["computed"]),
                   "tax": package["state"]["tax"], "balance": package["state"]["balance"]}
                  if package.get("state") else None),
        "carried": [{"label": c["description"], "amount": c["amount"]} for c in package["carried_figures"]][:50],
        # "[CA] ..." (the state block's tag) reads as "CA: ...".
        "open_items": [re.sub(r"^\[([A-Z]{2})\]\s*", r"\1: ", str(i))[:_TEXT]
                       for i in package["open_items"]][:50],
        "disclaimer": str(package["disclaimer"]),
        "text": tax_prep.render_review_package(draft, state),
    }


@router.post("/api/v1/tax/prepare")
async def tax_prepare(body: TaxPrepareIn, request: Request) -> dict:
    _same_origin(request)
    _tax_reader(request, "operate")
    return await run_in_threadpool(_tax_prepare, body)


class TaxAlias(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=120)
    type: str = Field(min_length=1, max_length=20)


class TaxReadinessIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    firm: str = Field(min_length=1, max_length=200)
    states: list[str] = Field(default_factory=list, max_length=60)
    clients: int = Field(default=0, ge=0, le=10_000_000)
    names: list[TaxAlias] = Field(default_factory=list, max_length=100)
    forms: list[str] = Field(default_factory=list, max_length=100)


def _tax_readiness(body: TaxReadinessIn) -> dict[str, Any]:
    from maverick.config import get_tax
    from maverick.tax_onboarding import FirmProfile, assess_readiness
    cfg = get_tax()
    profile = FirmProfile(
        name=body.firm.strip(), states=[s.strip().upper() for s in body.states],
        doc_aliases={a.label.strip(): a.type.strip() for a in body.names},
        constants_channel_configured=bool(cfg["update_url"] and cfg["trusted_constants_pubkeys"]),
        roster_size=body.clients, forms_handled=[f.strip()[:120] for f in body.forms if f.strip()])
    rep = assess_readiness(profile)
    checks = []
    if rep.invalid_states:
        checks.append({"ok": False, "text": "Some states are not recognised: " + ", ".join(rep.invalid_states) + "."})
    if rep.unresolved_aliases:
        checks.append({"ok": False, "text": "Some of your document names point to a form type Lightwork "
                                            "does not know: " + ", ".join(rep.unresolved_aliases) + "."})
    if rep.handoff_states:
        checks.append({"ok": True, "text": "Your tax software prepares these state returns: "
                                           + ", ".join(rep.handoff_states) + "."})
    if not profile.constants_channel_configured:
        checks.append({"ok": True, "text": "Tax tables are not updated automatically. Lightwork uses its built-in tables."})
    if rep.forms_unrecognized:
        checks.append({"ok": True, "text": "These forms will need a person to handle them: "
                                           + ", ".join(rep.forms_unrecognized) + "."})
    if rep.forms_flagged:
        checks.append({"ok": True, "text": "These forms are recognised and passed to the preparer to review: "
                                           + ", ".join(rep.forms_flagged) + "."})
    if body.clients <= 0:
        checks.append({"ok": True, "text": "Add how many clients you have, then test Lightwork on last year's "
                                           "returns before going live."})
    return {
        "ready": rep.ready_to_pilot,
        "summary": ("Ready to start a trial." if rep.ready_to_pilot
                    else "Not ready yet. Fix the items marked below first."),
        "drafted_states": rep.computed_states, "handed_off_states": rep.handoff_states,
        "forms_drafted": rep.forms_extracted, "checks": checks,
        "technical": _technical(rep.blockers + rep.warnings),
    }


@router.post("/api/v1/tax/readiness")
async def tax_readiness(body: TaxReadinessIn, request: Request) -> dict:
    _same_origin(request)
    _tax_reader(request)
    return await run_in_threadpool(_tax_readiness, body)


def _unpack_cases(raw: bytes, folder: Path) -> int:
    """Unpack ``<case>/<file>.txt`` and ``<case>/filed.json`` only."""
    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise HTTPException(422, "Choose a .zip file with one folder per client.") from exc
    cases: set[str] = set()
    total = 0
    with archive:
        members = [m for m in archive.infolist() if not m.is_dir()]
        if len(members) > 2000:
            raise HTTPException(413, "That file holds too many documents.")
        for member in members:
            parts = [p for p in member.filename.replace("\\", "/").split("/") if p]
            if len(parts) == 3:  # one optional top folder
                parts = parts[1:]
            if len(parts) != 2 or parts[0].startswith(".") or not re.fullmatch(r"[\w .-]{1,120}", parts[0]):
                continue
            leaf = parts[1]
            if not (leaf == "filed.json" or re.fullmatch(r"[\w .-]{1,120}\.txt", leaf)):
                continue
            total += member.file_size
            if member.file_size > _TAX_DOC_LIMIT or total > 4 * _TAX_ZIP_LIMIT:
                raise HTTPException(413, "That file is too large.")
            target = folder / parts[0] / leaf
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member))
            cases.add(parts[0])
    return len(cases)


def _tax_backtest(raw: bytes) -> dict[str, Any]:
    from maverick import tax_backtest as bt
    with tempfile.TemporaryDirectory(prefix="lw-tax-") as folder:
        if not _unpack_cases(raw, Path(folder)):
            raise HTTPException(422, "No client folders were found. Each client needs its own folder with "
                                     "its documents and the figures that were filed.")
        try:
            report = bt.run_backtest_dir(folder)
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(422, "One of the filed-figures files could not be read. Check it and try again.") from exc
        data = bt.backtest_dict(report)
        text = bt.render_backtest(report)
    return {
        "cases": data["cases"], "in_scope": data["in_scope"], "matched": data["matched"],
        "out_of_scope": data["out_of_scope"], "accuracy": data["accuracy"],
        "returns": [{"client": r["client"][:120], "in_scope": r["in_scope"], "matched": r["matched"],
                     "largest_difference": r["max_abs_delta"],
                     "why_not_compared": [str(x)[:_TEXT] for x in r["out_of_scope_reasons"]]}
                    for r in data["returns"]][:500],
        "text": text,
    }


@router.post("/api/v1/tax/backtest")
async def tax_backtest(request: Request) -> dict:
    _same_origin(request)
    _tax_reader(request, "operate")
    raw = await _body(request, _TAX_ZIP_LIMIT)
    return await run_in_threadpool(_tax_backtest, raw)


def _plain_tax_update(reason: str) -> str:
    text = reason.lower()
    if "trust anchor" in text or "untrusted" in text:
        return "This update is not from a publisher you trust, so it was not applied."
    if "signature" in text or "cryptograph" in text:
        return "This update could not be confirmed as genuine, so it was not applied."
    if "not newer" in text:
        return "You already have these tax tables or newer ones."
    if "no previous" in text:
        return "There is no earlier version to go back to."
    if "sanity" in text or "malformed" in text or "unreadable" in text:
        return "This file is not a tax table update Lightwork can use."
    return "The tax tables could not be updated."


@router.post("/api/v1/tax/tables/apply")
async def tax_tables_apply(request: Request) -> dict:
    _same_origin(request)
    require_global_permission(request, "admin")
    raw = await _body(request, 1024 * 1024)
    from maverick import tax_constants
    try:
        envelope = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(422, "This file is not a tax table update Lightwork can use.") from exc
    ok, reason = await run_in_threadpool(tax_constants.apply_bundle, envelope)
    if not ok:
        raise HTTPException(409, _plain_tax_update(reason))
    await run_in_threadpool(lambda: _record(request, "tax_tables_apply", installation=True,
                                            version=tax_constants.active_version()))
    return {"applied": True, "tables": f"Signed update {tax_constants.active_version()}"}


@router.post("/api/v1/tax/tables/roll-back")
async def tax_tables_roll_back(request: Request) -> dict:
    _same_origin(request)
    require_global_permission(request, "admin")
    from maverick import tax_constants
    ok, reason = await run_in_threadpool(tax_constants.rollback)
    if not ok:
        raise HTTPException(409, _plain_tax_update(reason))
    await run_in_threadpool(lambda: _record(request, "tax_tables_roll_back", installation=True,
                                            version=tax_constants.active_version()))
    return {"rolled_back": True}


class TaxTablesCheckIn(BaseModel):
    """Optional one-off update address (the command's ``--url``); https only."""
    model_config = ConfigDict(extra="forbid")
    url: str | None = Field(default=None, max_length=500, pattern=r"^https://[^\s]+$")


@router.post("/api/v1/tax/tables/check")
async def tax_tables_check(request: Request, body: TaxTablesCheckIn | None = None) -> dict:
    _same_origin(request)
    require_global_permission(request, "admin")
    from maverick import tax_constants
    url = body.url if body is not None and body.url else None
    status, detail = await run_in_threadpool(lambda: tax_constants.check_for_update(url=url, force=True))
    if status == "applied":
        await run_in_threadpool(lambda: _record(request, "tax_tables_apply", installation=True,
                                                version=tax_constants.active_version()))
    summary = {
        "applied": "Newer tax tables were found and are now in use.",
        "current": "You already have the newest tax tables.",
        "disabled": "Automatic tax table updates are not set up. Whoever installed Lightwork can set them up.",
    }.get(status, _plain_tax_update(detail))
    return {"status": status, "summary": summary, "technical": _technical([detail])}

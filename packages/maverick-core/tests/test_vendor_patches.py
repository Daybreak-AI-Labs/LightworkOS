"""The local-source audit must reject modified or substituted dependency fixes."""
from __future__ import annotations

import importlib.util
import shutil
from datetime import date, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("check_vendor_patches", ROOT / "scripts/check_vendor_patches.py")
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


@pytest.fixture()
def source_copy(tmp_path):
    shutil.copytree(ROOT / "vendor", tmp_path / "vendor")
    for relative in (
        "apps/desktop/src-tauri/Cargo.toml", "apps/desktop/src-tauri/Cargo.lock",
        "apps/installer-desktop/src-tauri/Cargo.toml", "apps/installer-desktop/src-tauri/Cargo.lock",
        "apps/installer-desktop/package.json", "apps/installer-desktop/pnpm-lock.yaml",
    ):
        destination = tmp_path / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    return tmp_path


def test_reviewed_sources_and_resolutions_match():
    assert checker.validate(ROOT) == []


def test_reintroduced_unsound_out_pointer_is_rejected(source_copy):
    path = source_copy / "vendor/rust/glib/src/variant_iter.rs"
    path.write_text(path.read_text().replace("&mut p,", "&p,"))
    assert any("source inventory or content changed" in error for error in checker.validate(source_copy))


def test_extra_source_file_is_rejected(source_copy):
    (source_copy / "vendor/js/deepmerge/unreviewed.cjs").write_text("module.exports = {}")
    assert any("source inventory or content changed" in error for error in checker.validate(source_copy))


def test_registry_substitution_is_rejected(source_copy):
    path = source_copy / "apps/desktop/src-tauri/Cargo.lock"
    path.write_text(path.read_text().replace('name = "glib"\n', 'name = "glib"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'))
    assert any("not the reviewed local source" in error for error in checker.validate(source_copy))


def test_frontend_override_removal_is_rejected(source_copy):
    path = source_copy / "apps/installer-desktop/package.json"
    path.write_text(path.read_text().replace("file:../../vendor/js/deepmerge", "4.3.1"))
    assert any("does not use the reviewed local source" in error for error in checker.validate(source_copy))


def _glib_report(root, *, advisory="RUSTSEC-2024-0429", lockfile="apps/desktop/src-tauri/Cargo.lock"):
    return {"results": [{"source": {"path": str(root / lockfile), "type": "lockfile"}, "packages": [{
        "package": {"name": "glib", "version": "0.18.5", "ecosystem": "crates.io"},
        "vulnerabilities": [{"id": advisory}],
    }]}]}


def test_osv_recognizes_only_the_proven_local_backport():
    from scripts.check_osv_results import evaluate
    errors, repaired, _accepted = evaluate(_glib_report(ROOT), 1)
    assert errors == []
    assert len(repaired) == 1


@pytest.mark.parametrize("advisory,lockfile", [
    ("RUSTSEC-2099-9999", "apps/desktop/src-tauri/Cargo.lock"),
    ("RUSTSEC-2024-0429", "unreviewed/Cargo.lock"),
])
def test_osv_unrelated_findings_and_copies_remain_blocking(advisory, lockfile):
    from scripts.check_osv_results import evaluate
    errors, repaired, _accepted = evaluate(_glib_report(ROOT, advisory=advisory, lockfile=lockfile), 1)
    assert errors and not repaired


def test_osv_cannot_clear_a_tampered_backport(source_copy):
    from scripts.check_osv_results import evaluate
    path = source_copy / "vendor/rust/glib/src/variant_iter.rs"
    path.write_text(path.read_text().replace("&mut p,", "&p,"))
    errors, repaired, _accepted = evaluate(_glib_report(source_copy), 1, source_copy)
    assert errors and not repaired


def test_osv_cannot_clear_registry_glib(source_copy):
    from scripts.check_osv_results import evaluate
    path = source_copy / "apps/desktop/src-tauri/Cargo.lock"
    path.write_text(path.read_text().replace('name = "glib"\n', 'name = "glib"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'))
    errors, repaired, _accepted = evaluate(_glib_report(source_copy), 1, source_copy)
    assert errors and not repaired


@pytest.mark.parametrize("report,status", [({}, 0), ({"results": []}, 1), ({"results": []}, 2)])
def test_osv_missing_evidence_and_scanner_errors_fail_closed(report, status):
    from scripts.check_osv_results import evaluate
    errors, repaired, _accepted = evaluate(report, status)
    assert errors and not repaired


def _npm_report(root, *, name="tar", version="6.2.1", advisory="GHSA-23hp-3jrh-7fpw",
                lockfile="apps/mobile-companion/package-lock.json"):
    return {"results": [{"source": {"path": str(root / lockfile), "type": "lockfile"}, "packages": [{
        "package": {"name": name, "version": version, "ecosystem": "npm"},
        "vulnerabilities": [{"id": advisory}],
    }]}]}


def test_osv_records_a_reviewed_unfixable_advisory_as_accepted_not_repaired():
    from scripts.check_osv_results import evaluate
    errors, repaired, accepted = evaluate(_npm_report(ROOT), 1, today=date(2026, 11, 5))
    assert errors == [] and repaired == []
    assert [(entry["lockfile"], entry["package"], entry["advisory"]) for entry in accepted] == [
        ("apps/mobile-companion/package-lock.json", "tar 6.2.1", "GHSA-23hp-3jrh-7fpw"),
    ]
    assert accepted[0]["accepted"] and accepted[0]["review_by"] and accepted[0]["reason"]


@pytest.mark.parametrize("change", [
    {"advisory": "GHSA-0000-0000-0000"},
    {"version": "6.2.0"},
    {"name": "node-forge", "version": "1.4.0", "advisory": "GHSA-86w9-cpqp-85rv"},
    {"lockfile": "examples/clients/typescript/package-lock.json"},
])
def test_osv_accepted_risk_covers_only_its_reviewed_findings(change):
    from scripts.check_osv_results import evaluate
    errors, repaired, accepted = evaluate(_npm_report(ROOT, **change), 1, today=date(2026, 11, 5))
    assert errors and not repaired and not accepted


def test_osv_accepted_risk_lapses_after_its_review_date():
    from scripts.check_osv_results import ACCEPTED_RISKS, evaluate
    lapsed = max(date.fromisoformat(risk["review_by"]) for risk in ACCEPTED_RISKS) + timedelta(days=1)
    errors, repaired, accepted = evaluate(_npm_report(ROOT), 1, today=lapsed)
    assert errors and not repaired and not accepted


def test_accepted_risks_are_dated_reasoned_and_short_lived():
    from scripts.check_osv_results import ACCEPTED_RISKS
    assert ACCEPTED_RISKS
    for risk in ACCEPTED_RISKS:
        accepted, review_by = date.fromisoformat(risk["accepted"]), date.fromisoformat(risk["review_by"])
        assert accepted < review_by <= accepted + timedelta(days=92)
        assert len(risk["reason"].split()) >= 20
        assert risk["advisories"] and (ROOT / risk["lockfile"]).is_file()


def test_osv_backport_is_recognized_after_an_unrelated_finding():
    from scripts.check_osv_results import evaluate
    report = _npm_report(ROOT, name="left-pad", version="1.0.0", advisory="GHSA-0000-0000-0000")
    report["results"] += _glib_report(ROOT, lockfile="vendor/tests/Cargo.lock")["results"]
    errors, repaired, accepted = evaluate(report, 1)
    assert len(errors) == 1 and "left-pad" in errors[0]
    assert [entry["lockfile"] for entry in repaired] == ["vendor/tests/Cargo.lock"]

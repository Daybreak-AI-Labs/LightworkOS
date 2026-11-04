"""The local-source audit must reject modified or substituted dependency fixes."""
from __future__ import annotations

import importlib.util
import shutil
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
    errors, repaired = evaluate(_glib_report(ROOT), 1)
    assert errors == []
    assert len(repaired) == 1


@pytest.mark.parametrize("advisory,lockfile", [
    ("RUSTSEC-2099-9999", "apps/desktop/src-tauri/Cargo.lock"),
    ("RUSTSEC-2024-0429", "unreviewed/Cargo.lock"),
])
def test_osv_unrelated_findings_and_copies_remain_blocking(advisory, lockfile):
    from scripts.check_osv_results import evaluate
    errors, repaired = evaluate(_glib_report(ROOT, advisory=advisory, lockfile=lockfile), 1)
    assert errors and not repaired


def test_osv_cannot_clear_a_tampered_backport(source_copy):
    from scripts.check_osv_results import evaluate
    path = source_copy / "vendor/rust/glib/src/variant_iter.rs"
    path.write_text(path.read_text().replace("&mut p,", "&p,"))
    errors, repaired = evaluate(_glib_report(source_copy), 1, source_copy)
    assert errors and not repaired


def test_osv_cannot_clear_registry_glib(source_copy):
    from scripts.check_osv_results import evaluate
    path = source_copy / "apps/desktop/src-tauri/Cargo.lock"
    path.write_text(path.read_text().replace('name = "glib"\n', 'name = "glib"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n'))
    errors, repaired = evaluate(_glib_report(source_copy), 1, source_copy)
    assert errors and not repaired


@pytest.mark.parametrize("report,status", [({}, 0), ({"results": []}, 1), ({"results": []}, 2)])
def test_osv_missing_evidence_and_scanner_errors_fail_closed(report, status):
    from scripts.check_osv_results import evaluate
    errors, repaired = evaluate(report, status)
    assert errors and not repaired

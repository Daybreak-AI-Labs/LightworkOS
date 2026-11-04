"""Synthetic archive/metadata tests: these do not establish a real release."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import zipfile
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "release_acceptance", Path(__file__).with_name("release_acceptance.py")
)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def plan():
    return {
        "schema": "lightwork.release-pair-plan.v1",
        "previous": {
            "release_id": 1,
            "asset_id": 2,
            "tag": "v0.1.7",
            "version": "0.1.7",
            "runtime_sha256": "a" * 64,
            "archive_sha256": "b" * 64,
        },
        "candidate": {
            "run_id": 3,
            "artifact_id": 4,
            "head_sha": "c" * 40,
            "version": "0.1.8",
            "runtime_sha256": "d" * 64,
            "archive_sha256": "e" * 64,
        },
        "updater_public_key_sha256": hashlib.sha256(b"synthetic-public-key").hexdigest(),
        "publisher_thumbprint": "f" * 40,
        "compatibility_review": "Synthetic test declaration, never a real release acceptance record.",
        "state_profile": "facts-and-encrypted-draft-v1",
    }


def provenance(value):
    release = {
        "id": 1,
        "tag_name": "v0.1.7",
        "immutable": True,
        "draft": False,
        "prerelease": False,
        "published_at": "synthetic-date",
        "assets": [{"id": 2}],
    }
    asset = {
        "id": 2,
        "state": "uploaded",
        "digest": "sha256:" + value["previous"]["archive_sha256"],
        "size": 100,
    }
    run = {
        "id": 3,
        "head_sha": "c" * 40,
        "head_branch": "main",
        "event": "workflow_dispatch",
        "conclusion": "success",
        "status": "completed",
        "path": ".github/workflows/windows-customer.yml",
        "repository": {"full_name": "Daybreak-AI-Labs/LightworkOS"},
    }
    artifact = {
        "id": 4,
        "name": "windows-customer-signed-candidate",
        "expired": False,
        "digest": "sha256:" + value["candidate"]["archive_sha256"],
        "size_in_bytes": 100,
        "workflow_run": {
            "id": 3,
            "head_sha": "c" * 40,
            "repository_id": 10,
            "head_repository_id": 10,
        },
    }
    jobs = {"jobs": [{"name": "sign-customer-candidate", "conclusion": "success"}]}
    return [release, asset, run, artifact, jobs]


def archive(tmp_path, value, *, mutate=lambda files: None):
    identity = value["previous"]
    msi = b"SYNTHETIC NONEXECUTABLE INSTALLER TEST CONTENT"
    digest = hashlib.sha256(msi).hexdigest()
    inventory = {
        "schema": "lightwork.windows-customer-build.v1",
        "acceptance_fixture": False,
        "complete_release_cohort": True,
        "version": identity["version"],
        "cohort_version": identity["version"],
        "runtime": {"sha256": identity["runtime_sha256"], "bytes": 100},
        "packages": [
            {"distribution": "maverick-" + name}
            for name in (
                "agent",
                "shield",
                "channels",
                "evolve",
                "dashboard",
                "mcp-server",
                "knowledge",
                "installer",
            )
        ],
    }
    manifest = {
        "version": identity["version"],
        "runtime_sha256": identity["runtime_sha256"],
        "installer_sha256": digest,
        "platforms": {"windows-x86_64": {"signature": "synthetic-signature"}},
    }
    verification = {
        "schema": "lightwork.windows-customer-signature.v1",
        "installer_sha256": digest,
        "publisher_thumbprint": "f" * 40,
        "publisher_signature_verified": True,
        "updater_signature_verified": True,
    }
    files = {
        "Lightwork.msi": msi,
        "Lightwork.msi.sig": b"synthetic-signature",
        "updater.pub": b"synthetic-public-key",
        "runtime-inventory.json": json.dumps(inventory).encode(),
        "signature-verification.json": json.dumps(verification).encode(),
        "versions/0.1.7.json": json.dumps(manifest).encode(),
    }
    mutate(files)
    path = tmp_path / "original.zip"
    with zipfile.ZipFile(path, "w") as bundle:
        for name, content in files.items():
            bundle.writestr(name, content)
    identity["archive_sha256"] = gate.sha256(path)
    return path


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p["candidate"].update(runtime_sha256=p["previous"]["runtime_sha256"]),
        lambda p: p["candidate"].update(version=p["previous"]["version"]),
        lambda p: p["candidate"].update(archive_sha256=p["previous"]["archive_sha256"]),
        lambda p: p["previous"].update(asset_id=True),
        lambda p: p.update(state_profile="arbitrary-code"),
    ],
)
def test_same_runtime_relabel_and_invalid_plan_are_refused(mutation):
    value = plan()
    mutation(value)
    with pytest.raises(ValueError):
        gate.validate_plan(value)


@pytest.mark.parametrize(
    "index,mutation",
    [
        (0, lambda r: r.update(immutable=False)),
        (0, lambda r: r.update(draft=True)),
        (1, lambda r: r.update(digest="sha256:" + "0" * 64)),
        (2, lambda r: r.update(event="pull_request")),
        (2, lambda r: r.update(head_branch="unreviewed")),
        (3, lambda r: r.update(expired=True)),
        (3, lambda r: r["workflow_run"].update(head_sha="0" * 40)),
        (3, lambda r: r["workflow_run"].update(repository_id=None, head_repository_id=None)),
        (4, lambda r: r["jobs"][0].update(conclusion="skipped")),
    ],
)
def test_original_immutable_release_and_protected_signing_provenance_required(index, mutation):
    value = plan()
    rows = provenance(value)
    gate.validate_provenance(value, *rows, "Daybreak-AI-Labs/LightworkOS")
    mutation(rows[index])
    with pytest.raises(ValueError):
        gate.validate_provenance(value, *rows, "Daybreak-AI-Labs/LightworkOS")


def test_contract_only_preserves_original_bundle_and_rejects_runtime_fixture(tmp_path):
    value = plan()
    path = archive(tmp_path, value)
    before = path.read_bytes()
    observed = gate.inspect_bundle(path, tmp_path / "extracted", value["previous"], value)
    assert observed["version"] == "0.1.7" and path.read_bytes() == before
    assert (tmp_path / "extracted/Lightwork.msi.sig").read_bytes() == b"synthetic-signature"
    other = tmp_path / "other"
    other.mkdir()

    def relabel(files):
        metadata = json.loads(files["runtime-inventory.json"])
        metadata["acceptance_fixture"] = True
        files["runtime-inventory.json"] = json.dumps(metadata).encode()

    path = archive(other, value, mutate=relabel)
    with pytest.raises(ValueError, match="Relabeled"):
        gate.inspect_bundle(path, other / "out", value["previous"], value)


@pytest.mark.parametrize(
    "name",
    [
        "../outside.txt",
        "C:/outside.txt",
        "versions/../../outside.txt",
        "private.key",
        "Lightwork.MSI",
        "directory\\file",
    ],
)
def test_archive_paths_and_unknown_secret_files_are_not_extracted(tmp_path, name):
    value = plan()
    path = archive(tmp_path, value, mutate=lambda files: files.update({name: b"synthetic"}))
    with pytest.raises(ValueError):
        gate.inspect_bundle(path, tmp_path / "out", value["previous"], value)
    assert not (tmp_path / "out").exists()


def test_pinned_bundle_rejects_byte_tamper_before_extract(tmp_path):
    value = plan()
    path = archive(tmp_path, value)
    path.write_bytes(path.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="reviewed pin"):
        gate.inspect_bundle(path, tmp_path / "out", value["previous"], value)
    assert not (tmp_path / "out").exists()


def test_refreshing_an_input_pin_cannot_waive_signed_manifest_binding(tmp_path):
    value = plan()
    path = archive(
        tmp_path,
        value,
        mutate=lambda files: files.update({"Lightwork.msi": b"different actual bytes"}),
    )
    with pytest.raises(ValueError, match="immutable original manifest"):
        gate.inspect_bundle(path, tmp_path / "out", value["previous"], value)


def test_invalid_origin_redirect_never_forwards_workflow_authorization():
    import urllib.request

    handler = gate._SafeRedirect()
    request = urllib.request.Request(
        "https://api.github.com/repos/x/y/actions/artifacts/1/zip",
        headers={"Authorization": "Bearer synthetic-workflow-credential"},
    )
    redirected = handler.redirect_request(
        request, None, 302, "found", {}, "https://objects.githubusercontent.com/asset"
    )
    assert redirected.get_header("Authorization") is None
    for url in (
        "https://attacker.example/asset",
        "http://objects.githubusercontent.com/asset",
        "https://objects.githubusercontent.com@attacker.example/asset",
    ):
        with pytest.raises(ValueError):
            handler.redirect_request(request, None, 302, "found", {}, url)


@pytest.mark.parametrize("field", ["packages", "signature_schema", "runtime_bytes"])
def test_incomplete_or_unrecognized_original_metadata_cannot_pass(tmp_path, field):
    value = plan()

    def mutate(files):
        name = (
            "signature-verification.json"
            if field == "signature_schema"
            else "runtime-inventory.json"
        )
        item = json.loads(files[name])
        if field == "signature_schema":
            item["schema"] = "unrecognized"
        elif field == "packages":
            item["packages"][0]["distribution"] = "maverick-arbitrary"
        else:
            item["runtime"]["bytes"] = True
        files[name] = json.dumps(item).encode()

    path = archive(tmp_path, value, mutate=mutate)
    with pytest.raises(ValueError):
        gate.inspect_bundle(path, tmp_path / "out", value["previous"], value)

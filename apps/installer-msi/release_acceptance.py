"""Pin original released/candidate bundles before a separately authorized VM run.

This standard-library helper only reads GitHub metadata, downloads bounded
archives, validates identities and extracts an explicit file allowlist. It does
not execute or sign installers, install trust or claim Windows acceptance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_JSON = 1024 * 1024
_HASH = re.compile(r"[a-f0-9]{64}\Z")
_VERSION = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)\Z")
_REQUIRED = {
    "Lightwork.msi",
    "Lightwork.msi.sig",
    "runtime-inventory.json",
    "updater.pub",
    "signature-verification.json",
}
_EXTRA = {"SHA256SUMS", "latest.json", "acceptance.json", "completed-rollback-acceptance.json"}


def sha256(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def validate_plan(plan):
    if (
        not isinstance(plan, dict)
        or set(plan)
        != {
            "schema",
            "previous",
            "candidate",
            "updater_public_key_sha256",
            "publisher_thumbprint",
            "compatibility_review",
            "state_profile",
        }
        or plan["schema"] != "lightwork.release-pair-plan.v1"
    ):
        raise ValueError("An exact reviewed release-pair plan is required")
    if (
        plan["state_profile"] != "facts-and-encrypted-draft-v1"
        or not isinstance(plan["compatibility_review"], str)
        or not 20 <= len(plan["compatibility_review"]) <= 2000
    ):
        raise ValueError(
            "Record the reviewed schema/key compatibility boundary and supported state profile"
        )
    if not _HASH.fullmatch(str(plan["updater_public_key_sha256"])) or not re.fullmatch(
        r"[A-Fa-f0-9]{40}", str(plan["publisher_thumbprint"])
    ):
        raise ValueError("Pin the existing updater public key and recognized publisher identity")
    for label, identifiers in (
        ("previous", {"release_id", "asset_id", "tag"}),
        ("candidate", {"run_id", "artifact_id", "head_sha"}),
    ):
        row = plan[label]
        if not isinstance(row, dict) or set(row) != identifiers | {
            "archive_sha256",
            "version",
            "runtime_sha256",
        }:
            raise ValueError("Release identities must contain only the reviewed pinned fields")
        if not _VERSION.fullmatch(str(row["version"])) or any(
            not _HASH.fullmatch(str(row[key])) for key in ("archive_sha256", "runtime_sha256")
        ):
            raise ValueError(
                "Each release needs its exact real version and archive/runtime digests"
            )
        for key in identifiers - {"tag", "head_sha"}:
            if type(row[key]) is not int or not 1 <= row[key] <= 2**63 - 1:
                raise ValueError(
                    "GitHub release, asset, run and artifact IDs must be positive integers"
                )
    if not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", str(plan["previous"]["tag"])
    ) or not re.fullmatch(r"[a-f0-9]{40}", str(plan["candidate"]["head_sha"])):
        raise ValueError("Pin the original release tag and candidate source commit")
    old, new = plan["previous"], plan["candidate"]
    if (
        tuple(map(int, old["version"].split("."))) >= tuple(map(int, new["version"].split(".")))
        or old["runtime_sha256"] == new["runtime_sha256"]
        or old["archive_sha256"] == new["archive_sha256"]
    ):
        raise ValueError(
            "Acceptance requires increasing real versions and distinct frozen-runtime bytes; relabeled fixtures are refused"
        )
    return plan


def validate_provenance(plan, release, asset, run, artifact, jobs, repository):
    validate_plan(plan)
    old, new = plan["previous"], plan["candidate"]
    if (
        release.get("id") != old["release_id"]
        or release.get("tag_name") != old["tag"]
        or release.get("immutable") is not True
        or release.get("draft") is not False
        or release.get("prerelease") is not False
        or not release.get("published_at")
    ):
        raise ValueError(
            "The previous installer must come from the pinned published immutable release"
        )
    if (
        not any(row.get("id") == old["asset_id"] for row in release.get("assets", []))
        or asset.get("id") != old["asset_id"]
        or asset.get("state") != "uploaded"
        or asset.get("digest") != "sha256:" + old["archive_sha256"]
    ):
        raise ValueError("The previous release asset does not match its pinned digest and release")
    if (
        run.get("id") != new["run_id"]
        or run.get("head_sha") != new["head_sha"]
        or run.get("head_branch") != "main"
        or run.get("event") != "workflow_dispatch"
        or run.get("conclusion") != "success"
        or run.get("status") != "completed"
        or run.get("path") != ".github/workflows/windows-customer.yml"
        or (run.get("repository") or {}).get("full_name", "").lower() != repository.lower()
    ):
        raise ValueError(
            "The candidate must be the successful reviewed main customer-signing workflow"
        )
    if not any(
        row.get("name") == "sign-customer-candidate" and row.get("conclusion") == "success"
        for row in jobs.get("jobs", [])
    ):
        raise ValueError("The protected customer-signing job did not complete successfully")
    source = artifact.get("workflow_run") or {}
    if (
        artifact.get("id") != new["artifact_id"]
        or artifact.get("name") != "windows-customer-signed-candidate"
        or artifact.get("expired") is not False
        or artifact.get("digest") != "sha256:" + new["archive_sha256"]
        or source.get("id") != new["run_id"]
        or source.get("head_sha") != new["head_sha"]
        or type(source.get("repository_id")) is not int
        or source["repository_id"] <= 0
        or source.get("repository_id") != source.get("head_repository_id")
    ):
        raise ValueError("The candidate artifact does not belong to the pinned signed run")
    for size in (asset.get("size"), artifact.get("size_in_bytes")):
        if type(size) is not int or not 1 <= size <= MAX_ARCHIVE:
            raise ValueError("An installer archive exceeds the supported size bound")


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urlsplit(newurl)
        host = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.port not in (None, 443)
            or not (
                host
                in {
                    "api.github.com",
                    "github.com",
                    "objects.githubusercontent.com",
                    "release-assets.githubusercontent.com",
                }
                or host.endswith(".blob.core.windows.net")
            )
        ):
            raise ValueError("GitHub returned an unexpected archive download origin")
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        if redirected is not None and host != "api.github.com":
            redirected.remove_header("Authorization")
        return redirected


def _request(repository, route, *, destination=None, limit=MAX_JSON):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid GitHub repository")
    token = os.environ.get("GH_TOKEN", "")
    if not token or "\n" in token or "\r" in token:
        raise ValueError("A read-only workflow token is required")
    request = urllib.request.Request(
        "https://api.github.com/repos/" + repository + route,
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/octet-stream" if destination else "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Lightwork-release-acceptance",
        },
    )
    with urllib.request.build_opener(_SafeRedirect()).open(request, timeout=60) as response:
        if destination is None:
            data = response.read(limit + 1)
            if len(data) > limit:
                raise ValueError("GitHub metadata exceeded its bound")
            return json.loads(data)
        with Path(destination).open("xb") as output:
            count = 0
            while block := response.read(1024 * 1024):
                count += len(block)
                if count > limit:
                    raise ValueError("The archive exceeded its declared bound")
                output.write(block)


def _json(path):
    if path.stat().st_size > MAX_JSON:
        raise ValueError("Release metadata exceeded its bound")
    return json.loads(path.read_text(encoding="utf-8-sig"))


def inspect_bundle(archive, output, identity, plan):
    if (
        archive.is_symlink()
        or not archive.is_file()
        or archive.stat().st_size > MAX_ARCHIVE
        or sha256(archive) != identity["archive_sha256"]
    ):
        raise ValueError("Original archive bytes do not match the reviewed pin")
    versioned = "versions/" + identity["version"] + ".json"
    required = _REQUIRED | {versioned}
    allowed = required | _EXTRA
    with zipfile.ZipFile(archive) as bundle:
        names = set()
        total = 0
        members = bundle.infolist()
        if len(members) > 32:
            raise ValueError("Release archive has too many entries")
        for item in members:
            if item.is_dir():
                if item.filename != "versions/":
                    raise ValueError("Unexpected archive directory")
                continue
            name = item.filename
            path = PurePosixPath(name)
            if (
                name not in allowed
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in name
                or name.lower() in names
                or stat.S_ISLNK(item.external_attr >> 16)
                or item.flag_bits & 1
            ):
                raise ValueError(
                    "Release archive contains an unsafe, duplicate or unexpected entry"
                )
            names.add(name.lower())
            total += item.file_size
            if total > MAX_ARCHIVE + 8 * MAX_JSON or item.file_size > (
                MAX_ARCHIVE if name == "Lightwork.msi" else MAX_JSON
            ):
                raise ValueError("Expanded release archive exceeds its bound")
        if not {name.lower() for name in required} <= names:
            raise ValueError("The original signed bundle lacks required immutable metadata")
        output.mkdir(parents=True, exist_ok=False)
        for name in sorted(required):
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(name) as source, target.open("xb") as destination:
                shutil.copyfileobj(source, destination, 1024 * 1024)
    inventory = _json(output / "runtime-inventory.json")
    manifest = _json(output / versioned)
    verification = _json(output / "signature-verification.json")
    msi_hash = sha256(output / "Lightwork.msi")
    signature = (output / "Lightwork.msi.sig").read_text(encoding="utf-8-sig").strip()
    key = (output / "updater.pub").read_text(encoding="utf-8-sig").strip()
    if (
        inventory.get("schema") != "lightwork.windows-customer-build.v1"
        or inventory.get("acceptance_fixture") is not False
        or inventory.get("complete_release_cohort") is not True
        or inventory.get("version") != identity["version"]
        or inventory.get("cohort_version") != identity["version"]
        or (inventory.get("runtime") or {}).get("sha256") != identity["runtime_sha256"]
    ):
        raise ValueError("Relabeled, incomplete or mismatched frozen-runtime inventory is refused")
    package_names = [row.get("distribution") for row in inventory.get("packages", [])]
    expected_packages = {
        "maverick-" + name
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
    }
    if (
        len(package_names) != 8
        or set(package_names) != expected_packages
        or type(inventory["runtime"].get("bytes")) is not int
        or not 1 <= inventory["runtime"]["bytes"] <= MAX_ARCHIVE
    ):
        raise ValueError(
            "The original runtime inventory does not describe the eight-package release cohort"
        )
    if (
        manifest.get("version") != identity["version"]
        or manifest.get("runtime_sha256") != identity["runtime_sha256"]
        or manifest.get("installer_sha256") != msi_hash
        or (manifest.get("platforms", {}).get("windows-x86_64") or {}).get("signature") != signature
    ):
        raise ValueError(
            "The immutable original manifest does not bind these installer/runtime/signature bytes"
        )
    if (
        hashlib.sha256(key.encode()).hexdigest() != plan["updater_public_key_sha256"]
        or verification.get("schema") != "lightwork.windows-customer-signature.v1"
        or verification.get("installer_sha256") != msi_hash
        or str(verification.get("publisher_thumbprint", "")).lower()
        != plan["publisher_thumbprint"].lower()
        or verification.get("publisher_signature_verified") is not True
        or verification.get("updater_signature_verified") is not True
    ):
        raise ValueError(
            "The original signature metadata does not match the reviewed release identity"
        )
    return {
        "version": identity["version"],
        "runtime_sha256": identity["runtime_sha256"],
        "installer_sha256": msi_hash,
        "archive_sha256": identity["archive_sha256"],
        "manifest_sha256": sha256(output / versioned),
        "inventory_sha256": sha256(output / "runtime-inventory.json"),
        "packages": package_names,
        "runtime_bytes": inventory["runtime"]["bytes"],
    }


def fetch(plan, repository, output, *, request=_request):
    validate_plan(plan)
    old, new = plan["previous"], plan["candidate"]
    release = request(repository, f"/releases/{old['release_id']}")
    asset = request(repository, f"/releases/assets/{old['asset_id']}")
    run = request(repository, f"/actions/runs/{new['run_id']}")
    artifact = request(repository, f"/actions/artifacts/{new['artifact_id']}")
    jobs = request(repository, f"/actions/runs/{new['run_id']}/jobs?filter=latest&per_page=100")
    validate_provenance(plan, release, asset, run, artifact, jobs, repository)
    output.mkdir(parents=True, exist_ok=False)
    request(
        repository,
        f"/releases/assets/{old['asset_id']}",
        destination=output / "previous-original.zip",
        limit=asset["size"],
    )
    request(
        repository,
        f"/actions/artifacts/{new['artifact_id']}/zip",
        destination=output / "candidate-original.zip",
        limit=artifact["size_in_bytes"],
    )
    observed = {
        label: inspect_bundle(output / (label + "-original.zip"), output / label, plan[label], plan)
        for label in ("previous", "candidate")
    }
    observed.update(
        schema="lightwork.release-pair-inputs.v1",
        repository=repository,
        previous_release_id=old["release_id"],
        previous_asset_id=old["asset_id"],
        candidate_run_id=new["run_id"],
        candidate_artifact_id=new["artifact_id"],
        candidate_head_sha=new["head_sha"],
        updater_public_key_sha256=plan["updater_public_key_sha256"],
        publisher_thumbprint=plan["publisher_thumbprint"],
        compatibility_review=plan["compatibility_review"],
        state_profile=plan["state_profile"],
        signatures_reverified_on_vm=False,
        installer_executed=False,
        release_accepted=False,
    )
    (output / "release-pair.json").write_text(
        json.dumps(observed, indent=2) + "\n", encoding="utf-8"
    )
    (output / "reviewed-plan.json").write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    value = os.environ.get("LIGHTWORK_RELEASE_ACCEPTANCE_PLAN", "")
    if len(value.encode()) > 16384:
        raise ValueError("Reviewed release plan exceeds its bound")
    result = fetch(json.loads(value), os.environ.get("GITHUB_REPOSITORY", ""), args.output)
    print(
        json.dumps(
            {
                "input_gate": "passed",
                "previous": result["previous"]["version"],
                "candidate": result["candidate"]["version"],
                "release_accepted": False,
            }
        )
    )


if __name__ == "__main__":
    main()

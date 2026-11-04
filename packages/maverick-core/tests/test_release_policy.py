from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import urllib.error
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_script(name: str):
    path = REPO_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_release_asset_verifier_starts_in_isolated_mode():
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(REPO_ROOT / "scripts" / "verify_github_release_assets.py"),
            "--help",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert "--expected-state" in result.stdout


def test_pypi_resume_accepts_only_digest_matching_subsets():
    policy = _load_script("verify_github_release_assets")
    expected = {
        "maverick_agent-1.2.3-py3-none-any.whl": "a" * 64,
        "maverick_agent-1.2.3.tar.gz": "b" * 64,
    }

    assert policy.require_digest_matching_subset(
        {},
        expected,
        label="PyPI maverick-agent==1.2.3",
    ) == sorted(expected)
    assert policy.require_digest_matching_subset(
        {
            "maverick_agent-1.2.3-py3-none-any.whl": "a" * 64,
        },
        expected,
        label="PyPI maverick-agent==1.2.3",
    ) == ["maverick_agent-1.2.3.tar.gz"]
    assert policy.require_digest_matching_subset(
        expected,
        expected,
        label="PyPI maverick-agent==1.2.3",
    ) == []


def test_pypi_resume_rejects_an_unexpected_existing_artifact():
    policy = _load_script("verify_github_release_assets")

    with pytest.raises(ValueError, match=r"unexpected=\['squatted-1.2.3.zip'\]"):
        policy.require_digest_matching_subset(
            {"squatted-1.2.3.zip": "a" * 64},
            {"maverick_agent-1.2.3.tar.gz": "b" * 64},
            label="PyPI maverick-agent==1.2.3",
        )


def test_pypi_resume_rejects_a_conflicting_existing_digest():
    policy = _load_script("verify_github_release_assets")
    filename = "maverick_agent-1.2.3.tar.gz"

    with pytest.raises(ValueError, match=r"conflicting=.*maverick_agent"):
        policy.require_digest_matching_subset(
            {filename: "a" * 64},
            {filename: "b" * 64},
            label="PyPI maverick-agent==1.2.3",
        )


def _pypi_sdist_payload() -> dict:
    filename = "maverick_agent-1.2.3.tar.gz"
    return {
        "info": {"name": "maverick-agent", "version": "1.2.3"},
        "urls": [
            {
                "digests": {"sha256": "a" * 64},
                "filename": filename,
                "packagetype": "sdist",
                "url": f"https://files.pythonhosted.org/packages/{filename}",
            }
        ],
    }


def test_homebrew_pypi_sdist_matches_the_signed_release_authority():
    policy = _load_script("verify_github_release_assets")
    filename = "maverick_agent-1.2.3.tar.gz"
    url, digest = policy.require_matching_pypi_sdist(
        _pypi_sdist_payload(),
        version="1.2.3",
        expected_filename=filename,
        expected_sha256="a" * 64,
    )

    assert url == f"https://files.pythonhosted.org/packages/{filename}"
    assert digest == "a" * 64


def test_homebrew_pypi_sdist_rejects_a_digest_not_in_the_signed_release():
    policy = _load_script("verify_github_release_assets")
    payload = _pypi_sdist_payload()
    payload["urls"][0]["digests"]["sha256"] = "b" * 64

    with pytest.raises(ValueError, match="signed exact-release authority"):
        policy.require_matching_pypi_sdist(
            payload,
            version="1.2.3",
            expected_filename="maverick_agent-1.2.3.tar.gz",
            expected_sha256="a" * 64,
        )


def test_homebrew_pypi_sdist_rejects_an_untrusted_download_origin():
    policy = _load_script("verify_github_release_assets")
    payload = _pypi_sdist_payload()
    payload["urls"][0]["url"] = (
        "https://attacker.invalid/packages/maverick_agent-1.2.3.tar.gz"
    )

    with pytest.raises(ValueError, match="unsafe sdist URL"):
        policy.require_matching_pypi_sdist(
            payload,
            version="1.2.3",
            expected_filename="maverick_agent-1.2.3.tar.gz",
            expected_sha256="a" * 64,
        )


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def test_github_release_state_distinguishes_draft_and_published(monkeypatch):
    policy = _load_script("github_release_state")
    payloads = iter(
        (
            {
                "data": {
                    "repository": {
                        "release": {
                            "tagName": "v1.2.3",
                            "isDraft": True,
                            "isPrerelease": False,
                        }
                    }
                }
            },
            {
                "data": {
                    "repository": {
                        "release": {
                            "tagName": "v1.2.3",
                            "isDraft": False,
                            "isPrerelease": False,
                        }
                    }
                }
            },
        )
    )

    def urlopen(_request, timeout):
        assert timeout == 30
        return _Response(json.dumps(next(payloads)).encode())

    monkeypatch.setattr(policy.urllib.request, "urlopen", urlopen)
    draft = policy.fetch_release_state("Daybreak-AI-Labs/LightworkOS", "v1.2.3", "x")
    published = policy.fetch_release_state(
        "Daybreak-AI-Labs/LightworkOS",
        "v1.2.3",
        "x",
    )
    assert (draft.state, draft.prerelease) == ("draft", False)
    assert (published.state, published.prerelease) == ("published", False)


def test_github_release_state_maps_graphql_null_to_absent(monkeypatch):
    policy = _load_script("github_release_state")

    def missing(*_args, **_kwargs):
        return _Response(
            json.dumps({"data": {"repository": {"release": None}}}).encode()
        )

    monkeypatch.setattr(policy.urllib.request, "urlopen", missing)
    result = policy.fetch_release_state(
        "Daybreak-AI-Labs/LightworkOS",
        "v1.2.3",
        "x",
    )
    assert result.state == "absent"
    assert result.prerelease is None


def test_github_release_state_fails_closed_on_http_error(monkeypatch):
    policy = _load_script("github_release_state")

    def forbidden(*_args, **_kwargs):
        raise urllib.error.HTTPError("https://api.github.test", 403, "", {}, None)

    monkeypatch.setattr(policy.urllib.request, "urlopen", forbidden)
    with pytest.raises(RuntimeError, match="HTTP 403"):
        policy.fetch_release_state(
            "Daybreak-AI-Labs/LightworkOS",
            "v1.2.3",
            "x",
        )


def test_github_release_state_rejects_mismatched_metadata(monkeypatch):
    policy = _load_script("github_release_state")

    def urlopen(*_args, **_kwargs):
        return _Response(
            json.dumps(
                {
                    "data": {
                        "repository": {
                            "release": {
                                "tagName": "v9.9.9",
                                "isDraft": False,
                                "isPrerelease": False,
                            }
                        }
                    }
                }
            ).encode()
        )

    monkeypatch.setattr(policy.urllib.request, "urlopen", urlopen)
    with pytest.raises(RuntimeError, match="different release tag"):
        policy.fetch_release_state(
            "Daybreak-AI-Labs/LightworkOS",
            "v1.2.3",
            "x",
        )


def _release_asset_fixture(tmp_path):
    root = tmp_path / "assets"
    root.mkdir()
    tag = "v1.2.3"
    revision = "a" * 40
    distributions = [f"lightwork-package-{index}" for index in range(8)]
    cohort = tmp_path / "release-cohort.toml"
    cohort.write_text(
        'schema_version = 1\nversion = "1.2.3"\n'
        + "".join(
            (
                "\n[[packages]]\n"
                f'distribution = "{name}"\n'
                f'path = "packages/{name}"\n'
            )
            for name in distributions
        ),
        encoding="utf-8",
    )

    upstream_names = (
        "maverick-linux-x86_64",
        "maverick-macos-arm64",
        "maverick-windows-x86_64.exe",
        f"maverick-container-{tag}.json",
        f"maverick-sbom-{tag}.cdx.json",
    )
    upstream = {}
    for name in upstream_names:
        payload = f"upstream:{name}".encode()
        (root / name).write_bytes(payload)
        upstream[name] = hashlib.sha256(payload).hexdigest()
    release_sums = root / f"maverick-release-{tag}.sha256"
    release_sums.write_text(
        "".join(f"{digest}  {name}\n" for name, digest in upstream.items()),
        encoding="ascii",
    )
    for name in (*upstream_names, release_sums.name):
        (root / f"{name}.sig").write_text("signature", encoding="ascii")
        (root / f"{name}.pem").write_text("certificate", encoding="ascii")

    records = []
    for index, distribution in enumerate(distributions):
        for kind, filename in (
            ("wheel", f"{distribution.replace('-', '_')}-1.2.3-py3-none-any.whl"),
            ("sdist", f"{distribution}-1.2.3.tar.gz"),
        ):
            payload = f"python:{filename}".encode()
            (root / filename).write_bytes(payload)
            records.append(
                {
                    "distribution": distribution,
                    "filename": filename,
                    "kind": kind,
                    "publish_prefix": f"package-{index}",
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "version": "1.2.3",
                }
            )
    manifest = {
        "schema_version": 1,
        "source_revision": revision,
        "version": "1.2.3",
        "artifacts": records,
    }
    (root / "release-manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{item['sha256']}  {item['filename']}\n"
            for item in sorted(records, key=lambda item: item["filename"])
        ),
        encoding="ascii",
    )
    for name in (
        *(item["filename"] for item in records),
        "release-manifest.json",
        "SHA256SUMS",
    ):
        (root / f"{name}.cosign.bundle").write_text("bundle", encoding="ascii")

    metadata = tmp_path / "metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "tagName": tag,
                "isDraft": True,
                "isPrerelease": False,
                "assets": [{"name": path.name} for path in root.iterdir()],
            }
        ),
        encoding="utf-8",
    )
    return root, metadata, tag, revision, cohort


def test_release_asset_policy_requires_exact_signed_byte_inventory(tmp_path):
    _load_script("release_version")
    policy = _load_script("verify_github_release_assets")
    root, metadata, tag, revision, cohort = _release_asset_fixture(tmp_path)

    summary = policy.verify_release_assets(
        root=root,
        metadata_path=metadata,
        tag=tag,
        revision=revision,
        expected_state="draft",
        cohort_path=cohort,
    )
    assert summary["python_artifact_count"] == 16
    assert summary["state"] == "draft"

    extra = root / "unreviewed.txt"
    extra.write_text("not signed", encoding="utf-8")
    metadata_payload = json.loads(metadata.read_text(encoding="utf-8"))
    metadata_payload["assets"].append({"name": extra.name})
    metadata.write_text(json.dumps(metadata_payload), encoding="utf-8")
    with pytest.raises(ValueError, match="signed state"):
        policy.verify_release_assets(
            root=root,
            metadata_path=metadata,
            tag=tag,
            revision=revision,
            expected_state="draft",
            cohort_path=cohort,
        )


def test_release_asset_policy_rejects_a_signed_but_incomplete_upstream_cohort(
    tmp_path,
):
    _load_script("release_version")
    policy = _load_script("verify_github_release_assets")
    root, metadata, tag, revision, cohort = _release_asset_fixture(tmp_path)
    omitted = "maverick-macos-arm64"
    for suffix in ("", ".sig", ".pem"):
        (root / f"{omitted}{suffix}").unlink()
    release_sums = root / f"maverick-release-{tag}.sha256"
    release_sums.write_text(
        "".join(
            line
            for line in release_sums.read_text(encoding="ascii").splitlines(
                keepends=True
            )
            if not line.endswith(f"  {omitted}\n")
        ),
        encoding="ascii",
    )
    metadata.write_text(
        json.dumps(
            {
                "tagName": tag,
                "isDraft": True,
                "isPrerelease": False,
                "assets": [{"name": path.name} for path in root.iterdir()],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact upstream cohort"):
        policy.verify_release_assets(
            root=root,
            metadata_path=metadata,
            tag=tag,
            revision=revision,
            expected_state="draft",
            cohort_path=cohort,
        )


def test_release_asset_policy_rejects_an_extra_even_when_checksums_and_sigs_exist(
    tmp_path,
):
    _load_script("release_version")
    policy = _load_script("verify_github_release_assets")
    root, metadata, tag, revision, cohort = _release_asset_fixture(tmp_path)
    extra = root / "lightwork-unreviewed-1.2.3.zip"
    extra.write_bytes(b"unreviewed")
    (root / f"{extra.name}.sig").write_text("signature", encoding="ascii")
    (root / f"{extra.name}.pem").write_text("certificate", encoding="ascii")
    release_sums = root / f"maverick-release-{tag}.sha256"
    with release_sums.open("a", encoding="ascii", newline="\n") as stream:
        stream.write(
            f"{hashlib.sha256(extra.read_bytes()).hexdigest()}  {extra.name}\n"
        )
    metadata.write_text(
        json.dumps(
            {
                "tagName": tag,
                "isDraft": True,
                "isPrerelease": False,
                "assets": [{"name": path.name} for path in root.iterdir()],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="exact upstream cohort"):
        policy.verify_release_assets(
            root=root,
            metadata_path=metadata,
            tag=tag,
            revision=revision,
            expected_state="draft",
            cohort_path=cohort,
        )

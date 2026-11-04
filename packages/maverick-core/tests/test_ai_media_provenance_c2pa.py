"""Security contracts for the bounded optional c2patool adapter."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from maverick import ai_media_provenance as provenance
from maverick import ai_media_provenance_c2pa as c2pa
from maverick.file_lock import private_path_is_restricted

NOW = 1_800_000_000.0
SIGNING_TIME = "2027-01-15T07:59:00Z"
ASSET_ID = "MAA-0123456789abcdef0123456789abcdef"
JPEG = b"\xff\xd8\xff\xe0test-jpeg-payload"
SIGNED_SUFFIX = b"|embedded-c2pa-manifest"
TOOL_EXECUTABLE = b"bounded c2patool executable fixture"
PRIVATE_KEY = (
    b"-----BEGIN PRIVATE KEY-----\n"
    b"adapter-test-private-key-secret\n"
    b"-----END PRIVATE KEY-----\n"
)
CERTIFICATE = (
    b"-----BEGIN CERTIFICATE-----\n"
    b"adapter-test-certificate\n"
    b"-----END CERTIFICATE-----\n"
)
TRUST_ANCHORS = (
    b"-----BEGIN CERTIFICATE-----\n"
    b"adapter-test-trust-anchor\n"
    b"-----END CERTIFICATE-----\n"
)


def _hex(value: str | bytes) -> str:
    payload = value if isinstance(value, bytes) else value.encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _canonical_sha(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _binding(media: bytes = JPEG, *, media_kind: str = "image") -> provenance.C2PABinding:
    return provenance.C2PABinding(
        media_kind=media_kind,
        source_content_sha256=_hex(media),
        asset_id=ASSET_ID,
        asset_revision=2,
        asset_version_digest=_hex("asset-v2"),
        deployment_id="production-east",
        deployment_revision=3,
        deployment_artifact_digest=_hex("deployment-v3"),
        context_id="public-release-v1",
        context_revision=4,
        context_digest=_hex("context-v4"),
    )


def _report(
    *,
    state: str = "Trusted",
    failure: list[dict[str, Any]] | None = None,
    signing_time: str = SIGNING_TIME,
) -> dict[str, Any]:
    success: list[dict[str, Any]] = [
        {
            "code": "claimSignature.validated",
            "url": "self#jumbf=/c2pa/urn:c2pa:test/c2pa.signature",
            "explanation": "claim signature valid",
        },
        {
            "code": "assertion.hashedURI.match",
            "url": (
                "self#jumbf=/c2pa/urn:c2pa:test/"
                "c2pa.assertions/c2pa.actions.v2"
            ),
        },
        {
            "code": "assertion.dataHash.match",
            "url": (
                "self#jumbf=/c2pa/urn:c2pa:test/"
                "c2pa.assertions/c2pa.hash.data"
            ),
        },
    ]
    if state == "Trusted":
        success.append(
            {
                "code": "signingCredential.trusted",
                "url": "self#jumbf=/c2pa/urn:c2pa:test/c2pa.signature",
            }
        )
    return {
        "active_manifest": "urn:c2pa:test",
        "manifests": {
            "urn:c2pa:test": {
                "assertions": [
                    {
                        "label": "c2pa.actions.v2",
                        "data": {"actions": [{"action": "c2pa.created"}]},
                    }
                ],
                "claim_generator_info": [
                    {"name": "c2patool", "version": "0.23.2"}
                ],
                "label": "urn:c2pa:test",
                "signature_info": {
                    "alg": "Es256",
                    "time": signing_time,
                },
            }
        },
        "validation_results": {
            "activeManifest": {
                "success": success,
                "informational": [],
                "failure": failure or [],
            },
            "ingredientDeltas": [],
            "validationTime": "2027-01-15T08:00:00Z",
        },
        "validation_state": state,
        "validation_status": [],
    }


def _manifest(_binding_value, _assertions):
    return {
        "title": "Governed release asset",
        "vendor": "lightwork",
        "claim_generator_info": [{"name": "Lightwork", "version": "0.1.7"}],
        "assertions": [
            {
                "label": "c2pa.actions.v2",
                "data": {"actions": [{"action": "c2pa.created"}]},
            }
        ],
    }


def _credentials() -> c2pa.C2PAToolSigningCredentials:
    return c2pa.C2PAToolSigningCredentials(
        certificate_chain=CERTIFICATE,
        private_key=PRIVATE_KEY,
        algorithm="es256",
    )


@dataclass
class Call:
    args: tuple[str, ...]
    cwd: Path
    env: dict[str, str]
    timeout_seconds: float
    output_limit_bytes: int


class RecordingRunner:
    def __init__(
        self,
        report: dict[str, Any] | None = None,
        *,
        behavior: str = "success",
    ) -> None:
        self.report = report or _report()
        self.behavior = behavior
        self.calls: list[Call] = []
        self.operation_workspace: Path | None = None
        self.private_modes: dict[str, int] = {}
        self.private_restricted: dict[str, bool] = {}
        self.manifest_definition: dict[str, Any] | None = None

    def __call__(
        self,
        args,
        *,
        cwd,
        env,
        timeout_seconds,
        output_limit_bytes,
    ) -> c2pa.C2PAToolProcessResult:
        call = Call(
            args=tuple(args),
            cwd=Path(cwd),
            env=dict(env),
            timeout_seconds=timeout_seconds,
            output_limit_bytes=output_limit_bytes,
        )
        self.calls.append(call)
        if "--version" in args:
            return c2pa.C2PAToolProcessResult(0, b"c2patool 0.23.2\n", b"")
        self.operation_workspace = Path(cwd)
        if self.behavior == "timeout":
            raise subprocess.TimeoutExpired(tuple(args), timeout_seconds)
        if self.behavior == "nonzero":
            return c2pa.C2PAToolProcessResult(7, b"", PRIVATE_KEY)
        if self.behavior == "oversize":
            return c2pa.C2PAToolProcessResult(
                0,
                b"x" * (output_limit_bytes + 1),
                b"",
            )
        if self.behavior == "wrong-result":
            return {"returncode": 0}  # type: ignore[return-value]

        for path in Path(cwd).iterdir():
            self.private_modes[path.name] = stat.S_IMODE(path.stat().st_mode)
            self.private_restricted[path.name] = private_path_is_restricted(path, 0o600)
        if "--manifest" in args:
            manifest_path = Path(args[args.index("--manifest") + 1])
            self.manifest_definition = json.loads(manifest_path.read_text("utf-8"))
            if "private_key" in self.manifest_definition:
                private_key_path = Path(self.manifest_definition["private_key"])
                certificate_path = Path(self.manifest_definition["sign_cert"])
                if not private_key_path.is_absolute():
                    private_key_path = Path(cwd) / private_key_path
                if not certificate_path.is_absolute():
                    certificate_path = Path(cwd) / certificate_path
                assert private_key_path.read_bytes() == PRIVATE_KEY
                assert certificate_path.read_bytes() == CERTIFICATE
            input_path = Path(args[1])
            output_path = Path(args[args.index("--output") + 1])
            output = input_path.read_bytes() + SIGNED_SUFFIX
            if self.behavior == "oversize-output":
                output = b"x" * 33
            if self.behavior == "unchanged-output":
                output = input_path.read_bytes()
            output_path.write_bytes(output)
        return c2pa.C2PAToolProcessResult(
            0,
            json.dumps(self.report, separators=(",", ":")).encode("utf-8"),
            b"",
        )


def _executable(tmp_path: Path) -> str:
    executable = (tmp_path / "bin" / "c2patool.exe").resolve()
    executable.parent.mkdir(exist_ok=True)
    if not executable.exists():
        executable.write_bytes(TOOL_EXECUTABLE)
    return str(executable)


def _verifier(tmp_path: Path, runner: RecordingRunner, **kwargs):
    temp_root = tmp_path / "temporary"
    temp_root.mkdir(exist_ok=True)
    return c2pa.C2PAToolVerifier(
        executable=_executable(tmp_path),
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
        temp_root=temp_root,
        clock=lambda: NOW,
        **kwargs,
    )


def _signer(tmp_path: Path, runner: RecordingRunner, **kwargs):
    temp_root = tmp_path / "temporary"
    temp_root.mkdir(exist_ok=True)
    return c2pa.C2PAToolSigner(
        executable=_executable(tmp_path),
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
        credential_provider=_credentials,
        manifest_provider=_manifest,
        temp_root=temp_root,
        clock=lambda: NOW,
        **kwargs,
    )


def test_missing_tool_is_unavailable_and_interfaces_are_structural(tmp_path):
    runner = RecordingRunner()
    verifier = c2pa.C2PAToolVerifier(
        executable_locator=lambda _name: None,
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
    )
    signer = c2pa.C2PAToolSigner(
        executable_locator=lambda _name: None,
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
        credential_provider=_credentials,
        manifest_provider=_manifest,
    )

    assert isinstance(verifier, provenance.C2PAVerifier)
    assert isinstance(signer, provenance.C2PASigner)
    assert verifier.is_available() is False
    assert signer.is_available() is False
    assert verifier.adapter_version == "unavailable"
    with pytest.raises(provenance.MediaProvenanceUnavailable):
        verifier.verify(JPEG, binding=_binding())
    with pytest.raises(provenance.MediaProvenanceUnavailable):
        signer.sign(
            JPEG,
            binding=_binding(),
            assertion_codes=("c2pa.actions",),
        )
    assert runner.calls == []


def test_signer_without_injected_custody_providers_stays_unavailable(tmp_path):
    runner = RecordingRunner()
    signer = c2pa.C2PAToolSigner(
        executable=_executable(tmp_path),
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
    )

    assert isinstance(signer, provenance.C2PASigner)
    assert signer.is_available() is False
    status = provenance.MediaProvenanceService(
        signer=signer,
        enforce_feature=False,
    ).capability_status()["signing"]
    assert status == {
        "configured": True,
        "available": False,
        "status": "unavailable",
        "adapter_id": "c2patool",
        "adapter_version": None,
    }
    with pytest.raises(provenance.MediaProvenanceUnavailable):
        signer.sign(JPEG, binding=_binding(), assertion_codes=("c2pa.actions",))
    assert runner.calls == []


@pytest.mark.parametrize(
    "expected_digest",
    [None, _hex(b"different c2patool executable")],
)
def test_c2patool_requires_the_exact_executable_digest_before_spawn(
    tmp_path,
    expected_digest,
):
    runner = RecordingRunner()
    verifier = c2pa.C2PAToolVerifier(
        executable=_executable(tmp_path),
        expected_executable_sha256=expected_digest,
        process_runner=runner,
    )

    assert verifier.is_available() is False
    with pytest.raises(provenance.MediaProvenanceUnavailable):
        verifier.verify(JPEG, binding=_binding())
    assert runner.calls == []


def test_c2patool_mutation_during_version_admission_fails_closed(tmp_path):
    executable = Path(_executable(tmp_path))

    class MutatingVersionRunner(RecordingRunner):
        def __call__(self, args, **kwargs):
            result = super().__call__(args, **kwargs)
            if "--version" in args:
                executable.write_bytes(b"mutated during version admission")
            return result

    runner = MutatingVersionRunner()
    verifier = c2pa.C2PAToolVerifier(
        executable=executable,
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
    )

    assert verifier.is_available() is False
    assert len(runner.calls) == 1


def test_verifier_rechecks_c2patool_replacement_immediately_before_spawn(tmp_path):
    executable = Path(_executable(tmp_path))
    runner = RecordingRunner()
    temp_root = tmp_path / "temporary"
    temp_root.mkdir()

    def replacing_anchors():
        replacement = executable.with_name("replacement-c2patool.exe")
        replacement.write_bytes(TOOL_EXECUTABLE)
        os.replace(replacement, executable)
        return TRUST_ANCHORS

    verifier = c2pa.C2PAToolVerifier(
        executable=executable,
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
        trust_anchor_provider=replacing_anchors,
        temp_root=temp_root,
    )
    assert verifier.is_available() is True

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        verifier.verify(JPEG, binding=_binding())

    assert len(runner.calls) == 1
    assert list(temp_root.iterdir()) == []


def test_local_signer_rechecks_c2patool_replacement_after_secret_access(tmp_path):
    executable = Path(_executable(tmp_path))
    runner = RecordingRunner()
    temp_root = tmp_path / "temporary"
    temp_root.mkdir()
    credentials_accessed = False

    def replacing_manifest(binding, assertions):
        replacement = executable.with_name("replacement-c2patool.exe")
        replacement.write_bytes(TOOL_EXECUTABLE)
        os.replace(replacement, executable)
        return _manifest(binding, assertions)

    def credentials():
        nonlocal credentials_accessed
        credentials_accessed = True
        return _credentials()

    signer = c2pa.C2PAToolSigner(
        executable=executable,
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
        credential_provider=credentials,
        manifest_provider=replacing_manifest,
        temp_root=temp_root,
    )

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        signer.sign(
            JPEG,
            binding=_binding(),
            assertion_codes=("c2pa.actions", "c2pa.hash.data"),
        )

    assert credentials_accessed is True
    assert len(runner.calls) == 1
    assert list(temp_root.iterdir()) == []


def test_verify_uses_fixed_local_argv_closed_receipt_and_cleanup(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("C2PATOOL_TRUST_ANCHORS", "must-not-be-inherited")
    monkeypatch.setenv("HTTPS_PROXY", "must-not-be-inherited")
    runner = RecordingRunner()
    verifier = _verifier(
        tmp_path,
        runner,
        trust_anchor_provider=lambda: TRUST_ANCHORS,
        timeout_seconds=2.5,
        output_limit_bytes=64 * 1024,
    )

    receipt = verifier.verify(JPEG, binding=_binding())
    normalized = provenance.normalize_c2pa_receipt(receipt)

    assert normalized.operation == "verification"
    assert normalized.adapter_id == "c2patool"
    assert normalized.adapter_version == "0.23.2"
    assert normalized.standard == "c2pa"
    assert normalized.content_sha256 == _hex(JPEG)
    assert normalized.source_content_sha256 == _hex(JPEG)
    assert normalized.validation_state == "valid"
    assert normalized.trust_chain_state == "trusted"
    assert normalized.assertion_codes == ("c2pa.actions", "c2pa.hash.data")
    assert normalized.claim_generator == "c2patool/0.23.2"
    assert normalized.receipt_sha256 == _canonical_sha(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )

    operation = runner.calls[-1]
    assert operation.args[0] == _executable(tmp_path)
    assert operation.args[2] == "--settings"
    assert operation.args[4:] == (
        "trust",
        "--trust_anchors",
        "trust-anchors.pem",
    )
    assert operation.timeout_seconds == 2.5
    assert operation.output_limit_bytes == 64 * 1024
    assert "C2PATOOL_TRUST_ANCHORS" not in operation.env
    assert "HTTPS_PROXY" not in operation.env
    assert set(operation.env).issubset(
        {"PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "TEMP", "TMP", "TMPDIR"}
    )
    if os.name != "nt":
        assert all(mode & 0o077 == 0 for mode in runner.private_modes.values())
    assert all(runner.private_restricted.values())
    assert runner.operation_workspace is not None
    assert not runner.operation_workspace.exists()
    serialized = json.dumps(receipt, sort_keys=True)
    assert PRIVATE_KEY.decode() not in serialized
    assert TRUST_ANCHORS.decode() not in serialized
    assert str(operation.cwd) not in serialized


def test_sign_uses_fixed_argv_keeps_secrets_off_argv_and_cleans(tmp_path):
    runner = RecordingRunner()
    signer = _signer(tmp_path, runner)

    signed_media, receipt = signer.sign(
        JPEG,
        binding=_binding(),
        assertion_codes=("c2pa.hash.data", "c2pa.actions"),
    )
    normalized = provenance.normalize_c2pa_receipt(receipt)

    assert signed_media == JPEG + SIGNED_SUFFIX
    assert normalized.operation == "signing"
    assert normalized.source_content_sha256 == _hex(JPEG)
    assert normalized.content_sha256 == _hex(signed_media)
    assert normalized.assertion_codes == ("c2pa.actions", "c2pa.hash.data")
    operation = runner.calls[-1]
    assert operation.args == (
        _executable(tmp_path),
        str(operation.cwd / "input.jpg"),
        "--manifest",
        str(operation.cwd / "manifest.json"),
        "--output",
        str(operation.cwd / "signed.jpg"),
        "--settings",
        str(operation.cwd / "settings.json"),
    )
    argv_and_env = "\n".join((*operation.args, *operation.env.values()))
    assert PRIVATE_KEY.decode() not in argv_and_env
    assert CERTIFICATE.decode() not in argv_and_env
    assert runner.manifest_definition is not None
    assert PRIVATE_KEY.decode() not in json.dumps(runner.manifest_definition)
    assert CERTIFICATE.decode() not in json.dumps(runner.manifest_definition)
    assert runner.manifest_definition["alg"] == "es256"
    if os.name != "nt":
        assert all(mode & 0o077 == 0 for mode in runner.private_modes.values())
    assert all(runner.private_restricted.values())
    assert runner.operation_workspace is not None
    assert not runner.operation_workspace.exists()
    serialized = json.dumps(receipt, sort_keys=True)
    assert PRIVATE_KEY.decode() not in serialized
    assert CERTIFICATE.decode() not in serialized
    assert str(operation.cwd) not in serialized


def test_external_signer_correct_digest_keeps_private_key_out_of_lightwork(tmp_path):
    runner = RecordingRunner()
    signer_binary = (tmp_path / "kms-signer.exe").resolve()
    signer_fixture = b"test executable fixture"
    signer_binary.write_bytes(signer_fixture)
    signer = c2pa.C2PAToolExternalSigner(
        executable=_executable(tmp_path),
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
        signer_path=signer_binary,
        expected_signer_sha256=_hex(signer_fixture),
        manifest_provider=_manifest,
        temp_root=tmp_path,
        clock=lambda: NOW,
    )

    signed_media, receipt = signer.sign(
        JPEG,
        binding=_binding(),
        assertion_codes=("c2pa.actions", "c2pa.hash.data"),
    )

    assert signed_media == JPEG + SIGNED_SUFFIX
    assert receipt["operation"] == "signing"
    operation = runner.calls[-1]
    assert operation.args[-2:] == ("--signer-path", str(signer_binary))
    assert runner.manifest_definition is not None
    assert not {
        "alg",
        "private_key",
        "sign_cert",
    }.intersection(runner.manifest_definition)
    assert "private-key.pem" not in runner.private_modes
    assert not operation.cwd.exists()


def test_external_signer_rejects_wrong_expected_digest(tmp_path):
    signer_binary = (tmp_path / "kms-signer.exe").resolve()
    signer_binary.write_bytes(b"approved external signer")

    with pytest.raises(ValueError, match="digest or identity mismatch"):
        c2pa.C2PAToolExternalSigner(
            executable=_executable(tmp_path),
            expected_executable_sha256=_hex(TOOL_EXECUTABLE),
            process_runner=RecordingRunner(),
            signer_path=signer_binary,
            expected_signer_sha256=_hex("different external signer"),
            manifest_provider=_manifest,
            temp_root=tmp_path,
            clock=lambda: NOW,
        )


def test_external_signer_replacement_after_construction_fails_before_spawn(tmp_path):
    runner = RecordingRunner()
    signer_binary = (tmp_path / "kms-signer.exe").resolve()
    approved = b"approved external signer"
    signer_binary.write_bytes(approved)

    def replacing_manifest(binding, assertions):
        replacement = tmp_path / "replacement-signer.exe"
        replacement.write_bytes(b"unapproved replacement signer")
        os.replace(replacement, signer_binary)
        return _manifest(binding, assertions)

    signer = c2pa.C2PAToolExternalSigner(
        executable=_executable(tmp_path),
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
        signer_path=signer_binary,
        expected_signer_sha256=_hex(approved),
        manifest_provider=replacing_manifest,
        temp_root=tmp_path,
        clock=lambda: NOW,
    )

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        signer.sign(
            JPEG,
            binding=_binding(),
            assertion_codes=("c2pa.actions", "c2pa.hash.data"),
        )

    assert signer.is_available() is False
    assert all("--manifest" not in call.args for call in runner.calls)


def test_external_signer_rechecks_c2patool_mutation_before_spawn(tmp_path):
    runner = RecordingRunner()
    executable = Path(_executable(tmp_path))
    signer_binary = (tmp_path / "kms-signer.exe").resolve()
    signer_fixture = b"approved external signer"
    signer_binary.write_bytes(signer_fixture)

    def mutating_manifest(binding, assertions):
        executable.write_bytes(b"mutated c2patool before external signing")
        return _manifest(binding, assertions)

    signer = c2pa.C2PAToolExternalSigner(
        executable=executable,
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
        signer_path=signer_binary,
        expected_signer_sha256=_hex(signer_fixture),
        manifest_provider=mutating_manifest,
        temp_root=tmp_path,
        clock=lambda: NOW,
    )

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        signer.sign(
            JPEG,
            binding=_binding(),
            assertion_codes=("c2pa.actions", "c2pa.hash.data"),
        )

    assert len(runner.calls) == 1
    assert all("--manifest" not in call.args for call in runner.calls)


def test_timestamp_authority_requires_safe_explicit_transport(tmp_path):
    runner = RecordingRunner()
    with pytest.raises(ValueError, match="timestamp authority URL"):
        _signer(
            tmp_path,
            runner,
            timestamp_authority_url="http://timestamp.example.com",
        )
    with pytest.raises(ValueError, match="host"):
        _signer(
            tmp_path,
            runner,
            timestamp_authority_url="https://127.0.0.1",
        )


def test_timestamp_egress_denial_precedes_signing_secret_access(
    tmp_path, monkeypatch
):
    runner = RecordingRunner()
    credential_calls = 0

    def credentials():
        nonlocal credential_calls
        credential_calls += 1
        return _credentials()

    monkeypatch.setattr(
        "maverick.enterprise.enterprise_egress_denial",
        lambda url, *, tool: "denied",
    )
    signer = c2pa.C2PAToolSigner(
        executable=_executable(tmp_path),
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
        credential_provider=credentials,
        manifest_provider=_manifest,
        timestamp_authority_url="https://timestamp.example.com",
        temp_root=tmp_path,
        clock=lambda: NOW,
    )

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        signer.sign(JPEG, binding=_binding(), assertion_codes=("c2pa.actions",))
    assert credential_calls == 0


def test_detached_lightwork_receipts_fail_closed(tmp_path):
    runner = RecordingRunner()
    verifier = _verifier(tmp_path, runner)
    signer = _signer(tmp_path, runner)

    with pytest.raises(provenance.MediaProvenanceUnavailable, match="detached"):
        verifier.attest_receipt({}, binding=_binding())
    with pytest.raises(provenance.MediaProvenanceUnavailable, match="detached"):
        signer.attest_receipt({}, binding=_binding())
    assert runner.calls == []


def test_invalid_media_is_reported_without_promoting_trust_or_validity(tmp_path):
    failure = [
        {
            "code": "signingCredential.untrusted",
            "url": "self#jumbf=/c2pa/urn:c2pa:test/c2pa.signature",
        }
    ]
    runner = RecordingRunner(report=_report(state="Invalid", failure=failure))
    verifier = _verifier(tmp_path, runner)

    receipt = verifier.verify(JPEG, binding=_binding())
    normalized = provenance.normalize_c2pa_receipt(receipt)

    assert normalized.validation_state == "invalid"
    assert normalized.trust_chain_state == "untrusted"
    assert normalized.standard == "c2pa"


def test_valid_untrusted_media_keeps_validity_and_does_not_promote_trust(tmp_path):
    failure = [
        {
            "code": "signingCredential.untrusted",
            "url": "self#jumbf=/c2pa/urn:c2pa:test/c2pa.signature",
        }
    ]
    runner = RecordingRunner(report=_report(state="Valid", failure=failure))
    verifier = _verifier(tmp_path, runner)

    receipt = verifier.verify(JPEG, binding=_binding())
    normalized = provenance.normalize_c2pa_receipt(receipt)

    assert normalized.validation_state == "valid"
    assert normalized.trust_chain_state == "untrusted"


@pytest.mark.parametrize("behavior", ["timeout", "nonzero", "oversize", "wrong-result"])
def test_process_failures_are_sanitized_and_workspace_is_cleaned(tmp_path, behavior):
    runner = RecordingRunner(behavior=behavior)
    verifier = _verifier(tmp_path, runner)

    with pytest.raises(provenance.MediaProvenanceUnavailable) as caught:
        verifier.verify(JPEG, binding=_binding())

    rendered = str(caught.value)
    assert "adapter-test-private-key-secret" not in rendered
    assert runner.operation_workspace is not None
    assert not runner.operation_workspace.exists()


def _encoded(report: object) -> bytes:
    return json.dumps(report, separators=(",", ":")).encode("utf-8")


def _malformed_reports() -> list[bytes]:
    unknown = _report()
    unknown["unexpected"] = True
    missing_manifest = _report()
    missing_manifest["active_manifest"] = "urn:c2pa:missing"
    invalid_state = _report()
    invalid_state["validation_state"] = "ProbablyValid"
    missing_trust = _report()
    missing_trust["validation_results"]["activeManifest"]["success"] = [
        item
        for item in missing_trust["validation_results"]["activeManifest"]["success"]
        if item["code"] != "signingCredential.trusted"
    ]
    valid_with_failure = _report(state="Valid")
    valid_with_failure["validation_results"]["activeManifest"]["failure"] = [
        {"code": "claimSignature.mismatch"}
    ]
    bad_time = _report(signing_time="2027-01-15T07:59:00")
    duplicate = (
        b'{"active_manifest":"urn:c2pa:test","active_manifest":"duplicate",'
        b'"manifests":{},"validation_results":{},"validation_state":"Valid"}'
    )
    return [
        b"not-json",
        b"\xef\xbb\xbf{}",
        duplicate,
        _encoded(unknown),
        _encoded(missing_manifest),
        _encoded(invalid_state),
        _encoded(missing_trust),
        _encoded(valid_with_failure),
        _encoded(bad_time),
    ]


@pytest.mark.parametrize("payload", _malformed_reports())
def test_malformed_or_inconsistent_reports_fail_closed_and_clean(tmp_path, payload):
    class PayloadRunner(RecordingRunner):
        def __call__(self, args, **kwargs):
            if "--version" in args:
                return super().__call__(args, **kwargs)
            call = Call(
                args=tuple(args),
                cwd=Path(kwargs["cwd"]),
                env=dict(kwargs["env"]),
                timeout_seconds=kwargs["timeout_seconds"],
                output_limit_bytes=kwargs["output_limit_bytes"],
            )
            self.calls.append(call)
            self.operation_workspace = call.cwd
            return c2pa.C2PAToolProcessResult(0, payload, b"")

    runner = PayloadRunner()
    verifier = _verifier(tmp_path, runner)

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        verifier.verify(JPEG, binding=_binding())
    assert runner.operation_workspace is not None
    assert not runner.operation_workspace.exists()


@pytest.mark.parametrize(
    ("unsafe_key", "unsafe_value"),
    [
        ("private_key", "C:/secrets/key.pem"),
        ("sign_cert", "C:/secrets/cert.pem"),
        ("ingredients", [{"title": "read-a-local-file"}]),
        ("thumbnail", {"identifier": "C:/secrets/image.jpg"}),
        ("base_path", "C:/secrets"),
    ],
)
def test_hostile_manifest_resource_controls_are_rejected_before_secret_access(
    tmp_path, unsafe_key, unsafe_value
):
    runner = RecordingRunner()
    credential_calls = 0

    def credentials():
        nonlocal credential_calls
        credential_calls += 1
        return _credentials()

    def manifest(binding, assertions):
        value = _manifest(binding, assertions)
        value[unsafe_key] = unsafe_value
        return value

    signer = c2pa.C2PAToolSigner(
        executable=_executable(tmp_path),
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
        credential_provider=credentials,
        manifest_provider=manifest,
        temp_root=tmp_path,
        clock=lambda: NOW,
    )

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        signer.sign(JPEG, binding=_binding(), assertion_codes=("c2pa.actions",))
    assert credential_calls == 0
    assert all("--manifest" not in call.args for call in runner.calls)


@pytest.mark.parametrize(
    "credentials",
    [
        c2pa.C2PAToolSigningCredentials(CERTIFICATE, PRIVATE_KEY, "hs256"),
        c2pa.C2PAToolSigningCredentials(b"not-a-certificate", PRIVATE_KEY, "es256"),
        c2pa.C2PAToolSigningCredentials(CERTIFICATE, b"not-a-key", "es256"),
        c2pa.C2PAToolSigningCredentials(CERTIFICATE, b"x" * (64 * 1024 + 1), "es256"),
    ],
)
def test_invalid_signing_credentials_never_reach_the_tool(tmp_path, credentials):
    runner = RecordingRunner()
    signer = c2pa.C2PAToolSigner(
        executable=_executable(tmp_path),
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
        credential_provider=lambda: credentials,
        manifest_provider=_manifest,
        temp_root=tmp_path,
        clock=lambda: NOW,
    )

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        signer.sign(JPEG, binding=_binding(), assertion_codes=("c2pa.actions",))
    assert all("--manifest" not in call.args for call in runner.calls)


@pytest.mark.parametrize(
    ("media", "kind"),
    [
        (b"", "image"),
        (b"plain text", "image"),
        (JPEG, "audio"),
        (b"RIFF\x00\x00\x00\x00WAVEpayload", "video"),
    ],
)
def test_empty_unsupported_or_kind_mismatched_media_fails_before_operation(
    tmp_path, media, kind
):
    runner = RecordingRunner()
    verifier = _verifier(tmp_path, runner)

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        verifier.verify(media, binding=_binding(media, media_kind=kind))
    assert all("--settings" not in call.args for call in runner.calls)


def test_media_input_bound_is_enforced_before_tool_execution(tmp_path, monkeypatch):
    runner = RecordingRunner()
    verifier = _verifier(tmp_path, runner)
    monkeypatch.setattr(c2pa, "_MAX_MEDIA_BYTES", len(JPEG) - 1)

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        verifier.verify(JPEG, binding=_binding())
    assert runner.calls == []


@pytest.mark.parametrize("behavior", ["oversize-output", "unchanged-output"])
def test_invalid_signed_output_fails_and_secrets_are_cleaned(
    tmp_path, monkeypatch, behavior
):
    runner = RecordingRunner(behavior=behavior)
    signer = _signer(tmp_path, runner)
    if behavior == "oversize-output":
        monkeypatch.setattr(c2pa, "_MAX_MEDIA_BYTES", 32)

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        signer.sign(JPEG, binding=_binding(), assertion_codes=("c2pa.actions",))
    assert runner.operation_workspace is not None
    assert not runner.operation_workspace.exists()


def test_hostile_tool_cannot_copy_credential_material_into_receipt(tmp_path):
    report = _report()
    report["manifests"]["urn:c2pa:test"]["claim_generator_info"] = [
        {"name": "adapter-test-private-key-secret", "version": "1"}
    ]
    runner = RecordingRunner(report=report)
    signer = _signer(tmp_path, runner)

    with pytest.raises(provenance.MediaProvenanceUnavailable) as caught:
        signer.sign(JPEG, binding=_binding(), assertion_codes=("c2pa.actions",))
    assert "adapter-test-private-key-secret" not in str(caught.value)
    assert runner.operation_workspace is not None
    assert not runner.operation_workspace.exists()


def test_secret_provider_exception_is_sanitized(tmp_path):
    runner = RecordingRunner()

    def credentials():
        raise provenance.MediaProvenanceUnavailable(
            "adapter-test-private-key-secret"
        )

    signer = c2pa.C2PAToolSigner(
        executable=_executable(tmp_path),
        expected_executable_sha256=_hex(TOOL_EXECUTABLE),
        process_runner=runner,
        credential_provider=credentials,
        manifest_provider=_manifest,
        temp_root=tmp_path,
        clock=lambda: NOW,
    )

    with pytest.raises(provenance.MediaProvenanceUnavailable) as caught:
        signer.sign(JPEG, binding=_binding(), assertion_codes=("c2pa.actions",))
    assert "adapter-test-private-key-secret" not in str(caught.value)
    assert all("--manifest" not in call.args for call in runner.calls)


def test_future_signing_time_and_oversized_nested_json_fail_closed(tmp_path):
    future = _report(signing_time="2099-01-01T00:00:00Z")
    nested: object = "leaf"
    for _index in range(40):
        nested = [nested]
    future["manifests"]["urn:c2pa:test"]["hostile"] = nested
    runner = RecordingRunner(report=future)
    verifier = _verifier(tmp_path, runner)

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        verifier.verify(JPEG, binding=_binding())
    assert runner.operation_workspace is not None
    assert not runner.operation_workspace.exists()


def test_missing_requested_assertion_rejects_signed_output_and_cleans(tmp_path):
    report = _report()
    report["manifests"]["urn:c2pa:test"]["assertions"] = [
        {"label": "org.example.other", "data": {}}
    ]
    success = report["validation_results"]["activeManifest"]["success"]
    report["validation_results"]["activeManifest"]["success"] = [
        item
        for item in success
        if "c2pa.actions" not in str(item.get("url", ""))
    ]
    runner = RecordingRunner(report=report)
    signer = _signer(tmp_path, runner)

    with pytest.raises(provenance.MediaProvenanceUnavailable):
        signer.sign(JPEG, binding=_binding(), assertion_codes=("c2pa.actions",))
    assert runner.operation_workspace is not None
    assert not runner.operation_workspace.exists()


def test_credentials_repr_and_process_result_repr_do_not_expose_bytes():
    credentials = _credentials()
    result = c2pa.C2PAToolProcessResult(1, PRIVATE_KEY, CERTIFICATE)

    assert "adapter-test-private-key-secret" not in repr(credentials)
    assert "adapter-test-private-key-secret" not in repr(result)
    assert "adapter-test-certificate" not in repr(result)

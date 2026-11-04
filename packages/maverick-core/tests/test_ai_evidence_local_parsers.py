from __future__ import annotations

import base64
import hashlib
import importlib.metadata
import sys
import zlib
from pathlib import Path

import pytest
from maverick import ai_evidence_analysis as evidence
from maverick import ai_evidence_local_parsers as local

_SIMPLE_XLS = (
    "eNq7cF7wwcKNUg8Z0IAdAzPDv/+cDGxIYoxAzAnjCDAA5f//BzFhNAcQ/x8FQwpwcgAjko2V"
    "YTfvGXZQHILi+yEDE8MGloNAkoHhERDHMBQw+OXnpSrQETiB3ZDICHKDLZBkZJgDFOFjkAS7S"
    "ghMJoNJYTC5HqxyD5h0AIv0gklboNoHjFEM5+39tCygqTiCSQksx8cAMnc7WM8tsIghgyjDC"
    "VAqrp/ACFHLyuBYlJmYMzgl5Fh4GJYwAOPNPTUvtSgx5wGDCDAClzB8/a/AwPAFllMPKIyK0"
    "1eckQEo/gNVnB2L+GQmFgaGBob/CeAE3gosU68yQwpS17LMlNS85NQ/DHrgYheElRkYfDzdP"
    "ULC/YO8413DPF1c/Zxd490cnUOsQIReYnJyanExF6iQBmdqAZRMzQtO7DxAMoWBH8wWBCd5Aa"
    "Btf1Z+vOSbFGAfDxZpABfkEDtVQS5k+M/QCNIB1MwHlmGCy2uB2dpgsglsqjSYLQUmRYAJFUi"
    "rBYhCGW7NYDUtYFk1oD3GYHDZXh2JrQFkt74O3CHX+theE8he5/6wSmTddfuFDErA6icFqB8"
    "Emxl0GHUYZ80EgZ32MJoRWjTcBZOSGMUEB5MA1O3/oXUaP8NfBi4wUxBMglQwoqmoY+ICiwky"
    "rAJVjUxCDNvAQeCAVDlyMYyCUTAKRsEoGAWjYBSMglEw6AEjtDkP6neAmvqs0O4CO3Rc5y8Q"
    "/xsdJhm2IIghHwhLgB1TV4Y8IF3EUElS+hFjYGWEmcVIpB7YeCEIhANtL2LIZkgCuyOb5PQL"
    "7O4xIvuHaI0C1MtCpNr/jxR30th+ADrTxgo="
)
_FORMULA_XLS = (
    "eNq7cF7wwcKNUg8Z0IAdAzPDv/+cDGxIYoxAzAnjCDAA5f//BzFhNAcQ/x8FQwpwcgAjko2V"
    "YTfvGXZQHILi+yEDE8MGloNAkoHhERDHMBQw+OXnpSrQETiB3ZDICHKDLZBkZJgDFOFjkAS7S"
    "ghMJoNJYTC5HqxyD5h0AIv0gklboNoHjFEM5+39tCygqTiCSQksx8cAMnc7WM8tsIghgyjDC"
    "VAqrp/ACFHLyuBYlJmYMzgl5Fh4GJYwAOPNPTUvtSgx5wGDCDAClzB8/a/AwPAFllMPKIyK0"
    "1eckQEo/gNVnB2L+GQmFgaGBob/CeAE3gosU9czQwpS17LMlNS85NQ/4EIVArhAxS84uwqgZ"
    "FdecDLmAZIpDPxgtiA4MQsA9f5Z+fGSb1KAfTxYpAFqGigVqYLsZvjP0AjSAdTMB5Zhgstrg"
    "dnaYLIJbKo0mC0FJkWASRBIqwWIQhluzWA1LWBZNaA9xmBw2V4dia0BZLe+Dtwh1/rYXhPIX"
    "uf+sEpk3XX7hQxKwIolBagfBJsZdBh1GGfNBIGd9jCaEZrp74JJSYwCgINJAOr2/9Daih8YO"
    "rJgpiADOFgZ/kOl2BnkGEGIGaSJEU1THRMXWEyQYRWoHmQSYtgGDhUHpJqQi2EUjIJRMApGw"
    "SgYBaNgFIyCoQgYoY1+UAMZ1CFghXYq2KHjOn+B+N/oMMmwBUEM+UBYAuyYujLkAekihkqS0"
    "o8YAysjzCxGIvXAxgtBIBxoexFDNkMS2B3ZJKdfYKeQEdk/RGsUoF4WItX+f6S4k8b2AwCP"
    "i7ws"
)
_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def _xls(value: str) -> bytes:
    return zlib.decompress(base64.b64decode(value))


def _xls_config(**overrides: object) -> local.LegacyXLSConfig:
    values: dict[str, object] = {
        "xlrd_version": "2.0.2",
        "xlrd_manifest_sha256": local._distribution_manifest_sha256("xlrd"),  # noqa: SLF001
        "olefile_version": "0.47",
        "olefile_manifest_sha256": local._distribution_manifest_sha256("olefile"),  # noqa: SLF001
        "max_output_bytes": 4_096,
        **overrides,
    }
    return local.LegacyXLSConfig(**values)  # type: ignore[arg-type]


def _sandbox(tmp_path: Path) -> local.LocalParserSandboxConfig:
    launcher = tmp_path / "bwrap"
    launcher.write_bytes(b"reviewed-bubblewrap")
    return local.LocalParserSandboxConfig(
        launcher=str(launcher.resolve()),
        launcher_sha256=hashlib.sha256(launcher.read_bytes()).hexdigest(),
        launcher_version="0.11.0",
    )


def _mock_sandbox_probe(command, **_kwargs):
    if command[1:] == ("--version",):
        return local._ProcessResult(0, b"bubblewrap 0.11.0\n", b"")  # noqa: SLF001
    if "--sandbox-self-test" in command:
        return local._ProcessResult(0, b"sandbox-ok", b"")  # noqa: SLF001
    if "--self-test" in command:
        return local._ProcessResult(0, b"self-test-ok", b"")  # noqa: SLF001
    raise AssertionError(command)


def test_legacy_xls_is_default_off_and_dependency_versions_are_exact() -> None:
    # A fresh container may lack the legacy-XLS toolchain; the adapter
    # correctly reports the dependency unavailable there, which is a
    # different (also-covered) failure mode than this test pins.
    pytest.importorskip("xlrd")
    pytest.importorskip("olefile")
    adapter = local.GovernedLocalExtractionAdapter(maximum_bytes=4_096)
    with pytest.raises(local.LocalParserAttestationError, match="disabled"):
        adapter._legacy_xls_text(_xls(_SIMPLE_XLS))  # noqa: SLF001

    with pytest.raises(local.LocalParserAttestationError, match="version mismatch"):
        local.GovernedLocalExtractionAdapter(
            maximum_bytes=4_096,
            legacy_xls=_xls_config(xlrd_version="0.0.0"),
        )


def test_real_worker_extracts_safe_biff8_and_rejects_formula(tmp_path: Path) -> None:
    pytest.importorskip("xlrd")
    pytest.importorskip("olefile")
    def runner(command, **kwargs):
        if command[1:] == ("--version",) or "--sandbox-self-test" in command or (
            "--self-test" in command
        ):
            return _mock_sandbox_probe(command, **kwargs)
        kwargs.pop("sandbox", None)
        return local._bounded_process(command, **kwargs)  # noqa: SLF001

    adapter = local.GovernedLocalExtractionAdapter(
        maximum_bytes=4_096,
        sandbox=_sandbox(tmp_path),
        legacy_xls=_xls_config(),
        _runner=runner,
    )

    assert adapter._legacy_xls_text(_xls(_SIMPLE_XLS)) == (  # noqa: SLF001
        "LIGHTWORK_EVIDENCE_FACT:FACT.access\n42.0"
    )
    with pytest.raises(evidence.EvidenceAnalysisValidationError, match="formulas"):
        adapter._legacy_xls_text(_xls(_FORMULA_XLS))  # noqa: SLF001


def test_workers_launch_through_a_linked_interpreter_and_refuse_a_repointed_link(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A virtual environment's python is a symlink to the base interpreter;
    # launching the resolved file would leave the environment's packages.
    pytest.importorskip("xlrd")
    pytest.importorskip("olefile")
    real = Path(sys.executable).resolve()
    link = tmp_path / "venv-python"
    try:
        link.symlink_to(real)
    except OSError as exc:
        if getattr(exc, "winerror", None) == 1314:
            pytest.skip("Windows symlink creation privilege is unavailable")
        raise
    monkeypatch.setattr(local.sys, "executable", str(link))
    launched: list[str] = []

    def runner(command, **kwargs):
        launched.append(command[0])
        return _mock_sandbox_probe(command, **kwargs)

    adapter = local.GovernedLocalExtractionAdapter(
        maximum_bytes=4_096,
        sandbox=_sandbox(tmp_path),
        legacy_xls=_xls_config(),
        _runner=runner,
    )
    assert str(link) in launched and str(real) not in launched
    adapter._verify_static_identity()  # noqa: SLF001

    other = tmp_path / "other-python"
    other.write_bytes(b"not the attested interpreter")
    link.unlink()
    link.symlink_to(other)
    with pytest.raises(local.LocalParserAttestationError, match="changed"):
        adapter._verify_static_identity()  # noqa: SLF001


def test_biff8_scanner_rejects_unknown_active_and_oversized_records() -> None:
    limits = local._XLSLimits(  # noqa: SLF001
        max_workbook_stream_bytes=4_096,
        max_record_bytes=1_024,
        max_records=20,
        max_sheets=2,
        max_rows_per_sheet=10,
        max_columns_per_sheet=10,
        max_cells=10,
        max_output_bytes=1_024,
    )
    bof_globals = b"\x09\x08\x04\x00\x00\x06\x05\x00"
    eof = b"\x0a\x00\x00\x00"
    bof_sheet = b"\x09\x08\x04\x00\x00\x06\x10\x00"

    with pytest.raises(local._WorkerFailure, match="xls_feature_unsupported"):  # noqa: SLF001
        local._validate_biff8(  # noqa: SLF001
            bof_globals + b"\xff\x7f\x00\x00" + eof + bof_sheet + eof,
            limits,
        )
    with pytest.raises(local._WorkerFailure, match="xls_macro_unsupported"):  # noqa: SLF001
        local._validate_biff8(  # noqa: SLF001
            bof_globals + eof + b"\x09\x08\x04\x00\x00\x06\x40\x00" + eof,
            limits,
        )


def test_ocr_attests_exact_runtime_uses_transient_input_and_returns_bounded_text(
    tmp_path: Path,
) -> None:
    # Pillow ships in the reviewed CI environment (requirements/ci.txt);
    # a container without it must skip, not fail (test_oidc precedent).
    pytest.importorskip("PIL")
    executable = tmp_path / "tesseract.exe"
    executable.write_bytes(b"reviewed-local-tesseract")
    traineddata = tmp_path / "eng.traineddata"
    traineddata.write_bytes(b"reviewed-english-data")
    runtime_library = tmp_path / "tesseract-runtime.dll"
    runtime_library.write_bytes(b"reviewed-runtime")
    seen_input: list[Path] = []

    def runner(command, **kwargs):
        if command[0].endswith("bwrap") and command[1:] == ("--version",):
            return local._ProcessResult(0, b"bubblewrap 0.11.0\n", b"")  # noqa: SLF001
        if "--sandbox-self-test" in command:
            return local._ProcessResult(0, b"sandbox-ok", b"")  # noqa: SLF001
        if "--self-test" in command:
            return local._ProcessResult(0, b"self-test-ok", b"")  # noqa: SLF001
        if command[1:] == ("--version",):
            return local._ProcessResult(0, b"tesseract 5.4.1\n", b"")  # noqa: SLF001
        if command[1:] == ("--list-langs",):
            return local._ProcessResult(0, b"List of available languages (1):\neng\n", b"")  # noqa: SLF001
        if "--image-worker" in command:
            assert kwargs["input_bytes"] == _PNG
            return local._ProcessResult(0, b"ok", b"")  # noqa: SLF001
        input_path = Path(command[1])
        assert input_path.read_bytes() == _PNG
        seen_input.append(input_path)
        return local._ProcessResult(  # noqa: SLF001
            0,
            b"LIGHTWORK_EVIDENCE_FACT:FACT.image\n",
            b"",
        )

    adapter = local.GovernedLocalExtractionAdapter(
        maximum_bytes=4_096,
        sandbox=_sandbox(tmp_path),
        ocr=local.TesseractOCRConfig(
            executable=str(executable.resolve()),
            executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
            tesseract_version="5.4.1",
            traineddata_path=str(traineddata.resolve()),
            traineddata_sha256=hashlib.sha256(traineddata.read_bytes()).hexdigest(),
            runtime_library_paths=(str(runtime_library.resolve()),),
            runtime_libraries_sha256=local._manifest_sha256(  # noqa: SLF001
                (runtime_library.resolve(),), "test runtime"
            ),
            pillow_version=importlib.metadata.version("Pillow"),
            pillow_manifest_sha256=local._distribution_manifest_sha256("Pillow"),  # noqa: SLF001
            max_output_bytes=4_096,
        ),
        _runner=runner,
    )

    assert adapter._ocr_text(_PNG, evidence.MEDIA_PNG) == (  # noqa: SLF001
        "LIGHTWORK_EVIDENCE_FACT:FACT.image\n"
    )
    assert seen_input and not seen_input[0].exists()
    with pytest.raises(local.LocalParserAttestationError, match="non-stock"):
        adapter.authority(valid_until=1_900_000_000)
    authority = local.GovernedLocalExtractionAdapter(maximum_bytes=4_096).authority(
        valid_until=1_900_000_000
    )
    assert authority.revision == 4
    assert authority.network_access is False
    assert authority.implementation_sha256 == local._implementation_sha256()  # noqa: SLF001


def test_ocr_digest_version_and_output_bounds_fail_closed(tmp_path: Path) -> None:
    # Pillow ships in the reviewed CI environment (requirements/ci.txt);
    # a container without it must skip, not fail (test_oidc precedent).
    pytest.importorskip("PIL")
    executable = tmp_path / "tesseract.exe"
    executable.write_bytes(b"reviewed-local-tesseract")
    traineddata = tmp_path / "eng.traineddata"
    traineddata.write_bytes(b"reviewed-english-data")
    runtime_library = tmp_path / "runtime.dll"
    runtime_library.write_bytes(b"reviewed-runtime")
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()

    with pytest.raises(local.LocalParserAttestationError, match="digest mismatch"):
        local.GovernedLocalExtractionAdapter(
            maximum_bytes=4_096,
            ocr=local.TesseractOCRConfig(
                executable=str(executable.resolve()),
                executable_sha256="0" * 64,
                tesseract_version="5.4.1",
                traineddata_path=str(traineddata.resolve()),
                traineddata_sha256=hashlib.sha256(traineddata.read_bytes()).hexdigest(),
                runtime_library_paths=(str(runtime_library.resolve()),),
                runtime_libraries_sha256=local._manifest_sha256(  # noqa: SLF001
                    (runtime_library.resolve(),), "test runtime"
                ),
                pillow_version=importlib.metadata.version("Pillow"),
                pillow_manifest_sha256=local._distribution_manifest_sha256("Pillow"),  # noqa: SLF001
            ),
        )

    def wrong_version(command, **_kwargs):
        if command[0].endswith("bwrap"):
            return local._ProcessResult(0, b"bubblewrap 0.11.0\n", b"")  # noqa: SLF001
        if "--sandbox-self-test" in command:
            return local._ProcessResult(0, b"sandbox-ok", b"")  # noqa: SLF001
        assert command[1:] == ("--version",)
        return local._ProcessResult(0, b"tesseract 4.0.0\n", b"")  # noqa: SLF001

    with pytest.raises(local.LocalParserAttestationError, match="version mismatch"):
        local.GovernedLocalExtractionAdapter(
            maximum_bytes=4_096,
            sandbox=_sandbox(tmp_path),
            ocr=local.TesseractOCRConfig(
                executable=str(executable.resolve()),
                executable_sha256=digest,
                tesseract_version="5.4.1",
                traineddata_path=str(traineddata.resolve()),
                traineddata_sha256=hashlib.sha256(traineddata.read_bytes()).hexdigest(),
                runtime_library_paths=(str(runtime_library.resolve()),),
                runtime_libraries_sha256=local._manifest_sha256(  # noqa: SLF001
                    (runtime_library.resolve(),), "test runtime"
                ),
                pillow_version=importlib.metadata.version("Pillow"),
                pillow_manifest_sha256=local._distribution_manifest_sha256("Pillow"),  # noqa: SLF001
            ),
            _runner=wrong_version,
        )


def test_bounded_process_enforces_output_limit() -> None:
    with pytest.raises(local._OutputBoundExceeded):  # noqa: SLF001
        local._bounded_process(  # noqa: SLF001
            (sys.executable, "-I", "-c", "import sys;sys.stdout.write('x'*4096)"),
            timeout_seconds=5,
            max_stdout_bytes=1_024,
            max_memory_bytes=134_217_728,
        )


def test_enabled_worker_fails_closed_without_enforceable_platform(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A fresh container may lack the legacy-XLS toolchain; the adapter
    # correctly reports the dependency unavailable there, which is a
    # different (also-covered) failure mode than this test pins.
    pytest.importorskip("xlrd")
    pytest.importorskip("olefile")
    monkeypatch.setattr(local, "_network_sandbox_supported", lambda: False)
    with pytest.raises(local.LocalParserAttestationError, match="unsupported on this platform"):
        local.GovernedLocalExtractionAdapter(
            maximum_bytes=4_096,
            sandbox=_sandbox(tmp_path),
            legacy_xls=_xls_config(),
        )


def test_authority_identity_binds_inherited_base_parser() -> None:
    adapter = local.GovernedLocalExtractionAdapter(maximum_bytes=4_096)
    authority = adapter.authority(valid_until=1_900_000_000)
    assert adapter._implementation_components["base_parser_sha256"] == hashlib.sha256(  # noqa: SLF001
        Path(evidence.__file__).read_bytes()
    ).hexdigest()
    assert authority.implementation_sha256 == local._canonical_sha256(  # noqa: SLF001
        adapter._implementation_components  # noqa: SLF001
    )


def test_real_isolated_image_validator_is_exact_and_bounded() -> None:
    # Pillow ships in the reviewed CI environment (requirements/ci.txt);
    # a container without it must skip, not fail (test_oidc precedent).
    pytest.importorskip("PIL")
    result = local._bounded_process(  # noqa: SLF001
        (
            sys.executable,
            "-I",
            "-m",
            "maverick.ai_evidence_local_parsers",
            "--image-worker",
            "--pillow-version",
            importlib.metadata.version("Pillow"),
            "--pillow-manifest-sha256",
            local._distribution_manifest_sha256("Pillow"),  # noqa: SLF001
            "--media-type",
            evidence.MEDIA_PNG,
            "--max-pixels",
            "100",
            "--implementation-sha256",
            local._implementation_sha256(),  # noqa: SLF001
        ),
        input_bytes=_PNG,
        timeout_seconds=5,
        max_stdout_bytes=1_024,
        max_stderr_bytes=1_024,
        max_memory_bytes=134_217_728,
    )
    assert result == local._ProcessResult(0, b"ok", b"")  # noqa: SLF001

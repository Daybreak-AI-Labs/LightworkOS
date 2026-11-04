"""Confidential-compute detection: SEV-SNP / TDX guest indicators."""
from __future__ import annotations

from maverick.confidential_compute import detect


def _exists(present):
    s = set(present)
    return lambda p: p in s


def test_none_on_normal_hardware():
    rep = detect(exists=_exists([]), cpuinfo="flags : fpu vme de")
    assert rep == {"tdx": False, "sev_snp": False, "confidential": False,
                   "indicators": []}


def test_tdx_via_device():
    rep = detect(exists=_exists(["/dev/tdx_guest"]), cpuinfo="")
    assert rep["tdx"] is True and rep["confidential"] is True
    assert "/dev/tdx_guest" in rep["indicators"]


def test_tdx_via_cpuflag():
    rep = detect(exists=_exists([]), cpuinfo="flags : fpu tdx_guest sse")
    assert rep["tdx"] is True
    assert "cpuflag:tdx_guest" in rep["indicators"]


def test_sev_snp_via_device():
    rep = detect(exists=_exists(["/dev/sev-guest"]), cpuinfo="")
    assert rep["sev_snp"] is True and rep["confidential"] is True
    assert "/dev/sev-guest" in rep["indicators"]


def test_sev_cpuflags_are_not_guest_proof():
    rep = detect(exists=_exists([]), cpuinfo="flags : fpu sev sev_es sev_snp")
    assert rep == {"tdx": False, "sev_snp": False, "confidential": False,
                   "indicators": []}


def test_firmware_sysfs_tdx():
    rep = detect(exists=_exists(["/sys/firmware/tdx"]), cpuinfo="")
    assert rep["tdx"] is True


def test_cli_confidential_compute(monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main
    monkeypatch.setattr("maverick.confidential_compute.detect",
                        lambda: {"tdx": True, "sev_snp": False,
                                 "confidential": True, "indicators": ["/dev/tdx_guest"]})
    res = CliRunner().invoke(main, ["confidential-compute"])
    assert res.exit_code == 0 and "CONFIDENTIAL VM (Intel TDX)" in res.output


def test_cli_exits_nonzero_when_not_confidential(monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main
    monkeypatch.setattr("maverick.confidential_compute.detect",
                        lambda: {"tdx": False, "sev_snp": False,
                                 "confidential": False, "indicators": []})
    res = CliRunner().invoke(main, ["confidential-compute"])
    assert res.exit_code == 1 and "NOT a confidential VM" in res.output

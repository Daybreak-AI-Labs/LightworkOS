"""Confidential-compute detection.

Full confidential-compute *support* (remote attestation, memory-encryption
integration) needs the hardware and a deep platform integration. This is the
posture slice that pairs with the air-gap preflight: **detect** whether the
process is running inside a hardware confidential VM (AMD **SEV-SNP** or Intel
**TDX**), so a regulated deployment can verify — and `maverick
confidential-compute` can gate — that its memory is actually encrypted before
it trusts the box.

Reads standard guest indicators: the ``/dev/{tdx,sev}-guest`` attestation
devices, the TDX firmware sysfs entry, and the TDX guest CPU flag. AMD SEV
CPU capability flags are intentionally not treated as guest proof, because a
host or container can expose them without protecting this process as an SEV-SNP
guest. Path/cpuinfo access is injected so the detection is tested
deterministically without the hardware.
"""
from __future__ import annotations

import os
from pathlib import Path


def _cpu_flags(cpuinfo: str) -> set[str]:
    flags: set[str] = set()
    for line in (cpuinfo or "").splitlines():
        if line.lower().startswith("flags"):
            _, _, rest = line.partition(":")
            flags.update(rest.split())
    return flags


def detect(*, exists=None, cpuinfo: str | None = None) -> dict:
    """Detect a confidential VM. Returns ``{tdx, sev_snp, confidential,
    indicators}``."""
    exists = exists or os.path.exists
    if cpuinfo is None:
        try:
            cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8")
        except OSError:
            cpuinfo = ""
    flags = _cpu_flags(cpuinfo)

    indicators: list[str] = []
    tdx = False
    sev_snp = False
    if exists("/dev/tdx_guest"):
        tdx = True
        indicators.append("/dev/tdx_guest")
    if exists("/sys/firmware/tdx"):
        tdx = True
        indicators.append("/sys/firmware/tdx")
    if "tdx_guest" in flags:
        tdx = True
        indicators.append("cpuflag:tdx_guest")
    if exists("/dev/sev-guest"):
        sev_snp = True
        indicators.append("/dev/sev-guest")
    return {
        "tdx": tdx,
        "sev_snp": sev_snp,
        "confidential": tdx or sev_snp,
        "indicators": indicators,
    }


__all__ = ["detect"]

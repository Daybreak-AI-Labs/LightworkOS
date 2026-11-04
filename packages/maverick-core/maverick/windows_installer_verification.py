"""Independent verification of retained customer MSI bytes before maintenance."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

from . import file_lock

MAX_INSTALLER_BYTES = 1024 * 1024 * 1024
UPGRADE_CODE = "AB5BC260-7EC9-4B70-AF78-28F4067BC530"
_INSPECT = r"""param([Parameter(Mandatory=$true)][string]$Installer)
$ErrorActionPreference = 'Stop'
$signature = Get-AuthenticodeSignature -LiteralPath $Installer
if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate) { throw 'The publisher signature is not trusted.' }
$engine = New-Object -ComObject WindowsInstaller.Installer
$database = $engine.OpenDatabase($Installer, 0)
$properties = @{}
foreach ($name in @('ProductVersion', 'ProductCode', 'UpgradeCode')) {
    $query = 'SELECT `Value` FROM `Property` WHERE `Property` = ''' + $name + ''''
    $view = $database.OpenView($query)
    $view.Execute()
    $record = $view.Fetch()
    if (-not $record) { throw 'A required installer property is missing.' }
    $properties[$name] = $record.StringData(1)
    $view.Close()
}
$summary = $database.SummaryInformation(0)
$properties['PackageCode'] = $summary.Property(9)
$properties['PublisherThumbprint'] = $signature.SignerCertificate.Thumbprint
$properties | ConvertTo-Json -Compress
"""


class InstallerVerificationError(RuntimeError):
    """No installer execution is permitted after verification failure."""


def _envelope_lines(value: str) -> list[str]:
    # Rust str::lines recognizes LF/CRLF, not Unicode separators that may be
    # part of a signed filename. Preserve the exact UTF-8 trusted comment.
    lines = base64.b64decode(value, validate=True).decode("utf-8").split("\n")
    if lines[-1] == "":
        lines.pop()
    return [line.removesuffix("\r") for line in lines]


def verify_minisign(path: Path, public_key: str, signature: str) -> str:
    """Verify Tauri's Minisign envelope, including its trusted-comment signature.

    Implements the encoded contract used by minisign-verify 0.2.5: Ed25519
    over message or BLAKE2b-512 digest, and over signature || trusted comment.
    Cryptographic primitives come from cryptography, not local implementations.
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    file_lock.ensure_private_file(path)
    if path.stat().st_size > MAX_INSTALLER_BYTES:
        raise InstallerVerificationError("The installer exceeds the maintenance size limit.")
    try:
        if len(public_key) > 4096 or len(signature) > 16384:
            raise ValueError("envelope too large")
        key_lines = _envelope_lines(public_key)
        sig_lines = _envelope_lines(signature)
        if len(key_lines) != 2 or len(sig_lines) != 4 or not sig_lines[2].startswith("trusted comment: "):
            raise ValueError("invalid envelope")
        key = base64.b64decode(key_lines[1], validate=True)
        signed = base64.b64decode(sig_lines[1], validate=True)
        global_signature = base64.b64decode(sig_lines[3], validate=True)
        if (len(key) != 42 or key[:2] not in {b"Ed", b"ED"} or len(signed) != 74
                or signed[:2] not in {b"Ed", b"ED"} or len(global_signature) != 64 or key[2:10] != signed[2:10]):
            raise ValueError("invalid signature metadata")
        verifier = Ed25519PublicKey.from_public_bytes(key[10:])
        if signed[:2] == b"ED":
            digest = hashlib.blake2b(digest_size=64)
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            message = digest.digest()
        else:
            message = path.read_bytes()
        verifier.verify(signed[10:], message)
        verifier.verify(global_signature, signed[10:] + sig_lines[2][17:].encode("utf-8"))
    except (ValueError, UnicodeError, InvalidSignature) as exc:
        raise InstallerVerificationError("The retained installer release signature did not verify.") from exc
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def installer_path(path: Path) -> str:
    """MSI/PowerShell process arguments use bounded ordinary Win32 paths.

    Workspace payload IO supports extended paths, but the Windows Installer
    COM engine does not promise that contract for package/log arguments.
    Refuse an unsupported install location before any MSI transaction starts.
    """
    text = str(path.absolute())
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("\\\\?\\"):
        text = text[4:]
    if len(text) >= 240 or text.startswith("\\\\") or any(char in text for char in ('"', '\r', '\n')):
        raise InstallerVerificationError("This installer location is outside the supported local Windows path limit. Use the administrator's coordinated recovery process.")
    return text


def inspect_signed_msi(path: Path, *, version: str, scratch: Path) -> dict:
    """Use Windows' trust and MSI engines; never execute installer actions."""
    if os.name != "nt":
        raise InstallerVerificationError("Customer installer verification requires Windows.")
    file_lock.ensure_private_directory(scratch)
    script = scratch / "inspect-installer.ps1"
    if script.exists():
        if file_lock.atomic_read_text(script) != _INSPECT:
            raise InstallerVerificationError("The retained installer inspection helper changed.")
    else:
        file_lock.atomic_create_text(script, _INSPECT)
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    command = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    # Python preserves PowerShell 7's module paths when launching Windows
    # PowerShell 5. Its incompatible Security module then prevents the actual
    # signature cmdlet from loading. Use only OS modules in this child; retain
    # the parent's environment and all Windows signature/product checks.
    environment = {name: value for name, value in os.environ.items() if name.lower() != "psmodulepath"}
    environment["PSModulePath"] = str(command.parent / "Modules")
    result = subprocess.run([str(command), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                             "-File", installer_path(script), "-Installer", installer_path(path)],
                            capture_output=True, text=True, timeout=120,
                            creationflags=subprocess.CREATE_NO_WINDOW, check=False, env=environment)
    try:
        properties = (
            json.loads(result.stdout)
            if result.returncode == 0 and len(result.stdout) <= 16384
            else {}
        )
        guid = r"\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}"
        if (properties.get("ProductVersion") != version
                or str(properties.get("UpgradeCode", "")).strip("{}").upper() != UPGRADE_CODE
                or not re.fullmatch(guid, properties.get("ProductCode", ""))
                or not re.fullmatch(guid, properties.get("PackageCode", ""))
                or not re.fullmatch(r"[0-9A-Fa-f]{40}", properties.get("PublisherThumbprint", ""))):
            raise ValueError("unmatched package")
    except (ValueError, TypeError, AttributeError) as exc:
        raise InstallerVerificationError("The installer publisher, product or version could not be verified.") from exc
    return properties

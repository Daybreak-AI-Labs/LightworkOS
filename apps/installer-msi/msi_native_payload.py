"""Hash the exact customer native payload without installing or executing an MSI.

Tauri patches its package-type marker while bundling, then restores the build
output. The restored executable is therefore not the identity shipped in MSI.
Only the Windows Installer database read API and cabinet decompression are used.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path

IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,71}\Z")
MAX_NATIVE_BYTES = 128 * 1024 * 1024


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Database:
    """Read-only MSI handles. No install, configure, or custom-action API."""

    def __init__(self, path: Path):
        self.dll = ctypes.WinDLL(str(Path(os.environ["SystemRoot"]) / "System32/msi.dll"))
        uint, ptr = ctypes.c_uint, ctypes.POINTER
        signatures = {
            "MsiOpenDatabaseW": [ctypes.c_wchar_p, ctypes.c_void_p, ptr(uint)],
            "MsiDatabaseOpenViewW": [uint, ctypes.c_wchar_p, ptr(uint)],
            "MsiViewExecute": [uint, uint], "MsiViewFetch": [uint, ptr(uint)],
            "MsiRecordGetStringW": [uint, uint, ctypes.c_wchar_p, ptr(uint)],
            "MsiRecordReadStream": [uint, uint, ctypes.c_void_p, ptr(uint)],
            "MsiCloseHandle": [uint],
        }
        for name, arguments in signatures.items():
            function = getattr(self.dll, name)
            function.argtypes, function.restype = arguments, uint
        self.handle = uint()
        self.check(self.dll.MsiOpenDatabaseW(str(path), None, ctypes.byref(self.handle)))

    @staticmethod
    def check(code):
        if code:
            raise RuntimeError(f"Read-only MSI database operation failed ({code}).")

    def close(self):
        self.dll.MsiCloseHandle(self.handle)

    @contextmanager
    def records(self, query):
        view, retained = ctypes.c_uint(), []
        self.check(self.dll.MsiDatabaseOpenViewW(self.handle, query, ctypes.byref(view)))
        try:
            self.check(self.dll.MsiViewExecute(view, 0))
            while True:
                record = ctypes.c_uint()
                code = self.dll.MsiViewFetch(view, ctypes.byref(record))
                if code == 259:  # ERROR_NO_MORE_ITEMS
                    break
                self.check(code)
                retained.append(record)
                if len(retained) > 10000:
                    raise RuntimeError("MSI payload table exceeds the fixture bound.")
            yield retained
        finally:
            for record in retained:
                self.dll.MsiCloseHandle(record)
            self.dll.MsiCloseHandle(view)

    def text(self, record, field):
        size = ctypes.c_uint(4096)
        buffer = ctypes.create_unicode_buffer(size.value)
        self.check(self.dll.MsiRecordGetStringW(record, field, buffer, ctypes.byref(size)))
        return buffer.value

    def rows(self, query, fields):
        with self.records(query) as records:
            return [tuple(self.text(record, field) for field in range(1, fields + 1)) for record in records]

    def cabinet(self, name, output, maximum):
        with self.records(f"SELECT `Data` FROM `_Streams` WHERE `Name` = '{name}'") as records:
            if len(records) != 1:
                raise RuntimeError("The native payload needs one embedded cabinet stream.")
            total, buffer = 0, ctypes.create_string_buffer(1024 * 1024)
            with output.open("xb") as stream:
                while True:
                    size = ctypes.c_uint(len(buffer))
                    self.check(self.dll.MsiRecordReadStream(records[0], 1, buffer, ctypes.byref(size)))
                    if not size.value:
                        break
                    total += size.value
                    if total > maximum:
                        raise RuntimeError("Embedded cabinet exceeds its source MSI size.")
                    stream.write(buffer.raw[:size.value])


def select_payload(files, components, media):
    matches = [row for row in files if row[2].split("|")[-1] == "maverick-desktop.exe"]
    if len(matches) != 1:
        raise RuntimeError("Expected exactly one customer native executable in the MSI.")
    identifier, component, _, size, sequence = matches[0]
    if not IDENTIFIER.fullmatch(identifier) or not IDENTIFIER.fullmatch(component):
        raise RuntimeError("Unsafe native payload identifier.")
    if [row[1] for row in components if row[0] == component] != ["INSTALLDIR"]:
        raise RuntimeError("The native MSI payload must belong directly to INSTALLDIR.")
    size, sequence = int(size), int(sequence)
    if not 0 < size <= MAX_NATIVE_BYTES or sequence <= 0:
        raise RuntimeError("Native MSI payload size or sequence is outside the fixture bound.")
    eligible = sorted((int(last), cabinet) for last, cabinet in media if int(last) >= sequence)
    if not eligible or eligible[0][0] <= 0:
        raise RuntimeError("No cabinet contains the native MSI payload.")
    cabinet = eligible[0][1]
    if not cabinet.startswith("#") or not IDENTIFIER.fullmatch(cabinet[1:]):
        raise RuntimeError("The native MSI payload must use a safe embedded cabinet.")
    return identifier, size, cabinet[1:]


def inspect_payload(msi: Path) -> dict:
    if os.name != "nt":
        raise RuntimeError("Read-only MSI payload inspection requires Windows.")
    msi = msi.resolve(strict=True)
    original = file_hash(msi)
    database = Database(msi)
    try:
        selected = select_payload(
            database.rows("SELECT `File`, `Component_`, `FileName`, `FileSize`, `Sequence` FROM `File`", 5),
            database.rows("SELECT `Component`, `Directory_` FROM `Component`", 2),
            database.rows("SELECT `LastSequence`, `Cabinet` FROM `Media`", 2),
        )
        identifier, size, cabinet_name = selected
        with tempfile.TemporaryDirectory(prefix="lightwork-msi-payload-") as temporary:
            root = Path(temporary)
            cabinet, expanded = root / "payload.cab", root / "expanded"
            expanded.mkdir()
            database.cabinet(cabinet_name, cabinet, msi.stat().st_size)
            expand = Path(os.environ["SystemRoot"]) / "System32/expand.exe"
            subprocess.run([str(expand), "-R", str(cabinet), "-F:" + identifier, str(expanded)],
                           check=True, capture_output=True, timeout=120)
            payload = expanded / identifier
            if list(expanded.iterdir()) != [payload] or not payload.is_file() or payload.stat().st_size != size:
                raise RuntimeError("Expanded native payload does not match the MSI file table.")
            native_hash = file_hash(payload)
    finally:
        database.close()
    if file_hash(msi) != original:
        raise RuntimeError("The MSI changed during read-only payload inspection.")
    return {"schema": "lightwork.msi-native-payload.v1", "msi_sha256": original,
            "native_sha256": native_hash, "native_bytes": size, "file_id": identifier}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--msi", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    args.report.write_text(json.dumps(inspect_payload(args.msi), indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()

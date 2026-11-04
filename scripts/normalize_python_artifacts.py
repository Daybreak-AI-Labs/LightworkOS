#!/usr/bin/env python3
"""Normalize wheel and sdist container metadata for reproducible releases."""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import gzip
import io
import os
import tarfile
import tempfile
import zipfile
from pathlib import Path


def _zip_timestamp(epoch: int) -> tuple[int, int, int, int, int, int]:
    value = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc)
    if value.year < 1980:
        value = value.replace(year=1980, month=1, day=1, hour=0, minute=0, second=0)
    return (
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second - (value.second % 2),
    )


def normalize_wheel(path: Path, *, epoch: int) -> None:
    """Repack a wheel with stable order, timestamps, modes, and ZIP metadata."""
    with zipfile.ZipFile(path, "r") as source:
        entries = [
            (copy.copy(info), source.read(info))
            for info in sorted(source.infolist(), key=lambda item: item.filename)
        ]

    temporary = _temporary_sibling(path)
    try:
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            strict_timestamps=True,
        ) as target:
            for original, payload in entries:
                info = zipfile.ZipInfo(original.filename, _zip_timestamp(epoch))
                info.compress_type = original.compress_type
                info.create_system = original.create_system
                info.external_attr = original.external_attr
                info.internal_attr = original.internal_attr
                info.flag_bits = original.flag_bits & 0x800
                info.comment = original.comment
                target.writestr(info, payload, compresslevel=9)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def normalize_sdist(path: Path, *, epoch: int) -> None:
    """Repack a ``.tar.gz`` sdist without wall-clock or host identity metadata."""
    with tarfile.open(path, "r:gz") as source:
        entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
        for original in sorted(source.getmembers(), key=lambda item: item.name):
            payload_file = source.extractfile(original) if original.isfile() else None
            payload = payload_file.read() if payload_file is not None else None
            info = copy.copy(original)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = epoch
            info.pax_headers = {
                key: value
                for key, value in original.pax_headers.items()
                if key not in {"atime", "ctime", "mtime"}
            }
            entries.append((info, payload))

    temporary = _temporary_sibling(path)
    try:
        with temporary.open("wb") as raw:
            with gzip.GzipFile(
                filename="",
                mode="wb",
                compresslevel=9,
                fileobj=raw,
                mtime=epoch,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                ) as target:
                    for info, payload in entries:
                        target.addfile(
                            info,
                            io.BytesIO(payload) if payload is not None else None,
                        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _temporary_sibling(path: Path) -> Path:
    descriptor, raw_path = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    os.close(descriptor)
    return Path(raw_path)


def normalize(path: Path, *, epoch: int) -> None:
    if path.suffix == ".whl":
        normalize_wheel(path, epoch=epoch)
    elif path.name.endswith(".tar.gz"):
        normalize_sdist(path, epoch=epoch)
    else:
        raise ValueError(f"unsupported Python release artifact: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        required=True,
        help="UTC timestamp used for every archive member",
    )
    parser.add_argument("artifacts", nargs="+", type=Path)
    args = parser.parse_args()
    for artifact in args.artifacts:
        normalize(artifact, epoch=args.source_date_epoch)
        print(f"normalized {artifact}")


if __name__ == "__main__":
    main()

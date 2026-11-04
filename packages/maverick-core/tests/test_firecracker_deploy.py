"""Firecracker backend: the kernel/rootfs guidance points at real build scripts.

The backend tells operators to build the microVM kernel + rootfs with the
scripts under ``deploy/firecracker/``. These tests lock that those scripts
exist and that the backend's missing-artifact error sends operators to them.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[3]
_DEPLOY = _REPO / "deploy" / "firecracker"


class TestDeployArtifactsExist:
    @pytest.mark.parametrize("name", ["README.md", "fetch-kernel.sh", "build-rootfs.sh"])
    def test_artifact_present(self, name):
        assert (_DEPLOY / name).is_file(), f"missing deploy/firecracker/{name}"

    def test_scripts_are_executable(self):
        for s in ("fetch-kernel.sh", "build-rootfs.sh"):
            assert os.access(_DEPLOY / s, os.X_OK), f"{s} is not executable"

    def test_scripts_target_the_convention_path(self):
        # The backend reads ~/.maverick/firecracker/{kernel,rootfs}.img; the
        # build scripts must write there so the two halves line up.
        assert "firecracker/kernel.img" in (_DEPLOY / "fetch-kernel.sh").read_text()
        assert "firecracker/rootfs.img" in (_DEPLOY / "build-rootfs.sh").read_text()


class TestMissingKernelGuidance:
    def test_error_points_to_build_scripts(self, tmp_path, monkeypatch):
        # Pretend firecracker + firectl are installed so we reach _firectl, but
        # provide no kernel/rootfs -> the helpful build guidance must fire.
        import maverick.sandbox.firecracker as fc
        monkeypatch.setattr(fc.shutil, "which", lambda name: f"/usr/bin/{name}")
        monkeypatch.setattr(fc, "data_dir",
                            lambda *p: tmp_path.joinpath(*p))
        be = fc.FirecrackerBackend(workdir=tmp_path, provider="local")
        res = be.exec("echo hi")
        assert res.exit_code == 127
        assert "fetch-kernel.sh" in res.stderr
        assert "build-rootfs.sh" in res.stderr


@pytest.mark.skipif(
    os.name == "nt",
    reason="Firecracker deployment scripts require a POSIX shell",
)
class TestFirecrackerArtifactIntegrity:
    def test_fetch_kernel_requires_sha256(self, tmp_path):
        import subprocess

        source = tmp_path / "kernel.bin"
        dest = tmp_path / "kernel.img"
        source.write_bytes(b"kernel")
        result = subprocess.run(
            [str(_DEPLOY / "fetch-kernel.sh")],
            env={
                **os.environ,
                "KERNEL_URL": source.as_uri(),
                "DEST": str(dest),
            },
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 2
        assert "KERNEL_SHA256 is required" in result.stderr
        assert not dest.exists()

    def test_fetch_kernel_rejects_sha256_mismatch(self, tmp_path):
        import subprocess

        source = tmp_path / "kernel.bin"
        dest = tmp_path / "kernel.img"
        source.write_bytes(b"kernel")
        result = subprocess.run(
            [str(_DEPLOY / "fetch-kernel.sh")],
            env={
                **os.environ,
                "KERNEL_URL": source.as_uri(),
                "KERNEL_SHA256": "0" * 64,
                "DEST": str(dest),
            },
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 1
        assert "kernel SHA-256 mismatch" in result.stderr
        assert not dest.exists()

    def test_fetch_kernel_installs_matching_sha256(self, tmp_path):
        import hashlib
        import subprocess

        source = tmp_path / "kernel.bin"
        dest = tmp_path / "kernel.img"
        source.write_bytes(b"kernel")
        digest = hashlib.sha256(source.read_bytes()).hexdigest()
        result = subprocess.run(
            [str(_DEPLOY / "fetch-kernel.sh")],
            env={
                **os.environ,
                "KERNEL_URL": source.as_uri(),
                "KERNEL_SHA256": digest,
                "DEST": str(dest),
            },
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert dest.read_bytes() == source.read_bytes()

    @pytest.mark.parametrize("image", ["", "ubuntu:24.04", "ubuntu@sha256:not-hex"])
    def test_build_rootfs_requires_digest_pinned_image(self, image):
        import subprocess

        env = {**os.environ}
        if image:
            env["IMAGE"] = image
        else:
            env.pop("IMAGE", None)
        result = subprocess.run(
            [str(_DEPLOY / "build-rootfs.sh")],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode == 2
        assert "IMAGE" in result.stderr

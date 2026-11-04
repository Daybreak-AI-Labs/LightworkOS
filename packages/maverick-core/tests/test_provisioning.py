"""Headless provisioning (`init --from-file`) + the runtime-protoc
opt-out for immutable/locked-down images."""
from __future__ import annotations

import pytest
from maverick import grpc_stubs
from maverick.file_lock import private_path_is_restricted

# ---- runtime-protoc opt-out -----------------------------------------------


def test_runtime_protoc_disabled_env(monkeypatch):
    monkeypatch.setenv("MAVERICK_NO_RUNTIME_PROTOC", "1")
    assert grpc_stubs.runtime_protoc_disabled() is True
    monkeypatch.setenv("MAVERICK_NO_RUNTIME_PROTOC", "0")
    assert grpc_stubs.runtime_protoc_disabled() is False


def test_guard_raises_when_disabled(monkeypatch):
    monkeypatch.setenv("MAVERICK_NO_RUNTIME_PROTOC", "1")
    with pytest.raises(RuntimeError, match="gen-stubs"):
        grpc_stubs.guard_runtime_generation("federation.proto")


def test_guard_noop_when_enabled(monkeypatch):
    monkeypatch.delenv("MAVERICK_NO_RUNTIME_PROTOC", raising=False)
    assert grpc_stubs.guard_runtime_generation("maverick.proto") is None


def test_cli_gen_stubs(monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main
    monkeypatch.setattr(grpc_stubs, "generate_all",
                        lambda: ["maverick.proto", "federation.proto"])
    r = CliRunner().invoke(main, ["gen-stubs"])
    assert r.exit_code == 0 and "maverick.proto" in r.output


# ---- headless provisioning -------------------------------------------------


def test_init_from_file_installs(monkeypatch, tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main
    src = tmp_path / "client.toml"
    src.write_text('[client]\nid = "acme-corp"\nenforce = true\n')
    dst = tmp_path / "installed" / "config.toml"
    monkeypatch.setenv("MAVERICK_CONFIG", str(dst))

    r = CliRunner().invoke(main, ["init", "--from-file", str(src)])
    assert r.exit_code == 0 and "installed config" in r.output
    assert dst.read_text() == src.read_text()
    assert private_path_is_restricted(dst, 0o600)
    assert private_path_is_restricted(dst.parent, 0o700)


def test_init_from_file_is_idempotent(monkeypatch, tmp_path):
    """A deployment retry with identical bytes must not republish config."""
    import maverick.file_lock as file_lock
    from click.testing import CliRunner
    from maverick.cli import main

    body = '[client]\nid = "acme-corp"\nenforce = true\n'
    src = tmp_path / "client.toml"
    src.write_text(body, encoding="utf-8")
    dst = tmp_path / "installed" / "config.toml"
    dst.parent.mkdir()
    dst.write_text(body, encoding="utf-8")
    file_lock.harden_path_permissions(dst, 0o600)
    monkeypatch.setenv("MAVERICK_CONFIG", str(dst))

    def unexpected_write(*_args, **_kwargs):
        raise AssertionError("identical config must not be republished")

    monkeypatch.setattr(file_lock, "atomic_write_bytes", unexpected_write)
    result = CliRunner().invoke(main, ["init", "--from-file", str(src)])

    assert result.exit_code == 0, result.output
    assert "config unchanged" in result.output
    assert dst.read_text(encoding="utf-8") == body
    assert private_path_is_restricted(dst, 0o600)


def test_init_from_file_line_endings_are_idempotent(monkeypatch, tmp_path):
    """A Windows/Unix line-ending change must not republish logical TOML."""
    import maverick.file_lock as file_lock
    from click.testing import CliRunner
    from maverick.cli import main

    body = '[client]\nid = "acme-corp"\nenforce = true\n'
    src = tmp_path / "client.toml"
    src.write_bytes(body.encode("utf-8"))
    dst = tmp_path / "installed" / "config.toml"
    dst.parent.mkdir()
    installed = body.replace("\n", "\r\n").encode("utf-8")
    dst.write_bytes(installed)
    file_lock.harden_path_permissions(dst, 0o600)
    monkeypatch.setenv("MAVERICK_CONFIG", str(dst))

    def unexpected_write(*_args, **_kwargs):
        raise AssertionError("line endings must not republish logical TOML")

    monkeypatch.setattr(file_lock, "atomic_write_bytes", unexpected_write)
    result = CliRunner().invoke(main, ["init", "--from-file", str(src)])

    assert result.exit_code == 0, result.output
    assert "config unchanged" in result.output
    assert dst.read_bytes() == installed
    assert private_path_is_restricted(dst, 0o600)


def test_init_from_file_is_0600_at_creation_not_world_readable(monkeypatch, tmp_path):
    """The config temp must have private custody before any key byte is written.

    The old shutil.copyfile path created the file world-readable (0644 & ~umask)
    and only chmod'd it AFTER the whole body -- which can carry inline provider
    api_keys -- was on disk. POSIX mode-at-creation alone does not establish a
    protected Windows DACL, so verify the shared secure creator directly."""
    import os

    import maverick.file_lock as file_lock
    from click.testing import CliRunner
    from maverick.cli import main

    src = tmp_path / "prod.toml"
    src.write_text(
        '[providers.anthropic]\n'
        'api_key = "sk-do-not-leak"  # pragma: allowlist secret\n'
    )
    dst = tmp_path / "installed" / "config.toml"
    monkeypatch.setenv("MAVERICK_CONFIG", str(dst))

    seen: list[tuple[int, bool, int]] = []
    real_create = file_lock._secure_mkstemp

    def spy_create(directory, *, prefix, suffix, mode):
        fd, temp_path = real_create(
            directory,
            prefix=prefix,
            suffix=suffix,
            mode=mode,
        )
        if directory == dst.parent and prefix.startswith(".config.toml-"):
            seen.append(
                (
                    mode,
                    file_lock.private_path_is_restricted(temp_path, mode),
                    os.stat(temp_path).st_size,
                )
            )
        return fd, temp_path

    monkeypatch.setattr(file_lock, "_secure_mkstemp", spy_create)
    old_umask = os.umask(0)
    try:
        r = CliRunner().invoke(main, ["init", "--from-file", str(src)])
    finally:
        os.umask(old_umask)

    assert r.exit_code == 0
    assert seen == [(0o600, True, 0)]
    assert private_path_is_restricted(dst, 0o600)
    assert dst.read_text() == src.read_text()
    assert private_path_is_restricted(dst.parent, 0o700)


def test_init_from_file_missing(monkeypatch, tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "out.toml"))
    r = CliRunner().invoke(main, ["init", "--from-file", str(tmp_path / "nope.toml")])
    assert r.exit_code != 0


def test_init_from_file_bad_toml(monkeypatch, tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main
    bad = tmp_path / "bad.toml"
    bad.write_text("this is = = not toml")
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "out.toml"))
    r = CliRunner().invoke(main, ["init", "--from-file", str(bad)])
    assert r.exit_code != 0 and "invalid TOML" in r.output


@pytest.mark.parametrize("body", [
    '[budgets]\nx = 1\n',
    '[budget]\nmax_dollarss = 50\n',
    '[budget]\nmax_dollars = "unlimited"\n',
])
def test_init_from_file_rejects_unusable_settings_without_replacing_old(
    monkeypatch, tmp_path, body,
):
    from click.testing import CliRunner
    from maverick.cli import main

    src = tmp_path / "new.toml"
    src.write_text(body, encoding="utf-8")
    dst = tmp_path / "installed" / "config.toml"
    dst.parent.mkdir()
    old = b'[budget]\nmax_dollars = 20\n'
    dst.write_bytes(old)
    monkeypatch.setenv("MAVERICK_CONFIG", str(dst))

    result = CliRunner().invoke(main, ["init", "--from-file", str(src)])

    assert result.exit_code != 0
    assert "no changes were made" in result.output
    assert dst.read_bytes() == old
    assert not list(dst.parent.glob("config.toml.bak-*"))


def test_init_from_file_preserves_private_backup_before_replacing(monkeypatch, tmp_path):
    from click.testing import CliRunner
    from maverick.cli import main

    src = tmp_path / "new.toml"
    src.write_bytes(b'[budget]\nmax_dollars = 50\n')
    dst = tmp_path / "installed" / "config.toml"
    dst.parent.mkdir()
    old = b'[budget]\nmax_dollars = 20\n'
    dst.write_bytes(old)
    monkeypatch.setenv("MAVERICK_CONFIG", str(dst))

    result = CliRunner().invoke(main, ["init", "--from-file", str(src)])

    assert result.exit_code == 0, result.output
    assert dst.read_bytes() == src.read_bytes()
    backups = list(dst.parent.glob("config.toml.bak-*"))
    assert len(backups) == 1 and backups[0].read_bytes() == old
    assert private_path_is_restricted(backups[0], 0o600)
    assert str(backups[0]) in result.output


@pytest.mark.parametrize("fail_when", ["backup", "replace"])
def test_init_from_file_write_failure_leaves_previous_settings(
    monkeypatch, tmp_path, fail_when,
):
    import maverick.file_lock as file_lock
    from click.testing import CliRunner
    from maverick.cli import main

    src = tmp_path / "new.toml"
    src.write_bytes(b'[budget]\nmax_dollars = 50\n')
    dst = tmp_path / "installed" / "config.toml"
    dst.parent.mkdir()
    old = b'[budget]\nmax_dollars = 20\n'
    dst.write_bytes(old)
    monkeypatch.setenv("MAVERICK_CONFIG", str(dst))
    original_write = file_lock.atomic_write_bytes

    def interrupted_write(path, data, *, mode):
        if (path == dst) == (fail_when == "replace"):
            raise OSError("simulated write failure")
        return original_write(path, data, mode=mode)

    monkeypatch.setattr(file_lock, "atomic_write_bytes", interrupted_write)
    result = CliRunner().invoke(main, ["init", "--from-file", str(src)])

    assert result.exit_code != 0 and "previous file remains" in result.output
    assert dst.read_bytes() == old
    backups = list(dst.parent.glob("config.toml.bak-*"))
    assert len(backups) == (fail_when == "replace")
    if backups:
        assert backups[0].read_bytes() == old

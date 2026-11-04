"""Config reads recover from private publication without losing policy health."""
from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest
from maverick import config, file_lock


@pytest.fixture
def configuration(tmp_path, monkeypatch):
    path = tmp_path / "config.toml"
    monkeypatch.setenv("MAVERICK_CONFIG", str(path))
    config.reset_config_cache()
    try:
        yield path
    finally:
        config.reset_config_cache()


@pytest.mark.skipif(os.name != "nt", reason="native Windows private-handle publication")
def test_config_retries_real_published_handle_until_writer_closes(configuration, monkeypatch):
    published = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    errors = []
    denials = []
    original_publish = file_lock._publish_new_private_temp
    original_read = Path.read_bytes

    def hold_after_publish(fd, tmp, path):
        original_publish(fd, tmp, path)
        published.set()
        assert release.wait(5), "reader never reached the native publication window"

    def observe_native_read(path):
        try:
            return original_read(path)
        except PermissionError:
            if file_lock._windows_extended_path(path) == file_lock._windows_extended_path(configuration):
                denials.append(True)
                release.set()
                assert finished.wait(5), "private writer did not close"
            raise

    def write():
        try:
            file_lock.atomic_create_text(configuration, "[budget]\nmax_dollars = 1.0\n")
        except BaseException as exc:
            errors.append(exc)
        finally:
            finished.set()

    monkeypatch.setattr(file_lock, "_publish_new_private_temp", hold_after_publish)
    monkeypatch.setattr(Path, "read_bytes", observe_native_read)
    writer = threading.Thread(target=write)
    writer.start()
    try:
        assert published.wait(5), "private file was not published"
        assert config.load_config()["budget"]["max_dollars"] == 1.0
        assert not config.config_source_errors()
    finally:
        release.set()
        writer.join(5)
    assert not writer.is_alive()
    assert not errors
    assert denials, "test must observe an actual OS sharing denial"
    assert file_lock.private_path_is_restricted(configuration)
    before = configuration.read_bytes()
    assert before == "[budget]\nmax_dollars = 1.0\n".replace("\n", os.linesep).encode()
    with pytest.raises(FileExistsError):
        file_lock.atomic_create_text(configuration, "replace = true\n")
    assert configuration.read_bytes() == before


@pytest.mark.parametrize("failure", [PermissionError, OSError])
def test_exhausted_io_error_recovers_without_metadata_change(configuration, monkeypatch, failure):
    configuration.write_bytes(b"[budget]\nmax_dollars = 1.0\n")
    before = configuration.stat()
    read = config.atomic_read_bytes

    def denied(path):
        raise failure("bounded read failed")

    monkeypatch.setattr(config, "atomic_read_bytes", denied)
    assert config.load_config() == {}
    assert str(configuration) in config.config_source_errors()
    assert str(configuration) not in config._toml_cache

    monkeypatch.setattr(config, "atomic_read_bytes", read)
    assert config.load_config()["budget"]["max_dollars"] == 1.0
    assert not config.config_source_errors()
    after = configuration.stat()
    assert (after.st_mtime_ns, after.st_size) == (before.st_mtime_ns, before.st_size)


def test_permanent_io_denial_remains_unhealthy_on_every_read(configuration, monkeypatch):
    configuration.write_bytes(b"[dashboard]\nrequire_auth = true\n")
    attempts = []

    def denied(path):
        attempts.append(path)
        raise PermissionError("unreadable policy")

    monkeypatch.setattr(config, "atomic_read_bytes", denied)
    for _ in range(2):
        assert config.load_config() == {}
        assert "PermissionError" in config.config_source_errors()[str(configuration)]
        assert str(configuration) not in config._toml_cache
    assert attempts == [configuration, configuration]


@pytest.mark.parametrize("content", [b"[incomplete\n", b"\xff"])
def test_malformed_content_stays_cached_and_unhealthy(configuration, monkeypatch, content):
    configuration.write_bytes(content)
    assert config.load_config() == {}
    assert str(configuration) in config.config_source_errors()

    def unexpected_read(path):
        pytest.fail("unchanged malformed content should retain its cached error")

    monkeypatch.setattr(config, "atomic_read_bytes", unexpected_read)
    assert config.load_config() == {}
    assert str(configuration) in config.config_source_errors()

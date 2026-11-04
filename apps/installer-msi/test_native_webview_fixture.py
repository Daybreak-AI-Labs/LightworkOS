"""Safe native-fixture infrastructure tests: temporary files/TLS, no host trust or MSI."""
from __future__ import annotations

import hashlib
import http.client
import importlib.util
import io
import json
import socket
import ssl
import subprocess
import zipfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID

_SPEC = importlib.util.spec_from_file_location('native_webview_fixture', Path(__file__).with_name('native_webview_fixture.py'))
fixture = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(fixture)


def packages(tmp_path):
    base, candidate = tmp_path / 'base.msi', tmp_path / 'next.msi'
    base.write_bytes(b'synthetic base package; never installed')
    candidate.write_bytes(b'synthetic next package; never installed')
    Path(str(base) + '.sig').write_text('synthetic-base-signature', encoding='utf-8')
    Path(str(candidate) + '.sig').write_text('synthetic-next-signature', encoding='utf-8')
    return base, candidate, {'version': '1.2.3', 'runtime': {'sha256': 'a' * 64}}


def tls_get(port, root, path, *, hostname=fixture.HOST):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=root.public_bytes(serialization.Encoding.PEM).decode())
    with socket.create_connection(('127.0.0.1', port), timeout=5) as plain:
        with context.wrap_socket(plain, server_hostname=hostname) as stream:
            stream.sendall(f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n'.encode('ascii'))
            response = http.client.HTTPResponse(stream)
            response.begin()
            return response.status, dict(response.headers), response.read()


def test_tls_uses_a_distinct_server_leaf_compatible_with_native_rustls(tmp_path):
    thumbprint = fixture.make_tls(tmp_path)
    root = x509.load_der_x509_certificate((tmp_path / 'tls.cer').read_bytes())
    leaf = x509.load_pem_x509_certificate((tmp_path / 'tls.pem').read_bytes())
    key = serialization.load_pem_private_key((tmp_path / 'tls.key').read_bytes(), password=None)
    assert thumbprint == root.fingerprint(hashes.SHA1()).hex()
    assert root.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    # rustls-webpki refuses a CA certificate as the TLS end entity. An OpenSSL
    # handshake alone does not establish this native-client compatibility.
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert root.fingerprint(hashes.SHA256()) != leaf.fingerprint(hashes.SHA256())
    assert leaf.issuer == root.subject
    assert leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName) == [fixture.HOST]
    assert ExtendedKeyUsageOID.SERVER_AUTH in leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) == leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def test_real_loopback_tls_serves_only_reviewed_manifests_and_packages_and_rejects_wrong_identity(tmp_path):
    fixture.make_tls(tmp_path)
    root = x509.load_der_x509_certificate((tmp_path / 'tls.cer').read_bytes())
    base, candidate, metadata = packages(tmp_path)
    with fixture.update_server(tmp_path, base, candidate, metadata, port=0) as (requests, port):
        status, headers, body = tls_get(port, root, '/latest.json')
        assert status == 200 and headers['Content-Type'] == 'application/json'
        manifest = json.loads(body)
        assert manifest['version'] == '1.2.4'
        assert manifest['installer_sha256'] == hashlib.sha256(candidate.read_bytes()).hexdigest()
        assert manifest['platforms']['windows-x86_64']['url'] == 'https://updates.example.test/next.msi'
        status, headers, body = tls_get(port, root, '/base.msi')
        assert status == 200 and body == base.read_bytes()
        assert int(headers['Content-Length']) == len(body)
        for path in ('/tls.key', '/../tls.key', '/latest.json?unreviewed=true'):
            assert tls_get(port, root, path)[0] == 404
        with pytest.raises(ssl.SSLCertVerificationError):
            tls_get(port, root, '/latest.json', hostname='wrong.example.test')
        assert requests == ['/latest.json', '/base.msi', '/tls.key', '/../tls.key', '/latest.json?unreviewed=true']
    with pytest.raises(OSError):
        socket.create_connection(('127.0.0.1', port), timeout=.2)


def test_temporary_hosts_cleanup_preserves_independent_edits_after_failure(tmp_path):
    hosts = tmp_path / 'hosts'  # Never the operating system hosts file.
    before = b'127.0.0.1 localhost\r\n'
    hosts.write_bytes(before)
    with pytest.raises(ValueError, match='synthetic failure'):
        with fixture.hosts_mapping(hosts, 'native-test-marker'):
            assert fixture.HOST.encode() in hosts.read_bytes()
            with hosts.open('ab') as stream:
                stream.write(b'127.0.0.1 independently-added.example.test\r\n')
            raise ValueError('synthetic failure')
    assert hosts.read_bytes() == before + b'127.0.0.1 independently-added.example.test\r\n'


def test_hosts_mapping_refuses_an_existing_case_insensitive_hostname(tmp_path):
    hosts = tmp_path / 'hosts'
    before = b'127.0.0.2 UPDATES.EXAMPLE.TEST\n'
    hosts.write_bytes(before)
    with pytest.raises(RuntimeError, match='already has'):
        with fixture.hosts_mapping(hosts, 'native-test-marker'):
            pytest.fail('Conflicting case-insensitive host mapping was accepted')
    assert hosts.read_bytes() == before


def test_hosts_cleanup_does_not_overwrite_a_changed_marker_or_unrelated_file(tmp_path):
    hosts = tmp_path / 'hosts'
    hosts.write_text('127.0.0.1 localhost\n', encoding='ascii')
    with pytest.raises(RuntimeError, match='entry changed'):
        with fixture.hosts_mapping(hosts, 'native-test-marker'):
            changed = b'127.0.0.1 changed-by-another-writer.example.test\n'
            hosts.write_bytes(changed)
    assert hosts.read_bytes() == changed


def test_driver_download_is_exact_version_and_does_not_extract_arbitrary_zip_paths(tmp_path, monkeypatch):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        archive.writestr('msedgedriver.exe', b'synthetic driver; never executed')
        archive.writestr('../outside.exe', b'must not be extracted')
    observed = []

    def download(url, timeout):
        observed.append((url, timeout))
        return io.BytesIO(data.getvalue())

    monkeypatch.setattr(fixture.urllib.request, 'urlopen', download)
    driver = fixture.download_driver(tmp_path, '150.0.1234.56')
    assert observed == [('https://msedgedriver.microsoft.com/150.0.1234.56/edgedriver_win64.zip', 45)]
    assert driver.read_bytes() == b'synthetic driver; never executed'
    assert not (tmp_path.parent / 'outside.exe').exists()
    assert fixture.digest(driver) == hashlib.sha256(driver.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match='exact installed version'):
        fixture.download_driver(tmp_path, '../latest')
    assert len(observed) == 1


def test_driver_download_refuses_oversized_transfer_before_writing(tmp_path, monkeypatch):
    class Oversized(io.BytesIO):
        def read(self, size):
            assert size == 40 * 1024 * 1024 + 1
            return b'x' * size
    monkeypatch.setattr(fixture.urllib.request, 'urlopen', lambda *a, **k: Oversized())
    with pytest.raises(RuntimeError, match='archive exceeds'):
        fixture.download_driver(tmp_path, '150.0.1234.56')
    assert not (tmp_path / 'msedgedriver.exe').exists()


@pytest.mark.parametrize('indexed', ['150.0.1234.57', '150.0.9999.1', '../untrusted', '1' * 129])
def test_driver_patch_fallback_requires_matching_build_and_records_exact_selected_version(tmp_path, monkeypatch, indexed):
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        archive.writestr('msedgedriver.exe', b'synthetic driver')
    calls = []

    def download(url, timeout):
        calls.append(url)
        if len(calls) == 1:
            raise fixture.urllib.error.HTTPError(url, 404, 'Fixture exact patch unavailable', None, None)
        if len(calls) == 2:
            assert url == 'https://msedgedriver.microsoft.com/LATEST_RELEASE_150_WINDOWS'
            assert timeout == 15
            return io.BytesIO(indexed.encode())
        assert url == 'https://msedgedriver.microsoft.com/150.0.1234.57/edgedriver_win64.zip'
        return io.BytesIO(data.getvalue())

    monkeypatch.setattr(fixture.urllib.request, 'urlopen', download)
    if indexed == '150.0.1234.57':
        driver = fixture.download_driver(tmp_path, '150.0.1234.56')
        assert driver.read_bytes() == b'synthetic driver'
        assert (tmp_path / 'driver-version.txt').read_text() == indexed
    else:
        with pytest.raises(RuntimeError):
            fixture.download_driver(tmp_path, '150.0.1234.56')
        assert len(calls) == 2
        assert not (tmp_path / 'msedgedriver.exe').exists()


def test_commands_preserve_timeouts_and_keep_sensitive_output_out_of_errors(monkeypatch):
    called = []

    def execute(arguments, **options):
        called.append(options)
        return subprocess.CompletedProcess(arguments, 5, stdout='PRIVATE STDOUT', stderr='PRIVATE STDERR')

    monkeypatch.setattr(fixture.subprocess, 'run', execute)
    with pytest.raises(RuntimeError) as caught:
        fixture.command(['synthetic-only.exe', 'private-input'], timeout=3)
    assert 'PRIVATE' not in str(caught.value) and 'private-input' not in str(caught.value)
    assert called[0]['timeout'] == 3 and called[0]['capture_output'] is True


def test_hosted_guard_refuses_local_execution(monkeypatch):
    monkeypatch.delenv('GITHUB_ACTIONS', raising=False)
    with pytest.raises(RuntimeError, match='disposable GitHub-hosted'):
        fixture.hosted_only()

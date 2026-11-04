"""Real native acceptance infrastructure; every mutation stays on its disposable VM."""
from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import urllib.error
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = "updates.example.test"


def hosted_only() -> None:
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "RUNNER_OS": "Windows", "GITHUB_JOB": "build-and-accept"}
    if os.name != "nt" or any(os.environ.get(key) != value for key, value in expected.items()):
        raise RuntimeError("Native acceptance requires the disposable GitHub-hosted Windows job.")


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        value = hashlib.sha256()
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(part)
    return value.hexdigest()


def command(args: list[str], *, env: dict | None = None, timeout: int = 90) -> str:
    result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode:
        raise RuntimeError(f"Native fixture command {Path(args[0]).name} failed with exit {result.returncode}.")
    return result.stdout.strip()


def make_tls(directory: Path) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, directory.name)])
    now = dt.datetime.now(dt.timezone.utc)
    root = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(root_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False), critical=True)
        .sign(root_key, hashes.SHA256()))
    # The updater's real Rust TLS verifier rejects a CA certificate presented
    # as the server leaf. Trust only the root; serve a separate CA:false leaf.
    certificate = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, HOST)]))
        .issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(root_key, hashes.SHA256()))
    (directory / "tls.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (directory / "tls.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM) + root.public_bytes(serialization.Encoding.PEM))
    (directory / "tls.cer").write_bytes(root.public_bytes(serialization.Encoding.DER))
    return root.fingerprint(hashes.SHA1()).hex()


@contextlib.contextmanager
def hosts_mapping(hosts: Path, marker: str):
    """Remove only our exact entry; preserve any independent host-file edits."""
    before = hosts.read_bytes()
    if HOST.encode().lower() in before.lower():
        raise RuntimeError("The native fixture hostname already has a hosts-file entry.")
    entry = f"\n127.0.0.1 {HOST} # {marker}\n".encode("ascii")
    hosts.write_bytes(before + entry)
    try:
        yield
    finally:
        current = hosts.read_bytes()
        if current.count(entry) != 1:
            raise RuntimeError("Native fixture hosts entry changed; refusing broad hosts-file replacement.")
        hosts.write_bytes(current.replace(entry, b"", 1))


def manifests(base: Path, candidate: Path, metadata: dict) -> dict:
    version = metadata["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise ValueError("Expected exact three-part fixture version.")
    parts = version.split(".")
    next_version = ".".join(parts[:2] + [str(int(parts[2]) + 1)])
    result = {}
    for filename, package, release in (("base.msi", base, version), ("next.msi", candidate, next_version)):
        value = {"version": release, "notes": "Disposable signed native acceptance fixture.",
                 "runtime_sha256": metadata["runtime"]["sha256"], "installer_sha256": digest(package),
                 "platforms": {"windows-x86_64": {
                     "url": f"https://{HOST}/{filename}",
                     "signature": Path(str(package) + ".sig").read_text(encoding="utf-8").strip()}}}
        result[f"/versions/{release}.json"] = json.dumps(value).encode()
        if filename == "next.msi":
            result["/latest.json"] = json.dumps(value).encode()
    return result


@contextlib.contextmanager
def update_server(directory: Path, base: Path, candidate: Path, metadata: dict, *, port: int = 443):
    payloads = manifests(base, candidate, metadata)
    packages = {"/base.msi": base, "/next.msi": candidate}
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - standard library HTTP handler
            requests.append(self.path)
            if self.path in payloads:
                payload = payloads[self.path]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            elif self.path in packages:
                package = packages[self.path]
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(package.stat().st_size))
                self.end_headers()
                with package.open("rb") as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b""):
                        self.wfile.write(block)
            else:
                self.send_error(404)

        def log_message(self, *_args):
            pass  # Test reports retain routes; request headers are never logged.

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(directory / "tls.pem", directory / "tls.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield requests, server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def available_port() -> int:
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def webview_runtime() -> tuple[str, Path]:
    roots = [Path(os.environ[name]) / "Microsoft/EdgeWebView/Application"
             for name in ("ProgramFiles(x86)", "ProgramFiles") if os.environ.get(name)]
    versions = [(tuple(map(int, path.name.split("."))), path) for root in roots for path in root.glob("*")
                if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", path.name) and (path / "msedgewebview2.exe").is_file()]
    if not versions:
        raise RuntimeError("The installed customer MSI did not provide WebView2.")
    _version, directory = max(versions)
    return directory.name, directory


def download_driver(directory: Path, version: str) -> Path:
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", version):
        raise ValueError("WebView driver must match an exact installed version.")
    selected = version
    url = f"https://msedgedriver.microsoft.com/{selected}/edgedriver_win64.zip"
    try:
        response = urllib.request.urlopen(url, timeout=45)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        # Microsoft requires the first three version parts to match. WebView2
        # and WebDriver may publish different fourth-part servicing patches.
        # Resolve only Microsoft's own release index and reject build changes.
        index = f"https://msedgedriver.microsoft.com/LATEST_RELEASE_{version.split('.')[0]}_WINDOWS"
        with urllib.request.urlopen(index, timeout=15) as release:
            raw_version = release.read(129)
        if len(raw_version) > 128:
            raise RuntimeError("Microsoft WebView driver version response exceeds the limit.") from error
        encoding = "utf-16" if raw_version.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
        selected = raw_version.decode(encoding).strip()
        if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", selected) or selected.split(".")[:3] != version.split(".")[:3]:
            raise RuntimeError("Microsoft has no indexed WebView driver matching the installed build.") from error
        url = f"https://msedgedriver.microsoft.com/{selected}/edgedriver_win64.zip"
        response = urllib.request.urlopen(url, timeout=45)
    with response:
        raw = response.read(40 * 1024 * 1024 + 1)
    if len(raw) > 40 * 1024 * 1024:
        raise RuntimeError("Microsoft WebView driver archive exceeds the acceptance limit.")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entry = archive.getinfo("msedgedriver.exe")
        if entry.file_size > 60 * 1024 * 1024:
            raise RuntimeError("Microsoft WebView driver exceeds the acceptance limit.")
        destination = directory / "msedgedriver.exe"
        destination.write_bytes(archive.read(entry))
    (directory / "driver-version.txt").write_text(selected, encoding="ascii")
    return destination

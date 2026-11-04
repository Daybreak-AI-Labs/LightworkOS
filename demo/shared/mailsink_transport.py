"""Shared SMTP transport for the standalone concierge demos.

Edit demo/shared/mailsink_transport.py; regenerate vendored copies with
scripts/sync_standalone_support.py.
"""
from __future__ import annotations

import asyncio
import ssl
import tempfile
from pathlib import Path


def selfsigned_context() -> ssl.SSLContext | None:
    """A throwaway server cert so STARTTLS works. smtplib's default STARTTLS
    context does not verify the cert, so self-signed is fine for the sink."""
    try:
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # OpenSSL reads the key into the context; remove temporary files after
        # loading instead of leaving a private key on the host indefinitely.
        with tempfile.TemporaryDirectory(prefix="lightwork-mailsink-") as directory:
            cert_path, key_path = Path(directory) / "cert.pem", Path(directory) / "key.pem"
            cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
            ctx.load_cert_chain(cert_path, key_path)
        return ctx
    except Exception as exc:  # pragma: no cover
        print(f"[mailsink] STARTTLS unavailable ({exc}); plaintext only")
        return None


async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, store, tls_context) -> None:
    async def send(line: str) -> None:
        writer.write((line + "\r\n").encode())
        await writer.drain()

    await send("220 demo-mailsink ESMTP")
    data_lines: list[bytes] = []
    in_data = False
    try:
        while True:
            raw = await reader.readline()
            if not raw:
                break
            if in_data:
                if raw.rstrip(b"\r\n") == b".":
                    store(b"".join(data_lines))
                    data_lines = []
                    in_data = False
                    await send("250 OK: queued")
                else:
                    line = raw[1:] if raw.startswith(b"..") else raw
                    data_lines.append(line)
                continue

            verb = raw.split(None, 1)[0].upper() if raw.strip() else b""
            if verb in (b"EHLO", b"HELO"):
                # Advertise STARTTLS + AUTH PLAIN so the real tool's flow works.
                writer.write(b"250-demo-mailsink\r\n")
                if tls_context() is not None:
                    writer.write(b"250-STARTTLS\r\n")
                writer.write(b"250 AUTH PLAIN LOGIN\r\n")
                await writer.drain()
            elif verb == b"STARTTLS" and tls_context() is not None:
                await send("220 Ready to start TLS")
                await writer.start_tls(tls_context())
            elif verb == b"AUTH":
                # One-shot PLAIN carries creds inline; LOGIN would need challenges.
                if b"LOGIN" in raw.upper():
                    await send("334 VXNlcm5hbWU6")            # "Username:"
                    await reader.readline()
                    await send("334 UGFzc3dvcmQ6")            # "Password:"
                    await reader.readline()
                await send("235 2.7.0 Authentication successful")
            elif verb == b"MAIL":
                await send("250 OK")
            elif verb == b"RCPT":
                await send("250 OK")
            elif verb == b"DATA":
                in_data = True
                await send("354 End data with <CR><LF>.<CR><LF>")
            elif verb == b"RSET":
                data_lines = []
                in_data = False
                await send("250 OK")
            elif verb == b"NOOP":
                await send("250 OK")
            elif verb == b"QUIT":
                await send("221 Bye")
                break
            else:
                await send("250 OK")
    except Exception:  # pragma: no cover - never crash the demo on a mail hiccup
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

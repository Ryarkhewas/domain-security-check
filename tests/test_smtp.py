"""Mail servers: STARTTLS, TLS version, certificates, DANE."""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import threading

import pytest

from domaincheck import smtp_scan
from domaincheck.email_checks import check_mail_servers
from domaincheck.models import MailServerInfo, MTASTSInfo, Status

NOW = dt.datetime(2026, 10, 18, tzinfo=dt.timezone.utc)


@pytest.fixture(scope="module")
def cert_files(tmp_path_factory):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    folder = tmp_path_factory.mktemp("smtp")
    (folder / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                                       serialization.NoEncryption()))
    return folder / "cert.pem", folder / "key.pem"


def fake_smtp(cert_files=None, starttls=True, banner=b"220 mx.test ESMTP\r\n") -> int:
    """A tiny SMTP server: greeting, EHLO, optional STARTTLS, QUIT."""
    ctx = None
    if cert_files:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_files[0], cert_files[1])
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)

    def lines(conn):
        buf = b""
        while True:
            data = conn.recv(1024)
            if not data:
                return
            buf += data
            while b"\r\n" in buf:
                line, buf = buf.split(b"\r\n", 1)
                yield line.decode().upper()

    def handle(conn):
        try:
            conn.sendall(banner)
            for line in lines(conn):
                if line.startswith("EHLO"):
                    conn.sendall(b"250-mx.test\r\n250-SIZE 10240000\r\n" + (b"250 STARTTLS\r\n" if starttls
                                                                            else b"250 8BITMIME\r\n"))
                elif line == "STARTTLS" and starttls:
                    conn.sendall(b"220 go ahead\r\n")
                    tls = ctx.wrap_socket(conn, server_side=True)
                    data = tls.recv(1024)
                    if data.startswith(b"QUIT"):
                        tls.sendall(b"221 bye\r\n")
                    tls.close()
                    return
                elif line == "QUIT":
                    conn.sendall(b"221 bye\r\n")
                    return
        except (OSError, ssl.SSLError):
            pass
        finally:
            conn.close()

    def serve():
        while True:
            conn, _ = server.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return server.getsockname()[1]


def test_server_with_starttls_and_self_signed_certificate(cert_files):
    info = smtp_scan.probe("localhost", timeout=5, port=fake_smtp(cert_files))
    assert info.reachable and info.starttls
    assert info.tls_version in ("TLSv1.2", "TLSv1.3")
    assert info.cert_valid is False and "self" in info.cert_error.lower()
    assert info.cert_expires and info.cert_expires > dt.datetime.now(dt.timezone.utc)


def test_server_without_starttls():
    info = smtp_scan.probe("localhost", timeout=5, port=fake_smtp(starttls=False))
    assert info.reachable and not info.starttls and info.cert_valid is None


def test_unreachable_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    info = smtp_scan.probe("localhost", timeout=2, port=port)
    assert not info.reachable and info.error == "connection refused"


def test_not_an_smtp_server():
    info = smtp_scan.probe("localhost", timeout=5, port=fake_smtp(banner=b"SSH-2.0-OpenSSH\r\n"))
    assert not info.reachable and "not an SMTP reply" in info.error


def test_multiline_greeting():
    info = smtp_scan.probe("localhost", timeout=5, port=fake_smtp(starttls=False,
                                                                  banner=b"220-mx.test\r\n220 welcome\r\n"))
    assert info.reachable


# --- Checks ---------------------------------------------------------------------------
def good(host="mx1.example.com", **kw):
    values = {"reachable": True, "starttls": True, "tls_version": "TLSv1.3", "cert_valid": True,
              "cert_expires": NOW + dt.timedelta(days=60)} | kw
    return MailServerInfo(host, **values)


def by_title(findings):
    return {f.title: f for f in findings}


def test_port_25_blocked_is_not_a_flaw():
    (f,) = check_mail_servers([MailServerInfo("mx1.example.com", error="timeout")], None, NOW)
    assert f.status == Status.INFO and f.points is None and "port 25" in f.detail


def test_all_good():
    f = by_title(check_mail_servers([good(), good("mx2.example.com")], None, NOW))
    assert f["Encryption of incoming email (STARTTLS)"].status == Status.OK
    assert f["Mail server certificates"].status == Status.OK
    assert f["DANE (mail server keys in DNS)"].status == Status.INFO
    assert all(x.points in (0, None) for x in f.values())


def test_no_starttls():
    f = by_title(check_mail_servers([good(), good("mx2.example.com", starttls=False, tls_version="",
                                                  cert_valid=None)], None, NOW))
    starttls = f["Encryption of incoming email (STARTTLS)"]
    assert (starttls.status, starttls.points) == (Status.WARNING, -20) and "mx2.example.com" in starttls.detail


def test_partly_reachable():
    f = by_title(check_mail_servers([good(), MailServerInfo("mx2.example.com", error="timeout")], None, NOW))
    assert "Not reached: mx2.example.com" in f["Encryption of incoming email (STARTTLS)"].detail


def test_old_tls():
    f = by_title(check_mail_servers([good(tls_version="TLSv1")], None, NOW))
    assert f["Mail server TLS version"].points == -10


def test_invalid_certificate_with_and_without_enforced_mta_sts():
    bad = good(cert_valid=False, cert_error="self-signed certificate")
    f = by_title(check_mail_servers([bad], None, NOW))
    assert f["Mail server certificates"].points == -5
    enforce = MTASTSInfo(txt=["v=STSv1; id=1"], policy="version: STSv1\nmode: enforce\nmx: *.example.com\n")
    f = by_title(check_mail_servers([bad], enforce, NOW))
    assert (f["Mail server certificates"].status, f["Mail server certificates"].points) == (Status.CRITICAL, -30)


def test_expired_certificate():
    f = by_title(check_mail_servers([good(cert_valid=True, cert_expires=NOW - dt.timedelta(days=1))], None, NOW))
    assert "expired on 2026-10-17" in f["Mail server certificates"].detail


def test_dane():
    f = by_title(check_mail_servers([good(tlsa=1), good("mx2.example.com", tlsa=2)], None, NOW))
    assert f["DANE (mail server keys in DNS)"].status == Status.OK
    f = by_title(check_mail_servers([good(tlsa=1), good("mx2.example.com")], None, NOW))
    assert "by mx2.example.com" in f["DANE (mail server keys in DNS)"].detail


def test_no_mx_no_finding():
    assert check_mail_servers([], None, NOW) == []


def endless_server(payload_loop):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(4)

    def serve():
        while True:
            conn, _ = server.accept()

            def talk(c=conn):
                try:
                    payload_loop(c)
                except OSError:
                    pass
                finally:
                    c.close()
            threading.Thread(target=talk, daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return server.getsockname()[1]


def test_endless_reply_is_cut():
    def flood(conn):
        while True:
            conn.sendall(b"220-still talking\r\n")

    info = smtp_scan.probe("localhost", timeout=5, port=endless_server(flood))
    assert not info.reachable and "reply too long" in info.error


def test_slow_server_is_cut(monkeypatch):
    import time

    monkeypatch.setattr(smtp_scan, "CONNECTION_DEADLINE", 1)

    def drip(conn):
        while True:
            conn.sendall(b"2")
            time.sleep(0.2)

    start = time.monotonic()
    info = smtp_scan.probe("localhost", timeout=5, port=endless_server(drip))
    assert time.monotonic() - start < 4 and not info.reachable
    assert info.error in ("timeout", "the server answers too slowly")

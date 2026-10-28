"""Accepted TLS versions and cipher suites: hand-built ClientHello, ServerHello reading, checks."""

from __future__ import annotations

import datetime as dt
import socket
import ssl
import struct
import threading
import warnings

import pytest

from domaincheck import tls_scan as scan
from domaincheck.collector import Collector, _public_key
from domaincheck.models import CertificateInfo, Status, TLSScanInfo
from domaincheck.tls_checks import check_tls_scan


# --- Messages -------------------------------------------------------------------------
def server_hello(version=scan.TLS12, cipher=0xC02F, session=b"") -> bytes:
    body = struct.pack("!H", version) + b"\x00" * 32 + bytes([len(session)]) + session + struct.pack("!HB", cipher, 0)
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return struct.pack("!BHH", 22, version, len(handshake)) + handshake


def test_client_hello_is_a_valid_record():
    data = scan.client_hello("example.com", scan.TLS12, [0xC02F, 0x002F])
    kind, record_version, length = struct.unpack("!BHH", data[:5])
    assert (kind, record_version, length) == (22, scan.TLS10, len(data) - 5)
    assert data[5] == 1  # ClientHello
    assert int.from_bytes(data[6:9], "big") == len(data) - 9
    assert struct.unpack("!H", data[9:11])[0] == scan.TLS12
    ciphers_len = struct.unpack("!H", data[44:46])[0]
    assert data[46:46 + ciphers_len] == bytes.fromhex("c02f002f00ff")
    assert b"example.com" in data  # SNI


def test_ssl3_hello_has_no_extensions():
    data = scan.client_hello("example.com", scan.SSL3, [0x000A])
    assert b"example.com" not in data
    assert data.endswith(b"\x01\x00")  # compression methods, nothing after


def test_read_server_hello():
    assert scan.read_server_hello(server_hello()) == scan.Hello(True, scan.TLS12, 0xC02F)
    assert scan.read_server_hello(server_hello(session=b"x" * 32, cipher=0x000A)).cipher == 0x000A
    assert scan.read_server_hello(server_hello(scan.TLS10)).version == scan.TLS10


def test_alert_is_a_refusal():
    assert scan.read_server_hello(bytes.fromhex("15030100020228")) == scan.Hello(False, alert=40)


def test_partial_answer_waits_for_more_bytes():
    data = server_hello()
    assert scan.read_server_hello(data[:3]) is None
    assert scan.read_server_hello(data[:20]) is None


def test_server_hello_split_over_two_records():
    handshake = server_hello()[5:]
    records = b"".join(struct.pack("!BHH", 22, scan.TLS12, len(part)) + part
                       for part in (handshake[:10], handshake[10:]))
    assert scan.read_server_hello(records).cipher == 0xC02F


def test_non_tls_answer_is_an_error():
    with pytest.raises(scan.ProbeError):
        scan.read_server_hello(b"HTTP/1.1 400 Bad Request\r\n\r\n")


def test_forward_secrecy_from_suite_name():
    assert scan.has_forward_secrecy("ECDHE-RSA-AES128-GCM-SHA256", "TLSv1.2")
    assert scan.has_forward_secrecy("TLS_AES_256_GCM_SHA384", "TLSv1.3")
    assert not scan.has_forward_secrecy("AES128-SHA", "TLSv1.2")


# --- Against a local TLS server -----------------------------------------------------------
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
            .serial_number(1).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    folder = tmp_path_factory.mktemp("tls")
    (folder / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                       serialization.PrivateFormat.TraditionalOpenSSL,
                                                       serialization.NoEncryption()))
    return folder / "cert.pem", folder / "key.pem", cert.public_bytes(serialization.Encoding.DER)


def local_server(cert_files, minimum, maximum, ciphers) -> int:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_files[0], cert_files[1])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version, ctx.maximum_version = minimum, maximum
    ctx.set_ciphers(ciphers)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(16)

    def serve():
        while True:
            conn, _ = sock.accept()
            try:
                ctx.wrap_socket(conn, server_side=True).close()
            except (ssl.SSLError, OSError):
                conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def test_scan_of_a_modern_server(cert_files):
    port = local_server(cert_files, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3, "ECDHE+AESGCM")
    info = Collector(timeout=5, allow_private=True).tls_scan("localhost", port=port)
    assert info.versions == {"SSLv3": False, "TLSv1": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}
    assert (info.weak_ciphers, info.weak_tested, info.static_rsa) == ([], True, False)


def test_scan_of_an_old_server(cert_files):
    port = local_server(cert_files, ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_2,
                        "ECDHE-RSA-AES128-SHA:AES128-SHA:AES256-SHA:@SECLEVEL=0")
    info = Collector(timeout=5, allow_private=True).tls_scan("localhost", port=port)
    if info.versions["TLSv1"] is False:
        pytest.skip("the local OpenSSL refuses to serve TLS 1.0")
    assert info.versions["TLSv1.1"] and info.versions["TLSv1.2"] and info.versions["TLSv1.3"] is False
    assert info.static_rsa is True


def test_unreachable_server_is_reported():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens on this port
    info = Collector(timeout=2, allow_private=True).tls_scan("localhost", port=port)
    assert info.error
    assert check_tls_scan(info, None)[0].status == Status.INFO


def test_public_key_of_the_certificate(cert_files):
    assert _public_key(cert_files[2]) == {"key_type": "RSA", "key_bits": 2048}
    assert _public_key(b"not a certificate") == {}
    assert _public_key(None) == {}


# --- Checks ---------------------------------------------------------------------------
MODERN = {"SSLv3": False, "TLSv1": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}


def cert(cipher="ECDHE-RSA-AES128-GCM-SHA256", version="TLSv1.2", key=("RSA", 2048)):
    return CertificateInfo(valid=True, tls_version=version, cipher=cipher, key_type=key[0], key_bits=key[1])


def by_title(findings):
    return {f.title: f for f in findings}


def test_modern_server_has_no_penalty():
    findings = check_tls_scan(TLSScanInfo(MODERN, [], True, False), cert())
    assert all(f.status == Status.OK and f.points == 0 for f in findings)
    assert set(by_title(findings)) == {"Accepted TLS versions", "Weak cipher suites", "Forward secrecy",
                                       "Certificate key"}


def test_old_versions():
    f = by_title(check_tls_scan(TLSScanInfo({**MODERN, "TLSv1": True}, [], True, False), cert()))
    assert (f["Accepted TLS versions"].status, f["Accepted TLS versions"].points) == (Status.WARNING, -20)
    assert "TLS 1.0" in f["Accepted TLS versions"].detail
    f = by_title(check_tls_scan(TLSScanInfo({**MODERN, "SSLv3": True}, [], True, False), cert()))
    assert (f["Accepted TLS versions"].status, f["Accepted TLS versions"].points) == (Status.CRITICAL, -30)


def test_missing_tls13():
    f = by_title(check_tls_scan(TLSScanInfo({**MODERN, "TLSv1.3": False}, [], True, False), cert()))
    assert f["TLS 1.3"].points == -5
    # not tested (old local OpenSSL): no finding
    assert "TLS 1.3" not in by_title(check_tls_scan(TLSScanInfo({**MODERN, "TLSv1.3": None}, [], True, False), cert()))


def test_weak_ciphers():
    f = by_title(check_tls_scan(TLSScanInfo(MODERN, ["DES-CBC3-SHA"], True, False), cert()))
    assert f["Weak cipher suites"].points == -20 and "DES-CBC3-SHA" in f["Weak cipher suites"].detail
    assert "Weak cipher suites" not in by_title(check_tls_scan(TLSScanInfo(MODERN, [], False, False), cert()))


def test_forward_secrecy():
    f = by_title(check_tls_scan(TLSScanInfo(MODERN, [], True, False), cert(cipher="AES128-SHA")))
    assert f["Forward secrecy"].points == -10
    f = by_title(check_tls_scan(TLSScanInfo(MODERN, [], True, True), cert()))
    assert f["Forward secrecy"].points == -5
    f = by_title(check_tls_scan(TLSScanInfo(MODERN, [], True, False), cert("TLS_AES_128_GCM_SHA256", "TLSv1.3")))
    assert f["Forward secrecy"].status == Status.OK


def test_certificate_key():
    assert by_title(check_tls_scan(TLSScanInfo(MODERN), cert(key=("RSA", 1024))))["Certificate key"].points == -30
    assert by_title(check_tls_scan(TLSScanInfo(MODERN), cert(key=("EC", 256))))["Certificate key"].status == Status.OK
    assert "Certificate key" not in by_title(check_tls_scan(TLSScanInfo(MODERN), cert(key=("", 0))))

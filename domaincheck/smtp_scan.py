"""Encryption offered by a domain's mail servers (the MX hosts).

The tool talks to each mail server exactly as a sending mail server would
before delivering a message: it connects on port 25, says EHLO, asks for
STARTTLS if offered, completes the TLS handshake and says QUIT. No message is
ever sent.

Port 25 is often blocked by the network the audit runs from (home
connections, cloud providers): then nothing can be concluded, and the report
says so instead of guessing.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
import time
from datetime import datetime, timezone

from .models import MailServerInfo

EHLO_NAME = "domain-security-check.localhost"


MAX_REPLY_LINES = 100
CONNECTION_DEADLINE = 30  # seconds for a whole conversation, however slowly the server answers


class SMTPError(OSError):
    """The server answered something unexpected."""


def _recv(sock: socket.socket, deadline: float) -> bytes:
    """recv() that cannot outlast the conversation's deadline (a server answering a byte at a time)."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SMTPError("the server answers too slowly")
    sock.settimeout(min(sock.gettimeout() or remaining, remaining))
    return sock.recv(4096)


def _read_reply(sock: socket.socket, deadline: float) -> tuple[int, list[str]]:
    """One SMTP reply (possibly multi-line: "250-..." then "250 ...")."""
    data = b""
    lines: list[str] = []
    while True:
        if len(lines) >= MAX_REPLY_LINES:
            raise SMTPError("reply too long")
        while b"\r\n" not in data and b"\n" not in data:
            chunk = _recv(sock, deadline)
            if not chunk:
                raise SMTPError("connection closed")
            data += chunk
            if len(data) > 65536:
                raise SMTPError("reply too long")
        line, _, data = data.partition(b"\n")
        text = line.rstrip(b"\r").decode("latin-1")
        if len(text) < 3 or not text[:3].isdigit():
            raise SMTPError(f"not an SMTP reply: {text[:40]!r}")
        lines.append(text[4:])
        if len(text) == 3 or text[3] == " ":
            if data:
                raise SMTPError("unexpected data after the reply")
            return int(text[:3]), lines


def _command(sock: socket.socket, line: str, deadline: float) -> tuple[int, list[str]]:
    sock.sendall(line.encode("ascii") + b"\r\n")
    return _read_reply(sock, deadline)


def _open(host: str, port: int, timeout: float) -> tuple[socket.socket, bool, float]:
    """Connect, greet, and return (socket, STARTTLS offered, deadline of the conversation)."""
    deadline = time.monotonic() + CONNECTION_DEADLINE
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        code, _ = _read_reply(sock, deadline)
        if code != 220:
            raise SMTPError(f"greeting {code}")
        code, lines = _command(sock, f"EHLO {EHLO_NAME}", deadline)
        if code != 250:
            raise SMTPError(f"EHLO refused ({code})")
        return sock, any(line.upper().split(" ")[0] == "STARTTLS" for line in lines), deadline
    except BaseException:
        sock.close()
        raise


def _starttls(host: str, port: int, timeout: float, verify: bool) -> ssl.SSLSocket:
    sock, offered, deadline = _open(host, port, timeout)
    try:
        if not offered:
            raise SMTPError("STARTTLS not offered")
        code, _ = _command(sock, "STARTTLS", deadline)
        if code != 220:
            raise SMTPError(f"STARTTLS refused ({code})")
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx.wrap_socket(sock, server_hostname=host)
    except BaseException:
        sock.close()
        raise


def _quit(sock: socket.socket) -> None:
    with contextlib.suppress(OSError):
        sock.sendall(b"QUIT\r\n")
    sock.close()


def probe(host: str, timeout: float = 10, port: int = 25) -> MailServerInfo:
    """STARTTLS support, TLS version and certificate of one mail server."""
    info = MailServerInfo(host)
    try:
        sock, offered, _ = _open(host, port, timeout)
    except (OSError, ssl.SSLError) as e:
        info.error = _reason(e)
        return info
    info.reachable, info.starttls = True, offered
    _quit(sock)
    if not offered:
        return info
    # First with certificate verification, as a sender applying MTA-STS or DANE would
    try:
        tls = _starttls(host, port, timeout, verify=True)
        info.cert_valid = True
    except ssl.SSLCertVerificationError as e:
        info.cert_valid, info.cert_error = False, e.verify_message or "invalid certificate"
        tls = None
    except (OSError, ssl.SSLError) as e:
        info.error = _reason(e)
        return info
    if tls is None:  # then without, to still see the protocol version
        try:
            tls = _starttls(host, port, timeout, verify=False)
        except (OSError, ssl.SSLError) as e:
            info.error = _reason(e)
            return info
    info.tls_version = tls.version() or ""
    info.cipher = (tls.cipher() or ("", "", 0))[0]
    info.cert_expires = _expiry(tls.getpeercert(binary_form=True))
    _quit(tls)
    return info


def _expiry(der: bytes | None) -> datetime | None:
    if not der:
        return None
    try:
        from cryptography import x509

        cert = x509.load_der_x509_certificate(der)
    except (ImportError, ValueError):
        return None
    after = getattr(cert, "not_valid_after_utc", None)
    if after is None:  # cryptography < 42
        after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    return after


def _reason(e: BaseException) -> str:
    if isinstance(e, socket.timeout | TimeoutError):
        return "timeout"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused"
    text = str(e) or e.__class__.__name__
    return text[:120]

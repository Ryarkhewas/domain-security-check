"""Which TLS versions and cipher suites a server accepts.

The local OpenSSL refuses to offer old protocols and ciphers (SSLv3, RC4,
3DES...), so these probes do not use the ssl module: they send a hand-built
ClientHello (RFC 5246, section 7.4.1.2) and only read the server's answer,
the ServerHello, which says which version and cipher suite the server picked.
The connection is then closed: no key exchange, no data, like the first step
of any visit by an old browser. TLS 1.3 is tested with the ssl module, which
supports it.

The functions that build and read the messages make no network calls, so
they can be tested on fixed bytes.
"""

from __future__ import annotations

import os
import socket
import ssl
import struct
import time
from dataclasses import dataclass

SSL3, TLS10, TLS11, TLS12 = 0x0300, 0x0301, 0x0302, 0x0303
VERSION_NAMES = {SSL3: "SSLv3", TLS10: "TLSv1", TLS11: "TLSv1.1", TLS12: "TLSv1.2"}

# Cipher suites (IANA registry) by family
WEAK_SUITES: dict[int, str] = {
    # RC4 (RFC 7465 forbids it)
    0x0004: "RC4-MD5", 0x0005: "RC4-SHA", 0xC007: "ECDHE-ECDSA-RC4-SHA", 0xC011: "ECDHE-RSA-RC4-SHA",
    # 3DES (64-bit block, Sweet32)
    0x000A: "DES-CBC3-SHA", 0x0016: "EDH-RSA-DES-CBC3-SHA", 0xC008: "ECDHE-ECDSA-DES-CBC3-SHA",
    0xC012: "ECDHE-RSA-DES-CBC3-SHA",
    # single DES
    0x0009: "DES-CBC-SHA", 0x0015: "EDH-RSA-DES-CBC-SHA",
    # export grade (40/56-bit)
    0x0003: "EXP-RC4-MD5", 0x0006: "EXP-RC2-CBC-MD5", 0x0008: "EXP-DES-CBC-SHA", 0x0014: "EXP-EDH-RSA-DES-CBC-SHA",
    # no encryption
    0x0001: "NULL-MD5", 0x0002: "NULL-SHA", 0x003B: "NULL-SHA256", 0xC010: "ECDHE-RSA-NULL-SHA",
    # no authentication (anonymous)
    0x0018: "ADH-RC4-MD5", 0x001B: "ADH-DES-CBC3-SHA", 0x0034: "ADH-AES128-SHA", 0x003A: "ADH-AES256-SHA",
    0xC018: "AECDH-AES128-SHA", 0xC019: "AECDH-AES256-SHA",
}
# RSA key exchange: no forward secrecy (a stolen private key decrypts recorded traffic)
STATIC_RSA_SUITES: dict[int, str] = {
    0x002F: "AES128-SHA", 0x0035: "AES256-SHA", 0x003C: "AES128-SHA256", 0x003D: "AES256-SHA256",
    0x009C: "AES128-GCM-SHA256", 0x009D: "AES256-GCM-SHA384", 0x0041: "CAMELLIA128-SHA",
    0x0084: "CAMELLIA256-SHA",
}
# Common modern suites, offered when only the protocol version is tested
MODERN_SUITES = [
    0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8, 0xC009, 0xC013, 0xC00A, 0xC014,
    0x009E, 0x009F, 0x0033, 0x0039,
]
VERSION_PROBE_SUITES = MODERN_SUITES + list(STATIC_RSA_SUITES) + [0x000A, 0x0005, 0x0004]


PROBE_DEADLINE = 20  # seconds for one probe, however slowly the server answers


@dataclass
class Hello:
    """What the server answered to a ClientHello."""

    accepted: bool
    version: int = 0  # version chosen by the server
    cipher: int = 0  # cipher suite chosen by the server
    alert: int | None = None  # TLS alert code, when the server refused


class ProbeError(OSError):
    """The server could not be reached, or its answer is not TLS."""


def client_hello(host: str, version: int, suites: list[int]) -> bytes:
    """A ClientHello record offering `version` (SSLv3 to TLS 1.2) and the given cipher suites."""
    extensions = b""
    if version >= TLS10:
        name = host.encode("idna")
        sni = struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
        extensions += _ext(0x0000, sni)  # server_name
        groups = [0x001D, 0x0017, 0x0018, 0x0019]  # x25519, P-256, P-384, P-521
        extensions += _ext(0x000A, struct.pack("!H", 2 * len(groups)) + b"".join(struct.pack("!H", g) for g in groups))
        extensions += _ext(0x000B, b"\x01\x00")  # ec_point_formats: uncompressed
        extensions += _ext(0xFF01, b"\x00")  # renegotiation_info (RFC 5746)
    if version >= TLS12:
        algorithms = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201]
        body = b"".join(struct.pack("!H", a) for a in algorithms)
        extensions += _ext(0x000D, struct.pack("!H", len(body)) + body)  # signature_algorithms
    ciphers = b"".join(struct.pack("!H", s) for s in suites) + b"\x00\xff"  # + renegotiation SCSV
    hello = (struct.pack("!H", version) + os.urandom(32) + b"\x00"  # empty session id
             + struct.pack("!H", len(ciphers)) + ciphers + b"\x01\x00")  # null compression only
    if extensions:
        hello += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + struct.pack("!I", len(hello))[1:] + hello
    record_version = min(version, TLS10)  # usual practice: record layer at most TLS 1.0
    return struct.pack("!BHH", 22, record_version, len(handshake)) + handshake


def _ext(kind: int, data: bytes) -> bytes:
    return struct.pack("!HH", kind, len(data)) + data


def read_server_hello(data: bytes) -> Hello | None:
    """Read the server's first records. None while more bytes are needed.

    Raise ProbeError if the bytes are not a TLS answer.
    """
    handshake = b""
    pos = 0
    while pos + 5 <= len(data):
        kind, _, length = struct.unpack("!BHH", data[pos:pos + 5])
        if pos + 5 + length > len(data):
            break
        payload = data[pos + 5:pos + 5 + length]
        pos += 5 + length
        if kind == 21:  # alert
            return Hello(False, alert=payload[1] if len(payload) > 1 else None)
        if kind != 22:
            raise ProbeError("not a TLS handshake")
        handshake += payload
        if len(handshake) >= 4:
            if handshake[0] != 2:  # first message must be ServerHello
                raise ProbeError("unexpected handshake message")
            size = int.from_bytes(handshake[1:4], "big")
            if len(handshake) >= 4 + size:
                body = handshake[4:4 + size]
                version = struct.unpack("!H", body[0:2])[0]
                session_len = body[34]
                cipher = struct.unpack("!H", body[35 + session_len:37 + session_len])[0]
                return Hello(True, version, cipher)
    if pos == 0 and len(data) >= 5 and data[0] not in (21, 22):
        raise ProbeError("not a TLS answer")
    return None


def probe(host: str, version: int, suites: list[int], timeout: float = 8, port: int = 443) -> Hello:
    """Send a ClientHello and read the answer. A closed connection counts as a refusal."""
    deadline = time.monotonic() + PROBE_DEADLINE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(client_hello(host, version, suites))
            data = b""
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:  # a server sending its answer a byte at a time
                    raise ProbeError("answer too slow")
                sock.settimeout(min(timeout, remaining))
                chunk = sock.recv(16384)
                if not chunk:
                    return Hello(False)
                data += chunk
                answer = read_server_hello(data)
                if answer is not None:
                    return answer
                if len(data) > 1 << 16:
                    raise ProbeError("ServerHello too long")
    except ConnectionResetError:
        return Hello(False)
    except TimeoutError as e:
        raise ProbeError("no answer") from e


def accepts_tls13(host: str, timeout: float = 8, port: int = 443) -> bool | None:
    """True / False, or None when the local OpenSSL cannot offer TLS 1.3 or the server cannot be reached."""
    if not ssl.HAS_TLSv1_3:
        return None
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # only the protocol is tested here; the certificate is checked elsewhere
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock, \
                ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.version() == "TLSv1.3"
    except ssl.SSLError:
        return False
    except OSError:
        return None


def has_forward_secrecy(cipher_name: str, version: str) -> bool:
    """Forward secrecy of a negotiated suite, from its OpenSSL name (TLS 1.3 always has it)."""
    return version == "TLSv1.3" or cipher_name.startswith(("ECDHE", "DHE", "EDH"))

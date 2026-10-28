"""Safety of the tool's own connections.

The audited domain is chosen by whoever runs the tool, but its DNS records,
redirects and certificates are controlled by the domain's owner. Two risks
follow, for the machine that runs the audit:

- the domain (or its mail servers, subdomains, redirects) may point to a
  private address: 127.0.0.1, 10.0.0.0/8, 169.254.169.254 (cloud metadata)...
  The tool would then probe the network it runs in. Connections to
  non-public addresses are refused by default; --allow-private lifts this for
  an audit of internal domains;
- a server may send an endless answer, or send it a byte at a time. Answers
  are read up to a size limit and within a time limit.

DNS rebinding (an address that changes between the check and the connection)
is not fully prevented for HTTP: the check narrows the window, it does not
close it.
"""

from __future__ import annotations

import ipaddress
import socket
import time
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

from .i18n import M

MAX_ANSWER = 2_000_000  # bytes read from a server of the audited domain
ANSWER_DEADLINE = 60  # seconds to read an answer, whatever the server's pace


class PrivateAddress(OSError):
    """A connection to a non-public address was refused."""


def is_public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def check_public(host: str, port: int = 443) -> None:
    """Raise PrivateAddress if host is, or resolves to, a non-public address. Unresolvable names pass
    (the connection will fail on its own)."""
    host = (host or "").strip("[]")
    try:
        addresses = {str(info[4][0]) for info in socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)}
    except (OSError, UnicodeError):
        return
    private = sorted(a for a in addresses if not is_public(a))
    if private:
        raise PrivateAddress(M("{host} points to a private or reserved address ({addresses}): not contacted "
                               "(use --allow-private to audit internal domains)", host=host,
                               addresses=", ".join(private)))


class GuardedAdapter(HTTPAdapter):
    """Checks the address of every request, including each redirect, before connecting."""

    def send(self, request, *args, **kwargs):
        parsed = urlparse(request.url)
        try:
            check_public(parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80))
        except PrivateAddress as e:
            raise requests.ConnectionError(str(e), request=request) from e
        return super().send(request, *args, **kwargs)


def session(allow_private: bool = False) -> requests.Session:
    s = requests.Session()
    if not allow_private:
        adapter = GuardedAdapter()
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    return s


def read_limited(response: requests.Response, max_bytes: int = MAX_ANSWER,
                 deadline: float = ANSWER_DEADLINE) -> requests.Response:
    """Read a streamed answer up to max_bytes and within deadline seconds, then close the connection.

    Afterwards response.content / .text / .json() work as usual, on what was read.
    """
    chunks: list[bytes] = []
    size, end = 0, time.monotonic() + deadline
    try:
        for chunk in ([] if max_bytes <= 0 else _pieces(response)):
            chunks.append(chunk)
            size += len(chunk)
            if size >= max_bytes or time.monotonic() > end:
                break
    except (requests.RequestException, OSError, ValueError):
        if not chunks:
            raise
    finally:
        response.close()
    response._content = b"".join(chunks)[:max_bytes]
    response._content_consumed = True  # type: ignore[attr-defined]
    return response


def _pieces(response: requests.Response):
    """The answer's bytes as they arrive (a slow server cannot hold a read longer than one network timeout)."""
    raw = response.raw
    read1 = getattr(raw, "read1", None)  # urllib3 2: returns what is available instead of waiting for a full chunk
    if read1 is None:
        yield from response.iter_content(chunk_size=1024)
        return
    while True:
        piece = read1(16_384, decode_content=True)
        if not piece:
            return
        yield piece

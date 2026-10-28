"""Safety of the tool's own connections: private addresses refused, answers bounded."""

from __future__ import annotations

import http.server
import threading
import time

import pytest
import requests

from domaincheck import cli, netguard
from domaincheck.audit import InvalidDomain, run_audit
from domaincheck.collector import Collector
from domaincheck.netguard import PrivateAddress, check_public, is_public, read_limited


@pytest.mark.parametrize("address, public", [
    ("8.8.8.8", True), ("2606:4700:4700::1111", True),
    ("127.0.0.1", False), ("10.1.2.3", False), ("192.168.1.1", False), ("172.16.0.1", False),
    ("169.254.169.254", False), ("100.64.0.1", False), ("0.0.0.0", False), ("::1", False), ("fd00::1", False),
    ("fe80::1%eth0", False), ("::ffff:127.0.0.1", False), ("224.0.0.1", False), ("not an address", False),
])
def test_is_public(address, public):
    assert is_public(address) is public


def test_check_public():
    with pytest.raises(PrivateAddress, match="127.0.0.1"):
        check_public("127.0.0.1")
    with pytest.raises(PrivateAddress):
        check_public("localhost")
    check_public("name.that.does.not.exist.invalid")  # unresolvable: the connection fails on its own


@pytest.fixture
def server():
    """A local web server: /redirect sends to /, /big sends 10 MB, /slow sends a byte every 0.2 s."""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server API
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                return
            self.send_response(200)
            self.end_headers()
            if self.path == "/big":
                for _ in range(10):
                    self.wfile.write(b"x" * 1_000_000)
            elif self.path == "/slow":
                try:
                    for _ in range(100):
                        self.wfile.write(b"y")
                        self.wfile.flush()
                        time.sleep(0.2)
                except OSError:
                    pass
            else:
                self.wfile.write(b"hello")

        def log_message(self, *args):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_guarded_session_refuses_private_addresses(server):
    with pytest.raises(requests.ConnectionError, match="private or reserved address"):
        netguard.session().get(server + "/")
    assert netguard.session(allow_private=True).get(server + "/").text == "hello"


def test_redirects_are_checked_too(server, monkeypatch):
    checked = []
    monkeypatch.setattr(netguard, "check_public", lambda host, port=443: checked.append((host, port)))
    r = netguard.session().get(server + "/redirect")
    assert r.text == "hello" and len(checked) == 2  # the first address and the redirect target


def test_size_limit(server):
    r = read_limited(requests.get(server + "/big", stream=True), max_bytes=100_000)
    assert len(r.content) == 100_000


def test_time_limit(server):
    start = time.monotonic()
    r = read_limited(requests.get(server + "/slow", stream=True, timeout=5), deadline=1)
    assert time.monotonic() - start < 3 and 0 < len(r.content) < 20


def test_no_body_needed(server):
    r = read_limited(requests.get(server + "/big", stream=True), max_bytes=0)
    assert r.content == b"" and r.status_code == 200


def test_collector_refuses_private_servers():
    c = Collector(timeout=2)
    assert c.certificate("127.0.0.1") is None
    assert "private or reserved" in str(c.tls_scan("localhost").error)
    (mail,) = c.mail_servers(["localhost"])
    assert not mail.reachable and "private or reserved" in str(mail.error)
    (sub,) = c.audit_subdomains(["localhost"])
    assert "private or reserved" in str(sub.error) and not sub.https


def test_audit_of_a_domain_pointing_to_a_private_address(monkeypatch):
    class Fake(Collector):
        def check_exists(self, domain):
            pass

    monkeypatch.setattr(netguard.socket, "getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.0.0.5", 443))])
    with pytest.raises(InvalidDomain, match="10.0.0.5"):
        run_audit("intranet.example.com", collector=Fake(timeout=1))


def test_cli_option(monkeypatch, tmp_path):
    seen = {}
    monkeypatch.setattr(cli, "run_audit", lambda domain, **options: seen.update(options) or (_ for _ in ()).throw(
        InvalidDomain("stop")))
    cli.main(["intranet.example.com", "--allow-private", "-o", str(tmp_path / "r.html")])
    assert seen == {"allow_private": True}

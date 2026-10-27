"""DKIM: keys found, their strength, and the sending services named in SPF."""

from __future__ import annotations

import base64

import pytest

from domaincheck.collector import DKIM_SELECTORS, Collector
from domaincheck.email_checks import SENDERS, check_dkim, dkim_key_bits, spf_senders
from domaincheck.models import Status


def record(bits: int) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    der = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}"


@pytest.fixture(scope="module")
def keys():
    return {bits: record(bits) for bits in (1024, 2048)}


def test_key_size(keys):
    assert dkim_key_bits(keys[2048]) == 2048
    assert dkim_key_bits(keys[1024]) == 1024
    assert dkim_key_bits("v=DKIM1; k=rsa; p=") == 0  # revoked
    assert dkim_key_bits("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=") is None
    assert dkim_key_bits("v=DKIM1; p=not base64!") is None


def test_every_sender_selector_is_tested():
    assert {sel for _, _, sels in SENDERS for sel in sels} <= set(DKIM_SELECTORS)


def test_senders_from_spf():
    spf = ["v=spf1 include:_spf.google.com include:sendgrid.net include:amazonses.com ~all", "google-site=x"]
    assert spf_senders(spf) == [("Google Workspace", ["google"]), ("SendGrid", ["s1", "s2"]), ("Amazon SES", [])]
    assert spf_senders(["v=spf1 include:eu.zoho.eu -all"]) == [("Zoho Mail", ["zoho", "zmail"])]
    assert spf_senders(["v=spf1 -all"]) == []


def test_strong_key(keys):
    (f,) = check_dkim(["google"], DKIM_SELECTORS, {"google": keys[2048]})
    assert f.status == Status.OK and "google (RSA 2048)" in f.detail


def test_short_key(keys):
    (f,) = check_dkim(["selector1"], DKIM_SELECTORS, {"selector1": keys[1024]})
    assert (f.status, f.points) == (Status.WARNING, -5)


def test_broken_key(monkeypatch):
    from domaincheck import email_checks

    monkeypatch.setattr(email_checks, "dkim_key_bits", lambda text: 512)  # too weak to be generated here
    (f,) = check_dkim(["old"], DKIM_SELECTORS, {"old": "v=DKIM1; p=..."})
    assert (f.status, f.points) == (Status.CRITICAL, -20)


def test_no_key_with_known_senders():
    (f,) = check_dkim([], DKIM_SELECTORS, {}, [("Google Workspace", ["google"]), ("Amazon SES", [])])
    assert f.status == Status.INFO and f.points is None
    assert "(Google Workspace)" in f.detail and "probably not enabled" in f.detail


def test_sender_without_its_key(keys):
    findings = check_dkim(["google"], DKIM_SELECTORS, {"google": keys[2048]},
                          [("Google Workspace", ["google"]), ("SendGrid", ["s1", "s2"]), ("Postmark", [])])
    assert [f.title for f in findings] == ["DKIM (email signing)", "DKIM for each sending service"]
    assert "SendGrid" in findings[1].detail and "Postmark" not in findings[1].detail


def test_old_call_still_works():
    assert check_dkim(["google"], ["google"])[0].status == Status.OK


def test_collector_keeps_the_records(monkeypatch):
    c = Collector()
    monkeypatch.setattr(c, "txt", lambda name: ["v=DKIM1; p=abc"] if name.startswith(("google.", "s1.")) else
                        ["unrelated"])
    assert c.dkim_keys("example.com") == {"google": "v=DKIM1; p=abc", "s1": "v=DKIM1; p=abc"}
    assert c.dkim_selectors("example.com") == ["google", "s1"]

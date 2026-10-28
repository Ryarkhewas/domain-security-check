"""Follow-up mode: alerts, webhook and email."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from domaincheck import alerts, cli
from domaincheck.alerts import AlertError, compute, email_settings, send_email, send_webhook, text
from domaincheck.audit import run_audit
from domaincheck.demo import DemoCollector
from domaincheck.history import Changes, FindingChange, GradeChange


def demo():
    return run_audit("bakery-example.com", collector=DemoCollector())


def messages(found):
    return [(a.level, str(a.message)) for a in found]


def test_first_audit_reports_critical_problems_and_expiry():
    found = messages(compute(demo()))
    assert ("critical", "Critical problem: Forgotten subdomains (CT logs).") in found
    expiry = "HTTPS certificate: The certificate expires in"
    assert any(level == "warning" and m.startswith(expiry) for level, m in found)


def test_changes_since_the_previous_audit():
    r = demo()
    r.changes = Changes(datetime(2026, 10, 20, tzinfo=timezone.utc),
                        grades=[GradeChange("OVERALL", "C", "F"), GradeChange("TLS", "A", "B"),
                                GradeChange("EMAIL", "D", "C")],
                        new=[FindingChange("DNS", "Forgotten subdomains (CT logs)", "", "critical")],
                        worse=[FindingChange("WEB", "HSTS", "ok", "warning")])
    found = messages(compute(r))
    assert ("critical", "Overall grade went down from C to F.") in found
    assert ("warning", "Certificate & TLS grade went down from A to B.") in found
    assert not any("Email grade" in m for _, m in found)  # it went up
    assert ("critical", "New problem: Forgotten subdomains (CT logs).") in found
    assert ("warning", "Got worse: HSTS.") in found
    assert not any(m.startswith("Critical problem") for _, m in found)  # only what changed


def test_nothing_changed():
    r = demo()
    r.changes = Changes(datetime(2026, 10, 20, tzinfo=timezone.utc))
    assert [m for _, m in messages(compute(r)) if "expires" not in m] == []


def test_text_in_french():
    from domaincheck.cli import _translator

    body = text(compute(demo()), _translator("fr"))
    assert body.startswith("Audit de sécurité :") and "[!!] Problème critique :" in body


def test_webhook(monkeypatch):
    sent = {}

    class Answer:
        def raise_for_status(self):
            pass

    monkeypatch.setattr(alerts.requests, "post", lambda url, json, timeout: sent.update(url=url, json=json) or Answer())
    send_webhook("https://hooks.example/abc", "hello")
    assert sent == {"url": "https://hooks.example/abc", "json": {"text": "hello", "content": "hello"}}

    def down(*args, **kwargs):
        raise alerts.requests.ConnectionError("down")

    monkeypatch.setattr(alerts.requests, "post", down)
    with pytest.raises(AlertError, match="webhook"):
        send_webhook("https://hooks.example/abc", "hello")


def test_email_settings():
    with pytest.raises(AlertError, match="DSC_SMTP_HOST, DSC_ALERT_FROM"):
        email_settings({"DSC_ALERT_TO": "a@example.com"})
    settings = email_settings({"DSC_SMTP_HOST": "smtp.example.com", "DSC_ALERT_FROM": "audit@example.com",
                               "DSC_ALERT_TO": "a@example.com, b@example.com"})
    assert settings["DSC_SMTP_PORT"] == ""


def test_email_uses_starttls(monkeypatch):
    calls = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            calls.append(("connect", host, port))

        def starttls(self, context):
            calls.append(("starttls",))

        def login(self, user, password):
            calls.append(("login", user))

        def send_message(self, message):
            calls.append(("send", message["To"], message["Subject"]))

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(alerts.smtplib, "SMTP", FakeSMTP)
    send_email("Subject", "Body", {"DSC_SMTP_HOST": "smtp.example.com", "DSC_SMTP_PORT": "", "DSC_SMTP_USER": "u",
                                   "DSC_SMTP_PASSWORD": "p", "DSC_ALERT_FROM": "audit@example.com",
                                   "DSC_ALERT_TO": "a@example.com, b@example.com"})
    assert calls == [("connect", "smtp.example.com", 587), ("starttls",), ("login", "u"),
                     ("send", "a@example.com, b@example.com", "Subject")]


def test_cli_follow_up(tmp_path, monkeypatch, capsys):
    out = tmp_path / "r.html"
    assert cli.main(["--demo", "-o", str(out)]) == 0  # without --alert: normal exit code
    assert cli.main(["--demo", "--alert", "-o", str(out)]) == 4  # the certificate still expires soon
    err = capsys.readouterr().err
    assert "HTTPS certificate" in err and "Critical problem" not in err  # second audit: only what changed


def test_cli_webhook_from_the_environment(tmp_path, monkeypatch, capsys):
    sent = []

    class Answer:
        def raise_for_status(self):
            pass

    monkeypatch.setattr(alerts.requests, "post", lambda url, json, timeout: sent.append(url) or Answer())
    monkeypatch.setenv("DSC_WEBHOOK_URL", "https://hooks.example/secret")
    assert cli.main(["--demo", "--alert", "--lang", "fr", "-o", str(tmp_path / "r.html")]) == 4
    assert sent == ["https://hooks.example/secret"]
    assert "Alertes envoyées au webhook." in capsys.readouterr().err


def test_cli_email_without_settings(tmp_path, monkeypatch, capsys):
    for key in alerts.EMAIL_SETTINGS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.delenv("DSC_WEBHOOK_URL", raising=False)
    assert cli.main(["--demo", "--email-alert", "-o", str(tmp_path / "r.html")]) == 1
    assert "missing setting" in capsys.readouterr().err

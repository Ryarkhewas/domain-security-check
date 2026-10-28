"""Alerts for a regular follow-up: what got worse since the previous audit, and what is about to expire.

Run the tool on a schedule (cron, GitHub Actions, a Docker container...) with
--alert: it compares each domain with its previous audit in the same folder,
prints the alerts, sends them to a chat webhook and/or by email if asked, and
ends with exit code 4 when there is at least one alert.

An alert is raised for:
- a grade that went down (overall or one area);
- a new problem, or a problem that got worse (critical alerts for critical problems);
- on the first audit of a domain, every critical problem;
- at every audit, a certificate or a domain name that expires soon.

Email settings come from environment variables, never from the command line
(it would leave the password in the shell history):
DSC_SMTP_HOST, DSC_SMTP_PORT (587 by default, 465 for SSL), DSC_SMTP_USER,
DSC_SMTP_PASSWORD, DSC_ALERT_FROM, DSC_ALERT_TO (comma-separated).
"""

from __future__ import annotations

import os
import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage

import requests

from .i18n import M
from .models import Category, Result, Status
from .scoring import GRADE_ORDER

EXPIRY_TITLES = {"HTTPS certificate", "Domain expiry date"}
AREA_LABELS = {"OVERALL": "Overall", "WEB": "Website", "TLS": "Certificate & TLS", "EMAIL": "Email",
               "DNS": "Domain & DNS"}
EMAIL_SETTINGS = ["DSC_SMTP_HOST", "DSC_SMTP_PORT", "DSC_SMTP_USER", "DSC_SMTP_PASSWORD", "DSC_ALERT_FROM",
                  "DSC_ALERT_TO"]


class AlertError(RuntimeError):
    """An alert could not be sent."""


@dataclass
class Alert:
    domain: str
    level: str  # "critical" or "warning"
    message: str  # translatable (Message)


def _worse_grade(old: str, new: str) -> bool:
    return old in GRADE_ORDER and new in GRADE_ORDER and GRADE_ORDER.index(new) > GRADE_ORDER.index(old)


def compute(r: Result) -> list[Alert]:
    """Alerts for one audited domain (compared with its previous audit, when there is one)."""
    alerts: list[Alert] = []
    titles = {(f.category.name, str(f.title)): f for f in r.findings}
    if r.changes is not None:
        for g in r.changes.grades:
            if _worse_grade(g.old, g.new):
                alerts.append(Alert(r.domain, "critical" if g.new in ("D", "D-", "F") else "warning",
                                    M("{area} grade went down from {old} to {new}.", area=M(AREA_LABELS[g.key]),
                                      old=g.old, new=g.new)))
        for change, is_new in ((r.changes.new, True), (r.changes.worse, False)):
            for c in change:
                if c.new not in (Status.CRITICAL.value, Status.WARNING.value):
                    continue
                f = titles.get((c.category, c.title))
                if f is not None and str(f.title) in EXPIRY_TITLES:
                    continue  # reported below, at every audit
                title = f.title if f is not None else c.title
                message = M("New problem: {title}.", title=title) if is_new else M("Got worse: {title}.", title=title)
                alerts.append(Alert(r.domain, "critical" if c.new == Status.CRITICAL.value else "warning", message))
    else:
        alerts += [Alert(r.domain, "critical", M("Critical problem: {title}.", title=f.title))
                   for f in r.findings if f.status == Status.CRITICAL and str(f.title) not in EXPIRY_TITLES]
    for f in r.findings:
        if str(f.title) in EXPIRY_TITLES and f.status in (Status.CRITICAL, Status.WARNING) \
                and f.category in (Category.TLS, Category.DNS):
            alerts.append(Alert(r.domain, f.status.value, M("{title}: {detail}", title=f.title, detail=f.detail)))
    return alerts


def text(alerts: list[Alert], t) -> str:
    """Plain text of the alerts, grouped by domain, translated with t."""
    lines = [t("Security audit: {count} alert(s)", count=len(alerts))]
    for domain in dict.fromkeys(a.domain for a in alerts):
        lines.append("")
        lines.append(domain)
        lines += [f"  {'[!!]' if a.level == 'critical' else '[!]'} {t(a.message)}" for a in alerts
                  if a.domain == domain]
    return "\n".join(lines)


def send_webhook(url: str, body: str, timeout: float = 15) -> None:
    """POST the alerts to a chat webhook: "text" for Slack, Mattermost, Google Chat; "content" for Discord."""
    try:
        r = requests.post(url, json={"text": body, "content": body[:1900]}, timeout=timeout)
        r.raise_for_status()
    except requests.RequestException as e:
        raise AlertError(f"webhook: {e}") from e


def email_settings(env: dict[str, str] | None = None) -> dict[str, str]:
    """The DSC_* email settings; raise AlertError naming the missing ones."""
    env = dict(os.environ if env is None else env)
    required = ["DSC_SMTP_HOST", "DSC_ALERT_FROM", "DSC_ALERT_TO"]
    missing = [k for k in required if not env.get(k)]
    if missing:
        raise AlertError("email: missing setting(s) " + ", ".join(missing))
    return {k: env.get(k, "") for k in EMAIL_SETTINGS}


def send_email(subject: str, body: str, settings: dict[str, str], timeout: float = 30) -> None:
    message = EmailMessage()
    message["Subject"], message["From"] = subject, settings["DSC_ALERT_FROM"]
    message["To"] = ", ".join(a.strip() for a in settings["DSC_ALERT_TO"].split(",") if a.strip())
    message.set_content(body)
    port = int(settings.get("DSC_SMTP_PORT") or 587)
    context = ssl.create_default_context()
    try:
        if port == 465:
            server: smtplib.SMTP = smtplib.SMTP_SSL(settings["DSC_SMTP_HOST"], port, timeout=timeout, context=context)
        else:
            server = smtplib.SMTP(settings["DSC_SMTP_HOST"], port, timeout=timeout)
            server.starttls(context=context)  # never send the password in clear text
        with server:
            if settings.get("DSC_SMTP_USER"):
                server.login(settings["DSC_SMTP_USER"], settings.get("DSC_SMTP_PASSWORD", ""))
            server.send_message(message)
    except (OSError, smtplib.SMTPException) as e:
        raise AlertError(f"email: {e}") from e

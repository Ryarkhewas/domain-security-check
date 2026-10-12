# domain-security-check

[![Tests](https://github.com/Ryarkhewas/domain-security-check/actions/workflows/tests.yml/badge.svg)](https://github.com/Ryarkhewas/domain-security-check/actions/workflows/tests.yml) [![Live check](https://github.com/Ryarkhewas/domain-security-check/actions/workflows/live-check.yml/badge.svg)](https://github.com/Ryarkhewas/domain-security-check/actions/workflows/live-check.yml)

**Passive security audit of a domain name, with a clear report for non-specialists.**

In a single command, the tool checks what anyone can see from the Internet about a domain: is the website properly protected with HTTPS, does the server send the right security headers, and above all, **can someone send emails pretending to be the company?** It produces an HTML report graded from A to F, with concrete actions to take.

![Report preview](examples/preview.png)

## What is checked

| Area | Checks |
|---|---|
| **Website** | Valid certificate and expiry date, TLS version, HTTP to HTTPS redirect |
| **Security headers** | HSTS, Content-Security-Policy, clickjacking protection, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, software version disclosure |
| **Email** | MX servers, SPF (presence, `all` rule, 10 DNS lookup limit), DMARC (policy, coverage, reports), DKIM (common selectors) |

Each item is rated **Critical**, **To improve**, **Compliant** or **Info**, with a plain-language recommendation.

## A strictly passive audit

The tool only does what any visitor or mail server does: public DNS lookups, an HTTPS connection and one request to the home page. **No port scanning, no intrusion testing.**

Even passive, an audit should only be run **on your own domains or with the owner's permission**.

## Installation

```bash
git clone https://github.com/Ryarkhewas/domain-security-check.git
cd domain-security-check
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
# Audit a domain (report in reports/<domain>.html)
python domain_check.py my-domain.com

# Choose the output file and sign the report
python domain_check.py my-domain.com -o reports/client.html --author "Your Name"

# JSON output (to feed another tool)
python domain_check.py my-domain.com --json

# Demo on a fictitious domain, without network access
python domain_check.py --demo
```

A full URL is accepted (`https://www.my-domain.com/contact`): the tool extracts the domain. Email checks run on the main domain, even if you enter `www.`.

## Reliable diagnosis

If a DNS query fails (network outage, timeout), the audit **stops without producing a report** rather than wrongly concluding "no SPF" or "no DMARC". A missing record and a check that could not be performed are two different things.

For DKIM, there is no way to list all of a domain's keys: the tool tests the most common selectors. Finding nothing is reported as information, not as a flaw.

## Scoring

The score starts at 100: −20 per critical item, −5 per item to improve.

| Grade | Score | Meaning |
|---|---|---|
| A | 90–100 | Very good configuration |
| B | 75–89 | Solid foundation, a few points to strengthen |
| C | 60–74 | Partial protection |
| D | 40–59 | Significant exposure |
| F | 0–39 | High exposure |

## Project structure

```
domain_check.py             Command line
domaincheck/
  collector.py              Network access (DNS, TLS, HTTP), nothing else
  email_checks.py           MX / SPF / DMARC / DKIM analysis
  web_checks.py             Certificate / redirect / headers analysis
  audit.py                  Orchestration and scoring
  report.py                 HTML report, console summary, JSON
  demo.py                   Fictitious data for the demo
tests/                      63 unit tests + live tests (tests/live)
scripts/live_summary.py     Audits a list of domains for the Live check workflow
```

Collection is kept separate from analysis: every rule can be tested on fixed data, without depending on the Internet.

## Tests

```bash
python -m pytest -q          # 63 unit tests, no network needed
python -m pytest -m live -v  # live tests against real domains (Internet required)
```

Two GitHub Actions workflows keep the tool honest:

- **Tests** runs the unit tests on every push, on Python 3.10 to 3.13.
- **Live check** runs every Monday (and on demand) against real domains:
  - hosts from [badssl.com](https://badssl.com), deliberately misconfigured for testing (expired, self-signed and wrong-host certificates), must be flagged as critical;
  - for github.com, google.com, cloudflare.com and wikipedia.org, the SPF and DMARC records read by the tool must match those returned by an independent resolver (Google DNS-over-HTTPS).

  The results table is published in the workflow summary and the HTML reports are kept as artifacts.

## Limits

The audit does not cover the site's applications (forms, CMS, plugins), workstations or user accounts. It gives an overview of the exposure visible from the Internet at a given date, not a security guarantee.

## License

MIT

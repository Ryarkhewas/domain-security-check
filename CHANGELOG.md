# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [1.0.0] - 2026-10-14

First release.

### Audit
- Passive audit of a domain: public DNS records, the HTTPS certificate, the home page (over HTTPS and HTTP) and `robots.txt`. No port scanning, no intrusion testing.
- Website checks aligned with Mozilla HTTP Observatory: HTTP to HTTPS redirect, HSTS (including the browsers' preload list), Content-Security-Policy, cookies, Subresource Integrity, clickjacking protection, X-Content-Type-Options, Referrer-Policy, Cross-Origin-Resource/Opener/Embedder-Policy. Permissions-Policy and software version disclosure are reported but not scored.
- Certificate & TLS checks: validity, expiry date, TLS version.
- Email checks: MX, SPF (`all` rule, 10 DNS lookup limit), DMARC (policy, coverage, reports, inheritance from the parent domain), DKIM (common selectors).
- Requests look like a current desktop browser, with the tool's name in the User-Agent.
- A failed DNS query stops the audit instead of producing a wrong diagnosis.

### Grades and report
- Three grades (website, certificate & TLS, email) and an overall grade equal to the weakest one. The website grade uses the Observatory scoring; the other two use this project's scales, based on the RFCs.
- Broken HTTPS caps the website grade at F; a domain without a website is graded on email only.
- Standalone HTML report: grades, priority actions, points and cited standard for every item, plain-language recommendations. Console summary and JSON output.

### Installation and quality
- Installable with pip, with a `domain-security-check` command (also `python -m domaincheck`).
- 201 unit tests on Python 3.10 to 3.13, lint (ruff) and type check (mypy) in CI, and a build test of the package.
- Weekly Live check against real domains, including a test-by-test comparison with the Mozilla HTTP Observatory API.

[1.0.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.0.0

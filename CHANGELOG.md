# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

### Fixed
- The domain name no longer gets a capital letter at the start of the expiry sentence ("Bakery-example.com est enregistré…" is now "Le domaine bakery-example.com est enregistré…").

## [1.3.0] - 2026-10-16

### Added
- Domain registration data from the registry (RDAP), in the Domain & DNS grade: expiry date of the domain (expired −50, within 15 days −30, within 30 days −10) and transfer lock (missing −5), with the registrar's name.
- security.txt (RFC 9116): found or not, Contact and Expires fields, expiry. Shown but not scored, like Permissions-Policy, so that the website grade stays aligned with the Observatory.
- Live check: warning when the Observatory reports another version of its scoring algorithm than the one this tool reproduces (version 6).

### Changed
- The Domain & DNS grade can be lower than with 1.2 for domains without a transfer lock.

## [1.2.1] - 2026-10-16

### Fixed
- `--lang fr` failed when the tool was installed with pip (1.2.0): the French translation was missing from the package. It worked only from a clone of the repository. The package test in CI now also runs the French report.

## [1.2.0] - 2026-10-16

### Added
- Reports in French with `--lang fr` (HTML, PDF, summary page, console and command-line messages), including dates, the usual certificate and DNS errors, and the titles of the cited standards. The JSON output stays in English.
- Changes since the previous audit: each result is saved as `<domain>.json` next to the report, and the next audit of the domain shows grades that changed, problems fixed, new problems, and problems that got worse or better. `--previous FILE` compares with any earlier result.
- Several domains are audited at the same time (`--workers`, 6 by default).

### Changed
- Faster Live check (about 2 to 3 minutes instead of 3 min 30 s, depending on how fast the Observatory answers), without skipping anything: audits and Observatory scans run in parallel, and live tests audit each domain once.

## [1.1.0] - 2026-10-14

### Added
- Fourth grade, **Domain & DNS**: DNSSEC (enabled, and DS record consistent with the domain's keys) and CAA (allowed certificate authorities, looked up on the domain and its parents).
- Email: MTA-STS (record, policy file, mode, coverage of the mail servers) and TLS reporting (shown, not scored).
- Several domains in one run (`domain-security-check a.com b.fr`, or `--file domains.txt`), with an `index.html` summary page; `--output-dir` chooses the folder, and `--json` prints `{"results": [...], "errors": {...}}`.
- PDF report with `--pdf` (optional dependency: `pip install "domain-security-check[pdf]"`).

### Changed
- The overall grade is now the weakest of four grades instead of three: with the new DNS checks, a domain can get a lower overall grade than with 1.0.0.
- The `<meta name="referrer">` tag of the home page is taken into account, as browsers and the Observatory do.
- DNSSEC queries are retried through public resolvers when the local resolver refuses them.

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

[1.3.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.3.0
[1.2.1]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.2.1
[1.2.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.2.0
[1.1.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.1.0
[1.0.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.0.0

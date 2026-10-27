# Changelog

All notable changes to this project are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[semantic versioning](https://semver.org/).

## [Unreleased]

## [1.7.0] - 2026-10-27

### Added
- Grades over time: each audit adds a line to `<domain>.history.json`, and from the second audit on the HTML and PDF reports show a chart of the four scores, with a table of the values (started from the previous `<domain>.json` when there is one).
- Docker images (`ghcr.io/ryarkhewas/domain-security-check`, and a `browser` variant with Chromium for `--browser`), built and tested on every push, published with each release.
- PyPI publishing from the Release workflow (trusted publishing, enabled by the `PUBLISH_TO_PYPI` repository variable); the package is checked with `twine check` on every push, and the README links are absolute so that it also displays on PyPI.
- CAA and the certificate in use: when CAA does not allow the authority that issued the current certificate, its renewal will be refused (−10, Domain & DNS). Wildcard certificates are compared with `issuewild` when present.
- DKIM: about 50 selectors (looked up in parallel), including the usual ones of the sending services named in SPF (Google Workspace, Microsoft 365, SendGrid, Mailgun, Mailchimp, Zoho, Proton Mail…); key strength (RSA under 1024 bits −20, 1024 bits −5); services named in SPF without their usual key are listed.
- Trackers before consent (not scored): advertising and analytics services (Google Analytics, Google Ads, Meta, LinkedIn, TikTok, Hotjar, Clarity…) loaded by the page without waiting for consent, tracker cookies set at the first visit, and the consent banner service recognised. `--browser` loads the page in headless Chromium without clicking anything, to see what is really contacted (optional dependency: `pip install "domain-security-check[browser]"`, then `playwright install chromium`).

### Changed
- The Email grade can be lower than with 1.6 for domains with short DKIM keys, and the Domain & DNS grade when CAA would block the renewal of the certificate.

## [1.6.0] - 2026-10-26

### Added
- Outdated software: WordPress, Joomla, Drupal, TYPO3, PrestaShop and PHP are recognised on the home page (generator tag, X-Generator and X-Powered-By headers, WordPress file addresses), and their support status is read from endoflife.date (cached for three days): unsupported version critical, update available warning. Not scored, so that the website grade stays the Observatory's, but listed among the priority actions.
- `--subdomains`: every subdomain in use found in the CT logs is checked like a visitor would see it: HTTPS, certificate, HTTP to HTTPS redirect, TLS 1.0/1.1 still accepted, outdated software. Not scored; listed among the priority actions.
- `--nis2`: a NIS 2 view in the HTML and PDF reports, linking each check to the measures of article 21(2) of Directive (EU) 2022/2555, with the problems found, and the measures that cannot be seen from outside. Presented as a reading grid, not a compliance assessment.

## [1.5.0] - 2026-10-18

### Added
- Mail servers: each MX is contacted on port 25 like a sending server (EHLO, STARTTLS, TLS handshake, QUIT; no email sent). STARTTLS missing −20, obsolete TLS −10, invalid certificate −5 (−30 with MTA-STS in enforce mode), DANE records shown. When port 25 is blocked, the report says nothing could be concluded. `--no-mail-servers` skips this step.
- Summary for decision makers at the top of the HTML and PDF reports (and in the console): main risks in business terms, number of quick fixes / few-hour fixes / projects, and the overall grade after the quick fixes. Each priority action shows its impact and effort, and the list is ordered by impact, then effort.
- Branded reports: `--company`, `--contact`, `--client`, `--logo`, `--color`, or a JSON file with `--brand`. The PDF gets a cover page (logo, client, overall grade, auditor, contact, confidentiality note), the accent colour and the company in the footer; the HTML report ends with the same details.

### Changed
- The Email grade can be lower than with 1.4, because of the new mail server checks.
- When crt.sh does not answer and the subdomains come from Cert Spotter, the report says the list may be incomplete (Cert Spotter may list fewer old certificates) and suggests running the audit again later.

## [1.4.0] - 2026-10-17

### Added
- Deeper TLS checks: protocol versions accepted by the server (SSL 3.0 to TLS 1.3), broken cipher suites (RC4, 3DES, export, no encryption, no authentication), forward secrecy, size of the certificate key. Old protocols and ciphers are tested with a hand-built ClientHello, since the local OpenSSL no longer offers them.
- Forgotten subdomains: names published in Certificate Transparency logs (crt.sh, Cert Spotter as fallback), each looked up in DNS. A CNAME pointing to a deleted resource at a provider open to takeover (Azure, AWS, Heroku, Netlify…) is critical (−30); another dangling record is a warning (−10). `--no-ct-logs` skips this check.
- Fixes for the platform in use: the web server or hosting platform (Apache, nginx, IIS, LiteSpeed, Cloudflare, Netlify, Vercel, GitHub Pages), the DNS host and the email provider are recognised, and each problem comes with the configuration line or the menu to open, with a link to the provider's documentation.
- Each item of the report now cites the matching ANSSI recommendation next to the standard, when there is one (website guide PA-009, TLS guide, Internet gateway guide PA-066, domain name guide BP-038), with the guide's version and date. The standard comes under "Source:", the guides under "See also:", so that a "Compliant" item does not read as "complies with ANSSI". HTML and PDF reports, in English and French.
- The CNIL security guide (2024, sheet "Sécuriser les sites web") is also cited, under "See also:", for the certificate, the TLS version, the HTTPS redirect and cookies.
- The Limits paragraph of the report says that the ANSSI citations show what each check relates to, and that the report is not a certificate of compliance.

### Changed
- The transfer lock cites RFC 5731 (domain statuses) instead of RFC 9083.
- The Certificate & TLS and Domain & DNS grades can be lower than with 1.3, because of the new checks.
- New dependency: `cryptography`, to read the certificate's key.

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

[1.7.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.7.0
[1.6.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.6.0
[1.5.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.5.0
[1.4.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.4.0
[1.3.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.3.0
[1.2.1]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.2.1
[1.2.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.2.0
[1.1.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.1.0
[1.0.0]: https://github.com/Ryarkhewas/domain-security-check/releases/tag/v1.0.0

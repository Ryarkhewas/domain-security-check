# domain-security-check

[![Tests](https://github.com/Ryarkhewas/domain-security-check/actions/workflows/tests.yml/badge.svg)](https://github.com/Ryarkhewas/domain-security-check/actions/workflows/tests.yml) [![Live check](https://github.com/Ryarkhewas/domain-security-check/actions/workflows/live-check.yml/badge.svg)](https://github.com/Ryarkhewas/domain-security-check/actions/workflows/live-check.yml)

**Passive security audit of a domain name, with a clear report for non-specialists.**

In a single command, the tool checks what anyone can see from the Internet about a domain: is the website properly protected with HTTPS, does the server send the right security headers, and above all, **can someone send emails pretending to be the company?** It produces an HTML report (and, if you want, a PDF) with a grade per area (website, certificate, email, DNS), the points behind each grade, the standard each check relies on, and concrete actions to take. Several domains can be audited at once, with a summary page. Reports exist in English and French, and each new audit of a domain shows what changed since the previous one.

![Report preview](https://raw.githubusercontent.com/Ryarkhewas/domain-security-check/main/examples/preview.png)

Example reports: [HTML](https://github.com/Ryarkhewas/domain-security-check/blob/main/examples/demo_report.html) and [PDF](https://github.com/Ryarkhewas/domain-security-check/blob/main/examples/demo_report.pdf), the same in French: [PDF](https://github.com/Ryarkhewas/domain-security-check/blob/main/examples/demo_report_fr.pdf), and a branded French PDF with a cover page, the subdomain checks and the NIS 2 view: [PDF](https://github.com/Ryarkhewas/domain-security-check/blob/main/examples/demo_report_branded_fr.pdf).

## What is checked

| Area | Checks |
|---|---|
| **Website** | HTTP to HTTPS redirect, HSTS (including the browsers' preload list), Content-Security-Policy, cookies (Secure, HttpOnly, SameSite), Subresource Integrity of external scripts, clickjacking protection, X-Content-Type-Options, Referrer-Policy, Cross-Origin-Resource/Opener/Embedder-Policy; not scored: Permissions-Policy, software version disclosure, security.txt (how to report a vulnerability), outdated software (WordPress, Joomla, Drupal, TYPO3, PrestaShop and PHP recognised on the home page, with their support status), advertising and analytics trackers loaded before consent (Google Analytics, Meta Pixel, Hotjar…) |
| **Certificate & TLS** | Valid certificate, expiry date, key strength; protocol versions accepted (SSL 3.0 to TLS 1.3), broken cipher suites (RC4, 3DES, export, no encryption), forward secrecy |
| **Email** | MX servers, SPF (presence, `all` rule, 10 DNS lookup limit), DMARC (policy, coverage, reports, inheritance from the parent domain for subdomains), DKIM (about 50 common selectors, including those of the sending services named in SPF; key strength: RSA under 2048 bits flagged), MTA-STS (record, policy file, mode, coverage of the mail servers), the mail servers themselves (STARTTLS offered, TLS version, certificate, as a sending server sees them); not scored: TLS reporting (TLS-RPT), DANE records |
| **Domain & DNS** | DNSSEC (enabled, and consistent between the parent zone and the domain's keys), CAA (which certificate authorities may issue certificates, and whether the authority of the certificate in use is one of them), expiry date of the domain and transfer lock (from the registry, through RDAP), forgotten subdomains: names published in Certificate Transparency logs whose DNS record points to a resource that no longer exists (subdomain takeover) |

Each item is rated **Critical**, **To improve**, **Compliant** or **Info**, shows the points it weighs in the grade, cites the standard it is based on (and the matching ANSSI or CNIL recommendation, when there is one), and comes with a plain-language recommendation.

**Optional, for a deeper audit:**
- `--subdomains` also checks every subdomain in use found in the Certificate Transparency logs: HTTPS available, valid certificate, HTTP to HTTPS redirect, TLS 1.0/1.1 still accepted, outdated software. It takes a few requests per subdomain, so it is off by default. These items are not scored (the grades describe the domain itself) but appear among the priority actions.
- `--browser` loads the home page in a real browser (headless Chromium), without clicking anything, to see the trackers that are contacted or set cookies before consent, including those a tag manager adds in JavaScript. Without it, trackers are looked for in the page received only. It needs Playwright: `pip install "domain-security-check[browser]"`, then `playwright install chromium`.
- `--nis2` adds a **NIS 2 view**: for each of the ten measures of article 21(2) of [Directive (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj) (encryption, maintenance and vulnerability handling, cyber hygiene, asset management…), the related checks of the audit and the problems found. Measures that cannot be seen from the Internet (risk analysis, incident handling, supply chain, training…) are shown as such: the table links checks to measures, it is not a compliance assessment.

**Summary for decision makers.** The report opens with the main risks in business terms ("anyone can send emails in the company's name"), the effort needed (quick fixes under 30 minutes, a few hours, or a project needing a developer or a provider) and the overall grade the quick fixes alone would give. Each priority action shows its impact and its effort, and the list starts with what pays off most for the least work.

**Fixes for the platform in use.** The tool recognises the web server or hosting platform (Apache, nginx, IIS, LiteSpeed, Cloudflare, Netlify, Vercel, GitHub Pages) from the HTTP headers, the DNS host from the NS records (OVHcloud, Cloudflare, Gandi, IONOS, Route 53…) and the email provider from the MX records (Google Workspace, Microsoft 365…). Each problem then comes with the configuration line for that server, or the menu to open at that provider (including OVHcloud, Gandi and IONOS for DNS records and DNSSEC), with a link to its documentation.

## A strictly passive audit

The tool only does what any visitor or mail server does: public DNS lookups, HTTPS connections, and requests to the home page (over HTTPS and HTTP) and to `robots.txt`, like Mozilla HTTP Observatory. **No port scanning, no intrusion testing.** It also reads the site's public `security.txt` file and, for email, the MTA-STS policy file when the domain announces one, as any sending mail server does. To check the mail servers, it connects to them on port 25 like a sending server, asks for encryption (STARTTLS), completes the TLS handshake and says goodbye (QUIT): no email is ever sent. Port 25 is blocked by many networks (home connections, cloud providers); the report then says nothing could be concluded, and `--no-mail-servers` skips this step. The registration data of the domain (expiry date, status) comes from the registry's public RDAP service, the successor of WHOIS. The support dates of software versions come from [endoflife.date](https://endoflife.date/) (cached for three days). The other downloads are public lists, each cached for a week: the [HSTS preload list](https://hstspreload.org/) and the [IANA list of RDAP servers](https://data.iana.org/rdap/dns.json). To see which TLS versions and cipher suites the server accepts, it sends a few times the first message of a TLS connection (the ClientHello an old or a current browser would send), reads the server's answer and closes: no key exchange, no data. Subdomains are read from public Certificate Transparency logs ([crt.sh](https://crt.sh/), or [Cert Spotter](https://sslmate.com/certspotter/) when crt.sh does not answer); each one is only looked up in DNS, never contacted. If the local DNS resolver refuses DNSSEC queries (some routers and Linux setups do), those queries are retried through public resolvers (Cloudflare, Quad9, Google).

Requests identify themselves as a current desktop browser, with `domain-security-check` appended to the User-Agent. Some sites answer differently to bots (no HTTPS redirect, missing headers): this way the report shows what real visitors get, while the tool stays identifiable in server logs.

Even passive, an audit should only be run **on your own domains or with the owner's permission**.

## Installation

Requires Python 3.10 or later.

```bash
# From PyPI (once published there, see "Publishing" below)
pip install domain-security-check            # add [pdf], [browser] or [pdf,browser] for the options

# Latest release, straight from GitHub
pip install "git+https://github.com/Ryarkhewas/domain-security-check@v1.7.0"

# With PDF output (add ,browser for --browser)
pip install "domain-security-check[pdf] @ git+https://github.com/Ryarkhewas/domain-security-check@v1.7.0"

# Or from a clone, to work on the code
git clone https://github.com/Ryarkhewas/domain-security-check.git
cd domain-security-check
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

The wheel and source archive of each version are also attached to the [GitHub releases](https://github.com/Ryarkhewas/domain-security-check/releases).

**With Docker**, nothing to install but Docker. Reports (and the history of each domain) are written to the folder mounted on `/reports`:

```bash
docker run --rm -v "$PWD/reports:/reports" ghcr.io/ryarkhewas/domain-security-check example.com --pdf --lang fr
# With a real browser for --browser (larger image)
docker run --rm -v "$PWD/reports:/reports" ghcr.io/ryarkhewas/domain-security-check:browser example.com --browser
```

The images are published with each release (`latest` and the version number, plus `browser` and `<version>-browser`), and can be built from the repository with `docker build -t domain-security-check .` (add `--target browser` for the larger one).

## Usage

```bash
# Audit a domain (report in reports/<domain>.html)
domain-security-check my-domain.com

# Choose the output file and sign the report
domain-security-check my-domain.com -o reports/client.html --author "Your Name"

# Also produce a PDF (install the extra first: pip install "domain-security-check[pdf]")
domain-security-check my-domain.com --pdf

# Report in French
domain-security-check my-domain.com --lang fr

# Several domains: one report each, plus reports/index.html to compare them
domain-security-check client-a.com client-b.fr client-c.org
domain-security-check --file domains.txt --output-dir reports/clients

# Branded PDF for a client: cover page with your logo, company and contact
domain-security-check client.fr --pdf --lang fr --brand examples/branding.example.json --client "Client name"
domain-security-check client.fr --pdf --company "Your company" --logo logo.png --color "#0f766e"

# Skip the Certificate Transparency logs (faster: crt.sh can take a minute on large domains)
domain-security-check my-domain.com --no-ct-logs

# Deeper audit: subdomains in use, trackers in a real browser, and the NIS 2 view
domain-security-check client.fr --subdomains --browser --nis2 --pdf --lang fr

# Skip the connections to the mail servers on port 25
domain-security-check my-domain.com --no-mail-servers

# JSON output (to feed another tool)
domain-security-check my-domain.com --json

# Demo on a fictitious domain, without network access
domain-security-check --demo
```

A domain file has one domain per line; blank lines and `#` comments are ignored. Several domains are audited at the same time (6 by default, `--workers` to change it). With several domains, a domain that cannot be audited (DNS failure, invalid name) is listed on the summary page with the reason, the others are still audited, and the command ends with exit code 3.

`python -m domaincheck` works the same way, and so does `python domain_check.py` from a clone, without installing.

A full URL is accepted (`https://www.my-domain.com/contact`): the tool extracts the domain. Email checks run on the main domain, even if you enter `www.`.

## Follow-up and alerts

Audit the same domains on a schedule, into the same folder, with `--alert`: each domain is compared with its previous audit, and the tool lists what needs attention:

- a grade that went down (overall or one area);
- a new problem, or a problem that got worse;
- on the first audit of a domain, every critical problem;
- at every audit, a certificate or a domain name that expires within 30 days.

The command then ends with exit code 4 (3 if a domain could not be audited), so a scheduler can react. The alerts can also be sent:

- to a chat webhook (Slack, Discord, Mattermost, Google Chat): `--webhook URL`, or better the `DSC_WEBHOOK_URL` environment variable, since the URL is a secret;
- by email: `--email-alert`, with the settings in environment variables (never on the command line): `DSC_SMTP_HOST`, `DSC_SMTP_PORT` (587 with STARTTLS by default, 465 for SSL), `DSC_SMTP_USER`, `DSC_SMTP_PASSWORD`, `DSC_ALERT_FROM`, `DSC_ALERT_TO` (comma-separated).

```bash
# Every Monday at 7:00 with cron, from a folder that keeps the reports and history
0 7 * * 1  cd ~/audits && DSC_WEBHOOK_URL=https://hooks.slack.com/... domain-security-check --file domains.txt --alert --pdf --lang fr

# The same with Docker
docker run --rm -v "$HOME/audits:/reports" -e DSC_WEBHOOK_URL ghcr.io/ryarkhewas/domain-security-check --file /reports/domains.txt --alert
```

**With GitHub Actions**, nothing to host: this repository is also a reusable action (`uses: Ryarkhewas/domain-security-check@v1.8.0`, inputs `domains`, `file`, `output-dir`, `args`). The [weekly audit template](https://github.com/Ryarkhewas/domain-security-check/blob/main/examples/monitoring/weekly-audit.yml) audits the domains of a `domains.txt` file every Monday, keeps the history of each domain from one week to the next, sends the alerts to your webhook or mailbox (from the repository's secrets), and marks the run as failed when there is an alert, so GitHub emails you as well. Use it in a private repository: the reports describe your clients' weaknesses.

## Branded reports

With `--company`, `--contact`, `--client`, `--logo` (PNG or JPEG) or `--color`, the PDF starts with a cover page: your logo, the domain, "Prepared for" the client, the date, the overall grade, your name, company and contact, and a confidentiality note. The accent colour is used for the headings, and your company appears in the footer of every page. The HTML report ends with the same details. To avoid typing them each time, put them in a JSON file and pass it with `--brand` ([example](https://github.com/Ryarkhewas/domain-security-check/blob/main/examples/branding.example.json)); command-line values take precedence over the file.

## Changes since the previous audit

Each report is saved with its result in JSON (`<domain>.json`, next to the HTML report). When the same domain is audited again into the same folder, the new report starts with what changed since then: grades that went up or down, problems fixed, new problems, and problems that got worse or better. The summary page of several domains shows it in one column. This is meant for a regular follow-up, for instance a weekly audit of a client's domains.

`--previous FILE` compares a single domain with any earlier JSON result.

**Grades over time.** Every audit also adds a line to `<domain>.history.json` (date, overall grade, grade and score of each area). From the second audit on, the HTML and PDF reports show a chart of the four scores over time, with the values in a table.

## Languages

`--lang fr` produces the HTML report, the PDF, the summary page and the console summary in French. All texts come from one catalog (`domaincheck/locales/fr.py`), and a test checks that every text of the code has its translation. The JSON output always stays in English, as it is meant for other programs.

## Reliable diagnosis

If a DNS query fails (network outage, timeout), the audit **stops without producing a report** rather than wrongly concluding "no SPF" or "no DMARC". A missing record and a check that could not be performed are two different things.

For DKIM, there is no way to list all of a domain's keys: the tool tests about 50 common selectors, including the usual ones of the sending services named in the SPF record (Google Workspace, Microsoft 365, SendGrid, Mailchimp…). Finding nothing is reported as information, not as a flaw; when a service named in SPF has none of its usual keys, the report says DKIM is probably not enabled there.

## Grades

The report gives **four grades**, one per area, and an **overall grade equal to the weakest of the four**: a site is only as safe as its weakest point.

| Area | How it is graded |
|---|---|
| **Website** | The [Mozilla HTTP Observatory](https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring) algorithm, with its official score modifiers: start at 100, apply the penalties, and add bonuses only if the score is still 90 or more. |
| **Certificate & TLS** | This project's scale, based on RFC 8996 and RFC 9325: −100 for a missing, invalid or expired certificate, −30 for a connection negotiated in TLS 1.0/1.1, SSL 3.0 accepted, a key that is too short (RSA under 2048 bits) or a certificate expiring within 15 days, −20 for TLS 1.0/1.1 still accepted or broken cipher suites accepted, −10 for no forward secrecy with current browsers or a certificate expiring within 30 days, −5 for no TLS 1.3 or the RSA key exchange still accepted for old clients. |
| **Email** | This project's scale, based on what the standards define as valid: e.g. no DMARC −40, no SPF −30 (−10 if a strict DMARC policy already stops spoofing), `p=none` −20, `?all` −20, no MTA-STS −5, MTA-STS in enforce mode that leaves out a mail server −30, a mail server without STARTTLS −20, an obsolete TLS version on a mail server −10, invalid mail server certificates −5 (−30 if MTA-STS is in enforce mode: senders that apply it refuse to deliver). |
| **Domain & DNS** | This project's scale, kept moderate since many large sites still do without these: DNSSEC not enabled −15, broken DNSSEC −50 (resolvers may refuse the domain), no CAA record −5, domain expiring within 30 days −10 (within 15 days −30, expired −50), no transfer lock −5, a subdomain open to takeover −30 (another dangling DNS record −10). |

All four use the Observatory grade chart (A+ … F, by steps of 5 points); A+ only exists for the website grade, the only one with bonuses.

Each item of the report shows the points it adds or removes, so every grade can be recomputed by hand.

**Broken HTTPS caps the website grade at F.** If the certificate is invalid or expired, or if the site answers over HTTP but not over HTTPS, visitors are not protected whatever the other settings, and the security headers cannot even be checked. A domain with no website at all (mail only) gets "N/A" for the website and TLS grades, and is graded on email and DNS only.

## Methodology

Every check is based on a published standard or guide, cited under each item of the report.

| Check | Reference |
|---|---|
| Content-Security-Policy | [W3C CSP Level 3](https://www.w3.org/TR/CSP3/) |
| HSTS | [RFC 6797](https://www.rfc-editor.org/rfc/rfc6797), [HSTS preload list](https://hstspreload.org/) (Chromium's list, used by all major browsers) |
| Subresource Integrity | [W3C SRI](https://www.w3.org/TR/SRI/) |
| Clickjacking (X-Frame-Options, frame-ancestors) | [RFC 7034](https://www.rfc-editor.org/rfc/rfc7034) |
| X-Content-Type-Options | [WHATWG Fetch](https://fetch.spec.whatwg.org/#x-content-type-options-header) |
| Referrer-Policy | [W3C Referrer Policy](https://www.w3.org/TR/referrer-policy/) |
| Cookies | [RFC 6265](https://www.rfc-editor.org/rfc/rfc6265), [MDN cookie guide](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies) |
| HTTP to HTTPS redirect | [MDN TLS guide](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/TLS#http_redirection) |
| Cross-Origin-Resource / Opener / Embedder-Policy | MDN reference pages |
| Permissions-Policy, version disclosure (not scored) | [W3C Permissions Policy](https://www.w3.org/TR/permissions-policy/), [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) |
| TLS protocol version | [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996) (TLS 1.0 and 1.1 deprecated), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (TLS 1.3) |
| Cipher suites, forward secrecy, key size | [RFC 9325](https://www.rfc-editor.org/rfc/rfc9325) (recommendations for the secure use of TLS) |
| SPF | [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208) |
| DMARC, including subdomain inheritance | [RFC 7489](https://www.rfc-editor.org/rfc/rfc7489) |
| DKIM | [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376), [RFC 8301](https://www.rfc-editor.org/rfc/rfc8301) (RSA keys of at least 1024 bits, 2048 recommended) |
| Domains that receive no email | [RFC 7505](https://www.rfc-editor.org/rfc/rfc7505) (null MX) |
| MTA-STS, TLS reporting | [RFC 8461](https://www.rfc-editor.org/rfc/rfc8461), [RFC 8460](https://www.rfc-editor.org/rfc/rfc8460) |
| Mail servers: STARTTLS, DANE | [RFC 3207](https://www.rfc-editor.org/rfc/rfc3207), [RFC 7672](https://www.rfc-editor.org/rfc/rfc7672); ANSSI PA-066 R42 (STARTTLS on SMTP servers) |
| DNSSEC | [RFC 4033](https://www.rfc-editor.org/rfc/rfc4033) to 4035 |
| CAA | [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659); CAA identifiers published by each authority |
| Trackers before consent (not scored) | [CNIL rules on cookies and other trackers](https://www.cnil.fr/fr/cookies-et-autres-traceurs/regles/cookies) (ePrivacy directive, article 5(3)) |
| Domain registration data (expiry, status) | [RFC 9083](https://www.rfc-editor.org/rfc/rfc9083) (RDAP), [RFC 9224](https://www.rfc-editor.org/rfc/rfc9224) (finding the RDAP server), [RFC 5731](https://www.rfc-editor.org/rfc/rfc5731#section-2.3) (transfer lock status) |
| Forgotten subdomains | [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162) (Certificate Transparency); ANSSI PA-009 R3 recommends watching CT logs |
| Outdated software (not scored) | Support dates from [endoflife.date](https://endoflife.date/); the CNIL website sheet asks to keep components updated |
| security.txt (not scored) | [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) |
| Website scoring | [Mozilla HTTP Observatory](https://github.com/mdn/mdn-http-observatory) (MPL 2.0) |

**ANSSI guides.** For a French audience, each item also cites, when there is one, the matching recommendation of the guides published by [ANSSI](https://cyber.gouv.fr/) (the French national cybersecurity agency). Only recommendation numbers read in the guides themselves are cited; when a topic has no numbered recommendation, the section is cited instead.

| Guide | Cited for |
|---|---|
| [Recommandations pour la mise en œuvre d'un site web](https://cyber.gouv.fr/uploads/2013/05/anssi-guide-recommandations_mise_en_oeuvre_site_web_maitriser_standards_securite_cote_navigateur-v2.0.pdf) (ANSSI-PA-009, v2.0, 2021) | HTTPS redirect and TLS (R1), HSTS (R2), X-Content-Type-Options (R6), Subresource Integrity (R11, R12), CSP (R14 to R16), clickjacking (R17, R18), Referrer-Policy (§5.4), cookies (§5.5.3) |
| [Recommandations de sécurité relatives à TLS](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-recommandations_de_securite_relatives_a_tls-v1.2.pdf) (v1.2, 2020) | TLS version (R3, R4), certificate (R8) |
| [Recommandations relatives à l'interconnexion d'un SI à Internet](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-passerelle_internet_securisee-v3.pdf) (ANSSI-PA-066, v3.0, 2020) | STARTTLS (R42), SPF (R44), DKIM (R46+), DMARC (R48+), DNSSEC of email domains (R50+), MTA-STS, TLS reporting and DANE (§5.3) |
| [Bonnes pratiques pour l'acquisition et l'exploitation de noms de domaine](https://messervices.cyber.gouv.fr/documents-guides/guide_dns_fr_anssi_1.3.pdf) (ANSSI-BP-038, v1.3, 2017) | transfer lock (R1, R3+), DNSSEC (R4+), domain expiry (§4.10) |

The [CNIL](https://www.cnil.fr/) (the French data protection authority) is also cited for the few topics its sheet [Sécuriser les sites web](https://www.cnil.fr/fr/securite-securiser-les-sites-web) (personal data security guide, 2024 edition) covers: certificate, TLS version, HTTPS redirect and cookies. Its guide is general and refers to ANSSI for technical details, but for a French company it links the website's security to the GDPR's security obligation.

A citation says which recommendation a check relates to. It does not mean the domain complies with ANSSI guidance: most recommendations also cover settings that cannot be seen from outside. This project is not affiliated with ANSSI or CNIL.

**Differences with the Observatory.** One Observatory test is not reproduced: CORS, whose only penalty requires sending a forged `Origin` header. A Content-Security-Policy declared only in a `<meta http-equiv>` tag is read, without the directives a meta tag cannot set (frame-ancestors, report-uri, sandbox); the Observatory may weigh that case differently. Only the first CSP policy is analysed when a site sends several. In these rare cases the website grade can differ from the Observatory's.

**Checked against the Observatory every week.** The Live check workflow asks the [Observatory API](https://github.com/mdn/mdn-http-observatory) for its result on the same domains and compares it test by test. Any test where the points differ is listed, and a grade gap raises a warning. This is how the HSTS preload, Subresource Integrity, cookie collection and `<meta name="referrer">` rules were found and fixed; on 14 October 2026, all six domains (github.com, google.com, cloudflare.com, wikipedia.org, docs.github.com, badssl.com) got exactly the same score, with the same points on every test.

## Project structure

```
domain_check.py             Runs the tool from a clone, without installing
pyproject.toml              Package definition, dependencies, tool settings
Dockerfile                  Docker images (standard and with a browser)
domaincheck/
  cli.py                    Command line (domain-security-check)
  collector.py              Network access (DNS, TLS, HTTP, CT logs), nothing else
  tls_scan.py               Accepted TLS versions and cipher suites (hand-built ClientHello)
  ct.py                     Subdomains from Certificate Transparency logs, takeover-prone providers
  hosting.py                Platform recognition and platform-specific fixes
  smtp_scan.py              Mail servers: STARTTLS, TLS and certificate on port 25
  summary.py                Summary for decision makers: risks, effort, impact
  branding.py               Branded reports (logo, company, contact, client, colour)
  software.py               Outdated software: CMS and PHP recognition, support dates
  trackers.py               Trackers before consent (page received, or real browser)
  timeline.py               Grades over time (history file of each domain)
  alerts.py                 Follow-up mode: alerts, webhook and email
action.yml                  Reusable GitHub Action
  nis2.py                   NIS 2 view: checks related to the measures of article 21(2)
  email_checks.py           MX / SPF / DMARC / DKIM / MTA-STS analysis
  dns_checks.py             DNSSEC, CAA, registration and subdomain analysis
  web_checks.py             Website checks (Mozilla HTTP Observatory tests)
  tls_checks.py             Certificate and TLS checks
  scoring.py                Grades: Observatory algorithm, own scales, overall grade
  sources.py                Standards, ANSSI and CNIL guides cited for each check
  audit.py                  Orchestration
  report.py                 HTML report, summary page for several domains, console summary, JSON
  pdf_report.py             PDF report (optional: needs ReportLab)
  history.py                Changes since the previous audit of a domain
  i18n.py, locales/fr.py    Report languages and the French translation
  demo.py                   Fictitious data for the demo
  hsts_preload.py           HSTS preload list (download, cache, lookups)
  rdap.py                   Domain registration data (RDAP servers, answers)
  observatory.py            Test-by-test comparison with the Observatory API
tests/                      1066 unit tests + live tests (tests/live)
scripts/live_summary.py     Audits a list of domains for the Live check workflow
scripts/observatory_compare.py  Compares the website grades with the Observatory
```

Collection is kept separate from analysis: every rule can be tested on fixed data, without depending on the Internet.

## Tests

```bash
python -m pytest -q          # 1066 unit tests, no network needed
ruff check .                 # lint
mypy                         # type check
python -m pytest -m live -v  # live tests against real domains (Internet required)
```

Three GitHub Actions workflows keep the tool honest (the Tests workflow also runs the reusable action of this repository on the demo):

- **Tests** runs on every push: the unit tests on Python 3.10 to 3.13, the lint and type checks, a build of the package installed in a clean environment and checked for PyPI (`twine check`), and a build of the Docker image that runs the demo.
- **Release** publishes a GitHub release with the package attached, the Docker images on the GitHub Container Registry and, once set up, the package on PyPI.
- **Live check** runs every Monday (and on demand) against real domains:
  - hosts from [badssl.com](https://badssl.com), deliberately misconfigured for testing (expired, self-signed and wrong-host certificates), must be flagged as critical;
  - for github.com, google.com, cloudflare.com and wikipedia.org, the SPF and DMARC records read by the tool must match those returned by an independent resolver (Google DNS-over-HTTPS);
  - a subdomain (docs.github.com) must inherit its parent's DMARC policy;
  - DNSSEC must match an independent resolver, and CAA (google.com) and MTA-STS (gmail.com) must be found where they are published;
  - registration data and security.txt must be found on known domains (including a .fr domain);
  - TLS 1.0 (tls-v1-0.badssl.com), 3DES (3des.badssl.com) and the RSA key exchange (static-rsa.badssl.com) must be detected, and github.com must pass the TLS checks;
  - the support dates of PHP, WordPress, Drupal, Joomla and TYPO3 must be read from endoflife.date, and docs.github.com must pass the subdomain checks;
  - gmail.com's mail server must offer STARTTLS with a valid certificate (skipped when port 25 is blocked from the network running the tests);
  - google.com's CAA must allow the authority of its certificate, gmail.com's DKIM keys must be read, and www.wikipedia.org loaded in a real browser must show no tracker;
  - subdomains of afnic.fr must be read from the Certificate Transparency logs (the test is skipped when crt.sh and Cert Spotter are both down), and the DNS host and email provider of known domains must be recognised;
  - the website grade of each domain is compared with Mozilla HTTP Observatory, test by test, and a warning is raised if the Observatory moves to another version of its scoring algorithm (this tool reproduces version 6).

  The results table is published in the workflow summary and the HTML reports are kept as artifacts.

## Publishing

**Docker images** need nothing more: the Release workflow pushes them to `ghcr.io/ryarkhewas/domain-security-check`. The first time, make the package public on GitHub (profile → Packages → domain-security-check → Package settings → Change visibility).

**PyPI** uses trusted publishing: GitHub proves to PyPI which workflow is publishing, so no PyPI password or token is stored in the repository. To set it up once:

1. Create an account on [pypi.org](https://pypi.org/account/register/) (with two-factor authentication).
2. In your PyPI account, Publishing → add a pending publisher: project `domain-security-check`, owner `Ryarkhewas`, repository `domain-security-check`, workflow `release.yml`, environment `pypi`.
3. In the GitHub repository, Settings → Environments → create `pypi`, then Settings → Secrets and variables → Actions → Variables → add `PUBLISH_TO_PYPI` with the value `true`.

The next release then publishes the package on PyPI too. Before that, the PyPI step is simply skipped.

## Limits

The audit does not cover the site's applications (forms, CMS, plugins), workstations or user accounts. It gives an overview of the exposure visible from the Internet at a given date, not a security guarantee. The subdomain check only sees names that appeared in a public certificate: a subdomain that never had one (or only a wildcard certificate) stays invisible. When crt.sh does not answer, the names come from Cert Spotter, which may list fewer old certificates; the report then says so. The platform-specific fixes are starting points to adapt, checked against each provider's documentation at the time of writing; provider menus change over time.

## Changelog

See [CHANGELOG.md](https://github.com/Ryarkhewas/domain-security-check/blob/main/CHANGELOG.md).

## License

MIT

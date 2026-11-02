# External security audit authorization

> **Template only.** This document helps frame an audit run with domain-security-check. It is not legal advice:
> adapt it to your situation (service contract, terms and conditions, insurance) and to the law that applies.
> Fill in the parts in square brackets `[ ]`; remove the options that do not apply.

## 1. Parties

**The client**, who authorizes the audit:
- Company name: [Company] — registration number: [number]
- Represented by: [First Last], [role], authorized to commit the company
- Address: [address]

**The auditor**, who runs the audit:
- Name or company: [First Last / company] — registration number: [number, if any]
- Address: [address]
- Contact: [email], [phone]

## 2. Purpose

The client authorizes the auditor to assess the security exposure, as visible from the Internet, of the domains
listed below, with the open source tool domain-security-check
(https://github.com/Ryarkhewas/domain-security-check), version [1.x.x].

## 3. Scope

| Domain | Included |
|---|---|
| [example.com] | Website, certificate and TLS, email (SPF, DKIM, DMARC, mail servers), DNS |
| [shop.example.com] | [same / specify] |

**Options** (tick the ones that are authorized):
- [ ] **Active subdomains** (`--subdomains`): subdomains found in public certificate logs (Certificate
  Transparency) that are still in use receive a few requests each (HTTPS connection, accepted TLS versions, home
  page, HTTP redirect).
- [ ] **Real browser** (`--browser`): the home page is opened in a browser (Chromium) to list the trackers loaded
  before any consent, as a visitor would see them.
- [ ] **Regular monitoring** (`--alert`): the same audit runs again [every week / every month] from [date] to
  [date], and the alerts are sent to [email or channel].

**Out of scope**: any domain, subdomain or IP address not listed above, as well as the site's applications (forms,
customer areas), workstations and user accounts.

## 4. What the tool does, and does not do

The tool behaves like an ordinary visitor or mail server:
- public DNS lookups;
- HTTPS and HTTP connections to the home page, `robots.txt`, `security.txt` and, when announced, the MTA-STS
  policy; one CORS check request (OPTIONS) on the home page;
- a few TLS connection openings (ClientHello message) to see the accepted versions and cipher suites, with no data
  exchanged;
- connections to the mail servers on port 25: EHLO, STARTTLS, TLS handshake, QUIT; **no email is ever sent**;
- reading public sources: Certificate Transparency logs, the domain registry (RDAP), the HSTS preload list,
  software end-of-life dates.

The tool **does not**: scan ports, look for hidden directories or files, run intrusion tests, exploit
vulnerabilities, try passwords or test denial of service.

## 5. Schedule

- Audit date(s): from [date] to [date], between [time] and [time].
- IP address or network the audit runs from: [IP address / "GitHub Actions" / to be specified].

## 6. Contacts and stop

- Client technical contact: [First Last], [email], [phone].
- The client can ask for the audit to stop at any time, by [email / phone]; the auditor stops on receipt.
- If the auditor finds a serious problem (for instance a subdomain that a third party could take over), they warn
  the technical contact [within 24 hours / immediately], without waiting for the report.

## 7. Client's statement

The client states that they hold the domains in scope, or have their holder's consent, and are entitled to
authorize this audit. When services are hosted or run by a provider (hosting, email provider, CDN), the client is
responsible for checking that their contracts allow this audit.

## 8. Confidentiality of the results

The reports describe the client's weaknesses: they are confidential.
- They are given only to [recipient(s)], by [means of transfer].
- The auditor keeps them for [duration, for instance 12 months], then deletes them, unless the client agrees
  otherwise in writing.
- The auditor does not publish or share the results with a third party without the client's written consent. An
  anonymized example can only be used with that consent.
- The audit collects no personal data about the client's visitors or staff. [If personal data still appears (for
  instance a contact address in security.txt), it is only used for the audit.]

## 9. Liability

The audit describes the exposure visible from the Internet on the date of the analysis; it does not guarantee that
there are no other weaknesses. The requests sent are those of an ordinary visitor; the auditor cannot be held
liable for an outage that does not result from a breach of this document on their part. [Specify, if any, the
auditor's professional liability insurance.]

## 10. Legal framework

Accessing a computer system without authorization is an offence in most countries (in France, article 323-1 of the
Code pénal). This authorization, signed before the audit, defines what the auditor is allowed to do. Any action
outside the scope and methods described here is not covered.

## Signatures

Signed in [city], on [date], in two copies.

| For the client | For the auditor |
|---|---|
| [First Last, role] | [First Last] |
| Signature: | Signature: |

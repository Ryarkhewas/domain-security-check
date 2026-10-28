# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately, through GitHub:
**Security** tab of this repository → **Report a vulnerability**. You will get an answer within a week.

Useful details: the version (`domain-security-check --version`), how the tool was run (pip, Docker, GitHub
Action), and the steps or the input that trigger the problem.

## Supported versions

Fixes are made on the latest release only. Update with `pip install -U domain-security-check` or by pulling
the latest Docker image.

## How the tool protects the machine that runs it

The audited domain's owner controls its DNS records, redirects, certificates and answers. The tool therefore:

- refuses by default to connect to private or reserved addresses (127.0.0.1, 10.0.0.0/8, 192.168.0.0/16,
  169.254.169.254...), including through redirects, mail servers and subdomains; `--allow-private` lifts this
  for an audit of internal domains;
- limits the size (2 MB) and the reading time of every answer, and the duration of the TLS and SMTP probes;
- escapes everything it shows in the HTML and PDF reports, which also forbid scripts and remote resources
  with a Content-Security-Policy, and removes control characters from what it prints in a terminal or sends
  in an alert;
- reads email passwords and webhook URLs from environment variables only, never prints the webhook URL, and
  only sends the SMTP password over an encrypted connection;
- runs as a non-root user in the Docker image, and refuses downloads in the optional browser.

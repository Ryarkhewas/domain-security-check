"""Command line.

Usage:
    domain-security-check example.com
    domain-security-check example.com -o reports/example.html --author "Your Name"
    domain-security-check example.com --json
    domain-security-check --demo

Also available as "python -m domaincheck" and "python domain_check.py".
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ._version import __version__
from .audit import InvalidDomain, run_audit
from .collector import CollectionError, DomainNotFound
from .demo import DEMO_DOMAIN, DemoCollector
from .report import console_summary, render_html, render_json

REMINDER = (
    "Reminder: only audit domains you own or for which you have the owner's permission."
)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="domain-security-check",
        description="Passive security audit of a domain name (HTTPS, headers, SPF/DKIM/DMARC).",
    )
    p.add_argument("domain", nargs="?", help="Domain to audit (e.g. example.com)")
    p.add_argument("-o", "--output", type=Path, help="Output HTML file (default: reports/<domain>.html)")
    p.add_argument("--author", default="", help="Name shown in the report")
    p.add_argument("--json", action="store_true", help="Print the result as JSON instead of the summary")
    p.add_argument("--demo", action="store_true", help="Demo on a fictitious domain, without network access")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    if not args.demo and not args.domain:
        p.error("give a domain, or --demo")

    try:
        if args.demo:
            result = run_audit(DEMO_DOMAIN, collector=DemoCollector())
        else:
            print(REMINDER, file=sys.stderr)
            result = run_audit(args.domain)
    except (InvalidDomain, DomainNotFound) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except CollectionError as e:
        print(f"Audit stopped: {e}\nNo report was produced, to avoid a wrong diagnosis.", file=sys.stderr)
        return 2

    output = args.output or Path("reports") / f"{result.domain}.html"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_html(result, args.author), encoding="utf-8")

    print(render_json(result) if args.json else console_summary(result))
    print(f"HTML report: {output}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

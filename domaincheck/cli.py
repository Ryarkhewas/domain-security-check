"""Command line.

Usage:
    domain-security-check example.com
    domain-security-check example.com -o reports/example.html --author "Your Name"
    domain-security-check example.com --json
    domain-security-check example.com example.org --output-dir reports/
    domain-security-check --file domains.txt
    domain-security-check --demo

With several domains, each one gets its report in the output directory, plus
an index.html summary page. A domain that cannot be audited is listed with
the reason, and the others are still audited.

Also available as "python -m domaincheck" and "python domain_check.py".
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ._version import __version__
from .audit import InvalidDomain, run_audit
from .collector import CollectionError, DomainNotFound
from .demo import DEMO_DOMAIN, DemoCollector
from .models import Result
from .report import console_summary, render_html, render_index, render_json

REMINDER = (
    "Reminder: only audit domains you own or for which you have the owner's permission."
)


def read_domain_file(path: Path) -> list[str]:
    """One domain per line; blank lines and # comments are ignored."""
    domains = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            domains.append(line)
    return domains


def _unique(items: list[str]) -> list[str]:
    """Remove duplicates (case-insensitive), keeping the first occurrence."""
    seen: set[str] = set()
    unique = []
    for item in items:
        if item.lower() not in seen:
            seen.add(item.lower())
            unique.append(item)
    return unique


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="domain-security-check",
        description="Passive security audit of domain names (HTTPS, headers, email, DNS).",
    )
    p.add_argument("domains", nargs="*", metavar="domain", help="Domain(s) to audit (e.g. example.com)")
    p.add_argument("-f", "--file", type=Path, help="Text file with one domain per line (# for comments)")
    p.add_argument("-o", "--output", type=Path, help="Output HTML file, for a single domain "
                   "(default: reports/<domain>.html)")
    p.add_argument("-d", "--output-dir", type=Path, default=Path("reports"),
                   help="Output directory for several domains (default: reports)")
    p.add_argument("--author", default="", help="Name shown in the report")
    p.add_argument("--json", action="store_true", help="Print the result as JSON instead of the summary")
    p.add_argument("--demo", action="store_true", help="Demo on a fictitious domain, without network access")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    domains = list(args.domains)
    if args.file:
        try:
            domains += read_domain_file(args.file)
        except OSError as e:
            p.error(f"cannot read {args.file}: {e.strerror or e}")
    domains = _unique(domains)

    if args.demo:
        result = run_audit(DEMO_DOMAIN, collector=DemoCollector())
        return _single(result, args)
    if not domains:
        p.error("give a domain, a --file, or --demo")
    if len(domains) > 1 and args.output:
        p.error("-o/--output is for a single domain; use --output-dir with several domains")

    print(REMINDER, file=sys.stderr)
    if len(domains) == 1:
        try:
            result = run_audit(domains[0])
        except (InvalidDomain, DomainNotFound) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        except CollectionError as e:
            print(f"Audit stopped: {e}\nNo report was produced, to avoid a wrong diagnosis.", file=sys.stderr)
            return 2
        return _single(result, args)
    return _several(domains, args)


def _single(result: Result, args) -> int:
    output = args.output or args.output_dir / f"{result.domain}.html"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_html(result, args.author), encoding="utf-8")
    print(render_json(result) if args.json else console_summary(result))
    print(f"HTML report: {output}", file=sys.stderr)
    return 0


def _several(domains: list[str], args) -> int:
    out: Path = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    results: list[Result] = []
    errors: dict[str, str] = {}
    for i, domain in enumerate(domains, 1):
        print(f"[{i}/{len(domains)}] {domain}", file=sys.stderr)
        try:
            result = run_audit(domain)
        except (InvalidDomain, DomainNotFound, CollectionError) as e:
            errors[domain] = str(e)
            print(f"    not audited: {e}", file=sys.stderr)
            continue
        results.append(result)
        (out / f"{result.domain}.html").write_text(render_html(result, args.author), encoding="utf-8")
        print(f"    overall grade {result.grade}", file=sys.stderr)

    (out / "index.html").write_text(render_index(results, errors, args.author), encoding="utf-8")
    if args.json:
        print(json.dumps({"results": [json.loads(render_json(r)) for r in results], "errors": errors},
                         ensure_ascii=False, indent=2))
    else:
        width = max(len(d) for d in domains)
        print(f"\n  {'Domain':<{width}}  Overall  Website  TLS  Email  DNS")
        for r in results:
            g = r.grades
            print(f"  {r.domain:<{width}}  {r.grade:<7}  {g['WEB'].grade:<7}  {g['TLS'].grade:<3}  "
                  f"{g['EMAIL'].grade:<5}  {g['DNS'].grade}")
        for domain, message in errors.items():
            print(f"  {domain:<{width}}  not audited: {message}")
    print(f"\nSummary: {out / 'index.html'} ({len(results)} audited, {len(errors)} not audited)", file=sys.stderr)
    return 0 if not errors else 3


if __name__ == "__main__":
    sys.exit(main())

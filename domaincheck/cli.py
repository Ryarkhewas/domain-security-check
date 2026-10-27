"""Command line.

Usage:
    domain-security-check example.com
    domain-security-check example.com -o reports/example.html --author "Your Name"
    domain-security-check example.com --json
    domain-security-check example.com example.org --output-dir reports/
    domain-security-check --file domains.txt
    domain-security-check example.com --pdf
    domain-security-check example.com --lang fr
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
from .audit import InvalidDomain, audit_many, run_audit
from .branding import Branding, BrandingError
from .branding import load as load_branding
from .branding import merge as merge_branding
from .collector import CollectionError, DomainNotFound
from .demo import DEMO_DOMAIN, DemoCollector
from .history import compare, load_previous
from .i18n import LANGUAGES, message_of
from .models import Result
from .pdf_report import INSTALL_HINT, render_pdf
from .report import _translator, console_summary, render_html, render_index, render_json
from .timeline import update as update_timeline

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
    p.add_argument("--pdf", action="store_true", help="Also write each report as a PDF (needs the [pdf] extra)")
    p.add_argument("--workers", type=int, default=6, help="Domains audited at the same time (default: 6)")
    p.add_argument("--lang", choices=LANGUAGES, default="en",
                   help="Language of the reports and summary: en (default) or fr; JSON stays in English")
    p.add_argument("--author", default="", help="Name shown in the report")
    p.add_argument("--brand", type=Path, metavar="FILE",
                   help="JSON file with author, company, contact, logo and color, for branded reports")
    p.add_argument("--company", default="", help="Your company, shown on the PDF cover page and footer")
    p.add_argument("--contact", default="", help="Your contact details (email, phone, website), on the cover page")
    p.add_argument("--client", default="", help="Client name, on the cover page (\"Prepared for ...\")")
    p.add_argument("--logo", default="", help="PNG or JPEG logo for the PDF cover page")
    p.add_argument("--color", default="", help="Accent colour of the PDF, as #RRGGBB")
    p.add_argument("--json", action="store_true", help="Print the result as JSON instead of the summary")
    p.add_argument("--previous", type=Path, metavar="FILE",
                   help="JSON result of an earlier audit to compare with, for a single domain "
                        "(default: the <domain>.json saved next to the report by the previous run)")
    p.add_argument("--no-ct-logs", action="store_true",
                   help="Skip the subdomains published in Certificate Transparency logs (faster)")
    p.add_argument("--nis2", action="store_true",
                   help="Add a NIS 2 view: how the checks relate to the measures of article 21 of the directive")
    p.add_argument("--browser", action="store_true",
                   help="Load the home page in a real browser to see the trackers set before consent "
                        "(needs the [browser] extra and: playwright install chromium)")
    p.add_argument("--subdomains", action="store_true",
                   help="Also check every subdomain in use found in the CT logs (HTTPS, certificate, old TLS, "
                        "outdated software); slower")
    p.add_argument("--no-mail-servers", action="store_true",
                   help="Do not connect to the mail servers on port 25 (STARTTLS, certificates)")
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
    say = _translator(args.lang)
    try:
        base = load_branding(args.brand) if args.brand else Branding()
        args.branding = merge_branding(base, author=args.author, company=args.company, contact=args.contact,
                                       client=args.client, logo=args.logo, color=args.color).check()
    except BrandingError as e:
        print(say("Error: {message}", message=str(e)), file=sys.stderr)
        return 1
    args.author = args.branding.author
    if args.pdf and not _pdf_available():
        print(say("Error: {message}", message=INSTALL_HINT), file=sys.stderr)
        return 1

    if args.demo:
        result = run_audit(DEMO_DOMAIN, collector=DemoCollector(), **_skip(args))
        return _single(result, args)
    if not domains:
        p.error("give a domain, a --file, or --demo")
    if len(domains) > 1 and args.output:
        p.error("-o/--output is for a single domain; use --output-dir with several domains")
    if len(domains) > 1 and args.previous:
        p.error("--previous is for a single domain; with several domains, each report is compared with the "
                "<domain>.json saved in the output directory")

    print(say(REMINDER), file=sys.stderr)
    if len(domains) == 1:
        try:
            result = run_audit(domains[0], **_skip(args))
        except (InvalidDomain, DomainNotFound) as e:
            print(say("Error: {message}", message=message_of(e)), file=sys.stderr)
            return 1
        except CollectionError as e:
            print(say("Audit stopped: {message}", message=message_of(e)), file=sys.stderr)
            print(say("No report was produced, to avoid a wrong diagnosis."), file=sys.stderr)
            return 2
        return _single(result, args)
    return _several(domains, args)


def _single(result: Result, args) -> int:
    output = args.output or args.output_dir / f"{result.domain}.html"
    output.parent.mkdir(parents=True, exist_ok=True)
    _compare_and_save(result, output.with_suffix(".json"), args.previous)
    output.write_text(render_html(result, args.author, args.lang, args.branding, args.nis2), encoding="utf-8")
    print(render_json(result) if args.json else console_summary(result, args.lang))
    say = _translator(args.lang)
    print(say("HTML report: {path}", path=str(output)), file=sys.stderr)
    if args.pdf:
        pdf = output.with_suffix(".pdf")
        pdf.write_bytes(render_pdf(result, args.author, args.lang, args.branding, args.nis2))
        print(say("PDF report: {path}", path=str(pdf)), file=sys.stderr)
    return 0


def _compare_and_save(result: Result, saved: Path, previous: Path | None = None) -> None:
    """Compare with the previous audit of the same domain, then save this one for the next comparison."""
    earlier = load_previous(previous or saved)
    if earlier and earlier.get("domain") == result.domain:
        result.changes = compare(earlier, result)
    result.history = update_timeline(saved.with_suffix(".history.json"), result, earlier)
    saved.write_text(render_json(result), encoding="utf-8")


def _pdf_available() -> bool:
    try:
        import reportlab  # noqa: F401
    except ImportError:
        return False
    return True


def _several(domains: list[str], args) -> int:
    out: Path = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    results: list[Result] = []
    errors: dict[str, str] = {}
    say = _translator(args.lang)
    done = 0

    def progress(domain: str, outcome) -> None:
        nonlocal done
        done += 1
        if isinstance(outcome, Exception):
            status = say("not audited: {reason}", reason=message_of(outcome))
        else:
            status = say("overall grade {grade}", grade=outcome.grade)
        print(f"[{done}/{len(domains)}] {domain}: {status}", file=sys.stderr)

    # Several audits run at the same time: most of an audit is spent waiting for the network
    for domain, outcome in audit_many(domains, workers=args.workers, on_done=progress, **_skip(args)).items():
        if isinstance(outcome, (InvalidDomain, DomainNotFound, CollectionError)):
            errors[domain] = message_of(outcome)
            continue
        if isinstance(outcome, Exception):
            raise outcome
        results.append(outcome)
        _compare_and_save(outcome, out / f"{outcome.domain}.json")
        html = render_html(outcome, args.author, args.lang, args.branding, args.nis2)
        (out / f"{outcome.domain}.html").write_text(html, encoding="utf-8")
        if args.pdf:
            pdf = render_pdf(outcome, args.author, args.lang, args.branding, args.nis2)
            (out / f"{outcome.domain}.pdf").write_bytes(pdf)

    (out / "index.html").write_text(render_index(results, errors, args.author, args.lang), encoding="utf-8")
    if args.json:
        print(json.dumps({"results": [json.loads(render_json(r)) for r in results], "errors": errors},
                         ensure_ascii=False, indent=2))
    else:
        width = max(len(d) for d in domains)
        columns = [say("Domain"), say("Overall"), say("Website"), "TLS", say("Email"), "DNS"]
        sizes = [max(width, len(columns[0]))] + [max(7, len(c)) for c in columns[1:]]
        print("\n  " + "  ".join(c.ljust(n) for c, n in zip(columns, sizes, strict=True)))
        for r in results:
            g = r.grades
            row = [r.domain, r.grade, g["WEB"].grade, g["TLS"].grade, g["EMAIL"].grade, g["DNS"].grade]
            print("  " + "  ".join(c.ljust(n) for c, n in zip(row, sizes, strict=True)))
        for domain, message in errors.items():
            print(f"  {domain.ljust(sizes[0])}  {say('not audited: {reason}', reason=message)}")
    summary = say("Summary: {path} ({audited} audited, {failed} not audited)", path=str(out / "index.html"),
                  audited=len(results), failed=len(errors))
    print(f"\n{summary}", file=sys.stderr)
    return 0 if not errors else 3


def _skip(args) -> dict[str, bool]:
    """Checks turned on or off on the command line (only passed when used, so the defaults stay in one place)."""
    skip = {}
    if args.no_ct_logs:
        skip["ct_logs"] = False
    if args.no_mail_servers:
        skip["mail_servers"] = False
    if args.subdomains:
        skip["subdomains"] = True
    if args.browser:
        skip["browser"] = True
    return skip


if __name__ == "__main__":
    sys.exit(main())


"""Audit a list of domains and print a Markdown summary table.

Used by the "Live check" workflow to publish results in the job summary.
Usage: python scripts/live_summary.py reports/ github.com google.com ...
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from domaincheck.audit import run_audit  # noqa: E402
from domaincheck.collector import CollectionError, DomainNotFound  # noqa: E402
from domaincheck.models import Status  # noqa: E402
from domaincheck.report import render_html  # noqa: E402


def main(out_dir: str, domains: list[str]) -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    print("| Domain | Grade | Score | Critical | To improve | Main issue |")
    print("|---|---|---|---|---|---|")
    for domain in domains:
        try:
            r = run_audit(domain)
        except (CollectionError, DomainNotFound) as e:
            print(f"| {domain} | – | – | – | – | error: {e} |")
            continue
        results.append(r)
        (out / f"{r.domain}.html").write_text(render_html(r), encoding="utf-8")
        critical = [f for f in r.findings if f.status == Status.CRITICAL]
        warning = [f for f in r.findings if f.status == Status.WARNING]
        main_issue = (critical or warning)[0].title if (critical or warning) else "–"
        print(f"| {r.domain} | **{r.grade}** | {r.score} | {len(critical)} | {len(warning)} | {main_issue} |")

    # Full details, folded, so every finding can be checked against other tools
    print("\n### Details\n")
    for r in results:
        print(f"<details><summary>{r.domain} — grade {r.grade} ({r.score}/100)</summary>\n")
        print("| Status | Check | Detail |\n|---|---|---|")
        for f in r.findings:
            detail = f.detail.replace("|", "\\|").replace("\n", " ")
            print(f"| {f.status.value} | {f.title} | {detail} |")
        print("\n</details>\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))

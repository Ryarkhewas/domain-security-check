"""Audit a list of domains and print a Markdown summary table.

Used by the "Live check" workflow to publish results in the job summary.
Usage: python scripts/live_summary.py reports/ github.com google.com ...
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from domaincheck.audit import audit_many  # noqa: E402
from domaincheck.models import Status  # noqa: E402
from domaincheck.report import render_html  # noqa: E402


def main(out_dir: str, domains: list[str]) -> int:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    print("| Domain | Overall | Website | Cert & TLS | Email | DNS | Main issue |")
    print("|---|---|---|---|---|---|---|")
    start = time.monotonic()

    def timing(domain, outcome):
        # GitHub annotation (on stderr, so that the Markdown table stays clean): how long each audit took,
        # and what the CT logs gave, the slowest part
        ct = "" if isinstance(outcome, Exception) else next(
            (f" CT logs: {f.status.value}, {f.detail[:160]}" for f in outcome.findings if f.source == "ct"), "")
        print(f"::notice title=Audit time::{domain}: {time.monotonic() - start:.0f} s.{ct}", file=sys.stderr)

    for domain, r in audit_many(domains, workers=8, on_done=timing).items():
        if isinstance(r, Exception):
            print(f"| {domain} | – | – | – | – | – | error: {r} |")
            continue
        results.append(r)
        (out / f"{r.domain}.html").write_text(render_html(r), encoding="utf-8")
        critical = [f for f in r.findings if f.status == Status.CRITICAL]
        warning = [f for f in r.findings if f.status == Status.WARNING]
        main_issue = (critical or warning)[0].title if (critical or warning) else "–"
        if r.cap_reason:
            main_issue = f"capped: {r.cap_reason}"
        g = {k: (v.grade + (f" ({v.score})" if v.score is not None else "")) for k, v in r.grades.items()}
        print(f"| {r.domain} | **{r.grade}** | {g['WEB']} | {g['TLS']} | {g['EMAIL']} | {g['DNS']} | {main_issue} |")

    # Full details, folded, so every finding can be checked against other tools
    print("\n### Details\n")
    for r in results:
        print(f"<details><summary>{r.domain} — overall grade {r.grade}</summary>\n")
        print("| Status | Points | Check | Detail |\n|---|---|---|---|")
        for f in r.findings:
            detail = f.detail.replace("|", "\\|").replace("\n", " ")
            pts = "–" if f.points is None else f.points
            print(f"| {f.status.value} | {pts} | {f.title} | {detail} |")
        print("\n</details>\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))

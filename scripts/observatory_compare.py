"""Compare this tool's website grade with Mozilla HTTP Observatory.

Used by the "Live check" workflow. Prints a Markdown table (for the job
summary), saves the raw Observatory answers next to the HTML reports, and
emits a GitHub warning annotation for every domain whose grade differs.
The exit code stays 0: external sites change, so a gap is a signal to look
at, not a broken build.

Usage: python scripts/observatory_compare.py reports/ github.com google.com ...
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from domaincheck.audit import run_audit  # noqa: E402
from domaincheck.collector import CollectionError, DomainNotFound  # noqa: E402
from domaincheck.observatory import ObservatoryError, compare, fetch, markdown  # noqa: E402


def main(out_dir: str, domains: list[str]) -> int:
    out = Path(out_dir) / "observatory"
    out.mkdir(parents=True, exist_ok=True)
    comparisons = []
    for domain in domains:
        try:
            result = run_audit(domain)
        except (CollectionError, DomainNotFound) as e:
            print(f"::warning::{domain}: audit failed ({e})", file=sys.stderr)
            continue
        try:
            data = fetch(result.domain)
            (out / f"{result.domain}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
            c = compare(result, data)
        except ObservatoryError as e:
            c = compare(result, None, str(e))
        comparisons.append(c)
        if not c.error and not c.same_grade:
            tests = ", ".join(g.test for g in c.gaps) or "no single test (check the bonus rule)"
            print(f"::warning::{c.domain}: website grade {c.our_grade} ({c.our_score}) vs Observatory "
                  f"{c.their_grade} ({c.their_score}); tests that differ: {tests}", file=sys.stderr)
    print(markdown(comparisons))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))

"""Compare this tool's website grade with Mozilla HTTP Observatory.

Used by the "Live check" workflow. Writes a Markdown table to
<out_dir>/observatory/summary.md (for the job summary), saves the raw
Observatory answers next to it, and prints one GitHub annotation per domain:
a notice when the grades match, a warning when they differ.
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
from domaincheck.observatory import Comparison, ObservatoryError, compare, fetch, markdown  # noqa: E402


def main(out_dir: str, domains: list[str]) -> int:
    out = Path(out_dir) / "observatory"
    out.mkdir(parents=True, exist_ok=True)
    comparisons = []
    for domain in domains:
        try:
            result = run_audit(domain)
        except (CollectionError, DomainNotFound) as e:
            print(f"::warning title=Observatory comparison::{domain}: audit failed ({e})")
            continue
        try:
            data = fetch(result.domain)
            (out / f"{result.domain}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
            c = compare(result, data)
        except ObservatoryError as e:
            c = compare(result, None, str(e))
        comparisons.append(c)
        print(annotation(c))
    (out / "summary.md").write_text(markdown(comparisons) + "\n", encoding="utf-8")
    return 0


def annotation(c: Comparison) -> str:
    """One line per domain, readable in the run's annotations (and through the API)."""
    title = "title=Observatory comparison"
    if c.error:
        return f"::notice {title}::{c.domain}: Observatory could not scan it ({c.error})"
    diff = "; ".join(f"{g.test} {g.ours} vs {g.theirs} ({g.their_result})" for g in c.gaps) or "none"
    level = "notice" if c.same_grade else "warning"
    return (f"::{level} {title}::{c.domain}: this tool {c.our_grade} ({c.our_score}), Observatory "
            f"{c.their_grade} ({c.their_score}). Tests that differ: {diff}")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2:]))

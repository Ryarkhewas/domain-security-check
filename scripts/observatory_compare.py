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
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from domaincheck.audit import audit_many  # noqa: E402
from domaincheck.observatory import Comparison, ObservatoryError, algorithm_warning, compare, fetch, markdown  # noqa: E402


def main(out_dir: str, domains: list[str]) -> int:
    out = Path(out_dir) / "observatory"
    out.mkdir(parents=True, exist_ok=True)
    # The Observatory scans start first and run while our own audits are made.
    # Every answer is awaited, however long it takes (google.com: up to ~3 min),
    # so that no comparison is skipped.
    with ThreadPoolExecutor(max_workers=len(domains) or 1) as pool:
        pending = {d: pool.submit(_observatory, d) for d in domains}
        audits = audit_many(domains, workers=8)
        answers = {d: f.result() for d, f in pending.items()}
    comparisons = []
    for domain, result in audits.items():
        if isinstance(result, Exception):
            print(f"::warning title=Observatory comparison::{domain}: audit failed ({result})")
            continue
        answer, seconds = answers[domain]
        if isinstance(answer, ObservatoryError):
            c = compare(result, None, str(answer))
        else:
            (out / f"{result.domain}.json").write_text(json.dumps(answer, indent=2), encoding="utf-8")
            c = compare(result, answer)
        comparisons.append(c)
        print(f"{annotation(c)} (Observatory answer: {seconds:.0f} s, algorithm v{c.algorithm_version})")
    warning = algorithm_warning(comparisons)
    if warning:
        print(f"::warning title=Observatory algorithm changed::{warning}")
    (out / "summary.md").write_text(markdown(comparisons) + "\n", encoding="utf-8")
    return 0


def _observatory(domain: str) -> tuple[dict | ObservatoryError, float]:
    start = time.monotonic()
    try:
        # Long network timeout: only there so that a server that never answers cannot block the run forever
        answer: dict | ObservatoryError = fetch(domain, timeout=300)
    except ObservatoryError as e:
        answer = e
    return answer, time.monotonic() - start


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

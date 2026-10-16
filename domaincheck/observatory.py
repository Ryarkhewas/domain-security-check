"""Compare our website grade with Mozilla HTTP Observatory, test by test.

The website checks follow the Observatory scoring, so for the same site both
tools should agree. This module asks the public Observatory API for its result
(POST /api/v2/analyze, which returns the scan and every test with its score
modifier) and lists the tests where the points differ, so that any gap can be
explained or fixed. It is used by the "Live check" workflow.

API source: https://github.com/mdn/mdn-http-observatory (src/api/v2/analyze).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import requests

from .models import Category, Result

API_URL = "https://observatory-api.mdn.mozilla.net/api/v2/analyze"
# Version of the Observatory scoring that the website checks reproduce (src/constants.js).
# If the API reports another version, the scoring may have changed: the Live check warns.
ALGORITHM_VERSION = 6

# Our finding "source" key -> Observatory test name
TEST_FOR_SOURCE = {
    "redirection": "redirection",
    "hsts": "strict-transport-security",
    "hsts-preload": "strict-transport-security",
    "sri": "subresource-integrity",
    "csp": "content-security-policy",
    "xfo": "x-frame-options",
    "xcto": "x-content-type-options",
    "referrer": "referrer-policy",
    "cookies": "cookies",
    "corp": "cross-origin-resource-policy",
    "coop": "cross-origin-opener-policy",
    "coep": "cross-origin-embedder-policy",
}
# Observatory tests this project does not implement (documented in the README)
NOT_IMPLEMENTED = {"cross-origin-resource-sharing"}


class ObservatoryError(Exception):
    """The Observatory could not scan the site (or could not be reached)."""


@dataclass
class TestGap:
    test: str
    ours: int | None  # None: not implemented on our side
    theirs: int
    their_result: str


@dataclass
class Comparison:
    domain: str
    our_grade: str
    our_score: int | None
    their_grade: str | None
    their_score: int | None
    gaps: list[TestGap] = field(default_factory=list)
    error: str = ""
    algorithm_version: int | None = None  # reported by the Observatory

    @property
    def algorithm_changed(self) -> bool:
        return self.algorithm_version is not None and self.algorithm_version != ALGORITHM_VERSION

    @property
    def same_grade(self) -> bool:
        return not self.error and self.our_grade == self.their_grade


def fetch(host: str, session: requests.Session | None = None, timeout: int = 90,
          retries: int = 2, wait: float = 10) -> dict:
    """Latest Observatory result for host (a recent one is reused, otherwise a new scan runs).

    The public API sometimes answers 5xx while busy: those answers are retried.
    """
    s = session or requests.Session()
    for attempt in range(retries + 1):
        try:
            r = s.post(API_URL, params={"host": host}, timeout=timeout)
        except requests.RequestException as e:
            raise ObservatoryError(f"API not reachable: {e}") from e
        if r.status_code < 500 or attempt == retries:
            break
        time.sleep(wait)
    try:
        data = r.json()
    except ValueError:
        raise ObservatoryError(f"unexpected answer (HTTP {r.status_code})") from None
    if r.status_code != 200:
        raise ObservatoryError(data.get("message") or data.get("error") or f"HTTP {r.status_code}")
    scan = data.get("scan") or {}
    if scan.get("error"):
        raise ObservatoryError(scan["error"])
    return data


def compare(result: Result, data: dict | None, error: str = "") -> Comparison:
    """Our website grade and points against an Observatory analyze response."""
    web = result.grades[Category.WEB.name]
    if data is None:
        return Comparison(result.domain, web.grade, web.score, None, None, error=error or "no data")
    scan, tests = data.get("scan", {}), data.get("tests", {})

    ours: dict[str, int | None] = {}
    for f in result.findings:
        test = TEST_FOR_SOURCE.get(f.source)
        if f.category == Category.WEB and test and f.points is not None:
            ours[test] = f.points

    gaps = []
    for name in sorted(tests):
        theirs = tests[name].get("score_modifier", 0) or 0
        mine = ours.get(name, None if name in NOT_IMPLEMENTED else 0)
        if mine != theirs and not (mine is None and theirs == 0):
            gaps.append(TestGap(name, mine, theirs, tests[name].get("result", "")))
    version = scan.get("algorithm_version")
    return Comparison(result.domain, web.grade, web.score, scan.get("grade"), scan.get("score"), gaps,
                      algorithm_version=version if isinstance(version, int) else None)


def _pts(p: int | None) -> str:
    if p is None:
        return "not implemented"
    return f"+{p}" if p > 0 else str(p)


def algorithm_warning(comparisons: list[Comparison]) -> str:
    """Message when the Observatory reports a scoring version other than the one reproduced here."""
    versions = sorted({c.algorithm_version for c in comparisons if c.algorithm_changed and c.algorithm_version})
    if not versions:
        return ""
    return (f"The Observatory now reports scoring algorithm version {', '.join(map(str, versions))}; this tool "
            f"reproduces version {ALGORITHM_VERSION}. Review the changes in mdn/mdn-http-observatory "
            "(src/grader/charts.js, src/analyzer) and update the website checks.")


def markdown(comparisons: list[Comparison]) -> str:
    """Summary table, then the tests that differ for each domain."""
    warning = algorithm_warning(comparisons)
    lines = [f"> **Warning:** {warning}\n"] if warning else []
    lines += ["| Domain | This tool | Observatory | Match | Tests that differ |", "|---|---|---|---|---|"]
    for c in comparisons:
        ours = f"{c.our_grade} ({c.our_score})" if c.our_score is not None else c.our_grade
        if c.error:
            lines.append(f"| {c.domain} | {ours} | – | – | Observatory: {c.error} |")
            continue
        theirs = f"{c.their_grade} ({c.their_score})"
        match = "yes" if c.same_grade else "**no**"
        diff = ", ".join(f"{g.test} ({_pts(g.ours)} vs {_pts(g.theirs)})" for g in c.gaps) or "–"
        lines.append(f"| {c.domain} | {ours} | {theirs} | {match} | {diff} |")
    details = [c for c in comparisons if c.gaps]
    if details:
        lines.append("\n**Observatory results for the tests that differ**\n")
        for c in details:
            for g in c.gaps:
                lines.append(f"- {c.domain} · `{g.test}`: Observatory result `{g.their_result}` "
                             f"({_pts(g.theirs)}), this tool {_pts(g.ours)}")
    return "\n".join(lines)

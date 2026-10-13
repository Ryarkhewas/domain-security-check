"""Comparison with Mozilla HTTP Observatory (no network: API answers are faked)."""

from datetime import datetime, timezone

import pytest

from domaincheck import observatory
from domaincheck.models import Category, CategoryGrade, Finding, Result, Status
from domaincheck.observatory import ObservatoryError, compare, fetch, markdown


def result(points_by_source, grade="B", score=75):
    findings = [Finding(Category.WEB, src, Status.OK, "d", points=p, source=src) for src, p in points_by_source.items()]
    findings.append(Finding(Category.EMAIL, "SPF", Status.OK, "d", points=-30, source="spf"))  # ignored
    return Result("example.com", datetime(2026, 10, 13, tzinfo=timezone.utc), findings,
                  {"WEB": CategoryGrade(score, grade)}, grade)


def api(tests, grade="B", score=75):
    return {"scan": {"grade": grade, "score": score, "error": None},
            "tests": {name: {"score_modifier": mod, "result": f"{name}-result"} for name, mod in tests.items()}}


def test_identical_results_have_no_gap():
    c = compare(result({"hsts": 0, "csp": -25}), api({"strict-transport-security": 0, "content-security-policy": -25}))
    assert c.same_grade and c.gaps == []


def test_gaps_are_listed_per_test():
    c = compare(result({"hsts": -20, "redirection": -10}, "C", 55),
                api({"strict-transport-security": -20, "redirection": -20}, "C-", 45))
    assert not c.same_grade
    assert [(g.test, g.ours, g.theirs) for g in c.gaps] == [("redirection", -10, -20)]
    assert c.gaps[0].their_result == "redirection-result"


def test_test_missing_on_our_side_counts_as_zero():
    c = compare(result({}), api({"cross-origin-opener-policy": 10}))
    assert [(g.test, g.ours) for g in c.gaps] == [("cross-origin-opener-policy", 0)]


def test_not_implemented_tests_only_show_when_they_score():
    c = compare(result({}), api({"subresource-integrity": 0, "cross-origin-resource-sharing": -50}))
    assert [(g.test, g.ours, g.theirs) for g in c.gaps] == [("cross-origin-resource-sharing", None, -50)]


def test_unscored_findings_are_not_compared():
    c = compare(result({"hsts": None}), api({"strict-transport-security": 0}))
    assert c.gaps == []


def test_error_is_reported():
    c = compare(result({}), None, "Site down")
    assert c.error == "Site down" and not c.same_grade
    assert "Observatory: Site down" in markdown([c])


def test_markdown_table():
    c = compare(result({"redirection": -10}, "C", 55), api({"redirection": -20}, "C-", 45))
    text = markdown([c])
    assert "| example.com | C (55) | C- (45) | **no** | redirection (-10 vs -20) |" in text
    assert "`redirection`: Observatory result `redirection-result` (-20), this tool -10" in text


class FakeResponse:
    def __init__(self, status, data):
        self.status_code, self._data = status, data

    def json(self):
        return self._data


class FakeSession:
    def __init__(self, response):
        self.response, self.calls = response, []

    def post(self, url, params, timeout):
        self.calls.append((url, params))
        return self.response


def test_fetch_ok():
    s = FakeSession(FakeResponse(200, api({})))
    assert fetch("example.com", s)["scan"]["grade"] == "B"
    assert s.calls == [(observatory.API_URL, {"host": "example.com"})]


@pytest.mark.parametrize("response, message", [
    (FakeResponse(422, {"error": "invalid-hostname", "message": "Cannot scan this host"}), "Cannot scan this host"),
    (FakeResponse(200, {"scan": {"error": "site down"}}), "site down"),
])
def test_fetch_errors(response, message):
    with pytest.raises(ObservatoryError, match=message):
        fetch("example.com", FakeSession(response))

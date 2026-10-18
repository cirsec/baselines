"""Tailoring files are checked against the content they tailor."""

import validate
from tailor import check_tailoring
from conftest import REPO

GOOD = {
    "standard": "buffet",
    "version": "1.1.0",
    "profile": "hardened",
    "parameters": {"CB-BUF-HYG-001": {"min_temp_c": 75}},
    "exclude": [{"control": "CB-BUF-GUARD-001", "reason": "Staff serve every dish."}],
}


def check(data):
    repo, _ = validate.run(REPO)
    return check_tailoring(repo, data)


def test_valid_tailoring():
    assert check(GOOD) == ([], [])


def test_override_out_of_bounds():
    errors, _ = check({**GOOD, "parameters": {"CB-BUF-HYG-001": {"min_temp_c": 40}}})
    assert any("below minimum 60" in e for e in errors)


def test_unknown_parameter_and_control():
    errors, _ = check({**GOOD, "parameters": {"CB-BUF-HYG-001": {"max_temp_c": 80}, "CB-BUF-HYG-404": {"x": 1}}})
    assert any("'max_temp_c' is not a parameter" in e for e in errors)
    assert any("unknown control CB-BUF-HYG-404" in e for e in errors)


def test_unknown_profile_and_schema():
    assert check({**GOOD, "profile": "gold"})[0] == ["unknown profile 'gold' (declared: ['baseline', 'hardened'])"]
    errors, _ = check({**GOOD, "exclude": [{"control": "CB-BUF-GUARD-001"}]})
    assert any("'reason' is a required property" in e for e in errors)


def test_warnings():
    _, warnings = check({**GOOD, "version": "0.9.0", "include": ["CB-BUF-HYG-001"],
                         "exclude": [{"control": "CB-BUF-GUARD-001", "reason": "x", "until": "2020-01-01"}]})
    assert len(warnings) == 3

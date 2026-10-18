"""Parameter resolution and the schemas that only tools consume (tailoring, result)."""

import json

from jsonschema import Draft202012Validator

import build
import validate
from common import control_profiles, load_yaml, resolve_parameters
from conftest import REPO


def load(root):
    repo, report = validate.run(root)
    assert report.errors == []
    return repo


def hyg1(repo):
    return repo.find_standard("buffet").controls["CB-BUF-HYG-001"]


def test_profile_defaults_follow_extends(buffet, repo):
    # competition extends hardened extends baseline, without its own value: inherits hardened's 70.
    std = buffet / "_standard.yml"
    std.write_text(std.read_text().replace(
        "    extends: baseline\n",
        "    extends: baseline\n  - key: competition\n    title: Competition\n    description: Eating contests.\n    extends: hardened\n",
        1,
    ))
    ctl = hyg1(load(repo))
    assert resolve_parameters(ctl, "baseline") == {"min_temp_c": 63}
    assert resolve_parameters(ctl, "hardened") == {"min_temp_c": 70}
    assert resolve_parameters(ctl, "competition") == {"min_temp_c": 70}
    assert resolve_parameters(ctl, "competition", {"min_temp_c": 80}) == {"min_temp_c": 80}
    assert control_profiles(ctl) == ["baseline", "competition", "hardened"]


def test_bundle_has_resolved_parameters_and_inlined_scripts():
    repo = load(REPO)
    std = repo.find_standard("buffet")
    bundle = build.build_bundle(repo, std, [std.controls["CB-BUF-HYG-001"], std.controls["CB-BUF-HYG-002"]], {})
    hyg1_b, hyg2_b = bundle["controls"]
    assert hyg1_b["resolved_parameters"] == {"baseline": {"min_temp_c": 63}, "hardened": {"min_temp_c": 70}}
    (script,) = hyg2_b["remediation"]["scripts"]
    assert script["file"] == "reminder.sh" and "CB_INTERVAL_MIN" in script["content"]
    assert {e["key"] for e in bundle["engines"]} == {"demo-sensor", "shell"}


def test_tailoring_template_is_valid():
    schema = json.loads((REPO / "schema/tailoring.schema.json").read_text())
    data = load_yaml(REPO / "templates/tailoring.yml")
    assert list(Draft202012Validator(schema).iter_errors(data)) == []

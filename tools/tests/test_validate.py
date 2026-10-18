"""Each test breaks one rule in a copy of the repo and checks the validator catches it."""

import re

import pytest

import validate


def run(root):
    _, report = validate.run(root)
    return [i.message for i in report.errors], [i.message for i in report.warnings]


def edit(path, old, new):
    text = path.read_text(encoding="utf-8")
    assert old in text, f"{old!r} not found in {path}"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def assert_error(root, pattern):
    errors, _ = run(root)
    assert any(re.search(pattern, e) for e in errors), f"expected /{pattern}/ in {errors}"


def test_current_repo_is_valid(repo):
    errors, warnings = run(repo)
    assert errors == []
    assert warnings == []


@pytest.mark.parametrize(
    "file, old, new, pattern",
    [
        # identity
        ("controls/CB-BUF-HYG-001.yml", "id: CB-BUF-HYG-001", "id: CB-BUF-HYG-009", r"must equal the file name"),
        ("controls/CB-BUF-HYG-001.yml", "profiles: [baseline]", "profiles: [gold]", r"unknown profile 'gold'"),
        # versions and engines
        ("controls/CB-BUF-HYG-001.yml", "versions: [classic]    # only", "versions: [vegan]    # only", r"version 'vegan' not in"),
        ("controls/CB-BUF-HYG-001.yml", "engine: demo-sensor    # must", "engine: telepathy    # must", r"engine 'telepathy' is not declared"),
        # parameters
        ("controls/CB-BUF-HYG-001.yml", "default: 63", "default: 42", r"below minimum"),
        ("controls/CB-BUF-HYG-001.yml", "default: 63", "default: hot", r"is not of type integer"),
        ("controls/CB-BUF-HYG-002.yml", "default: dishwasher", "default: tongue", r"not in allowed"),
        ("controls/CB-BUF-HYG-001.yml", "value: \"{{ min_temp_c }}\"", "value: \"{{ max_temp_c }}\"", r"undeclared parameter"),
        ("controls/CB-BUF-HYG-001.yml", "hardened: 70", "platinum: 70", r"unknown profile 'platinum'"),
        # mappings and threats
        ("controls/CB-BUF-HYG-001.yml", "id: FC-3.4", "id: 3.4", r"does not match demo-food-code pattern"),
        ("controls/CB-BUF-HYG-001.yml", "framework: demo-buffet-threats", "framework: demo-food-code", r"use mappings instead"),
        ("controls/CB-BUF-HYG-001.yml", "framework: demo-food-code", "framework: hacker-news", r"not declared in baselines.yml"),
        # relations and lifecycle
        ("controls/CB-BUF-HYG-001.yml", "id: CB-BUF-GUARD-001", "id: CB-BUF-GUARD-404", r"unknown control"),
        ("controls/CB-BUF-ABUSE-002.yml", "supersedes: [CB-BUF-ABUSE-001]", "supersedes: [CB-BUF-GUARD-001]", r"which is not deprecated"),
        ("controls/CB-BUF-ABUSE-001.yml", "deprecated_in: 1.1.0", "deprecated_in: 9.0.0", r"after the standard version"),
        ("controls/CB-BUF-HYG-002.yml", "introduced_in: 1.1.0", "introduced_in: 2.0.0", r"after the standard version"),
        ("controls/CB-BUF-HYG-001.yml", "created: 2026-10-01", "created: 2026-12-01", r"updated is earlier than created"),
        # people
        ("controls/CB-BUF-HYG-001.yml", "  - name: Chef Demo\n", "  - name: Ali\n    github: sn0walice\n", r"is also an author"),
        # schema
        ("controls/CB-BUF-HYG-001.yml", "assessment: automated", "assessment: vibes", r"schema: assessment"),
        ("controls/CB-BUF-HYG-001.yml", "tags: [temperature", "flavour: umami\ntags: [temperature", r"schema: .*flavour"),
        # standard
        ("_standard.yml", "extends: baseline", "extends: hardened", r"circular extends"),
        ("_standard.yml", "code: BUF", "code: M365", r"code 'M365' already used"),
        ("_standard.yml", "id: buffet", "id: brunch", r"must equal the folder name"),
        # translations
        ("i18n/fr/CB-BUF-HYG-001.yml", "locale: fr", "locale: de", r"must equal the folder name 'fr'"),
        ("i18n/fr/CB-BUF-HYG-001.yml", "  min_temp_c: Temp", "  max_temp_c: Temp", r"is not a parameter"),
        # engine specs and capabilities
        ("controls/CB-BUF-HYG-001.yml", "sensor: bain_marie.*.core_temp", "sensr: bain_marie", r"spec: .*'sensor' is a required"),
        ("controls/CB-BUF-HYG-002.yml", "engine: shell", "engine: demo-sensor", r"has no 'script' capability"),
        # facts
        ("_standard.yml", "key: cleaning-app", "key: sneeze-guard-rails", r"duplicate fact"),
        ("_standard.yml", "sensor: cleaning_app.installed", "sensr: x", r"facts.cleaning-app.detect: spec"),
        ("controls/CB-BUF-GUARD-001.yml", "facts: [sneeze-guard-rails]", "facts: [unicorn]", r"fact 'unicorn' is not declared"),
        ("controls/CB-BUF-HYG-002.yml", "facts: [cleaning-app]", "facts: [robot]", r"fact 'robot' is not declared"),
        # remediation
        ("controls/CB-BUF-HYG-001.yml", "from_check: bain-marie-temp", "from_check: fridge", r"is not a check of this control"),
        ("controls/CB-BUF-HYG-001.yml", "restart: none            # none", "restart: service            # none", r"'services' is a required"),
        ("controls/CB-BUF-HYG-002.yml", "  effects:\n    restart: none\n    disruption: none\n", "", r"'effects' is a dependency of 'scripts'"),
        ("controls/CB-BUF-HYG-002.yml", "file: reminder.sh", "file: gone.sh", r"scripts/CB-BUF-HYG-002/gone.sh does not exist"),
        ("controls/CB-BUF-HYG-002.yml", "      file: reminder.sh", "      file: reminder.sh\n      content: echo", r"schema: remediation/scripts/0"),
        # verification
        ("controls/CB-BUF-HYG-001.yml", "versions: [conveyor]\n    environment: Sushi", "versions: [classic]\n    environment: Sushi", r"not verified on version\(s\) \['conveyor'\]"),
        ("controls/CB-BUF-ABUSE-002.yml", "versions: [classic, conveyor]", "versions: [classic, vegan]", r"version 'vegan' not in"),
    ],
)
def test_rule_is_enforced(buffet, repo, file, old, new, pattern):
    edit(buffet / file, old, new)
    assert_error(repo, pattern)


def test_duplicate_yaml_key(buffet, repo):
    edit(buffet / "controls/CB-BUF-HYG-001.yml", "status: active", "status: active\nstatus: draft")
    assert_error(repo, r"duplicate key 'status'")


def test_duplicate_control_id_across_standards(buffet, repo):
    other = repo / "categories/os/debian/controls/CB-BUF-HYG-001.yml"
    other.write_text((buffet / "controls/CB-BUF-HYG-001.yml").read_text(encoding="utf-8"), encoding="utf-8")
    assert_error(repo, r"duplicate control id")


def test_wrong_extension(buffet, repo):
    (buffet / "controls/CB-BUF-HYG-001.yml").rename(buffet / "controls/CB-BUF-HYG-001.yaml")
    assert_error(repo, r"use the \.yml extension")


def test_unexpected_folder_in_standard(buffet, repo):
    (buffet / "drafts").mkdir()
    assert_error(repo, r"unexpected folder")


def test_orphan_translation(buffet, repo):
    (buffet / "i18n/fr/CB-BUF-HYG-001.yml").rename(buffet / "i18n/fr/CB-BUF-HYG-077.yml")
    assert_error(repo, r"translation of unknown control")


def test_stale_translation_is_a_warning(buffet, repo):
    edit(buffet / "controls/CB-BUF-HYG-001.yml", "updated: 2026-10-16", "updated: 2026-10-17")
    errors, warnings = run(repo)
    assert errors == []
    assert any("stale translation" in w for w in warnings)


def test_strict_mode_fails_on_warnings(buffet, repo):
    edit(buffet / "controls/CB-BUF-HYG-001.yml", "updated: 2026-10-16", "updated: 2026-10-17")
    assert validate.main(["--root", str(repo)]) == 0
    assert validate.main(["--root", str(repo), "--strict"]) == 1


def test_placeholder_forbidden_in_code(buffet, repo):
    edit(buffet / "scripts/CB-BUF-HYG-002/reminder.sh", '"$CB_INTERVAL_MIN"', '"{{ interval_min }}"')
    assert_error(repo, r"no \{\{ \}\} in code")


def test_from_check_needs_fix_capability(repo):
    edit(repo / "baselines.yml", "  - key: demo-sensor\n    capabilities: [check, fix]", "  - key: demo-sensor\n    capabilities: [check]")
    assert_error(repo, r"engine 'demo-sensor' of check 'bain-marie-temp' has no 'fix' capability")


def test_engine_spec_schema_must_exist(repo):
    (repo / "schema/engines/demo-sensor.schema.json").unlink()
    assert_error(repo, r"spec_schema schema/engines/demo-sensor.schema.json does not exist")


def test_unreferenced_script_file(buffet, repo):
    (buffet / "scripts/CB-BUF-HYG-002/extra.sh").write_text("true\n")
    assert_error(repo, r"not referenced by CB-BUF-HYG-002")


def test_script_folder_of_unknown_control(buffet, repo):
    (buffet / "scripts/CB-BUF-NOPE-001").mkdir()
    assert_error(repo, r"scripts/ only holds <control ID>/ folders")


def test_id_only_mappings_are_a_warning(repo):
    edit(repo / "baselines.yml", "    reference_policy: id-title\n    display_order: 10\n  - key: demo-buffet-threats",
         "    reference_policy: id-only\n    display_order: 10\n  - key: demo-buffet-threats")
    errors, warnings = run(repo)
    assert errors == []
    assert any("only point to id-only frameworks" in w for w in warnings)

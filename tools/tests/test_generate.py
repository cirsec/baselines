"""Generator: shell runtime, end-to-end run of generated scripts, golden files, Ansible, OSCAL.

Golden files live in tools/tests/golden/. After an intended generator change, refresh them with
    UPDATE_GOLDEN=1 python -m pytest -q tools/tests/test_generate.py
and review the diff.
"""

import json
import os
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

import build
import generate
import validate
from conftest import REPO, TOOLS

FIXTURE = TOOLS / "tests" / "fixtures" / "lab"
GOLDEN = TOOLS / "tests" / "golden"
LIB = TOOLS / "lib" / "cirsec.sh"


@pytest.fixture
def lab(repo):
    shutil.copytree(FIXTURE, repo / "categories" / "demo" / "lab")
    return repo


def load(root):
    repo, report = validate.run(root)
    assert [i.message for i in report.errors] == []
    return repo


def gen(root, out, profile="strict", tailoring=None):
    repo = load(root)
    generate.generate(repo, repo.find_standard("lab"), profile, out, tailoring=tailoring)
    return out


def sh(script, *args, env=None, cwd=None):
    full_env = {**os.environ, "CB_BACKUP_DIR": "/tmp/cirsec-test-backup", **(env or {})}
    return subprocess.run(["sh", str(script), *args], capture_output=True, text=True, env=full_env, cwd=cwd)


# --------------------------------------------------------------------------- runtime


@pytest.mark.parametrize("observed, op, expected, rc", [
    ("no", "==", "no", 0), ("yes", "==", "no", 1), ("a", "!=", "b", 0),
    ("4", "<=", "6", 0), ("7", "<=", "6", 1), ("-1", "<", "0", 0), ("x", ">=", "1", 3), ("1.5", ">", "1", 3),
    ("b", "in", "a\nb", 0), ("c", "in", "a\nb", 1), ("c", "not_in", "a\nb", 0),
    ("abc123", "match", "^abc[0-9]+$", 0), ("abc", "match", "^z", 1), ("a", "~", "a", 3),
])
def test_cb_cmp(observed, op, expected, rc):
    r = subprocess.run(["sh", "-c", f'. "{LIB}"; cb_cmp "$1" "$2" "$3"', "sh", observed, op, expected],
                       capture_output=True, env={**os.environ, "CB_PRODUCT_VERSION": "x"})
    assert r.returncode == rc


# --------------------------------------------------------------------------- end to end


def test_generated_scripts_run(lab, tmp_path):
    flag = tmp_path / "flag"
    tailoring = {"standard": "lab", "version": "0.1.0", "profile": "base",
                 "parameters": {"CB-LAB-FILE-001": {"target": str(flag)}}}
    out = gen(lab, tmp_path / "gen", profile="base", tailoring=tailoring)
    ctl = out / "controls" / "CB-LAB-FILE-001.sh"
    env = {"CB_PRODUCT_VERSION": "a"}

    r = sh(ctl, "check", env=env)
    assert r.returncode == 1
    assert "check\texists\tfail" in r.stdout
    assert "check\tonly-on-b\tnot_applicable" in r.stdout          # version filter

    r = sh(ctl, "fix", env=env)
    assert "fix\tcreate\twould-apply" in r.stdout and not flag.exists()  # dry run by default

    r = sh(ctl, "fix", "--apply", env=env)
    assert r.returncode == 0 and "fix\tcreate\tCHANGED" in r.stdout
    assert flag.read_text() == "heredoc kept verbatim\n"          # handwritten code kept verbatim

    r = sh(ctl, "check", env=env)
    assert r.returncode == 0 and "control\tCB-LAB-FILE-001\tpass" in r.stdout

    r = sh(out / "controls" / "CB-LAB-FILE-002.sh", "check", env=env)
    assert r.returncode == 2 and "not_applicable" in r.stdout     # fact "never" is false

    r = sh(ctl, "check", env={"CB_PRODUCT_VERSION": ""})
    assert "check\tonly-on-b\terror" in r.stdout                  # unknown version is an error, not n/a


def test_audit_output_matches_result_schema(lab, tmp_path):
    tailoring = {"standard": "lab", "version": "0.1.0", "profile": "strict",
                 "exclude": [{"control": "CB-LAB-FILE-002", "reason": "test"}]}
    out = gen(lab, tmp_path / "gen", tailoring=tailoring)
    r = sh(out / "audit.sh", env={"CB_PRODUCT_VERSION": "a"})
    assert r.returncode == 1  # the flag file is missing
    result = json.loads(r.stdout)
    schema = json.loads((REPO / "schema" / "result.schema.json").read_text())
    assert list(Draft202012Validator(schema).iter_errors(result)) == []
    status = {c["control"]: c["status"] for c in result["results"]}
    assert status["CB-LAB-FILE-001"] == "fail"
    assert status["CB-LAB-FILE-002"] == "excluded"
    assert result["results"][0]["parameters"] == {"target": "/nonexistent/flag"}
    sys_checks = {c["id"]: c for c in next(c for c in result["results"] if c["control"] == "CB-LAB-SYS-001")["checks"]}
    assert sys_checks["auth-tries"]["evidence"]["expected"] == "<= 4"
    # Readable report on stderr, without colors when stderr is not a terminal.
    assert "✘ CB-LAB-FILE-001" in r.stderr and "1 excluded" in r.stderr
    assert "\033" not in r.stderr


def test_remediate_dry_run_and_lockout_default(lab, tmp_path):
    out = gen(lab, tmp_path / "gen")
    r = sh(out / "remediate.sh", env={"CB_PRODUCT_VERSION": "a"})
    assert "CB-LAB-FILE-001\tfix\tcreate\twould-apply" in r.stdout
    assert "CB-LAB-SYS-001\tdisabled" in r.stdout                 # lockout_risk: off by default
    defaults = yaml.safe_load((out / "ansible/roles/cirsec_lab/defaults/main.yml").read_text())
    assert defaults["cirsec_lab_cb_lab_sys_001_enabled"] is False

    out = gen(lab, tmp_path / "gen2", tailoring={"standard": "lab", "version": "0.1.0", "profile": "strict",
                                                  "fixes": {"CB-LAB-SYS-001": True}})
    defaults = yaml.safe_load((out / "ansible/roles/cirsec_lab/defaults/main.yml").read_text())
    assert defaults["cirsec_lab_cb_lab_sys_001_enabled"] is True


def test_dependency_order(lab, tmp_path):
    out = gen(lab, tmp_path / "gen")
    text = (out / "audit.sh").read_text()
    assert text.index("run CB-LAB-FILE-001") < text.index("run CB-LAB-FILE-002")  # FILE-002 requires FILE-001


# --------------------------------------------------------------------------- static checks


def test_generated_files_are_valid(lab, tmp_path):
    out = gen(lab, tmp_path / "gen")
    scripts = sorted(out.rglob("*.sh"))
    for f in scripts:
        assert os.access(f, os.X_OK), f
        r = subprocess.run(["sh", "-n", str(f)], capture_output=True, text=True)
        assert r.returncode == 0, f"{f}: {r.stderr}"
    for f in out.rglob("*.yml"):
        assert yaml.safe_load(f.read_text()) is not None, f
    tasks = yaml.safe_load((out / "ansible/roles/cirsec_lab/tasks/main.yml").read_text())
    fix = next(t for t in tasks if t["name"] == "CB-LAB-SYS-001 | fix")
    assert fix["notify"] == ["cirsec restart ssh"]
    handlers = yaml.safe_load((out / "ansible/roles/cirsec_lab/handlers/main.yml").read_text())
    assert handlers[0]["name"] == "cirsec restart ssh"
    if shutil.which("shellcheck"):
        r = subprocess.run(["shellcheck", "-S", "warning", "-s", "sh", str(LIB), *map(str, scripts)],
                           capture_output=True, text=True)
        assert r.returncode == 0, r.stdout


def _golden_files(out: Path) -> dict[str, str]:
    lib = LIB.read_text().rstrip()
    files = {}
    for rel in ("controls/CB-LAB-SYS-001.sh", "controls/CB-LAB-FILE-001.sh", "audit.sh", "remediate.sh",
                "ansible/site.yml", "ansible/roles/cirsec_lab/tasks/main.yml",
                "ansible/roles/cirsec_lab/defaults/main.yml", "ansible/roles/cirsec_lab/handlers/main.yml"):
        files[rel] = (out / rel).read_text().replace(lib, "# <tools/lib/cirsec.sh>")
    return files


def test_golden_files(lab, tmp_path):
    files = _golden_files(gen(lab, tmp_path / "gen"))
    if os.environ.get("UPDATE_GOLDEN"):
        shutil.rmtree(GOLDEN, ignore_errors=True)
        for rel, text in files.items():
            (GOLDEN / rel).parent.mkdir(parents=True, exist_ok=True)
            (GOLDEN / rel).write_text(text)
    for rel, text in files.items():
        assert (GOLDEN / rel).read_text() == text, f"{rel} differs, see the module docstring"


# --------------------------------------------------------------------------- release


def test_release_has_oscal_and_generated(repo, tmp_path):
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    out = tmp_path / "out"
    assert build.main(["--root", str(repo), "--standard", "buffet", "--allow-demo", "--no-tag-check", "--out", str(out)]) == 0
    with zipfile.ZipFile(next(out.glob("*.zip"))) as zf:
        names = zf.namelist()
        catalog = json.loads(zf.read(next(n for n in names if n.endswith("oscal/catalog.json"))))
        profile = json.loads(zf.read(next(n for n in names if n.endswith("oscal/profile-hardened.json"))))
        mode = zf.getinfo(next(n for n in names if n.endswith("generated/hardened/audit.sh"))).external_attr >> 16
    ids = [c["id"] for g in catalog["catalog"]["groups"] for c in g["controls"]]
    assert ids == ["cb-buf-hyg-001", "cb-buf-guard-001", "cb-buf-abuse-001", "cb-buf-abuse-002"]
    params = {p["param-id"]: p["values"] for p in profile["profile"]["modify"]["set-parameters"]}
    assert params["cb-buf-hyg-001_prm_min_temp_c"] == ["70"]
    assert any(n.endswith("generated/baseline/ansible/site.yml") for n in names)
    assert mode == 0o755


@pytest.mark.parametrize("target,listed,rc", [("24.04", "24.04", 0), ("24.04", "22.04", 2), ("12", "12", 0), ("12.7", "12", 0), ("", "12", 3)])
def test_cb_version_in(target, listed, rc):
    r = subprocess.run(["sh", "-c", f'. "{LIB}"; cb_version_in {listed} 26.04'], capture_output=True, text=True,
                       env={**os.environ, "CB_PRODUCT_VERSION": target})
    assert r.returncode == rc


def test_fix_skipped_when_check_errors(tmp_path):
    marker = tmp_path / "touched"
    script = (f'. "{LIB}"; CB_APPLY=1 CB_RC=0; '
              f'chk() {{ return 3; }}; fx() {{ touch "{marker}"; }}; '
              f'cb_fixit demo "" "" chk fx; exit "$CB_RC"')
    r = subprocess.run(["sh", "-c", script], capture_output=True, text=True, env={**os.environ, "CB_PRODUCT_VERSION": "x"})
    assert r.returncode == 1 and "fix\tdemo\terror" in r.stdout
    assert not marker.exists()

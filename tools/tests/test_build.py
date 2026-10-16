"""Release builder: content selection, reproducibility, guards and release notes."""

import json
import subprocess
import zipfile

import build


def git(root, *args):
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)


def init_git(root):
    git(root, "init", "-q", "-b", "main")
    git(root, "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
    git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init")


def commit_all(root, msg):
    git(root, "-c", "user.name=t", "-c", "user.email=t@t", "add", "-A")
    git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", msg)


def do_build(repo, out, *extra):
    return build.main(["--root", str(repo), "--standard", "buffet", "--allow-demo", "--out", str(out), *extra])


def read_bundle(out):
    (zip_path,) = out.glob("*.zip")
    with zipfile.ZipFile(zip_path) as zf:
        name = next(n for n in zf.namelist() if n.endswith("/bundle.json"))
        return json.loads(zf.read(name)), zf.namelist()


def test_build_selects_released_controls_only(repo, tmp_path):
    init_git(repo)
    out = tmp_path / "out"
    assert do_build(repo, out) == 0
    bundle, names = read_bundle(out)
    ids = [c["id"] for c in bundle["controls"]]
    assert ids == ["CB-BUF-ABUSE-001", "CB-BUF-ABUSE-002", "CB-BUF-GUARD-001", "CB-BUF-HYG-001"]
    assert "CB-BUF-HYG-002" not in json.dumps(ids)  # status review: not released
    hyg = next(c for c in bundle["controls"] if c["id"] == "CB-BUF-HYG-001")
    assert hyg["translations"]["fr"]["title"].startswith("Maintenir")
    assert hyg["translation_status"] == {"fr": "current"}
    assert {e["key"] for e in bundle["engines"]} == {"demo-sensor"}
    assert any(n.endswith("controls/CB-BUF-HYG-001.yml") for n in names)
    assert not any(n.endswith("CB-BUF-HYG-002.yml") for n in names)


def test_build_is_reproducible(repo, tmp_path):
    init_git(repo)
    a, b = tmp_path / "a", tmp_path / "b"
    assert do_build(repo, a) == 0 and do_build(repo, b) == 0
    assert next(a.glob("*.sha256")).read_text() == next(b.glob("*.sha256")).read_text()


def test_version_must_match_standard(repo, tmp_path):
    init_git(repo)
    assert do_build(repo, tmp_path / "out", "--version", "9.9.9") == 1


def test_demo_needs_flag(repo, tmp_path):
    init_git(repo)
    assert build.main(["--root", str(repo), "--standard", "buffet", "--out", str(tmp_path)]) == 1


def test_existing_tag_is_refused(repo, tmp_path):
    init_git(repo)
    git(repo, "tag", "buffet/v1.1.0")
    assert do_build(repo, tmp_path / "out") == 1
    assert do_build(repo, tmp_path / "out", "--no-tag-check") == 0


def test_invalid_content_blocks_build(buffet, repo, tmp_path):
    init_git(repo)
    p = buffet / "controls/CB-BUF-HYG-001.yml"
    p.write_text(p.read_text().replace("assessment: automated", "assessment: vibes"))
    assert do_build(repo, tmp_path / "out") == 1


def test_release_notes_diff_previous_tag(buffet, repo, tmp_path):
    std = buffet / "_standard.yml"
    std.write_text(std.read_text().replace("version: 1.1.0", "version: 1.0.0"))
    # State of 1.0.0: ABUSE-001 still active, ABUSE-002 does not exist yet.
    abuse1 = buffet / "controls/CB-BUF-ABUSE-001.yml"
    original_abuse1 = abuse1.read_text()
    lines = [l for l in original_abuse1.splitlines()
             if not l.startswith(("deprecated_in", "superseded_by", "deprecation_reason", "  Counting", "  Replaced"))]
    abuse1.write_text("\n".join(lines).replace("status: deprecated", "status: active") + "\n")
    abuse2 = buffet / "controls/CB-BUF-ABUSE-002.yml"
    original_abuse2 = abuse2.read_text()
    abuse2.unlink()
    hyg2 = buffet / "controls/CB-BUF-HYG-002.yml"
    original_hyg2 = hyg2.read_text()
    hyg2.write_text(original_hyg2.replace("introduced_in: 1.1.0", "introduced_in: 1.0.0"))
    init_git(repo)
    git(repo, "tag", "buffet/v1.0.0")

    # Back to 1.1.0: ABUSE-001 deprecated, ABUSE-002 added.
    std.write_text(std.read_text().replace("version: 1.0.0", "version: 1.1.0"))
    abuse1.write_text(original_abuse1)
    abuse2.write_text(original_abuse2)
    hyg2.write_text(original_hyg2)
    commit_all(repo, "1.1.0")

    out = tmp_path / "out"
    assert do_build(repo, out) == 0
    notes = (out / "RELEASE_NOTES.md").read_text()
    assert "Changes since `buffet/v1.0.0`" in notes
    added = notes.split("### Added")[1].split("###")[0]
    deprecated = notes.split("### Deprecated")[1].split("###")[0]
    assert "CB-BUF-ABUSE-002" in added
    assert "CB-BUF-ABUSE-001" in deprecated

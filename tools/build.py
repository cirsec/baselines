#!/usr/bin/env python3
"""Build a release bundle for one standard (or all, for smoke tests).

A release contains the controls with status "active" or "deprecated" (draft and
review controls are left out), their translations, the root metadata, the
schemas and the content license, plus two generated files:

  bundle.json   everything resolved in one JSON file (controls + translations)
  index.json    lightweight list of controls, for sites and scanners

Outputs, in --out (default: dist/):

  cirsec-baselines-<standard>-<version>.zip          deterministic archive
  cirsec-baselines-<standard>-<version>.zip.sha256   checksum
  RELEASE_NOTES.md                                   changes since the previous tag

The release tag is "<standard>/v<version>". The version must already be set in
_standard.yml (bump it in a pull request, then release).

Usage:
    python tools/build.py --standard m365 --version 1.0.0
    python tools/build.py --all --allow-demo --allow-empty --no-tag-check   # CI smoke test
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, SLUG_RE, Control, Repo, Standard, load_yaml_text, parse_semver  # noqa: E402
import validate  # noqa: E402

RELEASED_STATUSES = {"active", "deprecated"}
DEMO_CATEGORY = "demo"
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)  # fixed timestamps -> reproducible archives


class BuildError(Exception):
    pass


# =========================================================================== git


def git(root: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(
            ["git", *args], cwd=root, check=True, capture_output=True, text=True
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return out.stdout.strip()


def tag_exists(root: Path, tag: str) -> bool:
    return git(root, "rev-parse", "-q", "--verify", f"refs/tags/{tag}") is not None


def previous_tag(root: Path, std_id: str, version: str) -> str | None:
    out = git(root, "tag", "--list", f"{std_id}/v*")
    if not out:
        return None
    current = parse_semver(version)
    best = None
    for tag in out.splitlines():
        v = parse_semver(tag.split("/v", 1)[-1])
        if v is not None and v < current and (best is None or v > best[0]):
            best = (v, tag)
    return best[1] if best else None


def controls_at_tag(root: Path, tag: str, std: Standard) -> dict[str, dict]:
    rel = std.path.relative_to(root).as_posix() + "/controls"
    listing = git(root, "ls-tree", "-r", "--name-only", tag, "--", rel) or ""
    out = {}
    for path in listing.splitlines():
        if not path.endswith(".yml"):
            continue
        text = git(root, "show", f"{tag}:{path}")
        if text is None:
            continue
        try:
            data = load_yaml_text(text)
        except Exception:  # an old file we cannot parse should not block a release
            continue
        if isinstance(data, dict):
            out[Path(path).stem] = data
    return out


# =========================================================================== content


def selected_controls(std: Standard) -> list[Control]:
    return sorted(
        (c for c in std.controls.values() if c.data.get("status") in RELEASED_STATUSES),
        key=lambda c: c.id,
    )


def translation_payload(ctl: Control) -> tuple[dict, dict]:
    texts, status = {}, {}
    for locale, tr in sorted(ctl.translations.items()):
        texts[locale] = {k: v for k, v in tr.data.items() if k not in ("id", "locale")}
        stale = tr.data.get("source_updated", "") < ctl.data.get("updated", "")
        status[locale] = "stale" if stale else "current"
    return texts, status


def build_bundle(repo: Repo, std: Standard, controls: list[Control], release: dict) -> dict:
    used_engines, used_frameworks = set(), set()
    items = []
    for ctl in controls:
        d = ctl.data
        for group in ((d.get("audit") or {}).get("checks"), (d.get("remediation") or {}).get("scripts")):
            used_engines.update(i.get("engine") for i in group or [])
        used_frameworks.update(m.get("framework") for m in d.get("mappings", []) or [])
        used_frameworks.update(m.get("framework") for m in d.get("threats", []) or [])
        texts, status = translation_payload(ctl)
        items.append({**d, "translations": texts, "translation_status": status})

    meta = repo.meta
    return {
        "format": "cirsec-baselines-bundle",
        "schema_version": meta.get("schema_version"),
        "project": meta.get("project"),
        "licenses": meta.get("licenses"),
        "release": release,
        "category": std.category.data,
        "standard": std.data,
        "locales": meta.get("locales"),
        "engines": [e for e in meta.get("engines", []) if e.get("key") in used_engines],
        "frameworks": [f for f in meta.get("frameworks", []) if f.get("key") in used_frameworks],
        "controls": items,
    }


def build_index(std: Standard, controls: list[Control], release: dict) -> dict:
    rows = []
    for ctl in controls:
        d = ctl.data
        rows.append({
            "id": ctl.id,
            "domain": ctl.id.split("-")[2],
            "title": d.get("title"),
            "finding": (d.get("finding") or {}).get("title"),
            "status": d.get("status"),
            "profiles": d.get("profiles"),
            "severity": (d.get("risk") or {}).get("severity"),
            "score": (d.get("risk") or {}).get("score"),
            "assessment": d.get("assessment"),
            "introduced_in": d.get("introduced_in"),
            "deprecated_in": d.get("deprecated_in"),
            "superseded_by": d.get("superseded_by"),
            "locales": sorted(ctl.translations),
        })
    return {
        "standard": {k: std.data.get(k) for k in ("id", "code", "title", "version", "status")},
        "category": std.category.id,
        "release": release,
        "controls": rows,
    }


def release_notes(repo: Repo, std: Standard, controls: list[Control], release: dict, prev: str | None) -> str:
    title = f"{std.data.get('title')} v{release['version']}"
    lines = [f"# {title}", "", f"Tag `{release['tag']}`, commit `{release['commit'][:12]}`, {release['date']}.", ""]

    active = [c for c in controls if c.data.get("status") == "active"]
    deprecated = [c for c in controls if c.data.get("status") == "deprecated"]
    lines += ["## Summary", "", f"- **{len(active)}** active controls, **{len(deprecated)}** deprecated"]
    parents = {p.get("key"): p.get("extends") for p in std.data.get("profiles", [])}
    for prof in parents:
        chain, cur = set(), prof
        while cur is not None and cur not in chain:  # profile + every profile it extends
            chain.add(cur)
            cur = parents.get(cur)
        n = sum(1 for c in active if chain & set(c.data.get("profiles", [])))
        extra = f" (includes {', '.join(sorted(chain - {prof}))})" if len(chain) > 1 else ""
        lines.append(f"- profile `{prof}`: {n} active control(s){extra}")
    sev: dict[str, int] = {}
    for c in active:
        s = (c.data.get("risk") or {}).get("severity", "?")
        sev[s] = sev.get(s, 0) + 1
    order = ["critical", "high", "medium", "low", "info"]
    lines.append("- severity: " + ", ".join(f"{k} {sev[k]}" for k in order if k in sev))
    for locale in sorted(repo.locales - {repo.default_locale}):
        done = [c for c in controls if locale in c.translations]
        stale = [c for c in done if translation_payload(c)[1].get(locale) == "stale"]
        lines.append(f"- translation `{locale}`: {len(done)}/{len(controls)}" + (f" ({len(stale)} stale)" if stale else ""))
    lines.append("")

    def entry(c_id: str, data: dict) -> str:
        return f"- `{c_id}` {data.get('title', '')}"

    if prev is None:
        lines += ["## Changes", "", "Initial release.", ""]
    else:
        old = {k: v for k, v in controls_at_tag(repo.root, prev, std).items() if v.get("status") in RELEASED_STATUSES}
        new = {c.id: c.data for c in controls}
        added = [k for k in new if k not in old]
        newly_dep = [k for k in new if k in old and new[k].get("status") == "deprecated" and old[k].get("status") != "deprecated"]
        updated = [k for k in new if k in old and k not in newly_dep and new[k].get("updated") != old[k].get("updated")]
        removed = [k for k in old if k not in new]
        lines += [f"## Changes since `{prev}`", ""]
        for label, keys, src in (("Added", added, new), ("Deprecated", newly_dep, new), ("Updated", updated, new), ("Removed", removed, old)):
            if keys:
                lines += [f"### {label}", ""] + [entry(k, src[k]) for k in sorted(keys)] + [""]
        if not (added or newly_dep or updated or removed):
            lines += ["No control changes (metadata, translations or tooling only).", ""]

    lines += [
        "## Files",
        "",
        "- `cirsec-baselines-*.zip`: controls (YAML), translations, schemas, `bundle.json`, `index.json`",
        "- `*.sha256`: checksum of the archive",
        "",
        f"Content licensed under {repo.meta.get('licenses', {}).get('content', 'CC-BY-4.0')}. "
        "Independent project, not affiliated with or endorsed by any referenced framework publisher.",
        "",
    ]
    return "\n".join(lines)


def bundle_readme(std: Standard, release: dict) -> str:
    return (
        f"# CIRSEC Baselines - {std.data.get('title')} v{release['version']}\n\n"
        f"Tag `{release['tag']}`, commit `{release['commit']}`.\n\n"
        "- `bundle.json`: every released control with its translations, resolved in one file\n"
        "- `index.json`: lightweight list of controls\n"
        "- `categories/`: source YAML files (same layout as the repository)\n"
        "- `schema/`: JSON Schemas for the YAML files\n"
        "- `baselines.yml`: engines, frameworks and locales referenced by controls\n\n"
        "Only controls with status `active` or `deprecated` are included.\n"
        "Control content is licensed under CC BY 4.0, see `LICENSE-CONTENT`.\n"
    )


# =========================================================================== build


def write_zip(src_dir: Path, zip_path: Path) -> None:
    files = sorted(p for p in src_dir.rglob("*") if p.is_file())
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for f in files:
            info = zipfile.ZipInfo(f.relative_to(src_dir.parent).as_posix(), date_time=ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, f.read_bytes())


def build_standard(repo: Repo, std: Standard, version: str | None, out: Path, *,
                   allow_demo: bool, allow_empty: bool, tag_check: bool) -> dict:
    root = repo.root
    std_version = std.data.get("version")
    version = version or std_version
    if parse_semver(version or "") is None:
        raise BuildError(f"invalid version {version!r}, expected SemVer like 1.2.0")
    if version != std_version:
        raise BuildError(
            f"{std.id}: requested version {version} but _standard.yml says {std_version}. "
            "Bump the version in _standard.yml through a pull request first."
        )
    if std.category.id == DEMO_CATEGORY and not allow_demo:
        raise BuildError(f"{std.id} is in the demo category and cannot be released")

    tag = f"{std.id}/v{version}"
    if tag_check and tag_exists(root, tag):
        raise BuildError(f"tag {tag} already exists")

    controls = selected_controls(std)
    if not controls and not allow_empty:
        raise BuildError(f"{std.id}: no active or deprecated control to release")

    released_ids = {c.id for c in controls}
    for c in controls:
        for rel in c.data.get("related_controls", []) or []:
            if rel.get("id", "").startswith(f"CB-{std.data.get('code')}-") and rel.get("id") not in released_ids:
                print(f"WARNING {c.id}: related control {rel.get('id')} is not part of this release")

    commit = git(root, "rev-parse", "HEAD") or os.environ.get("GITHUB_SHA", "unknown")
    rel_date = std.data.get("released") or git(root, "log", "-1", "--format=%cs") or date.today().isoformat()
    prev = previous_tag(root, std.id, version)
    release = {"version": version, "tag": tag, "commit": commit, "date": rel_date, "previous_tag": prev}

    name = f"cirsec-baselines-{std.id}-{version}"
    out.mkdir(parents=True, exist_ok=True)
    stage = out / "_stage" / name
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)

    # Root files
    for rel in ("baselines.yml", "LICENSE-CONTENT"):
        shutil.copy2(root / rel, stage / rel)
    shutil.copytree(root / "schema", stage / "schema")

    # Category, standard, released controls and their translations, same layout as the repo
    std_rel = std.path.relative_to(root)
    (stage / std_rel / "controls").mkdir(parents=True)
    shutil.copy2(std.category.path / "_category.yml", stage / std_rel.parent / "_category.yml")
    shutil.copy2(std.path / "_standard.yml", stage / std_rel / "_standard.yml")
    for c in controls:
        shutil.copy2(c.path, stage / std_rel / "controls" / c.path.name)
        for locale, tr in c.translations.items():
            dst = stage / std_rel / "i18n" / locale / tr.path.name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(tr.path, dst)

    dump = lambda obj: json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=False) + "\n"  # noqa: E731
    (stage / "bundle.json").write_text(dump(build_bundle(repo, std, controls, release)), encoding="utf-8")
    (stage / "index.json").write_text(dump(build_index(std, controls, release)), encoding="utf-8")
    (stage / "README.md").write_text(bundle_readme(std, release), encoding="utf-8")

    zip_path = out / f"{name}.zip"
    write_zip(stage, zip_path)
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    sha_path = out / f"{name}.zip.sha256"
    sha_path.write_text(f"{digest}  {zip_path.name}\n", encoding="utf-8")

    notes_path = out / "RELEASE_NOTES.md"
    notes_path.write_text(release_notes(repo, std, controls, release, prev), encoding="utf-8")

    shutil.rmtree(out / "_stage")
    return {
        "tag": tag,
        "title": f"{std.data.get('title')} v{version}",
        "zip": str(zip_path),
        "sha256": str(sha_path),
        "notes": str(notes_path),
        "controls": len(controls),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--standard", help="standard id (folder name), e.g. m365")
    target.add_argument("--all", action="store_true", help="build every standard at its current version (smoke test)")
    ap.add_argument("--version", help="version to release, must equal _standard.yml (default: that version)")
    ap.add_argument("--out", type=Path, default=ROOT / "dist", help="output folder (default: dist/)")
    ap.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    ap.add_argument("--allow-demo", action="store_true", help="allow building the demo category")
    ap.add_argument("--allow-empty", action="store_true", help="allow a standard with no releasable control")
    ap.add_argument("--no-tag-check", action="store_true", help="do not fail when the tag already exists")
    args = ap.parse_args(argv)

    if args.standard is not None and not SLUG_RE.match(args.standard):
        print(f"ERROR invalid standard id {args.standard!r}")
        return 1
    if args.all and args.version:
        print("ERROR --version cannot be used with --all")
        return 1

    repo, report = validate.run(args.root.resolve())
    if repo is None or report.errors:
        report.print()
        print("\nValidation failed, nothing built.")
        return 1

    if args.all:
        targets = list(repo.standards())
    else:
        std = repo.find_standard(args.standard)
        if std is None:
            known = ", ".join(sorted(s.id for s in repo.standards()))
            print(f"ERROR unknown standard {args.standard!r} (known: {known})")
            return 1
        targets = [std]

    results = []
    for std in targets:
        out = args.out / std.id if args.all else args.out
        if out.exists() and not args.all:
            for old in out.glob("cirsec-baselines-*"):
                old.unlink()
        try:
            res = build_standard(
                repo, std, args.version, out,
                allow_demo=args.allow_demo or args.all,
                allow_empty=args.allow_empty,
                tag_check=not args.no_tag_check,
            )
        except BuildError as exc:
            print(f"ERROR {exc}")
            return 1
        results.append(res)
        print(f"built {res['tag']}: {res['controls']} control(s) -> {res['zip']}")

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out and len(results) == 1:
        with open(gh_out, "a", encoding="utf-8") as fh:
            for k in ("tag", "title", "zip", "sha256", "notes"):
                fh.write(f"{k}={results[0][k]}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

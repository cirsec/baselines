#!/usr/bin/env python3
"""Validate the whole CIRSEC Baselines repository.

Checks every YAML file against its JSON Schema, then enforces the cross-file
rules documented in README.md (section "Validation rules").

Usage:
    python tools/validate.py [--root PATH] [--strict]

Exit code 0 when there is no error (warnings allowed unless --strict), 1 otherwise.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import date
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    ALLOWED_DOC_FILES,
    PLACEHOLDER_RE,
    ROOT,
    Category,
    Control,
    Report,
    Repo,
    Standard,
    Translation,
    load_validators,
    load_yaml,
    parse_semver,
    schema_errors,
    semver_le,
    semver_lt,
)


# =========================================================================== loading


def _load(path: Path, report: Report) -> dict | None:
    try:
        data = load_yaml(path)
    except yaml.YAMLError as exc:
        report.error(path, f"invalid YAML: {exc}".replace("\n", " "))
        return None
    if not isinstance(data, dict):
        report.error(path, "file must contain a YAML mapping")
        return None
    return data


def load_repo(root: Path, report: Report) -> Repo | None:
    """Load the tree, validating each file against its schema along the way."""
    validators = load_validators(root)

    meta_path = root / "baselines.yml"
    if not meta_path.is_file():
        report.error(meta_path, "missing baselines.yml")
        return None
    meta = _load(meta_path, report)
    if meta is None:
        return None
    for msg in schema_errors(validators["baselines"], meta):
        report.error(meta_path, msg)

    repo = Repo(root=root, meta=meta)
    cat_root = root / "categories"
    if not cat_root.is_dir():
        report.error(cat_root, "missing categories/ folder")
        return repo

    for cat_dir in sorted(cat_root.iterdir()):
        if cat_dir.is_file():
            if cat_dir.name not in ALLOWED_DOC_FILES:
                report.error(cat_dir, "unexpected file, categories/ only holds category folders")
            continue
        cat_file = cat_dir / "_category.yml"
        if not cat_file.is_file():
            report.error(cat_dir, "category folder without _category.yml")
            continue
        cat_data = _load(cat_file, report) or {}
        for msg in schema_errors(validators["category"], cat_data):
            report.error(cat_file, msg)
        category = Category(path=cat_dir, data=cat_data)
        repo.categories[cat_dir.name] = category

        for std_dir in sorted(cat_dir.iterdir()):
            if std_dir.is_file():
                if std_dir.name not in ALLOWED_DOC_FILES | {"_category.yml"}:
                    report.error(std_dir, "unexpected file in category folder")
                continue
            _load_standard(std_dir, category, validators, report)

    return repo


def _load_standard(std_dir: Path, category: Category, validators, report: Report) -> None:
    std_file = std_dir / "_standard.yml"
    if not std_file.is_file():
        report.error(std_dir, "standard folder without _standard.yml")
        return
    std_data = _load(std_file, report) or {}
    for msg in schema_errors(validators["standard"], std_data):
        report.error(std_file, msg)
    standard = Standard(path=std_dir, data=std_data, category=category)
    category.standards[std_dir.name] = standard

    for entry in sorted(std_dir.iterdir()):
        if entry.is_file() and entry.name not in ALLOWED_DOC_FILES | {"_standard.yml"}:
            report.error(entry, "unexpected file in standard folder")
        elif entry.is_dir() and entry.name not in {"controls", "i18n"}:
            report.error(entry, "unexpected folder, a standard only holds controls/ and i18n/")

    controls_dir = std_dir / "controls"
    if not controls_dir.is_dir():
        report.error(std_dir, "missing controls/ folder")
    else:
        for f in sorted(controls_dir.iterdir()):
            if f.name == ".gitkeep":
                continue
            if f.is_dir() or f.suffix != ".yml":
                report.error(f, "controls/ only holds <ID>.yml files (use the .yml extension)")
                continue
            data = _load(f, report)
            if data is None:
                continue
            for msg in schema_errors(validators["control"], data):
                report.error(f, msg)
            standard.controls[f.stem] = Control(path=f, data=data, standard=standard)

    i18n_dir = std_dir / "i18n"
    if i18n_dir.is_dir():
        for loc_dir in sorted(i18n_dir.iterdir()):
            if not loc_dir.is_dir():
                report.error(loc_dir, "i18n/ only holds <locale>/ folders")
                continue
            for f in sorted(loc_dir.iterdir()):
                if f.name == ".gitkeep":
                    continue
                if f.is_dir() or f.suffix != ".yml":
                    report.error(f, "i18n/<locale>/ only holds <ID>.yml files")
                    continue
                data = _load(f, report)
                if data is None:
                    continue
                for msg in schema_errors(validators["control-i18n"], data):
                    report.error(f, msg)
                ctl = standard.controls.get(f.stem)
                if ctl is None:
                    report.error(f, f"translation of unknown control {f.stem} in this standard")
                    continue
                ctl.translations[loc_dir.name] = Translation(path=f, locale=loc_dir.name, data=data)


# =========================================================================== rules


def check_root(repo: Repo, report: Report) -> None:
    path = repo.root / "baselines.yml"
    meta = repo.meta

    for key, label in (("engines", "engine"), ("frameworks", "framework")):
        seen = set()
        for item in meta.get(key, []) or []:
            k = item.get("key")
            if k in seen:
                report.error(path, f"duplicate {label} key {k!r}")
            seen.add(k)

    locales = meta.get("locales") or {}
    if locales.get("default") not in (locales.get("available") or []):
        report.error(path, "locales.default must be listed in locales.available")

    for fw in meta.get("frameworks", []) or []:
        pattern = fw.get("id_pattern")
        if pattern:
            try:
                re.compile(pattern)
            except re.error as exc:
                report.error(path, f"framework {fw.get('key')}: invalid id_pattern: {exc}")


def _check_i18n_block(repo: Repo, path: Path, data: dict, report: Report, std: Standard | None = None) -> None:
    for locale, tr in (data.get("i18n") or {}).items():
        if locale not in repo.locales:
            report.error(path, f"i18n: locale {locale!r} is not in baselines.yml locales.available")
        if locale == repo.default_locale:
            report.error(path, f"i18n: {locale!r} is the default locale, edit the main fields instead")
        if std is not None and isinstance(tr, dict):
            for code in (tr.get("domains") or {}):
                if code not in std.domains:
                    report.error(path, f"i18n.{locale}.domains: unknown domain {code!r}")
            for key in (tr.get("profiles") or {}):
                if key not in std.profiles:
                    report.error(path, f"i18n.{locale}.profiles: unknown profile {key!r}")


def check_categories_and_standards(repo: Repo, report: Report) -> None:
    codes: dict[str, Path] = {}
    std_ids: dict[str, Path] = {}

    for cat in repo.categories.values():
        cat_file = cat.path / "_category.yml"
        if cat.data.get("id") != cat.id:
            report.error(cat_file, f"id {cat.data.get('id')!r} must equal the folder name {cat.id!r}")
        _check_i18n_block(repo, cat_file, cat.data, report)

        for std in cat.standards.values():
            f = std.path / "_standard.yml"
            d = std.data
            if d.get("id") != std.id:
                report.error(f, f"id {d.get('id')!r} must equal the folder name {std.id!r}")
            if std.id in std_ids:
                report.error(f, f"standard id {std.id!r} already used by {std_ids[std.id]}")
            std_ids[std.id] = f
            code = d.get("code")
            if code in codes:
                report.error(f, f"code {code!r} already used by {codes[code]}")
            codes[code] = f

            for key, label in (("profiles", "key"), ("domains", "code")):
                seen = set()
                for item in d.get(key, []) or []:
                    v = item.get(label)
                    if v in seen:
                        report.error(f, f"duplicate {key[:-1]} {v!r}")
                    seen.add(v)

            # Profile inheritance: target exists, no self reference, no cycle.
            parents = {p.get("key"): p.get("extends") for p in d.get("profiles", []) or []}
            for key, parent in parents.items():
                if parent is None:
                    continue
                if parent not in parents:
                    report.error(f, f"profile {key!r} extends unknown profile {parent!r}")
                    continue
                seen, cur = {key}, parent
                while cur is not None:
                    if cur in seen:
                        report.error(f, f"profile {key!r}: circular extends chain")
                        break
                    seen.add(cur)
                    cur = parents.get(cur)

            _check_i18n_block(repo, f, d, report, std)


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def _type_ok(ptype: str, value) -> bool:
    if ptype == "string":
        return isinstance(value, str)
    if ptype == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if ptype == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if ptype == "boolean":
        return isinstance(value, bool)
    if ptype == "list":
        return isinstance(value, list)
    return True  # enum: checked against "allowed"


def check_parameters(ctl: Control, report: Report) -> set[str]:
    f, d, std = ctl.path, ctl.data, ctl.standard
    names: set[str] = set()
    for p in d.get("parameters", []) or []:
        name, ptype = p.get("name"), p.get("type")
        if name in names:
            report.error(f, f"duplicate parameter {name!r}")
        names.add(name)

        for prof in (p.get("profile_defaults") or {}):
            if prof not in std.profiles:
                report.error(f, f"parameter {name}: profile_defaults uses unknown profile {prof!r}")

        lo, hi, allowed = p.get("minimum"), p.get("maximum"), p.get("allowed")
        if lo is not None and hi is not None and lo > hi:
            report.error(f, f"parameter {name}: minimum is greater than maximum")
        if (lo is not None or hi is not None) and ptype not in ("integer", "number"):
            report.error(f, f"parameter {name}: minimum/maximum only apply to integer and number")

        values = [("default", p["default"])] if "default" in p else []
        values += [(f"profile_defaults.{k}", v) for k, v in (p.get("profile_defaults") or {}).items()]
        for label, value in values:
            if not _type_ok(ptype, value):
                report.error(f, f"parameter {name}: {label} {value!r} is not of type {ptype}")
                continue
            if ptype in ("integer", "number"):
                if lo is not None and value < lo:
                    report.error(f, f"parameter {name}: {label} {value!r} is below minimum {lo}")
                if hi is not None and value > hi:
                    report.error(f, f"parameter {name}: {label} {value!r} is above maximum {hi}")
            if allowed is not None:
                items = value if ptype == "list" else [value]
                for item in items:
                    if item not in allowed:
                        report.error(f, f"parameter {name}: {label} {item!r} is not in allowed {allowed}")
    return names


def check_controls(repo: Repo, report: Report) -> dict[str, Control]:
    all_ids: dict[str, Control] = {}
    engines, frameworks = repo.engines, repo.frameworks
    today = date.today().isoformat()

    for ctl in repo.controls():
        f, d, std = ctl.path, ctl.data, ctl.standard
        cid = d.get("id", "")
        std_version = std.data.get("version", "")

        # Identity
        if cid != f.stem:
            report.error(f, f"id {cid!r} must equal the file name {f.stem!r}")
        if cid in all_ids:
            report.error(f, f"duplicate control id, already defined in {all_ids[cid].path}")
        all_ids[cid] = ctl
        parts = cid.split("-")
        if len(parts) == 4:
            if parts[1] != std.data.get("code"):
                report.error(f, f"id must start with CB-{std.data.get('code')}- in standard {std.id!r}")
            if parts[2] not in std.domains:
                report.error(f, f"domain {parts[2]!r} is not declared in {std.id}/_standard.yml")

        # Profiles
        for prof in d.get("profiles", []) or []:
            if prof not in std.profiles:
                report.error(f, f"unknown profile {prof!r} (declared: {sorted(std.profiles)})")

        # Versions
        def _check_versions(versions, where):
            for v in versions or []:
                if not std.versions:
                    report.error(f, f"{where}: standard {std.id!r} declares no versions in applies_to")
                    return
                if v not in std.versions:
                    report.error(f, f"{where}: version {v!r} not in standard versions {sorted(std.versions)}")

        _check_versions((d.get("applicability") or {}).get("versions"), "applicability.versions")
        audit, remediation = d.get("audit") or {}, d.get("remediation") or {}
        for group, items in (("audit.checks", audit.get("checks")), ("remediation.scripts", remediation.get("scripts"))):
            ids = set()
            for i, item in enumerate(items or []):
                where = f"{group}[{i}]"
                if item.get("id") in ids:
                    report.error(f, f"{where}: duplicate id {item.get('id')!r}")
                ids.add(item.get("id"))
                if item.get("engine") not in engines:
                    report.error(f, f"{where}: engine {item.get('engine')!r} is not declared in baselines.yml")
                _check_versions(item.get("versions"), where)

        # Parameters and placeholders
        params = check_parameters(ctl, report)
        content = {k: v for k, v in d.items() if k != "parameters"}
        for name in sorted({m for s in _strings(content) for m in PLACEHOLDER_RE.findall(s)}):
            if name not in params:
                report.error(f, f"placeholder {{{{ {name} }}}} references an undeclared parameter")

        # Mappings and threats
        for group, want_control in (("mappings", True), ("threats", False)):
            for i, m in enumerate(d.get(group, []) or []):
                where = f"{group}[{i}]"
                fw = frameworks.get(m.get("framework"))
                if fw is None:
                    report.error(f, f"{where}: framework {m.get('framework')!r} is not declared in baselines.yml")
                    continue
                is_control = fw.get("kind") == "control-framework"
                if want_control and not is_control:
                    report.error(f, f"{where}: {fw['key']} is a {fw.get('kind')}, use threats instead")
                if not want_control and is_control:
                    report.error(f, f"{where}: {fw['key']} is a control-framework, use mappings instead")
                pattern = fw.get("id_pattern")
                if pattern and not re.match(pattern, str(m.get("id", ""))):
                    report.error(f, f"{where}: id {m.get('id')!r} does not match {fw['key']} pattern {pattern}")

        # People: nobody reviews their own control
        def _who(p):
            return (p.get("github") or p.get("name", "")).lower()

        authors = {_who(p) for p in d.get("authors", []) or []}
        for p in d.get("reviewers", []) or []:
            if _who(p) in authors:
                report.error(f, f"reviewer {p.get('name')!r} is also an author")

        # Dates
        created, updated = d.get("created", ""), d.get("updated", "")
        if created and updated and updated < created:
            report.error(f, "updated is earlier than created")
        for label, value in (("created", created), ("updated", updated)):
            if value and value > today:
                report.warning(f, f"{label} {value} is in the future")
        for v in d.get("verified", []) or []:
            if v.get("date", "") > today:
                report.warning(f, f"verified date {v.get('date')} is in the future")

        # Lifecycle vs standard version
        introduced = d.get("introduced_in", "")
        if introduced and std_version and not semver_le(introduced, std_version):
            report.error(f, f"introduced_in {introduced} is after the standard version {std_version}")
        status = d.get("status")
        if status == "deprecated":
            dep = d.get("deprecated_in", "")
            if dep and introduced and not semver_lt(introduced, dep):
                report.error(f, f"deprecated_in {dep} must be after introduced_in {introduced}")
            if dep and std_version and not semver_le(dep, std_version):
                report.error(f, f"deprecated_in {dep} is after the standard version {std_version}")
        else:
            for key in ("deprecated_in", "deprecation_reason", "superseded_by"):
                if key in d:
                    report.error(f, f"{key} is only allowed when status is deprecated")

    return all_ids


def check_relations(repo: Repo, all_ids: dict[str, Control], report: Report) -> None:
    for ctl in repo.controls():
        f, d, cid = ctl.path, ctl.data, ctl.id
        for i, rel in enumerate(d.get("related_controls", []) or []):
            target = rel.get("id")
            if target == cid:
                report.error(f, f"related_controls[{i}]: a control cannot relate to itself")
            elif target not in all_ids:
                report.error(f, f"related_controls[{i}]: unknown control {target!r}")

        for key, back in (("supersedes", "superseded_by"), ("superseded_by", "supersedes")):
            for target in d.get(key, []) or []:
                if target == cid:
                    report.error(f, f"{key}: a control cannot reference itself")
                    continue
                other = all_ids.get(target)
                if other is None:
                    report.error(f, f"{key}: unknown control {target!r}")
                    continue
                if cid not in (other.data.get(back) or []):
                    report.warning(f, f"{key} {target}, but {target} does not list {cid} in {back}")
                if key == "superseded_by" and other.data.get("status") == "deprecated":
                    report.warning(f, f"superseded_by points to {target}, which is deprecated too")
                if key == "supersedes" and other.data.get("status") != "deprecated":
                    report.error(f, f"supersedes {target}, which is not deprecated")


def check_translations(repo: Repo, report: Report) -> None:
    for ctl in repo.controls():
        params = {p.get("name") for p in ctl.data.get("parameters", []) or []}
        for locale, tr in ctl.translations.items():
            f, d = tr.path, tr.data
            if d.get("id") != f.stem:
                report.error(f, f"id {d.get('id')!r} must equal the file name {f.stem!r}")
            if d.get("locale") != locale:
                report.error(f, f"locale {d.get('locale')!r} must equal the folder name {locale!r}")
            if locale not in repo.locales:
                report.error(f, f"locale {locale!r} is not in baselines.yml locales.available")
            if locale == repo.default_locale:
                report.error(f, f"{locale!r} is the default locale, it lives in controls/")

            for name in (d.get("parameters") or {}):
                if name not in params:
                    report.error(f, f"parameters: {name!r} is not a parameter of {ctl.id}")
            for name in sorted({m for s in _strings(d) for m in PLACEHOLDER_RE.findall(s)}):
                if name not in params:
                    report.error(f, f"placeholder {{{{ {name} }}}} references an undeclared parameter")

            # Text present in the translation but absent from the source.
            for key in ("notes", "impact"):
                if key in d and key not in ctl.data:
                    report.warning(f, f"{key} is translated but the source control has none")
            if (d.get("finding") or {}).get("description") and not (ctl.data.get("finding") or {}).get("description"):
                report.warning(f, "finding.description is translated but the source control has none")

            src_updated, tr_updated = ctl.data.get("updated", ""), d.get("source_updated", "")
            if src_updated and tr_updated:
                if tr_updated < src_updated:
                    report.warning(f, f"stale translation: source updated {src_updated}, translated from {tr_updated}")
                elif tr_updated > src_updated:
                    report.error(f, f"source_updated {tr_updated} is later than the source updated {src_updated}")


# =========================================================================== entry points


def run(root: Path = ROOT) -> tuple[Repo | None, Report]:
    report = Report(root=root)
    repo = load_repo(root, report)
    if repo is None:
        return None, report
    check_root(repo, report)
    check_categories_and_standards(repo, report)
    all_ids = check_controls(repo, report)
    check_relations(repo, all_ids, report)
    check_translations(repo, report)
    return repo, report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=ROOT, help="repository root (default: this repo)")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    args = ap.parse_args(argv)

    repo, report = run(args.root.resolve())
    report.print()

    n_std = sum(1 for _ in repo.standards()) if repo else 0
    n_ctl = sum(1 for _ in repo.controls()) if repo else 0
    n_tr = sum(len(c.translations) for c in repo.controls()) if repo else 0
    print(
        f"\n{len(report.errors)} error(s), {len(report.warnings)} warning(s) "
        f"- {n_std} standard(s), {n_ctl} control(s), {n_tr} translation(s)"
    )
    failed = bool(report.errors) or (args.strict and bool(report.warnings))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

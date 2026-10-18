#!/usr/bin/env python3
"""Check a tailoring file against the standard it tailors.

A tailoring file (schema/tailoring.schema.json) is written by an organization to adapt a
released standard: profile, parameter overrides, exclusions. The schema checks its shape,
this tool checks it against the content: controls, parameters and bounds.

Usage:
    python tools/tailor.py path/to/tailoring.yml [--root PATH]

Exit code 0 when there is no error, 1 otherwise. Warnings are printed but do not fail.
"""

from __future__ import annotations

import argparse
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, Repo, control_profiles, load_validators, load_yaml, schema_errors  # noqa: E402
import validate  # noqa: E402


def check_tailoring(repo: Repo, data: dict) -> tuple[list[str], list[str]]:
    errors = schema_errors(load_validators(repo.root)["tailoring"], data)
    warnings: list[str] = []
    if errors:
        return errors, warnings

    std = repo.find_standard(data["standard"])
    if std is None:
        return [f"unknown standard {data['standard']!r}"], warnings
    if data["version"] != std.data.get("version"):
        warnings.append(f"written for {std.id} {data['version']}, the standard is at {std.data.get('version')}")
    profile = data["profile"]
    if profile not in std.profiles:
        return [f"unknown profile {profile!r} (declared: {sorted(std.profiles)})"], warnings

    def control(cid: str, where: str):
        ctl = std.controls.get(cid)
        if ctl is None:
            errors.append(f"{where}: unknown control {cid} in standard {std.id}")
        return ctl

    excluded = set()
    for i, ex in enumerate(data.get("exclude") or []):
        if control(ex["control"], f"exclude[{i}]"):
            excluded.add(ex["control"])
        if ex.get("until") and ex["until"] < date.today().isoformat():
            warnings.append(f"exclude[{i}]: {ex['control']} review date {ex['until']} is past")

    for cid in data.get("include") or []:
        ctl = control(cid, "include")
        if ctl is None:
            continue
        if cid in excluded:
            errors.append(f"include: {cid} is also excluded")
        elif profile in control_profiles(ctl):
            warnings.append(f"include: {cid} is already in profile {profile}")

    for cid, values in (data.get("parameters") or {}).items():
        ctl = control(cid, "parameters")
        if ctl is None:
            continue
        declared = {p.get("name"): p for p in ctl.data.get("parameters", []) or []}
        for name, value in values.items():
            if name not in declared:
                errors.append(f"parameters.{cid}: {name!r} is not a parameter of {cid}")
            else:
                errors.extend(f"{cid}: {m}" for m in validate.value_errors(declared[name], value, "override"))

    for cid, enabled in (data.get("fixes") or {}).items():
        ctl = control(cid, "fixes")
        if ctl is not None and enabled and not ((ctl.data.get("remediation") or {}).get("effects") or {}).get("lockout_risk"):
            warnings.append(f"fixes: {cid} has no lockout risk, its fix is already enabled")
    return errors, warnings


def load_checked(path: Path, repo: Repo) -> dict:
    """Load a tailoring file, print its warnings, raise SystemExit on error."""
    data = load_yaml(path)
    errors, warnings = check_tailoring(repo, data if isinstance(data, dict) else {})
    for w in warnings:
        print(f"WARNING {path}: {w}")
    if errors:
        for e in errors:
            print(f"ERROR   {path}: {e}")
        raise SystemExit(1)
    return data


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("tailoring", type=Path)
    ap.add_argument("--root", type=Path, default=ROOT, help="repository root (default: this repo)")
    args = ap.parse_args(argv)

    repo, report = validate.run(args.root.resolve())
    if repo is None or report.errors:
        report.print()
        print("\nRepository validation failed.")
        return 1
    try:
        load_checked(args.tailoring, repo)
    except SystemExit as exc:
        return int(exc.code or 0)
    print(f"{args.tailoring}: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())

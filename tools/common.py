"""Shared helpers for CIRSEC Baselines tooling: YAML loading, repo model, reporting."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent.parent

SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")

# Files tolerated next to metadata files.
ALLOWED_DOC_FILES = {"README.md", "CHANGELOG.md"}


# --------------------------------------------------------------------------- YAML


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate keys instead of silently keeping the last one."""


def _construct_mapping(loader: _StrictLoader, node: yaml.MappingNode, deep: bool = False):
    loader.flatten_mapping(node)
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.constructor.ConstructorError(
                None, None, f"duplicate key {key!r}", key_node.start_mark
            )
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)


def to_jsonable(value: Any) -> Any:
    """YAML gives date objects for unquoted dates; schemas expect ISO strings."""
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_jsonable(v) for v in value]
    return value


def load_yaml(path: Path) -> Any:
    with path.open(encoding="utf-8") as fh:
        return to_jsonable(yaml.load(fh, Loader=_StrictLoader))


def load_yaml_text(text: str) -> Any:
    return to_jsonable(yaml.load(text, Loader=_StrictLoader))


# --------------------------------------------------------------------------- versions


def parse_semver(value: str) -> tuple | None:
    m = SEMVER_RE.match(value or "")
    if not m:
        return None
    major, minor, patch, pre = m.groups()
    # A pre-release sorts before the release it precedes.
    return (int(major), int(minor), int(patch), 0 if pre else 1, pre or "")


def semver_le(a: str, b: str) -> bool:
    pa, pb = parse_semver(a), parse_semver(b)
    return pa is not None and pb is not None and pa <= pb


def semver_lt(a: str, b: str) -> bool:
    pa, pb = parse_semver(a), parse_semver(b)
    return pa is not None and pb is not None and pa < pb


# --------------------------------------------------------------------------- reporting


@dataclass
class Issue:
    level: str  # "error" | "warning"
    path: str
    message: str


@dataclass
class Report:
    root: Path
    issues: list[Issue] = field(default_factory=list)

    def _rel(self, path: Path | str) -> str:
        p = Path(path)
        try:
            return p.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return str(p)

    def error(self, path: Path | str, message: str) -> None:
        self.issues.append(Issue("error", self._rel(path), message))

    def warning(self, path: Path | str, message: str) -> None:
        self.issues.append(Issue("warning", self._rel(path), message))

    @property
    def errors(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "error"]

    @property
    def warnings(self) -> list[Issue]:
        return [i for i in self.issues if i.level == "warning"]

    def print(self) -> None:
        gha = os.environ.get("GITHUB_ACTIONS") == "true"
        for i in sorted(self.issues, key=lambda x: (x.level != "error", x.path, x.message)):
            if gha:
                msg = i.message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
                print(f"::{i.level} file={i.path}::{msg}")
            else:
                print(f"{i.level.upper():7} {i.path}: {i.message}")


# --------------------------------------------------------------------------- repo model


@dataclass
class Translation:
    path: Path
    locale: str
    data: dict


@dataclass
class Control:
    path: Path
    data: dict
    standard: "Standard"
    translations: dict[str, Translation] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.data.get("id", self.path.stem)


@dataclass
class Standard:
    path: Path
    data: dict
    category: "Category"
    controls: dict[str, Control] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.path.name

    @property
    def versions(self) -> set[str]:
        out: set[str] = set()
        for a in self.data.get("applies_to", []) or []:
            out.update(a.get("versions", []) or [])
        return out

    @property
    def profiles(self) -> set[str]:
        return {p.get("key") for p in self.data.get("profiles", []) or []}

    @property
    def domains(self) -> set[str]:
        return {d.get("code") for d in self.data.get("domains", []) or []}

    @property
    def facts(self) -> set[str]:
        return {f.get("key") for f in self.data.get("facts", []) or []}

    def profile_chain(self, profile: str) -> list[str]:
        """The profile, then every profile it extends, nearest first. Stops on a cycle."""
        parents = {p.get("key"): p.get("extends") for p in self.data.get("profiles", []) or []}
        chain, cur = [], profile
        while cur is not None and cur not in chain:
            chain.append(cur)
            cur = parents.get(cur)
        return chain


def resolve_parameters(ctl: "Control", profile: str, overrides: dict | None = None) -> dict:
    """Parameter values for one profile: override, then profile_defaults along the extends chain, then default."""
    chain = ctl.standard.profile_chain(profile)
    out = {}
    for p in ctl.data.get("parameters", []) or []:
        name = p.get("name")
        if overrides and name in overrides:
            out[name] = overrides[name]
            continue
        defaults = p.get("profile_defaults") or {}
        out[name] = next((defaults[k] for k in chain if k in defaults), p.get("default"))
    return out


def resolve_value(value: Any, params: dict) -> Any:
    """Replace {{ name }} in a spec. A string that is exactly one placeholder takes the parameter's type."""
    if isinstance(value, str):
        m = PLACEHOLDER_RE.fullmatch(value.strip())
        if m:
            return params[m.group(1)]
        return PLACEHOLDER_RE.sub(lambda m: render_text(params[m.group(1)]), value)
    if isinstance(value, dict):
        return {k: resolve_value(v, params) for k, v in value.items()}
    if isinstance(value, list):
        return [resolve_value(v, params) for v in value]
    return value


def render_text(value: Any) -> str:
    """A parameter value as text: true/false for booleans, space-separated lists."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return " ".join(render_text(v) for v in value)
    return str(value)


def control_profiles(ctl: "Control") -> list[str]:
    """Every profile of the standard that includes this control, directly or through extends."""
    own = set(ctl.data.get("profiles", []) or [])
    return [k for k in sorted(ctl.standard.profiles) if own & set(ctl.standard.profile_chain(k))]


@dataclass
class Category:
    path: Path
    data: dict
    standards: dict[str, Standard] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return self.path.name


@dataclass
class Repo:
    root: Path
    meta: dict
    categories: dict[str, Category] = field(default_factory=dict)
    spec_validators: dict[str, Draft202012Validator] = field(default_factory=dict)  # engine key -> spec schema

    def standards(self):
        for c in self.categories.values():
            yield from c.standards.values()

    def controls(self):
        for s in self.standards():
            yield from s.controls.values()

    def find_standard(self, standard_id: str) -> Standard | None:
        for s in self.standards():
            if s.id == standard_id:
                return s
        return None

    @property
    def engines(self) -> dict[str, dict]:
        return {e.get("key"): e for e in self.meta.get("engines", []) or []}

    def has_capability(self, engine: str | None, capability: str) -> bool:
        return capability in ((self.engines.get(engine) or {}).get("capabilities") or [])

    @property
    def frameworks(self) -> dict[str, dict]:
        return {f.get("key"): f for f in self.meta.get("frameworks", []) or []}

    @property
    def default_locale(self) -> str:
        return (self.meta.get("locales") or {}).get("default", "en")

    @property
    def locales(self) -> set[str]:
        return set((self.meta.get("locales") or {}).get("available", []) or [])


# --------------------------------------------------------------------------- schemas


def load_validators(root: Path) -> dict[str, Draft202012Validator]:
    out = {}
    for name in ("baselines", "category", "standard", "control", "control-i18n", "result", "tailoring"):
        schema = json.loads((root / "schema" / f"{name}.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        out[name] = Draft202012Validator(schema, format_checker=FormatChecker())
    return out


def schema_errors(validator: Draft202012Validator, data: Any, prefix: str = "schema") -> list[str]:
    msgs = []
    for e in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
        where = "/".join(str(p) for p in e.path) or "<root>"
        msgs.append(f"{prefix}: {where}: {e.message}")
    return msgs


def script_path(ctl: "Control", file: str) -> Path:
    """Where remediation.scripts[].file lives: <standard>/scripts/<control ID>/<file>."""
    return ctl.standard.path / "scripts" / ctl.id / file

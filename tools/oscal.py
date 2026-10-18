"""OSCAL export of a standard: one catalog, one profile per CIRSEC profile (OSCAL 1.1.2, JSON).

Mapping:
  standard          -> catalog, domains -> groups, controls -> controls
  description       -> part "statement", rationale -> part "guidance", audit.manual -> part "assessment-method"
  parameters        -> params, with the default value
  severity, status  -> props (namespace https://baselines.cirsec.org/ns/oscal)
  CIRSEC profile    -> OSCAL profile importing the catalog, with set-parameters for that profile

UUIDs are derived from the standard, version and profile, so a build is reproducible.
"""

from __future__ import annotations

import uuid

from common import Control, Standard, control_profiles, resolve_parameters

OSCAL_VERSION = "1.1.2"
NS = "https://baselines.cirsec.org/ns/oscal"
UUID_NS = uuid.UUID("6f1d6c1e-1b9a-4c35-9d0e-2c1b7a3e5f10")  # fixed namespace for CIRSEC Baselines


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(UUID_NS, "/".join(parts)))


def _metadata(std: Standard, release: dict, title: str) -> dict:
    return {
        "title": title,
        "last-modified": f"{release['date']}T00:00:00Z",
        "version": release["version"],
        "oscal-version": OSCAL_VERSION,
    }


def _control(ctl: Control) -> dict:
    d = ctl.data
    cid = ctl.id.lower()
    out = {
        "id": cid,
        "title": d.get("title"),
        "props": [
            {"name": "label", "value": ctl.id},
            {"name": "severity", "ns": NS, "value": d.get("risk", {}).get("severity")},
            {"name": "assessment", "ns": NS, "value": d.get("assessment")},
            {"name": "status", "value": "withdrawn" if d.get("status") == "deprecated" else "active"},
        ],
        "parts": [
            {"id": f"{cid}_smt", "name": "statement", "prose": d.get("description", "").strip()},
            {"id": f"{cid}_gdn", "name": "guidance", "prose": d.get("rationale", "").strip()},
            {"id": f"{cid}_asm", "name": "assessment-method", "prose": (d.get("audit") or {}).get("manual", "").strip()},
        ],
    }
    params = [
        {
            "id": f"{cid}_prm_{p['name']}",
            "label": p["name"],
            "usage": p.get("description"),
            "values": [str(v) for v in (p["default"] if isinstance(p["default"], list) else [p["default"]])],
        }
        for p in d.get("parameters", []) or []
    ]
    if params:
        out["params"] = params
    return out


def build_oscal(std: Standard, controls: list[Control], release: dict) -> dict[str, dict]:
    """Return {file name: OSCAL document}."""
    key = (std.id, release["version"])
    groups = []
    for dom in std.data.get("domains", []) or []:
        members = [_control(c) for c in controls if c.id.split("-")[2] == dom["code"]]
        if members:
            groups.append({"id": dom["code"].lower(), "title": dom["title"], "controls": members})
    title = f"CIRSEC Baselines - {std.data.get('title')}"
    catalog = {"uuid": _uuid(*key, "catalog"), "metadata": _metadata(std, release, title)}
    if groups:
        catalog["groups"] = groups
    files = {"catalog.json": {"catalog": catalog}}
    for prof in sorted(std.profiles):
        members = [c for c in controls if c.data.get("status") == "active" and prof in control_profiles(c)]
        set_params = [
            {"param-id": f"{c.id.lower()}_prm_{name}", "values": [str(v) for v in (value if isinstance(value, list) else [value])]}
            for c in members for name, value in resolve_parameters(c, prof).items()
        ]
        if not members:  # an OSCAL import needs at least one control
            continue
        doc = {
            "uuid": _uuid(*key, "profile", prof),
            "metadata": _metadata(std, release, f"{title} - profile {prof}"),
            "imports": [{"href": "catalog.json", "include-controls": [{"with-ids": [c.id.lower() for c in members]}]}],
        }
        if set_params:
            doc["modify"] = {"set-parameters": set_params}
        files[f"profile-{prof}.json"] = {"profile": doc}
    return files

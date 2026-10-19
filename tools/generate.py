#!/usr/bin/env python3
"""Generate audit and remediation artifacts for one standard and profile.

Controls declare the expected state (engine + spec). This tool turns it into code, the
same way for every control of an engine. Outputs, in --out:

  controls/<ID>.sh   one self-contained POSIX sh script per control:
                       <ID>.sh check            one line per check, exit with the control status
                       <ID>.sh fix [--apply]    dry run unless --apply
  audit.sh           runs every check, prints a result JSON (schema/result.schema.json)
  remediate.sh       runs every enabled fix in dependency order, dry run unless --apply,
                     then restarts each affected service once
  ansible/           playbook and role running the same control scripts (check mode supported)

Parameters are resolved for the profile, then overridden by the tailoring file if given.
Fixes with lockout_risk are disabled unless the tailoring file opts in.

Usage:
    python tools/generate.py --standard debian --profile server --out gen/
    python tools/generate.py --standard debian --profile server --tailoring acme.yml --out gen/
"""

from __future__ import annotations

import argparse
import json
import re
import shlex
import shutil
import sys
from graphlib import TopologicalSorter
from pathlib import Path
from typing import Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (  # noqa: E402
    ROOT, Control, Repo, Standard, control_profiles, render_text, resolve_parameters, resolve_value,
    script_path,
)
import tailor  # noqa: E402
import validate  # noqa: E402

LIB = (Path(__file__).resolve().parent / "lib" / "cirsec.sh").read_text(encoding="utf-8")
REPORT = (Path(__file__).resolve().parent / "lib" / "report.sh").read_text(encoding="utf-8")
GENERATED_STATUSES = {"active"}
q = shlex.quote


class GenerateError(Exception):
    pass


# =========================================================================== engine snippets
# A check snippet prints the observed value and returns 0 pass, 1 fail, 2 not applicable, 3 error.
# A fix snippet makes the check pass, backs up what it changes, returns non-zero on failure.


def _expected(spec: dict) -> str:
    value = spec.get("value")
    if isinstance(value, list):
        return q("\n".join(render_text(v) for v in value))
    return q(render_text(value))


def expected_text(engine: str, spec: dict) -> str:
    """What a check wants, in one line, for reports: '>= 1', 'installed', 'mode <= 0640'."""
    if "value" in spec:
        value = spec["value"]
        value = ", ".join(map(render_text, value)) if isinstance(value, list) else render_text(value)
        text = f"{spec.get('operator', '==')} {value}"
    elif "state" in spec:
        text = spec["state"]
    elif engine == "file-content":
        text = f"{spec.get('expect', 'match')} {spec['pattern']}"
    elif engine == "osquery":
        text = spec.get("expect", "rows")
    else:
        text = ", ".join(f"{k} {'<= ' if k == 'mode' else ''}{spec[k]}" for k in ("owner", "group", "mode") if spec.get(k))
    return " ".join(str(text).splitlines())


def _op(spec: dict) -> str:
    return q(spec.get("operator", "=="))


def _glob(path: str) -> str:
    """Quote a path for sh, keeping glob characters active."""
    return "".join(c if c.isalnum() or c in "/._-*?[]" else "\\" + c for c in path)


def _sed_re(text: str) -> str:
    return re.sub(r"([.\[\]*^$/\\])", r"\\\1", text)


def sysctl_check(s: dict) -> str:
    return (f"o=$(sysctl -n {q(s['key'])} 2>/dev/null | tr -s '\\t ' '  ') || return 3\n"
            f"printf '%s\\n' \"$o\"\n"
            f"cb_cmp \"$o\" {_op(s)} {_expected(s)}")


def sysctl_fix(s: dict) -> str:
    key, value = s["key"], render_text(s["value"])
    return (f"f=/etc/sysctl.d/60-cirsec.conf\n"
            f"cb_backup \"$f\"\n"
            f"touch \"$f\"\n"
            f"sed -i '/^[[:space:]]*{_sed_re(key)}[[:space:]]*=/d' \"$f\"\n"
            f"printf '%s = %s\\n' {q(key)} {q(value)} >>\"$f\"\n"
            f"sysctl -q -w {q(f'{key}={value}')}")


def package_check(s: dict) -> str:
    return (f"case $(dpkg-query -W -f='${{Status}}' {q(s['name'])} 2>/dev/null) in\n"
            f"  *' installed') o=installed ;;\n"
            f"  *) o=absent ;;\n"
            f"esac\n"
            f"printf '%s\\n' \"$o\"\n"
            f"[ \"$o\" = {q(s['state'])} ]")


def package_fix(s: dict) -> str:
    if s["state"] == "installed":
        return f"DEBIAN_FRONTEND=noninteractive apt-get install -y -q {q(s['name'])}"
    return f"DEBIAN_FRONTEND=noninteractive apt-get purge -y -q {q(s['name'])}"


def systemd_check(s: dict) -> str:
    ok = {"enabled": "enabled", "disabled": "disabled | masked | not-found", "masked": "masked | not-found"}[s["state"]]
    return (f"o=$(systemctl is-enabled {q(s['unit'])} 2>/dev/null)\n"
            f"[ -n \"$o\" ] || o=not-found\n"
            f"printf '%s\\n' \"$o\"\n"
            f"case $o in {ok}) return 0 ;; esac\n"
            f"return 1")


def systemd_fix(s: dict) -> str:
    verb = {"enabled": "enable", "disabled": "disable", "masked": "mask"}[s["state"]]
    return f"systemctl {verb} --now {q(s['unit'])}"


def _perm_lines(s: dict, fix: bool) -> list[str]:
    lines = []
    if s.get("owner"):
        lines.append(f"[ \"$1\" = {q(s['owner'])} ] || " + (f"chown {q(s['owner'])} \"$f\" || return 1" if fix else "rc=1"))
    if s.get("group"):
        lines.append(f"[ \"$2\" = {q(s['group'])} ] || " + (f"chgrp {q(s['group'])} \"$f\" || return 1" if fix else "rc=1"))
    if s.get("mode"):
        mode = s["mode"].lstrip("0") or "0"
        if fix:
            lines.append(f"[ $((0$3 & ~0{mode})) -eq 0 ] || chmod \"$(printf '%o' $((0$3 & 0{mode})))\" \"$f\" || return 1")
        else:
            lines.append(f"[ $((0$3 & ~0{mode})) -eq 0 ] || rc=1")
    return lines


def file_perms_check(s: dict) -> str:
    body = "\n  ".join(_perm_lines(s, fix=False))
    return (f"rc=0 found=0\n"
            f"for f in {_glob(s['path'])}; do\n"
            f"  [ -e \"$f\" ] || continue\n"
            f"  found=1\n"
            f"  # shellcheck disable=SC2046\n"
            f"  set -- $(stat -c '%U %G %a' \"$f\")\n"
            f"  printf '%s %s:%s %s\\n' \"$f\" \"$1\" \"$2\" \"$3\"\n"
            f"  {body}\n"
            f"done\n"
            f"[ \"$found\" = 1 ] || return 2\n"
            f"return \"$rc\"")


def file_perms_fix(s: dict) -> str:
    body = "\n  ".join(_perm_lines(s, fix=True))
    return (f"for f in {_glob(s['path'])}; do\n"
            f"  [ -e \"$f\" ] || continue\n"
            f"  # shellcheck disable=SC2046\n"
            f"  set -- $(stat -c '%U %G %a' \"$f\")\n"
            f"  {body}\n"
            f"done")


def sshd_check(s: dict) -> str:
    return (f"o=$(PATH=\"$PATH:/usr/sbin\" sshd -T 2>/dev/null | awk -v k={q(s['key'])} '$1 == k {{ $1 = \"\"; sub(/^ /, \"\"); print; exit }}')\n"
            f"[ -n \"$o\" ] || return 3\n"
            f"printf '%s\\n' \"$o\"\n"
            f"cb_cmp \"$o\" {_op(s)} {_expected(s)}")


def sshd_fix(s: dict) -> str:
    key, value = s["key"], render_text(s["value"])
    return ("grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\\*\\.conf' /etc/ssh/sshd_config || {\n"
            "  echo '/etc/ssh/sshd_config does not include sshd_config.d/*.conf' >&2\n"
            "  return 1\n"
            "}\n"
            "f=/etc/ssh/sshd_config.d/00-cirsec.conf\n"
            "mkdir -p /etc/ssh/sshd_config.d\n"
            "cb_backup \"$f\"\n"
            "touch \"$f\"\n"
            f"sed -i '/^[[:space:]]*{_sed_re(key)}[[:space:]]/Id' \"$f\"\n"
            f"printf '%s %s\\n' {q(key)} {q(value)} >>\"$f\"\n"
            "if ! PATH=\"$PATH:/usr/sbin\" sshd -t; then\n"
            "  cb_restore \"$f\"\n"
            "  echo 'sshd -t rejected the change, reverted' >&2\n"
            "  return 1\n"
            "fi")


def _dconf_names(key: str) -> tuple[str, str, str]:
    section, name = key.strip("/").rsplit("/", 1)
    return section, name, "00-cirsec-" + re.sub(r"[^a-z0-9]+", "-", key.lower()).strip("-")


def dconf_check(s: dict) -> str:
    lines = [f"o=$(dconf read {q(s['key'])} 2>/dev/null)",
             "printf '%s\\n' \"$o\"",
             f"[ \"$o\" = {_expected(s)} ] || return 1"]
    if s.get("locked", True):
        lines.append(f"grep -rqsx -- {q(s['key'])} /etc/dconf/db/local.d/locks/ || {{ echo 'not locked'; return 1; }}")
    return "\n".join(lines)


def dconf_fix(s: dict) -> str:
    section, name, file = _dconf_names(s["key"])
    lines = ["mkdir -p /etc/dconf/db/local.d/locks /etc/dconf/profile",
             "[ -f /etc/dconf/profile/user ] || printf 'user-db:user\\nsystem-db:local\\n' >/etc/dconf/profile/user",
             "grep -qx 'system-db:local' /etc/dconf/profile/user || {",
             "  echo '/etc/dconf/profile/user does not use system-db:local' >&2",
             "  return 1",
             "}",
             f"f=/etc/dconf/db/local.d/{file}",
             "cb_backup \"$f\"",
             f"printf '[%s]\\n%s=%s\\n' {q(section)} {q(name)} {q(render_text(s['value']))} >\"$f\""]
    if s.get("locked", True):
        lines += [f"l=/etc/dconf/db/local.d/locks/{file}", "cb_backup \"$l\"", f"printf '%s\\n' {q(s['key'])} >\"$l\""]
    lines.append("dconf update")
    return "\n".join(lines)


def file_content_check(s: dict) -> str:
    want = "1" if s.get("expect", "match") == "match" else "0"
    return (f"found=0 hit=0\n"
            f"for f in {_glob(s['path'])}; do\n"
            f"  [ -f \"$f\" ] || continue\n"
            f"  found=1\n"
            f"  if grep -Eq -- {q(s['pattern'])} \"$f\"; then\n"
            f"    hit=1\n"
            f"    grep -EHm 3 -- {q(s['pattern'])} \"$f\"\n"
            f"  fi\n"
            f"done\n"
            f"[ \"$found\" = 1 ] || return 2\n"
            f"[ \"$hit\" = {want} ]")


def osquery_check(s: dict) -> str:
    test = "-n" if s.get("expect", "rows") == "rows" else "-z"
    return (f"command -v osqueryi >/dev/null 2>&1 || return 3\n"
            f"o=$(osqueryi --csv --header=false {q(s['query'])} 2>/dev/null) || return 3\n"
            f"printf '%s\\n' \"$o\" | head -n 5\n"
            f"[ {test} \"$o\" ]")


def code(text: str) -> str:
    """Handwritten code runs in a subshell: it cannot change the generated script's state."""
    return f"(\n{text.rstrip()}\n)"


# engine -> (check snippet, fix snippet). Engines without a shell generator are reported as errors.
ENGINES: dict[str, tuple[Callable | None, Callable | None]] = {
    "sysctl": (sysctl_check, sysctl_fix),
    "package": (package_check, package_fix),
    "systemd-unit": (systemd_check, systemd_fix),
    "file-perms": (file_perms_check, file_perms_fix),
    "sshd-config": (sshd_check, sshd_fix),
    "dconf": (dconf_check, dconf_fix),
    "file-content": (file_content_check, None),
    "osquery": (osquery_check, None),
    "shell": (lambda s: code(s["script"]), None),
}


def check_snippet(engine: str, spec: dict) -> str:
    gen = ENGINES.get(engine, (None, None))[0]
    if gen is None:
        return f"echo {q(f'engine {engine} has no shell generator')}\nreturn 3"
    return gen(spec)


def fix_snippet(engine: str, spec: dict) -> str:
    gen = ENGINES.get(engine, (None, None))[1]
    if gen is None:
        return f"echo {q(f'engine {engine} has no shell generator')} >&2\nreturn 1"
    return gen(spec)


# =========================================================================== control scripts


def fn_name(prefix: str, slug: str) -> str:
    return f"{prefix}_" + slug.replace("-", "_")


def function(name: str, body: str) -> str:
    if body.startswith("(\n"):  # handwritten code: kept verbatim, indenting would break heredocs
        return f"{name}() {{\n{body}\n}}\n"
    return f"{name}() {{\n" + "\n".join(f"  {line}" if line else "" for line in body.splitlines()) + "\n}\n"


def control_script(ctl: Control, params: dict, header: str) -> str:
    d, std = ctl.data, ctl.standard
    audit, remediation = d.get("audit") or {}, d.get("remediation") or {}
    applicability = d.get("applicability") or {}
    checks = audit.get("checks") or []
    by_id = {c["id"]: c for c in checks}

    out = [
        "#!/bin/sh",
        f"# {ctl.id} - {d.get('title')}",
        header,
        "#",
        f"# Usage: {ctl.id}.sh check | fix [--apply]",
        "# Exit codes of check: 0 pass, 1 fail, 2 not applicable, 3 error, 4 manual or review.",
        "set -u",
        "",
        LIB.rstrip(),
        "",
        f"CB_CONTROL={q(ctl.id)}",
        f"CB_LOGIC={q(audit.get('logic', 'all'))}",
        f"CB_ASSESSMENT={q(d.get('assessment'))}",
    ]
    for name, value in params.items():
        var = "CB_" + name.upper()
        out.append(f"{var}={q(render_text(value))}; export {var}")
    out.append("")

    facts = {f.get("key"): f for f in std.data.get("facts", []) or []}
    used = set(applicability.get("facts") or [])
    for item in checks + (remediation.get("scripts") or []):
        used.update(item.get("facts") or [])
    for key in sorted(used):
        det = facts[key]["detect"]
        out.append(function(fn_name("cb_detect", key), check_snippet(det["engine"], det.get("spec") or {})))

    scope = []
    if applicability.get("versions"):
        scope.append("cb_version_in " + " ".join(q(v) for v in applicability["versions"]) + " || return $?")
    for key in applicability.get("facts") or []:
        scope.append(f"cb_fact {fn_name('', key)[1:]} || return $?")
    scope.append("return 0")
    out.append(function("cb_applicable", "\n".join(scope)))

    def scope_args(item: dict) -> str:
        versions = " ".join(item.get("versions") or [])
        facts_ = " ".join(fn_name("", k)[1:] for k in item.get("facts") or [])
        return f"{q(versions)} {q(facts_)}"

    calls = []
    for c in checks:
        name = fn_name("cb_check", c["id"])
        spec = resolve_value(c.get("spec") or {}, params)
        out.append(function(name, check_snippet(c["engine"], spec)))
        expected = expected_text(c["engine"], spec)
        calls.append(f"cb_try {q(c['id'])} {scope_args(c)} {name}" + (f" {q(expected)}" if expected else ""))
    out.append(function("cb_run_checks", "\n".join(calls) or ":"))

    calls = []
    for s in remediation.get("scripts") or []:
        name = fn_name("cb_fix", s["id"])
        if "from_check" in s:
            c = by_id[s["from_check"]]
            body = fix_snippet(c["engine"], resolve_value(c.get("spec") or {}, params))
            calls.append(f"cb_fixit {q(s['id'])} {scope_args(c)} {fn_name('cb_check', c['id'])} {name}")
        else:
            text = s["content"] if "content" in s else script_path(ctl, s["file"]).read_text(encoding="utf-8")
            body = code(text) if s["engine"] == "shell" else fix_snippet(s["engine"], {})
            calls.append(f"cb_fixit {q(s['id'])} {scope_args(s)} '' {name}")
        out.append(function(name, body))
    out.append(function("cb_run_fixes", "\n".join(calls) or ":"))
    out.append('cb_main "$@"')
    return "\n".join(out) + "\n"


# =========================================================================== selection


def select_controls(std: Standard, profile: str, tailoring: dict, include_drafts: bool) -> list[Control]:
    statuses = GENERATED_STATUSES | ({"draft", "review"} if include_drafts else set())
    extra = set(tailoring.get("include") or [])
    excluded = {e["control"] for e in tailoring.get("exclude") or []}
    picked = {
        c.id: c for c in std.controls.values()
        if c.data.get("status") in statuses
        and (profile in control_profiles(c) or c.id in extra)
        and c.id not in excluded
    }
    # Dependency order: a control comes after the controls it requires.
    ts = TopologicalSorter({cid: {r["id"] for r in c.data.get("related_controls") or []
                                  if r.get("type") == "requires" and r.get("id") in picked}
                            for cid, c in picked.items()})
    ts.prepare()
    order = []
    while ts.is_active():
        ready = sorted(ts.get_ready())
        order.extend(ready)
        ts.done(*ready)
    for cid in order:
        for r in picked[cid].data.get("related_controls") or []:
            if r.get("type") == "conflicts" and r.get("id") in picked:
                print(f"WARNING {cid} conflicts with {r['id']}, both are selected")
    return [picked[cid] for cid in order]


def fix_enabled(ctl: Control, tailoring: dict) -> bool:
    effects = (ctl.data.get("remediation") or {}).get("effects") or {}
    return not effects.get("lockout_risk") or bool((tailoring.get("fixes") or {}).get(ctl.id))


# =========================================================================== audit.sh / remediate.sh


def audit_script(std: Standard, profile: str, controls: list[Control], params: dict, tailoring: dict, header: str) -> str:
    rows = []
    for c in controls:
        d = c.data
        fixable = "1" if (d.get("remediation") or {}).get("scripts") and fix_enabled(c, tailoring) else "0"
        manual = resolve_value(((d.get("audit") or {}).get("manual") or "").strip(), params[c.id])
        rows.append(f"run {q(c.id)} {q(json.dumps(params[c.id], sort_keys=True))} "
                    f"{q((d.get('risk') or {}).get('severity', 'info'))} {fixable} {q(d.get('title', ''))} {q(manual)}")
    rows += [f"excluded {q(e['control'])} {q(e['reason'])}" for e in tailoring.get("exclude") or []]
    meta = {"standard": std.id, "version": std.data.get("version"), "profile": profile}
    return f"""#!/bin/sh
# Audit {std.id} {meta['version']}, profile {profile}: runs every check, prints a result JSON
# (schema/result.schema.json) and a readable report on stderr. On a terminal, the JSON goes
# to ./cirsec-result-<host>-<date>.json instead of stdout. Exit 0 when nothing fails, 1 otherwise.
# Usage: audit.sh [-v | --verbose]
{header}
set -u
dir=$(dirname "$0")/controls
rc=0 sep=

{REPORT.rstrip()}

case ${{1:-}} in
  -v | --verbose) CB_VERBOSE=1 ;;
  "") ;;
  *) echo "usage: $0 [-v | --verbose]" >&2; exit 64 ;;
esac
json_file=
if [ -t 1 ]; then
  json_file=cirsec-result-$(hostname)-$(date +%Y%m%d-%H%M%S).json
  exec >"$json_file"
fi

json() {{ printf '"%s"' "$(printf '%s' "$1" | sed 's/\\\\/\\\\\\\\/g; s/"/\\\\"/g' | tr -d '\\000-\\037')"; }}

run() {{
  out=$(sh "$dir/$1.sh" check)
  status=$(printf '%s\\n' "$out" | awk -F '\\t' '$1 == "control" {{ print $3 }}')
  case $status in fail | error) rc=1 ;; esac
  printf '%s{{"control":%s,"status":%s,"parameters":%s,"checks":[' "$sep" "$(json "$1")" "$(json "$status")" "$2"
  csep=
  printf '%s\\n' "$out" | awk -F '\\t' '$1 == "check" {{ print $2; print $3; print $4; print $5 }}' |
    while read -r id && read -r st && read -r ev && read -r ex; do
      exj=
      [ -z "$ex" ] || exj=",\\"expected\\":$(json "$ex")"
      printf '%s{{"id":%s,"status":%s,"evidence":{{"observed":%s%s}}}}' "$csep" "$(json "$id")" "$(json "$st")" "$(json "$ev")" "$exj"
      csep=,
    done
  printf ']}}'
  sep=,
  cb_report "$1" "$status" "$3" "$4" "$5" "$6" "$out"
}}

excluded() {{
  printf '%s{{"control":%s,"status":"excluded","message":%s}}' "$sep" "$(json "$1")" "$(json "$2")"
  sep=,
  cb_report_excluded
}}

printf '{{"format":"cirsec-baselines-result","standard":%s,"version":%s,"profile":%s,' \\
  {q(json.dumps(meta['standard']))} {q(json.dumps(meta['version']))} {q(json.dumps(profile))}
CB_PRODUCT_VERSION=${{CB_PRODUCT_VERSION-$( (. /etc/os-release && printf '%s' "$VERSION_ID") 2>/dev/null)}}
export CB_PRODUCT_VERSION
printf '"target":{{"name":%s,"product_version":%s}},' "$(json "$(hostname)")" "$(json "$CB_PRODUCT_VERSION")"
printf '"scanner":{{"name":"cirsec-audit.sh","version":%s}},"started":%s,"results":[' \\
  {q(json.dumps(meta['version']))} "$(json "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
{chr(10).join(rows)}
printf '],"finished":%s}}\\n' "$(json "$(date -u +%Y-%m-%dT%H:%M:%SZ)")"
cb_report_print {q(std.id)} {q(str(meta['version']))} {q(profile)} "$json_file"
exit "$rc"
"""


def remediate_script(std: Standard, profile: str, controls: list[Control], tailoring: dict, header: str) -> str:
    lines = []
    for c in controls:
        if not (c.data.get("remediation") or {}).get("scripts"):
            continue
        eff = (c.data.get("remediation") or {}).get("effects") or {}
        var = "CB_ENABLE_" + c.id.replace("-", "_")
        default = "1" if fix_enabled(c, tailoring) else "0"
        lines.append(f"fix {q(c.id)} \"${{{var}:-{default}}}\" {q(eff.get('restart', 'none'))} {q(' '.join(eff.get('services') or []))}")
    return f"""#!/bin/sh
# Remediate {std.id} {std.data.get('version')}, profile {profile}. Dry run unless --apply.
# Fixes run in dependency order. Each service to restart is restarted once, at the end.
# Disable one fix with CB_ENABLE_<ID with underscores>=0, enable a lockout-risk fix with =1.
{header}
set -u
dir=$(dirname "$0")/controls
apply='' rc=0 services='' reboot='' session=''
[ "${{1:-}}" = --apply ] && apply=--apply
if [ -n "$apply" ] && [ "$(id -u)" != 0 ]; then
  echo "--apply needs root" >&2
  exit 1
fi
CB_BACKUP_DIR=${{CB_BACKUP_DIR:-/var/backups/cirsec/$(date +%Y%m%d-%H%M%S)}}
export CB_BACKUP_DIR
[ -z "$apply" ] || echo "backups of changed files: $CB_BACKUP_DIR"

fix() {{
  if [ "$2" != 1 ]; then
    printf '%s\\tdisabled\\n' "$1"
    return
  fi
  out=$(sh "$dir/$1.sh" fix $apply) || rc=1
  printf '%s\\n' "$out" | sed "s/^/$1\\t/"
  case $out in
    *CHANGED*)
      case $3 in
        service) services="$services $4" ;;
        reboot) reboot=1 ;;
        session) session=1 ;;
      esac ;;
  esac
}}

{chr(10).join(lines) or ':'}

# shellcheck disable=SC2086 # one word per service
for s in $(printf '%s\\n' $services | sort -u); do
  echo "restarting $s"
  systemctl try-reload-or-restart "$s" || rc=1
done
[ -z "$session" ] || echo "users must log in again for some changes to apply"
[ -z "$reboot" ] || echo "REBOOT REQUIRED for some changes to apply"
exit "$rc"
"""


# =========================================================================== Ansible


def ansible_files(std: Standard, profile: str, controls: list[Control], tailoring: dict, header: str) -> dict[str, str]:
    role = "cirsec_" + std.id.replace("-", "_")
    comment = "\n".join("# " + line.lstrip("# ") for line in header.splitlines())
    defaults, tasks, handlers = [comment, "---"], [comment, "---"], [comment, "---"]
    handler_names = {}
    for c in controls:
        rem = c.data.get("remediation") or {}
        if not rem.get("scripts"):
            continue
        slug = c.id.lower().replace("-", "_")
        enabled, reg = f"{role}_{slug}_enabled", f"{role}_{slug}_check"
        defaults.append(f"{enabled}: {'true' if fix_enabled(c, tailoring) else 'false'}")
        eff = rem.get("effects") or {}
        notify = []
        if eff.get("restart") == "service":
            for svc in eff.get("services") or []:
                notify.append(f"cirsec restart {svc}")
                handler_names[notify[-1]] = f"ansible.builtin.command: systemctl try-reload-or-restart {svc}\n  changed_when: true"
        elif eff.get("restart") in ("reboot", "session"):
            notify.append(f"cirsec {eff['restart']} required")
            msg = "REBOOT REQUIRED" if eff["restart"] == "reboot" else "users must log in again"
            handler_names[notify[-1]] = f"ansible.builtin.debug:\n    msg: {json.dumps(msg)}"
        title = json.dumps(c.data.get("title"))[1:-1]
        tasks.append(f"""
- name: "{c.id} | check | {title}"
  ansible.builtin.script: {c.id}.sh check
  register: {reg}
  changed_when: false
  failed_when: {reg}.rc not in [0, 1, 2, 4]
  check_mode: false
  when: {enabled} | bool
  tags: [{c.id}]

- name: "{c.id} | fix"
  ansible.builtin.script: {c.id}.sh fix --apply
  register: {role}_{slug}_fix
  changed_when: "'CHANGED' in {role}_{slug}_fix.stdout"
  when: {enabled} | bool and {reg}.rc == 1""")
        if notify:
            tasks.append("  notify:\n" + "\n".join(f"    - {json.dumps(n)}" for n in notify))
        tasks.append(f"  tags: [{c.id}]")
    for name, body in handler_names.items():
        handlers.append(f"- name: {json.dumps(name)}\n  {body}")
    play = f"""{comment}
---
- name: CIRSEC Baselines {std.id} {std.data.get('version')}, profile {profile}
  hosts: all
  become: true
  roles:
    - {role}
"""
    if len(defaults) == 2:
        defaults.append("{}")
    if len(tasks) == 2:
        tasks.append("[]")
    if len(handlers) == 2:
        handlers.append("[]")
    base = f"roles/{role}"
    return {
        "site.yml": play,
        f"{base}/defaults/main.yml": "\n".join(defaults) + "\n",
        f"{base}/tasks/main.yml": "\n".join(tasks) + "\n",
        f"{base}/handlers/main.yml": "\n".join(handlers) + "\n",
    }


# =========================================================================== entry points


def generate(repo: Repo, std: Standard, profile: str, out: Path, *, tailoring: dict | None = None,
             include_drafts: bool = False) -> list[Control]:
    """Write every artifact for one profile into out (replaced). Deterministic: no dates, no host data."""
    tailoring = tailoring or {}
    if profile not in std.profiles:
        raise GenerateError(f"unknown profile {profile!r} (declared: {sorted(std.profiles)})")
    controls = select_controls(std, profile, tailoring, include_drafts)
    overrides = tailoring.get("parameters") or {}
    params = {c.id: resolve_parameters(c, profile, overrides.get(c.id)) for c in controls}
    origin = f"{std.id} {std.data.get('version')}, profile {profile}"
    if tailoring:
        origin += f", tailoring {tailoring.get('title') or 'file'}"
    header = (f"# Generated by CIRSEC Baselines tools/generate.py from {origin}. Do not edit.\n"
              f"# SPDX-License-Identifier: {repo.meta.get('licenses', {}).get('code', 'Apache-2.0')}")

    if out.exists():
        shutil.rmtree(out)
    files = {f"controls/{c.id}.sh": control_script(c, params[c.id], header) for c in controls}
    files["audit.sh"] = audit_script(std, profile, controls, params, tailoring, header)
    files["remediate.sh"] = remediate_script(std, profile, controls, tailoring, header)
    with_fix = [c for c in controls if (c.data.get("remediation") or {}).get("scripts")]
    role = "cirsec_" + std.id.replace("-", "_")
    for name, text in ansible_files(std, profile, with_fix, tailoring, header).items():
        files[f"ansible/{name}"] = text
    for c in with_fix:
        files[f"ansible/roles/{role}/files/{c.id}.sh"] = files[f"controls/{c.id}.sh"]
    for rel, text in files.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        if rel.endswith(".sh"):
            path.chmod(0o755)
    return controls


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--standard", required=True, help="standard id (folder name)")
    ap.add_argument("--profile", help="profile key (default: the one in --tailoring)")
    ap.add_argument("--tailoring", type=Path, help="tailoring file (schema/tailoring.schema.json)")
    ap.add_argument("--out", type=Path, required=True, help="output folder, replaced")
    ap.add_argument("--include-drafts", action="store_true", help="also generate draft and review controls")
    ap.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    repo, report = validate.run(args.root.resolve())
    if repo is None or report.errors:
        report.print()
        print("\nValidation failed, nothing generated.")
        return 1
    std = repo.find_standard(args.standard)
    if std is None:
        print(f"ERROR unknown standard {args.standard!r}")
        return 1
    tailoring = {}
    if args.tailoring:
        try:
            tailoring = tailor.load_checked(args.tailoring, repo)
        except SystemExit as exc:
            return int(exc.code or 1)
        if tailoring["standard"] != std.id:
            print(f"ERROR tailoring is for standard {tailoring['standard']!r}")
            return 1
    profile = args.profile or tailoring.get("profile")
    if not profile:
        print("ERROR --profile is required without --tailoring")
        return 1
    if tailoring and profile != tailoring["profile"]:
        print(f"ERROR tailoring is for profile {tailoring['profile']!r}")
        return 1
    try:
        controls = generate(repo, std, profile, args.out, tailoring=tailoring, include_drafts=args.include_drafts)
    except GenerateError as exc:
        print(f"ERROR {exc}")
        return 1
    print(f"generated {std.id} profile {profile}: {len(controls)} control(s) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

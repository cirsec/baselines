# CIRSEC Baselines - runtime shared by every generated control script.
# Inlined by tools/generate.py into each controls/<ID>.sh, so every script is self-contained.
# SPDX-License-Identifier: Apache-2.0
#
# A generated script defines:
#   CB_CONTROL, CB_LOGIC (all|any), CB_ASSESSMENT (automated|partial|manual)
#   cb_applicable   returns 0 applicable, 2 not applicable, 3 error
#   cb_run_checks   calls cb_try for each check
#   cb_run_fixes    calls cb_fixit for each script
#   cb_check_*, cb_fix_*, cb_detect_*   engine snippets
#
# Snippet return codes: 0 pass, 1 fail, 2 not applicable, 3 error. Stdout is the evidence.

CB_BACKUP_DIR=${CB_BACKUP_DIR:-/var/backups/cirsec/$(date +%Y%m%d-%H%M%S)}

# Product version of the target (e.g. 12 for Debian 12). Override with CB_PRODUCT_VERSION.
if [ -z "${CB_PRODUCT_VERSION+x}" ]; then
  CB_PRODUCT_VERSION=$( (. /etc/os-release && printf '%s' "${VERSION_ID%%.*}") 2>/dev/null)
fi

# cb_cmp OBSERVED OPERATOR EXPECTED -> 0 true, 1 false, 3 cannot compare.
# For in/not_in, EXPECTED holds one value per line.
cb_cmp() {
  _cb_cmp "$@"
  _r=$?
  [ "$_r" -le 1 ] && return "$_r"
  return 3
}
_cb_cmp() {
  case $2 in
    "==") [ "$1" = "$3" ] ;;
    "!=") [ "$1" != "$3" ] ;;
    "<" | "<=" | ">" | ">=")
      case $1$3 in *[!0-9-]* | "") return 3 ;; esac
      case $2 in
        "<") [ "$1" -lt "$3" ] ;;
        "<=") [ "$1" -le "$3" ] ;;
        ">") [ "$1" -gt "$3" ] ;;
        ">=") [ "$1" -ge "$3" ] ;;
      esac ;;
    in) printf '%s\n' "$3" | grep -Fxq -- "$1" ;;
    not_in) ! printf '%s\n' "$3" | grep -Fxq -- "$1" ;;
    match) printf '%s' "$1" | grep -Eq -- "$3" ;;
    *) return 3 ;;
  esac
}

# cb_version_in V... -> 0 if the target version is listed, 2 if not, 3 if unknown.
cb_version_in() {
  if [ -z "$CB_PRODUCT_VERSION" ]; then
    echo "product version unknown, set CB_PRODUCT_VERSION" >&2
    return 3
  fi
  for _v in "$@"; do
    [ "$_v" = "$CB_PRODUCT_VERSION" ] && return 0
  done
  return 2
}

# cb_fact NAME -> 0 true, 2 false, 3 detection error.
cb_fact() {
  "cb_detect_$1" >/dev/null 2>&1
  case $? in
    0) return 0 ;;
    1 | 2) return 2 ;;
    *) return 3 ;;
  esac
}

# cb_scope "VERSIONS" "FACTS" -> 0 in scope, 2 not, 3 error. Both are space-separated, may be empty.
cb_scope() {
  if [ -n "$1" ]; then
    # shellcheck disable=SC2086 # word splitting is the point
    cb_version_in $1 || return $?
  fi
  for _f in $2; do
    cb_fact "$_f" || return $?
  done
  return 0
}

cb_oneline() { printf '%s' "$1" | tr '\t\n\r' '   ' | cut -c1-500; }

# Back up a file before changing it. A missing file is recorded so cb_restore can remove it.
cb_backup() {
  _b="$CB_BACKUP_DIR$1"
  [ -e "$_b" ] || [ -e "$_b.absent" ] && return 0
  mkdir -p "$(dirname "$_b")"
  if [ -e "$1" ]; then cp -p "$1" "$_b"; else : >"$_b.absent"; fi
}
cb_restore() {
  _b="$CB_BACKUP_DIR$1"
  if [ -e "$_b" ]; then cp -p "$_b" "$1"; elif [ -e "$_b.absent" ]; then rm -f "$1"; fi
}

# cb_try ID "VERSIONS" "FACTS" FUNCTION ["EXPECTED"]
# -> prints "check<TAB>id<TAB>status<TAB>evidence<TAB>expected".
cb_try() {
  cb_scope "$2" "$3"
  _r=$?
  _out=
  if [ "$_r" -eq 0 ]; then
    _out=$("$4" 2>&1)
    _r=$?
  fi
  case $_r in
    0) _s=pass; CB_P=$((CB_P + 1)) ;;
    1) _s=fail; CB_F=$((CB_F + 1)) ;;
    2) _s=not_applicable ;;
    *) _s=error; CB_E=$((CB_E + 1)) ;;
  esac
  printf 'check\t%s\t%s\t%s\t%s\n' "$1" "$_s" "$(cb_oneline "$_out")" "${5:-}"
}

# cb_fixit ID "VERSIONS" "FACTS" CHECK_FUNCTION FIX_FUNCTION
# CHECK_FUNCTION is empty for handwritten scripts, which must be idempotent.
cb_fixit() {
  cb_scope "$2" "$3"
  _r=$?
  if [ "$_r" -ne 0 ]; then
    [ "$_r" -eq 2 ] && _s=not_applicable || _s=error
    printf 'fix\t%s\t%s\n' "$1" "$_s"
    [ "$_r" -eq 2 ] || CB_RC=1
    return
  fi
  if [ -n "$4" ]; then
    "$4" >/dev/null 2>&1
    case $? in
      0) printf 'fix\t%s\tcompliant\n' "$1"; return ;;
      1) ;;
      2) printf 'fix\t%s\tnot_applicable\n' "$1"; return ;;
      *) printf 'fix\t%s\terror\tcheck could not run, fix skipped\n' "$1"; CB_RC=1; return ;;
    esac
  fi
  if [ "$CB_APPLY" -ne 1 ]; then
    printf 'fix\t%s\twould-apply\n' "$1"
    return
  fi
  _out=$("$5" 2>&1)
  if [ $? -ne 0 ]; then
    printf 'fix\t%s\tfailed\t%s\n' "$1" "$(cb_oneline "$_out")"
    CB_RC=1
    return
  fi
  if [ -n "$4" ] && ! "$4" >/dev/null 2>&1; then
    printf 'fix\t%s\tstill-failing\n' "$1"
    CB_RC=1
    return
  fi
  printf 'fix\t%s\tCHANGED\n' "$1"
}

# Control status from the counters, following CB_LOGIC and CB_ASSESSMENT.
cb_status() {
  if [ "$CB_LOGIC" = any ]; then
    if [ "$CB_P" -gt 0 ]; then _s=pass
    elif [ "$CB_E" -gt 0 ]; then _s=error
    elif [ "$CB_F" -gt 0 ]; then _s=fail
    else _s=not_applicable; fi
  else
    if [ "$CB_F" -gt 0 ]; then _s=fail
    elif [ "$CB_E" -gt 0 ]; then _s=error
    elif [ "$CB_P" -gt 0 ]; then _s=pass
    else _s=not_applicable; fi
  fi
  [ "$_s" = pass ] && [ "$CB_ASSESSMENT" = partial ] && _s=review
  printf '%s' "$_s"
}

cb_exit_code() {
  case $1 in
    pass) echo 0 ;; fail) echo 1 ;; not_applicable) echo 2 ;; error) echo 3 ;; *) echo 4 ;;
  esac
}

cb_main() {
  case ${1:-} in
    check)
      if [ "$CB_ASSESSMENT" = manual ]; then
        printf 'control\t%s\tmanual\n' "$CB_CONTROL"
        exit 4
      fi
      cb_applicable
      _r=$?
      if [ "$_r" -ne 0 ]; then
        [ "$_r" -eq 2 ] && _s=not_applicable || _s=error
      else
        CB_P=0 CB_F=0 CB_E=0
        cb_run_checks
        _s=$(cb_status)
      fi
      printf 'control\t%s\t%s\n' "$CB_CONTROL" "$_s"
      exit "$(cb_exit_code "$_s")"
      ;;
    fix)
      CB_APPLY=0
      [ "${2:-}" = --apply ] && CB_APPLY=1
      CB_RC=0
      cb_applicable
      _r=$?
      if [ "$_r" -ne 0 ]; then
        [ "$_r" -eq 2 ] && _s=not_applicable || _s=error
        printf 'control\t%s\t%s\n' "$CB_CONTROL" "$_s"
        [ "$_r" -eq 2 ] && exit 0
        exit 1
      fi
      cb_run_fixes
      exit "$CB_RC"
      ;;
    *)
      echo "usage: $0 check | fix [--apply]" >&2
      exit 64
      ;;
  esac
}

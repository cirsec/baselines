# CIRSEC Baselines - human-readable report of audit.sh, printed on stderr.
# Inlined by tools/generate.py into audit.sh. Colors only on a terminal, and never with NO_COLOR.
# SPDX-License-Identifier: Apache-2.0
#
# audit.sh calls cb_report once per control, cb_report_excluded per excluded control,
# then cb_report_print at the end. Sections are kept in a temporary directory, one file
# per control named <severity rank>-<ID>, so a glob lists them by severity.

CB_VERBOSE=0
CB_TMP=$(mktemp -d) || exit 3
trap 'rm -rf "$CB_TMP"' EXIT
mkdir "$CB_TMP/fail" "$CB_TMP/error" "$CB_TMP/manual"
n_pass=0 n_fail=0 n_error=0 n_manual=0 n_review=0 n_na=0 n_excluded=0 n_fixable=0

if [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
  e=$(printf '\033')
  c_ok="${e}[32m" c_ko="${e}[31m" c_wa="${e}[33m" c_ac="${e}[36m" c_mu="${e}[2m" c_b="${e}[1m" c_0="${e}[0m"
else
  c_ok='' c_ko='' c_wa='' c_ac='' c_mu='' c_b='' c_0=''
fi

# cb_report ID STATUS SEVERITY FIXABLE(0|1) TITLE MANUAL CHECK_OUTPUT
cb_report() {
  case $2 in
    pass) n_pass=$((n_pass + 1)); return ;;
    not_applicable) n_na=$((n_na + 1)); return ;;
    fail) n_fail=$((n_fail + 1)); _d=fail _m="${c_ko}✘${c_0}"
      [ "$4" = 1 ] && n_fixable=$((n_fixable + 1)) ;;
    manual) n_manual=$((n_manual + 1)); _d=manual _m="$c_wa?$c_0" ;;
    review) n_review=$((n_review + 1)); _d=manual _m="$c_wa~$c_0" ;;
    *) n_error=$((n_error + 1)); _d=error _m="$c_ko!$c_0" ;;
  esac
  case $3 in
    critical) _r=1 _c=$c_ko ;; high) _r=2 _c=$c_ko ;; medium) _r=3 _c=$c_wa ;; low) _r=4 _c=$c_mu ;; *) _r=5 _c=$c_mu ;;
  esac
  {
    printf '  %s %-18s %s%-8s%s %s\n' "$_m" "$1" "$_c" "$3" "$c_0" "$5"
    # Failing checks: observed and expected values.
    printf '%s\n' "$7" | awk -F '\t' -v d="$c_mu" -v z="$c_0" '
      $1 == "check" && ($3 == "fail" || $3 == "error") {
        s = "      " $2 ($3 == "error" ? " (could not run)" : "") "  " d "observed" z " " ($4 == "" ? "-" : $4)
        if ($5 != "") s = s "  " d "expected" z " " $5
        print s
      }'
    if [ "$_d" = manual ] && [ -n "$6" ]; then
      printf '%s\n' "$6" | awk -v d="$c_mu" -v z="$c_0" '{ print (NR == 1 ? "      → " : "        ") d $0 z }'
    fi
  } >"$CB_TMP/$_d/$_r-$1"
}

cb_report_excluded() { n_excluded=$((n_excluded + 1)); }

# cb_report_section DIR TITLE COLOR LIMIT
cb_report_section() {
  _all=0
  for _f in "$CB_TMP/$1"/*; do [ -e "$_f" ] && _all=$((_all + 1)); done
  [ "$_all" -eq 0 ] && return
  printf '\n%s%s%s (%s)%s\n' "$c_b" "$3" "$2" "$_all" "$c_0"
  _n=0
  for _f in "$CB_TMP/$1"/*; do
    [ "$CB_VERBOSE" = 1 ] || [ "$_n" -lt "$4" ] || break
    cat "$_f"
    _n=$((_n + 1))
  done
  [ "$_n" -lt "$_all" ] && printf '  %s… %s more, run with --verbose to show all%s\n' "$c_mu" $((_all - _n)) "$c_0"
  return 0
}

cb_bar() {
  _i=0
  while [ "$_i" -lt "$2" ]; do printf '%s' "$1"; _i=$((_i + 1)); done
}

# cb_report_print STANDARD VERSION PROFILE JSON_FILE
cb_report_print() {
  _os=$( (. /etc/os-release && printf '%s' "$PRETTY_NAME") 2>/dev/null)
  _total=$((n_pass + n_fail + n_error + n_manual + n_review + n_na))
  _scored=$((n_pass + n_fail + n_error))
  {
    printf '\n%sCIRSEC Baselines%s · %s %s · profile %s%s%s\n' "$c_b" "$c_0" "$1" "$2" "$c_ac" "$3" "$c_0"
    printf '%sTarget  %s · %s · %s%s\n' "$c_mu" "$(hostname)" "${_os:-unknown OS}" "$(date -u '+%Y-%m-%d %H:%M UTC')" "$c_0"
    printf '\n%sSummary%s\n  ' "$c_b" "$c_0"
    if [ "$_total" -gt 0 ]; then
      _w_ok=$((n_pass * 40 / _total)) _w_ko=$(((n_fail + n_error) * 40 / _total)) _w_wa=$(((n_manual + n_review) * 40 / _total))
      printf '%s' "$c_ok"; cb_bar ■ "$_w_ok"
      printf '%s' "$c_ko"; cb_bar ■ "$_w_ko"
      printf '%s' "$c_wa"; cb_bar ■ "$_w_wa"
      printf '%s' "$c_mu"; cb_bar ■ $((40 - _w_ok - _w_ko - _w_wa))
      printf '%s' "$c_0"
    fi
    [ "$_scored" -gt 0 ] && printf '  %s%s %%%s compliant' "$c_b" $((n_pass * 100 / _scored)) "$c_0"
    printf '\n  %s✔ %s passed%s   %s✘ %s failed%s   %s! %s errors%s   %s? %s manual%s   %s~ %s to confirm%s\n' \
      "$c_ok" "$n_pass" "$c_0" "$c_ko" "$n_fail" "$c_0" "$c_ko" "$n_error" "$c_0" \
      "$c_wa" "$n_manual" "$c_0" "$c_wa" "$n_review" "$c_0"
    printf '  %s– %s not applicable   ⊘ %s excluded (tailoring)%s\n' "$c_mu" "$n_na" "$n_excluded" "$c_0"

    cb_report_section fail "Failed" "$c_ko" 10
    cb_report_section error "Errors" "$c_ko" 10
    cb_report_section manual "Check by hand" "$c_wa" 5

    printf '\n%sNext%s\n' "$c_b" "$c_0"
    _rem="$(dirname "$0")/remediate.sh"
    if [ "$n_fixable" -gt 0 ]; then
      printf '  %ssh %s%s  %spreview the fixes, changes nothing%s\n' "$c_ac" "$_rem" "$c_0" "$c_mu" "$c_0"
      printf '  %ssudo sh %s --apply%s  %sapply the available fixes (%s)%s\n' "$c_ac" "$_rem" "$c_0" "$c_mu" "$n_fixable" "$c_0"
    elif [ "$n_fail" -eq 0 ]; then
      printf '  %sNothing to fix.%s\n' "$c_ok" "$c_0"
    else
      printf '  %sNo automatic fix available for these failures, see the controls.%s\n' "$c_mu" "$c_0"
    fi
    [ -z "$4" ] || printf '  %sResult JSON: %s%s\n' "$c_mu" "$4" "$c_0"
  } >&2
}

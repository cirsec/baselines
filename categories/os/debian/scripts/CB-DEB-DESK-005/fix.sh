# Turn off XDMCP in GDM. Only edits /etc/gdm3/daemon.conf when XDMCP is enabled.
f=/etc/gdm3/daemon.conf
[ -f "$f" ] || { echo "$f not found" >&2; exit 1; }

# ini_get SECTION KEY: last value of KEY in [SECTION] of daemon.conf, empty when unset.
ini_get() {
  S="[$1]" K=$2 awk '
    BEGIN { s = ENVIRON["S"]; k = ENVIRON["K"] }
    /^[ \t]*\[/ { h = $0; gsub(/^[ \t]+|[ \t]+$/, "", h); in_s = (h == s); next }
    in_s && /=/ && !/^[ \t]*[#;]/ {
      key = substr($0, 1, index($0, "=") - 1); gsub(/^[ \t]+|[ \t]+$/, "", key)
      if (key == k) { v = substr($0, index($0, "=") + 1); gsub(/^[ \t]+|[ \t]+$/, "", v) }
    }
    END { print v }
  ' "$f"
}

# ini_set SECTION KEY VALUE: set KEY=VALUE right after the [SECTION] header, adding the section if missing.
ini_set() {
  S="[$1]" K=$2 V=$3 awk '
    BEGIN { s = ENVIRON["S"]; k = ENVIRON["K"]; v = ENVIRON["V"] }
    function out() { if (!done) { print k "=" v; done = 1 } }
    /^[ \t]*\[/ { print; h = $0; gsub(/^[ \t]+|[ \t]+$/, "", h); in_s = (h == s); if (in_s) out(); next }
    in_s && $0 ~ "^[ \t]*" k "[ \t]*=" { next }
    { print }
    END { if (!done) { print s; out() } }
  ' "$f" >"$f.cirsec-tmp" && cat "$f.cirsec-tmp" >"$f"
  rc=$?
  rm -f "$f.cirsec-tmp"
  return "$rc"
}

is_true() { case $1 in [Tt][Rr][Uu][Ee] | 1) return 0 ;; esac; return 1; }

is_true "$(ini_get xdmcp Enable)" || exit 0
cb_backup "$f"
ini_set xdmcp Enable false

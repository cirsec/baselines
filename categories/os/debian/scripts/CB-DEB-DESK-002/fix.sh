# Debian builds the GDM greeter dconf database from /usr/share/gdm/dconf/, which links
# /etc/gdm3/greeter.dconf-defaults. Set the keys there, then rebuild the database.
f=/etc/gdm3/greeter.dconf-defaults
[ -f "$f" ] || { echo "$f not found" >&2; exit 1; }

# ini_set KEY VALUE: set KEY=VALUE right after the [org/gnome/login-screen] header,
# adding the section if missing.
ini_set() {
  S='[org/gnome/login-screen]' K=$1 V=$2 awk '
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

# GVariant string: escape backslashes and quotes, newlines as \n.
txt=$(printf '%s\n' "$CB_BANNER_TEXT" | sed -e 's/\\/\\\\/g' -e "s/'/\\\\'/g" | awk 'NR > 1 { printf "\\n" } { printf "%s", $0 }')

cb_backup "$f"
ini_set banner-message-enable true || exit 1
ini_set banner-message-text "'$txt'" || exit 1
ini_set disable-user-list true || exit 1
/usr/share/gdm/generate-config

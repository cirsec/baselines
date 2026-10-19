# CB-UBU-NET-017: bring SSH keepalive and connection limits within bounds, changing only what is out of bounds.
PATH="$PATH:/usr/sbin"
# sshd -T and -t need /run/sshd, which only exists once ssh.service has run (ssh.socket on 24.04 and later).
[ -d /run/sshd ] || mkdir -p -m 0755 /run/sshd
f=/etc/ssh/sshd_config.d/00-cirsec.conf
grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\*\.conf' /etc/ssh/sshd_config || {
  echo '/etc/ssh/sshd_config does not include sshd_config.d/*.conf' >&2
  exit 1
}
cfg=$(sshd -T 2>/dev/null) || { echo 'sshd -T failed' >&2; exit 1; }
get() { printf '%s\n' "$cfg" | awk -v k="$1" '$1 == k { print $2; exit }'; }
# in_range VALUE MAX: VALUE is an integer between 1 and MAX.
in_range() { case $1 in '' | *[!0-9]*) return 1 ;; esac; [ "$1" -ge 1 ] && [ "$1" -le "$2" ]; }
changes=
in_range "$(get clientaliveinterval)" "$CB_SSH_CLIENT_ALIVE_INTERVAL" || changes="$changes clientaliveinterval=$CB_SSH_CLIENT_ALIVE_INTERVAL"
in_range "$(get clientalivecountmax)" "$CB_SSH_CLIENT_ALIVE_COUNT_MAX" || changes="$changes clientalivecountmax=$CB_SSH_CLIENT_ALIVE_COUNT_MAX"
in_range "$(get maxsessions)" "$CB_SSH_MAX_SESSIONS" || changes="$changes maxsessions=$CB_SSH_MAX_SESSIONS"
get maxstartups | grep -Eq '^([1-9]|10):([1-9]|[12][0-9]|30):([1-9]|[1-5][0-9]|60)$' || changes="$changes maxstartups=10:30:60"
[ -n "$changes" ] || exit 0
mkdir -p /etc/ssh/sshd_config.d
cb_backup "$f"
touch "$f"
chmod 600 "$f"
for c in $changes; do
  k=${c%%=*}
  sed -i "/^[[:space:]]*${k}[[:space:]]/Id" "$f"
  printf '%s %s\n' "$k" "${c#*=}" >>"$f"
done
if ! sshd -t; then
  cb_restore "$f"
  echo 'sshd -t rejected the change, reverted' >&2
  exit 1
fi

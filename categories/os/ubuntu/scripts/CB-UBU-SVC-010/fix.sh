# Bind the local MTA (exim4 or Postfix) to the loopback interface only.
# Idempotent: each MTA is changed and restarted only when its setting differs.
rc=0
f=/etc/exim4/update-exim4.conf.conf
want="dc_local_interfaces='127.0.0.1 ; ::1'"
if [ -f "$f" ] && ! grep -qxF "$want" "$f"; then
  cb_backup "$f"
  if grep -q '^dc_local_interfaces=' "$f"; then
    sed -i "s/^dc_local_interfaces=.*/$want/" "$f"
  else
    printf '%s\n' "$want" >>"$f"
  fi
  if update-exim4.conf; then
    systemctl try-restart exim4.service || rc=1
  else
    cb_restore "$f"
    echo "update-exim4.conf failed, reverted $f" >&2
    rc=1
  fi
fi
if command -v postconf >/dev/null 2>&1 && [ -f /etc/postfix/main.cf ] &&
  [ "$(postconf -h inet_interfaces)" != loopback-only ]; then
  cb_backup /etc/postfix/main.cf
  postconf -e 'inet_interfaces = loopback-only' || rc=1
  systemctl try-restart postfix.service || rc=1
fi
exit "$rc"

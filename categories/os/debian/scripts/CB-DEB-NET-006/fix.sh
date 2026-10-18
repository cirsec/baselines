# CB-DEB-NET-006: with ufw active, allow each SSH port that has no rule, then deny incoming and routed by default.
PATH="$PATH:/usr/sbin"
s=$(ufw status 2>/dev/null)
printf '%s\n' "$s" | grep -q '^Status: active' || exit 0
for f in /etc/default/ufw /etc/ufw/user.rules /etc/ufw/user6.rules; do cb_backup "$f"; done
for p in $(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }'); do
  printf '%s\n' "$s" | grep -Eq "^($p(/tcp)?|OpenSSH)[[:space:]]+(ALLOW|LIMIT)" && continue
  ufw allow "$p/tcp" comment 'SSH (CIRSEC Baselines)' >/dev/null || exit 1
done
ufw default deny incoming >/dev/null || exit 1
ufw default deny routed >/dev/null

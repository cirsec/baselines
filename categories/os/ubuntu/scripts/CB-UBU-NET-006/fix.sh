# CB-UBU-NET-006: with ufw active, allow each SSH port that has no rule, then deny incoming and routed by default.
PATH="$PATH:/usr/sbin"
s=$(ufw status 2>/dev/null)
printf '%s\n' "$s" | grep -q '^Status: active' || exit 0
# sshd -T needs /run/sshd, which only exists once ssh.service has run (ssh.socket on 24.04 and later).
if command -v sshd >/dev/null 2>&1; then
  [ -d /run/sshd ] || mkdir -m 0755 /run/sshd
  ports=$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }')
  if [ -z "$ports" ]; then
    echo 'cannot read the SSH ports with sshd -T; ufw defaults left unchanged' >&2
    exit 1
  fi
fi
for f in /etc/default/ufw /etc/ufw/user.rules /etc/ufw/user6.rules; do cb_backup "$f"; done
for p in $ports; do
  printf '%s\n' "$s" | grep -Eq "^($p(/tcp)?|OpenSSH)[[:space:]]+(ALLOW|LIMIT)" && continue
  ufw allow "$p/tcp" comment 'SSH (CIRSEC Baselines)' >/dev/null || exit 1
done
ufw default deny incoming >/dev/null || exit 1
ufw default deny routed >/dev/null

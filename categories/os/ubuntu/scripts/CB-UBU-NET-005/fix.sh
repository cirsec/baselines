# CB-UBU-NET-005: when no firewall is active, enable ufw (installed by default on Ubuntu), allowing SSH first.
# Does nothing when exactly one firewall tool is active; fails when several are (choice left to a human).
PATH="$PATH:/usr/sbin"
active=
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
  active="$active ufw"
fi
for u in nftables firewalld netfilter-persistent; do
  [ "$(systemctl is-enabled "$u.service" 2>/dev/null)" = enabled ] && active="$active $u"
done
# shellcheck disable=SC2086 # word splitting is the point
set -- $active
[ "$#" -eq 1 ] && exit 0
if [ "$#" -gt 1 ]; then
  echo "several firewall tools are enabled:$active; keep one by hand" >&2
  exit 1
fi
# sshd -T needs /run/sshd, which only exists once ssh.service has run (ssh.socket on 24.04 and later).
if command -v sshd >/dev/null 2>&1; then
  [ -d /run/sshd ] || mkdir -p -m 0755 /run/sshd
  ports=$(sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }')
  if [ -z "$ports" ]; then
    echo 'cannot read the SSH ports with sshd -T; ufw left disabled' >&2
    exit 1
  fi
fi
if ! command -v ufw >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=300 install -y -q ufw >/dev/null || exit 1
fi
for f in /etc/ufw/ufw.conf /etc/ufw/user.rules /etc/ufw/user6.rules; do cb_backup "$f"; done
# Allow every port sshd listens on before turning the firewall on.
for p in $ports; do
  ufw allow "$p/tcp" comment 'SSH (CIRSEC Baselines)' >/dev/null || exit 1
done
ufw --force enable

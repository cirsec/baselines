# CB-DEB-FS-003: mount /tmp as a tmpfs with nodev, nosuid and noexec through systemd's tmp.mount.
if awk '$1 !~ /^#/ && $2 == "/tmp"' /etc/fstab | grep -q .; then
  echo "/tmp is defined in /etc/fstab: add nodev,nosuid,noexec to its options by hand" >&2
  exit 1
fi
if [ -L /tmp ]; then
  echo "/tmp is a symbolic link, tmp.mount does not apply" >&2
  exit 1
fi

# Debian 12 ships tmp.mount as an example in /usr/share/systemd, Debian 13 as an active unit.
if ! systemctl cat tmp.mount >/dev/null 2>&1; then
  [ -f /usr/share/systemd/tmp.mount ] || { echo "no tmp.mount unit available" >&2; exit 1; }
  cb_backup /etc/systemd/system/tmp.mount
  cp /usr/share/systemd/tmp.mount /etc/systemd/system/tmp.mount
fi

f=/etc/systemd/system/tmp.mount.d/60-cirsec.conf
cb_backup "$f"
mkdir -p /etc/systemd/system/tmp.mount.d
printf '%s\n' '# Written by CIRSEC Baselines CB-DEB-FS-003' '[Mount]' \
  'Options=mode=1777,strictatime,nosuid,nodev,noexec,size=50%%,nr_inodes=1m' >"$f"
chmod 644 "$f"
systemctl daemon-reload
[ "$(systemctl is-enabled tmp.mount 2>/dev/null)" = disabled ] && systemctl enable tmp.mount

# Mounting a new tmpfs over a live /tmp would hide files in use: only remount an existing tmpfs.
if [ "$(findmnt -kn -o FSTYPE --mountpoint /tmp | tail -n 1)" = tmpfs ]; then
  mount -o remount,nodev,nosuid,noexec /tmp
else
  echo "/tmp becomes a tmpfs at the next reboot"
fi

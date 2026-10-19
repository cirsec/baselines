# CB-UBU-BOOT-016: set kernel.apparmor_restrict_unprivileged_userns = 1 for good.
# The usual workaround puts "= 0" in a file such as /etc/sysctl.d/99-userns.conf, which sorts after
# 60-cirsec.conf and would win at the next boot: such assignments are commented out (with a backup).
k=kernel.apparmor_restrict_unprivileged_userns
re='^[[:space:]]*kernel[./]apparmor_restrict_unprivileged_userns[[:space:]]*='
c=/etc/sysctl.d/60-cirsec.conf
for f in /etc/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf; do
  [ -f "$f" ] && [ "$f" != "$c" ] || continue
  grep -Eq "$re" "$f" || continue
  cb_backup "$f"
  sed -i --follow-symlinks -E "s|$re|# Disabled by CIRSEC Baselines CB-UBU-BOOT-016: &|" "$f"
done
cb_backup "$c"
touch "$c"
sed -i '/^[[:space:]]*kernel\.apparmor_restrict_unprivileged_userns[[:space:]]*=/d' "$c"
printf '%s = 1\n' "$k" >>"$c"
sysctl -q -w "$k=1"

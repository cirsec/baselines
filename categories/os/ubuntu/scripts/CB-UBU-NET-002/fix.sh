# CB-UBU-NET-002: keep unused network protocol modules from loading, unload the loaded ones.
f=/etc/modprobe.d/60-cirsec-net.conf
cb_backup "$f"
{
  echo '# Written by CIRSEC Baselines CB-UBU-NET-002'
  for m in $CB_NET_MODULES; do
    printf 'install %s /bin/false\nblacklist %s\n' "$m" "$m"
  done
} >"$f"
chmod 644 "$f"
for m in $CB_NET_MODULES; do
  if grep -q "^$m " /proc/modules && ! modprobe -r "$m"; then
    echo "$m is in use and could not be unloaded, reboot to finish" >&2
    exit 1
  fi
done
exit 0

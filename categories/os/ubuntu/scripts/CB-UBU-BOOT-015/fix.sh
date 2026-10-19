# CB-UBU-BOOT-015: turn off apport and whoopsie. Idempotent.
f=/etc/default/apport
if [ -f "$f" ]; then
  if ! grep -Eq '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*0[[:space:]]*$' "$f" ||
    grep -Eq '^[[:space:]]*enabled[[:space:]]*=[[:space:]]*[^0[:space:]]' "$f"; then
    cb_backup "$f"
    if grep -Eq '^[[:space:]]*enabled[[:space:]]*=' "$f"; then
      sed -i -E 's/^[[:space:]]*enabled[[:space:]]*=.*/enabled=0/' "$f"
    else
      printf '%s\n' 'enabled=0' >>"$f"
    fi
  fi
fi
# Stop and mask every crash reporting unit that exists. Stopping apport puts back
# kernel.core_pattern = core and fs.suid_dumpable = 0.
for u in apport-autoreport.timer apport-autoreport.path apport-forward.socket whoopsie.path whoopsie.service apport.service; do
  e=$(systemctl is-enabled "$u" 2>/dev/null)
  case $e in "" | not-found) continue ;; esac
  systemctl stop "$u" || exit 1
  [ "$e" = masked ] || systemctl mask "$u" || exit 1
done
case $(cat /proc/sys/kernel/core_pattern) in
  "|/usr/share/apport/"*) printf 'core\n' >/proc/sys/kernel/core_pattern ;;
esac

# CB-DEB-FS-004: mount /dev/shm with nodev, nosuid and noexec, at once and at every boot.
f=/etc/fstab
cb_backup "$f"
if awk '$1 !~ /^#/ && $2 == "/dev/shm"' "$f" | grep -q .; then
  # Add the missing options to the existing line, leave every other line untouched.
  awk '$1 !~ /^#/ && $2 == "/dev/shm" {
         n = split("nodev nosuid noexec", w, " ")
         for (i = 1; i <= n; i++) if (index("," $4 ",", "," w[i] ",") == 0) $4 = $4 "," w[i]
       }
       { print }' "$f" >"$f.cirsec.tmp" || { rm -f "$f.cirsec.tmp"; exit 1; }
  cat "$f.cirsec.tmp" >"$f"
  rm -f "$f.cirsec.tmp"
else
  printf 'tmpfs\t/dev/shm\ttmpfs\tdefaults,nodev,nosuid,noexec\t0\t0\n' >>"$f"
fi
systemctl daemon-reload
mount -o remount,nodev,nosuid,noexec /dev/shm

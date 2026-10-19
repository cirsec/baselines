# CB-UBU-BOOT-017: raise fs.protected_fifos / fs.protected_regular to CB_PROTECTION_LEVEL.
# Ubuntu sets both keys in /usr/lib/sysctl.d/99-protect-links.conf (protect-links.conf on 20.04),
# which sort after 60-cirsec.conf: the value goes in a file that sorts after both. Never lowers a value.
f=/etc/sysctl.d/zz-cirsec.conf
for k in fs.protected_fifos fs.protected_regular; do
  cur=$(sysctl -n "$k") || exit 1
  [ "$cur" -ge "$CB_PROTECTION_LEVEL" ] && continue
  cb_backup "$f"
  touch "$f"
  sed -i "/^[[:space:]]*$(printf '%s' "$k" | sed 's/\./\\./g')[[:space:]]*=/d" "$f"
  printf '%s = %s\n' "$k" "$CB_PROTECTION_LEVEL" >>"$f"
  sysctl -q -w "$k=$CB_PROTECTION_LEVEL" || exit 1
done

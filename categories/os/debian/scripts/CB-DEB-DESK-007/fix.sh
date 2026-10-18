# Add "auth required pam_succeed_if.so user != root quiet_success" before the first auth line of
# each display manager PAM service that lacks a root refusal.
re='^[[:space:]]*auth[[:space:]]+(required|requisite|\[[^]]*default=(bad|die)[^]]*\])[[:space:]]+pam_succeed_if\.so[[:space:]].*user[[:space:]]*!=[[:space:]]*root'
line='auth	required	pam_succeed_if.so user != root quiet_success'
for f in /etc/pam.d/gdm-password /etc/pam.d/gdm-fingerprint /etc/pam.d/gdm-smartcard \
  /etc/pam.d/lightdm /etc/pam.d/sddm; do
  [ -f "$f" ] || continue
  grep -Eq "$re" "$f" && continue
  grep -Eq '^[[:space:]]*(auth[[:space:]]|@include[[:space:]]+common-auth)' "$f" || {
    echo "$f has no auth line, left unchanged" >&2
    continue
  }
  cb_backup "$f"
  L=$line awk '!done && /^[ \t]*(auth[ \t]|@include[ \t]+common-auth)/ { print ENVIRON["L"]; done = 1 } { print }' \
    "$f" >"$f.cirsec-tmp" && cat "$f.cirsec-tmp" >"$f"
  rc=$?
  rm -f "$f.cirsec-tmp"
  [ "$rc" -eq 0 ] || exit 1
  echo "added root refusal to $f"
done

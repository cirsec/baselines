#!/bin/sh
# CB-UBU-AUTH-002 / scripts - stop the dynamic MOTD scripts that print the OS version or the kernel release.
# The mode is recorded with dpkg-statoverride so package upgrades keep it. Idempotent.
# SPDX-License-Identifier: Apache-2.0
set -eu
d=/etc/update-motd.d
[ -d "$d" ] || exit 0
v=$(. /etc/os-release && printf '%s' "$VERSION_ID")
k=$(uname -r)
for f in "$d"/*; do
  [ -f "$f" ] && [ -x "$f" ] || continue
  timeout 60 "$f" 2>/dev/null | grep -qF -e "$k" -e "Ubuntu $v" || continue
  if [ -L "$f" ]; then
    echo "$f is a symbolic link and prints system details: review it by hand" >&2
    exit 1
  fi
  dpkg-statoverride --list "$f" >/dev/null 2>&1 || dpkg-statoverride --update --add root root 0644 "$f"
  chmod 0644 "$f"
  echo "disabled $f"
done

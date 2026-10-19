#!/bin/sh
# CB-UBU-PKG-002 / https-ubuntu - switch the Ubuntu archive entries from HTTP to HTTPS.
# Only archive.ubuntu.com, security.ubuntu.com and ports.ubuntu.com are changed: Canonical serves
# them over HTTPS. Country mirrors and other hosts need a human. Hosts listed in
# CB_HTTP_ALLOWED_URIS are left alone. Idempotent, no-op when compliant.
# SPDX-License-Identifier: Apache-2.0
set -eu

files=
for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
  [ -f "$f" ] && files="$files $f"
done
[ -n "$files" ] || exit 0
# Mirror lists referenced as mirror+file: hold the real URIs.
# shellcheck disable=SC2086
for p in $(grep -hoE 'mirror\+file:/*[^[:space:]]+' $files | sed -E 's#^mirror\+file:/*#/#' | sort -u); do
  [ -f "$p" ] && files="$files $p"
done

for host in archive security ports; do
  for a in ${CB_HTTP_ALLOWED_URIS:-}; do
    case $a in *"://$host.ubuntu.com"*) continue 2 ;; esac
  done
  for f in $files; do
    grep -Eq "(^|[[:space:]+])http://$host\.ubuntu\.com/" "$f" || continue
    if [ ! -s /etc/ssl/certs/ca-certificates.crt ]; then
      echo "ca-certificates is not installed, APT could not check the HTTPS servers" >&2
      exit 1
    fi
    cb_backup "$f"
    sed -E -i "s#(^|[[:space:]+])http://$host\.ubuntu\.com/#\1https://$host.ubuntu.com/#g" "$f"
  done
done

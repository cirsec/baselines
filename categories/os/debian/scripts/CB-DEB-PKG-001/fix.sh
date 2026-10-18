#!/bin/sh
# CB-DEB-PKG-001 / signed-by-debian - add Signed-By to Debian archive entries that lack it.
# Only entries pointing to deb.debian.org, security.debian.org or ftp.<cc>.debian.org are changed:
# the key of any other repository must be chosen by a human. Idempotent, no-op when compliant.
# SPDX-License-Identifier: Apache-2.0
set -eu

k=/usr/share/keyrings/debian-archive-keyring.gpg
h='(https?|tor\+https?)://(deb|security|ftp\.[a-z]+)\.debian\.org/'

# One-line format: sources.list and *.list
for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
  [ -f "$f" ] || continue
  grep -E '^[[:space:]]*deb(-src)?[[:space:]]' "$f" | grep -v 'signed-by=' | grep -Eq "$h" || continue
  [ -e "$k" ] || { echo "$k is missing, install debian-archive-keyring" >&2; exit 1; }
  cb_backup "$f"
  sed -E -i "/signed-by=/! {
s#^([[:space:]]*deb(-src)?[[:space:]]+)\[([^]]*)\]([[:space:]]*$h)#\1[signed-by=$k \3]\4#
t
s#^([[:space:]]*deb(-src)?[[:space:]]+)($h)#\1[signed-by=$k] \3#
}" "$f"
done

# deb822 format: *.sources, one stanza per paragraph
for f in /etc/apt/sources.list.d/*.sources; do
  [ -f "$f" ] || continue
  t=$(mktemp)
  if awk -v k="$k" '
    function flush(  i) {
      for (i = 1; i <= n; i++) {
        print b[i]
        if (i == u && deb && !sig) { print "Signed-By: " k; c = 1 }
      }
      n = u = deb = sig = 0
    }
    /^[ \t]*$/ { flush(); print; next }
    { b[++n] = $0 }
    tolower($0) ~ /^signed-by:/ { sig = 1 }
    tolower($0) ~ /^uris:/ { u = n; if ($0 ~ /:\/\/(deb|security|ftp\.[a-z]+)\.debian\.org\//) deb = 1 }
    END { flush(); exit !c }' "$f" >"$t"; then
    [ -e "$k" ] || { rm -f "$t"; echo "$k is missing, install debian-archive-keyring" >&2; exit 1; }
    cb_backup "$f"
    cat "$t" >"$f"
  fi
  rm -f "$t"
done

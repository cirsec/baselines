#!/bin/sh
# CB-DEB-AUTH-011 / configure - enable pam_faillock through pam-auth-update profiles and set faillock.conf.
# Parameters: CB_DENY, CB_UNLOCK_TIME, CB_DENY_ROOT. Idempotent.
# SPDX-License-Identifier: Apache-2.0
set -eu
: "${CB_DENY:?}" "${CB_UNLOCK_TIME:?}" "${CB_DENY_ROOT:?}"

p=/usr/share/pam-configs
cat >"$p/cirsec_faillock_notify" <<'EOF'
Name: CIRSEC - count failed logins (pam_faillock preauth)
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth
Account-Type: Primary
Account:
	required	pam_faillock.so
EOF
cat >"$p/cirsec_faillock" <<'EOF'
Name: CIRSEC - lock after failed logins (pam_faillock authfail)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
EOF
for f in /etc/pam.d/common-auth /etc/pam.d/common-account; do cb_backup "$f"; done
DEBIAN_FRONTEND=noninteractive pam-auth-update --enable cirsec_faillock_notify cirsec_faillock

# Set one "key = value" (or a bare flag) in faillock.conf, replacing any active or commented line.
f=/etc/security/faillock.conf
cb_backup "$f"
set_kv() {
  sed -i "/^[[:space:]]*#*[[:space:]]*$1[[:space:]]*\(=.*\)\{0,1\}$/d" "$f"
  printf '%s\n' "$2" >>"$f"
}
set_kv deny "deny = $CB_DENY"
set_kv unlock_time "unlock_time = $CB_UNLOCK_TIME"
if [ "$CB_DENY_ROOT" = true ]; then set_kv even_deny_root even_deny_root; fi

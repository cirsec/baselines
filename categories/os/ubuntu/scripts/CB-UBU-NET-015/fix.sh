# CB-UBU-NET-015: set strong SSH server algorithms, keeping only those this OpenSSH version supports.
PATH="$PATH:/usr/sbin"
# sshd -T and -t need /run/sshd, which only exists once ssh.service has run (ssh.socket on 24.04 and later).
[ -d /run/sshd ] || mkdir -m 0755 /run/sshd
f=/etc/ssh/sshd_config.d/00-cirsec.conf
grep -Eqi '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config.d/\*\.conf' /etc/ssh/sshd_config || {
  echo '/etc/ssh/sshd_config does not include sshd_config.d/*.conf' >&2
  exit 1
}
# keep TYPE LIST: the algorithms of LIST that "ssh -Q TYPE" knows, comma separated, in LIST order.
keep() {
  sup=$(ssh -Q "$1") || return 1
  out=
  for a in $(printf '%s' "$2" | tr ',' ' '); do
    printf '%s\n' "$sup" | grep -Fxq -- "$a" && out="${out:+$out,}$a"
  done
  [ -n "$out" ] && printf '%s' "$out"
}
nokeep() {
  echo "ssh -Q $1 failed or knows none of the recommended algorithms" >&2
  exit 1
}
c=$(keep cipher chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr) || nokeep cipher
m=$(keep mac hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256) || nokeep mac
k=$(keep kex mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256) || nokeep kex
mkdir -p /etc/ssh/sshd_config.d
cb_backup "$f"
touch "$f"
chmod 600 "$f"
sed -i '/^[[:space:]]*\(ciphers\|macs\|kexalgorithms\)[[:space:]]/Id' "$f"
printf 'ciphers %s\nmacs %s\nkexalgorithms %s\n' "$c" "$m" "$k" >>"$f"
if ! sshd -t; then
  cb_restore "$f"
  echo 'sshd -t rejected the change, reverted' >&2
  exit 1
fi

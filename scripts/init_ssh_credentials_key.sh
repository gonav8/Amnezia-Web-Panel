#!/usr/bin/env bash
set -euo pipefail

key_file="${1:-./secrets/ssh-credentials.key}"
key_dir="$(dirname -- "$key_file")"

if [[ -e "$key_file" || -L "$key_file" ]]; then
    printf 'Refusing to overwrite existing key path: %s\n' "$key_file" >&2
    exit 1
fi

install -d -m 0700 -- "$key_dir"
command -v openssl >/dev/null 2>&1 || {
    echo 'OpenSSL is required to generate the key.' >&2
    exit 1
}

umask 077
tmp_file="$(mktemp "$key_dir/.ssh-credentials-key.XXXXXXXX")"
trap 'rm -f -- "$tmp_file"' EXIT
openssl rand -base64 32 >"$tmp_file"
chmod 0400 "$tmp_file"
mv -- "$tmp_file" "$key_file"
trap - EXIT
printf 'Created protected SSH credential key at %s\n' "$key_file"
printf 'Save a separate protected copy; it is not included in panel backups. Do not commit or share it.\n'

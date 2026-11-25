#!/bin/sh
# Creates random secrets in the secrets/ folder (excluded from git and from the Docker build context).
# Existing secrets are not overwritten: losing file_encryption_key means losing all documents.
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p secrets
chmod 700 secrets

generate() {
    name="$1"; bytes="$2"; mode="$3"
    if [ -s "secrets/$name" ]; then
        echo "secrets/$name already exists, left unchanged"
        return
    fi
    if [ "$mode" = key ]; then
        head -c "$bytes" /dev/urandom | base64 | tr -d '\n' > "secrets/$name"
    else
        head -c "$bytes" /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_' > "secrets/$name"
    fi
    # The files are mounted into containers where processes do not run as the file owner.
    chmod 644 "secrets/$name"
    echo "created secrets/$name"
}

generate postgres_password 32 password
generate app_db_password 32 password
generate file_encryption_key 32 key
generate backup_passphrase 32 password

echo "Keep a copy of file_encryption_key and backup_passphrase in a protected store (password vault, KMS)."

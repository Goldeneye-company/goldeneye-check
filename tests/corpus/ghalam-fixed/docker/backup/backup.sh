#!/bin/sh
# Periodic encrypted backup: a PostgreSQL dump and an archive of the document folder.
# Encryption: GnuPG, AES-256 with integrity protection; the passphrase is the Docker secret backup_passphrase.
# Restoring is described in the README (section "Backups").
set -eu
set -o pipefail

INTERVAL="${BACKUP_INTERVAL_SECONDS:-86400}"
KEEP_DAYS="${BACKUP_RETENTION_DAYS:-14}"
PASSFILE=/run/secrets/backup_passphrase
export PGPASSWORD="$(cat /run/secrets/postgres_password)"
export GNUPGHOME=/tmp/gnupg
mkdir -p "$GNUPGHOME" && chmod 700 "$GNUPGHOME"
umask 077

encrypt() {
    gpg --batch --yes --quiet --pinentry-mode loopback --passphrase-file "$PASSFILE" \
        --symmetric --cipher-algo AES256 --s2k-digest-algo SHA512 --output "$1"
}

while true; do
    TS="$(date -u +%Y%m%dT%H%M%SZ)"
    pg_dump --host db --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --format custom \
        | encrypt "/backups/db-$TS.dump.gpg"
    tar -C /data -cf - uploads | encrypt "/backups/files-$TS.tar.gpg"
    find /backups -name '*.gpg' -type f -mtime +"$KEEP_DAYS" -delete
    echo "$(date -u +%FT%TZ) backup $TS completed"
    sleep "$INTERVAL"
done

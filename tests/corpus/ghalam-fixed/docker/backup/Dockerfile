# Backups of the database and the encrypted documents (ISO 27002: 8.13).
FROM postgres:17-alpine
RUN apk add --no-cache gnupg
COPY backup.sh /usr/local/bin/ghalam-backup.sh
RUN chmod 0755 /usr/local/bin/ghalam-backup.sh
ENTRYPOINT ["/usr/local/bin/ghalam-backup.sh"]

#!/bin/sh
# Run by the postgres image once, when an empty database volume is initialised.
# Creates the schema owner role and the application role with minimal rights (ISO 27002: 8.2, 8.3).
set -e

APP_DB_PASSWORD="$(cat /run/secrets/app_db_password)"

psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" \
     --dbname "$POSTGRES_DB" \
     -v db_name="$POSTGRES_DB" \
     -v app_user="${APP_DB_USER:-ghalam_app}" \
     -v app_password="$APP_DB_PASSWORD" \
     -f /docker-entrypoint-initdb.d/schema/schema.sql

# GHALAM: secure document transfer portal

PHP 8.3, PostgreSQL 17, Docker Compose. An employee uploads a document and creates
a personal link with a password, an expiry time and a download limit.
The recipient does not need an account.

## Features

- employee sign-in with a password and a one-time code (TOTP, MFA);
- "administrator" and "employee" roles: an employee sees only their own documents;
- upload of PDF, PNG, JPG and TXT up to 100 MB with an antivirus check (ClamAV);
- every document encrypted with its own key (XChaCha20-Poly1305) and an integrity check (SHA-256);
- a link (192-bit token) and a separate password (about 79 bits), sent through different channels;
- download limit, link lifetime, revocation, automatic lock after 20 wrong passwords;
- an audit log of all actions, protected from changes;
- retention periods for documents and logs, a daily encrypted backup;
- HTTPS through Caddy, HSTS, CSP and no caching.

## Architecture

| Container | Purpose | Network |
| --- | --- | --- |
| `proxy` | Caddy: TLS, HSTS, HTTP→HTTPS redirect | ports 80/443 published |
| `app` | PHP + Apache as `www-data`, read-only file system | internal |
| `db` | PostgreSQL 17, the port is not published | internal, no internet |
| `clamav` | antivirus, updates its databases from the internet | internal + access for updates |
| `maintenance` | applies the retention periods once an hour | internal |
| `backup` | makes an encrypted backup of the database and documents once a day | internal |

The application connects to the database as the `ghalam_app` role, which has only the read and write
rights it needs, no DDL. For this role the audit log is append-only.

## First start

Below is a start for a check on your own computer. Deployment on an Ubuntu 24.04 server
in an internal network is described in DEPLOY.md.

1. Create the secrets (once):

   ```powershell
   .\scripts\init-secrets.ps1
   ```

   On Linux and macOS: `sh scripts/init-secrets.sh`. The secrets appear in the `secrets/` folder.
   This folder is excluded from git and from the image build.
   **Keep a copy of `file_encryption_key` and `backup_passphrase` in a password vault:
   without the key the documents and backups cannot be decrypted.**

2. If needed, create `.env` from `.env.example`. For a check on your own computer
   the default values are enough (`https://localhost`).

3. Start:

   ```powershell
   docker compose up -d --build
   ```

   On the first start ClamAV downloads its antivirus databases, which takes a few minutes.
   Until it is ready, document uploads are rejected. This is intended: `CLAMAV_REQUIRED=true`.

4. Create the first administrator:

   ```powershell
   docker compose run --rm app php /var/www/bin/create-user.php admin@company.kz admin
   ```

   The command prints a temporary password once.

5. Open <https://localhost>. For `localhost` Caddy issues a certificate from its internal CA,
   and the browser shows a warning. For a production domain set in `.env`
   `SITE_ADDRESS=docs.example.kz` and `APP_BASE_URL=https://docs.example.kz`:
   a Let's Encrypt certificate is obtained automatically.

6. On the first sign-in set up the authenticator app and change the temporary password.

The administrator creates the other employees in the "Users" section.

## Moving from the training version

The database schema, the PostgreSQL accounts and the file storage format have changed
(documents are now encrypted). Delete the old test data:

```powershell
docker compose down -v
```

The command irreversibly deletes the volumes with the test database and files. Then follow the steps in "First start".

## How to check

1. Sign in as the administrator, set up MFA, change the password.
2. Upload a test file. Check that the log has the event "Document uploaded".
3. Create a link. The link and the password are shown in separate blocks and only once.
4. Open the link in a private window. The file name is not shown before the password.
5. Enter a wrong password 5 times: the sixth attempt is blocked for 15 minutes.
6. Download the document, then check the limit, the link revocation and the log.
7. Check the antivirus with the EICAR test file (the string from eicar.org saved as `.txt`).

## Backups

The `backup` service saves two files to `BACKUP_DIR` (by default `./backups`) every
`BACKUP_INTERVAL_SECONDS` (by default once a day):

- `db-<time>.dump.gpg`: the PostgreSQL dump;
- `files-<time>.tar.gpg`: the document folder (the documents inside are encrypted too).

Copies older than `BACKUP_RETENTION_DAYS` are deleted. Moving them to another server and
step-by-step restoring are described in DEPLOY.md, section 10. Restoring needs
`backup_passphrase` and the same `file_encryption_key`.

## Keys and secrets

| Secret | Purpose | If lost |
| --- | --- | --- |
| `file_encryption_key` | master key for documents and MFA secrets | documents cannot be decrypted |
| `backup_passphrase` | backup encryption | backups cannot be decrypted |
| `app_db_password` | application sign-in to the database | change it in the database and in the file |
| `postgres_password` | database superuser (initialisation, backup) | change it in the database and in the file |

On a Linux server the secret files are readable by the containers (mode 644), but the `secrets/` folder is closed (700).
For production an external secret store (Vault, KMS) is recommended.

## Settings

All parameters are listed in `.env.example`. The main ones:

- `DOCUMENT_RETENTION_DAYS`: days after all links of a document have ended before it is deleted (30);
- `AUDIT_RETENTION_DAYS`: how long the audit log is kept (365);
- `IP_RETENTION_DAYS`: days after which IP addresses in the log are anonymised (90);
- `STORAGE_QUOTA_MB`: quota per employee (2048).

Audit events are also written to the container log as `AUDIT {...}` lines for a SIEM:

```powershell
docker compose logs app | Select-String AUDIT
```

## Updates

The base images are given by minor version (`php:8.3-apache-bookworm`, `postgres:17-alpine`,
`caddy:2-alpine`, `clamav/clamav:stable`). For reproducible builds pin them by digest
(`image@sha256:...`) and update them through Dependabot or Renovate. Rebuild the images monthly
and check them with a vulnerability scanner, for example `trivy image`.

## Structure

- `public/index.php`: routing;
- `public/app.js`, `public/style.css`: the interface without inline scripts;
- `src/config.php`: configuration and secret checks at start;
- `src/bootstrap.php`: initialisation, error handling, database connection;
- `src/security.php`: headers, sessions, CSRF, passwords, sign-in attempt limits;
- `src/crypto.php`: encryption of documents and secrets;
- `src/totp.php`: one-time MFA codes;
- `src/audit.php`: the audit log;
- `src/antivirus.php`: the ClamAV check;
- `src/routes/`: page handlers;
- `bin/create-user.php`, `bin/maintenance.php`: administration commands;
- `db/init/`: database roles and schema, run when the volume is created;
- `docker/`: Apache, PHP, Caddy, ClamAV and backup configuration;
- `scripts/init-secrets.*`: secret generation.

## Limitations

- No QR code is shown for MFA. The secret is entered into the authenticator app by hand or with the `otpauth://` link.
- Before encryption the temporary upload file lies in `/var/www/data/tmp` and PHP deletes it at the end of the request.
- Organisational measures of ISO/IEC 27001 (policies, training, incident management) are not provided by the code.

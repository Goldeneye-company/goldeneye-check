# GHALAM — secure document delivery portal

A learning MVP on PHP 8.3 and PostgreSQL. One employee uploads a document
and creates a personal link with a password, an expiry time and a download limit.
The recipient does not need an account.

## What works

- a private dashboard for one employee;
- upload of PDF, PNG, JPG and TXT up to 100 MB;
- a long random link and a separate random password;
- a maximum number of downloads;
- a link lifetime;
- access revocation;
- lockout after 5 wrong passwords in 15 minutes from one IP;
- a log of downloads and errors;
- PostgreSQL instead of SQLite;
- a minimal GHALAM interface.

## What Docker runs

`docker compose` runs two containers:

1. `app` — PHP 8.3 and Apache;
2. `db` — PostgreSQL 17.

Documents and the database live in separate persistent Docker volumes, so a normal
stop of the containers does not delete data.

## First run

Open PowerShell in the `document-portal` folder:

```powershell
docker compose up --build
```

Open <http://localhost:8080>.

Demo sign-in:

```text
Email: admin@example.com
Password: Admin123!
```

Stop: `Ctrl+C`. Run again:

```powershell
docker compose up
```

Container status:

```powershell
docker compose ps
```

Application and database logs:

```powershell
docker compose logs app db
```

## Settings for a local check

Without `.env` Docker uses the demo values from `docker-compose.yml`.
To try your own passwords:

```powershell
Copy-Item .env.example .env
```

Then edit `.env` and run:

```powershell
docker compose up --build
```

The `.env` file is excluded in `.gitignore` and will not get to GitHub.

Note: the employee is created only on the first start of a new database. If the database
already exists, changing `ADMIN_PASSWORD` alone does not change the existing password.

## How to check

1. Sign in as the employee.
2. Upload a test file up to 100 MB.
3. Set the recipient, the lifetime and the number of downloads.
4. Copy the link and the password.
5. Open the link in a private window.
6. Try a wrong and the right password.
7. Check the limit, the revocation and the log.

## Structure

- `public/index.php` — routes and business logic;
- `src/bootstrap.php` — session, PostgreSQL, tables and functions;
- `public/style.css` — look and feel;
- `php/uploads.ini` — PHP upload limits of 100 MB;
- `Dockerfile` — PHP/Apache build;
- `docker-compose.yml` — the application, PostgreSQL and persistent volumes;
- `.env.example` — a configuration example without real secrets;
- `.gitignore` — protection of local secrets and service files.

## Important limitations

This is still a demo version. Hosting it on the internet will require
HTTPS, production secrets, backups of PostgreSQL and documents,
protection of the employee sign-in and a reverse proxy. The next big step is
Nextcloud instead of the local documents folder.

## Full reset of test data

The command below irreversibly deletes the test database and the uploaded files:

```powershell
docker compose down -v
```

Use it only in a test environment.

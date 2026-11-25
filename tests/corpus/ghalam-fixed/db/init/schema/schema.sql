-- GHALAM schema. Run from 01-init.sh when the database volume is created.
-- ghalam_owner  - owner of the objects, cannot sign in;
-- :app_user     - application role: only the DML rights it needs, no DDL, no UPDATE/DELETE on the audit log.

\set ON_ERROR_STOP on

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;

CREATE ROLE ghalam_owner NOLOGIN;
CREATE ROLE :"app_user" LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;

GRANT CONNECT ON DATABASE :"db_name" TO :"app_user";
GRANT USAGE, CREATE ON SCHEMA public TO ghalam_owner;
GRANT USAGE ON SCHEMA public TO :"app_user";

SET ROLE ghalam_owner;

CREATE TABLE employees (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'employee' CHECK (role IN ('admin', 'employee')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
    totp_secret_enc TEXT,
    totp_last_step BIGINT,
    password_changed_at TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE documents (
    id BIGSERIAL PRIMARY KEY,
    original_name VARCHAR(255) NOT NULL,
    stored_name CHAR(48) NOT NULL UNIQUE,
    mime_type VARCHAR(100) NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes > 0),
    sha256 CHAR(64) NOT NULL,
    wrapped_key TEXT NOT NULL,
    antivirus_status VARCHAR(20) NOT NULL,
    uploaded_by BIGINT NOT NULL REFERENCES employees(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX documents_uploaded_by_idx ON documents (uploaded_by);

CREATE TABLE download_links (
    id BIGSERIAL PRIMARY KEY,
    document_id BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    recipient_label VARCHAR(100),
    max_downloads INTEGER NOT NULL CHECK (max_downloads BETWEEN 1 AND 100),
    download_count INTEGER NOT NULL DEFAULT 0 CHECK (download_count >= 0),
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL,
    created_by BIGINT NOT NULL REFERENCES employees(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    revoked_by BIGINT REFERENCES employees(id),
    revoke_reason VARCHAR(40)
);
CREATE INDEX download_links_document_idx ON download_links (document_id);

CREATE TABLE login_attempts (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    stage VARCHAR(10) NOT NULL CHECK (stage IN ('password', 'mfa')),
    success BOOLEAN NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX login_attempts_email_idx ON login_attempts (email, created_at);
CREATE INDEX login_attempts_ip_idx ON login_attempts (ip_address, created_at);

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    actor_type VARCHAR(20) NOT NULL CHECK (actor_type IN ('employee', 'recipient', 'system', 'anonymous')),
    actor_id BIGINT,
    actor_label VARCHAR(255),
    action VARCHAR(60) NOT NULL,
    object_type VARCHAR(30),
    object_id BIGINT,
    ip_address VARCHAR(45),
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX audit_log_object_idx ON audit_log (object_type, object_id, action, created_at);
CREATE INDEX audit_log_actor_idx ON audit_log (actor_type, actor_id);
CREATE INDEX audit_log_created_idx ON audit_log (created_at);

-- Append-only log: changes and deletions are possible only inside the retention procedure.
CREATE FUNCTION audit_log_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF current_setting('ghalam.retention', true) IS DISTINCT FROM 'on' THEN
        RAISE EXCEPTION 'audit_log is append-only';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER audit_log_append_only
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_guard();

-- Retention of the log and personal data (ISO 27002: 5.33, 5.34). Runs with the owner's rights.
CREATE FUNCTION ghalam_apply_retention(p_audit_days INTEGER, p_ip_days INTEGER, p_attempt_days INTEGER)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
    IF p_audit_days < 30 OR p_ip_days < 1 OR p_attempt_days < 1 THEN
        RAISE EXCEPTION 'retention period is too short';
    END IF;
    PERFORM set_config('ghalam.retention', 'on', true);
    UPDATE audit_log SET ip_address = NULL
        WHERE ip_address IS NOT NULL AND created_at < CURRENT_TIMESTAMP - make_interval(days => p_ip_days);
    DELETE FROM audit_log WHERE created_at < CURRENT_TIMESTAMP - make_interval(days => p_audit_days);
    DELETE FROM login_attempts WHERE created_at < CURRENT_TIMESTAMP - make_interval(days => p_attempt_days);
    PERFORM set_config('ghalam.retention', 'off', true);
END;
$$;

REVOKE ALL ON FUNCTION ghalam_apply_retention(INTEGER, INTEGER, INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_log_guard() FROM PUBLIC;

RESET ROLE;

GRANT SELECT, INSERT, UPDATE ON employees TO :"app_user";
GRANT SELECT, INSERT, DELETE ON documents TO :"app_user";
GRANT SELECT, INSERT, UPDATE ON download_links TO :"app_user";
GRANT SELECT, INSERT ON login_attempts TO :"app_user";
GRANT SELECT, INSERT ON audit_log TO :"app_user";
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO :"app_user";
GRANT EXECUTE ON FUNCTION ghalam_apply_retention(INTEGER, INTEGER, INTEGER) TO :"app_user";

<?php
declare(strict_types=1);

/*
 * HTTP headers, sessions, CSRF, passwords and sign-in attempt limits.
 * ISO 27002: 8.5 (authentication), 8.12 (leakage), 8.26 (application requirements).
 */

/** Common passwords that must not be used (extend as needed). */
const COMMON_PASSWORDS = [
    'admin123!', 'password123', 'password1234', 'qwerty123456', '123456789012', 'administrator',
    'welcome12345', 'p@ssw0rd1234', 'changeme1234', 'letmein12345', 'iloveyou1234', 'qwertyuiop12',
];

function send_security_headers(): void
{
    header_remove('X-Powered-By');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
        . "connect-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    header('Cross-Origin-Opener-Policy: same-origin');
    header('Cross-Origin-Resource-Policy: same-origin');
    // Pages hold link passwords and document data: no caching at all (ISO 27002: 8.12).
    header('Cache-Control: no-store, max-age=0');
    header('Pragma: no-cache');
}

function client_ip(): string
{
    // REMOTE_ADDR already holds the client address: mod_remoteip sets it only for the trusted proxy.
    return substr((string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown'), 0, 45);
}

function start_session(): void
{
    $c = config();
    session_name($c['cookie_secure'] ? '__Host-ghalam' : 'ghalam');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $c['cookie_secure'],
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_start();

    $auth = $_SESSION['auth'] ?? null;
    if (!is_array($auth)) {
        return;
    }
    $now = time();
    $pendingExpired = $auth['stage'] === 'mfa' && $now - $auth['started'] > 300;
    $idleExpired = $now - $auth['last_activity'] > $c['session_idle_seconds'];
    $absoluteExpired = $now - $auth['started'] > $c['session_absolute_seconds'];
    if ($pendingExpired || $idleExpired || $absoluteExpired) {
        if ($auth['stage'] === 'full') {
            audit('auth.session_expired', [
                'actor_type' => 'employee',
                'actor_id' => (int) $auth['employee_id'],
                'details' => ['reason' => $absoluteExpired ? 'absolute' : 'idle'],
            ]);
        }
        end_session();
        flash_set('The session has timed out. Sign in again.', 'error');
        return;
    }
    $_SESSION['auth']['last_activity'] = $now;
}

function end_session(): void
{
    $_SESSION = [];
    session_regenerate_id(true);
}

function csrf_token(): string
{
    return $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
}

function require_post(): void
{
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
        header('Allow: POST');
        error_page(405, 'Method not allowed', 'This action is done only by submitting a form.');
    }
    require_csrf();
}

function require_csrf(): void
{
    if (!hash_equals($_SESSION['csrf'] ?? '', (string) ($_POST['csrf'] ?? ''))) {
        error_page(403, 'Session expired', 'Reload the page and repeat the action.');
    }
}

function password_algorithm(): string|int|null
{
    return defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
}

function hash_password(string $password): string
{
    return password_hash($password, password_algorithm());
}

/** @return list<string> */
function password_policy_errors(string $password, string $email): array
{
    $errors = [];
    $length = mb_strlen($password);
    if ($length < 12) {
        $errors[] = 'at least 12 characters long';
    }
    if ($length > 128) {
        $errors[] = 'at most 128 characters long';
    }
    $lower = mb_strtolower($password);
    if (in_array($lower, COMMON_PASSWORDS, true)) {
        $errors[] = 'not on the list of common passwords';
    }
    $local = mb_strtolower((string) strstr($email, '@', true));
    if ($local !== '' && mb_strlen($local) >= 3 && str_contains($lower, $local)) {
        $errors[] = 'free of the name from the email';
    }
    if (count(array_unique(mb_str_split($password))) < 6) {
        $errors[] = 'made of at least 6 different characters';
    }
    return $errors;
}

/** Serialises parallel sign-in attempts to one account until the end of the transaction. */
function lock_login_subject(string $email): void
{
    $stmt = db()->prepare('SELECT pg_advisory_xact_lock(hashtextextended(?, 0))');
    $stmt->execute(['login:' . $email]);
}

function login_is_locked(string $email, string $ip): bool
{
    $c = config();
    $stmt = db()->prepare("SELECT
            COUNT(*) FILTER (WHERE email = :email) AS by_email,
            COUNT(*) FILTER (WHERE ip_address = :ip) AS by_ip
        FROM login_attempts
        WHERE success = FALSE
          AND created_at > CURRENT_TIMESTAMP - make_interval(mins => :minutes)
          AND (email = :email2 OR ip_address = :ip2)");
    $stmt->execute([
        'email' => $email, 'ip' => $ip, 'minutes' => $c['login_lock_minutes'],
        'email2' => $email, 'ip2' => $ip,
    ]);
    $row = $stmt->fetch();
    return (int) $row['by_email'] >= $c['login_max_failures_per_account']
        || (int) $row['by_ip'] >= $c['login_max_failures_per_ip'];
}

function record_login_attempt(string $email, string $ip, string $stage, bool $success): void
{
    $stmt = db()->prepare('INSERT INTO login_attempts (email, ip_address, stage, success) VALUES (?, ?, ?, ' . ($success ? 'TRUE' : 'FALSE') . ')');
    $stmt->execute([$email, $ip, $stage]);
}

function load_employee(int $id): ?array
{
    $stmt = db()->prepare('SELECT id, email, role, is_active, must_change_password, totp_secret_enc, totp_last_step
        FROM employees WHERE id = ?');
    $stmt->execute([$id]);
    $row = $stmt->fetch();
    return $row ?: null;
}

/** The current employee after full authentication (password + MFA). Rights are re-read from the database on every request. */
function current_employee(): ?array
{
    $auth = $_SESSION['auth'] ?? null;
    if (!is_array($auth) || $auth['stage'] !== 'full') {
        return null;
    }
    $employee = load_employee((int) $auth['employee_id']);
    if ($employee === null || !$employee['is_active']) {
        end_session();
        return null;
    }
    return $employee;
}

function require_employee(bool $allowPendingPasswordChange = false): array
{
    $employee = current_employee();
    if ($employee === null) {
        redirect('/?page=login');
    }
    if ($employee['must_change_password'] && !$allowPendingPasswordChange) {
        redirect('/?page=change-password');
    }
    return $employee;
}

function require_admin(): array
{
    $employee = require_employee();
    if ($employee['role'] !== 'admin') {
        error_page(403, 'Access denied', 'This section is available only to the administrator.');
    }
    return $employee;
}

function is_admin(array $employee): bool
{
    return $employee['role'] === 'admin';
}

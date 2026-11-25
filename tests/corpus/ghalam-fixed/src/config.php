<?php
declare(strict_types=1);

/*
 * Application configuration.
 * Secrets are read from files (variable NAME_FILE, Docker secrets) or from the environment.
 * The application does not start when required values are missing or weak (ISO 27002: 5.17, 8.9).
 */

const DATA_DIR = '/var/www/data';
const UPLOAD_DIR = DATA_DIR . '/uploads';

/** Values that must not be used in production. */
const FORBIDDEN_SECRETS = ['', 'change_me', 'ghalam_demo_password', 'Admin123!', 'password', 'postgres'];

function env_value(string $name, ?string $default = null): ?string
{
    $file = getenv($name . '_FILE');
    if ($file !== false && $file !== '') {
        if (!is_readable($file)) {
            throw new RuntimeException("The secret file for {$name} is not readable");
        }
        return trim((string) file_get_contents($file));
    }
    $value = getenv($name);
    return ($value === false || $value === '') ? $default : $value;
}

function env_int(string $name, int $default, int $min, int $max): int
{
    $raw = env_value($name);
    if ($raw === null) {
        return $default;
    }
    $value = filter_var($raw, FILTER_VALIDATE_INT);
    if ($value === false || $value < $min || $value > $max) {
        throw new RuntimeException("{$name} must be an integer from {$min} to {$max}");
    }
    return $value;
}

function env_bool(string $name, bool $default): bool
{
    $raw = env_value($name);
    if ($raw === null) {
        return $default;
    }
    $value = filter_var($raw, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE);
    if ($value === null) {
        throw new RuntimeException("{$name} must be true or false");
    }
    return $value;
}

function config(): array
{
    static $config = null;
    if ($config !== null) {
        return $config;
    }

    $env = env_value('APP_ENV', 'production');
    if (!in_array($env, ['production', 'development'], true)) {
        throw new RuntimeException('APP_ENV must be production or development');
    }

    $baseUrl = rtrim((string) env_value('APP_BASE_URL', ''), '/');
    if ($baseUrl === '' || filter_var($baseUrl, FILTER_VALIDATE_URL) === false) {
        throw new RuntimeException('APP_BASE_URL is not set or invalid');
    }
    if ($env === 'production' && !str_starts_with($baseUrl, 'https://')) {
        throw new RuntimeException('In production APP_BASE_URL must start with https://');
    }

    $dbPassword = (string) env_value('DB_PASSWORD', '');
    if (in_array($dbPassword, FORBIDDEN_SECRETS, true) || strlen($dbPassword) < 16) {
        throw new RuntimeException('DB_PASSWORD is missing or too weak (at least 16 characters required)');
    }

    $fileKey = base64_decode((string) env_value('FILE_ENCRYPTION_KEY', ''), true);
    if ($fileKey === false || strlen($fileKey) !== SODIUM_CRYPTO_SECRETBOX_KEYBYTES) {
        throw new RuntimeException('FILE_ENCRYPTION_KEY must hold 32 bytes in base64');
    }

    $timezone = (string) env_value('APP_TIMEZONE', 'UTC');
    if (!in_array($timezone, DateTimeZone::listIdentifiers(), true)) {
        throw new RuntimeException('APP_TIMEZONE holds an unknown time zone');
    }

    $config = [
        'env' => $env,
        'base_url' => $baseUrl,
        'timezone' => $timezone,
        'cookie_secure' => env_bool('COOKIE_SECURE', $env === 'production'),

        'db_host' => (string) env_value('DB_HOST', 'db'),
        'db_port' => env_int('DB_PORT', 5432, 1, 65535),
        'db_name' => (string) env_value('DB_NAME', 'ghalam'),
        'db_user' => (string) env_value('DB_USER', 'ghalam_app'),
        'db_password' => $dbPassword,

        'file_key' => $fileKey,

        'clamav_enabled' => env_bool('CLAMAV_ENABLED', true),
        'clamav_required' => env_bool('CLAMAV_REQUIRED', true),
        'clamav_host' => (string) env_value('CLAMAV_HOST', 'clamav'),
        'clamav_port' => env_int('CLAMAV_PORT', 3310, 1, 65535),

        'max_file_bytes' => env_int('MAX_FILE_MB', 100, 1, 1024) * 1024 * 1024,
        'quota_bytes' => env_int('STORAGE_QUOTA_MB', 2048, 1, 1048576) * 1024 * 1024,
        'disk_reserve_bytes' => env_int('DISK_RESERVE_MB', 1024, 0, 1048576) * 1024 * 1024,

        'session_idle_seconds' => env_int('SESSION_IDLE_MINUTES', 15, 1, 240) * 60,
        'session_absolute_seconds' => env_int('SESSION_ABSOLUTE_HOURS', 8, 1, 24) * 3600,

        'login_max_failures_per_account' => env_int('LOGIN_MAX_FAILURES', 5, 3, 20),
        'login_max_failures_per_ip' => env_int('LOGIN_MAX_FAILURES_PER_IP', 20, 5, 200),
        'login_lock_minutes' => env_int('LOGIN_LOCK_MINUTES', 15, 1, 1440),

        'link_max_failures_per_ip' => env_int('LINK_MAX_FAILURES_PER_IP', 5, 3, 20),
        'link_max_failures_total' => env_int('LINK_MAX_FAILURES_TOTAL', 20, 5, 200),

        'document_retention_days' => env_int('DOCUMENT_RETENTION_DAYS', 30, 1, 3650),
        'audit_retention_days' => env_int('AUDIT_RETENTION_DAYS', 365, 30, 3650),
        'ip_retention_days' => env_int('IP_RETENTION_DAYS', 90, 1, 3650),
    ];

    return $config;
}

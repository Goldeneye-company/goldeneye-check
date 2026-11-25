<?php
declare(strict_types=1);

/*
 * Common initialisation for web requests and CLI scripts.
 * The database schema is created once by db/init (not on every request),
 * the administrator is created by bin/create-user.php (not automatically).
 */

require __DIR__ . '/config.php';
require __DIR__ . '/view.php';
require __DIR__ . '/audit.php';
require __DIR__ . '/crypto.php';
require __DIR__ . '/totp.php';
require __DIR__ . '/security.php';
require __DIR__ . '/antivirus.php';

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    throw new ErrorException($message, 0, $severity, $file, $line);
});

// The user sees only an incident code, the details go to the server log (ISO 27002: 8.28).
set_exception_handler(static function (Throwable $exception): void {
    $incident = bin2hex(random_bytes(6));
    error_log(sprintf(
        '[incident %s] %s: %s in %s:%d%s%s',
        $incident,
        get_class($exception),
        $exception->getMessage(),
        $exception->getFile(),
        $exception->getLine(),
        PHP_EOL,
        $exception->getTraceAsString()
    ));
    if (PHP_SAPI === 'cli') {
        fwrite(STDERR, 'Error: ' . $exception->getMessage() . PHP_EOL);
        exit(1);
    }
    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: text/html; charset=utf-8');
        header('Cache-Control: no-store');
    }
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Error · GHALAM</title>'
        . '<link rel="stylesheet" href="/style.css"></head><body><main class="public-main">'
        . '<section class="download-card"><h1>Internal error</h1>'
        . '<p class="muted">Try again later. Incident code: <code>' . $incident . '</code></p>'
        . '</section></main></body></html>';
    exit;
});

date_default_timezone_set('UTC');

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $c = config();
    $dsn = sprintf('pgsql:host=%s;port=%d;dbname=%s', $c['db_host'], $c['db_port'], $c['db_name']);
    $last = null;
    for ($attempt = 1; $attempt <= 5; $attempt++) {
        try {
            $pdo = new PDO($dsn, $c['db_user'], $c['db_password'], [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
            $pdo->exec("SET TIME ZONE 'UTC'");
            return $pdo;
        } catch (PDOException $exception) {
            $last = $exception;
            if ($attempt < 5) {
                sleep(1);
            }
        }
    }
    throw new RuntimeException('The database is unavailable', 0, $last);
}

if (PHP_SAPI !== 'cli') {
    config(); // configuration errors are detected before the request is handled
    send_security_headers();
    start_session();
}

<?php
declare(strict_types=1);

const DATA_DIR = '/var/www/data';
const MAX_FILE_SIZE = 100 * 1024 * 1024;

session_name('ghalam_documents');
session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'secure' => false]);
session_start();

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');

if (!is_dir(DATA_DIR . '/uploads')) mkdir(DATA_DIR . '/uploads', 0700, true);

$dbHost = getenv('DB_HOST') ?: 'db';
$dbPort = getenv('DB_PORT') ?: '5432';
$dbName = getenv('DB_NAME') ?: 'ghalam';
$dbUser = getenv('DB_USER') ?: 'ghalam';
$dbPassword = getenv('DB_PASSWORD') ?: 'change_me';

// On the first start PostgreSQL may take a little longer than PHP.
$db = null;
for ($attempt = 1; $attempt <= 10; $attempt++) {
    try {
        $db = new PDO("pgsql:host={$dbHost};port={$dbPort};dbname={$dbName}", $dbUser, $dbPassword);
        break;
    } catch (PDOException $exception) {
        if ($attempt === 10) throw $exception;
        sleep(2);
    }
}
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
$db->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS employees (
 id BIGSERIAL PRIMARY KEY, email VARCHAR(255) NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS documents (
 id BIGSERIAL PRIMARY KEY, original_name TEXT NOT NULL,
 stored_name TEXT NOT NULL UNIQUE, mime_type VARCHAR(255) NOT NULL, size_bytes BIGINT NOT NULL,
 uploaded_by BIGINT NOT NULL REFERENCES employees(id), created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS download_links (
 id BIGSERIAL PRIMARY KEY, document_id BIGINT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
 public_token TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, recipient_label TEXT,
 max_downloads INTEGER NOT NULL CHECK (max_downloads > 0), download_count INTEGER NOT NULL DEFAULT 0,
 expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS download_logs (
 id BIGSERIAL PRIMARY KEY, link_id BIGINT NOT NULL REFERENCES download_links(id) ON DELETE CASCADE,
 ip_address VARCHAR(45) NOT NULL, result VARCHAR(40) NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
SQL);

$adminEmail = strtolower(getenv('ADMIN_EMAIL') ?: 'admin@example.com');
$adminPassword = getenv('ADMIN_PASSWORD') ?: 'Admin123!';
$seed = $db->prepare('INSERT INTO employees (email, password_hash) VALUES (?, ?) ON CONFLICT (email) DO NOTHING');
$seed->execute([$adminEmail, password_hash($adminPassword, PASSWORD_DEFAULT)]);

function e(string $value): string { return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function csrfToken(): string { return $_SESSION['csrf'] ??= bin2hex(random_bytes(32)); }
function requireCsrf(): void {
    if (!hash_equals($_SESSION['csrf'] ?? '', (string) ($_POST['csrf'] ?? ''))) {
        http_response_code(419); exit('Session expired. Reload the page.');
    }
}
function employee(): ?array { return $_SESSION['employee'] ?? null; }
function requireEmployee(): array {
    $current = employee();
    if (!$current) redirect('/?page=login');
    return $current;
}
function redirect(string $location): never { header('Location: ' . $location); exit; }
function renderHeader(string $title, bool $public = false): void {
    $current = employee();
    echo '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>' . e($title) . ' · GHALAM</title><link rel="stylesheet" href="/style.css"></head><body><div class="stars"></div>';
    echo '<header><a class="brand" href="' . ($current ? '/?page=dashboard' : '/') . '"><span class="planet"></span>GHALAM</a>';
    if ($current && !$public) echo '<nav><span>' . e($current['email']) . '</span><a href="/?page=logout">Sign out</a></nav>';
    echo '</header><main class="' . ($public ? 'public-main' : '') . '">';
}
function renderFooter(): void { echo '</main><footer>Secure document delivery · GHALAM</footer></body></html>'; }
function addLog(PDO $db, int $linkId, string $result): void {
    $stmt = $db->prepare('INSERT INTO download_logs (link_id, ip_address, result) VALUES (?, ?, ?)');
    $stmt->execute([$linkId, $_SERVER['REMOTE_ADDR'] ?? 'unknown', $result]);
}
function formatBytes(int $bytes): string {
    return $bytes >= 1048576 ? round($bytes / 1048576, 1) . ' MB' : round($bytes / 1024, 1) . ' KB';
}

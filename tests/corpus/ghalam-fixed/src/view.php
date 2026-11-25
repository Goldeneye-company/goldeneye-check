<?php
declare(strict_types=1);

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $location): never
{
    // Only relative addresses inside the application: no open redirect.
    if (!str_starts_with($location, '/') || str_starts_with($location, '//')) {
        $location = '/';
    }
    header('Location: ' . $location, true, 303);
    exit;
}

function format_dt(?string $timestamp): string
{
    if ($timestamp === null || $timestamp === '') {
        return '—';
    }
    $dt = new DateTimeImmutable($timestamp);
    return $dt->setTimezone(new DateTimeZone(config()['timezone']))->format('d.m.Y H:i');
}

function format_bytes(int $bytes): string
{
    return $bytes >= 1048576 ? round($bytes / 1048576, 1) . ' MB' : round($bytes / 1024, 1) . ' KB';
}

function flash_set(string $message, string $kind = 'notice'): void
{
    $_SESSION['flash'] = ['message' => $message, 'kind' => $kind === 'error' ? 'error' : 'notice'];
}

function flash_render(): void
{
    $flash = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    if (is_array($flash)) {
        echo '<p class="alert ' . e($flash['kind']) . '">' . e($flash['message']) . '</p>';
    }
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf" value="' . e(csrf_token()) . '">';
}

function render_header(string $title, ?array $employee = null, bool $public = false): void
{
    echo '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        . '<meta name="viewport" content="width=device-width,initial-scale=1">'
        . '<meta name="referrer" content="no-referrer">'
        . '<title>' . e($title) . ' · GHALAM</title>'
        . '<link rel="stylesheet" href="/style.css"><script src="/app.js" defer></script></head>'
        . '<body><div class="stars"></div>';
    echo '<header><a class="brand" href="' . ($employee ? '/?page=dashboard' : '/') . '"><span class="planet"></span>GHALAM</a>';
    if ($employee && !$public) {
        echo '<nav><span>' . e($employee['email']) . '</span>';
        echo '<a href="/?page=dashboard">Dashboard</a>';
        if ($employee['role'] === 'admin') {
            echo '<a href="/?page=users">Users</a>';
        }
        echo '<a href="/?page=change-password">Password</a>';
        echo '<form method="post" action="/?page=logout" class="inline">' . csrf_field()
            . '<button class="link-button">Sign out</button></form></nav>';
    }
    echo '</header><main class="' . ($public ? 'public-main' : '') . '">';
}

function render_footer(): void
{
    echo '</main><footer>Secure document delivery · GHALAM</footer></body></html>';
}

function error_page(int $status, string $title, string $message): never
{
    http_response_code($status);
    render_header($title, null, true);
    echo '<section class="download-card"><div class="file-orbit">×</div><h1>' . e($title) . '</h1>'
        . '<p class="muted">' . e($message) . '</p></section>';
    render_footer();
    exit;
}

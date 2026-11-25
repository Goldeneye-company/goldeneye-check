<?php
declare(strict_types=1);

require '/var/www/src/bootstrap.php';
require '/var/www/src/routes/auth.php';
require '/var/www/src/routes/public.php';
require '/var/www/src/routes/documents.php';
require '/var/www/src/routes/users.php';

$routes = [
    'login' => 'route_login',
    'mfa' => 'route_mfa',
    'logout' => 'route_logout',
    'change-password' => 'route_change_password',
    'file' => 'route_file',
    'dashboard' => 'route_dashboard',
    'upload' => 'route_upload',
    'create-link' => 'route_create_link',
    'revoke' => 'route_revoke',
    'delete-document' => 'route_delete_document',
    'users' => 'route_users',
];

$page = (string) ($_GET['page'] ?? '');
if ($page === '') {
    redirect(current_employee() ? '/?page=dashboard' : '/?page=login');
}
if (!isset($routes[$page])) {
    error_page(404, 'Page not found', 'Check the address.');
}
$routes[$page]();

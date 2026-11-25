<?php
declare(strict_types=1);

/*
 * Creates an account from the command line (the first administrator).
 * The temporary password is random and printed once; on the first sign-in
 * the user sets up MFA and changes the password.
 *
 * docker compose run --rm app php /var/www/bin/create-user.php admin@company.kz admin
 */

require dirname(__DIR__) . '/src/bootstrap.php';
require dirname(__DIR__) . '/src/routes/users.php';

$email = $argv[1] ?? '';
$role = $argv[2] ?? 'admin';
if ($email === '') {
    fwrite(STDERR, "Usage: php bin/create-user.php <email> [admin|employee]\n");
    exit(2);
}

try {
    $created = create_employee($email, $role);
} catch (InvalidArgumentException $exception) {
    fwrite(STDERR, $exception->getMessage() . PHP_EOL);
    exit(1);
}
audit('user.created', [
    'actor_type' => 'system',
    'actor_label' => 'cli',
    'object_type' => 'employee',
    'object_id' => $created['id'],
    'details' => ['email' => $created['email'], 'role' => $created['role']],
]);

echo "User created: {$created['email']} ({$created['role']})\n";
echo "Temporary password (shown once): {$created['temporary_password']}\n";
echo "On the first sign-in the user must set up MFA and change the password.\n";

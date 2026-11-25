<?php
declare(strict_types=1);

/*
 * Account management (ISO 27002: 5.16, 5.18).
 * Administrator only. Accounts are disabled, not deleted, so the audit trail stays intact.
 */

function create_employee(string $email, string $role): array
{
    $email = mb_strtolower(trim($email));
    if (filter_var($email, FILTER_VALIDATE_EMAIL) === false || mb_strlen($email) > 255) {
        throw new InvalidArgumentException('Invalid email.');
    }
    if (!in_array($role, ['admin', 'employee'], true)) {
        throw new InvalidArgumentException('Invalid role.');
    }
    $exists = db()->prepare('SELECT 1 FROM employees WHERE email = ?');
    $exists->execute([$email]);
    if ($exists->fetchColumn()) {
        throw new InvalidArgumentException('A user with this email already exists.');
    }
    $temporary = random_code(16);
    $stmt = db()->prepare('INSERT INTO employees (email, password_hash, role, must_change_password) VALUES (?, ?, ?, TRUE) RETURNING id');
    $stmt->execute([$email, hash_password($temporary), $role]);
    return ['id' => (int) $stmt->fetchColumn(), 'email' => $email, 'role' => $role, 'temporary_password' => $temporary];
}

function route_users(): void
{
    $admin = require_admin();
    $created = null;
    $error = null;
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        require_csrf();
        $action = (string) ($_POST['action'] ?? '');
        $targetId = filter_input(INPUT_POST, 'employee_id', FILTER_VALIDATE_INT);
        try {
            if ($action === 'create') {
                $created = create_employee((string) ($_POST['email'] ?? ''), (string) ($_POST['role'] ?? 'employee'));
                audit_employee($admin, 'user.created', 'employee', $created['id'], ['email' => $created['email'], 'role' => $created['role']]);
            } elseif (in_array($action, ['disable', 'enable', 'reset-mfa'], true) && $targetId) {
                if ($targetId === (int) $admin['id'] && $action !== 'enable') {
                    throw new InvalidArgumentException('You cannot disable yourself or reset your own MFA.');
                }
                $target = load_employee($targetId);
                if ($target === null) {
                    throw new InvalidArgumentException('User not found.');
                }
                if ($action === 'disable') {
                    db()->prepare('UPDATE employees SET is_active = FALSE WHERE id = ?')->execute([$targetId]);
                    audit_employee($admin, 'user.disabled', 'employee', $targetId, ['email' => $target['email']]);
                    flash_set('The user is disabled. Their active sessions end on the next request.');
                } elseif ($action === 'enable') {
                    db()->prepare('UPDATE employees SET is_active = TRUE WHERE id = ?')->execute([$targetId]);
                    audit_employee($admin, 'user.enabled', 'employee', $targetId, ['email' => $target['email']]);
                    flash_set('The user is enabled.');
                } else {
                    db()->prepare('UPDATE employees SET totp_secret_enc = NULL, totp_last_step = NULL WHERE id = ?')->execute([$targetId]);
                    audit_employee($admin, 'user.mfa_reset', 'employee', $targetId, ['email' => $target['email']]);
                    flash_set('MFA is reset. The user sets it up again on the next sign-in.');
                }
                redirect('/?page=users');
            } else {
                throw new InvalidArgumentException('Unknown action.');
            }
        } catch (InvalidArgumentException $exception) {
            $error = $exception->getMessage();
        }
    }

    $users = db()->query('SELECT id, email, role, is_active, must_change_password, totp_secret_enc IS NOT NULL AS has_mfa, created_at, last_login_at
        FROM employees ORDER BY id')->fetchAll();

    render_header('Users', $admin);
    echo '<div class="hero"><div><p class="eyebrow">ACCESS MANAGEMENT</p><h1>Users</h1>'
        . '<p class="muted">Create accounts, disable them and reset MFA.</p></div></div>';
    flash_render();
    if ($error) {
        echo '<p class="alert error">' . e($error) . '</p>';
    }
    if ($created) {
        echo '<section class="new-link"><p class="eyebrow">ACCOUNT CREATED</p><h2>' . e($created['email']) . '</h2>'
            . '<p class="muted">Give the temporary password to the user through a protected channel. It is shown once; '
            . 'on the first sign-in the user sets up MFA and changes the password.</p>'
            . '<input id="temp-password" readonly value="' . e($created['temporary_password']) . '">'
            . '<button type="button" class="copy-button" data-copy="temp-password">Copy password</button></section>';
    }

    echo '<div class="grid"><section><h2>New user</h2><form method="post" action="/?page=users" class="plain-form">'
        . csrf_field() . '<input type="hidden" name="action" value="create">'
        . '<label>Email<input type="email" name="email" required maxlength="255"></label>'
        . '<label>Role<select name="role"><option value="employee">Employee: own documents only</option>'
        . '<option value="admin">Administrator: all documents and users</option></select></label>'
        . '<button>Create <span>+</span></button></form></section></div>';

    echo '<section class="wide"><div class="table-wrap"><table><thead><tr><th>Email</th><th>Role</th><th>Status</th><th>MFA</th>'
        . '<th>Last sign-in</th><th></th></tr></thead><tbody>';
    foreach ($users as $user) {
        $id = (int) $user['id'];
        $status = !$user['is_active'] ? 'Disabled' : ($user['must_change_password'] ? 'Awaiting password change' : 'Active');
        echo '<tr><td>' . e($user['email']) . '</td><td>' . ($user['role'] === 'admin' ? 'Administrator' : 'Employee') . '</td>'
            . '<td><span class="badge ' . ($user['is_active'] ? 'active' : 'closed') . '">' . e($status) . '</span></td>'
            . '<td>' . ($user['has_mfa'] ? 'Yes' : 'No') . '</td><td>' . e(format_dt($user['last_login_at'])) . '</td><td>';
        if ($id !== (int) $admin['id']) {
            $toggle = $user['is_active'] ? 'disable' : 'enable';
            echo '<form method="post" action="/?page=users" class="inline">' . csrf_field()
                . '<input type="hidden" name="employee_id" value="' . $id . '"><input type="hidden" name="action" value="' . $toggle . '">'
                . '<button class="link-button">' . ($user['is_active'] ? 'Disable' : 'Enable') . '</button></form> ';
            if ($user['has_mfa']) {
                echo '<form method="post" action="/?page=users" class="inline" data-confirm="Reset the user\'s MFA?">' . csrf_field()
                    . '<input type="hidden" name="employee_id" value="' . $id . '"><input type="hidden" name="action" value="reset-mfa">'
                    . '<button class="link-button">Reset MFA</button></form>';
            }
        }
        echo '</td></tr>';
    }
    echo '</tbody></table></div></section>';
    render_footer();
}

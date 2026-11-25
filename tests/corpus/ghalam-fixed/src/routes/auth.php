<?php
declare(strict_types=1);

/*
 * Two-step sign-in: password, then TOTP (ISO 27002: 8.5, 5.17).
 * - failed attempts are limited per account and per IP, parallel attempts are serialised;
 * - the response time is the same for existing and unknown accounts;
 * - on the first sign-in the user enrols MFA and must change the temporary password.
 */

function route_login(): void
{
    if (current_employee()) {
        redirect('/?page=dashboard');
    }
    $error = null;
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        require_csrf();
        $email = mb_strtolower(trim((string) ($_POST['email'] ?? '')));
        $password = (string) ($_POST['password'] ?? '');
        $ip = client_ip();
        $employee = null;
        $ok = false;

        $pdo = db();
        $pdo->beginTransaction();
        lock_login_subject($email);
        if (login_is_locked($email, $ip)) {
            $pdo->commit();
            audit('auth.login_locked', ['actor_label' => $email]);
            $error = 'Too many failed attempts. Try again in ' . config()['login_lock_minutes'] . ' minutes.';
        } else {
            $stmt = $pdo->prepare('SELECT id, email, password_hash, is_active FROM employees WHERE email = ?');
            $stmt->execute([$email]);
            $found = $stmt->fetch();
            if ($found) {
                $ok = password_verify($password, $found['password_hash']) && $found['is_active'];
                $employee = $found;
            } else {
                hash_password($password); // equalises the response time
            }
            record_login_attempt($email, $ip, 'password', $ok);
            $pdo->commit();
            if ($ok) {
                if (password_needs_rehash($employee['password_hash'], password_algorithm())) {
                    $pdo->prepare('UPDATE employees SET password_hash = ? WHERE id = ?')
                        ->execute([hash_password($password), $employee['id']]);
                }
                session_regenerate_id(true);
                $_SESSION['auth'] = [
                    'employee_id' => (int) $employee['id'],
                    'stage' => 'mfa',
                    'started' => time(),
                    'last_activity' => time(),
                ];
                redirect('/?page=mfa');
            }
            audit('auth.login_failed', [
                'actor_type' => $employee ? 'employee' : 'anonymous',
                'actor_id' => $employee ? (int) $employee['id'] : null,
                'actor_label' => $email,
                'details' => ['reason' => $employee && !$employee['is_active'] ? 'disabled' : 'credentials'],
            ]);
            $error = 'Wrong email or password.';
        }
    }

    render_header('Employee sign-in');
    echo '<section class="auth-card"><p class="eyebrow">CONTROL CENTER</p><h1>Employee sign-in</h1>'
        . '<p class="muted">Manage documents and access</p>';
    flash_render();
    if ($error) {
        echo '<p class="alert error">' . e($error) . '</p>';
    }
    echo '<form method="post" action="/?page=login" class="plain-form">' . csrf_field()
        . '<label>Email<input type="email" name="email" required maxlength="255" autocomplete="username"></label>'
        . '<label>Password<input type="password" name="password" required maxlength="128" autocomplete="current-password"></label>'
        . '<button>Continue <span>→</span></button></form></section>';
    render_footer();
}

function route_mfa(): void
{
    $auth = $_SESSION['auth'] ?? null;
    if (!is_array($auth) || $auth['stage'] !== 'mfa') {
        redirect('/?page=login');
    }
    $employee = load_employee((int) $auth['employee_id']);
    if ($employee === null || !$employee['is_active']) {
        end_session();
        redirect('/?page=login');
    }
    $enrolling = $employee['totp_secret_enc'] === null;
    if ($enrolling) {
        $_SESSION['pending_totp'] ??= totp_generate_secret();
        $secret = $_SESSION['pending_totp'];
    } else {
        $secret = open_secret($employee['totp_secret_enc']);
    }

    $error = null;
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        require_csrf();
        $email = $employee['email'];
        $ip = client_ip();
        $pdo = db();
        $pdo->beginTransaction();
        lock_login_subject($email);
        if (login_is_locked($email, $ip)) {
            $pdo->commit();
            audit_employee($employee, 'auth.login_locked', null, null, ['stage' => 'mfa']);
            end_session();
            flash_set('Too many failed attempts. Try again in ' . config()['login_lock_minutes'] . ' minutes.', 'error');
            redirect('/?page=login');
        }
        // The last used step is re-read under the lock: a code cannot be used twice.
        $fresh = load_employee((int) $employee['id']);
        $lastStep = $fresh['totp_last_step'] === null ? null : (int) $fresh['totp_last_step'];
        $step = totp_verify($secret, (string) ($_POST['code'] ?? ''), $lastStep);
        record_login_attempt($email, $ip, 'mfa', $step !== null);
        if ($step === null) {
            $pdo->commit();
            audit_employee($employee, 'auth.mfa_failed');
            $error = 'Wrong code. Check the time on the device and try again.';
        } else {
            if ($enrolling) {
                $pdo->prepare('UPDATE employees SET totp_secret_enc = ?, totp_last_step = ?, last_login_at = CURRENT_TIMESTAMP WHERE id = ?')
                    ->execute([seal_secret($secret), $step, $employee['id']]);
            } else {
                $pdo->prepare('UPDATE employees SET totp_last_step = ?, last_login_at = CURRENT_TIMESTAMP WHERE id = ?')
                    ->execute([$step, $employee['id']]);
            }
            $pdo->commit();
            if ($enrolling) {
                audit_employee($employee, 'auth.mfa_enrolled');
            }
            audit_employee($employee, 'auth.login');
            unset($_SESSION['pending_totp']);
            session_regenerate_id(true);
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
            $_SESSION['auth'] = [
                'employee_id' => (int) $employee['id'],
                'stage' => 'full',
                'started' => time(),
                'last_activity' => time(),
            ];
            redirect('/?page=dashboard');
        }
    }

    render_header('Sign-in confirmation');
    echo '<section class="auth-card"><p class="eyebrow">TWO-FACTOR PROTECTION</p>';
    if ($enrolling) {
        echo '<h1>Set up MFA</h1><p class="muted">Add the account to an authenticator app '
            . '(Google Authenticator, Microsoft Authenticator, Aegis and others) and enter the code it shows.</p>'
            . '<label>Secret key<input id="totp-secret" readonly value="' . e(chunk_split($secret, 4, ' ')) . '"></label>'
            . '<button type="button" class="copy-button" data-copy="totp-secret">Copy</button>'
            . '<label>Link for the app<input id="totp-uri" readonly value="' . e(totp_uri($secret, $employee['email'])) . '"></label>'
            . '<button type="button" class="copy-button" data-copy="totp-uri">Copy</button>';
    } else {
        echo '<h1>Confirmation code</h1><p class="muted">Enter the 6 digits from the authenticator app.</p>';
    }
    if ($error) {
        echo '<p class="alert error">' . e($error) . '</p>';
    }
    echo '<form method="post" action="/?page=mfa" class="plain-form">' . csrf_field()
        . '<label>Code<input name="code" required inputmode="numeric" pattern="[0-9 ]{6,7}" maxlength="7" autocomplete="one-time-code" autofocus></label>'
        . '<button>Confirm <span>→</span></button></form></section>';
    render_footer();
}

function route_logout(): void
{
    require_post();
    $employee = current_employee();
    if ($employee) {
        audit_employee($employee, 'auth.logout');
    }
    end_session();
    redirect('/?page=login');
}

function route_change_password(): void
{
    $employee = require_employee(true);
    $error = null;
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        require_csrf();
        $current = (string) ($_POST['current_password'] ?? '');
        $new = (string) ($_POST['new_password'] ?? '');
        $confirm = (string) ($_POST['confirm_password'] ?? '');
        $stmt = db()->prepare('SELECT password_hash FROM employees WHERE id = ?');
        $stmt->execute([$employee['id']]);
        $hash = (string) $stmt->fetchColumn();
        $policy = password_policy_errors($new, $employee['email']);
        if (!password_verify($current, $hash)) {
            $error = 'The current password is wrong.';
        } elseif ($new !== $confirm) {
            $error = 'The new password and the confirmation do not match.';
        } elseif (password_verify($new, $hash)) {
            $error = 'The new password must differ from the current one.';
        } elseif ($policy) {
            $error = 'The password must be: ' . implode(', ', $policy) . '.';
        } else {
            db()->prepare('UPDATE employees SET password_hash = ?, must_change_password = FALSE, password_changed_at = CURRENT_TIMESTAMP WHERE id = ?')
                ->execute([hash_password($new), $employee['id']]);
            audit_employee($employee, 'auth.password_changed');
            session_regenerate_id(true);
            flash_set('The password has been changed.');
            redirect('/?page=dashboard');
        }
    }

    render_header('Change password', $employee);
    echo '<section class="auth-card"><p class="eyebrow">ACCOUNT</p><h1>Change password</h1>';
    if ($employee['must_change_password']) {
        echo '<p class="alert notice">Replace the temporary password before you start working.</p>';
    }
    flash_render();
    if ($error) {
        echo '<p class="alert error">' . e($error) . '</p>';
    }
    echo '<form method="post" action="/?page=change-password" class="plain-form">' . csrf_field()
        . '<label>Current password<input type="password" name="current_password" required maxlength="128" autocomplete="current-password"></label>'
        . '<label>New password<input type="password" name="new_password" required minlength="12" maxlength="128" autocomplete="new-password"></label>'
        . '<label>Repeat the new password<input type="password" name="confirm_password" required minlength="12" maxlength="128" autocomplete="new-password"></label>'
        . '<p class="hint">At least 12 characters. A phrase of several words works well.</p>'
        . '<button>Save <span>→</span></button></form></section>';
    render_footer();
}

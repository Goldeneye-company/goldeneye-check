<?php
declare(strict_types=1);
require '/var/www/src/bootstrap.php';

$page = (string) ($_GET['page'] ?? (employee() ? 'dashboard' : 'login'));
$error = null;

if ($page === 'logout') {
    $_SESSION = []; session_destroy(); redirect('/?page=login');
}

if ($page === 'login') {
    if (employee()) redirect('/?page=dashboard');
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        requireCsrf();
        $stmt = $db->prepare('SELECT * FROM employees WHERE email = ?');
        $stmt->execute([strtolower(trim((string) ($_POST['email'] ?? '')))]);
        $found = $stmt->fetch();
        if ($found && password_verify((string) ($_POST['password'] ?? ''), $found['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION['employee'] = ['id' => (int) $found['id'], 'email' => $found['email']];
            redirect('/?page=dashboard');
        }
        $error = 'Wrong email or password.';
    }
    renderHeader('Employee sign-in');
    echo '<section class="auth-card"><p class="eyebrow">CONTROL CENTER</p><h1>Employee sign-in</h1><p class="muted">Manage documents and access</p>';
    if ($error) echo '<p class="alert error">' . e($error) . '</p>';
    echo '<form method="post" class="plain-form"><input type="hidden" name="csrf" value="' . csrfToken() . '"><label>Email<input type="email" name="email" required autocomplete="username"></label><label>Password<input type="password" name="password" required autocomplete="current-password"></label><button>Sign in <span>→</span></button></form><p class="demo">Demo: admin@example.com · Admin123!</p></section>';
    renderFooter(); exit;
}

// The recipient comes here by a random link and does not need an account.
if ($page === 'file') {
    $token = (string) ($_GET['token'] ?? '');
    $stmt = $db->prepare('SELECT l.*, d.original_name, d.stored_name, d.mime_type, d.size_bytes FROM download_links l JOIN documents d ON d.id = l.document_id WHERE l.public_token = ?');
    $stmt->execute([$token]);
    $link = $stmt->fetch();
    if (!$link) {
        http_response_code(404); renderHeader('Link unavailable', true);
        echo '<section class="download-card"><div class="file-orbit">×</div><h1>Link unavailable</h1><p class="muted">Check the address or contact the sender.</p></section>';
        renderFooter(); exit;
    }
    $expired = strtotime($link['expires_at']) < time();
    $exhausted = (int) $link['download_count'] >= (int) $link['max_downloads'];
    $revoked = $link['revoked_at'] !== null;
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        requireCsrf();
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $attempts = $db->prepare("SELECT COUNT(*) FROM download_logs WHERE link_id = ? AND ip_address = ? AND result = 'wrong_password' AND created_at >= CURRENT_TIMESTAMP - INTERVAL '15 minutes'");
        $attempts->execute([$link['id'], $ip]);
        $blocked = (int) $attempts->fetchColumn() >= 5;
        if ($blocked) {
            $error = 'Too many attempts. Try again in 15 minutes.';
        } elseif ($revoked || $expired || $exhausted) {
            addLog($db, (int) $link['id'], $revoked ? 'revoked' : ($expired ? 'expired' : 'limit_reached'));
            $error = 'Access to the document has ended.';
        } elseif (!password_verify((string) ($_POST['password'] ?? ''), $link['password_hash'])) {
            addLog($db, (int) $link['id'], 'wrong_password'); $error = 'Wrong password.';
        } else {
            $db->beginTransaction();
            $update = $db->prepare('UPDATE download_links SET download_count = download_count + 1 WHERE id = ? AND revoked_at IS NULL AND expires_at >= CURRENT_TIMESTAMP AND download_count < max_downloads');
            $update->execute([$link['id']]);
            if ($update->rowCount() !== 1) {
                $db->rollBack(); $error = 'Access to the document has ended.';
            } else {
                addLog($db, (int) $link['id'], 'downloaded'); $db->commit();
                $path = DATA_DIR . '/uploads/' . $link['stored_name'];
                header('Content-Type: ' . $link['mime_type']);
                header('Content-Length: ' . (int) $link['size_bytes']);
                header("Content-Disposition: attachment; filename*=UTF-8''" . rawurlencode($link['original_name']));
                readfile($path); exit;
            }
        }
    }
    renderHeader('Document download', true);
    echo '<section class="download-card"><div class="file-orbit">↓</div><p class="eyebrow">SECURE TRANSFER</p><h1>' . e($link['original_name']) . '</h1><p class="muted">' . e(formatBytes((int) $link['size_bytes'])) . ' · available until ' . e(date('d.m.Y H:i', strtotime($link['expires_at']))) . '</p>';
    if ($error) echo '<p class="alert error">' . e($error) . '</p>';
    if ($revoked || $expired || $exhausted) {
        if (!$error) echo '<p class="alert error">Access to the document has ended.</p>';
    } else {
        echo '<form method="post" class="plain-form"><input type="hidden" name="csrf" value="' . csrfToken() . '"><label>Document password<input type="password" name="password" required autocomplete="one-time-code" autofocus></label><button>Download document <span>↓</span></button></form><p class="counter">Downloads left: <strong>' . ((int) $link['max_downloads'] - (int) $link['download_count']) . '</strong></p>';
    }
    echo '</section>'; renderFooter(); exit;
}

$current = requireEmployee();

if ($page === 'upload') {
    requireCsrf(); $file = $_FILES['document'] ?? null;
    if (!$file || $file['error'] !== UPLOAD_ERR_OK) { $_SESSION['flash'] = 'Upload failed.'; redirect('/?page=dashboard'); }
    if ((int) $file['size'] > MAX_FILE_SIZE) { $_SESSION['flash'] = 'The file is larger than 100 MB.'; redirect('/?page=dashboard'); }
    $allowed = ['application/pdf', 'image/png', 'image/jpeg', 'text/plain'];
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($file['tmp_name']);
    if (!in_array($mime, $allowed, true)) { $_SESSION['flash'] = 'Allowed: PDF, PNG, JPG and TXT.'; redirect('/?page=dashboard'); }
    $storedName = bin2hex(random_bytes(24));
    if (!move_uploaded_file($file['tmp_name'], DATA_DIR . '/uploads/' . $storedName)) throw new RuntimeException('Could not save the file.');
    $stmt = $db->prepare('INSERT INTO documents (original_name, stored_name, mime_type, size_bytes, uploaded_by) VALUES (?, ?, ?, ?, ?)');
    $stmt->execute([basename((string) $file['name']), $storedName, $mime, (int) $file['size'], $current['id']]);
    $_SESSION['flash'] = 'Document uploaded. Now create a link.'; redirect('/?page=dashboard');
}

if ($page === 'create-link') {
    requireCsrf();
    $documentId = filter_input(INPUT_POST, 'document_id', FILTER_VALIDATE_INT);
    $maxDownloads = filter_input(INPUT_POST, 'max_downloads', FILTER_VALIDATE_INT);
    $lifetimeHours = filter_input(INPUT_POST, 'lifetime_hours', FILTER_VALIDATE_INT);
    $recipient = trim((string) ($_POST['recipient_label'] ?? ''));
    if (!$documentId || !$maxDownloads || !$lifetimeHours || $maxDownloads < 1 || $maxDownloads > 100 || $lifetimeHours < 1 || $lifetimeHours > 8760) {
        $_SESSION['flash'] = 'Check the link parameters.'; redirect('/?page=dashboard');
    }
    $password = strtoupper(substr(bin2hex(random_bytes(8)), 0, 12));
    $token = bin2hex(random_bytes(24));
    $expiresAt = date('Y-m-d H:i:s', time() + $lifetimeHours * 3600);
    $stmt = $db->prepare('INSERT INTO download_links (document_id, public_token, password_hash, recipient_label, max_downloads, expires_at) VALUES (?, ?, ?, ?, ?, ?)');
    $stmt->execute([$documentId, $token, password_hash($password, PASSWORD_DEFAULT), $recipient ?: null, $maxDownloads, $expiresAt]);
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $_SESSION['new_link'] = ['url' => $scheme . '://' . $_SERVER['HTTP_HOST'] . '/?page=file&token=' . $token, 'password' => $password];
    redirect('/?page=dashboard');
}

if ($page === 'revoke') {
    requireCsrf(); $linkId = filter_input(INPUT_POST, 'link_id', FILTER_VALIDATE_INT);
    if ($linkId) { $stmt = $db->prepare('UPDATE download_links SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE id = ?'); $stmt->execute([$linkId]); }
    $_SESSION['flash'] = 'Access revoked.'; redirect('/?page=dashboard');
}

renderHeader('Employee dashboard');
echo '<div class="hero"><div><p class="eyebrow">DOCUMENT CONTROL</p><h1>Control center</h1><p class="muted">Upload documents and create limited access.</p></div><div class="status"><i></i> System is active</div></div>';
$flash = $_SESSION['flash'] ?? null; unset($_SESSION['flash']);
if ($flash) echo '<p class="alert notice">' . e($flash) . '</p>';
if (isset($_SESSION['new_link'])) {
    $created = $_SESSION['new_link']; unset($_SESSION['new_link']);
    echo '<section class="new-link"><p class="eyebrow">ACCESS CREATED</p><h2>Copy the details now</h2><p class="muted">The password is stored only as a hash and will not be shown again.</p><label>Link<input readonly value="' . e($created['url']) . '" onclick="this.select()"></label><label>Password<input readonly value="' . e($created['password']) . '" onclick="this.select()"></label></section>';
}

$documents = $db->query('SELECT * FROM documents ORDER BY id DESC')->fetchAll();
echo '<div class="grid"><section><p class="step">01</p><h2>Upload a document</h2><form method="post" action="/?page=upload" enctype="multipart/form-data" class="plain-form"><input type="hidden" name="csrf" value="' . csrfToken() . '"><label class="drop"><input type="file" name="document" required><span>Choose a PDF, PNG, JPG or TXT</span><small>Up to 100 MB</small></label><button>Upload <span>↑</span></button></form></section>';
echo '<section><p class="step">02</p><h2>Create access</h2>';
if (!$documents) echo '<p class="muted">Upload a document first.</p>';
else {
    echo '<form method="post" action="/?page=create-link" class="plain-form"><input type="hidden" name="csrf" value="' . csrfToken() . '"><label>Document<select name="document_id">';
    foreach ($documents as $document) echo '<option value="' . (int) $document['id'] . '">' . e($document['original_name']) . '</option>';
    echo '</select></label><label>Recipient or note<input name="recipient_label" maxlength="100" placeholder="For example: Alpha Company"></label><div class="form-row"><label>Downloads<input type="number" name="max_downloads" value="1" min="1" max="100"></label><label>Lifetime, hours<input type="number" name="lifetime_hours" value="72" min="1" max="8760"></label></div><button>Create link <span>↗</span></button></form>';
}
echo '</section></div>';

$links = $db->query('SELECT l.*, d.original_name FROM download_links l JOIN documents d ON d.id = l.document_id ORDER BY l.id DESC')->fetchAll();
$logs = $db->query('SELECT g.*, d.original_name, l.recipient_label FROM download_logs g JOIN download_links l ON l.id = g.link_id JOIN documents d ON d.id = l.document_id ORDER BY g.id DESC LIMIT 50')->fetchAll();
$labels = ['downloaded' => 'Downloaded', 'wrong_password' => 'Wrong password', 'expired' => 'Expired', 'limit_reached' => 'Limit reached', 'revoked' => 'Revoked'];
echo '<section class="wide"><div class="section-title"><div><p class="eyebrow">ACCESS LINKS</p><h2>Issued access links</h2></div><span>' . count($links) . ' records</span></div><div class="table-wrap"><table><thead><tr><th>Document</th><th>Recipient</th><th>Downloads</th><th>Valid until</th><th>Status</th><th></th></tr></thead><tbody>';
if (!$links) echo '<tr><td colspan="6" class="empty">No links yet</td></tr>';
foreach ($links as $link) {
    $ended = $link['revoked_at'] || strtotime($link['expires_at']) < time() || (int) $link['download_count'] >= (int) $link['max_downloads'];
    echo '<tr><td>' . e($link['original_name']) . '</td><td>' . e($link['recipient_label'] ?: '—') . '</td><td>' . (int) $link['download_count'] . ' / ' . (int) $link['max_downloads'] . '</td><td>' . e(date('d.m.Y H:i', strtotime($link['expires_at']))) . '</td><td><span class="badge ' . ($ended ? 'closed' : 'active') . '">' . ($ended ? 'Ended' : 'Active') . '</span></td><td>';
    if (!$ended) echo '<form method="post" action="/?page=revoke" class="inline"><input type="hidden" name="csrf" value="' . csrfToken() . '"><input type="hidden" name="link_id" value="' . (int) $link['id'] . '"><button class="link-button">Revoke</button></form>';
    echo '</td></tr>';
}
echo '</tbody></table></div></section>';
echo '<section class="wide"><div class="section-title"><div><p class="eyebrow">ACTIVITY LOG</p><h2>Activity log</h2></div><span>Last 50</span></div><div class="table-wrap"><table><thead><tr><th>Time</th><th>Document</th><th>Recipient</th><th>IP</th><th>Result</th></tr></thead><tbody>';
if (!$logs) echo '<tr><td colspan="5" class="empty">No events yet</td></tr>';
foreach ($logs as $log) echo '<tr><td>' . e(date('d.m.Y H:i', strtotime($log['created_at']))) . '</td><td>' . e($log['original_name']) . '</td><td>' . e($log['recipient_label'] ?: '—') . '</td><td><code>' . e($log['ip_address']) . '</code></td><td>' . e($labels[$log['result']] ?? $log['result']) . '</td></tr>';
echo '</tbody></table></div></section>';
renderFooter();

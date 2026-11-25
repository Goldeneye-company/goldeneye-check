<?php
declare(strict_types=1);

/*
 * Employee dashboard.
 * An employee sees and changes only their own documents and links, the administrator sees all (ISO 27002: 5.15, 8.3).
 */

const ALLOWED_MIME = [
    'application/pdf' => ['pdf'],
    'image/png' => ['png'],
    'image/jpeg' => ['jpg', 'jpeg'],
    'text/plain' => ['txt'],
];

/** A document the employee may access, or null. */
function find_owned_document(array $employee, int $documentId, bool $forUpdate = false): ?array
{
    $sql = 'SELECT * FROM documents WHERE id = ?' . (is_admin($employee) ? '' : ' AND uploaded_by = ?') . ($forUpdate ? ' FOR UPDATE' : '');
    $params = is_admin($employee) ? [$documentId] : [$documentId, $employee['id']];
    $stmt = db()->prepare($sql);
    $stmt->execute($params);
    $row = $stmt->fetch();
    return $row ?: null;
}

function clean_file_name(string $name): string
{
    $name = basename(str_replace('\\', '/', $name));
    $name = preg_replace('/[\x00-\x1F\x7F]/u', '', $name) ?? '';
    $name = trim($name);
    return $name === '' ? 'document' : mb_substr($name, 0, 200);
}

function route_upload(): void
{
    require_post();
    $employee = require_employee();
    $c = config();
    $file = $_FILES['document'] ?? null;
    $reject = static function (string $message, string $reason, array $details = []) use ($employee): never {
        audit_employee($employee, 'document.upload_rejected', null, null, ['reason' => $reason] + $details);
        flash_set($message, 'error');
        redirect('/?page=dashboard');
    };

    if (!is_array($file) || !isset($file['error']) || is_array($file['error']) || $file['error'] !== UPLOAD_ERR_OK
        || !is_uploaded_file($file['tmp_name'])) {
        $reject('The file could not be uploaded.', 'upload_error');
    }
    $size = (int) $file['size'];
    if ($size <= 0 || $size > $c['max_file_bytes']) {
        $reject('The file is empty or larger than ' . intdiv($c['max_file_bytes'], 1048576) . ' MB.', 'size', ['size' => $size]);
    }
    $name = clean_file_name((string) $file['name']);
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($file['tmp_name']);
    $extension = mb_strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if (!isset(ALLOWED_MIME[$mime]) || !in_array($extension, ALLOWED_MIME[$mime], true)) {
        $reject('Allowed: PDF, PNG, JPG and TXT with the matching extension.', 'type', ['mime' => $mime, 'extension' => $extension]);
    }

    // The employee quota and a free disk space reserve.
    $used = db()->prepare('SELECT COALESCE(SUM(size_bytes), 0) FROM documents WHERE uploaded_by = ?');
    $used->execute([$employee['id']]);
    if ((int) $used->fetchColumn() + $size > $c['quota_bytes']) {
        $reject('The storage quota is exceeded. Delete documents you no longer need.', 'quota');
    }
    $free = disk_free_space(UPLOAD_DIR);
    if ($free === false || $free - $size * 1.1 < $c['disk_reserve_bytes']) {
        $reject('Not enough space in the storage. Tell the administrator.', 'disk_space');
    }

    $scan = antivirus_scan($file['tmp_name']);
    if ($scan['status'] === 'infected') {
        audit_employee($employee, 'document.malware_detected', null, null, ['signature' => $scan['detail'], 'name' => $name]);
        flash_set('The file is rejected: malicious content found.', 'error');
        redirect('/?page=dashboard');
    }
    if ($scan['status'] === 'error' && $c['clamav_required']) {
        error_log('Antivirus error: ' . $scan['detail']);
        $reject('The antivirus check is unavailable, uploads are temporarily disabled.', 'antivirus_unavailable');
    }

    $storedName = bin2hex(random_bytes(24));
    $target = UPLOAD_DIR . '/' . $storedName;
    try {
        [$sha256, $wrappedKey] = encrypt_file($file['tmp_name'], $target);
        $stmt = db()->prepare('INSERT INTO documents (original_name, stored_name, mime_type, size_bytes, sha256, wrapped_key, uploaded_by, antivirus_status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id');
        $stmt->execute([$name, $storedName, $mime, $size, $sha256, $wrappedKey, $employee['id'], $scan['status']]);
        $documentId = (int) $stmt->fetchColumn();
    } catch (Throwable $exception) {
        if (is_file($target)) {
            unlink($target);
        }
        throw $exception;
    }
    audit_employee($employee, 'document.uploaded', 'document', $documentId, [
        'name' => $name, 'size' => $size, 'mime' => $mime, 'sha256' => $sha256, 'antivirus' => $scan['status'],
    ]);
    flash_set('The document is uploaded and encrypted. Now create a link.');
    redirect('/?page=dashboard');
}

function route_create_link(): void
{
    require_post();
    $employee = require_employee();

    // A one-time form identifier: submitting the form again does not create a second access.
    $nonce = (string) ($_POST['nonce'] ?? '');
    if ($nonce === '' || !isset($_SESSION['form_nonces'][$nonce])) {
        flash_set('The form has already been submitted. Create the access again.', 'error');
        redirect('/?page=dashboard');
    }
    unset($_SESSION['form_nonces'][$nonce]);

    $documentId = filter_input(INPUT_POST, 'document_id', FILTER_VALIDATE_INT);
    $maxDownloads = filter_input(INPUT_POST, 'max_downloads', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 100]]);
    $lifetimeHours = filter_input(INPUT_POST, 'lifetime_hours', FILTER_VALIDATE_INT, ['options' => ['min_range' => 1, 'max_range' => 720]]);
    $recipient = mb_substr(trim((string) ($_POST['recipient_label'] ?? '')), 0, 100);
    $recipient = preg_replace('/[\x00-\x1F\x7F]/u', '', $recipient) ?? '';
    if (!$documentId || !$maxDownloads || !$lifetimeHours) {
        flash_set('Check the link parameters: up to 100 downloads and up to 720 hours.', 'error');
        redirect('/?page=dashboard');
    }
    $document = find_owned_document($employee, $documentId);
    if ($document === null) {
        flash_set('Document not found.', 'error');
        redirect('/?page=dashboard');
    }

    $token = bin2hex(random_bytes(24));
    $password = random_code(16);
    $stmt = db()->prepare('INSERT INTO download_links (document_id, token_hash, password_hash, recipient_label, max_downloads, expires_at, created_by)
        VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP + make_interval(hours => ?), ?) RETURNING id, expires_at');
    $stmt->execute([$documentId, token_hash($token), hash_password($password), $recipient !== '' ? $recipient : null,
        $maxDownloads, $lifetimeHours, $employee['id']]);
    $created = $stmt->fetch();
    audit_employee($employee, 'link.created', 'link', (int) $created['id'], [
        'document_id' => $documentId, 'max_downloads' => $maxDownloads, 'lifetime_hours' => $lifetimeHours, 'recipient' => $recipient,
    ]);

    // The link and the password are kept neither in the database nor in the session: they are shown once in this response.
    $url = config()['base_url'] . '/?page=file&token=' . $token;
    render_header('Access created', $employee);
    echo '<section class="new-link"><p class="eyebrow">ACCESS CREATED</p><h2>' . e($document['original_name']) . '</h2>'
        . '<p class="muted">Valid until ' . e(format_dt($created['expires_at'])) . ', downloads: ' . (int) $maxDownloads . '. '
        . 'The details are shown once: the password is stored only as a hash.</p>'
        . '<div class="secret-block"><p class="step-title">1. Link: send it to the recipient, for example by email</p>'
        . '<input id="link-url" readonly value="' . e($url) . '">'
        . '<button type="button" class="copy-button" data-copy="link-url">Copy link</button></div>'
        . '<div class="secret-block"><p class="step-title">2. Password: send it <strong>through another channel</strong>: SMS, a messenger or a call</p>'
        . '<input id="link-password" readonly value="' . e($password) . '">'
        . '<button type="button" class="copy-button" data-copy="link-password">Copy password</button></div>'
        . '<p class="hint">If the link and the password end up in one email, intercepting the email gives access to the document.</p>'
        . '<p><a href="/?page=dashboard">← Back to the dashboard</a></p></section>';
    render_footer();
}

function route_revoke(): void
{
    require_post();
    $employee = require_employee();
    $linkId = filter_input(INPUT_POST, 'link_id', FILTER_VALIDATE_INT);
    if (!$linkId) {
        flash_set('Link not found.', 'error');
        redirect('/?page=dashboard');
    }
    $sql = 'UPDATE download_links l SET revoked_at = CURRENT_TIMESTAMP, revoked_by = ?, revoke_reason = \'manual\'
        FROM documents d WHERE d.id = l.document_id AND l.id = ? AND l.revoked_at IS NULL'
        . (is_admin($employee) ? '' : ' AND d.uploaded_by = ?');
    $params = is_admin($employee) ? [$employee['id'], $linkId] : [$employee['id'], $linkId, $employee['id']];
    $stmt = db()->prepare($sql);
    $stmt->execute($params);
    if ($stmt->rowCount() === 1) {
        audit_employee($employee, 'link.revoked', 'link', (int) $linkId);
        flash_set('Access revoked.');
    } else {
        flash_set('The link was not found or is no longer valid.', 'error');
    }
    redirect('/?page=dashboard');
}

function route_delete_document(): void
{
    require_post();
    $employee = require_employee();
    $documentId = filter_input(INPUT_POST, 'document_id', FILTER_VALIDATE_INT);
    $pdo = db();
    $pdo->beginTransaction();
    $document = $documentId ? find_owned_document($employee, $documentId, true) : null;
    if ($document === null) {
        $pdo->rollBack();
        flash_set('Document not found.', 'error');
        redirect('/?page=dashboard');
    }
    $pdo->prepare('DELETE FROM documents WHERE id = ?')->execute([$documentId]);
    $pdo->commit();
    $path = UPLOAD_DIR . '/' . $document['stored_name'];
    if (is_file($path)) {
        unlink($path);
    }
    audit_employee($employee, 'document.deleted', 'document', (int) $documentId, [
        'name' => $document['original_name'], 'sha256' => $document['sha256'],
    ]);
    flash_set('The document and all its links have been deleted.');
    redirect('/?page=dashboard');
}

function route_dashboard(): void
{
    $employee = require_employee();
    $admin = is_admin($employee);
    $ownerFilter = $admin ? '' : ' WHERE d.uploaded_by = :me';
    $params = $admin ? [] : ['me' => $employee['id']];

    $stmt = db()->prepare('SELECT d.*, e.email AS owner_email FROM documents d JOIN employees e ON e.id = d.uploaded_by' . $ownerFilter . ' ORDER BY d.id DESC');
    $stmt->execute($params);
    $documents = $stmt->fetchAll();

    $stmt = db()->prepare('SELECT l.id, l.recipient_label, l.download_count, l.max_downloads, l.expires_at, l.revoked_at, l.revoke_reason, d.original_name
        FROM download_links l JOIN documents d ON d.id = l.document_id' . $ownerFilter . ' ORDER BY l.id DESC LIMIT 200');
    $stmt->execute($params);
    $links = $stmt->fetchAll();

    if ($admin) {
        $stmt = db()->prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 100');
        $stmt->execute();
    } else {
        $stmt = db()->prepare("SELECT * FROM audit_log a WHERE a.actor_id = :me1 AND a.actor_type = 'employee'
            OR (a.object_type = 'link' AND a.object_id IN (SELECT l.id FROM download_links l JOIN documents d ON d.id = l.document_id WHERE d.uploaded_by = :me2))
            ORDER BY a.id DESC LIMIT 100");
        $stmt->execute(['me1' => $employee['id'], 'me2' => $employee['id']]);
    }
    $logs = $stmt->fetchAll();

    $nonce = bin2hex(random_bytes(16));
    $_SESSION['form_nonces'] = array_slice(($_SESSION['form_nonces'] ?? []) + [$nonce => time()], -20, null, true);
    $maxMb = intdiv(config()['max_file_bytes'], 1048576);

    render_header('Employee dashboard', $employee);
    echo '<div class="hero"><div><p class="eyebrow">DOCUMENT CONTROL</p><h1>Control center</h1>'
        . '<p class="muted">Documents are stored encrypted and checked by an antivirus.</p></div>'
        . '<div class="status"><i></i> ' . ($admin ? 'Administrator' : 'Employee') . '</div></div>';
    flash_render();

    echo '<div class="grid"><section><p class="step">01</p><h2>Upload a document</h2>'
        . '<form method="post" action="/?page=upload" enctype="multipart/form-data" class="plain-form">' . csrf_field()
        . '<label class="drop"><input type="file" name="document" required accept=".pdf,.png,.jpg,.jpeg,.txt">'
        . '<span>Choose a PDF, PNG, JPG or TXT</span><small>Up to ' . $maxMb . ' MB</small></label>'
        . '<button>Upload <span>↑</span></button></form></section>';
    echo '<section><p class="step">02</p><h2>Create access</h2>';
    if (!$documents) {
        echo '<p class="muted">Upload a document first.</p>';
    } else {
        echo '<form method="post" action="/?page=create-link" class="plain-form">' . csrf_field()
            . '<input type="hidden" name="nonce" value="' . e($nonce) . '"><label>Document<select name="document_id">';
        foreach ($documents as $document) {
            echo '<option value="' . (int) $document['id'] . '">' . e($document['original_name']) . '</option>';
        }
        echo '</select></label><label>Recipient or note<input name="recipient_label" maxlength="100" placeholder="For example: Alpha Company"></label>'
            . '<div class="form-row"><label>Downloads<input type="number" name="max_downloads" value="1" min="1" max="100"></label>'
            . '<label>Lifetime, hours<input type="number" name="lifetime_hours" value="72" min="1" max="720"></label></div>'
            . '<button>Create link <span>↗</span></button></form>';
    }
    echo '</section></div>';

    echo '<section class="wide"><div class="section-title"><div><p class="eyebrow">DOCUMENTS</p><h2>Documents</h2></div><span>'
        . count($documents) . ' records</span></div><div class="table-wrap"><table><thead><tr><th>Document</th><th>Size</th>'
        . ($admin ? '<th>Owner</th>' : '') . '<th>Uploaded</th><th>SHA-256</th><th></th></tr></thead><tbody>';
    if (!$documents) {
        echo '<tr><td colspan="' . ($admin ? 6 : 5) . '" class="empty">No documents</td></tr>';
    }
    foreach ($documents as $document) {
        echo '<tr><td>' . e($document['original_name']) . '</td><td>' . e(format_bytes((int) $document['size_bytes'])) . '</td>'
            . ($admin ? '<td>' . e($document['owner_email']) . '</td>' : '')
            . '<td>' . e(format_dt($document['created_at'])) . '</td><td><code title="' . e($document['sha256']) . '">'
            . e(substr($document['sha256'], 0, 12)) . '…</code></td><td>'
            . '<form method="post" action="/?page=delete-document" class="inline" data-confirm="Delete the document and all its links?">'
            . csrf_field() . '<input type="hidden" name="document_id" value="' . (int) $document['id'] . '">'
            . '<button class="link-button">Delete</button></form></td></tr>';
    }
    echo '</tbody></table></div></section>';

    echo '<section class="wide"><div class="section-title"><div><p class="eyebrow">ACCESS LINKS</p><h2>Issued access links</h2></div><span>'
        . count($links) . ' records</span></div><div class="table-wrap"><table><thead><tr><th>Document</th><th>Recipient</th>'
        . '<th>Downloads</th><th>Valid until</th><th>Status</th><th></th></tr></thead><tbody>';
    if (!$links) {
        echo '<tr><td colspan="6" class="empty">No links yet</td></tr>';
    }
    foreach ($links as $link) {
        $reason = link_end_reason($link);
        $status = match ($reason) {
            null => 'Active',
            'revoked' => $link['revoke_reason'] === 'too_many_attempts' ? 'Locked' : 'Revoked',
            'expired' => 'Expired',
            default => 'Limit reached',
        };
        echo '<tr><td>' . e($link['original_name']) . '</td><td>' . e($link['recipient_label'] ?? '—') . '</td><td>'
            . (int) $link['download_count'] . ' / ' . (int) $link['max_downloads'] . '</td><td>' . e(format_dt($link['expires_at']))
            . '</td><td><span class="badge ' . ($reason === null ? 'active' : 'closed') . '">' . e($status) . '</span></td><td>';
        if ($reason === null) {
            echo '<form method="post" action="/?page=revoke" class="inline">' . csrf_field()
                . '<input type="hidden" name="link_id" value="' . (int) $link['id'] . '"><button class="link-button">Revoke</button></form>';
        }
        echo '</td></tr>';
    }
    echo '</tbody></table></div></section>';

    echo '<section class="wide"><div class="section-title"><div><p class="eyebrow">AUDIT LOG</p><h2>Audit log</h2></div>'
        . '<span>Last 100</span></div><div class="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Who</th>'
        . '<th>Object</th><th>IP</th></tr></thead><tbody>';
    if (!$logs) {
        echo '<tr><td colspan="5" class="empty">No events yet</td></tr>';
    }
    foreach ($logs as $log) {
        $object = $log['object_type'] ? $log['object_type'] . ' #' . $log['object_id'] : '—';
        echo '<tr><td>' . e(format_dt($log['created_at'])) . '</td><td>' . e(AUDIT_LABELS[$log['action']] ?? $log['action']) . '</td><td>'
            . e($log['actor_label'] ?? $log['actor_type']) . '</td><td>' . e($object) . '</td><td><code>' . e($log['ip_address'] ?? '—')
            . '</code></td></tr>';
    }
    echo '</tbody></table></div></section>';
    render_footer();
}

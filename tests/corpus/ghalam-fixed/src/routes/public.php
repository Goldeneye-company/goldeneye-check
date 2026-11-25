<?php
declare(strict_types=1);

/*
 * Getting a document by link. The recipient does not need an account.
 * - The file name and size are not disclosed before the password (ISO 27002: 5.12);
 * - the password, limits and counter are checked in one transaction with a lock on the link row,
 *   so parallel requests do not bypass the limits (ISO 27002: 8.5);
 * - after LINK_MAX_FAILURES_TOTAL wrong passwords from any address the link is locked;
 * - the file integrity is checked before it is served (AEAD + SHA-256).
 */

function find_link_by_token(string $token): ?array
{
    if (!preg_match('/^[a-f0-9]{48}$/', $token)) {
        return null;
    }
    $stmt = db()->prepare('SELECT l.*, d.original_name, d.stored_name, d.mime_type, d.size_bytes, d.sha256, d.wrapped_key
        FROM download_links l JOIN documents d ON d.id = l.document_id WHERE l.token_hash = ?');
    $stmt->execute([token_hash($token)]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function link_end_reason(array $link): ?string
{
    if ($link['revoked_at'] !== null) {
        return 'revoked';
    }
    if (new DateTimeImmutable($link['expires_at']) <= new DateTimeImmutable('now')) {
        return 'expired';
    }
    if ((int) $link['download_count'] >= (int) $link['max_downloads']) {
        return 'limit_reached';
    }
    return null;
}

function route_file(): void
{
    $token = (string) ($_GET['token'] ?? '');
    $link = find_link_by_token($token);
    if ($link === null) {
        error_page(404, 'Link unavailable', 'Check the address or contact the sender.');
    }

    $error = null;
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') {
        require_csrf();
        $error = attempt_download((int) $link['id'], (string) ($_POST['password'] ?? ''));
        $link = find_link_by_token($token) ?? $link;
    }

    $ended = link_end_reason($link) !== null;
    render_header('Document download', null, true);
    echo '<section class="download-card"><div class="file-orbit">↓</div><p class="eyebrow">SECURE TRANSFER</p>'
        . '<h1>Protected document</h1>'
        . '<p class="muted">Available until ' . e(format_dt($link['expires_at'])) . '. The file name is shown after the download.</p>';
    if ($error) {
        echo '<p class="alert error">' . e($error) . '</p>';
    }
    if ($ended) {
        if (!$error) {
            echo '<p class="alert error">Access to the document has ended.</p>';
        }
    } else {
        echo '<form method="post" action="/?page=file&amp;token=' . e($token) . '" class="plain-form">' . csrf_field()
            . '<label>Document password<input type="password" name="password" required maxlength="64" autocomplete="off" autofocus></label>'
            . '<button>Download document <span>↓</span></button></form>'
            . '<p class="counter">The sender gives you the password separately from the link.</p>';
    }
    echo '</section>';
    render_footer();
}

/** Returns an error text, or serves the file and ends the request. */
function attempt_download(int $linkId, string $password): string
{
    $c = config();
    $ip = client_ip();
    $pdo = db();
    $pdo->beginTransaction();
    $stmt = $pdo->prepare('SELECT l.*, d.original_name, d.stored_name, d.mime_type, d.size_bytes, d.sha256, d.wrapped_key
        FROM download_links l JOIN documents d ON d.id = l.document_id WHERE l.id = ? FOR UPDATE OF l');
    $stmt->execute([$linkId]);
    $link = $stmt->fetch();
    if (!$link) {
        $pdo->rollBack();
        return 'Access to the document has ended.';
    }
    $recipient = ['actor_type' => 'recipient', 'actor_label' => $link['recipient_label'], 'object_type' => 'link', 'object_id' => $linkId];

    $attempts = $pdo->prepare("SELECT COUNT(*) FROM audit_log
        WHERE object_type = 'link' AND object_id = ? AND action = 'link.wrong_password' AND ip_address = ?
          AND created_at > CURRENT_TIMESTAMP - INTERVAL '15 minutes'");
    $attempts->execute([$linkId, $ip]);
    if ((int) $attempts->fetchColumn() >= $c['link_max_failures_per_ip']) {
        audit('link.blocked', $recipient);
        $pdo->commit();
        return 'Too many attempts. Try again in 15 minutes.';
    }

    $reason = link_end_reason($link);
    if ($reason !== null) {
        audit('link.access_denied', $recipient + ['details' => ['reason' => $reason]]);
        $pdo->commit();
        return 'Access to the document has ended.';
    }

    if (!password_verify($password, $link['password_hash'])) {
        $failed = (int) $link['failed_attempts'] + 1;
        $pdo->prepare('UPDATE download_links SET failed_attempts = ? WHERE id = ?')->execute([$failed, $linkId]);
        audit('link.wrong_password', $recipient + ['details' => ['failed_total' => $failed]]);
        if ($failed >= $c['link_max_failures_total']) {
            $pdo->prepare("UPDATE download_links SET revoked_at = CURRENT_TIMESTAMP, revoke_reason = 'too_many_attempts'
                WHERE id = ? AND revoked_at IS NULL")->execute([$linkId]);
            audit('link.auto_revoked', ['actor_type' => 'system', 'object_type' => 'link', 'object_id' => $linkId,
                'details' => ['reason' => 'too_many_attempts', 'failed_total' => $failed]]);
            $pdo->commit();
            return 'The link is locked after many wrong passwords. Contact the sender.';
        }
        $pdo->commit();
        return 'Wrong password.';
    }

    // Integrity is checked before the download is counted: a damaged file does not use up the limit.
    $path = UPLOAD_DIR . '/' . $link['stored_name'];
    try {
        $digest = decrypt_file($path, $link['wrapped_key']);
        if (!hash_equals($link['sha256'], $digest)) {
            throw new RuntimeException('SHA-256 mismatch');
        }
    } catch (Throwable $exception) {
        error_log('Integrity check failed for link ' . $linkId . ': ' . $exception->getMessage());
        audit('link.integrity_error', $recipient + ['details' => ['document_id' => (int) $link['document_id']]]);
        $pdo->commit();
        return 'The document is temporarily unavailable. Tell the sender.';
    }

    $pdo->prepare('UPDATE download_links SET download_count = download_count + 1 WHERE id = ?')->execute([$linkId]);
    audit('link.downloaded', $recipient + ['details' => ['document_id' => (int) $link['document_id'], 'sha256' => $link['sha256']]]);
    $pdo->commit();

    stream_document($link);
}

function stream_document(array $link): never
{
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    $name = (string) $link['original_name'];
    $fallback = preg_replace('/[^A-Za-z0-9._-]/', '_', $name) ?: 'document';
    header('Content-Type: ' . $link['mime_type']);
    header('Content-Length: ' . (int) $link['size_bytes']);
    header('Content-Disposition: attachment; filename="' . $fallback . '"; filename*=UTF-8\'\'' . rawurlencode($name));
    header("Content-Security-Policy: default-src 'none'; sandbox");
    set_time_limit(0);
    decrypt_file(UPLOAD_DIR . '/' . $link['stored_name'], $link['wrapped_key'], static function (string $chunk): void {
        echo $chunk;
        flush();
    });
    exit;
}

<?php
declare(strict_types=1);

/*
 * Retention maintenance (ISO 27002: 8.10, 5.33; ISO/IEC 27701).
 * - deletes documents that have had no valid links for longer than DOCUMENT_RETENTION_DAYS;
 * - deletes files without a database record (leftovers of interrupted uploads);
 * - anonymises IPs in the log older than IP_RETENTION_DAYS and deletes records older than AUDIT_RETENTION_DAYS.
 *
 * Once: php bin/maintenance.php        In a loop (maintenance service): php bin/maintenance.php --loop
 */

require dirname(__DIR__) . '/src/bootstrap.php';

function run_maintenance(): void
{
    $c = config();
    $pdo = db();

    $stmt = $pdo->prepare("SELECT d.id, d.stored_name, d.original_name, d.sha256 FROM documents d
        WHERE d.created_at < CURRENT_TIMESTAMP - make_interval(days => :days)
          AND NOT EXISTS (
              SELECT 1 FROM download_links l
              WHERE l.document_id = d.id
                AND (
                    (l.revoked_at IS NULL AND l.expires_at > CURRENT_TIMESTAMP AND l.download_count < l.max_downloads)
                    OR GREATEST(l.expires_at, COALESCE(l.revoked_at, l.expires_at)) > CURRENT_TIMESTAMP - make_interval(days => :days2)
                )
          )");
    $stmt->execute(['days' => $c['document_retention_days'], 'days2' => $c['document_retention_days']]);
    $deleted = 0;
    foreach ($stmt->fetchAll() as $document) {
        $pdo->prepare('DELETE FROM documents WHERE id = ?')->execute([$document['id']]);
        $path = UPLOAD_DIR . '/' . $document['stored_name'];
        if (is_file($path)) {
            unlink($path);
        }
        audit('document.retention_deleted', [
            'actor_type' => 'system',
            'actor_label' => 'maintenance',
            'object_type' => 'document',
            'object_id' => (int) $document['id'],
            'details' => ['name' => $document['original_name'], 'sha256' => $document['sha256'], 'retention_days' => $c['document_retention_days']],
        ]);
        $deleted++;
    }

    $known = array_flip($pdo->query('SELECT stored_name FROM documents')->fetchAll(PDO::FETCH_COLUMN));
    $orphans = 0;
    foreach (scandir(UPLOAD_DIR) ?: [] as $file) {
        $path = UPLOAD_DIR . '/' . $file;
        if (preg_match('/^[a-f0-9]{48}$/', $file) && !isset($known[$file]) && is_file($path) && filemtime($path) < time() - 86400) {
            unlink($path);
            $orphans++;
        }
    }

    $pdo->prepare('SELECT ghalam_apply_retention(?, ?, ?)')->execute([$c['audit_retention_days'], $c['ip_retention_days'], 30]);

    echo gmdate('c') . " maintenance: documents deleted={$deleted}, orphan files={$orphans}\n";
}

$loop = in_array('--loop', $argv, true);
do {
    run_maintenance();
    if ($loop) {
        sleep(3600);
    }
} while ($loop);

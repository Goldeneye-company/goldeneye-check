<?php
declare(strict_types=1);

/*
 * Audit log (ISO 27002: 8.15, 5.28).
 * The application may only INSERT and SELECT on audit_log; changes and deletions
 * are forbidden by grants and a trigger. Every event is also written to stderr as a JSON line
 * for collection by an external system (SIEM, syslog).
 */

const AUDIT_LABELS = [
    'auth.login' => 'Signed in',
    'auth.login_failed' => 'Failed sign-in',
    'auth.login_locked' => 'Sign-in locked',
    'auth.mfa_failed' => 'Wrong MFA code',
    'auth.mfa_enrolled' => 'MFA set up',
    'auth.logout' => 'Signed out',
    'auth.session_expired' => 'Session expired',
    'auth.password_changed' => 'Password changed',
    'document.uploaded' => 'Document uploaded',
    'document.upload_rejected' => 'Upload rejected',
    'document.malware_detected' => 'Malware detected',
    'document.deleted' => 'Document deleted',
    'document.retention_deleted' => 'Deleted by retention period',
    'link.created' => 'Link created',
    'link.revoked' => 'Link revoked',
    'link.auto_revoked' => 'Link locked',
    'link.downloaded' => 'Downloaded',
    'link.wrong_password' => 'Wrong password',
    'link.blocked' => 'Attempt while locked',
    'link.access_denied' => 'Access ended',
    'link.integrity_error' => 'Integrity error',
    'user.created' => 'User created',
    'user.disabled' => 'User disabled',
    'user.enabled' => 'User enabled',
    'user.mfa_reset' => 'MFA reset',
];

/**
 * @param array{actor_type?:string, actor_id?:?int, actor_label?:?string, object_type?:?string, object_id?:?int, details?:array} $options
 */
function audit(string $action, array $options = []): void
{
    $record = [
        'actor_type' => $options['actor_type'] ?? 'anonymous',
        'actor_id' => $options['actor_id'] ?? null,
        'actor_label' => isset($options['actor_label']) ? mb_substr((string) $options['actor_label'], 0, 255) : null,
        'action' => $action,
        'object_type' => $options['object_type'] ?? null,
        'object_id' => $options['object_id'] ?? null,
        'ip_address' => PHP_SAPI === 'cli' ? null : client_ip(),
        'details' => $options['details'] ?? [],
    ];
    $details = json_encode($record['details'], JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);

    $stmt = db()->prepare('INSERT INTO audit_log (actor_type, actor_id, actor_label, action, object_type, object_id, ip_address, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, CAST(? AS jsonb))');
    $stmt->execute([
        $record['actor_type'], $record['actor_id'], $record['actor_label'], $action,
        $record['object_type'], $record['object_id'], $record['ip_address'], $details,
    ]);

    error_log('AUDIT ' . json_encode(['ts' => gmdate('c')] + $record, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR));
}

function audit_employee(array $employee, string $action, ?string $objectType = null, ?int $objectId = null, array $details = []): void
{
    audit($action, [
        'actor_type' => 'employee',
        'actor_id' => (int) $employee['id'],
        'actor_label' => $employee['email'],
        'object_type' => $objectType,
        'object_id' => $objectId,
        'details' => $details,
    ]);
}

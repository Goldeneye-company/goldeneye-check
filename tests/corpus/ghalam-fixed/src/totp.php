<?php
declare(strict_types=1);

/*
 * TOTP per RFC 6238 (30 seconds, 6 digits, HMAC-SHA1): works with Google Authenticator,
 * Microsoft Authenticator, Aegis, FreeOTP and others (ISO 27002: 8.5).
 */

const TOTP_PERIOD = 30;
const TOTP_DIGITS = 6;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32_encode(string $data): string
{
    $bits = '';
    foreach (str_split($data) as $char) {
        $bits .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 5) as $chunk) {
        $out .= BASE32_ALPHABET[bindec(str_pad($chunk, 5, '0'))];
    }
    return $out;
}

function base32_decode(string $data): string
{
    $data = strtoupper(preg_replace('/[\s=-]/', '', $data) ?? '');
    $bits = '';
    foreach (str_split($data) as $char) {
        $index = strpos(BASE32_ALPHABET, $char);
        if ($index === false) {
            throw new InvalidArgumentException('Invalid base32 string');
        }
        $bits .= str_pad(decbin($index), 5, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) {
            $out .= chr(bindec($byte));
        }
    }
    return $out;
}

function totp_generate_secret(): string
{
    return base32_encode(random_bytes(20));
}

function totp_code(string $secretBase32, int $step): string
{
    $hmac = hash_hmac('sha1', pack('J', $step), base32_decode($secretBase32), true);
    $offset = ord($hmac[19]) & 0x0f;
    $binary = ((ord($hmac[$offset]) & 0x7f) << 24)
        | (ord($hmac[$offset + 1]) << 16)
        | (ord($hmac[$offset + 2]) << 8)
        | ord($hmac[$offset + 3]);
    return str_pad((string) ($binary % (10 ** TOTP_DIGITS)), TOTP_DIGITS, '0', STR_PAD_LEFT);
}

/**
 * Checks a code with a tolerance of one step either way. Returns the step number or null.
 * A code from an already used step is rejected (replay protection).
 */
function totp_verify(string $secretBase32, string $code, ?int $lastUsedStep): ?int
{
    $code = preg_replace('/\D/', '', $code) ?? '';
    if (strlen($code) !== TOTP_DIGITS) {
        return null;
    }
    $current = intdiv(time(), TOTP_PERIOD);
    for ($offset = -1; $offset <= 1; $offset++) {
        $step = $current + $offset;
        if ($lastUsedStep !== null && $step <= $lastUsedStep) {
            continue;
        }
        if (hash_equals(totp_code($secretBase32, $step), $code)) {
            return $step;
        }
    }
    return null;
}

function totp_uri(string $secretBase32, string $account): string
{
    return 'otpauth://totp/' . rawurlencode('GHALAM:' . $account)
        . '?secret=' . $secretBase32 . '&issuer=GHALAM&algorithm=SHA1&digits=' . TOTP_DIGITS . '&period=' . TOTP_PERIOD;
}

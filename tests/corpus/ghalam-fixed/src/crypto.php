<?php
declare(strict_types=1);

/*
 * Cryptography (ISO 27002: 8.24).
 * - Every document is encrypted with its own key (XChaCha20-Poly1305, libsodium stream mode).
 * - The document key is stored in the database encrypted with the master key (envelope encryption).
 *   The master key lives outside the document volume and outside the database (Docker secret).
 * - The SHA-256 of the original file is recorded on upload and checked before it is served.
 */

const FILE_MAGIC = 'GHL1';
const FILE_CHUNK = 65536;

function seal_secret(string $plain): string
{
    $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    return base64_encode($nonce . sodium_crypto_secretbox($plain, $nonce, config()['file_key']));
}

function open_secret(string $sealed): string
{
    $raw = base64_decode($sealed, true);
    $minLength = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES;
    if ($raw === false || strlen($raw) < $minLength) {
        throw new RuntimeException('The encrypted secret is damaged');
    }
    $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
    $plain = sodium_crypto_secretbox_open(substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES), $nonce, config()['file_key']);
    if ($plain === false) {
        throw new RuntimeException('The secret failed the integrity check');
    }
    return $plain;
}

/** The link token is stored only as a hash: a database leak gives no working links. */
function token_hash(string $token): string
{
    return hash('sha256', $token);
}

/** A random string from an alphabet without look-alike characters (0/O, 1/I/L). */
function random_code(int $length, int $groupSize = 4): string
{
    $alphabet = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
    $max = strlen($alphabet) - 1;
    $out = '';
    for ($i = 0; $i < $length; $i++) {
        if ($i > 0 && $groupSize > 0 && $i % $groupSize === 0) {
            $out .= '-';
        }
        $out .= $alphabet[random_int(0, $max)];
    }
    return $out;
}

/**
 * Encrypts a file with a new key. Returns [sha256 of the original, document key encrypted with the master key].
 *
 * @return array{0:string,1:string}
 */
function encrypt_file(string $source, string $destination): array
{
    $fileKey = sodium_crypto_secretstream_xchacha20poly1305_keygen();
    $size = filesize($source);
    $in = fopen($source, 'rb');
    $out = fopen($destination, 'xb');
    if ($size === false || $in === false || $out === false) {
        throw new RuntimeException('Could not open the file for encryption');
    }
    try {
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($fileKey);
        fwrite($out, FILE_MAGIC . $header);
        $hash = hash_init('sha256');
        $read = 0;
        do {
            $chunk = fread($in, FILE_CHUNK);
            if ($chunk === false) {
                throw new RuntimeException('Read error while encrypting the file');
            }
            $read += strlen($chunk);
            $final = $read >= $size || feof($in);
            $tag = $final
                ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL
                : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
            hash_update($hash, $chunk);
            if (fwrite($out, sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, '', $tag)) === false) {
                throw new RuntimeException('Write error for the encrypted file');
            }
        } while (!$final);
        if (!fflush($out)) {
            throw new RuntimeException('Write error for the encrypted file');
        }
        $digest = hash_final($hash);
    } finally {
        fclose($in);
        fclose($out);
        sodium_memzero($state);
    }
    $wrapped = seal_secret($fileKey);
    sodium_memzero($fileKey);
    return [$digest, $wrapped];
}

/**
 * Decrypts a file. When $sink is given, plaintext chunks are passed to it.
 * Returns the SHA-256 of the plaintext. Any change to the file throws an exception.
 */
function decrypt_file(string $path, string $wrappedKey, ?callable $sink = null): string
{
    $fileKey = open_secret($wrappedKey);
    $in = fopen($path, 'rb');
    if ($in === false) {
        throw new RuntimeException('The encrypted file was not found');
    }
    try {
        if (fread($in, strlen(FILE_MAGIC)) !== FILE_MAGIC) {
            throw new RuntimeException('Unknown encrypted file format');
        }
        $header = fread($in, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
        if ($header === false || strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
            throw new RuntimeException('The encrypted file header is damaged');
        }
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $fileKey);
        $hash = hash_init('sha256');
        do {
            $cipher = fread($in, FILE_CHUNK + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES);
            if ($cipher === false || $cipher === '') {
                throw new RuntimeException('The encrypted file is truncated');
            }
            $result = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $cipher);
            if ($result === false) {
                throw new RuntimeException('The file failed the integrity check');
            }
            [$plain, $tag] = $result;
            hash_update($hash, $plain);
            if ($sink !== null) {
                $sink($plain);
            }
        } while ($tag !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL);
        if (fread($in, 1) !== '') {
            throw new RuntimeException('Extra data after the end of the encrypted file');
        }
        return hash_final($hash);
    } finally {
        fclose($in);
        sodium_memzero($fileKey);
    }
}

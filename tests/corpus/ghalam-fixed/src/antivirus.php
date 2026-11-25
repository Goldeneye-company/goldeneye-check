<?php
declare(strict_types=1);

/*
 * Uploaded files are checked in ClamAV (clamd, INSTREAM command): ISO 27002: 8.7.
 * When the antivirus is required (CLAMAV_REQUIRED=true), uploads are rejected while it is unavailable.
 *
 * @return array{status:string, detail:string} status: clean | infected | error | skipped
 */
function antivirus_scan(string $path): array
{
    $c = config();
    if (!$c['clamav_enabled']) {
        return ['status' => 'skipped', 'detail' => 'ClamAV is disabled'];
    }
    $socket = @stream_socket_client(sprintf('tcp://%s:%d', $c['clamav_host'], $c['clamav_port']), $errno, $errstr, 5);
    if ($socket === false) {
        return ['status' => 'error', 'detail' => "clamd is unavailable: {$errstr}"];
    }
    try {
        stream_set_timeout($socket, 180);
        fwrite($socket, "zINSTREAM\0");
        $file = fopen($path, 'rb');
        if ($file === false) {
            return ['status' => 'error', 'detail' => 'could not open the file'];
        }
        while (!feof($file)) {
            $chunk = fread($file, 65536);
            if ($chunk === false || $chunk === '') {
                break;
            }
            if (fwrite($socket, pack('N', strlen($chunk)) . $chunk) === false) {
                fclose($file);
                return ['status' => 'error', 'detail' => 'clamd closed the connection'];
            }
        }
        fclose($file);
        fwrite($socket, pack('N', 0));
        $response = trim((string) stream_get_contents($socket), "\0\r\n ");
    } finally {
        fclose($socket);
    }

    if ($response === 'stream: OK') {
        return ['status' => 'clean', 'detail' => 'OK'];
    }
    if (str_ends_with($response, 'FOUND')) {
        $signature = trim(substr($response, strlen('stream:'), -strlen('FOUND')));
        return ['status' => 'infected', 'detail' => $signature];
    }
    return ['status' => 'error', 'detail' => $response === '' ? 'empty clamd response' : $response];
}

<?php

/**
 * N-PAMP conformance adapter (PHP). A "testee": it reads length-prefixed JSON
 * requests {op,in} on stdin and writes length-prefixed JSON responses
 * {out|error|skipped} on stdout, calling the OPEN PHP reference implementation
 * (impl/php/src/Npamp.php) for each operation -- it contains no protocol
 * logic of its own.
 *
 * Framing: 4-byte little-endian length N, then N bytes of JSON (repeat until EOF).
 * All byte-valued fields are lowercase hex strings.
 *
 * Windows note: php://stdin and php://stdout are binary streams (no CRLF
 * translation), and we flush after every response so the byte framing is not
 * corrupted. errors/warnings are routed to stderr only, never stdout.
 */

declare(strict_types=1);

error_reporting(E_ALL & ~E_DEPRECATED);
ini_set('display_errors', 'stderr');

require __DIR__ . '/../../../impl/php/src/Npamp.php';

use Sh\Bubblefish\Npamp\Frame;
use Sh\Bubblefish\Npamp\FrameException;
use Sh\Bubblefish\Npamp\Npamp;

/** Decode a lowercase-hex field from the input map (missing/empty -> ""). */
function hx(array $in, string $k): string
{
    $v = $in[$k] ?? '';
    if (!is_string($v) || $v === '') {
        return '';
    }
    $b = @hex2bin($v);
    return $b === false ? '' : $b;
}

/** Read an integer field. */
function iv(array $in, string $k): int
{
    return (int) ($in[$k] ?? 0);
}

/**
 * RFC 5869 HKDF-Expand from the reference implementation. The impl exposes this
 * as a private static method (the public surface is HKDF-Expand-LABEL, which
 * builds a TLS-style info string the contract does not want); we invoke the
 * private RFC-5869 routine directly via reflection so we exercise the reference
 * code, not a reimplementation.
 */
function refHkdfExpand(string $prk, string $info, int $length, string $algo): string
{
    static $method = null;
    if ($method === null) {
        $method = new ReflectionMethod(Npamp::class, 'hkdfExpand');
    }
    return $method->invoke(null, $prk, $info, $length, $algo);
}

/**
 * Dispatch one request to the reference implementation.
 *
 * @return array{out?:array,error?:string,skipped?:string}
 */
function handle(array $req): array
{
    $op = $req['op'] ?? '';
    $in = $req['in'] ?? [];
    if (!is_array($in)) {
        $in = [];
    }

    switch ($op) {
        case 'header.encode':
            // Build the 36-byte header from fields via the reference Frame:
            // prefix(21) | crc32c(prefix) (4 BE) | 11 reserved zero octets.
            $f = new Frame(
                iv($in, 'frameType'),
                iv($in, 'channel'),
                iv($in, 'seq'),
                iv($in, 'flags'),
                iv($in, 'ver'),
                ''
            );
            $prefix = $f->headerPrefix(iv($in, 'payloadLength'));
            $frame = $prefix
                . Npamp::uintToBytes(Npamp::crc32c($prefix), 4)
                . str_repeat("\0", Npamp::HEADER_SIZE - 25);
            return ['out' => ['frame' => Npamp::toHex($frame)]];

        case 'header.decode':
            $buf = hx($in, 'frame');
            try {
                $f = Frame::unmarshal($buf);
            } catch (FrameException $e) {
                return ['error' => $e->getMessage()];
            }
            // unmarshal validated magic/version/crc/reserved/length; surface the
            // header fields the contract asks for, reading crc/payloadLength from
            // the on-wire bytes.
            return ['out' => [
                'magic' => Npamp::MAGIC,
                'ver' => $f->version,
                'flags' => $f->flags,
                'frameType' => $f->ftype,
                'channel' => $f->channel,
                'seq' => $f->seq,
                'payloadLength' => Npamp::bytesToUint(substr($buf, 17, 4)),
                'crc32c' => Npamp::toHex(substr($buf, 21, 4)),
                'reservedZero' => true,
            ]];

        case 'crc32c':
            $octets = hx($in, 'octets');
            $crc = Npamp::crc32c($octets);
            return ['out' => ['crc32c' => Npamp::toHex(Npamp::uintToBytes($crc, 4))]];

        case 'aead.seal':
            if (($in['suite'] ?? null) !== 'AES-256-GCM') {
                return ['skipped' => 'suite not implemented: ' . ($in['suite'] ?? 'null')];
            }
            // deriveNonce(iv, seq=0) == iv, so pass the contract nonce as the IV
            // with seq 0 to seal under the exact nonce the corpus specifies.
            try {
                $sealed = Npamp::sealAes256Gcm(
                    hx($in, 'key'),
                    hx($in, 'nonce'),
                    0,
                    hx($in, 'aad'),
                    hx($in, 'pt')
                );
            } catch (\Throwable $e) {
                return ['error' => $e->getMessage()];
            }
            return ['out' => ['sealed' => Npamp::toHex($sealed)]];

        case 'aead.open':
            if (($in['suite'] ?? null) !== 'AES-256-GCM') {
                return ['skipped' => 'suite not implemented: ' . ($in['suite'] ?? 'null')];
            }
            try {
                $pt = Npamp::openAes256Gcm(
                    hx($in, 'key'),
                    hx($in, 'nonce'),
                    0,
                    hx($in, 'aad'),
                    hx($in, 'sealed')
                );
            } catch (\Throwable $e) {
                return ['error' => 'authentication failed'];
            }
            return ['out' => ['pt' => Npamp::toHex($pt)]];

        case 'hkdf.expand':
            $hash = $in['hash'] ?? null;
            if ($hash !== 'sha256' && $hash !== 'sha384') {
                return ['skipped' => 'hash not implemented: ' . (is_string($hash) ? $hash : 'null')];
            }
            $okm = refHkdfExpand(
                hx($in, 'prk'),
                hx($in, 'info'),
                iv($in, 'length'),
                $hash
            );
            return ['out' => ['okm' => Npamp::toHex($okm)]];

        case 'tlv.decode':
            // The OPEN PHP reference implements the frame layer and crypto, not a
            // standalone TLV decoder. Report Unimplemented rather than substitute
            // an adapter-local reimplementation.
            return ['skipped' => 'tlv.decode not in PHP reference implementation'];

        case 'profile.check':
            // No profile-acceptance routine exists in the PHP reference.
            return ['skipped' => 'profile.check not in PHP reference implementation'];

        default:
            return ['skipped' => 'op not implemented: ' . $op];
    }
}

function main(): void
{
    $rd = fopen('php://stdin', 'rb');
    $wr = fopen('php://stdout', 'wb');
    if ($rd === false || $wr === false) {
        fwrite(STDERR, "adapter: cannot open binary stdio\n");
        exit(1);
    }

    while (true) {
        $lp = '';
        // Read exactly 4 length bytes (handle short reads).
        while (strlen($lp) < 4) {
            $chunk = fread($rd, 4 - strlen($lp));
            if ($chunk === false || $chunk === '') {
                return; // EOF: runner closed stdin
            }
            $lp .= $chunk;
        }
        $n = unpack('V', $lp)[1];

        $body = '';
        while (strlen($body) < $n) {
            $chunk = fread($rd, $n - strlen($body));
            if ($chunk === false || $chunk === '') {
                return; // truncated
            }
            $body .= $chunk;
        }

        $req = json_decode($body, true);
        if (!is_array($req)) {
            $resp = ['error' => 'bad request json'];
        } else {
            try {
                $resp = handle($req);
            } catch (\Throwable $e) {
                $resp = ['error' => 'adapter exception: ' . $e->getMessage()];
            }
        }

        $ob = json_encode($resp);
        if ($ob === false) {
            $ob = '{"error":"adapter encode failure"}';
        }
        fwrite($wr, pack('V', strlen($ob)));
        fwrite($wr, $ob);
        fflush($wr);
    }
}

main();

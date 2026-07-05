<?php

/**
 * Conformance test for the N-PAMP PHP reference (draft-bubblefish-npamp-00).
 *
 * Reproduces the four cross-language golden vectors plus five property tests,
 * mirroring the Go/Rust/Java/Python/C# suites. Prints one line per check and
 * exits 0 on success, 1 if any check fails.
 *
 * Run from impl/php:  php test/ConformanceTest.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/Npamp.php';

use Sh\Bubblefish\Npamp\Frame;
use Sh\Bubblefish\Npamp\FrameException;
use Sh\Bubblefish\Npamp\Npamp;

$failures = 0;

function check(string $name, bool $ok): void
{
    global $failures;
    if ($ok) {
        echo "ok   - {$name}\n";
    } else {
        echo "FAIL - {$name}\n";
        $failures++;
    }
}

function ramp(int $start, int $count): string
{
    $out = '';
    for ($i = 0; $i < $count; $i++) {
        $out .= chr(($start + $i) & 0xFF);
    }
    return $out;
}

// --- cross-language vector reproduction (values from the Go reference) ---

$f = new Frame(Npamp::FRAME_PING, Npamp::CHAN_CONTROL, 0);
check('vec_header', Npamp::toHex($f->marshal())
    === '4e50414d20000100000000000000000000000000000d880c250000000000000000000000');

check('vec_nonce', Npamp::toHex(Npamp::deriveNonce(ramp(0x01, 12), 0x0102030405060708))
    === '010203040404040c0c0c0c04');

$key = ramp(0x00, 32);
$iv = ramp(0x10, 12);
$aad = (new Frame(Npamp::FRAME_PING, Npamp::CHAN_CONTROL))->headerPrefix(11);
$sealed = Npamp::sealAes256Gcm($key, $iv, 7, $aad, 'hello world');
check('vec_aead', Npamp::toHex($sealed)
    === '3fe8b79f95b5697926b3395429c2c2466999c652f9346aeebb30bf');

$master = str_repeat(chr(0x2A), 48);
$ts = Npamp::deriveTrafficSecret($master, 0, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_CONTROL, false);
[$tk] = Npamp::deriveKeyIv($ts, false);
check('vec_traffic_key', Npamp::toHex($tk)
    === '79372e2fb7f92d63e3a68099ff72514f310ebf6773deb0fa7ef45d013c652dcc');

// --- property tests (mirror the Go/Rust/Java suites) ---

$f = new Frame(0x0100, Npamp::CHAN_MEMORY, 42, Npamp::FLAG_ENC, 0, 'payload');
$g = Frame::unmarshal($f->marshal());
check('roundtrip', $g->flags === Npamp::FLAG_ENC && $g->ftype === 0x0100
    && $g->channel === Npamp::CHAN_MEMORY && $g->seq === 42 && $g->payload === 'payload');

// Corrupt the frame-type byte; CRC must reject before any field is trusted.
$buf = (new Frame(Npamp::FRAME_PING, Npamp::CHAN_CONTROL))->marshal();
$buf[5] = chr(ord($buf[5]) ^ 0xFF);
$rejected = false;
try {
    Frame::unmarshal($buf);
} catch (FrameException $e) {
    $rejected = ($e->getMessage() === 'bad crc');
}
check('crc_validated_first', $rejected);

// Set a reserved octet (byte 30). CRC covers only the 21-byte prefix, so it still
// passes; the reserved-zero check must then reject the frame.
$buf = (new Frame(Npamp::FRAME_PING, Npamp::CHAN_CONTROL))->marshal();
$buf[30] = chr(1);
$rejected = false;
try {
    Frame::unmarshal($buf);
} catch (FrameException $e) {
    $rejected = ($e->getMessage() === 'bad crc' || $e->getMessage() === 'reserved nonzero');
}
check('reserved_must_be_zero', $rejected);

// Seal, confirm open round-trips, then flip an AAD byte: open must reject.
$key = str_repeat("\0", 32);
$iv = ramp(0x10, 12);
$aad = (new Frame(Npamp::FRAME_PING, Npamp::CHAN_CONTROL))->headerPrefix(5);
$sealed = Npamp::sealAes256Gcm($key, $iv, 7, $aad, 'hello');
$openOk = (Npamp::openAes256Gcm($key, $iv, 7, $aad, $sealed) === 'hello');
$aad[5] = chr(ord($aad[5]) ^ 1);
$tamperRejected = false;
try {
    Npamp::openAes256Gcm($key, $iv, 7, $aad, $sealed);
} catch (\Throwable $e) {
    $tamperRejected = true;
}
check('aead_tamper_fails', $openOk && $tamperRejected);

check('hkdf_prefix_protocol_specific',
    Npamp::LABEL_PREFIX === 'n-pamp ' && Npamp::LABEL_PREFIX !== 'tls13 ');

echo $failures === 0 ? "ALL PASS (9/9)\n" : "FAILURES: {$failures}\n";
exit($failures === 0 ? 0 : 1);

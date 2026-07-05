<?php

/**
 * Standards-derived, NON-CIRCULAR known-answer test for the draft-00 Finished
 * verify_data (binding spec/10 section 6.2; RFC 8446 section 4.4.4):
 * verify_data = HMAC(finished_key, transcript_hash) under the profile hash
 * (SHA-256 at Standard). PHP mirror of the Go/Python/TS reference tests against
 * the SAME pinned vector (test-vectors/v1/finished-kat.json).
 *
 * Three legs:
 *   ANCHOR - HMAC-SHA-256 reproduces RFC 4231 TC1/TC2.
 *   ORACLE - an independent hash_hmac (no computeFinished) reproduces verify_data,
 *            guarding the vector.
 *   IMPL   - computeFinished reproduces verify_data; verifyFinished accepts the
 *            correct MAC and rejects a tampered one, guarding the impl.
 *
 * Run from impl/php:  php test/finished_kat.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/Npamp.php';

use Sh\Bubblefish\Npamp\Handshake;

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

const VEC_DIR = __DIR__ . '/../../../test-vectors/v1';
const FINISHED_KAT_SHA256 = '25c21b0bd3b3b6b77862f4a819f81ff5e4ff42e4b1d70af81feeedc5aad73c7f';

/** Load and SHA-256-pin the vector (fail loud on a swapped/corrupt vector). */
function loadKat(): array
{
    $raw = @file_get_contents(VEC_DIR . '/finished-kat.json');
    if ($raw === false) {
        fwrite(STDERR, "cannot read finished-kat.json\n");
        exit(2);
    }
    $got = hash('sha256', $raw);
    if (!hash_equals(FINISHED_KAT_SHA256, $got)) {
        fwrite(STDERR, "Finished KAT vector SHA-256 mismatch (swapped vector?): {$got}\n");
        exit(2);
    }
    return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
}

function hx(string $s): string
{
    $out = $s === '' ? '' : hex2bin($s);
    if ($out === false) {
        fwrite(STDERR, "bad hex: {$s}\n");
        exit(2);
    }
    return $out;
}

/** Standard HMAC-SHA-256, independent of computeFinished. */
function hmacOracle(string $key, string $data): string
{
    return hash_hmac('sha256', $data, $key, true);
}

$k = loadKat();

// --- ANCHOR: HMAC-SHA-256 reproduces the RFC 4231 TC1/TC2 published MACs. ---
foreach (['tc1', 'tc2'] as $label) {
    $tc = $k['rfc4231_hmac_sha256'][$label];
    $got = bin2hex(hmacOracle(hx($tc['key']), hx($tc['data'])));
    check("finished anchor: HMAC-SHA-256 RFC 4231 {$label}", $got === $tc['hmac_sha256']);
}

$nn = $k['npamp_inputs'];
$e = $k['expected'];

// --- ORACLE: independent hash_hmac reproduces verify_data. ---
check('finished oracle: verify_data_server',
    bin2hex(hmacOracle(hx($nn['finished_key_server']), hx($nn['th_scv']))) === $e['verify_data_server']);
check('finished oracle: verify_data_client',
    bin2hex(hmacOracle(hx($nn['finished_key_client']), hx($nn['th_ccv']))) === $e['verify_data_client']);

// --- IMPL: computeFinished + verifyFinished accept/reject. ---
$cases = [
    ['server', $nn['finished_key_server'], $nn['th_scv'], $e['verify_data_server']],
    ['client', $nn['finished_key_client'], $nn['th_ccv'], $e['verify_data_client']],
];
foreach ($cases as [$name, $fkHex, $thHex, $want]) {
    $fk = hx($fkHex);
    $th = hx($thHex);
    $wantB = hx($want);

    check("finished impl: computeFinished {$name}",
        bin2hex(Handshake::computeFinished($fk, $th, true)) === $want);
    check("finished impl: verifyFinished accepts correct {$name}",
        Handshake::verifyFinished($fk, $th, $wantB, true));

    $bad = $wantB;
    $bad[0] = chr(ord($bad[0]) ^ 0x01);
    check("finished impl: verifyFinished rejects tampered {$name}",
        !Handshake::verifyFinished($fk, $th, $bad, true));
}

echo $failures === 0 ? "ALL PASS\n" : "FAILURES: {$failures}\n";
exit($failures === 0 ? 0 : 1);

<?php

/**
 * Standards-derived, NON-CIRCULAR known-answer test for the draft-00 transcript
 * construction (binding spec/10 section 3). PHP mirror of the Go/Python/TS
 * reference tests against the SAME pinned, FIPS-180-4-anchored vector
 * (test-vectors/v1/transcript-kat.json).
 *
 * Three legs:
 *   ANCHOR - SHA-256("abc") == FIPS 180-4, proving the hash primitive first.
 *   ORACLE - an in-test manual byte-constructor (no Transcript) reproduces every
 *            TH_*, guarding the vector against corruption.
 *   IMPL   - the real Transcript type reproduces every TH_*, guarding the impl.
 *
 * Absorption is driven straight from the vector's frame/TLV order; the cut points
 * are encoded as a (frame index, TLV index) -> transcript-hash name map, which IS
 * the spec section 3 structure (no TLV names are hardcoded).
 *
 * Run from impl/php:  php test/transcript_kat.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/Npamp.php';

use Sh\Bubblefish\Npamp\Handshake;
use Sh\Bubblefish\Npamp\Transcript;

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
const TRANSCRIPT_KAT_SHA256 = 'fab6d852497b6ff56405595e9a014d0c45cabc5cde80a60a17444b337d556ee5';

// (frame index : TLV index within that frame) -> transcript-hash point name.
const CUT_POINTS = [
    '1:4' => 'th_kem',
    '2:0' => 'th_sid',
    '2:1' => 'th_scv',
    '3:0' => 'th_cid',
    '3:1' => 'th_ccv',
];
const POINT_ORDER = ['th_kem', 'th_sid', 'th_scv', 'th_cid', 'th_ccv'];

/** Load and SHA-256-pin the vector (fail loud on a swapped/corrupt vector). */
function loadKat(): array
{
    $raw = @file_get_contents(VEC_DIR . '/transcript-kat.json');
    if ($raw === false) {
        fwrite(STDERR, "cannot read transcript-kat.json\n");
        exit(2);
    }
    $got = hash('sha256', $raw);
    if (!hash_equals(TRANSCRIPT_KAT_SHA256, $got)) {
        fwrite(STDERR, "transcript KAT vector SHA-256 mismatch (swapped vector?): {$got}\n");
        exit(2);
    }
    return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
}

function trimHex(string $s): string
{
    return strncasecmp($s, '0x', 2) === 0 ? substr($s, 2) : $s;
}

/**
 * Walk the vector frames/TLVs IN ORDER, snapshotting at each spec section 3 cut
 * point. The three legs supply their own absorb/snapshot closures; the sequence
 * and cut points come from the vector, never from hardcoded TLV names.
 *
 * @return array<string,string> point name -> hex digest
 */
function drive(array $k, callable $addFrameType, callable $addTlv, callable $snap): array
{
    $points = [];
    foreach ($k['frames'] as $fi => $f) {
        $addFrameType(intval(trimHex($f['frame_type']), 16));
        foreach ($f['tlvs'] as $ti => $tl) {
            $val = hex2bin($tl['value']);
            if ($val === false) {
                fwrite(STDERR, "bad TLV hex at frame {$fi} tlv {$ti}\n");
                exit(2);
            }
            $addTlv(intval(trimHex($tl['type']), 16), $val);
            $key = "{$fi}:{$ti}";
            if (isset(CUT_POINTS[$key])) {
                $points[CUT_POINTS[$key]] = $snap();
            }
        }
    }
    return $points;
}

/** Assert every cut point (hex) equals the vector's expected_transcript_points. */
function checkPoints(string $leg, array $k, array $points): void
{
    $exp = $k['expected_transcript_points'];
    check("transcript {$leg}: all 5 cut points present", count($points) === count(POINT_ORDER));
    foreach (POINT_ORDER as $name) {
        $got = $points[$name] ?? '(missing)';
        check("transcript {$leg}: {$name}", $got === $exp[$name]);
    }
}

$k = loadKat();

// --- ANCHOR: the test's SHA-256 reproduces the FIPS 180-4 SHA-256("abc") KAT. ---
$fips = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
$abc = $k['fips180_4_sha256_abc'];
check('transcript anchor: SHA-256("abc") == FIPS 180-4',
    hash('sha256', $abc['input_ascii']) === $fips && $abc['digest'] === $fips);

// --- ORACLE: manual big-endian byte-constructor (pack), no Transcript. ---
$buf = '';
$oracleFt = function (int $v) use (&$buf): void {
    $buf .= pack('n', $v & 0xFFFF);
};
$oracleTlv = function (int $t, string $val) use (&$buf): void {
    $buf .= pack('n', $t & 0xFFFF) . pack('n', strlen($val)) . $val;
};
$oracleSnap = function () use (&$buf): string {
    return hash('sha256', $buf);
};
checkPoints('oracle', $k, drive($k, $oracleFt, $oracleTlv, $oracleSnap));

// --- IMPL: the real Transcript type. ---
check('transcript impl: frame-type constants match spec section 1 code points',
    Handshake::FRAME_CLIENT_HELLO === 0x0100
    && Handshake::FRAME_SERVER_HELLO === 0x0101
    && Handshake::FRAME_SERVER_AUTH === 0x0102
    && Handshake::FRAME_CLIENT_AUTH === 0x0103);

$tr = new Transcript();
$implFt = function (int $v) use ($tr): void {
    $tr->addFrameType($v);
};
$implTlv = function (int $t, string $val) use ($tr): void {
    $tr->addTlv($t, $val);
};
$implSnap = function () use ($tr): string {
    return bin2hex($tr->hash(true));
};
checkPoints('impl', $k, drive($k, $implFt, $implTlv, $implSnap));

echo $failures === 0 ? "ALL PASS\n" : "FAILURES: {$failures}\n";
exit($failures === 0 ? 0 : 1);

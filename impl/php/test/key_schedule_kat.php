<?php

/**
 * Standards-derived, NON-CIRCULAR known-answer test for the draft-00 key
 * schedule (binding spec/10 section 5; draft-00 section 7.4 HKDF-Expand-Label +
 * section 7.5 traffic keys). PHP mirror of the Go/Python/TS reference tests
 * against the SAME pinned vector (test-vectors/v1/key-schedule-kat.json).
 *
 * The vector stores NO N-PAMP output bytes (those would be circular). It stores
 * external RFC anchors and fixed inputs only; the test proves its own oracle
 * against the RFC vectors, then judges the impl with that proven oracle.
 *
 * Three legs:
 *   ANCHOR - raw HKDF-Extract/Expand reproduce RFC 5869 TC1 (prk + okm). The
 *            impl's hkdfExtract is anchored to the same prk.
 *   ORACLE - an INDEPENDENT in-test HKDF-Expand-Label (which rebuilds the
 *            HkdfLabel bytes itself, prefix as a parameter, and never calls the
 *            impl) reproduces RFC 8448's key/iv/finished under the "tls13 "
 *            prefix, guarding the construction MECHANISM and the vector.
 *   IMPL   - the new key-schedule functions (hkdfExtract, deriveHandshakeSecret,
 *            deriveClient/ServerHandshakeSecret, deriveMasterSecret,
 *            deriveFinishedKey) and the existing deriveTrafficSecret/deriveKeyIv
 *            reproduce the proven oracle applied with the "n-pamp " prefix.
 *
 * Run from impl/php:  php test/key_schedule_kat.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/Npamp.php';

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

const VEC_DIR = __DIR__ . '/../../../test-vectors/v1';
const KEY_SCHEDULE_KAT_SHA256 = 'e108f5cfdf99a378d7b677792448c8046abf3c630fc23fd8ea2ccb3927f2691c';

// AES-256-GCM = 0x0001 per registries/aead.csv (= the impl's AEAD_AES256_GCM =
// npamp.AEADAES256GCM in the Go reference); 0x0002 is ChaCha20-Poly1305. The
// draft-00 section 7.5 traffic context binds this AEAD code point. The KAT and
// its oracle bind it via Npamp::AEAD_AES256_GCM -- the exact symbol the sibling
// ConformanceTest passes to deriveTrafficSecret -- never a magic literal.
// Direction octet for the server->client traffic secret (draft-00 section 7.5).
const KS_DIR_SERVER_TO_CLIENT = 0x01;

/** Load and SHA-256-pin the vector (fail loud on a swapped/corrupt vector). */
function loadKat(): array
{
    $raw = @file_get_contents(VEC_DIR . '/key-schedule-kat.json');
    if ($raw === false) {
        fwrite(STDERR, "cannot read key-schedule-kat.json\n");
        exit(2);
    }
    $got = hash('sha256', $raw);
    if (!hash_equals(KEY_SCHEDULE_KAT_SHA256, $got)) {
        fwrite(STDERR, "key-schedule KAT vector SHA-256 mismatch (swapped vector?): {$got}\n");
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

// --- Independent oracle primitives (SHA-256, no calls into the impl). ---

/** Raw HKDF-Extract (RFC 5869 section 2.2): PRK = HMAC-Hash(salt, IKM). */
function extractOracle(string $salt, string $ikm): string
{
    return hash_hmac('sha256', $ikm, $salt, true);
}

/** Raw HKDF-Expand (RFC 5869 section 2.3): OKM = T(1) | T(2) | ... truncated to L. */
function expandOracle(string $prk, string $info, int $length): string
{
    $hashLen = 32;
    $n = intdiv($length + $hashLen - 1, $hashLen);
    if ($n > 255) {
        fwrite(STDERR, "expandOracle: length too large\n");
        exit(2);
    }
    $okm = '';
    $t = '';
    for ($i = 1; $i <= $n; $i++) {
        $t = hash_hmac('sha256', $t . $info . chr($i), $prk, true);
        $okm .= $t;
    }
    return substr($okm, 0, $length);
}

/**
 * Independent HKDF-Expand-Label (RFC 8446 section 7.1) with the label PREFIX as a
 * parameter. Rebuilds HkdfLabel = uint16(L) | uint8(len(prefix+label)) |
 * (prefix+label) | uint8(len(context)) | context from the spec, then calls the
 * raw expand oracle. Deliberately does NOT call Npamp::hkdfExpandLabel, so the
 * two must agree independently.
 */
function expandLabelOracle(string $secret, string $prefix, string $label, string $context, int $length): string
{
    $full = $prefix . $label;
    $info = pack('n', $length)
        . chr(strlen($full)) . $full
        . chr(strlen($context)) . $context;
    return expandOracle($secret, $info, $length);
}

$k = loadKat();

// --- ANCHOR: raw HKDF-Extract/Expand reproduce RFC 5869 TC1. ---
$tc = $k['rfc5869_tc1'];
$prkAnchor = extractOracle(hx($tc['salt']), hx($tc['ikm']));
check('key-schedule anchor: HKDF-Extract == RFC 5869 TC1 prk',
    bin2hex($prkAnchor) === $tc['prk']);
check('key-schedule anchor: HKDF-Expand == RFC 5869 TC1 okm',
    bin2hex(expandOracle($prkAnchor, hx($tc['info']), (int) $tc['L'])) === $tc['okm']);
// The impl's new HKDF-Extract is anchored to the same published PRK.
check('key-schedule anchor: impl hkdfExtract == RFC 5869 TC1 prk',
    bin2hex(Npamp::hkdfExtract(hx($tc['salt']), hx($tc['ikm']), true)) === $tc['prk']);

// --- ORACLE: the independent Expand-Label reproduces RFC 8448 (tls13 prefix). ---
$r = $k['rfc8448_expand_label'];
$tlsSecret = hx($r['client_handshake_traffic_secret']);
check('key-schedule oracle: expandLabel(tls13 ,"key") == RFC 8448 write_key',
    bin2hex(expandLabelOracle($tlsSecret, 'tls13 ', 'key', '', 16)) === $r['write_key']);
check('key-schedule oracle: expandLabel(tls13 ,"iv") == RFC 8448 write_iv',
    bin2hex(expandLabelOracle($tlsSecret, 'tls13 ', 'iv', '', 12)) === $r['write_iv']);
check('key-schedule oracle: expandLabel(tls13 ,"finished") == RFC 8448 finished_key',
    bin2hex(expandLabelOracle($tlsSecret, 'tls13 ', 'finished', '', 32)) === $r['finished_key']);

// --- IMPL: the new key-schedule functions reproduce the proven oracle with the
//           "n-pamp " prefix. Goldens are computed by the oracle, never hardcoded.
$nn = $k['npamp_inputs'];
$P = Npamp::LABEL_PREFIX; // "n-pamp "
check('key-schedule impl: LABEL_PREFIX is "n-pamp "', $P === 'n-pamp ');

$mlkemSs = hx($nn['ikm_mlkem_ss']);
$x25519Ss = hx($nn['ikm_x25519_ss']);
$thKem = hx($nn['th_kem']);
$thCcv = hx($nn['th_ccv']);
$zeros32 = str_repeat("\0", 32);

// handshake_secret = HKDF-Extract(32 zero octets, ML-KEM_SS || X25519_SS).
$hsOracle = extractOracle($zeros32, $mlkemSs . $x25519Ss);
$hsImpl = Npamp::deriveHandshakeSecret($mlkemSs, $x25519Ss, true);
check('key-schedule impl: handshake_secret == extractOracle(zeros32, mlkem||x25519)',
    $hsImpl === $hsOracle);

// c_hs / s_hs / master against the oracle applied with the "n-pamp " prefix.
$cHs = Npamp::deriveClientHandshakeSecret($hsImpl, $thKem, true);
$sHs = Npamp::deriveServerHandshakeSecret($hsImpl, $thKem, true);
$master = Npamp::deriveMasterSecret($hsImpl, $thCcv, true);
check('key-schedule impl: c_hs == oracle(hs,"n-pamp ","c hs",th_kem,32)',
    $cHs === expandLabelOracle($hsImpl, $P, 'c hs', $thKem, 32));
check('key-schedule impl: s_hs == oracle(hs,"n-pamp ","s hs",th_kem,32)',
    $sHs === expandLabelOracle($hsImpl, $P, 's hs', $thKem, 32));
check('key-schedule impl: master == oracle(hs,"n-pamp ","master",th_ccv,32)',
    $master === expandLabelOracle($hsImpl, $P, 'master', $thCcv, 32));

// finished_key for each direction (client from c_hs, server from s_hs).
check('key-schedule impl: finished_key(c_hs) == oracle(c_hs,"n-pamp ","finished","",32)',
    Npamp::deriveFinishedKey($cHs, true) === expandLabelOracle($cHs, $P, 'finished', '', 32));
check('key-schedule impl: finished_key(s_hs) == oracle(s_hs,"n-pamp ","finished","",32)',
    Npamp::deriveFinishedKey($sHs, true) === expandLabelOracle($sHs, $P, 'finished', '', 32));

// s2c handshake AEAD via the existing deriveTrafficSecret/deriveKeyIv, against
// an oracle-computed key/iv (dir=ServerToClient, epoch=0, suite=AES-256-GCM,
// channel=Control).
$tsImpl = Npamp::deriveTrafficSecret($sHs, KS_DIR_SERVER_TO_CLIENT, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_CONTROL, true);
[$keyImpl, $ivImpl] = Npamp::deriveKeyIv($tsImpl, true);

$ctxOracle = chr(KS_DIR_SERVER_TO_CLIENT)
    . pack('J', 0)                       // epoch (u64 BE)
    . pack('n', Npamp::AEAD_AES256_GCM)  // suite (u16 BE)
    . pack('n', Npamp::CHAN_CONTROL);    // channel (u16 BE)
$tsOracle = expandLabelOracle($sHs, $P, 'traffic', $ctxOracle, 32);
$keyOracle = expandLabelOracle($tsOracle, $P, 'key', '', 32);
$ivOracle = expandLabelOracle($tsOracle, $P, 'iv', '', 12);

check('key-schedule impl: s2c handshake key == oracle key', $keyImpl === $keyOracle);
check('key-schedule impl: s2c handshake iv == oracle iv', $ivImpl === $ivOracle);

echo $failures === 0 ? "ALL PASS\n" : "FAILURES: {$failures}\n";
exit($failures === 0 ? 0 : 1);

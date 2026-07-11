<?php

/**
 * Standards-derived, NON-CIRCULAR known-answer test for the draft-00 CertVerify
 * (binding spec/10 section 6.1; RFC 8446 section 4.4.3 structure; Ed25519 per
 * RFC 8032). The value is u16(0x0807) | Ed25519(priv, signing_input), with
 * signing_input = 64*0x20 | context | 0x00 | TH. PHP mirror of the Go/Python/TS
 * reference tests against the SAME pinned vector (test-vectors/v1/certverify-kat.json).
 *
 * Three legs:
 *   ANCHOR - the Ed25519 primitive reproduces RFC 8032 TEST1/TEST2 (pubkey +
 *            deterministic signature).
 *   ORACLE - rebuild signing_input by hand and sign with an independently
 *            constructed key (no src signing functions), guarding the vector.
 *   IMPL   - certVerifySigningInput + signCertVerify reproduce the vector;
 *            verifyCertVerify accepts the correct value but rejects a
 *            role/context mismatch, a wrong transcript, a wrong scheme, and a
 *            truncated signature, guarding the impl.
 *
 * Ed25519 is provided by ext-sodium (bundled with PHP). Run from impl/php:
 *   php test/certverify_kat.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/Npamp.php';

use Sh\Bubblefish\Npamp\Handshake;

// ext-sodium ships with PHP (bundled since 7.2) but may be disabled in php.ini;
// load it for this CLI run so the bare `php test/certverify_kat.php` works.
if (!extension_loaded('sodium')) {
    $dll = PHP_SHLIB_SUFFIX === 'dll' ? 'php_sodium.dll' : 'sodium.' . PHP_SHLIB_SUFFIX;
    @dl($dll);
}
if (!function_exists('sodium_crypto_sign_detached')) {
    fwrite(STDERR, "ext-sodium not available; cannot run the Ed25519 CertVerify KAT\n");
    exit(2);
}

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
const CERTVERIFY_KAT_SHA256 = '19afd438c3036fd7d51481e5e6e91cc73010d76cb94aa2082c7752c8ba714d3f';

/** Load and SHA-256-pin the vector (fail loud on a swapped/corrupt vector). */
function loadKat(): array
{
    $raw = @file_get_contents(VEC_DIR . '/certverify-kat.json');
    if ($raw === false) {
        fwrite(STDERR, "cannot read certverify-kat.json\n");
        exit(2);
    }
    $got = hash('sha256', $raw);
    if (!hash_equals(CERTVERIFY_KAT_SHA256, $got)) {
        fwrite(STDERR, "CertVerify KAT vector SHA-256 mismatch (swapped vector?): {$got}\n");
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

/** Oracle signing-input builder, independent of certVerifySigningInput. */
function oracleSigningInput(string $ctx, string $th): string
{
    return str_repeat("\x20", 64) . $ctx . "\x00" . $th;
}

$k = loadKat();
$nn = $k['npamp_inputs'];
$e = $k['expected'];
$c = $k['contexts'];

// --- ANCHOR: Ed25519 reproduces RFC 8032 TEST1/TEST2 (pubkey + signature). ---
foreach (['test1', 'test2'] as $label) {
    $v = $k['rfc8032_ed25519'][$label];
    // The src key helper derives sk from the seed; the signature uses the sodium
    // primitive directly (no src signing functions) so this leg stays independent
    // of signCertVerify.
    $sk = Handshake::ed25519SecretKeyFromSeed(hx($v['seed']));
    $kp = sodium_crypto_sign_seed_keypair(hx($v['seed']));
    $pk = sodium_crypto_sign_publickey($kp);
    check("certverify anchor: {$label} pubkey == RFC 8032",
        bin2hex($pk) === $v['public_key']);
    check("certverify anchor: {$label} signature == RFC 8032",
        bin2hex(sodium_crypto_sign_detached(hx($v['message']), $sk)) === $v['signature']);
    check("certverify anchor: {$label} verify round-trips",
        sodium_crypto_sign_verify_detached(hx($v['signature']), hx($v['message']), hx($v['public_key'])));
}

// --- ORACLE: hand-built signing_input + independent sodium signature. ---
$oracleCases = [
    ['server', $c['server'], $nn['server_seed'], $nn['th_sid'], $e['signing_input_server'], $e['signature_server']],
    ['client', $c['client'], $nn['client_seed'], $nn['th_cid'], $e['signing_input_client'], $e['signature_client']],
];
foreach ($oracleCases as [$name, $ctx, $seedHex, $thHex, $wantSi, $wantSig]) {
    $si = oracleSigningInput($ctx, hx($thHex));
    check("certverify oracle: {$name} signing_input == vector",
        bin2hex($si) === $wantSi);
    $kp = sodium_crypto_sign_seed_keypair(hx($seedHex));
    $sk = sodium_crypto_sign_secretkey($kp);
    check("certverify oracle: {$name} signature == vector",
        bin2hex(sodium_crypto_sign_detached($si, $sk)) === $wantSig);
}

// --- IMPL: signing input + value reproduction + accept/reject behaviour. ---
check('certverify impl: server context constant matches spec section 6.1',
    Handshake::CONTEXT_SERVER_CERTVERIFY === $c['server']);
check('certverify impl: client context constant matches spec section 6.1',
    Handshake::CONTEXT_CLIENT_CERTVERIFY === $c['client']);

$implCases = [
    ['server', true, $nn['server_seed'], $nn['server_pub'], $nn['th_sid'], $e['signing_input_server'], $e['certverify_value_server']],
    ['client', false, $nn['client_seed'], $nn['client_pub'], $nn['th_cid'], $e['signing_input_client'], $e['certverify_value_client']],
];
foreach ($implCases as [$name, $isServer, $seedHex, $pubHex, $thHex, $wantSi, $wantVal]) {
    $sk = Handshake::ed25519SecretKeyFromSeed(hx($seedHex));
    $pub = hx($pubHex);
    $th = hx($thHex);

    check("certverify impl: {$name} certVerifySigningInput == vector",
        bin2hex(Handshake::certVerifySigningInput($isServer, $th)) === $wantSi);

    $val = Handshake::signCertVerify($sk, $isServer, $th);
    check("certverify impl: {$name} signCertVerify value == vector",
        bin2hex($val) === $wantVal);

    check("certverify impl: {$name} verifyCertVerify accepts correct value",
        Handshake::verifyCertVerify($pub, $isServer, $th, $val));

    // Domain separation: the opposite role must FAIL (different context string).
    check("certverify impl: {$name} rejects role/context mismatch",
        !Handshake::verifyCertVerify($pub, !$isServer, $th, $val));

    // Transcript binding: a different transcript hash must FAIL.
    $wrongTh = $th;
    $wrongTh[0] = chr(ord($wrongTh[0]) ^ 0x01);
    check("certverify impl: {$name} rejects wrong transcript",
        !Handshake::verifyCertVerify($pub, $isServer, $wrongTh, $val));

    // Scheme guard: a non-Ed25519 scheme code point (0x0905) must FAIL.
    $badScheme = $val;
    $badScheme[0] = "\x09";
    $badScheme[1] = "\x05";
    check("certverify impl: {$name} rejects non-Ed25519 scheme",
        !Handshake::verifyCertVerify($pub, $isServer, $th, $badScheme));

    // Length guard: an Ed25519 signature is exactly 64 octets; a truncated value must FAIL.
    check("certverify impl: {$name} rejects truncated signature",
        !Handshake::verifyCertVerify($pub, $isServer, $th, substr($val, 0, strlen($val) - 1)));
}

echo $failures === 0 ? "ALL PASS\n" : "FAILURES: {$failures}\n";
exit($failures === 0 ? 0 : 1);

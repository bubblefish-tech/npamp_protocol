<?php

/**
 * Byte-pinned handshake-flow known-answer test (issue #60, class golden-interop).
 * PHP mirror of the Go reference verifier (impl/go/handshakeflow_kat_test.go)
 * against the SAME frozen vector (test-vectors/v1/handshake-flow-kat.json).
 *
 * Unlike the standards-anchored primitive KATs (transcript/key-schedule/
 * certverify/finished), this vector pins the Go reference's SERIALIZED handshake
 * frames, so every language impl must reproduce them byte-for-byte. The
 * CLIENT_HELLO whole-frame assertion below is the one that catches the
 * draft-00-vs-draft-01 ProfileOffer wire drift: the draft-01 ProfileOffer is a
 * list of one-octet Profile code points, so a single-profile offer is exactly
 * ONE octet (0x01). An impl emitting a fixed 4-octet ProfileOffer (or any other
 * draft-00 encoding) fails this test instead of a live handshake.
 *
 * From the six fixed seeds the flow is fully determined. This PHP impl is the
 * OPEN protocol layer only (framing, registries, AEAD record layer, key
 * schedule, transcript, Finished, CertVerify): it has no ML-KEM primitive, and
 * its bundled X25519 comes from ext-sodium. Two consequences, both matching the
 * vector's own provenance note:
 *
 *   - The ML-KEM shared secret is a PINNED, self-validating input. PHP cannot
 *     decapsulate inputs.mlkem_ciphertext (no ML-KEM in ext-sodium, and even
 *     Go's public crypto/mlkem cannot re-encapsulate a captured ciphertext), so
 *     this test asserts the KEM WIRE STRUCTURE — kem_ciphertext = ML-KEM
 *     ciphertext(1088) || server X25519 public(32), and kem_share = ML-KEM
 *     encapsulation key(1184) || client X25519 public(32) — and feeds the pinned
 *     mlkem_shared_secret into the real key schedule.
 *   - The X25519 shared secret IS re-derivable here: this test recomputes
 *     X25519(client_priv, server_pub) via ext-sodium and asserts it equals the
 *     pinned x25519_shared_secret (and that both public keys sit in the pinned
 *     KEM wire bytes), so the classical leg is independently verified, not
 *     trusted.
 *
 * Everything else — the four handshake frames (whole-frame byte-equality), both
 * AUTH plaintexts, the five transcript points, the full section 5 key ladder,
 * the Finished keys/MACs, the CertVerify signatures — is rebuilt through this
 * impl's real code path (Frame::marshal, Transcript, Npamp key schedule,
 * Npamp::sealAes256Gcm, Handshake::signCertVerify/computeFinished) from the
 * pinned inputs and asserted byte-for-byte. Two mutation guards (a one-octet
 * flip in the server CertVerify signature AND in the client Finished MAC) must
 * REJECT.
 *
 * ext-sodium ships with PHP (bundled since 7.2) but may be disabled in php.ini;
 * this test loads it for the CLI run so bare `php test/handshake_flow_kat.php`
 * works. Run from impl/php:  php test/handshake_flow_kat.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/Npamp.php';

use Sh\Bubblefish\Npamp\Frame;
use Sh\Bubblefish\Npamp\Handshake;
use Sh\Bubblefish\Npamp\Npamp;
use Sh\Bubblefish\Npamp\Transcript;

// ext-sodium provides Ed25519 (CertVerify identities) and X25519 (the classical
// KEM leg). Load it for this CLI run if php.ini left it disabled.
if (!extension_loaded('sodium')) {
    $dll = PHP_SHLIB_SUFFIX === 'dll' ? 'php_sodium.dll' : 'sodium.' . PHP_SHLIB_SUFFIX;
    @dl($dll);
}
if (!function_exists('sodium_crypto_sign_detached') || !function_exists('sodium_crypto_scalarmult')) {
    fwrite(STDERR, "ext-sodium (Ed25519 + X25519) not available; cannot run the handshake-flow KAT\n");
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
const HANDSHAKE_FLOW_KAT_SHA256 = 'cf1d3c1fba550f3742e4de16d0f86d3beeafeb56efff90f85ff16165063c0fc9';

// Standard profile: SHA-256 KDF hash. The impl's key schedule takes a boolean
// "standard" flag; at Standard it is true.
const STANDARD = true;

// Negotiated code points for the pinned flow (registries/*.csv), taken from the
// impl's own symbols so a registry drift is caught, never a magic literal.
// Profile "Standard" is code point 0x01 (spec section 2 / profiles registry).
const PROFILE_STANDARD = 0x01;

// Handshake TLV type code points (tlv registry section 9.4). The impl's Npamp
// class exposes only the two it needs directly; the full handshake set is fixed
// by the spec and reproduced here so the frame byte layout is explicit.
const T_PROFILE_OFFER  = 0x01;
const T_PROFILE_SELECT = 0x02;
const T_KEM_OFFER      = 0x03;
const T_KEM_SELECT     = 0x04;
const T_SIG_OFFER      = 0x05;
const T_SIG_SELECT     = 0x06;
const T_KEM_SHARE      = 0x07;
const T_KEM_CIPHERTEXT = 0x08;
const T_IDENTITY_KEY   = 0x09;
const T_CERT_VERIFY    = 0x0A;
const T_FINISHED       = 0x0B;
const T_AEAD_OFFER     = 0x0C;
const T_AEAD_SELECT    = 0x0D;

// Record-layer direction octets (draft-00 section 7.5).
const DIR_CLIENT_TO_SERVER = 0x00;
const DIR_SERVER_TO_CLIENT = 0x01;

// ML-KEM-768 / X25519 sub-part sizes for the hybrid KEM wire layout.
const MLKEM768_CIPHERTEXT_LEN = 1088;
const MLKEM768_ENCAPS_KEY_LEN = 1184;
const X25519_PUBLIC_LEN       = 32;

/** Load and SHA-256-pin the vector (fail loud on a swapped/corrupt vector). */
function loadKat(): array
{
    $raw = @file_get_contents(VEC_DIR . '/handshake-flow-kat.json');
    if ($raw === false) {
        fwrite(STDERR, "cannot read handshake-flow-kat.json\n");
        exit(2);
    }
    $got = hash('sha256', $raw);
    if (!hash_equals(HANDSHAKE_FLOW_KAT_SHA256, $got)) {
        fwrite(STDERR, "handshake-flow KAT vector SHA-256 mismatch (swapped vector?): {$got}\n");
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

/** Canonical TLV wire encoding: Type(2 BE) | Length(2 BE) | Value. */
function tlv(int $type, string $value): string
{
    return Npamp::uintToBytes($type, 2) . Npamp::uintToBytes(strlen($value), 2) . $value;
}

/**
 * Marshal a cleartext handshake frame (Control channel, seq 0) through the
 * impl's real Frame::marshal path.
 */
function marshalFrame(int $ftype, string $payload): string
{
    return (new Frame($ftype, Npamp::CHAN_CONTROL, 0, 0, 0, $payload))->marshal();
}

/**
 * Seal an AUTH plaintext into a wire frame through the impl's real key-schedule
 * + record path (dir-specific handshake traffic key, AES-256-GCM, FLAG_ENC).
 * The AAD is the 21-octet header prefix over the SEALED length (plaintext + the
 * 16-octet GCM tag), matching the Go sealAuthKAT.
 */
function sealAuthFrame(int $ftype, string $baseSecret, int $dir, string $plaintext): string
{
    $ts = Npamp::deriveTrafficSecret($baseSecret, $dir, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_CONTROL, STANDARD);
    [$key, $iv] = Npamp::deriveKeyIv($ts, STANDARD);
    $f = new Frame($ftype, Npamp::CHAN_CONTROL, 0, Npamp::FLAG_ENC, 0, '');
    $aad = $f->headerPrefix(strlen($plaintext) + 16);
    $f->payload = Npamp::sealAes256Gcm($key, $iv, 0, $aad, $plaintext);
    return $f->marshal();
}

$k = loadKat();
$in = $k['inputs'];
$e = $k['expected'];

// --- Vector self-consistency: this really is the golden-interop flow. ---
check('handshake-flow: class is golden-interop', ($k['class'] ?? '') === 'golden-interop');
check('handshake-flow: profile is Standard, hash SHA-256, aead AES-256-GCM',
    ($k['profile'] ?? '') === 'Standard' && ($k['hash'] ?? '') === 'SHA-256' && ($k['aead'] ?? '') === 'AES-256-GCM');
check('handshake-flow: impl frame-type constants match spec section 1 code points',
    Handshake::FRAME_CLIENT_HELLO === 0x0100 && Handshake::FRAME_SERVER_HELLO === 0x0101
    && Handshake::FRAME_SERVER_AUTH === 0x0102 && Handshake::FRAME_CLIENT_AUTH === 0x0103);

$kemShare = hx($e['kem']['kem_share']);
$kemCt    = hx($e['kem']['kem_ciphertext']);
$mlkemCt  = hx($in['mlkem_ciphertext']);
$mlkemSs  = hx($in['mlkem_shared_secret']);
$wantX25519Ss = hx($in['x25519_shared_secret']);

$clientX25519Priv = hx($in['client_x25519_private']);
$serverX25519Priv = hx($in['server_x25519_private']);

// === KEM leg =============================================================
// Structure: kem_share = ML-KEM encaps key(1184) || client X25519 public(32);
//            kem_ciphertext = ML-KEM ciphertext(1088) || server X25519 public(32).
check('handshake-flow kem: kem_share length == 1184+32',
    strlen($kemShare) === MLKEM768_ENCAPS_KEY_LEN + X25519_PUBLIC_LEN);
check('handshake-flow kem: kem_ciphertext length == 1088+32',
    strlen($kemCt) === MLKEM768_CIPHERTEXT_LEN + X25519_PUBLIC_LEN);
check('handshake-flow kem: kem_ciphertext front == pinned mlkem_ciphertext input',
    substr($kemCt, 0, MLKEM768_CIPHERTEXT_LEN) === $mlkemCt);

// Server X25519 public is the tail of kem_ciphertext; client X25519 public is
// the tail of kem_share. Re-derive both from the pinned privates via ext-sodium.
$clientX25519Pub = sodium_crypto_scalarmult_base($clientX25519Priv);
$serverX25519Pub = sodium_crypto_scalarmult_base($serverX25519Priv);
check('handshake-flow kem: client X25519 public == kem_share tail',
    substr($kemShare, -X25519_PUBLIC_LEN) === $clientX25519Pub);
check('handshake-flow kem: server X25519 public == kem_ciphertext tail',
    substr($kemCt, -X25519_PUBLIC_LEN) === $serverX25519Pub);

// The classical leg IS re-derivable in PHP: recompute the X25519 shared secret
// (both directions) and assert it equals the pinned x25519_shared_secret. The
// ML-KEM leg is a pinned self-validating input (no ML-KEM in ext-sodium; the
// vector's provenance note records that even Go's crypto/mlkem cannot recover a
// captured ciphertext) — it feeds the key schedule as-is.
check('handshake-flow kem: X25519(client_priv, server_pub) == pinned x25519_shared_secret',
    hash_equals($wantX25519Ss, sodium_crypto_scalarmult($clientX25519Priv, $serverX25519Pub)));
check('handshake-flow kem: X25519(server_priv, client_pub) == pinned x25519_shared_secret',
    hash_equals($wantX25519Ss, sodium_crypto_scalarmult($serverX25519Priv, $clientX25519Pub)));

// === CLIENT_HELLO (whole-frame byte-equality) ============================
// TLVs in spec order: ProfileOffer, KEMOffer, SigOffer, AEADOffer, KEMShare.
// ProfileOffer is the draft-01 one-octet-per-profile list: a single Standard
// profile is exactly ONE octet (0x01) — the ProfileOffer wire-drift guard.
$chPayload = tlv(T_PROFILE_OFFER, chr(PROFILE_STANDARD))
    . tlv(T_KEM_OFFER, Npamp::uintToBytes(Npamp::KEM_X25519_MLKEM768, 2))
    . tlv(T_SIG_OFFER, Npamp::uintToBytes(Npamp::SIG_ED25519, 2))
    . tlv(T_AEAD_OFFER, Npamp::uintToBytes(Npamp::AEAD_AES256_GCM, 2))
    . tlv(T_KEM_SHARE, $kemShare);
$chFrame = marshalFrame(Handshake::FRAME_CLIENT_HELLO, $chPayload);
check('handshake-flow: CLIENT_HELLO frame == expected (the ProfileOffer wire-drift guard)',
    hash_equals(hx($e['frames']['client_hello']), $chFrame));

// === SERVER_HELLO (whole-frame byte-equality) ============================
// TLVs in spec order: ProfileSelect(1 octet), KEMSelect, SigSelect, AEADSelect
// (2 octets each), KEMCiphertext (the pinned kem_ciphertext).
$shPayload = tlv(T_PROFILE_SELECT, chr(PROFILE_STANDARD))
    . tlv(T_KEM_SELECT, Npamp::uintToBytes(Npamp::KEM_X25519_MLKEM768, 2))
    . tlv(T_SIG_SELECT, Npamp::uintToBytes(Npamp::SIG_ED25519, 2))
    . tlv(T_AEAD_SELECT, Npamp::uintToBytes(Npamp::AEAD_AES256_GCM, 2))
    . tlv(T_KEM_CIPHERTEXT, $kemCt);
$shFrame = marshalFrame(Handshake::FRAME_SERVER_HELLO, $shPayload);
check('handshake-flow: SERVER_HELLO frame == expected',
    hash_equals(hx($e['frames']['server_hello']), $shFrame));

// === Transcript th_kem + key ladder through the real impl ================
$tr = new Transcript();
$tr->addFrameType(Handshake::FRAME_CLIENT_HELLO);
$tr->addTlv(T_PROFILE_OFFER, chr(PROFILE_STANDARD));
$tr->addTlv(T_KEM_OFFER, Npamp::uintToBytes(Npamp::KEM_X25519_MLKEM768, 2));
$tr->addTlv(T_SIG_OFFER, Npamp::uintToBytes(Npamp::SIG_ED25519, 2));
$tr->addTlv(T_AEAD_OFFER, Npamp::uintToBytes(Npamp::AEAD_AES256_GCM, 2));
$tr->addTlv(T_KEM_SHARE, $kemShare);
$tr->addFrameType(Handshake::FRAME_SERVER_HELLO);
$tr->addTlv(T_PROFILE_SELECT, chr(PROFILE_STANDARD));
$tr->addTlv(T_KEM_SELECT, Npamp::uintToBytes(Npamp::KEM_X25519_MLKEM768, 2));
$tr->addTlv(T_SIG_SELECT, Npamp::uintToBytes(Npamp::SIG_ED25519, 2));
$tr->addTlv(T_AEAD_SELECT, Npamp::uintToBytes(Npamp::AEAD_AES256_GCM, 2));
$tr->addTlv(T_KEM_CIPHERTEXT, $kemCt);
$thKem = $tr->hash(STANDARD);
check('handshake-flow: th_kem == expected', hash_equals(hx($e['transcript']['th_kem']), $thKem));

$hs = Npamp::deriveHandshakeSecret($mlkemSs, $wantX25519Ss, STANDARD);
check('handshake-flow: handshake_secret == expected',
    hash_equals(hx($e['secrets']['handshake_secret']), $hs));
$cHs = Npamp::deriveClientHandshakeSecret($hs, $thKem, STANDARD);
$sHs = Npamp::deriveServerHandshakeSecret($hs, $thKem, STANDARD);
check('handshake-flow: c_hs_secret == expected', hash_equals(hx($e['secrets']['c_hs_secret']), $cHs));
check('handshake-flow: s_hs_secret == expected', hash_equals(hx($e['secrets']['s_hs_secret']), $sHs));

// Identities from the two fixed Ed25519 seeds via the impl helper + ext-sodium.
$serverSk = Handshake::ed25519SecretKeyFromSeed(hx($in['server_identity_ed25519_seed']));
$clientSk = Handshake::ed25519SecretKeyFromSeed(hx($in['client_identity_ed25519_seed']));
$serverPub = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(hx($in['server_identity_ed25519_seed'])));
$clientPub = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(hx($in['client_identity_ed25519_seed'])));

// === SERVER_AUTH =========================================================
$tr->addFrameType(Handshake::FRAME_SERVER_AUTH);
$tr->addTlv(T_IDENTITY_KEY, $serverPub);
$thSid = $tr->hash(STANDARD);
check('handshake-flow: th_sid == expected', hash_equals(hx($e['transcript']['th_sid']), $thSid));

// Ed25519 is deterministic (RFC 8032), so the pinned signature must match.
$sCV = Handshake::signCertVerify($serverSk, true, $thSid);
check('handshake-flow: cert_verify.server == expected', hash_equals(hx($e['cert_verify']['server']), $sCV));
check('handshake-flow: server CertVerify verifies',
    Handshake::verifyCertVerify($serverPub, true, $thSid, $sCV));

$tr->addTlv(T_CERT_VERIFY, $sCV);
$thScv = $tr->hash(STANDARD);
check('handshake-flow: th_scv == expected', hash_equals(hx($e['transcript']['th_scv']), $thScv));

$sFinKey = Npamp::deriveFinishedKey($sHs, STANDARD);
check('handshake-flow: finished_keys.server == expected',
    hash_equals(hx($e['finished_keys']['server']), $sFinKey));
$sFin = Handshake::computeFinished($sFinKey, $thScv, STANDARD);
check('handshake-flow: finished.server == expected', hash_equals(hx($e['finished']['server']), $sFin));
$tr->addTlv(T_FINISHED, $sFin);

$serverAuthPlain = tlv(T_IDENTITY_KEY, $serverPub) . tlv(T_CERT_VERIFY, $sCV) . tlv(T_FINISHED, $sFin);
check('handshake-flow: auth_plaintext.server == expected',
    hash_equals(hx($e['auth_plaintext']['server_auth']), $serverAuthPlain));
$serverAuthFrame = sealAuthFrame(Handshake::FRAME_SERVER_AUTH, $sHs, DIR_SERVER_TO_CLIENT, $serverAuthPlain);
check('handshake-flow: SERVER_AUTH frame == expected',
    hash_equals(hx($e['frames']['server_auth']), $serverAuthFrame));

// === CLIENT_AUTH =========================================================
$tr->addFrameType(Handshake::FRAME_CLIENT_AUTH);
$tr->addTlv(T_IDENTITY_KEY, $clientPub);
$thCid = $tr->hash(STANDARD);
check('handshake-flow: th_cid == expected', hash_equals(hx($e['transcript']['th_cid']), $thCid));

$cCV = Handshake::signCertVerify($clientSk, false, $thCid);
check('handshake-flow: cert_verify.client == expected', hash_equals(hx($e['cert_verify']['client']), $cCV));
check('handshake-flow: client CertVerify verifies',
    Handshake::verifyCertVerify($clientPub, false, $thCid, $cCV));

$tr->addTlv(T_CERT_VERIFY, $cCV);
$thCcv = $tr->hash(STANDARD);
check('handshake-flow: th_ccv == expected', hash_equals(hx($e['transcript']['th_ccv']), $thCcv));

$cFinKey = Npamp::deriveFinishedKey($cHs, STANDARD);
check('handshake-flow: finished_keys.client == expected',
    hash_equals(hx($e['finished_keys']['client']), $cFinKey));
$cFin = Handshake::computeFinished($cFinKey, $thCcv, STANDARD);
check('handshake-flow: finished.client == expected', hash_equals(hx($e['finished']['client']), $cFin));

$clientAuthPlain = tlv(T_IDENTITY_KEY, $clientPub) . tlv(T_CERT_VERIFY, $cCV) . tlv(T_FINISHED, $cFin);
check('handshake-flow: auth_plaintext.client == expected',
    hash_equals(hx($e['auth_plaintext']['client_auth']), $clientAuthPlain));
$clientAuthFrame = sealAuthFrame(Handshake::FRAME_CLIENT_AUTH, $cHs, DIR_CLIENT_TO_SERVER, $clientAuthPlain);
check('handshake-flow: CLIENT_AUTH frame == expected',
    hash_equals(hx($e['frames']['client_auth']), $clientAuthFrame));

// === Master + application-phase traffic keys =============================
$master = Npamp::deriveMasterSecret($hs, $thCcv, STANDARD);
check('handshake-flow: master_secret == expected', hash_equals(hx($e['secrets']['master_secret']), $master));

/**
 * Derive a traffic secret + key + iv through the impl and assert each against
 * the pinned expected hex.
 */
function assertTrafficKeyIv(string $name, string $parent, int $dir, array $e): void
{
    $ts = Npamp::deriveTrafficSecret($parent, $dir, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_CONTROL, STANDARD);
    check("handshake-flow: {$name}_traffic_secret == expected",
        hash_equals(hx($e['secrets'][$name . '_traffic_secret']), $ts));
    [$key, $iv] = Npamp::deriveKeyIv($ts, STANDARD);
    check("handshake-flow: {$name}_key == expected", hash_equals(hx($e['secrets'][$name . '_key']), $key));
    check("handshake-flow: {$name}_iv == expected", hash_equals(hx($e['secrets'][$name . '_iv']), $iv));
}

assertTrafficKeyIv('c_hs', $cHs, DIR_CLIENT_TO_SERVER, $e);
assertTrafficKeyIv('s_hs', $sHs, DIR_SERVER_TO_CLIENT, $e);
assertTrafficKeyIv('app_c2s', $master, DIR_CLIENT_TO_SERVER, $e);
assertTrafficKeyIv('app_s2c', $master, DIR_SERVER_TO_CLIENT, $e);

// === Mutation guards =====================================================
// A one-octet flip in the server CertVerify signature must REJECT.
$badCV = $sCV;
$badCV[strlen($badCV) - 1] = chr(ord($badCV[strlen($badCV) - 1]) ^ 0x01);
check('handshake-flow mutation guard: flipped server CertVerify signature REJECTS',
    !Handshake::verifyCertVerify($serverPub, true, $thSid, $badCV));

// A one-octet flip in the client Finished MAC must REJECT.
$badFin = $cFin;
$badFin[0] = chr(ord($badFin[0]) ^ 0x01);
check('handshake-flow mutation guard: flipped client Finished MAC REJECTS',
    !Handshake::verifyFinished($cFinKey, $thCcv, $badFin, STANDARD));

// Sanity: the untouched signature and MAC still verify.
check('handshake-flow: unmutated server CertVerify still verifies',
    Handshake::verifyCertVerify($serverPub, true, $thSid, $sCV));
check('handshake-flow: unmutated client Finished still verifies',
    Handshake::verifyFinished($cFinKey, $thCcv, $cFin, STANDARD));

echo $failures === 0 ? "ALL PASS\n" : "FAILURES: {$failures}\n";
exit($failures === 0 ? 0 : 1);

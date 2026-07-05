<?php

/**
 * Independent crypto KAT: drive N-PAMP's AES-256-GCM seal/open through Google
 * Project Wycheproof vectors (C2SP/wycheproof), via the dependency-free flat
 * corpus _shared/wycheproof/aesgcm_kat.tsv (keySize=256, ivSize=96, tagSize=128).
 *
 * These vectors are authored by an independent authority and encode KNOWN ATTACKS
 * (truncated tags, modified ciphertext) that our self-generated golden vectors
 * never include -- so a shared bug between our impls cannot pass them.
 *
 * Trick: sealAes256Gcm(key, iv, seq, ...) derives nonce = iv XOR (0^4||seq); with
 * seq=0 the nonce IS the given IV, so each vector exercises the REAL seal/open path.
 *
 * Exit 0 iff every vector behaves exactly as Wycheproof labels it, and total > 0.
 * PHP port of the Python reference runner kat_aesgcm_wycheproof.py (passes 66/66).
 *
 * Run from impl/php:  php test/kat_aesgcm.php <TSV-path>
 */

declare(strict_types=1);

require __DIR__ . '/../src/Npamp.php';

use Sh\Bubblefish\Npamp\Npamp;

/** Decode a hex string into raw bytes; "" -> "". */
function fromHex(string $s): string
{
    if ($s === '') {
        return '';
    }
    $out = hex2bin($s);
    if ($out === false) {
        throw new \RuntimeException("bad hex: {$s}");
    }
    return $out;
}

// Externally-provided Wycheproof corpus: pass as argv[1], set NPAMP_SHARED_DIR, or place at ../_shared.
$tsvPath = $argv[1] ?? ((getenv('NPAMP_SHARED_DIR') ?: (__DIR__ . '/../_shared')) . '/wycheproof/aesgcm_kat.tsv');

$contents = @file_get_contents($tsvPath);
if ($contents === false) {
    fwrite(STDERR, "cannot read TSV: {$tsvPath}\n");
    exit(1);
}

$total = 0;
$passed = 0;
$fails = [];

foreach (preg_split("/\r\n|\n|\r/", $contents) as $line) {
    if ($line === '' || $line[0] === '#') {
        continue;
    }
    // Limit -1 preserves trailing empty fields (aad/msg/ct/tag may be EMPTY).
    $f = explode("\t", $line);
    if (count($f) !== 8) {
        throw new \RuntimeException('expected 8 columns, got ' . count($f) . ": {$line}");
    }
    [$tc, $result, $keyHex, $ivHex, $aadHex, $msgHex, $ctHex, $tagHex] = $f;
    $key = fromHex($keyHex);
    $iv = fromHex($ivHex);
    $aad = fromHex($aadHex);
    $msg = fromHex($msgHex);
    $sealed = fromHex($ctHex) . fromHex($tagHex);

    $ok = true;
    $reason = '';

    if ($result === 'valid') {
        $gotSealed = null;
        try {
            $gotSealed = Npamp::sealAes256Gcm($key, $iv, 0, $aad, $msg);
        } catch (\Throwable $e) {
            $gotSealed = null;
        }
        if ($gotSealed === null || !hash_equals($sealed, $gotSealed)) {
            $ok = false;
            $reason = 'encrypt mismatch';
        } else {
            $gotPt = null;
            try {
                $gotPt = Npamp::openAes256Gcm($key, $iv, 0, $aad, $sealed);
            } catch (\Throwable $e) {
                $gotPt = null;
            }
            if ($gotPt === null || !hash_equals($msg, $gotPt)) {
                $ok = false;
                $reason = 'decrypt mismatch';
            }
        }
    } elseif ($result === 'invalid') {
        try {
            Npamp::openAes256Gcm($key, $iv, 0, $aad, $sealed);
            $ok = false;
            $reason = 'accepted an invalid vector';
        } catch (\Throwable $e) {
            // correct: rejected
        }
    } else { // "acceptable"
        try {
            $gotPt = Npamp::openAes256Gcm($key, $iv, 0, $aad, $sealed);
            if (!hash_equals($msg, $gotPt)) {
                $ok = false;
                $reason = 'acceptable but wrong plaintext';
            }
        } catch (\Throwable $e) {
            // rejection is also allowed for acceptable
        }
    }

    $total++;
    if ($ok) {
        $passed++;
    } else {
        $fails[] = "  FAIL tcId={$tc} result={$result}: {$reason}";
    }
}

echo "AES-256-GCM Wycheproof KAT (php): {$passed}/{$total} passed\n";
foreach (array_slice($fails, 0, 15) as $line) {
    echo $line . "\n";
}
exit(empty($fails) && $total > 0 ? 0 : 1);

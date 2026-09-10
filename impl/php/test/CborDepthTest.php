<?php

/**
 * CBOR nesting-depth resource guard test for the PHP N-PAMP body decoder.
 *
 * Mirrors the Go reference guard (impl/go/memory_cbor.go, cborMaxNestingDepth = 8)
 * against the spec-derived, non-circular conformance vectors:
 *   - REJECT: eight 0x81 (array-of-one) headers followed by 0x00 (scalar at
 *     depth 9) -> CborDepthExceededException.
 *   - ACCEPT: seven 0x81 headers followed by 0x00 (scalar at depth 8) -> decodes.
 *
 * Run from impl/php:  php test/CborDepthTest.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/NpampBodies.php';

use Sh\Bubblefish\Npamp\Cbor;
use Sh\Bubblefish\Npamp\CborDepthExceededException;

$failures = 0;

function check(string $name, bool $ok): void
{
    global $failures;
    echo ($ok ? 'PASS' : 'FAIL') . " {$name}\n";
    if (!$ok) {
        $failures++;
    }
}

// Eight 0x81 (array, 1 element) headers + a 0x00 scalar: the scalar sits at
// depth 9 (outermost array = depth 1, ... 8th nested array = depth 8, its
// element = depth 9). MUST be rejected.
$reject = str_repeat("\x81", 8) . "\x00";
$rejectedRight = false;
try {
    Cbor::decodeTop($reject);
} catch (CborDepthExceededException $e) {
    $rejectedRight = true;
} catch (\Throwable $e) {
    $rejectedRight = false; // wrong exception type
}
check('depth_9_scalar_rejected_with_depth_exceeded', $rejectedRight);

// Seven 0x81 headers + a 0x00 scalar: the scalar sits at depth 8 (outermost
// array = depth 1, ..., 7th nested array = depth 7, its element = depth 8).
// MUST be accepted (decodes without error).
$accept = str_repeat("\x81", 7) . "\x00";
$acceptedOk = false;
try {
    Cbor::decodeTop($accept);
    $acceptedOk = true;
} catch (\Throwable $e) {
    $acceptedOk = false;
}
check('depth_8_scalar_accepted', $acceptedOk);

echo $failures === 0 ? "ALL PASS (2/2)\n" : "FAILURES: {$failures}\n";
exit($failures === 0 ? 0 : 1);

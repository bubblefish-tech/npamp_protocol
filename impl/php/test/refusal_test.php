<?php

/**
 * Behaviour check, not a conformance vector: the open PHP module implements the Standard
 * profile only, so every key-schedule, transcript and Finished primitive refuses a
 * non-Standard profile with NoSuiteForProfile and still succeeds at Standard. No external
 * authority (RFC or FIPS) defines this module's scope.
 *
 * Run from impl/php:  php test/refusal_test.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/Npamp.php';

use Sh\Bubblefish\Npamp\Handshake;
use Sh\Bubblefish\Npamp\Npamp;
use Sh\Bubblefish\Npamp\NoSuiteForProfile;
use Sh\Bubblefish\Npamp\Transcript;

$failures = 0;

function check(string $name, bool $ok): void
{
    global $failures;
    if ($ok) {
        echo "PASS $name\n";
    } else {
        echo "FAIL $name\n";
        $failures++;
    }
}

function refused(string $name, callable $call): void
{
    $threw = false;
    try {
        $call();
    } catch (NoSuiteForProfile $e) {
        $threw = true;
    } catch (\Throwable $e) {
        echo '     wrong exception for ' . $name . ': ' . get_class($e) . "\n";
    }
    check('non-standard refused: ' . $name, $threw);
}

$secret = str_repeat(chr(0x11), 32);
$th = str_repeat(chr(0x22), 32);

check('standard control: hkdfExtract', strlen(Npamp::hkdfExtract(str_repeat(chr(0), 32), $secret, true)) === 32);
check('standard control: deriveTrafficSecret',
    strlen(Npamp::deriveTrafficSecret($secret, 0, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_CONTROL, true)) === 32);
[$k, $iv] = Npamp::deriveKeyIv($secret, true);
check('standard control: deriveKeyIv', strlen($k) === 32 && strlen($iv) === 12);
check('standard control: deriveHandshakeSecret', strlen(Npamp::deriveHandshakeSecret($secret, $secret, true)) === 32);
check('standard control: deriveFinishedKey', strlen(Npamp::deriveFinishedKey($secret, true)) === 32);
check('standard control: transcript hash', strlen((new Transcript())->hash(true)) === 32);
$mac = Handshake::computeFinished($secret, $th, true);
check('standard control: finished verifies', Handshake::verifyFinished($secret, $th, $mac, true));

refused('hkdfExtract', fn() => Npamp::hkdfExtract(str_repeat(chr(0), 48), $secret, false));
refused('hkdfExpandLabel', fn() => Npamp::hkdfExpandLabel($secret, 'key', '', 32, false));
refused('deriveTrafficSecret',
    fn() => Npamp::deriveTrafficSecret($secret, 0, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_CONTROL, false));
refused('deriveKeyIv', fn() => Npamp::deriveKeyIv($secret, false));
refused('deriveHandshakeSecret', fn() => Npamp::deriveHandshakeSecret($secret, $secret, false));
refused('deriveClientHandshakeSecret', fn() => Npamp::deriveClientHandshakeSecret($secret, $th, false));
refused('deriveServerHandshakeSecret', fn() => Npamp::deriveServerHandshakeSecret($secret, $th, false));
refused('deriveMasterSecret', fn() => Npamp::deriveMasterSecret($secret, $th, false));
refused('deriveFinishedKey', fn() => Npamp::deriveFinishedKey($secret, false));
refused('Transcript::hash', fn() => (new Transcript())->hash(false));
refused('computeFinished', fn() => Handshake::computeFinished($secret, $th, false));
refused('verifyFinished', fn() => Handshake::verifyFinished($secret, $th, $th, false));

echo $failures === 0 ? "ALL PASS\n" : "FAILURES: $failures\n";
exit($failures === 0 ? 0 : 1);

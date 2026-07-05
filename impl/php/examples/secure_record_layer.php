<?php

/**
 * Runnable example: the draft-00 secure record layer, end to end.
 *
 * Composes the OPEN-protocol primitives this port provides - the HKDF key
 * schedule, the AES-256-GCM record layer, and the 36-octet frame codec - into
 * one send -> receive round-trip over an in-memory "wire". Mirrors the Go
 * reference's Example_secureRecordLayer (impl/go/example_test.go).
 *
 * The master secret is a fixed demo value; in a live session it is the
 * handshake output (binding spec/10 section 5). Standard profile only
 * (SHA-256, AES-256-GCM). Run from impl/php:
 *
 *   php examples/secure_record_layer.php
 */

declare(strict_types=1);

require __DIR__ . '/../src/Npamp.php';

use Sh\Bubblefish\Npamp\Frame;
use Sh\Bubblefish\Npamp\Npamp;

// Direction octet (draft-00 7.5): client-to-server = 0.
const DIR_CLIENT_TO_SERVER = 0;

// 1. Key schedule: derive a per-(direction, channel, suite) traffic key + IV
//    from the master secret. In a live session the master secret is the
//    handshake output; here it is fixed so the example is deterministic.
$master = str_repeat("\x2B", 32);
$ts = Npamp::deriveTrafficSecret($master, DIR_CLIENT_TO_SERVER, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_MEMORY, true);
[$key, $iv] = Npamp::deriveKeyIv($ts, true);

// 2. Sender: seal an application payload into an AEAD-protected frame on the
//    Memory channel. The AEAD associated data is the 21-octet header prefix,
//    so the ciphertext is bound to the frame's type/channel/seq/length - a
//    tampered header makes the open fail.
$appType = 0x0120; // application frame type (app-defined; this port is wire-only)
$plaintext = 'hello over n-pamp';
$seq = 0;
$out = new Frame($appType, Npamp::CHAN_MEMORY, $seq, Npamp::FLAG_ENC);
$aad = $out->headerPrefix(strlen($plaintext) + 16); // +16 = AES-256-GCM authentication tag
$out->payload = Npamp::sealAes256Gcm($key, $iv, $seq, $aad, $plaintext);
$wire = $out->marshal();

// 3. ... the $wire bytes travel over any transport (the consumer supplies TCP/TLS) ...

// 4. Receiver: parse the frame (validates CRC32C/magic/version) and open the
//    payload under the same key/seq and the reconstructed header-prefix AAD.
$in = Frame::unmarshal($wire);
$raad = $in->headerPrefix(strlen($in->payload));
$opened = Npamp::openAes256Gcm($key, $iv, $in->seq, $raad, $in->payload);

printf("channel=%d seq=%d encrypted=%s\n", $in->channel, $in->seq, ($in->flags & Npamp::FLAG_ENC) !== 0 ? 'true' : 'false');
printf("recovered: %s\n", $opened);
exit($opened === $plaintext ? 0 : 1);

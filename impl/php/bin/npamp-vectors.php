<?php

// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Emit the cross-language conformance vectors as JSON, byte-identical to Go
// (impl/go/cmd/npamp-vectors) and every other reference implementation. The harness
// impl/_conformance-harness/run-all-langs.sh regenerates this from each language and
// compares (line-ending-normalized) against _shared/conformance-vectors/vectors.json.
// The JSON is hand-formatted with two-space indent + this exact key order to match Go's
// encoding/json MarshalIndent output; json_encode(JSON_PRETTY_PRINT) uses four spaces and
// would not match.
//
// Run from impl/php:  php bin/npamp-vectors.php

declare(strict_types=1);

require __DIR__ . '/../src/Npamp.php';

use Sh\Bubblefish\Npamp\Npamp;
use Sh\Bubblefish\Npamp\Frame;

// 1. Golden header: PING on Control, seq 0, empty payload.
$header = (new Frame(Npamp::FRAME_PING, Npamp::CHAN_CONTROL, 0))->marshal();

// 2. Nonce: iv = 01..0C, seq = 0x0102030405060708.
$iv = '';
for ($i = 1; $i <= 12; $i++) {
    $iv .= chr($i);
}
$nonce = Npamp::deriveNonce($iv, 0x0102030405060708);

// 3. AEAD seal: fixed key 00..1F, iv 10..1B, seq 7, aad = header prefix (11), pt = "hello world".
$key = '';
for ($i = 0; $i < 32; $i++) {
    $key .= chr($i);
}
$iv2 = '';
for ($i = 0; $i < 12; $i++) {
    $iv2 .= chr(0x10 + $i);
}
$aad = (new Frame(Npamp::FRAME_PING, Npamp::CHAN_CONTROL))->headerPrefix(11);
$sealed = Npamp::sealAes256Gcm($key, $iv2, 7, $aad, 'hello world');

// 4. Key schedule: master = 48 x 0x2A (SHA-384 length), High profile (standard=false), traffic secret -> key.
$master = str_repeat("\x2a", 48);
$ts = Npamp::deriveTrafficSecret($master, 0, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_CONTROL, false);
[$tk, ] = Npamp::deriveKeyIv($ts, false);

echo "{\n"
    . '  "spec": "draft-bubblefish-npamp-00",' . "\n"
    . '  "header_ping_control_seq0": "' . bin2hex($header) . '",' . "\n"
    . '  "nonce_iv1to12_seq0102": "' . bin2hex($nonce) . '",' . "\n"
    . '  "aes256gcm_seal_helloworld": "' . bin2hex($sealed) . '",' . "\n"
    . '  "traffic_key_sha384": "' . bin2hex($tk) . '"' . "\n"
    . "}\n";

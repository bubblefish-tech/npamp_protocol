// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Emit the cross-language conformance vectors as JSON, byte-identical to Go
// (impl/go/cmd/npamp-vectors) and every other reference implementation. The harness
// impl/_conformance-harness/run-all-langs.sh regenerates this from each language and
// compares (line-ending-normalized) against _shared/conformance-vectors/vectors.json.
// JSON.stringify(_, null, 2) matches Go's encoding/json MarshalIndent (two-space indent,
// insertion-order keys).
//
// Run from impl/typescript:  node bin/npamp-vectors.ts

import {
  Frame,
  deriveNonce,
  sealAes256Gcm,
  deriveTrafficSecret,
  deriveKeyIv,
  FRAME_PING,
  CHAN_CONTROL,
  AEAD_AES256_GCM,
} from "../src/npamp.ts";

// 1. Golden header: PING on Control, seq 0, empty payload.
const header = new Frame({ ftype: FRAME_PING, channel: CHAN_CONTROL, seq: 0 }).marshal();

// 2. Nonce: iv = 01..0C, seq = 0x0102030405060708.
const iv = Buffer.from(Array.from({ length: 12 }, (_, i) => i + 1));
const nonce = deriveNonce(iv, 0x0102030405060708n);

// 3. AEAD seal: fixed key 00..1F, iv 10..1B, seq 7, aad = header prefix (11), pt = "hello world".
const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const iv2 = Buffer.from(Array.from({ length: 12 }, (_, i) => 0x10 + i));
const aad = new Frame({ ftype: FRAME_PING, channel: CHAN_CONTROL }).headerPrefix(11);
const sealed = sealAes256Gcm(key, iv2, 7n, aad, Buffer.from("hello world"));

// 4. Key schedule: master = 48 x 0x2A (SHA-384 length), High profile (standard=false), traffic secret -> key.
const master = Buffer.alloc(48, 0x2a);
const ts = deriveTrafficSecret(master, 0, 0n, AEAD_AES256_GCM, CHAN_CONTROL, false);
const [tk] = deriveKeyIv(ts, false);

const out = {
  spec: "draft-bubblefish-npamp-00",
  header_ping_control_seq0: header.toString("hex"),
  nonce_iv1to12_seq0102: nonce.toString("hex"),
  aes256gcm_seal_helloworld: sealed.toString("hex"),
  traffic_key_sha384: tk.toString("hex"),
};

process.stdout.write(JSON.stringify(out, null, 2) + "\n");

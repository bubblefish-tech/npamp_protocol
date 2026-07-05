// Runnable example: the draft-00 secure record layer, end to end.
//
// Composes the OPEN-protocol primitives this port provides — the HKDF key schedule, the
// AES-256-GCM record layer, and the 36-octet frame codec — into one send -> receive round-trip
// over an in-memory "wire". Mirrors the Go reference's Example_secureRecordLayer
// (impl/go/example_test.go).
//
// The master secret is a fixed demo value; in a live session it is the handshake output (binding
// spec/10 §5). Standard profile only (SHA-256, AES-256-GCM). Run from impl/typescript:
//
//   node examples/secure-record-layer.ts
import {
  Frame, FLAG_ENC, CHAN_MEMORY, AEAD_AES256_GCM,
  deriveTrafficSecret, deriveKeyIv, sealAes256Gcm, openAes256Gcm,
} from "../src/npamp.ts";

const DIR_CLIENT_TO_SERVER = 0; // direction octet (draft-00 7.5)

// 1. Key schedule: derive a per-(direction, channel, suite) traffic key + IV from the master
//    secret. In a live session the master secret is the handshake output; here it is fixed.
const master = Buffer.alloc(32, 0x2b);
const ts = deriveTrafficSecret(master, DIR_CLIENT_TO_SERVER, 0n, AEAD_AES256_GCM, CHAN_MEMORY, true);
const [key, iv] = deriveKeyIv(ts, true);

// 2. Sender: seal an application payload into an AEAD-protected frame on the Memory channel.
//    The AEAD associated data is the 21-octet header prefix, so the ciphertext is bound to the
//    frame's type/channel/seq/length — a tampered header makes the open fail.
const appType = 0x0120; // application frame type (app-defined; this port is wire-only)
const plaintext = Buffer.from("hello over n-pamp");
const seq = 0n;
const out = new Frame({ ftype: appType, channel: CHAN_MEMORY, seq, flags: FLAG_ENC });
const aad = out.headerPrefix(plaintext.length + 16); // +16 = AES-256-GCM authentication tag
out.payload = sealAes256Gcm(key, iv, seq, aad, plaintext);
const wire = out.marshal();

// 3. ... the `wire` bytes travel over any transport (the consumer supplies TCP/TLS) ...

// 4. Receiver: parse the frame (validates CRC32C/magic/version) and open the payload under the
//    same key/seq and the reconstructed header-prefix AAD.
const inc = Frame.unmarshal(wire);
const raad = inc.headerPrefix(inc.payload.length);
const opened = openAes256Gcm(key, iv, inc.seq, raad, inc.payload);

console.log(`channel=${inc.channel} seq=${inc.seq} encrypted=${(inc.flags & FLAG_ENC) !== 0}`);
console.log(`recovered: ${opened.toString()}`);
if (!opened.equals(plaintext)) {
  console.error("roundtrip mismatch");
  process.exit(1);
}

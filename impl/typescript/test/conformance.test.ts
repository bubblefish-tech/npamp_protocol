import { test } from "node:test";
import assert from "node:assert";
import { Frame, deriveNonce, sealAes256Gcm, openAes256Gcm, deriveTrafficSecret, deriveKeyIv, FRAME_PING, CHAN_CONTROL, CHAN_MEMORY, AEAD_AES256_GCM, FLAG_ENC, LABEL_PREFIX } from "../src/npamp.ts";

const HDR = "4e50414d20000100000000000000000000000000000d880c250000000000000000000000";
const NONCE = "010203040404040c0c0c0c04";
const AEAD = "3fe8b79f95b5697926b3395429c2c2466999c652f9346aeebb30bf";
const TK = "79372e2fb7f92d63e3a68099ff72514f310ebf6773deb0fa7ef45d013c652dcc";

test("vec_header", () => {
  assert.equal(new Frame({ ftype: FRAME_PING, channel: CHAN_CONTROL, seq: 0 }).marshal().toString("hex"), HDR);
});
test("vec_nonce", () => {
  assert.equal(deriveNonce(Buffer.from(Array.from({ length: 12 }, (_, i) => i + 1)), 0x0102030405060708n).toString("hex"), NONCE);
});
test("vec_aead", () => {
  const key = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
  const iv = Buffer.from(Array.from({ length: 12 }, (_, i) => 0x10 + i));
  const aad = new Frame({ ftype: FRAME_PING, channel: CHAN_CONTROL }).headerPrefix(11);
  assert.equal(sealAes256Gcm(key, iv, 7n, aad, Buffer.from("hello world")).toString("hex"), AEAD);
});
test("vec_traffic_key", () => {
  const ts = deriveTrafficSecret(Buffer.alloc(48, 0x2a), 0, 0n, AEAD_AES256_GCM, CHAN_CONTROL, false);
  assert.equal(deriveKeyIv(ts, false)[0].toString("hex"), TK);
});
test("roundtrip", () => {
  const f = new Frame({ ftype: 0x0100, channel: CHAN_MEMORY, seq: 42, flags: FLAG_ENC, payload: Buffer.from("payload") });
  const g = Frame.unmarshal(f.marshal());
  assert.equal(g.ftype, 0x0100); assert.equal(g.channel, CHAN_MEMORY); assert.equal(g.seq, 42n); assert.equal(g.flags, FLAG_ENC); assert.equal(g.payload.toString(), "payload");
});
test("crc_first", () => {
  const buf = new Frame({ ftype: FRAME_PING }).marshal(); buf[5] ^= 0xff;
  assert.throws(() => Frame.unmarshal(buf), /bad crc/);
});
test("reserved_zero", () => {
  const buf = new Frame({ ftype: FRAME_PING }).marshal(); buf[30] = 1;
  assert.throws(() => Frame.unmarshal(buf), /reserved/);
});
test("aead_tamper", () => {
  const key = Buffer.alloc(32); const iv = Buffer.from(Array.from({ length: 12 }, (_, i) => 0x10 + i));
  const aad = new Frame({ ftype: FRAME_PING }).headerPrefix(5);
  const sealed = sealAes256Gcm(key, iv, 7n, aad, Buffer.from("hello"));
  assert.equal(openAes256Gcm(key, iv, 7n, aad, sealed).toString(), "hello");
  aad[5] ^= 1;
  assert.throws(() => openAes256Gcm(key, iv, 7n, aad, sealed));
});
test("hkdf_prefix", () => { assert.equal(LABEL_PREFIX, "n-pamp "); assert.notEqual(LABEL_PREFIX, "tls13 "); });

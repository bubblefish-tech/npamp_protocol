// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 handshake key schedule
// (binding spec/10 §5; ML-KEM-first per ADR-0005; draft-00 §7.4 HKDF-Expand-Label + §7.5 traffic
// keys). TypeScript mirror of the sibling KATs (transcript/finished/certverify) against the SAME
// pinned vector. N-PAMP's HKDF-Expand-Label is RFC 8446 §7.1 with the prefix swapped from "tls13 "
// to "n-pamp " — so RFC 8448 (which uses "tls13 ") validates the MECHANISM and the prefix is the
// only N-PAMP-original element.
//
// NON-CIRCULARITY: this file stores NO golden N-PAMP output bytes. It proves an INDEPENDENT in-test
// HKDF-Expand-Label oracle against published RFC vectors FIRST, then uses that proven oracle (applied
// with the "n-pamp " prefix) to judge the implementation. Four legs:
//  1. ANCHOR — raw HKDF-Extract/Expand (impl AND the in-test oracle primitives) reproduce RFC 5869
//     Appendix A.1 TC1: Extract(salt,ikm)==prk and Expand(prk,info,L)==okm (trust the primitive).
//  2. ORACLE — an INDEPENDENT HKDF-Expand-Label that re-derives the HkdfLabel bytes itself (prefix as
//     a PARAMETER, NOT calling the impl's hkdfExpandLabel) reproduces RFC 8448 §3 key/iv/finished
//     with the "tls13 " prefix (guards the oracle/mechanism against an external vector).
//  3. IMPL   — the new key-schedule trunk (hkdfExtract / deriveHandshakeSecret / deriveClient&
//     ServerHandshakeSecret / deriveMasterSecret / deriveFinishedKey) reproduces, byte-for-byte, the
//     proven oracle applied with the "n-pamp " prefix to npamp_inputs (guards the implementation).
//  4. (within IMPL) the s2c handshake AEAD key/iv from deriveTrafficSecret/deriveKeyIv match the
//     oracle-computed traffic key/iv.
import { test } from "node:test";
import assert from "node:assert";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  hkdfExtract, hkdfExpand,
  deriveHandshakeSecret, deriveClientHandshakeSecret, deriveServerHandshakeSecret,
  deriveMasterSecret, deriveFinishedKey, deriveTrafficSecret, deriveKeyIv,
  CHAN_CONTROL, AEAD_AES256_GCM,
} from "../src/npamp.ts";

const VECTORS = join(import.meta.dirname, "..", "..", "..", "test-vectors", "v1");
const KEY_SCHEDULE_KAT_SHA256 = "e108f5cfdf99a378d7b677792448c8046abf3c630fc23fd8ea2ccb3927f2691c";

// Direction byte (binding §5 / §7.5 traffic context): ServerToClient = 1.
const DIR_S2C = 1;
// AES-256-GCM = 0x0001 per registries/aead.csv (= the impl's AEAD_AES256_GCM = npamp.AEADAES256GCM in
// the Go reference); 0x0002 is ChaCha20-Poly1305. The §7.5 traffic context binds this AEAD code point.

const hx = (s) => Buffer.from(s, "hex");

function loadKeyScheduleKAT() {
  const raw = readFileSync(join(VECTORS, "key-schedule-kat.json"));
  const got = createHash("sha256").update(raw).digest("hex");
  assert.equal(got, KEY_SCHEDULE_KAT_SHA256, "key-schedule KAT vector SHA-256 mismatch (swapped vector?)");
  return JSON.parse(raw.toString("utf8"));
}

// --- Independent in-test oracle primitives (node createHmac only; no impl key-schedule code) -------

// extractOracle: HKDF-Extract (RFC 5869 §2.2) = HMAC-SHA-256(salt, ikm). Standard profile is SHA-256.
function extractOracle(salt, ikm) {
  return createHmac("sha256", salt).update(ikm).digest();
}

// expandOracle: HKDF-Expand (RFC 5869 §2.3) over SHA-256, independent of the impl.
function expandOracle(prk, info, length) {
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  let t = Buffer.alloc(0);
  const out = [];
  for (let i = 1; i <= n; i++) {
    t = createHmac("sha256", prk).update(Buffer.concat([t, info, Buffer.from([i])])).digest();
    out.push(t);
  }
  return Buffer.concat(out).subarray(0, length);
}

// expandLabelOracle: HKDF-Expand-Label (RFC 8446 §7.1) re-deriving the HkdfLabel bytes itself with
// the prefix as a PARAMETER. info = uint16(length) || uint8(len(prefix+label)) || prefix+label ||
// uint8(len(context)) || context. It MUST NOT call the impl's hkdfExpandLabel — the two must agree
// independently. Built on expandOracle (anchored against RFC 5869 in the ANCHOR leg).
function expandLabelOracle(secret, prefix, label, context, length) {
  const full = Buffer.from(prefix + label);
  const info = Buffer.concat([
    Buffer.from([(length >> 8) & 0xff, length & 0xff]),
    Buffer.from([full.length]), full,
    Buffer.from([context.length]), context,
  ]);
  return expandOracle(secret, info, length);
}

// ANCHOR: raw HKDF-Extract/Expand (impl AND oracle) reproduce RFC 5869 Appendix A.1 TC1.
test("key_schedule_kat_rfc5869_anchor", () => {
  const k = loadKeyScheduleKAT();
  const tc = k.rfc5869_tc1;
  const salt = hx(tc.salt), ikm = hx(tc.ikm), info = hx(tc.info), L = tc.L;

  // Impl raw primitives.
  assert.equal(hkdfExtract(salt, ikm, true).toString("hex"), tc.prk, "impl hkdfExtract != RFC 5869 TC1 PRK");
  assert.equal(hkdfExpand("sha256", hx(tc.prk), info, L).toString("hex"), tc.okm, "impl hkdfExpand != RFC 5869 TC1 OKM");

  // Oracle raw primitives (so the oracle's own raw layer is anchored before it judges anything).
  assert.equal(extractOracle(salt, ikm).toString("hex"), tc.prk, "oracle extract != RFC 5869 TC1 PRK");
  assert.equal(expandOracle(hx(tc.prk), info, L).toString("hex"), tc.okm, "oracle expand != RFC 5869 TC1 OKM");
});

// ORACLE: the independent HKDF-Expand-Label reproduces RFC 8448 §3 key/iv/finished ("tls13 " prefix),
// validating the label-byte construction + expand mechanism against an external vector.
test("key_schedule_kat_rfc8448_oracle", () => {
  const k = loadKeyScheduleKAT();
  const v = k.rfc8448_expand_label;
  const secret = hx(v.client_handshake_traffic_secret);
  const empty = Buffer.alloc(0);
  assert.equal(expandLabelOracle(secret, "tls13 ", "key", empty, 16).toString("hex"), v.write_key, "oracle expandLabel key != RFC 8448");
  assert.equal(expandLabelOracle(secret, "tls13 ", "iv", empty, 12).toString("hex"), v.write_iv, "oracle expandLabel iv != RFC 8448");
  assert.equal(expandLabelOracle(secret, "tls13 ", "finished", empty, 32).toString("hex"), v.finished_key, "oracle expandLabel finished != RFC 8448");
});

// IMPL: the new key-schedule trunk reproduces the proven oracle applied with the "n-pamp " prefix to
// npamp_inputs; the s2c handshake AEAD key/iv match the oracle-computed traffic key/iv. No golden
// N-PAMP byte is hardcoded — every expectation is computed by the oracle proven in the legs above.
test("key_schedule_kat_impl", () => {
  const k = loadKeyScheduleKAT();
  const n = k.npamp_inputs;
  assert.equal(n.label_prefix, "n-pamp ", "vector label_prefix drifted from n-pamp");
  assert.equal(CHAN_CONTROL, 0x0000, "CHAN_CONTROL drifted from spec (Control channel)");

  const mlkemSs = hx(n.ikm_mlkem_ss);   // ML-KEM shared secret (IKM), concatenated FIRST
  const x25519Ss = hx(n.ikm_x25519_ss); // X25519 shared secret (IKM)
  const thKem = hx(n.th_kem);
  const thCcv = hx(n.th_ccv);
  const empty = Buffer.alloc(0);
  const PFX = "n-pamp ";

  // handshake_secret = HKDF-Extract(salt = 32 zero octets, ML-KEM_SS || X25519_SS).
  const zeros32 = Buffer.alloc(32);
  const hsOracle = extractOracle(zeros32, Buffer.concat([mlkemSs, x25519Ss]));
  const hsImpl = deriveHandshakeSecret(mlkemSs, x25519Ss, true);
  assert.equal(hsImpl.toString("hex"), hsOracle.toString("hex"), "handshake_secret: impl != oracle");

  // Ladder: c_hs / s_hs bind TH_kem; master binds TH_ccv.
  const cHsOracle = expandLabelOracle(hsOracle, PFX, "c hs", thKem, 32);
  const cHsImpl = deriveClientHandshakeSecret(hsImpl, thKem, true);
  assert.equal(cHsImpl.toString("hex"), cHsOracle.toString("hex"), "c_hs: impl != oracle");

  const sHsOracle = expandLabelOracle(hsOracle, PFX, "s hs", thKem, 32);
  const sHsImpl = deriveServerHandshakeSecret(hsImpl, thKem, true);
  assert.equal(sHsImpl.toString("hex"), sHsOracle.toString("hex"), "s_hs: impl != oracle");

  const masterOracle = expandLabelOracle(hsOracle, PFX, "master", thCcv, 32);
  const masterImpl = deriveMasterSecret(hsImpl, thCcv, true);
  assert.equal(masterImpl.toString("hex"), masterOracle.toString("hex"), "master: impl != oracle");

  // finished_key(secret) = HKDF-Expand-Label(secret, "finished", "", 32). Client from c_hs, server from s_hs.
  const fkClientOracle = expandLabelOracle(cHsOracle, PFX, "finished", empty, 32);
  const fkClientImpl = deriveFinishedKey(cHsImpl, true);
  assert.equal(fkClientImpl.toString("hex"), fkClientOracle.toString("hex"), "finished_key(c_hs): impl != oracle");

  const fkServerOracle = expandLabelOracle(sHsOracle, PFX, "finished", empty, 32);
  const fkServerImpl = deriveFinishedKey(sHsImpl, true);
  assert.equal(fkServerImpl.toString("hex"), fkServerOracle.toString("hex"), "finished_key(s_hs): impl != oracle");

  // s2c handshake AEAD: traffic_secret from s_hs (dir=ServerToClient, epoch=0, suite=AES-256-GCM,
  // channel=Control), then key/iv. ctx = dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE).
  const ctx = Buffer.alloc(1 + 8 + 2 + 2);
  ctx[0] = DIR_S2C;
  ctx.writeBigUInt64BE(0n, 1);
  ctx.writeUInt16BE(AEAD_AES256_GCM, 9);
  ctx.writeUInt16BE(CHAN_CONTROL, 11);
  const trafficOracle = expandLabelOracle(sHsOracle, PFX, "traffic", ctx, 32);
  const keyOracle = expandLabelOracle(trafficOracle, PFX, "key", empty, 32);
  const ivOracle = expandLabelOracle(trafficOracle, PFX, "iv", empty, 12);

  const trafficImpl = deriveTrafficSecret(sHsImpl, DIR_S2C, 0n, AEAD_AES256_GCM, CHAN_CONTROL, true);
  const [keyImpl, ivImpl] = deriveKeyIv(trafficImpl, true);
  assert.equal(keyImpl.toString("hex"), keyOracle.toString("hex"), "s2c handshake key: impl != oracle");
  assert.equal(ivImpl.toString("hex"), ivOracle.toString("hex"), "s2c handshake iv: impl != oracle");
});

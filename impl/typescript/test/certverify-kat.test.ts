// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 CertVerify (binding spec/10
// §6.1; RFC 8446 §4.4.3 structure; Ed25519 per RFC 8032). The value is u16(0x0807) ||
// Ed25519(priv, signing_input), signing_input = 64*0x20 || context || 0x00 || TH. TypeScript mirror
// of the Go reference test against the SAME pinned vector.
//
// NON-CIRCULARITY: the expected signatures in test-vectors/v1/certverify-kat.json were produced with
// Ed25519 directly, NOT with signCertVerify/certVerifySigningInput. Three legs:
//  1. ANCHOR — the src Ed25519 key helpers reproduce the published RFC 8032 §7.1 TEST 1/TEST 2
//     public keys + signatures (trust the primitive + the PKCS8/SPKI wiring).
//  2. ORACLE — rebuild signing_input by hand and re-sign with an independently-constructed key,
//     reproducing the vector (guards the vector; no src signing functions).
//  3. IMPL   — certVerifySigningInput + signCertVerify reproduce the vector; verifyCertVerify
//     accepts the correct value but REJECTS a role/context mismatch and a wrong transcript (guards
//     the impl + the domain-separation property).
import { test } from "node:test";
import assert from "node:assert";
import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  certVerifySigningInput, signCertVerify, verifyCertVerify,
  ed25519PrivateKeyFromSeed, ed25519PublicKeyFromRaw,
  CONTEXT_SERVER_CERTVERIFY, CONTEXT_CLIENT_CERTVERIFY,
} from "../src/npamp.ts";

const VECTORS = join(import.meta.dirname, "..", "..", "..", "test-vectors", "v1");
const CERTVERIFY_KAT_SHA256 = "f56ec6ba250ba8f8c6c84214a16f580a3e476e9b2cfd05720c3352de299fe555";

const hx = (s) => Buffer.from(s, "hex");

function loadCertVerifyKAT() {
  const raw = readFileSync(join(VECTORS, "certverify-kat.json"));
  const got = createHash("sha256").update(raw).digest("hex");
  assert.equal(got, CERTVERIFY_KAT_SHA256, "CertVerify KAT vector SHA-256 mismatch (swapped vector?)");
  return JSON.parse(raw.toString("utf8"));
}

// rawPub extracts the 32-octet raw Ed25519 public key from a KeyObject (via JWK x).
function rawPub(keyObject) {
  return Buffer.from(keyObject.export({ format: "jwk" }).x, "base64url");
}

// Oracle key construction (RFC 8410 PKCS8 wrap), independent of the src helpers.
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
function oraclePriv(seed) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_ED25519_PREFIX, seed]), format: "der", type: "pkcs8" });
}
// Oracle signing_input, built by hand (independent of certVerifySigningInput).
function oracleSigningInput(ctx, th) {
  return Buffer.concat([Buffer.alloc(64, 0x20), Buffer.from(ctx), Buffer.from([0x00]), th]);
}

// ANCHOR: the src Ed25519 helpers reproduce the published RFC 8032 §7.1 keys + signatures.
test("certverify_kat_rfc8032_anchor", () => {
  const k = loadCertVerifyKAT();
  for (const [name, v] of [["TEST1", k.rfc8032_ed25519.test1], ["TEST2", k.rfc8032_ed25519.test2]]) {
    const priv = ed25519PrivateKeyFromSeed(hx(v.seed));
    assert.equal(rawPub(createPublicKey(priv)).toString("hex"), v.public_key, `${name} derived pubkey != RFC 8032`);
    const sig = sign(null, hx(v.message), priv);
    assert.equal(sig.toString("hex"), v.signature, `${name} signature != RFC 8032`);
    const pub = ed25519PublicKeyFromRaw(hx(v.public_key));
    assert.ok(verify(null, hx(v.message), pub, hx(v.signature)), `${name} ed25519PublicKeyFromRaw failed to verify`);
  }
});

// ORACLE: rebuild signing_input by hand and re-sign with an independent key, reproducing the vector.
test("certverify_kat_oracle", () => {
  const k = loadCertVerifyKAT();
  const n = k.npamp_inputs, e = k.expected, c = k.contexts;
  for (const role of [
    { name: "server", ctx: c.server, seed: n.server_seed, th: n.th_sid, wantSI: e.signing_input_server, wantSig: e.signature_server },
    { name: "client", ctx: c.client, seed: n.client_seed, th: n.th_cid, wantSI: e.signing_input_client, wantSig: e.signature_client },
  ]) {
    const si = oracleSigningInput(role.ctx, hx(role.th));
    assert.equal(si.toString("hex"), role.wantSI, `[${role.name}] oracle signing_input != vector`);
    const sig = sign(null, si, oraclePriv(hx(role.seed)));
    assert.equal(sig.toString("hex"), role.wantSig, `[${role.name}] oracle signature != vector`);
  }
});

// IMPL: certVerifySigningInput + signCertVerify reproduce the vector; verifyCertVerify accepts the
// correct value, rejects a role/context mismatch and a wrong transcript.
test("certverify_kat_impl", () => {
  const k = loadCertVerifyKAT();
  const n = k.npamp_inputs, e = k.expected, c = k.contexts;
  assert.equal(CONTEXT_SERVER_CERTVERIFY, c.server, "server CertVerify context constant drifted from spec §6.1");
  assert.equal(CONTEXT_CLIENT_CERTVERIFY, c.client, "client CertVerify context constant drifted from spec §6.1");
  for (const role of [
    { name: "server", isServer: true, seed: n.server_seed, pub: n.server_pub, th: n.th_sid, wantSI: e.signing_input_server, wantValue: e.certverify_value_server },
    { name: "client", isServer: false, seed: n.client_seed, pub: n.client_pub, th: n.th_cid, wantSI: e.signing_input_client, wantValue: e.certverify_value_client },
  ]) {
    const priv = ed25519PrivateKeyFromSeed(hx(role.seed));
    const pub = ed25519PublicKeyFromRaw(hx(role.pub));
    const th = hx(role.th);

    assert.equal(certVerifySigningInput(role.isServer, th).toString("hex"), role.wantSI, `[${role.name}] certVerifySigningInput != vector`);

    const val = signCertVerify(priv, role.isServer, th);
    assert.equal(val.toString("hex"), role.wantValue, `[${role.name}] signCertVerify value != vector`);

    assert.ok(verifyCertVerify(pub, role.isServer, th, val), `[${role.name}] verifyCertVerify rejected the correct value`);
    // Domain separation: verifying with the opposite role must FAIL (different context string).
    assert.ok(!verifyCertVerify(pub, !role.isServer, th, val), `[${role.name}] verifyCertVerify accepted a role/context mismatch`);
    // Transcript binding: a different transcript hash must FAIL.
    const wrongTH = Buffer.from(th);
    wrongTH[0] ^= 0x01;
    assert.ok(!verifyCertVerify(pub, role.isServer, wrongTH, val), `[${role.name}] verifyCertVerify accepted a wrong transcript hash`);
    // Scheme guard: a non-Ed25519 scheme code point must FAIL.
    const wrongScheme = Buffer.from(val);
    wrongScheme.writeUInt16BE(0x0905, 0); // ML-DSA-87 code point, not Ed25519 (0x0807)
    assert.ok(!verifyCertVerify(pub, role.isServer, th, wrongScheme), `[${role.name}] verifyCertVerify accepted a non-Ed25519 scheme`);
    // Length guard: an Ed25519 signature is exactly 64 octets; a truncated value must FAIL.
    assert.ok(!verifyCertVerify(pub, role.isServer, th, val.subarray(0, val.length - 1)), `[${role.name}] verifyCertVerify accepted a truncated signature`);
  }
});

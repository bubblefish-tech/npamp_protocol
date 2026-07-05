// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 Finished verify_data
// (binding spec/10 §6.2; RFC 8446 §4.4.4): verify_data = HMAC(finished_key, transcript_hash) under
// the profile hash (SHA-256 at Standard). TypeScript mirror of the Go reference test against
// the SAME pinned vector.
//
// NON-CIRCULARITY: the expected verify_data in test-vectors/v1/finished-kat.json were produced with
// HMAC directly, NOT with computeFinished. Three legs:
//  1. ANCHOR — HMAC-SHA-256 reproduces the published RFC 4231 TC1/TC2 MACs (trust the primitive).
//  2. ORACLE — an independent createHmac reproduces verify_data (guards the vector).
//  3. IMPL   — computeFinished reproduces verify_data; verifyFinished accepts the correct MAC and
//     rejects a single-bit tamper (guards the implementation).
// finished_key inputs are fixtures (their DERIVATION is anchored by the key-schedule KAT); the
// transcript_hash inputs are the Transcript KAT's TH_sCV / TH_cCV (the points §6.2 covers).
import { test } from "node:test";
import assert from "node:assert";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { computeFinished, verifyFinished } from "../src/npamp.ts";

const VECTORS = join(import.meta.dirname, "..", "..", "..", "test-vectors", "v1");
const FINISHED_KAT_SHA256 = "25c21b0bd3b3b6b77862f4a819f81ff5e4ff42e4b1d70af81feeedc5aad73c7f";

const hx = (s) => Buffer.from(s, "hex");

function loadFinishedKAT() {
  const raw = readFileSync(join(VECTORS, "finished-kat.json"));
  const got = createHash("sha256").update(raw).digest("hex");
  assert.equal(got, FINISHED_KAT_SHA256, "Finished KAT vector SHA-256 mismatch (swapped vector?)");
  return JSON.parse(raw.toString("utf8"));
}

// hmacOracle is the standard HMAC-SHA-256, independent of computeFinished.
function hmacOracle(key, data) {
  return createHmac("sha256", key).update(data).digest();
}

// ANCHOR: HMAC-SHA-256 reproduces the published RFC 4231 vectors before any verify_data is trusted.
test("finished_kat_rfc4231_anchor", () => {
  const k = loadFinishedKAT();
  for (const [name, tc] of [["TC1", k.rfc4231_hmac_sha256.tc1], ["TC2", k.rfc4231_hmac_sha256.tc2]]) {
    assert.equal(hmacOracle(hx(tc.key), hx(tc.data)).toString("hex"), tc.hmac_sha256, `HMAC-SHA-256 ${name} != RFC 4231`);
  }
});

// ORACLE: reproduce verify_data with an independent createHmac (guards the vector).
test("finished_kat_oracle", () => {
  const k = loadFinishedKAT();
  const n = k.npamp_inputs, e = k.expected;
  assert.equal(hmacOracle(hx(n.finished_key_server), hx(n.th_scv)).toString("hex"), e.verify_data_server, "oracle server verify_data");
  assert.equal(hmacOracle(hx(n.finished_key_client), hx(n.th_ccv)).toString("hex"), e.verify_data_client, "oracle client verify_data");
});

// IMPL: computeFinished reproduces verify_data; verifyFinished accepts the correct MAC, rejects a tamper.
test("finished_kat_impl", () => {
  const k = loadFinishedKAT();
  const n = k.npamp_inputs, e = k.expected;
  for (const c of [
    { name: "server", fk: n.finished_key_server, th: n.th_scv, want: e.verify_data_server },
    { name: "client", fk: n.finished_key_client, th: n.th_ccv, want: e.verify_data_client },
  ]) {
    const fk = hx(c.fk), th = hx(c.th), want = hx(c.want);
    assert.equal(computeFinished(fk, th, true).toString("hex"), c.want, `[${c.name}] computeFinished mismatch`);
    assert.ok(verifyFinished(fk, th, want, true), `[${c.name}] verifyFinished rejected the correct verify_data`);
    const bad = Buffer.from(want);
    bad[0] ^= 0x01;
    assert.ok(!verifyFinished(fk, th, bad, true), `[${c.name}] verifyFinished accepted a tampered verify_data`);
  }
});

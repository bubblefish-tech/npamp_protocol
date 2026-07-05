// Standards-derived, NON-CIRCULAR known-answer test for the draft-00 transcript construction
// (binding spec/10 §3). TypeScript mirror of the Go reference test, so both reference impls grade
// against the SAME pinned, FIPS-180-4-anchored vector.
//
// NON-CIRCULARITY: the expected TH_* in test-vectors/v1/transcript-kat.json were produced by an
// INDEPENDENT byte-constructor (frame-type as 2-octet BE; each TLV as Type(2 BE)||Length(2 BE)||
// Value) + SHA-256 — NOT by the Transcript class under test. This file checks three legs:
//  1. ANCHOR — SHA-256("abc") reproduces the FIPS 180-4 known answer (trust the hash primitive).
//  2. ORACLE — an in-test manual constructor reproduces every TH_* (guards the vector).
//  3. IMPL   — the real Transcript class reproduces every TH_* (guards the implementation).
import { test } from "node:test";
import assert from "node:assert";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Transcript, FRAME_CLIENT_HELLO, FRAME_SERVER_HELLO, FRAME_SERVER_AUTH, FRAME_CLIENT_AUTH } from "../src/npamp.ts";

// Canonical vector lives at GitHub/test-vectors/v1/; this test file is at GitHub/impl/typescript/test/.
const VECTORS = join(import.meta.dirname, "..", "..", "..", "test-vectors", "v1");

// Pins test-vectors/v1/transcript-kat.json (same SHA-256 the Go reference pins). A swapped vector
// fails loud before any TH_* is trusted.
const TRANSCRIPT_KAT_SHA256 = "fab6d852497b6ff56405595e9a014d0c45cabc5cde80a60a17444b337d556ee5";

function loadTranscriptKAT() {
  const raw = readFileSync(join(VECTORS, "transcript-kat.json"));
  const got = createHash("sha256").update(raw).digest("hex");
  assert.equal(got, TRANSCRIPT_KAT_SHA256, "transcript KAT vector SHA-256 mismatch (swapped vector?)");
  return JSON.parse(raw.toString("utf8"));
}

function trimHexPrefix(s) {
  return s.startsWith("0x") || s.startsWith("0X") ? s.slice(2) : s;
}

// transcriptInputs decodes every TLV in the vector into name -> {typ, val}. TLV names are unique
// across the vector (Server*/Client* distinguish the two AUTH frames).
function transcriptInputs(k) {
  const m = new Map();
  for (const f of k.frames) {
    for (const tl of f.tlvs) {
      const typ = parseInt(trimHexPrefix(tl.type), 16);
      const val = Buffer.from(tl.value, "hex");
      assert.ok(!m.has(tl.name), `duplicate TLV name ${tl.name} in vector`);
      m.set(tl.name, { typ, val });
    }
  }
  return m;
}

// transcriptAbsorb drives the spec §3 absorption order: ft(frameType) begins a frame, tlv(name)
// appends one TLV's bytes, snap() takes a transcript-hash point (hex). It returns the five cut
// points. The sequence (which TLV, where each TH_* falls) IS spec §1/§3 structure; the per-element
// bytes come from the vector via the caller's closures.
function transcriptAbsorb(ft, tlv, snap) {
  ft(0x0100); // CLIENT_HELLO
  for (const n of ["ProfileOffer", "KEMOffer", "SigOffer", "AEADOffer", "KEMShare"]) tlv(n);
  ft(0x0101); // SERVER_HELLO
  for (const n of ["ProfileSelect", "KEMSelect", "SigSelect", "AEADSelect", "KEMCiphertext"]) tlv(n);
  const thKem = snap();

  ft(0x0102); // SERVER_AUTH
  tlv("ServerIdentityKey");
  const thSId = snap();
  tlv("ServerCertVerify");
  const thSCV = snap(); // excludes ServerFinished
  tlv("ServerFinished");

  ft(0x0103); // CLIENT_AUTH
  tlv("ClientIdentityKey");
  const thCId = snap();
  tlv("ClientCertVerify");
  const thCCV = snap(); // excludes ClientFinished
  tlv("ClientFinished");

  return { thKem, thSId, thSCV, thCId, thCCV };
}

function checkTH(leg, k, pts) {
  const exp = k.expected_transcript_points;
  assert.equal(pts.thKem, exp.th_kem, `[${leg}] TH_kem mismatch`);
  assert.equal(pts.thSId, exp.th_sid, `[${leg}] TH_sId mismatch`);
  assert.equal(pts.thSCV, exp.th_scv, `[${leg}] TH_sCV mismatch`);
  assert.equal(pts.thCId, exp.th_cid, `[${leg}] TH_cId mismatch`);
  assert.equal(pts.thCCV, exp.th_ccv, `[${leg}] TH_cCV mismatch`);
}

// ANCHOR: prove the test's SHA-256 is the real FIPS 180-4 primitive before any TH_* is trusted.
test("transcript_kat_fips180_anchor", () => {
  const k = loadTranscriptKAT();
  const fips = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
  assert.equal(createHash("sha256").update(k.fips180_4_sha256_abc.input_ascii).digest("hex"), fips);
  assert.equal(k.fips180_4_sha256_abc.digest, fips);
});

// ORACLE: reproduce every TH_* with an in-test manual constructor (no Transcript), guarding the vector.
test("transcript_kat_oracle", () => {
  const k = loadTranscriptKAT();
  const m = transcriptInputs(k);
  let buf = Buffer.alloc(0);
  const ft = (v) => {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(v, 0);
    buf = Buffer.concat([buf, b]);
  };
  const tlv = (name) => {
    const e = m.get(name);
    const h = Buffer.alloc(4);
    h.writeUInt16BE(e.typ, 0);
    h.writeUInt16BE(e.val.length, 2);
    buf = Buffer.concat([buf, h, e.val]);
  };
  const snap = () => createHash("sha256").update(buf).digest("hex");
  checkTH("oracle", k, transcriptAbsorb(ft, tlv, snap));
});

// IMPL: reproduce every TH_* with the real Transcript class, guarding the implementation.
test("transcript_kat_impl", () => {
  const k = loadTranscriptKAT();
  const m = transcriptInputs(k);
  // Frame-type constants must equal the spec §1 code points the vector/oracle absorption assumes.
  assert.equal(FRAME_CLIENT_HELLO, 0x0100, "FRAME_CLIENT_HELLO drifted from spec §1");
  assert.equal(FRAME_SERVER_HELLO, 0x0101, "FRAME_SERVER_HELLO drifted from spec §1");
  assert.equal(FRAME_SERVER_AUTH, 0x0102, "FRAME_SERVER_AUTH drifted from spec §1");
  assert.equal(FRAME_CLIENT_AUTH, 0x0103, "FRAME_CLIENT_AUTH drifted from spec §1");
  const tr = new Transcript();
  const ft = (v) => tr.addFrameType(v);
  const tlv = (name) => {
    const e = m.get(name);
    tr.addTLV(e.typ, e.val);
  };
  const snap = () => tr.hash(true).toString("hex");
  checkTH("impl", k, transcriptAbsorb(ft, tlv, snap));
});

// Byte-pinned handshake-flow known-answer test (issue #60, class golden-interop). Unlike the
// standards-anchored primitive KATs (transcript / key-schedule / certverify / finished), this vector
// pins the Go reference's SERIALIZED handshake frames so every language impl reproduces them
// byte-for-byte. The CLIENT_HELLO assertion below is the one that would have caught the
// draft-00-vs-draft-01 ProfileOffer wire drift (a fixed 4-octet ProfileOffer vs the draft-01
// one-octet-per-profile form). TypeScript mirror of the Go reference verifier
// impl/go/handshakeflow_kat_test.go and the Java mirror HandshakeFlowKat.java, against the SAME
// pinned vector (test-vectors/v1/handshake-flow-kat.json).
//
// This runner rebuilds every EXPECTED artifact through THIS impl's real code path from the pinned
// INPUTS and asserts WHOLE-frame byte-equality (client_hello / server_hello / server_auth /
// client_auth), transcript points, the full spec/10 §5 key ladder, Finished keys + MACs, CertVerify
// signatures, and the AUTH plaintexts; then mutation-guards (a one-octet-flipped server CertVerify
// signature AND client Finished MAC must REJECT).
//
// KEM leg honesty (mirrors the Java sibling's contract). The X25519 leg is decapsulated for REAL
// through node:crypto (client scalar × server public, where server public is the 32-octet tail of the
// pinned kem_ciphertext) and asserted against the pinned x25519_shared_secret. The ML-KEM leg is a
// pinned self-validating input: Node's built-in ML-KEM (crypto.generateKeyPairSync("ml-kem-768",
// {seed})) does NOT honor the FIPS 203 d||z seed deterministically — it silently generates a random
// key (verified: two calls with the same seed yield different encapsulation keys and neither matches
// the Go reference's), so Node cannot reconstruct Go's decapsulation key to recover the pinned
// mlkem_shared_secret. This impl therefore consumes mlkem_shared_secret from the vector and asserts
// its structural placement (kem_ciphertext = mlkem_ciphertext || server_x25519_public) byte-exactly,
// plus combined_secret = mlkem_ss || x25519_ss. Every OTHER artifact is rebuilt through the impl's
// real crypto (encodeClientHello / encodeServerHello / encodeAuthMessage, Transcript, the key
// schedule, signCertVerify / computeFinished, and the AEAD record path).
import { test } from "node:test";
import assert from "node:assert";
import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  Frame,
  Transcript,
  encodeClientHello, encodeServerHello, encodeAuthMessage,
  x25519PrivateKeyFromRaw, x25519PublicKeyFromRaw, x25519SharedSecret,
  ed25519PrivateKeyFromSeed, ed25519PublicKeyFromRaw,
  signCertVerify, verifyCertVerify, computeFinished, verifyFinished,
  deriveHandshakeSecret, deriveClientHandshakeSecret, deriveServerHandshakeSecret,
  deriveMasterSecret, deriveFinishedKey, deriveTrafficSecret, deriveKeyIv,
  sealAes256Gcm,
  FRAME_CLIENT_HELLO, FRAME_SERVER_HELLO, FRAME_SERVER_AUTH, FRAME_CLIENT_AUTH,
  TLV_PROFILE_OFFER, TLV_KEM_OFFER, TLV_SIG_OFFER, TLV_AEAD_OFFER, TLV_KEM_SHARE,
  TLV_PROFILE_SELECT, TLV_KEM_SELECT, TLV_SIG_SELECT, TLV_AEAD_SELECT, TLV_KEM_CIPHERTEXT,
  TLV_IDENTITY_KEY, TLV_CERT_VERIFY, TLV_FINISHED,
  PROFILE_STANDARD, KEM_X25519_MLKEM768, SIG_ED25519, AEAD_AES256_GCM,
  CHAN_CONTROL, FLAG_ENC,
} from "../src/npamp.ts";

// Canonical vector lives at GitHub/test-vectors/v1/; this test file is at GitHub/impl/typescript/test/.
const VECTORS = join(import.meta.dirname, "..", "..", "..", "test-vectors", "v1");

// Pins test-vectors/v1/handshake-flow-kat.json (same SHA-256 the Go/Java references pin). A swapped
// vector fails loud before any artifact is trusted.
const HANDSHAKE_FLOW_KAT_SHA256 = "0c89003cd95c4bef744e021797ccd169b062e0a058d2a6e2b17e164eb4e9bad2";

// Standard profile (SHA-256, 32-octet secrets). The vector's "profile" is "Standard".
const STANDARD = true;
const X25519_PUBLIC_LEN = 32; // the tail of kem_ciphertext / kem_share

// Direction bytes (spec/10 §5 / §7.5 traffic context): ClientToServer = 0, ServerToClient = 1.
const DIR_CLIENT_TO_SERVER = 0x00;
const DIR_SERVER_TO_CLIENT = 0x01;

const hx = (s: string) => Buffer.from(s, "hex");

function loadHandshakeFlowKAT() {
  const raw = readFileSync(join(VECTORS, "handshake-flow-kat.json"));
  const got = createHash("sha256").update(raw).digest("hex");
  assert.equal(got, HANDSHAKE_FLOW_KAT_SHA256, "handshake-flow KAT vector SHA-256 mismatch (swapped vector?)");
  return JSON.parse(raw.toString("utf8"));
}

// Derives the raw 32-octet Ed25519 public key from a seed (RFC 8032) via the impl's key helper:
// build the private KeyObject from the seed, then recover the public point. Node exposes the raw
// public key as the JWK "x" (base64url) of the derived public KeyObject.
function ed25519RawPublic(seed: Buffer): Buffer {
  const priv = ed25519PrivateKeyFromSeed(seed);
  const pubObj = createPublicKey(priv);
  return Buffer.from(pubObj.export({ format: "jwk" }).x, "base64url");
}

// marshalCleartextFrame serializes a cleartext handshake frame (Control channel, seq 0) through the
// impl's real record path (Frame.marshal builds the 36-octet header + CRC-32C).
function marshalCleartextFrame(frameType: number, payload: Buffer): Buffer {
  return new Frame({ ftype: frameType, channel: CHAN_CONTROL, seq: 0, payload }).marshal();
}

// sealAuthFrame seals an AUTH plaintext into a wire frame through the impl's real key-schedule +
// record path: derive the traffic secret from the direction's handshake secret, derive key/iv, then
// AEAD-seal under the 21-octet header prefix and marshal the FLAG_ENC frame (mirrors the Go
// sealAuthKAT / Java sealAuthFrame). AAD length = plaintext + 16 (the GCM tag).
function sealAuthFrame(frameType: number, baseSecret: Buffer, dir: number, plaintext: Buffer): Buffer {
  const ts = deriveTrafficSecret(baseSecret, dir, 0n, AEAD_AES256_GCM, CHAN_CONTROL, STANDARD);
  const [key, iv] = deriveKeyIv(ts, STANDARD);
  const f = new Frame({ flags: FLAG_ENC, ftype: frameType, channel: CHAN_CONTROL, seq: 0 });
  const aad = f.headerPrefix(plaintext.length + 16);
  const sealed = sealAes256Gcm(key, iv, 0n, aad, plaintext);
  f.payload = sealed;
  return f.marshal();
}

// TestHandshakeFlowKAT rebuilds every handshake artifact through the real impl code path from the
// frozen pinned inputs and asserts byte-equality with the expected wire bytes.
test("handshake_flow_kat", () => {
  const k = loadHandshakeFlowKAT();
  assert.equal(k.profile, "Standard", "vector profile drifted from Standard");
  assert.equal(k.aead, "AES-256-GCM", "vector AEAD drifted from AES-256-GCM");
  assert.equal(k.hash, "SHA-256", "vector hash drifted from SHA-256");

  // Frame-type + TLV code points the vector/oracle assume must equal the impl's spec §1 constants.
  assert.equal(FRAME_CLIENT_HELLO, 0x0100, "FRAME_CLIENT_HELLO drifted from spec §1");
  assert.equal(FRAME_SERVER_HELLO, 0x0101, "FRAME_SERVER_HELLO drifted from spec §1");
  assert.equal(FRAME_SERVER_AUTH, 0x0102, "FRAME_SERVER_AUTH drifted from spec §1");
  assert.equal(FRAME_CLIENT_AUTH, 0x0103, "FRAME_CLIENT_AUTH drifted from spec §1");

  // --- Pinned inputs ---
  const clientX25519Priv = hx(k.inputs.client_x25519_private);
  const mlkemCiphertext = hx(k.inputs.mlkem_ciphertext);
  const clientEdSeed = hx(k.inputs.client_identity_ed25519_seed);
  const serverEdSeed = hx(k.inputs.server_identity_ed25519_seed);
  const wantMlkemSs = hx(k.inputs.mlkem_shared_secret);
  const wantX25519Ss = hx(k.inputs.x25519_shared_secret);
  const wantCombined = hx(k.inputs.combined_secret);

  // --- Long-term Ed25519 identities from the fixed seeds (deterministic pubkeys) ---
  const clientEdPriv = ed25519PrivateKeyFromSeed(clientEdSeed);
  const serverEdPriv = ed25519PrivateKeyFromSeed(serverEdSeed);
  const clientPub = ed25519RawPublic(clientEdSeed);
  const serverPub = ed25519RawPublic(serverEdSeed);
  const clientPubKey = ed25519PublicKeyFromRaw(clientPub);
  const serverPubKey = ed25519PublicKeyFromRaw(serverPub);

  // --- KEM wire structure + REAL X25519 decapsulation ---
  // The pinned kem_ciphertext = ml-kem ciphertext || server X25519 public.
  const kemCiphertext = hx(k.expected.kem.kem_ciphertext);
  const kemShare = hx(k.expected.kem.kem_share);
  const ctFront = kemCiphertext.subarray(0, kemCiphertext.length - X25519_PUBLIC_LEN);
  const serverX25519Pub = kemCiphertext.subarray(kemCiphertext.length - X25519_PUBLIC_LEN);
  assert.ok(ctFront.equals(mlkemCiphertext), "kem: kem_ciphertext front != pinned mlkem_ciphertext input");
  const clientX25519Pub = kemShare.subarray(kemShare.length - X25519_PUBLIC_LEN);
  assert.equal(clientX25519Pub.length, X25519_PUBLIC_LEN, "kem: kem_share must carry a 32-octet X25519 tail");

  // REAL X25519 leg: client scalar × server public must recover the pinned x25519_shared_secret.
  const x25519Ss = x25519SharedSecret(
    x25519PrivateKeyFromRaw(clientX25519Priv),
    x25519PublicKeyFromRaw(serverX25519Pub),
  );
  assert.equal(x25519Ss.toString("hex"), k.inputs.x25519_shared_secret, "kem: X25519 decapsulation != pinned x25519_shared_secret");
  assert.ok(x25519Ss.equals(wantX25519Ss), "kem: x25519_shared_secret internal mismatch");

  // ML-KEM leg: Node's built-in ML-KEM cannot reproduce Go's seed-derived key (the {seed} option is
  // non-deterministic here), so mlkem_shared_secret is the pinned self-validating input. Combine
  // ML-KEM-first (ADR-0005): combined = ML-KEM_SS || X25519_SS.
  const combined = Buffer.concat([wantMlkemSs, x25519Ss]);
  assert.equal(combined.toString("hex"), k.inputs.combined_secret, "kem: combined_secret != ml-kem_ss || x25519_ss");
  assert.ok(combined.equals(wantCombined), "kem: pinned combined_secret is internally inconsistent");

  // --- CLIENT_HELLO whole-frame byte-equality (the ProfileOffer wire-drift guard) ---
  // encodeClientHello emits the draft-01 one-octet-per-profile ProfileOffer; a draft-00 fixed
  // 4-octet ProfileOffer would fail this exact assertion.
  const chPayload = encodeClientHello(
    [PROFILE_STANDARD], [KEM_X25519_MLKEM768], [SIG_ED25519], [AEAD_AES256_GCM], kemShare,
  );
  const chFrame = marshalCleartextFrame(FRAME_CLIENT_HELLO, chPayload);
  assert.equal(chFrame.toString("hex"), k.expected.frames.client_hello, "frame: client_hello whole-frame byte-equality failed (ProfileOffer drift?)");

  // --- SERVER_HELLO whole-frame byte-equality ---
  const shPayload = encodeServerHello(
    PROFILE_STANDARD, KEM_X25519_MLKEM768, SIG_ED25519, AEAD_AES256_GCM, kemCiphertext,
  );
  const shFrame = marshalCleartextFrame(FRAME_SERVER_HELLO, shPayload);
  assert.equal(shFrame.toString("hex"), k.expected.frames.server_hello, "frame: server_hello whole-frame byte-equality failed");

  // --- Transcript + key ladder through the REAL impl ---
  const u16 = (v: number) => { const b = Buffer.alloc(2); b.writeUInt16BE(v & 0xffff, 0); return b; };
  const tr = new Transcript();
  // CLIENT_HELLO: frame type then its five TLVs, in wire order.
  tr.addFrameType(FRAME_CLIENT_HELLO);
  tr.addTLV(TLV_PROFILE_OFFER, Buffer.from([PROFILE_STANDARD]));
  tr.addTLV(TLV_KEM_OFFER, u16(KEM_X25519_MLKEM768));
  tr.addTLV(TLV_SIG_OFFER, u16(SIG_ED25519));
  tr.addTLV(TLV_AEAD_OFFER, u16(AEAD_AES256_GCM));
  tr.addTLV(TLV_KEM_SHARE, kemShare);
  // SERVER_HELLO: frame type then its five TLVs.
  tr.addFrameType(FRAME_SERVER_HELLO);
  tr.addTLV(TLV_PROFILE_SELECT, Buffer.from([PROFILE_STANDARD]));
  tr.addTLV(TLV_KEM_SELECT, u16(KEM_X25519_MLKEM768));
  tr.addTLV(TLV_SIG_SELECT, u16(SIG_ED25519));
  tr.addTLV(TLV_AEAD_SELECT, u16(AEAD_AES256_GCM));
  tr.addTLV(TLV_KEM_CIPHERTEXT, kemCiphertext);
  const thKem = tr.hash(STANDARD);
  assert.equal(thKem.toString("hex"), k.expected.transcript.th_kem, "transcript: th_kem mismatch");

  // handshake_secret = HKDF-Extract(0-salt, ML-KEM_SS || X25519_SS).
  const hs = deriveHandshakeSecret(wantMlkemSs, x25519Ss, STANDARD);
  assert.equal(hs.toString("hex"), k.expected.secrets.handshake_secret, "secret: handshake_secret mismatch");
  const cHS = deriveClientHandshakeSecret(hs, thKem, STANDARD);
  const sHS = deriveServerHandshakeSecret(hs, thKem, STANDARD);
  assert.equal(cHS.toString("hex"), k.expected.secrets.c_hs_secret, "secret: c_hs_secret mismatch");
  assert.equal(sHS.toString("hex"), k.expected.secrets.s_hs_secret, "secret: s_hs_secret mismatch");

  // --- SERVER_AUTH: IdentityKey, then TH_sId, CertVerify, TH_sCV, Finished ---
  tr.addFrameType(FRAME_SERVER_AUTH);
  tr.addTLV(TLV_IDENTITY_KEY, serverPub);
  const thSID = tr.hash(STANDARD);
  assert.equal(thSID.toString("hex"), k.expected.transcript.th_sid, "transcript: th_sid mismatch");
  const sCV = signCertVerify(serverEdPriv, true, thSID);
  assert.equal(sCV.toString("hex"), k.expected.cert_verify.server, "certverify: server mismatch");
  assert.ok(verifyCertVerify(serverPubKey, true, thSID, sCV), "certverify: server failed to verify");
  tr.addTLV(TLV_CERT_VERIFY, sCV);
  const thSCV = tr.hash(STANDARD);
  assert.equal(thSCV.toString("hex"), k.expected.transcript.th_scv, "transcript: th_scv mismatch");
  const sFinKey = deriveFinishedKey(sHS, STANDARD);
  assert.equal(sFinKey.toString("hex"), k.expected.finished_keys.server, "finished_key: server mismatch");
  const sFin = computeFinished(sFinKey, thSCV, STANDARD);
  assert.equal(sFin.toString("hex"), k.expected.finished.server, "finished: server mismatch");
  tr.addTLV(TLV_FINISHED, sFin);
  const serverAuthPlain = encodeAuthMessage(serverPub, sCV, sFin);
  assert.equal(serverAuthPlain.toString("hex"), k.expected.auth_plaintext.server_auth, "auth_plaintext: server_auth mismatch");
  const serverAuthFrame = sealAuthFrame(FRAME_SERVER_AUTH, sHS, DIR_SERVER_TO_CLIENT, serverAuthPlain);
  assert.equal(serverAuthFrame.toString("hex"), k.expected.frames.server_auth, "frame: server_auth whole-frame byte-equality failed");

  // --- CLIENT_AUTH: IdentityKey, then TH_cId, CertVerify, TH_cCV, Finished ---
  tr.addFrameType(FRAME_CLIENT_AUTH);
  tr.addTLV(TLV_IDENTITY_KEY, clientPub);
  const thCID = tr.hash(STANDARD);
  assert.equal(thCID.toString("hex"), k.expected.transcript.th_cid, "transcript: th_cid mismatch");
  const cCV = signCertVerify(clientEdPriv, false, thCID);
  assert.equal(cCV.toString("hex"), k.expected.cert_verify.client, "certverify: client mismatch");
  assert.ok(verifyCertVerify(clientPubKey, false, thCID, cCV), "certverify: client failed to verify");
  tr.addTLV(TLV_CERT_VERIFY, cCV);
  const thCCV = tr.hash(STANDARD);
  assert.equal(thCCV.toString("hex"), k.expected.transcript.th_ccv, "transcript: th_ccv mismatch");
  const cFinKey = deriveFinishedKey(cHS, STANDARD);
  assert.equal(cFinKey.toString("hex"), k.expected.finished_keys.client, "finished_key: client mismatch");
  const cFin = computeFinished(cFinKey, thCCV, STANDARD);
  assert.equal(cFin.toString("hex"), k.expected.finished.client, "finished: client mismatch");
  const clientAuthPlain = encodeAuthMessage(clientPub, cCV, cFin);
  assert.equal(clientAuthPlain.toString("hex"), k.expected.auth_plaintext.client_auth, "auth_plaintext: client_auth mismatch");
  const clientAuthFrame = sealAuthFrame(FRAME_CLIENT_AUTH, cHS, DIR_CLIENT_TO_SERVER, clientAuthPlain);
  assert.equal(clientAuthFrame.toString("hex"), k.expected.frames.client_auth, "frame: client_auth whole-frame byte-equality failed");

  // --- Master secret + application-phase traffic keys ---
  const master = deriveMasterSecret(hs, thCCV, STANDARD);
  assert.equal(master.toString("hex"), k.expected.secrets.master_secret, "secret: master_secret mismatch");

  const checkTrafficKeyIv = (name: string, parent: Buffer, dir: number) => {
    const ts = deriveTrafficSecret(parent, dir, 0n, AEAD_AES256_GCM, CHAN_CONTROL, STANDARD);
    assert.equal(ts.toString("hex"), k.expected.secrets[`${name}_traffic_secret`], `secret: ${name}_traffic_secret mismatch`);
    const [key, iv] = deriveKeyIv(ts, STANDARD);
    assert.equal(key.toString("hex"), k.expected.secrets[`${name}_key`], `secret: ${name}_key mismatch`);
    assert.equal(iv.toString("hex"), k.expected.secrets[`${name}_iv`], `secret: ${name}_iv mismatch`);
  };
  checkTrafficKeyIv("c_hs", cHS, DIR_CLIENT_TO_SERVER);
  checkTrafficKeyIv("s_hs", sHS, DIR_SERVER_TO_CLIENT);
  checkTrafficKeyIv("app_c2s", master, DIR_CLIENT_TO_SERVER);
  checkTrafficKeyIv("app_s2c", master, DIR_SERVER_TO_CLIENT);

  // --- Mutation guard 1: a one-octet flip in the server CertVerify signature must REJECT. ---
  const badCV = Buffer.from(sCV);
  badCV[badCV.length - 1] ^= 0x01; // flip a signature bit (last octet of the Ed25519 sig)
  assert.ok(!verifyCertVerify(serverPubKey, true, thSID, badCV), "mutation: a one-octet-flipped server CertVerify signature VERIFIED");

  // --- Mutation guard 2: a one-octet flip in the client Finished MAC must REJECT. ---
  const badFin = Buffer.from(cFin);
  badFin[0] ^= 0x01;
  assert.ok(!verifyFinished(cFinKey, thCCV, badFin, STANDARD), "mutation: a one-octet-flipped client Finished MAC VERIFIED");

  // --- Sanity: the untouched signature and MAC still verify. ---
  assert.ok(verifyCertVerify(serverPubKey, true, thSID, sCV), "sanity: unmutated server CertVerify should verify");
  assert.ok(verifyFinished(cFinKey, thCCV, cFin, STANDARD), "sanity: unmutated client Finished should verify");
});

// Open reference implementation of the N-PAMP wire format (draft-bubblefish-npamp-00).
// OPEN protocol layer only: framing, registries, AEAD record layer, key schedule.
// No proprietary methods, parameters, or weights.
import { createHash, createHmac, createCipheriv, createDecipheriv, timingSafeEqual, createPrivateKey, createPublicKey, sign, verify, diffieHellman, KeyObject } from "node:crypto";

export const HEADER_SIZE = 36;
export const PROTOCOL_VERSION = 0x2;
export const MAGIC = Buffer.from("NPAM");
export const ALPN = "n-pamp/2";
export const LABEL_PREFIX = "n-pamp "; // protocol-specific; NOT "tls13 "

export const FLAG_URG = 0x01, FLAG_ENC = 0x02, FLAG_COMP = 0x04, FLAG_FRAG = 0x08;
export const CHAN_CONTROL = 0x0000, CHAN_MEMORY = 0x0001, CHAN_IMMUNE = 0x0005, CHAN_AUDIT = 0x000b, CHAN_BRIDGE = 0x000d, CHAN_SPATIAL = 0x0013;
export const FRAME_PING = 0x0001, FRAME_PONG = 0x0002, FRAME_CLOSE = 0x0003, FRAME_FLOW_UPDATE = 0x000a, CHANNEL_SPECIFIC_BASE = 0x0100;
export const TLV_PROFILE_OFFER = 0x01, TLV_KEM_CIPHERTEXT = 0x08, TLV_ANOMALY_CHARGE = 0x12;
export const KEM_X25519_MLKEM768 = 0x11ec, KEM_X25519_MLKEM1024 = 0x11ed;
export const AEAD_AES256_GCM = 0x0001, AEAD_CHACHA20_POLY1305 = 0x0002;
export const SIG_ED25519 = 0x0807, SIG_MLDSA87 = 0x0905;

// CRC32C (Castagnoli, reflected) - identical to Go hash/crc32 Castagnoli.
export function crc32c(data: Buffer): number {
  const POLY = 0x82f63b78;
  let crc = 0xffffffff;
  for (const b of data) {
    crc ^= b;
    for (let i = 0; i < 8; i++) crc = (crc & 1) ? ((crc >>> 1) ^ POLY) : (crc >>> 1);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export class Frame {
  version: number; flags: number; ftype: number; channel: number; seq: bigint; payload: Buffer;
  constructor(o: { version?: number; flags?: number; ftype?: number; channel?: number; seq?: number | bigint; payload?: Buffer }) {
    this.version = o.version ?? 0;
    this.flags = o.flags ?? 0;
    this.ftype = o.ftype ?? 0;
    this.channel = o.channel ?? 0;
    this.seq = BigInt(o.seq ?? 0);
    this.payload = o.payload ?? Buffer.alloc(0);
  }
  headerPrefix(payloadLen: number): Buffer {
    const ver = this.version || PROTOCOL_VERSION;
    const out = Buffer.alloc(21);
    MAGIC.copy(out, 0);
    out[4] = (ver << 4) | (this.flags & 0x0f);
    out.writeUInt16BE(this.ftype, 5);
    out.writeUInt16BE(this.channel, 7);
    out.writeBigUInt64BE(this.seq, 9);
    out.writeUInt32BE(payloadLen, 17);
    return out;
  }
  marshal(): Buffer {
    const prefix = this.headerPrefix(this.payload.length);
    const out = Buffer.alloc(HEADER_SIZE + this.payload.length);
    prefix.copy(out, 0);
    out.writeUInt32BE(crc32c(prefix), 21);
    this.payload.copy(out, HEADER_SIZE);
    return out;
  }
  static unmarshal(buf: Buffer): Frame {
    if (buf.length < HEADER_SIZE) throw new Error("short header");
    if (buf.readUInt32BE(21) !== crc32c(buf.subarray(0, 21))) throw new Error("bad crc");
    if (!buf.subarray(0, 4).equals(MAGIC)) throw new Error("bad magic");
    const ver = buf[4] >> 4;
    if (ver !== PROTOCOL_VERSION) throw new Error("bad version");
    for (let i = 25; i < HEADER_SIZE; i++) if (buf[i] !== 0) throw new Error("reserved nonzero");
    const plen = buf.readUInt32BE(17);
    if (plen !== buf.length - HEADER_SIZE) throw new Error("length mismatch");
    const f = new Frame({ ftype: buf.readUInt16BE(5), channel: buf.readUInt16BE(7) });
    f.version = ver;
    f.flags = buf[4] & 0x0f;
    f.seq = buf.readBigUInt64BE(9);
    f.payload = Buffer.from(buf.subarray(HEADER_SIZE));
    return f;
  }
}

// Per-frame AEAD nonce (draft-00 7.5): IV XOR left-zero-padded seq. No channel.
export function deriveNonce(iv: Buffer, seq: bigint): Buffer {
  const n = Buffer.alloc(12);
  n.writeBigUInt64BE(seq, 4);
  for (let i = 0; i < 12; i++) n[i] ^= iv[i];
  return n;
}

export function sealAes256Gcm(key: Buffer, iv: Buffer, seq: bigint, aad: Buffer, pt: Buffer): Buffer {
  const c = createCipheriv("aes-256-gcm", key, deriveNonce(iv, seq));
  c.setAAD(aad);
  const enc = Buffer.concat([c.update(pt), c.final()]);
  return Buffer.concat([enc, c.getAuthTag()]);
}

export function openAes256Gcm(key: Buffer, iv: Buffer, seq: bigint, aad: Buffer, sealed: Buffer): Buffer {
  const tag = sealed.subarray(sealed.length - 16);
  const ct = sealed.subarray(0, sealed.length - 16);
  const d = createDecipheriv("aes-256-gcm", key, deriveNonce(iv, seq));
  d.setAAD(aad);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

// HKDF-Expand (RFC 5869), expand-only (PRK supplied).
export function hkdfExpand(hash: string, prk: Buffer, info: Buffer, length: number): Buffer {
  const hashLen = hash === "sha256" ? 32 : 48;
  const n = Math.ceil(length / hashLen);
  let t = Buffer.alloc(0);
  const out: Buffer[] = [];
  for (let i = 1; i <= n; i++) {
    t = createHmac(hash, prk).update(Buffer.concat([t, info, Buffer.from([i])])).digest();
    out.push(t);
  }
  return Buffer.concat(out).subarray(0, length);
}

export function hkdfExpandLabel(secret: Buffer, label: string, context: Buffer, length: number, standard: boolean): Buffer {
  const full = Buffer.from(LABEL_PREFIX + label);
  const info = Buffer.concat([
    Buffer.from([(length >> 8) & 0xff, length & 0xff]),
    Buffer.from([full.length]), full,
    Buffer.from([context.length]), context,
  ]);
  return hkdfExpand(standard ? "sha256" : "sha384", secret, info, length);
}

export function deriveTrafficSecret(master: Buffer, dir: number, epoch: bigint, suite: number, channel: number, standard: boolean): Buffer {
  const ctx = Buffer.alloc(1 + 8 + 2 + 2);
  ctx[0] = dir;
  ctx.writeBigUInt64BE(epoch, 1);
  ctx.writeUInt16BE(suite, 9);
  ctx.writeUInt16BE(channel, 11);
  return hkdfExpandLabel(master, "traffic", ctx, standard ? 32 : 48, standard);
}

export function deriveKeyIv(secret: Buffer, standard: boolean): [Buffer, Buffer] {
  return [hkdfExpandLabel(secret, "key", Buffer.alloc(0), 32, standard), hkdfExpandLabel(secret, "iv", Buffer.alloc(0), 12, standard)];
}

// ----------------------------------------------------------------------------
// Handshake key schedule trunk (binding spec/10 §5; ML-KEM-first per ADR-0005). The leaves above
// (hkdfExpand / hkdfExpandLabel / deriveTrafficSecret / deriveKeyIv) are reused unchanged; the
// functions below add HKDF-Extract and the handshake-secret ladder that feeds them.
// ----------------------------------------------------------------------------

// HKDF-Extract (RFC 5869 §2.2): extract(salt, ikm) = HMAC-Hash(salt, ikm). Hash is SHA-256 at
// Standard, SHA-384 at High/Sovereign — wired through the same `standard` flag as the leaves.
export function hkdfExtract(salt: Buffer, ikm: Buffer, standard: boolean): Buffer {
  return createHmac(standard ? "sha256" : "sha384", salt).update(ikm).digest();
}

// deriveHandshakeSecret runs the §5 extract step. The IKM is the two KEM shared secrets concatenated
// with ML-KEM FIRST (ADR-0005): ikm = ML-KEM_SS || X25519_SS. The binding's default salt is HashLen
// zero octets (32 at Standard / SHA-256). mlkemSs and x25519Ss are shared secrets (IKM), not keys.
export function deriveHandshakeSecret(mlkemSs: Buffer, x25519Ss: Buffer, standard: boolean): Buffer {
  const salt = Buffer.alloc(standard ? 32 : 48); // HashLen zero octets
  const ikm = Buffer.concat([mlkemSs, x25519Ss]); // ML-KEM concatenated first
  return hkdfExtract(salt, ikm, standard);
}

// The handshake-secret ladder (binding spec/10 §5): c_hs / s_hs bind TH_kem; master binds TH_ccv.
// Labels are exactly "c hs" / "s hs" / "master" — the "n-pamp " prefix is added by hkdfExpandLabel.
export function deriveClientHandshakeSecret(handshakeSecret: Buffer, thKem: Buffer, standard: boolean): Buffer {
  return hkdfExpandLabel(handshakeSecret, "c hs", thKem, standard ? 32 : 48, standard);
}

export function deriveServerHandshakeSecret(handshakeSecret: Buffer, thKem: Buffer, standard: boolean): Buffer {
  return hkdfExpandLabel(handshakeSecret, "s hs", thKem, standard ? 32 : 48, standard);
}

export function deriveMasterSecret(handshakeSecret: Buffer, thCcv: Buffer, standard: boolean): Buffer {
  return hkdfExpandLabel(handshakeSecret, "master", thCcv, standard ? 32 : 48, standard);
}

// deriveFinishedKey (binding spec/10 §6.2 / §5.4): finished_key = HKDF-Expand-Label(secret,
// "finished", "" /*empty context*/, HashLen). The client Finished key derives from c_hs; the server
// Finished key derives from s_hs. This is the KEY; computeFinished consumes it to produce the MAC.
export function deriveFinishedKey(secret: Buffer, standard: boolean): Buffer {
  return hkdfExpandLabel(secret, "finished", Buffer.alloc(0), standard ? 32 : 48, standard);
}

// ----------------------------------------------------------------------------
// Handshake binding layer (draft-00 binding spec/10): transcript construction.
// ----------------------------------------------------------------------------

// Handshake frame types (spec §1), carried on the control channel.
export const FRAME_CLIENT_HELLO = 0x0100, FRAME_SERVER_HELLO = 0x0101, FRAME_SERVER_AUTH = 0x0102, FRAME_CLIENT_AUTH = 0x0103;

// Security profiles (draft-00 §6). Standard = 0x01 (SHA-256, 32-octet secrets).
export const PROFILE_STANDARD = 0x01, PROFILE_HIGH = 0x02, PROFILE_SOVEREIGN = 0x03;

// KEM/Sig/AEAD registry code points used by the handshake flights (spec §1/§4).
export const KEM_X25519_MLKEM768_CP = KEM_X25519_MLKEM768;

// Handshake TLV types (registry §9.4 / spec/10 §1.1) beyond the negotiation TLVs declared above.
export const TLV_KEM_OFFER = 0x03, TLV_SIG_OFFER = 0x05, TLV_KEM_SHARE = 0x07;
export const TLV_PROFILE_SELECT = 0x02, TLV_KEM_SELECT = 0x04, TLV_SIG_SELECT = 0x06, TLV_AEAD_SELECT = 0x0d;
export const TLV_IDENTITY_KEY = 0x09, TLV_CERT_VERIFY = 0x0a, TLV_FINISHED = 0x0b, TLV_AEAD_OFFER = 0x0c;

// encodeTLV appends one TLV to dst in canonical wire form (Type u16 BE || Length u16 BE || Value),
// the draft-00 §4.5 encoding shared by every handshake flight and the AUTH plaintext.
export function encodeTLV(type: number, value: Buffer): Buffer {
  const hdr = Buffer.alloc(4);
  hdr.writeUInt16BE(type & 0xffff, 0);
  hdr.writeUInt16BE(value.length, 2);
  return Buffer.concat([hdr, value]);
}

function u16be(v: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(v & 0xffff, 0);
  return b;
}

// encodeClientHello returns the CLIENT_HELLO frame payload (spec/10 §1): the five TLVs
// ProfileOffer, KEMOffer, SigOffer, AEADOffer, KEMShare, in that order.
//
// ProfileOffer is the draft-01 VARIABLE-LENGTH form: ONE OCTET PER PROFILE (a single 0x01 for
// {Standard}). The draft-00 fixed 4-octet ProfileOffer (Buffer.alloc(4)) would produce different
// bytes and FAIL the handshake-flow KAT client_hello byte-equality — this encoder is the drift guard.
export function encodeClientHello(profiles: number[], kems: number[], sigs: number[], aeads: number[], kemShare: Buffer): Buffer {
  const profileOffer = Buffer.from(profiles.map((p) => p & 0xff)); // one octet per profile (draft-01)
  const u16list = (ids: number[]) => Buffer.concat(ids.map(u16be));
  return Buffer.concat([
    encodeTLV(TLV_PROFILE_OFFER, profileOffer),
    encodeTLV(TLV_KEM_OFFER, u16list(kems)),
    encodeTLV(TLV_SIG_OFFER, u16list(sigs)),
    encodeTLV(TLV_AEAD_OFFER, u16list(aeads)),
    encodeTLV(TLV_KEM_SHARE, kemShare),
  ]);
}

// encodeServerHello returns the SERVER_HELLO frame payload (spec/10 §1): ProfileSelect (1 octet),
// KEMSelect, SigSelect, AEADSelect (2 octets each), KEMCiphertext, in that order.
export function encodeServerHello(profile: number, kem: number, sig: number, aead: number, kemCiphertext: Buffer): Buffer {
  return Buffer.concat([
    encodeTLV(TLV_PROFILE_SELECT, Buffer.from([profile & 0xff])),
    encodeTLV(TLV_KEM_SELECT, u16be(kem)),
    encodeTLV(TLV_SIG_SELECT, u16be(sig)),
    encodeTLV(TLV_AEAD_SELECT, u16be(aead)),
    encodeTLV(TLV_KEM_CIPHERTEXT, kemCiphertext),
  ]);
}

// encodeAuthMessage returns the SERVER_AUTH / CLIENT_AUTH plaintext (spec/10 §6.4): exactly three
// TLVs in order — IdentityKey, CertVerify, Finished — sealed by the record layer at the call site.
export function encodeAuthMessage(identityKey: Buffer, certVerify: Buffer, finished: Buffer): Buffer {
  return Buffer.concat([
    encodeTLV(TLV_IDENTITY_KEY, identityKey),
    encodeTLV(TLV_CERT_VERIFY, certVerify),
    encodeTLV(TLV_FINISHED, finished),
  ]);
}

// RFC 8410 DER prefixes that wrap a raw 32-octet X25519 scalar / public u-coordinate into a
// KeyObject (Node has no raw-scalar X25519 constructor). OID 1.3.101.110 = id-X25519.
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

export function x25519PrivateKeyFromRaw(raw: Buffer): KeyObject {
  return createPrivateKey({ key: Buffer.concat([X25519_PKCS8_PREFIX, raw]), format: "der", type: "pkcs8" });
}

export function x25519PublicKeyFromRaw(raw: Buffer): KeyObject {
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

// x25519SharedSecret performs the raw RFC 7748 ECDH (client scalar × server public u), the X25519
// leg of the X25519MLKEM768 hybrid KEM (spec/10 §4). Returns the 32-octet shared secret.
export function x25519SharedSecret(privateKey: KeyObject, publicKey: KeyObject): Buffer {
  return diffieHellman({ privateKey, publicKey });
}

// Transcript accumulates the draft-00 handshake transcript (binding spec/10 §3) and hashes it at a
// cut point. Absorption granularity is per-TLV: addFrameType appends the 2-octet frame type ONLY
// (NOT the rest of the 36-octet frame header — the spec §3/§7.1 divergence from RFC 8446 §4.4.1);
// addTLV appends Type(2 BE)||Length(2 BE)||Value. A transcript point = hash over all bytes absorbed
// so far (SHA-256 at Standard, SHA-384 at High/Sovereign).
export class Transcript {
  #buf: Buffer = Buffer.alloc(0);
  addFrameType(ft: number): void {
    const b = Buffer.alloc(2);
    b.writeUInt16BE(ft & 0xffff, 0);
    this.#buf = Buffer.concat([this.#buf, b]);
  }
  addTLV(type: number, value: Buffer): void {
    const h = Buffer.alloc(4);
    h.writeUInt16BE(type & 0xffff, 0);
    h.writeUInt16BE(value.length, 2);
    this.#buf = Buffer.concat([this.#buf, h, value]);
  }
  hash(standard: boolean): Buffer {
    return createHash(standard ? "sha256" : "sha384").update(this.#buf).digest();
  }
}

// Finished (binding spec/10 §6.2; RFC 8446 §4.4.4): verify_data = HMAC(finished_key, transcript_hash)
// under the profile hash (SHA-256 at Standard, SHA-384 at High/Sovereign).
export function computeFinished(finishedKey: Buffer, transcriptHash: Buffer, standard: boolean): Buffer {
  return createHmac(standard ? "sha256" : "sha384", finishedKey).update(transcriptHash).digest();
}

// verifyFinished recomputes the Finished MAC and constant-time-compares it to the received
// verify_data. A length mismatch is a definite reject (timingSafeEqual requires equal lengths).
export function verifyFinished(finishedKey: Buffer, transcriptHash: Buffer, verifyData: Buffer, standard: boolean): boolean {
  const want = computeFinished(finishedKey, transcriptHash, standard);
  return want.length === verifyData.length && timingSafeEqual(want, verifyData);
}

// CertVerify (binding spec/10 §6.1; RFC 8446 §4.4.3 structure; Ed25519 signatures per RFC 8032).
export const CONTEXT_SERVER_CERTVERIFY = "N-PAMP/2, server CertificateVerify";
export const CONTEXT_CLIENT_CERTVERIFY = "N-PAMP/2, client CertificateVerify";

// RFC 8410 DER prefixes that wrap a raw 32-octet Ed25519 seed / public key into a KeyObject (Node
// has no raw-seed Ed25519 constructor). The anchored KAT proves these reproduce RFC 8032 keys.
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function ed25519PrivateKeyFromSeed(seed: Buffer): KeyObject {
  return createPrivateKey({ key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]), format: "der", type: "pkcs8" });
}

export function ed25519PublicKeyFromRaw(raw: Buffer): KeyObject {
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

// certVerifySigningInput builds the §6.1 signing input: 64 octets of 0x20, the role context string,
// a 0x00 separator, then the transcript hash — TLS-1.3-style domain separation (RFC 8446 §4.4.3).
export function certVerifySigningInput(isServer: boolean, transcriptHash: Buffer): Buffer {
  const ctx = Buffer.from(isServer ? CONTEXT_SERVER_CERTVERIFY : CONTEXT_CLIENT_CERTVERIFY);
  return Buffer.concat([Buffer.alloc(64, 0x20), ctx, Buffer.from([0x00]), transcriptHash]);
}

// signCertVerify produces the CertVerify TLV value: u16(0x0807, Ed25519) || Ed25519(priv, signing_input).
export function signCertVerify(privateKey: KeyObject, isServer: boolean, transcriptHash: Buffer): Buffer {
  const sig = sign(null, certVerifySigningInput(isServer, transcriptHash), privateKey);
  const scheme = Buffer.alloc(2);
  scheme.writeUInt16BE(SIG_ED25519, 0);
  return Buffer.concat([scheme, sig]);
}

// verifyCertVerify checks a CertVerify TLV value against the signer's public key, role, and
// transcript hash. It rejects a non-Ed25519 scheme, a role/context mismatch, or a wrong transcript.
export function verifyCertVerify(publicKey: KeyObject, isServer: boolean, transcriptHash: Buffer, value: Buffer): boolean {
  if (value.length < 2 || value.readUInt16BE(0) !== SIG_ED25519) return false;
  const sig = value.subarray(2);
  if (sig.length !== 64) return false; // Ed25519 signatures are exactly 64 octets (RFC 8032 §5.1.6)
  return verify(null, certVerifySigningInput(isServer, transcriptHash), publicKey, sig);
}

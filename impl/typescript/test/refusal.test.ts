// The open TypeScript module implements the Standard profile only. Every key-schedule, transcript
// and Finished primitive refuses a non-Standard profile with NoSuiteForProfile and still succeeds
// at Standard. No external authority (RFC or FIPS) defines this module's scope, so these are
// behaviour checks, not conformance vectors.
import { test } from "node:test";
import assert from "node:assert";
import {
  NoSuiteForProfile,
  AEAD_AES256_GCM,
  CHAN_CONTROL,
  hkdfExpand,
  hkdfExpandLabel,
  hkdfExtract,
  deriveTrafficSecret,
  deriveKeyIv,
  deriveHandshakeSecret,
  deriveClientHandshakeSecret,
  deriveServerHandshakeSecret,
  deriveMasterSecret,
  deriveFinishedKey,
  computeFinished,
  verifyFinished,
  Transcript,
} from "../src/npamp.ts";

const secret = Buffer.alloc(32, 0x11);
const th = Buffer.alloc(32, 0x22);

test("standard profile control succeeds", () => {
  assert.equal(hkdfExpandLabel(secret, "key", Buffer.alloc(0), 32, true).length, 32);
  assert.equal(hkdfExtract(Buffer.alloc(32), secret, true).length, 32);
  assert.equal(hkdfExpand("sha256", secret, Buffer.from("info"), 32).length, 32);
  assert.equal(deriveTrafficSecret(secret, 0, 0n, AEAD_AES256_GCM, CHAN_CONTROL, true).length, 32);
  const [k, iv] = deriveKeyIv(secret, true);
  assert.deepEqual([k.length, iv.length], [32, 12]);
  assert.equal(deriveHandshakeSecret(secret, secret, true).length, 32);
  assert.equal(deriveFinishedKey(secret, true).length, 32);
  assert.equal(new Transcript().hash(true).length, 32);
  const mac = computeFinished(secret, th, true);
  assert.ok(verifyFinished(secret, th, mac, true));
});

const refused: Array<[string, () => unknown]> = [
  ["hkdfExpand sha384", () => hkdfExpand("sha384", secret, Buffer.from("info"), 48)],
  ["hkdfExpand sha512", () => hkdfExpand("sha512", secret, Buffer.from("info"), 48)],
  ["hkdfExpandLabel", () => hkdfExpandLabel(secret, "key", Buffer.alloc(0), 32, false)],
  ["hkdfExtract", () => hkdfExtract(Buffer.alloc(48), secret, false)],
  ["deriveTrafficSecret", () => deriveTrafficSecret(secret, 0, 0n, AEAD_AES256_GCM, CHAN_CONTROL, false)],
  ["deriveKeyIv", () => deriveKeyIv(secret, false)],
  ["deriveHandshakeSecret", () => deriveHandshakeSecret(secret, secret, false)],
  ["deriveClientHandshakeSecret", () => deriveClientHandshakeSecret(secret, th, false)],
  ["deriveServerHandshakeSecret", () => deriveServerHandshakeSecret(secret, th, false)],
  ["deriveMasterSecret", () => deriveMasterSecret(secret, th, false)],
  ["deriveFinishedKey", () => deriveFinishedKey(secret, false)],
  ["Transcript.hash", () => new Transcript().hash(false)],
  ["computeFinished", () => computeFinished(secret, th, false)],
  ["verifyFinished", () => verifyFinished(secret, th, th, false)],
];
for (const [name, call] of refused) {
  test(`non-standard profile is refused: ${name}`, () => {
    assert.throws(call, NoSuiteForProfile);
  });
}

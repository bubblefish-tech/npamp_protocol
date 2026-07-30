// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
//
// Independent crypto KAT: drive N-PAMP's AES-256-GCM seal/open through Google Project
// Wycheproof vectors, via the dependency-free flat corpus
// _shared/wycheproof/aesgcm_kat.tsv (keySize=256, ivSize=96, tagSize=128). These vectors
// are authored by an independent authority and encode KNOWN ATTACKS (truncated tags,
// modified ciphertext) that our self-generated golden vectors never include, so a shared
// bug between our impls cannot pass them.
//
// Trick: sealAes256Gcm(key, iv, seq, ...) derives nonce = iv XOR (0^4||seq); with seq=0 the
// nonce IS the given iv, so each vector exercises the REAL seal/open path.
//
// Exit 0 iff every vector behaves exactly as Wycheproof labels it, and total > 0.
// TypeScript port of the PHP reference runner test/kat_aesgcm.php.
//
// Run from impl/typescript:  node bin/npamp-kat.ts <TSV-path>

import { readFileSync } from "node:fs";
import { sealAes256Gcm, openAes256Gcm } from "../src/npamp.ts";

function fromHex(s: string): Buffer {
  return Buffer.from(s, "hex");
}

// Externally-provided Wycheproof corpus: pass as argv[2], set NPAMP_SHARED_DIR, or place at ../_shared.
const sharedDir = process.env.NPAMP_SHARED_DIR ?? new URL("../_shared", import.meta.url).pathname;
const tsvPath = process.argv[2] ?? `${sharedDir}/wycheproof/aesgcm_kat.tsv`;

let contents: string;
try {
  contents = readFileSync(tsvPath, "utf8");
} catch {
  process.stderr.write(`cannot read TSV: ${tsvPath}\n`);
  process.exit(1);
}

let total = 0;
let passed = 0;
const fails: string[] = [];

for (const line of contents.split(/\r\n|\n|\r/)) {
  if (line === "" || line[0] === "#") {
    continue;
  }
  const f = line.split("\t");
  if (f.length !== 8) {
    throw new Error(`expected 8 columns, got ${f.length}: ${line}`);
  }
  const [tc, result, keyHex, ivHex, aadHex, msgHex, ctHex, tagHex] = f;
  const key = fromHex(keyHex);
  const iv = fromHex(ivHex);
  const aad = fromHex(aadHex);
  const msg = fromHex(msgHex);
  const sealed = Buffer.concat([fromHex(ctHex), fromHex(tagHex)]);

  let ok = true;
  let reason = "";

  if (result === "valid") {
    let gotSealed: Buffer | null = null;
    try {
      gotSealed = sealAes256Gcm(key, iv, 0n, aad, msg);
    } catch {
      gotSealed = null;
    }
    if (gotSealed === null || !gotSealed.equals(sealed)) {
      ok = false;
      reason = "encrypt mismatch";
    } else {
      let gotPt: Buffer | null = null;
      try {
        gotPt = openAes256Gcm(key, iv, 0n, aad, sealed);
      } catch {
        gotPt = null;
      }
      if (gotPt === null || !gotPt.equals(msg)) {
        ok = false;
        reason = "decrypt mismatch";
      }
    }
  } else if (result === "invalid") {
    try {
      openAes256Gcm(key, iv, 0n, aad, sealed);
      ok = false;
      reason = "accepted an invalid vector";
    } catch {
      // correct: rejected
    }
  } else {
    // "acceptable"
    try {
      const gotPt = openAes256Gcm(key, iv, 0n, aad, sealed);
      if (!gotPt.equals(msg)) {
        ok = false;
        reason = "acceptable but wrong plaintext";
      }
    } catch {
      // rejection is also allowed for acceptable
    }
  }

  total++;
  if (ok) {
    passed++;
  } else {
    fails.push(`  FAIL tcId=${tc} result=${result}: ${reason}`);
  }
}

process.stdout.write(`AES-256-GCM Wycheproof KAT (typescript): ${passed}/${total} passed\n`);
for (const line of fails.slice(0, 15)) {
  process.stdout.write(line + "\n");
}
process.exit(fails.length === 0 && total > 0 ? 0 : 1);

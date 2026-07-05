// Reference npamp_00 conformance adapter (TypeScript). A third-language "testee" proving
// the runner is language-agnostic. Reads length-prefixed JSON requests {op,in} on stdin,
// writes length-prefixed JSON responses {out|error|skipped} on stdout, performing the real
// npamp_00 primitive for each op by CALLING the impl/typescript reference implementation
// (src/npamp.ts) -- it does not reimplement the primitives.
//
// Windows note: reads/writes the binary stdio streams (process.stdin/stdout are binary in
// Node; no CRLF translation is applied to Buffers) and FLUSHES nothing extra is needed since
// Node flushes Buffer writes, but we wait for the drain/callback to guarantee ordering.
//
// Mapping notes (adapter -> reference):
//  - crc32c(octets)        -> crc32c(buf) from src/npamp.ts (number -> 4-byte big-endian hex)
//  - header.encode(fields) -> new Frame({...}).marshal()  (frame is header(36) + payload(0))
//  - header.decode(frame)  -> Frame.unmarshal(buf); crc/fields read back from the buffer
//  - aead.seal/open        -> sealAes256Gcm/openAes256Gcm(key, iv=nonce, seq=0n, aad, pt|sealed)
//                             with seq=0 the impl's deriveNonce(iv,0) == iv, so the raw nonce
//                             from the corpus is used verbatim on the REAL seal/open path.
//  - hkdf.expand           -> hkdfExpand(hash, prk, info, length) from src/npamp.ts
//  - tlv.decode            -> wire TLV parse (the reference impl ships no TLV decoder)
//  - profile.check         -> skipped (the reference impl ships no profile checker)
import { writeSync } from "node:fs";
import {
  crc32c,
  Frame,
  sealAes256Gcm,
  openAes256Gcm,
  hkdfExpand,
  HEADER_SIZE,
  MAGIC,
} from "../../../impl/typescript/src/npamp.ts";

const BREAK = process.argv.slice(2).includes("--break");

type Req = { op?: string; in?: Record<string, unknown> };
type Resp =
  | { out: Record<string, unknown> }
  | { error: string }
  | { skipped: string };

function s(o: Record<string, unknown>, k: string): string {
  const v = o[k];
  return typeof v === "string" ? v : "";
}
function num(o: Record<string, unknown>, k: string): number {
  const v = o[k];
  return typeof v === "number" ? v : Number(v ?? 0);
}
function hx(o: Record<string, unknown>, k: string): Buffer {
  return Buffer.from(s(o, k), "hex");
}
function u32hex(n: number): string {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b.toString("hex");
}

function handle(req: Req): Resp {
  const op = req.op;
  const i = req.in ?? {};
  switch (op) {
    case "header.encode": {
      // Build the frame from its fields via the reference Frame + marshal().
      const f = new Frame({
        version: num(i, "ver"),
        flags: num(i, "flags"),
        ftype: num(i, "frameType"),
        channel: num(i, "channel"),
        seq: BigInt(num(i, "seq")),
        // payload is empty for header vectors; payloadLength encodes from payload.length,
        // and the golden vectors carry payloadLength 0.
      });
      return { out: { frame: f.marshal().toString("hex") } };
    }

    case "header.decode": {
      const b = hx(i, "frame");
      if (b.length !== HEADER_SIZE) return { error: "malformed header length" };
      let f: Frame;
      try {
        f = Frame.unmarshal(b);
      } catch (e) {
        return { error: (e as Error).message };
      }
      return {
        out: {
          magic: MAGIC.toString("latin1"),
          ver: f.version,
          flags: f.flags,
          frameType: f.ftype,
          channel: f.channel,
          seq: Number(f.seq),
          payloadLength: b.readUInt32BE(17),
          crc32c: b.subarray(21, 25).toString("hex"),
          reservedZero: true,
        },
      };
    }

    case "crc32c": {
      const b = hx(i, "octets");
      let c = u32hex(crc32c(b));
      if (BREAK) c = "deadbeef"; // deliberate corruption for the runner's mutation check
      return { out: { crc32c: c } };
    }

    case "tlv.decode": {
      const b = hx(i, "tlv");
      if (b.length < 4) return { error: "truncated tlv" };
      const typ = b.readUInt16BE(0);
      const length = b.readUInt16BE(2);
      if (typ & 0x8000)
        return { error: "unknown forward-incompatible TLV (high bit set)" };
      if (length !== b.length - 4) return { error: "tlv length mismatch" };
      return {
        out: { type: typ, length, value: b.subarray(4).toString("hex") },
      };
    }

    case "aead.seal": {
      if (s(i, "suite") !== "AES-256-GCM")
        return { skipped: "suite not implemented: " + s(i, "suite") };
      try {
        // seq=0n -> deriveNonce(iv,0)==iv, so the corpus nonce is used as-is.
        const sealed = sealAes256Gcm(
          hx(i, "key"),
          hx(i, "nonce"),
          0n,
          hx(i, "aad"),
          hx(i, "pt"),
        );
        return { out: { sealed: sealed.toString("hex") } };
      } catch (e) {
        return { error: (e as Error).message };
      }
    }

    case "aead.open": {
      if (s(i, "suite") !== "AES-256-GCM")
        return { skipped: "suite not implemented: " + s(i, "suite") };
      try {
        const pt = openAes256Gcm(
          hx(i, "key"),
          hx(i, "nonce"),
          0n,
          hx(i, "aad"),
          hx(i, "sealed"),
        );
        return { out: { pt: pt.toString("hex") } };
      } catch {
        return { error: "authentication failed" };
      }
    }

    case "hkdf.expand": {
      const hash = s(i, "hash");
      if (hash !== "sha256" && hash !== "sha384")
        return { skipped: "hash not implemented: " + hash };
      const okm = hkdfExpand(hash, hx(i, "prk"), hx(i, "info"), num(i, "length"));
      return { out: { okm: okm.toString("hex") } };
    }

    case "profile.check":
      // The OPEN reference implementation ships no profile-acceptance checker.
      return { skipped: "profile.check not implemented in reference impl" };

    default:
      return { skipped: "op not implemented: " + op };
  }
}

// ---- length-prefixed framing over binary stdin/stdout ----
// 4-byte little-endian length N, then N bytes of JSON. Repeat until stdin closes.

function writeResp(resp: Resp): void {
  const ob = Buffer.from(JSON.stringify(resp), "utf8");
  const ol = Buffer.alloc(4);
  ol.writeUInt32LE(ob.length, 0);
  // Synchronous write to fd 1 guarantees the bytes are flushed and ordered on Windows,
  // so the length prefix and JSON body are never split or reordered across responses.
  writeSync(1, ol);
  writeSync(1, ob);
}

function main(): void {
  let buffered = Buffer.alloc(0);

  function drain(): void {
    for (;;) {
      if (buffered.length < 4) return;
      const n = buffered.readUInt32LE(0);
      if (buffered.length < 4 + n) return;
      const body = buffered.subarray(4, 4 + n);
      buffered = buffered.subarray(4 + n);
      let resp: Resp;
      try {
        resp = handle(JSON.parse(body.toString("utf8")) as Req);
      } catch (e) {
        resp = { error: "adapter exception: " + (e as Error).message };
      }
      writeResp(resp);
    }
  }

  process.stdin.on("data", (c: Buffer) => {
    buffered = Buffer.concat([buffered, c]);
    drain();
  });
  process.stdin.on("end", () => process.exit(0));
  process.stdin.on("close", () => process.exit(0));
}

main();

// Open reference implementation of the N-PAMP native-channel body codec
// (draft-bubblefish-npamp-01). OPEN protocol layer only: the deterministic
// (canonical) CBOR subset that every native operation channel (NPAMP-MEMORY,
// -STREAM, -CAP, -IMMUNE, -SETTLEMENT, -TELEMETRY, -COMMERCE, -INTERACT,
// -WORKFLOW, -KNOWLEDGE) encodes its bodies in. No proprietary methods.
//
// This is a straight port of the Go reference codec impl/go/memory_cbor.go
// (spec/companion/81_memory_channel.md §4; RFC 8949 §4.2.1 core-deterministic).
// It implements exactly the subset the native bodies use — unsigned integers,
// negative integers, byte strings, text strings, arrays, maps, and the simple
// values false/true/null — all definite-length, shortest-form, with map keys in
// canonical (bytewise-of-encoded-key) order. It is deliberately NOT a general
// CBOR library: on decode it REJECTS anything outside this subset (indefinite
// lengths, non-shortest integer/length encodings, tags, floats, other simple
// values, and out-of-order or duplicate map keys), which is precisely what a
// deterministic-encoding receiver MUST reject.
//
// Decoded value types (mirroring the Go uint64/int64/[]byte/string/[]any/
// *cborMap/bool/nil): integers decode to bigint (major 0 → a non-negative
// bigint; major 1 → a negative bigint), byte strings to Buffer, text strings to
// string, arrays to CborValue[], maps to CborMap, and the three simple values to
// boolean / null.

export type CborValue = bigint | Buffer | string | CborValue[] | CborMap | boolean | null;

export class CborError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CborError";
  }
}

// byteLess reports whether a sorts strictly before b in bytewise (shorter-prefix-
// first, then lexicographic) order — RFC 8949 §4.2.1 canonical map-key ordering.
export function byteLess(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return a.length < b.length;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return a[i] < b[i];
    }
  }
  return false;
}

interface CborEntry {
  keyEnc: Buffer; // canonical encoding of the key, used for ordering + equality
  key: CborValue;
  val: CborValue;
}

// CborMap is a CBOR map preserving canonical key order. Keys are themselves CBOR
// values (here always bigint/string/Buffer); entries are kept in the order they
// were decoded, which the decoder has already verified is canonical ascending.
export class CborMap {
  readonly entries: CborEntry[];
  constructor(entries: CborEntry[]) {
    this.entries = entries;
  }

  // get returns the value for an unsigned-integer key (the form every native
  // envelope/body key takes) and undefined if absent. Maps here hold a handful of
  // keys, so a direct scan over the canonically-ordered entries is used.
  get(key: number | bigint): CborValue | undefined {
    const ke = encodeHead(0, BigInt(key));
    for (const e of this.entries) {
      if (ke.equals(e.keyEnc)) {
        return e.val;
      }
    }
    return undefined;
  }

  has(key: number | bigint): boolean {
    return this.get(key) !== undefined;
  }

  // keys returns every key in canonical order (used for forward-compat checks).
  keys(): CborValue[] {
    return this.entries.map((e) => e.key);
  }
}

// encodeHead encodes a CBOR type header (major<<5 | argument) in shortest form.
// Used both for encoding integer keys for lookup and internally by the decoder is
// not needed; kept here to build lookup keys deterministically.
export function encodeHead(major: number, arg: bigint): Buffer {
  const mb = major << 5;
  if (arg < 24n) {
    return Buffer.from([mb | Number(arg)]);
  }
  if (arg < 1n << 8n) {
    return Buffer.from([mb | 24, Number(arg)]);
  }
  if (arg < 1n << 16n) {
    return Buffer.from([mb | 25, Number((arg >> 8n) & 0xffn), Number(arg & 0xffn)]);
  }
  if (arg < 1n << 32n) {
    return Buffer.from([
      mb | 26,
      Number((arg >> 24n) & 0xffn),
      Number((arg >> 16n) & 0xffn),
      Number((arg >> 8n) & 0xffn),
      Number(arg & 0xffn),
    ]);
  }
  const out = Buffer.alloc(9);
  out[0] = mb | 27;
  for (let i = 8; i >= 1; i--) {
    out[i] = Number(arg & 0xffn);
    arg >>= 8n;
  }
  return out;
}

// decodeTop decodes a single canonical CBOR item and requires that it consumes
// all of b (no trailing bytes) — the shape of a frame payload.
export function decodeTop(b: Buffer): CborValue {
  const [v, n] = decode(b, 0);
  if (n !== b.length) {
    throw new CborError("npamp/cbor: trailing bytes after top-level item");
  }
  return v;
}

// decode decodes one item from b starting at off, returning the value and the
// absolute offset just past it. It enforces the deterministic subset strictly.
function decode(b: Buffer, off: number): [CborValue, number] {
  if (off >= b.length) {
    throw new CborError("npamp/cbor: truncated input");
  }
  const ib = b[off];
  const major = ib >> 5;
  const ai = ib & 0x1f;

  if (major === 7) {
    // Simple values and floats. Only false(20)/true(21)/null(22) are in the
    // deterministic subset; floats (25/26/27), other simple values, and the break
    // stop (31) are rejected.
    switch (ai) {
      case 20:
        return [false, off + 1];
      case 21:
        return [true, off + 1];
      case 22:
        return [null, off + 1];
      default:
        throw new CborError("npamp/cbor: unsupported major type or simple value");
    }
  }

  const [arg, hdrLen] = decodeArg(ai, b, off);
  const n = off + hdrLen; // absolute offset just past the header

  switch (major) {
    case 0: // unsigned int
      return [arg, n];
    case 1: // negative int: value = -1 - arg
      return [-1n - arg, n];
    case 2:
    case 3: {
      // byte string / text string
      const len = Number(arg);
      const end = n + len;
      if (arg > BigInt(b.length) || end > b.length || end < n) {
        throw new CborError("npamp/cbor: truncated input");
      }
      const payload = b.subarray(n, end);
      if (major === 2) {
        return [Buffer.from(payload), end];
      }
      return [payload.toString("utf8"), end];
    }
    case 4: {
      // array. Each element is at least one byte, so a declared count larger than
      // the remaining input cannot be satisfied — reject before iterating on the
      // attacker-controlled count (huge-count DoS guard).
      if (arg > BigInt(b.length - n)) {
        throw new CborError("npamp/cbor: truncated input");
      }
      const count = Number(arg);
      const out: CborValue[] = [];
      let cur = n;
      for (let i = 0; i < count; i++) {
        const [el, en] = decode(b, cur);
        out.push(el);
        cur = en;
      }
      return [out, cur];
    }
    case 5: {
      // map. Each entry is a key plus a value — at least two bytes — so a declared
      // count larger than the remaining input cannot be satisfied.
      if (arg > BigInt(b.length - n)) {
        throw new CborError("npamp/cbor: truncated input");
      }
      const count = Number(arg);
      const entries: CborEntry[] = [];
      let cur = n;
      let prevKeyEnc: Buffer | null = null;
      for (let i = 0; i < count; i++) {
        const keyStart = cur;
        const [key, kn] = decode(b, cur);
        const keyEnc = Buffer.from(b.subarray(keyStart, kn));
        // Canonical order: each key MUST sort strictly after the previous one.
        if (prevKeyEnc !== null && !byteLess(prevKeyEnc, keyEnc)) {
          throw new CborError("npamp/cbor: map keys not in canonical ascending order (or duplicate)");
        }
        prevKeyEnc = keyEnc;
        cur = kn;
        const [val, vn] = decode(b, cur);
        cur = vn;
        entries.push({ keyEnc, key, val });
      }
      return [new CborMap(entries), cur];
    }
    default: // major 6 (tags): unsupported
      throw new CborError("npamp/cbor: unsupported major type or simple value");
  }
}

// decodeArg reads the argument for an additional-information value ai from b[off],
// enforcing shortest-form (RFC 8949 §4.2.1) and rejecting indefinite lengths.
// Returns the argument and the header length (including the leading byte).
function decodeArg(ai: number, b: Buffer, off: number): [bigint, number] {
  if (ai < 24) {
    return [BigInt(ai), 1];
  }
  switch (ai) {
    case 24: {
      if (off + 2 > b.length) {
        throw new CborError("npamp/cbor: truncated input");
      }
      const v = BigInt(b[off + 1]);
      if (v < 24n) {
        throw new CborError("npamp/cbor: integer/length not in shortest form");
      }
      return [v, 2];
    }
    case 25: {
      if (off + 3 > b.length) {
        throw new CborError("npamp/cbor: truncated input");
      }
      const v = (BigInt(b[off + 1]) << 8n) | BigInt(b[off + 2]);
      if (v < 1n << 8n) {
        throw new CborError("npamp/cbor: integer/length not in shortest form");
      }
      return [v, 3];
    }
    case 26: {
      if (off + 5 > b.length) {
        throw new CborError("npamp/cbor: truncated input");
      }
      let v = 0n;
      for (let i = 1; i <= 4; i++) {
        v = (v << 8n) | BigInt(b[off + i]);
      }
      if (v < 1n << 16n) {
        throw new CborError("npamp/cbor: integer/length not in shortest form");
      }
      return [v, 5];
    }
    case 27: {
      if (off + 9 > b.length) {
        throw new CborError("npamp/cbor: truncated input");
      }
      let v = 0n;
      for (let i = 1; i <= 8; i++) {
        v = (v << 8n) | BigInt(b[off + i]);
      }
      if (v < 1n << 32n) {
        throw new CborError("npamp/cbor: integer/length not in shortest form");
      }
      return [v, 9];
    }
    case 31:
      throw new CborError("npamp/cbor: indefinite-length item (non-deterministic)");
    default: // 28,29,30 are reserved
      throw new CborError("npamp/cbor: unsupported major type or simple value");
  }
}

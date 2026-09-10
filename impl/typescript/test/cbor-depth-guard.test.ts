// CBOR nesting-depth resource guard test for the TypeScript N-PAMP body decoder.
//
// Mirrors the Go reference guard (impl/go/memory_cbor.go, cborMaxNestingDepth = 8)
// against the spec-derived, non-circular conformance vectors:
//   - REJECT: eight 0x81 (array-of-one) headers followed by 0x00 (scalar at
//     depth 9) -> CborDepthExceededError.
//   - ACCEPT: seven 0x81 headers followed by 0x00 (scalar at depth 8) -> decodes.

import { test } from "node:test";
import assert from "node:assert";

import { decodeTop, CborDepthExceededError, type CborValue } from "../src/npamp_cbor.ts";

test("depth_9_scalar_rejected_with_depth_exceeded", () => {
  // Eight 0x81 (array, 1 element) headers + a 0x00 scalar: the scalar sits at
  // depth 9 (outermost array = depth 1, ..., 8th nested array = depth 8, its
  // element = depth 9). MUST be rejected with the depth-exceeded error.
  const b = Buffer.from([0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00]);
  assert.throws(() => decodeTop(b), CborDepthExceededError);
});

test("depth_8_scalar_accepted", () => {
  // Seven 0x81 headers + a 0x00 scalar: the scalar sits at depth 8 (outermost
  // array = depth 1, ..., 7th nested array = depth 7, its element = depth 8).
  // MUST be accepted (decodes without error).
  const b = Buffer.from([0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x81, 0x00]);
  let v: CborValue = decodeTop(b);
  for (let i = 0; i < 7; i++) {
    assert.ok(Array.isArray(v) && v.length === 1);
    v = (v as CborValue[])[0];
  }
  assert.strictEqual(v, 0n);
});

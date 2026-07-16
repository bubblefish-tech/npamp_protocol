// Open reference implementation of the N-PAMP native-channel body validators
// (draft-bubblefish-npamp-01). OPEN protocol layer only. No proprietary methods.
//
// A native operation-channel frame payload is a deterministic-CBOR map
// (npamp_cbor.ts, the shared codec). This file adds, per channel, the common
// envelope check (§4.2 frame_kind + correlation key), the per-frame-type body
// field schemas (required/typed), the forward-compatibility rule (accept an
// unknown non-negative integer key, reject an unknown negative or non-integer
// key), and the nested-structure MUST-reject rules each channel adds. It is a
// straight port of the Go reference validators impl/go/{memory,stream,capability,
// immune,settlement,telemetry,commerce,interaction,workflow,knowledge}_bodies.go —
// matching their behavior, keyed to the same spec sections.
//
// Each Validate<Channel>Payload(ft, payload) returns the decoded CborMap on
// success and THROWS on any structural fault (invalid deterministic CBOR, a
// non-map payload, a frame_kind that contradicts ft, a missing/mistyped envelope
// or body field, a nested-structure violation, or an unknown negative/non-integer
// key). Throwing-on-reject is the whole contract the corpus MUST-reject vectors
// grade.

import { CborMap, decodeTop, CborError, type CborValue } from "./npamp_cbor.ts";

// ---------- shared field-schema machinery (port of memory_bodies.go) ----------

// Kind is the expected CBOR type of a body field. A plain const object (not a TS
// `enum`) so the module runs under Node's type-strip-only loader, which rejects
// `enum` as runtime-emitting syntax.
export const Kind = {
  Uint: 0,
  Text: 1,
  Bytes: 2,
  Array: 3,
  Map: 4,
  Bool: 5,
  Number: 6, // uint OR negative int (telemetry MetricSample value, §5.1)
} as const;
type KindT = (typeof Kind)[keyof typeof Kind];

interface Field {
  key: number;
  kind: KindT;
  required: boolean;
}

function f(key: number, kind: KindT, required: boolean): Field {
  return { key, kind, required };
}

function isUint(v: CborValue | undefined): boolean {
  return typeof v === "bigint" && v >= 0n;
}

function matchesKind(v: CborValue, k: KindT): boolean {
  switch (k) {
    case Kind.Uint:
      return typeof v === "bigint" && v >= 0n;
    case Kind.Text:
      return typeof v === "string";
    case Kind.Bytes:
      return Buffer.isBuffer(v);
    case Kind.Array:
      return Array.isArray(v);
    case Kind.Map:
      return v instanceof CborMap;
    case Kind.Bool:
      return typeof v === "boolean";
    case Kind.Number:
      return typeof v === "bigint";
    default:
      return false;
  }
}

// forwardCompatKeys enforces the §4.3/§4.4 rule on a decoded map: an unknown
// non-negative integer key is accepted; an unknown NEGATIVE integer key, or a
// non-integer key, MUST be rejected. Since the deterministic codec decodes every
// integer to a bigint (non-negative for major 0, negative for major 1), a
// negative bigint key is a reserved-key violation and any non-bigint key (text,
// bytes, …) is a non-integer key.
function forwardCompatKeys(m: CborMap, malformed: (msg: string) => Error): void {
  for (const k of m.keys()) {
    if (typeof k === "bigint") {
      if (k < 0n) {
        throw malformed(`unknown negative key ${k} (reserved)`);
      }
      // known or unknown-non-negative: both accepted.
    } else {
      throw malformed("non-integer map key");
    }
  }
}

// checkFields enforces a schema's required/typed fields and then the
// forward-compatibility key rule on a decoded map.
function checkFields(m: CborMap, schema: Field[], malformed: (msg: string) => Error): void {
  for (const fld of schema) {
    const val = m.get(fld.key);
    if (val === undefined) {
      if (fld.required) {
        throw malformed(`missing required field (key ${fld.key})`);
      }
      continue;
    }
    if (!matchesKind(val, fld.kind)) {
      throw malformed(`field (key ${fld.key}) has the wrong CBOR type`);
    }
  }
  forwardCompatKeys(m, malformed);
}

// decodeMap decodes payload as deterministic CBOR and requires the top-level item
// to be a map. It surfaces both the codec's MUST-reject faults (non-deterministic
// encoding) and the "payload is not a map" fault as the channel's malformed error.
function decodeMap(payload: Buffer, malformed: (msg: string) => Error): CborMap {
  let v: CborValue;
  try {
    v = decodeTop(payload);
  } catch (e) {
    if (e instanceof CborError) {
      throw malformed(e.message);
    }
    throw e;
  }
  if (!(v instanceof CborMap)) {
    throw malformed("payload is not a CBOR map");
  }
  return v;
}

// checkFrameKind enforces the common-envelope frame_kind (0) == ft rule (§4.2).
function checkFrameKind(m: CborMap, ft: number, malformed: (msg: string) => Error): void {
  const fk = m.get(0);
  if (fk === undefined) {
    throw malformed("missing frame_kind (0)");
  }
  if (!isUint(fk)) {
    throw malformed("frame_kind (0) is not an unsigned int");
  }
  if (fk !== BigInt(ft)) {
    throw malformed(`frame_kind 0x${Number(fk).toString(16)} contradicts frame type 0x${ft.toString(16)}`);
  }
}

// checkCorr enforces the common-envelope corr (1) rule shared by the corr-bearing
// channels (§4.2): a non-empty byte string of 1-64 bytes.
function checkCorr(m: CborMap, malformed: (msg: string) => Error): void {
  const corr = m.get(1);
  if (corr === undefined) {
    throw malformed("missing corr (1)");
  }
  if (!Buffer.isBuffer(corr) || corr.length < 1 || corr.length > 64) {
    throw malformed("corr (1) must be a byte string of 1-64 bytes");
  }
}

function mkMalformed(prefix: string): (msg: string) => Error {
  return (msg: string) => new Error(`${prefix}: ${msg}`);
}

// ---------- NPAMP-MEMORY (spec/companion/81 §4-§8) ----------

export const FrameMemoryCreateReq = 0x0100;
export const FrameMemoryCreateResult = 0x0101;
export const FrameMemoryReadReq = 0x0102;
export const FrameMemoryReadResult = 0x0103;
export const FrameMemoryUpdateReq = 0x0104;
export const FrameMemoryUpdateResult = 0x0105;
export const FrameMemoryDeleteReq = 0x0106;
export const FrameMemoryDeleteResult = 0x0107;
export const FrameMemoryRetrieveReq = 0x0108;
export const FrameMemoryRetrieveResult = 0x0109;
export const FrameMemoryRetrieveStreamData = 0x010a;
export const FrameMemoryRetrieveStreamEnd = 0x010b;
export const FrameMemoryStatusReq = 0x010c;
export const FrameMemoryStatusResult = 0x010d;
export const FrameMemoryError = 0x010e;
export const FrameMemoryEvict = 0x0035;
export const FrameMemoryRevive = 0x0036;

const memorySchemas: Record<number, Field[]> = {
  [FrameMemoryCreateReq]: [
    f(2, Kind.Text, true), f(3, Kind.Text, false), f(4, Kind.Text, false), f(5, Kind.Text, false),
    f(6, Kind.Text, false), f(7, Kind.Text, false), f(8, Kind.Text, false), f(9, Kind.Text, false),
    f(10, Kind.Map, false), f(11, Kind.Uint, true),
  ],
  [FrameMemoryCreateResult]: [f(2, Kind.Text, true), f(3, Kind.Text, true)],
  [FrameMemoryReadReq]: [f(2, Kind.Text, true), f(3, Kind.Uint, true)],
  [FrameMemoryReadResult]: [f(2, Kind.Map, true)],
  [FrameMemoryUpdateReq]: [
    f(2, Kind.Text, true), f(3, Kind.Text, false), f(4, Kind.Text, false), f(5, Kind.Text, false),
    f(6, Kind.Text, false), f(7, Kind.Text, false), f(8, Kind.Text, false), f(9, Kind.Map, false),
    f(10, Kind.Uint, true),
  ],
  [FrameMemoryUpdateResult]: [f(2, Kind.Text, true), f(3, Kind.Text, true)],
  [FrameMemoryDeleteReq]: [f(2, Kind.Text, true), f(3, Kind.Uint, true)],
  [FrameMemoryDeleteResult]: [f(2, Kind.Text, true), f(3, Kind.Text, true)],
  [FrameMemoryRetrieveReq]: [
    f(2, Kind.Text, false), f(3, Kind.Text, false), f(4, Kind.Text, false), f(5, Kind.Text, false),
    f(6, Kind.Text, false), f(7, Kind.Uint, false), f(8, Kind.Text, false), f(9, Kind.Bytes, false),
    f(10, Kind.Uint, true),
  ],
  [FrameMemoryRetrieveResult]: [
    f(2, Kind.Array, true), f(3, Kind.Bool, true), f(4, Kind.Bytes, false), f(5, Kind.Uint, false),
    f(6, Kind.Bool, false),
  ],
  [FrameMemoryRetrieveStreamData]: [f(2, Kind.Array, true)],
  [FrameMemoryRetrieveStreamEnd]: [f(2, Kind.Array, false), f(3, Kind.Bool, true)],
  [FrameMemoryStatusReq]: [],
  [FrameMemoryStatusResult]: [
    f(2, Kind.Text, true), f(3, Kind.Text, false), f(4, Kind.Uint, false), f(5, Kind.Map, false),
  ],
  [FrameMemoryError]: [
    f(2, Kind.Uint, true), f(3, Kind.Text, true), f(4, Kind.Uint, false), f(5, Kind.Text, false),
  ],
  [FrameMemoryEvict]: [f(2, Kind.Text, true), f(3, Kind.Text, false), f(4, Kind.Uint, true)],
  [FrameMemoryRevive]: [f(2, Kind.Text, true), f(3, Kind.Uint, true)],
};

export function validateMemoryPayload(ft: number, payload: Buffer): CborMap {
  const bad = mkMalformed("npamp/memory: malformed_request");
  const schema = memorySchemas[ft];
  if (schema === undefined) {
    throw bad(`0x${ft.toString(16)} is not a Memory operation frame type`);
  }
  const m = decodeMap(payload, bad);
  checkFrameKind(m, ft, bad);
  checkCorr(m, bad);
  checkFields(m, schema, bad);
  return m;
}

// ---------- NPAMP-STREAM (spec/companion/80 §4-§5) ----------

export const FrameStreamOpen = 0x0100;
export const FrameStreamData = 0x0101;
export const FrameStreamClose = 0x0102;
export const FrameStreamReset = 0x0103;
export const FrameStreamWindowUpdate = 0x0104;

const streamSchemas: Record<number, Field[]> = {
  [FrameStreamOpen]: [f(2, Kind.Uint, true), f(3, Kind.Uint, true), f(4, Kind.Text, false), f(5, Kind.Uint, false)],
  [FrameStreamData]: [f(2, Kind.Uint, true), f(3, Kind.Bytes, true), f(4, Kind.Uint, false)],
  [FrameStreamClose]: [f(2, Kind.Uint, true)],
  [FrameStreamReset]: [f(2, Kind.Uint, true), f(3, Kind.Uint, true)],
  [FrameStreamWindowUpdate]: [f(2, Kind.Uint, true)],
};

export function validateStreamPayload(ft: number, payload: Buffer): CborMap {
  const bad = mkMalformed("npamp/stream: malformed");
  const schema = streamSchemas[ft];
  if (schema === undefined) {
    throw bad(`0x${ft.toString(16)} is not a Stream frame type`);
  }
  const m = decodeMap(payload, bad);
  checkFrameKind(m, ft, bad);
  // Envelope key 1 is sub_stream_id — an Unsigned int, unlike the byte-string corr.
  const ssid = m.get(1);
  if (ssid === undefined) {
    throw bad("missing sub_stream_id (1)");
  }
  if (!isUint(ssid)) {
    throw bad("sub_stream_id (1) is not an unsigned int");
  }
  checkFields(m, schema, bad);
  return m;
}

// ---------- NPAMP-CAP (spec/companion/84 §4-§8) ----------

export const FrameCapIssueReq = 0x0100;
export const FrameCapIssueResult = 0x0101;
export const FrameCapDelegateReq = 0x0102;
export const FrameCapDelegateResult = 0x0103;
export const FrameCapRevokeReq = 0x0104;
export const FrameCapRevokeResult = 0x0105;
export const FrameCapLookupReq = 0x0106;
export const FrameCapLookupResult = 0x0107;
export const FrameCapError = 0x0108;
export const FrameCapTokenPresent = 0x0060;
export const FrameCapTokenAccept = 0x0061;
export const FrameCapTokenChallenge = 0x0062;
export const FrameCapTokenProof = 0x0063;

const capabilitySchemas: Record<number, Field[]> = {
  [FrameCapIssueReq]: [
    f(2, Kind.Text, true), f(3, Kind.Text, true), f(4, Kind.Map, false), f(5, Kind.Text, false),
    f(6, Kind.Text, false), f(7, Kind.Uint, false), f(8, Kind.Text, false), f(9, Kind.Uint, true),
  ],
  [FrameCapIssueResult]: [f(2, Kind.Map, true), f(3, Kind.Text, true)],
  [FrameCapDelegateReq]: [
    f(2, Kind.Text, true), f(3, Kind.Text, true), f(4, Kind.Map, false), f(5, Kind.Text, false),
    f(6, Kind.Uint, false), f(7, Kind.Uint, true),
  ],
  [FrameCapDelegateResult]: [f(2, Kind.Map, true), f(3, Kind.Text, true)],
  [FrameCapRevokeReq]: [f(2, Kind.Text, true), f(3, Kind.Bool, false), f(4, Kind.Text, false), f(5, Kind.Uint, true)],
  [FrameCapRevokeResult]: [f(2, Kind.Text, true), f(3, Kind.Text, true), f(4, Kind.Uint, false)],
  [FrameCapLookupReq]: [
    f(2, Kind.Text, false), f(3, Kind.Text, false), f(4, Kind.Text, false), f(5, Kind.Bool, false),
    f(6, Kind.Uint, false), f(7, Kind.Bytes, false), f(8, Kind.Uint, true),
  ],
  [FrameCapLookupResult]: [f(2, Kind.Array, true), f(3, Kind.Bool, true), f(4, Kind.Bytes, false)],
  [FrameCapError]: [f(2, Kind.Uint, true), f(3, Kind.Text, true), f(4, Kind.Uint, false), f(5, Kind.Text, false)],
  [FrameCapTokenPresent]: [f(2, Kind.Map, true), f(3, Kind.Array, false), f(4, Kind.Uint, true)],
  [FrameCapTokenAccept]: [f(2, Kind.Text, true), f(3, Kind.Text, true)],
  [FrameCapTokenChallenge]: [f(2, Kind.Text, true), f(3, Kind.Bytes, true), f(4, Kind.Uint, true)],
  [FrameCapTokenProof]: [f(2, Kind.Text, true), f(3, Kind.Bytes, true)],
};

export function validateCapabilityPayload(ft: number, payload: Buffer): CborMap {
  const bad = mkMalformed("npamp/capability: malformed_request");
  const schema = capabilitySchemas[ft];
  if (schema === undefined) {
    throw bad(`0x${ft.toString(16)} is not a Capability operation frame type`);
  }
  const m = decodeMap(payload, bad);
  checkFrameKind(m, ft, bad);
  checkCorr(m, bad);
  checkFields(m, schema, bad);
  return m;
}

// ---------- NPAMP-IMMUNE (spec/companion/85 §4-§8) ----------

export const FrameImmuneReportReq = 0x0100;
export const FrameImmuneReportResult = 0x0101;
export const FrameImmuneError = 0x0102;
export const FrameImmuneGossipAdvertise = 0x00c0;
export const FrameImmuneGossipAck = 0x00c1;
export const FrameImmuneGossipPullReq = 0x00c2;
export const FrameImmuneGossipPullResult = 0x00c3;
export const FrameImmuneGossipRetract = 0x00c4;

const immuneSchemas: Record<number, Field[]> = {
  [FrameImmuneReportReq]: [
    f(2, Kind.Text, true), f(3, Kind.Uint, true), f(4, Kind.Uint, true), f(5, Kind.Text, false),
    f(6, Kind.Text, false), f(7, Kind.Text, false), f(8, Kind.Bytes, false), f(9, Kind.Uint, false),
    f(10, Kind.Text, false),
  ],
  [FrameImmuneReportResult]: [f(2, Kind.Uint, true), f(3, Kind.Text, false)],
  [FrameImmuneError]: [f(2, Kind.Uint, true), f(3, Kind.Text, true), f(4, Kind.Uint, false)],
  [FrameImmuneGossipAdvertise]: [f(2, Kind.Array, true), f(3, Kind.Bool, false)],
  [FrameImmuneGossipAck]: [f(2, Kind.Array, false), f(3, Kind.Array, false), f(4, Kind.Uint, false)],
  [FrameImmuneGossipPullReq]: [f(2, Kind.Array, true)],
  [FrameImmuneGossipPullResult]: [f(2, Kind.Array, true)],
  [FrameImmuneGossipRetract]: [f(2, Kind.Bytes, true), f(3, Kind.Uint, true), f(4, Kind.Uint, false)],
};

// gossip_descriptor (§6.4) — nested map, keys start at 0, no envelope.
const gossipDescriptorSchema: Field[] = [
  f(0, Kind.Bytes, true), f(1, Kind.Uint, true), f(2, Kind.Uint, false), f(3, Kind.Uint, false),
  f(4, Kind.Bytes, false), f(5, Kind.Text, false), f(6, Kind.Text, false), f(7, Kind.Uint, false),
  f(8, Kind.Bytes, false), f(9, Kind.Bytes, false),
];

// gossip_item (§6.5) — like a descriptor but body(8) is REQUIRED.
const gossipItemSchema: Field[] = [
  f(0, Kind.Bytes, true), f(1, Kind.Uint, true), f(2, Kind.Uint, false), f(3, Kind.Uint, false),
  f(4, Kind.Bytes, false), f(5, Kind.Text, false), f(6, Kind.Text, false), f(7, Kind.Uint, false),
  f(8, Kind.Bytes, true),
];

function validateGossipArray(m: CborMap, nested: Field[], bad: (msg: string) => Error): void {
  const itemsV = m.get(2);
  if (!Array.isArray(itemsV)) {
    throw bad("items (2) is not an array");
  }
  itemsV.forEach((el, i) => {
    if (!(el instanceof CborMap)) {
      throw bad(`items[${i}] is not a CBOR map`);
    }
    checkFields(el, nested, bad);
  });
}

export function validateImmunePayload(ft: number, payload: Buffer): CborMap {
  const bad = mkMalformed("npamp/immune: malformed_request");
  const schema = immuneSchemas[ft];
  if (schema === undefined) {
    throw bad(`0x${ft.toString(16)} is not an Immune operation frame type`);
  }
  const m = decodeMap(payload, bad);
  checkFrameKind(m, ft, bad);
  checkCorr(m, bad);
  checkFields(m, schema, bad);
  if (ft === FrameImmuneGossipAdvertise) {
    validateGossipArray(m, gossipDescriptorSchema, bad);
  } else if (ft === FrameImmuneGossipPullResult) {
    validateGossipArray(m, gossipItemSchema, bad);
  }
  return m;
}

// ---------- NPAMP-SETTLEMENT (spec/companion/86 §4-§8) ----------

export const FrameSettleIntentReq = 0x0100;
export const FrameSettleIntentResult = 0x0101;
export const FrameReceiptReq = 0x0102;
export const FrameReceiptResult = 0x0103;
export const FrameSettleError = 0x0104;
export const FrameSettleBatchCommitReq = 0x00a0;
export const FrameSettleBatchCommitResult = 0x00a1;

const settlementSchemas: Record<number, Field[]> = {
  [FrameSettleIntentReq]: [
    f(2, Kind.Text, true), f(3, Kind.Text, false), f(4, Kind.Text, false), f(5, Kind.Text, false),
    f(6, Kind.Text, false), f(7, Kind.Text, false), f(8, Kind.Uint, true),
  ],
  [FrameSettleIntentResult]: [f(2, Kind.Text, true), f(3, Kind.Text, true), f(4, Kind.Text, false)],
  [FrameReceiptReq]: [f(2, Kind.Text, true), f(3, Kind.Text, false), f(4, Kind.Uint, true)],
  [FrameReceiptResult]: [f(2, Kind.Map, true)],
  [FrameSettleError]: [f(2, Kind.Uint, true), f(3, Kind.Text, true), f(4, Kind.Uint, false), f(5, Kind.Text, false)],
  [FrameSettleBatchCommitReq]: [
    f(2, Kind.Text, true), f(3, Kind.Bytes, true), f(4, Kind.Text, false), f(5, Kind.Uint, false),
    f(6, Kind.Text, false), f(7, Kind.Uint, true),
  ],
  [FrameSettleBatchCommitResult]: [f(2, Kind.Text, true), f(3, Kind.Text, true), f(4, Kind.Text, false)],
};

export function validateSettlementPayload(ft: number, payload: Buffer): CborMap {
  const bad = mkMalformed("npamp/settlement: malformed_request");
  const schema = settlementSchemas[ft];
  if (schema === undefined) {
    throw bad(`0x${ft.toString(16)} is not a Settlement operation frame type`);
  }
  const m = decodeMap(payload, bad);
  checkFrameKind(m, ft, bad);
  checkCorr(m, bad);
  checkFields(m, schema, bad);
  return m;
}

// ---------- NPAMP-TELEMETRY (spec/companion/87 §4-§8) ----------

export const FrameTelemetryReport = 0x0100;
export const FrameTelemetrySubscribe = 0x0101;
export const FrameTelemetrySubAck = 0x0102;
export const FrameTelemetryUnsubscribe = 0x0103;
export const FrameTelemetryCredit = 0x0104;
export const FrameTelemetryError = 0x0105;

const telemetrySchemas: Record<number, Field[]> = {
  [FrameTelemetrySubscribe]: [
    f(2, Kind.Array, false), f(3, Kind.Array, false), f(4, Kind.Array, false),
    f(5, Kind.Uint, false), f(6, Kind.Uint, false), f(7, Kind.Uint, true),
  ],
  [FrameTelemetrySubAck]: [f(2, Kind.Bytes, true), f(3, Kind.Uint, true), f(4, Kind.Array, false)],
  [FrameTelemetryUnsubscribe]: [f(2, Kind.Bytes, true)],
  [FrameTelemetryCredit]: [f(2, Kind.Bytes, true), f(3, Kind.Uint, true), f(4, Kind.Uint, false)],
  [FrameTelemetryError]: [f(2, Kind.Uint, true), f(3, Kind.Text, false), f(4, Kind.Bytes, false)],
};

// Nested item schemas (§5.1-§5.3); keys start at 0, no envelope.
const metricSchema: Field[] = [
  f(0, Kind.Text, true), f(1, Kind.Uint, true), f(2, Kind.Uint, true), f(3, Kind.Number, true),
  f(4, Kind.Text, false), f(5, Kind.Map, false), f(6, Kind.Uint, false),
];
const eventSchema: Field[] = [
  f(0, Kind.Text, true), f(1, Kind.Uint, true), f(2, Kind.Uint, false),
  f(3, Kind.Map, false), f(4, Kind.Text, false), f(5, Kind.Uint, false),
];
const healthSchema: Field[] = [
  f(0, Kind.Text, true), f(1, Kind.Uint, true), f(2, Kind.Uint, true),
  f(3, Kind.Text, false), f(4, Kind.Map, false),
];

function isTelemetryFrame(ft: number): boolean {
  return ft >= FrameTelemetryReport && ft <= FrameTelemetryError;
}

export function validateTelemetryPayload(ft: number, payload: Buffer): CborMap {
  const bad = mkMalformed("npamp/telemetry: malformed_payload");
  if (!isTelemetryFrame(ft)) {
    throw bad(`0x${ft.toString(16)} is not a Telemetry operation frame type`);
  }
  const m = decodeMap(payload, bad);
  checkFrameKind(m, ft, bad);

  if (ft === FrameTelemetryReport) {
    return validateTelemetryReport(m, bad);
  }

  // Every non-REPORT Telemetry frame carries a REQUIRED, non-empty corr (1) (§4.1).
  checkCorr(m, bad);
  checkFields(m, telemetrySchemas[ft], bad);
  return m;
}

// validateTelemetryReport enforces the §5 TELEMETRY_REPORT rules: corr (1) is
// CONDITIONAL (present iff the batch answers a subscription, in which case sub_id
// (2) MUST also be present; a standalone report MUST omit both); batch_seq (3) is
// REQUIRED; and the report MUST carry content (at least one of metrics(4)/
// events(5)/health(6) present and non-empty), each element validated nested.
function validateTelemetryReport(m: CborMap, bad: (msg: string) => Error): CborMap {
  const corr = m.get(1);
  const hasCorr = corr !== undefined;
  const hasSubID = m.has(2);
  if (hasCorr) {
    if (!Buffer.isBuffer(corr) || corr.length < 1 || corr.length > 64) {
      throw bad("corr (1) must be a byte string of 1-64 bytes");
    }
    if (!hasSubID) {
      throw bad("subscribed report carries corr (1) but omits sub_id (2)");
    }
    if (!Buffer.isBuffer(m.get(2))) {
      throw bad("sub_id (2) must be a byte string");
    }
  } else if (hasSubID) {
    throw bad("standalone report carries sub_id (2) without corr (1)");
  }

  const bs = m.get(3);
  if (bs === undefined) {
    throw bad("missing required batch_seq (3)");
  }
  if (!isUint(bs)) {
    throw bad("batch_seq (3) is not an unsigned int");
  }

  let nonEmpty = 0;
  for (const c of [
    { key: 4, schema: metricSchema, what: "metric" },
    { key: 5, schema: eventSchema, what: "event" },
    { key: 6, schema: healthSchema, what: "health" },
  ]) {
    const val = m.get(c.key);
    if (val === undefined) {
      continue;
    }
    if (!Array.isArray(val)) {
      throw bad(`${c.what} array (key ${c.key}) is not a CBOR array`);
    }
    if (val.length > 0) {
      nonEmpty++;
    }
    for (const el of val) {
      if (!(el instanceof CborMap)) {
        throw bad(`${c.what} array element is not a CBOR map`);
      }
      checkFields(el, c.schema, bad);
    }
  }
  if (nonEmpty === 0) {
    throw bad("TELEMETRY_REPORT carries no metrics, events, or health");
  }

  forwardCompatKeys(m, bad);
  return m;
}

// ---------- NPAMP-COMMERCE (spec/companion/88 §4-§8) ----------

export const FrameCommerceMandateCreateReq = 0x0100;
export const FrameCommerceMandateCreateResult = 0x0101;
export const FrameCommerceMandateReadReq = 0x0102;
export const FrameCommerceMandateReadResult = 0x0103;
export const FrameCommerceMandateRevokeReq = 0x0104;
export const FrameCommerceMandateRevokeResult = 0x0105;
export const FrameCommerceMandateStatusReq = 0x0106;
export const FrameCommerceMandateStatusResult = 0x0107;
export const FrameCommerceIntentProposeReq = 0x0108;
export const FrameCommerceIntentProposeResult = 0x0109;
export const FrameCommerceIntentRespondReq = 0x010a;
export const FrameCommerceIntentRespondResult = 0x010b;
export const FrameCommerceIntentStatusReq = 0x010c;
export const FrameCommerceIntentStatusResult = 0x010d;
export const FrameCommerceError = 0x010e;

const commerceSchemas: Record<number, Field[]> = {
  [FrameCommerceMandateCreateReq]: [
    f(2, Kind.Text, true), f(3, Kind.Text, true), f(4, Kind.Map, true), f(5, Kind.Text, false),
    f(6, Kind.Text, false), f(7, Kind.Text, false), f(8, Kind.Map, false), f(9, Kind.Text, false),
    f(10, Kind.Bytes, false), f(11, Kind.Text, false), f(12, Kind.Text, false), f(13, Kind.Uint, true),
  ],
  [FrameCommerceMandateCreateResult]: [f(2, Kind.Text, true), f(3, Kind.Text, true)],
  [FrameCommerceMandateReadReq]: [f(2, Kind.Text, true), f(3, Kind.Uint, true)],
  [FrameCommerceMandateReadResult]: [f(2, Kind.Map, true)],
  [FrameCommerceMandateRevokeReq]: [f(2, Kind.Text, true), f(3, Kind.Text, false), f(4, Kind.Uint, true)],
  [FrameCommerceMandateRevokeResult]: [f(2, Kind.Text, true), f(3, Kind.Text, true)],
  [FrameCommerceMandateStatusReq]: [f(2, Kind.Text, true), f(3, Kind.Uint, true)],
  [FrameCommerceMandateStatusResult]: [f(2, Kind.Text, true), f(3, Kind.Text, true), f(4, Kind.Text, false)],
  [FrameCommerceIntentProposeReq]: [
    f(2, Kind.Array, true), f(3, Kind.Array, true), f(4, Kind.Text, false), f(5, Kind.Map, false),
    f(6, Kind.Text, false), f(7, Kind.Uint, true),
  ],
  [FrameCommerceIntentProposeResult]: [f(2, Kind.Text, true), f(3, Kind.Text, true)],
  [FrameCommerceIntentRespondReq]: [
    f(2, Kind.Text, true), f(3, Kind.Uint, true), f(4, Kind.Array, false), f(5, Kind.Text, false), f(6, Kind.Uint, true),
  ],
  [FrameCommerceIntentRespondResult]: [f(2, Kind.Text, true), f(3, Kind.Text, true)],
  [FrameCommerceIntentStatusReq]: [f(2, Kind.Text, true), f(3, Kind.Uint, true)],
  [FrameCommerceIntentStatusResult]: [
    f(2, Kind.Text, true), f(3, Kind.Text, true), f(4, Kind.Array, false), f(5, Kind.Array, false),
  ],
  [FrameCommerceError]: [f(2, Kind.Uint, true), f(3, Kind.Text, true), f(4, Kind.Uint, false), f(5, Kind.Text, false)],
};

// validateCommerceAmount enforces the §4.3 monetary-amount structure: units (0) a
// signed integer, scale (1) an unsigned int, currency (2) a text string — all
// REQUIRED — plus the §4.4 forward-compat key rule.
function validateCommerceAmount(v: CborValue | undefined, bad: (msg: string) => Error): void {
  if (!(v instanceof CborMap)) {
    throw bad("`amount` is not a CBOR map (§4.3)");
  }
  const units = v.get(0);
  if (units === undefined) {
    throw bad("`amount` omits REQUIRED units (0) (§4.3)");
  }
  if (typeof units !== "bigint") {
    throw bad("`amount` units (0) is not an integer (§4.3)");
  }
  const scale = v.get(1);
  if (scale === undefined) {
    throw bad("`amount` omits REQUIRED scale (1) (§4.3)");
  }
  if (!isUint(scale)) {
    throw bad("`amount` scale (1) is not an unsigned int (§4.3)");
  }
  const cur = v.get(2);
  if (cur === undefined) {
    throw bad("`amount` omits REQUIRED currency (2) (§4.3)");
  }
  if (typeof cur !== "string") {
    throw bad("`amount` currency (2) is not a text string (§4.3)");
  }
  forwardCompatKeys(v, bad);
}

function validateCommerceLeg(v: CborValue, parties: Set<string>, bad: (msg: string) => Error): void {
  if (!(v instanceof CborMap)) {
    throw bad("a settlement leg is not a CBOR map (§6.6)");
  }
  const frm = v.get(0);
  if (frm === undefined) {
    throw bad("a leg omits REQUIRED `from` (0) (§6.6)");
  }
  if (typeof frm !== "string") {
    throw bad("a leg `from` (0) is not a text string (§6.6)");
  }
  const to = v.get(1);
  if (to === undefined) {
    throw bad("a leg omits REQUIRED `to` (1) (§6.6)");
  }
  if (typeof to !== "string") {
    throw bad("a leg `to` (1) is not a text string (§6.6)");
  }
  const amt = v.get(2);
  if (amt === undefined) {
    throw bad("a leg omits REQUIRED `amount` (2) (§6.6)");
  }
  validateCommerceAmount(amt, bad);
  if (!parties.has(frm)) {
    throw bad("leg `from` names a party not in `parties` (§6.6)");
  }
  if (!parties.has(to)) {
    throw bad("leg `to` names a party not in `parties` (§6.6)");
  }
  forwardCompatKeys(v, bad);
}

function validateCommerceNested(ft: number, m: CborMap, bad: (msg: string) => Error): void {
  if (ft === FrameCommerceMandateCreateReq) {
    const av = m.get(4);
    if (av !== undefined) {
      validateCommerceAmount(av, bad);
    }
  } else if (ft === FrameCommerceIntentProposeReq) {
    const pv = m.get(2);
    const parties = new Set<string>();
    if (Array.isArray(pv)) {
      for (const p of pv) {
        if (typeof p !== "string") {
          throw bad("a `parties` element is not a text string (§6.6)");
        }
        parties.add(p);
      }
    }
    const lv = m.get(3);
    if (Array.isArray(lv)) {
      for (const lg of lv) {
        validateCommerceLeg(lg, parties, bad);
      }
    }
  }
}

export function validateCommercePayload(ft: number, payload: Buffer): CborMap {
  const bad = mkMalformed("npamp/commerce: malformed_request");
  const schema = commerceSchemas[ft];
  if (schema === undefined) {
    throw bad(`0x${ft.toString(16)} is not a Commerce operation frame type`);
  }
  const m = decodeMap(payload, bad);
  checkFrameKind(m, ft, bad);
  checkCorr(m, bad);
  checkFields(m, schema, bad);
  validateCommerceNested(ft, m, bad);
  return m;
}

// ---------- NPAMP-INTERACT (spec/companion/89 §4-§8) ----------

export const FrameInteractEvent = 0x0100;
export const FrameInteractEventAck = 0x0101;
export const FrameInteractPromptReq = 0x0102;
export const FrameInteractPromptResult = 0x0103;
export const FrameInteractApprovalReq = 0x0104;
export const FrameInteractApprovalResult = 0x0105;
export const FrameInteractCancel = 0x0106;
export const FrameInteractError = 0x0107;

const interactionSchemas: Record<number, Field[]> = {
  [FrameInteractEvent]: [f(2, Kind.Uint, true), f(3, Kind.Text, false), f(4, Kind.Map, false), f(5, Kind.Bool, false)],
  [FrameInteractEventAck]: [],
  [FrameInteractPromptReq]: [
    f(2, Kind.Uint, true), f(3, Kind.Text, true), f(4, Kind.Array, false), f(5, Kind.Map, false), f(6, Kind.Uint, false),
  ],
  [FrameInteractPromptResult]: [f(2, Kind.Uint, true)],
  [FrameInteractApprovalReq]: [f(2, Kind.Text, true), f(3, Kind.Uint, false), f(4, Kind.Map, false), f(5, Kind.Uint, false)],
  [FrameInteractApprovalResult]: [f(2, Kind.Uint, true), f(3, Kind.Text, false)],
  [FrameInteractCancel]: [f(2, Kind.Uint, false)],
  [FrameInteractError]: [f(2, Kind.Uint, true), f(3, Kind.Text, true), f(4, Kind.Uint, false), f(5, Kind.Text, false)],
};

export function validateInteractionPayload(ft: number, payload: Buffer): CborMap {
  const bad = mkMalformed("npamp/interaction: malformed_request");
  const schema = interactionSchemas[ft];
  if (schema === undefined) {
    throw bad(`0x${ft.toString(16)} is not an Interaction operation frame type`);
  }
  const m = decodeMap(payload, bad);
  checkFrameKind(m, ft, bad);
  checkCorr(m, bad);
  checkFields(m, schema, bad);
  return m;
}

// ---------- NPAMP-WORKFLOW (spec/companion/8a §4-§8) ----------

export const FrameWorkflowSubmitReq = 0x0100;
export const FrameWorkflowSubmitResult = 0x0101;
export const FrameWorkflowStatusReq = 0x0102;
export const FrameWorkflowStatusResult = 0x0103;
export const FrameWorkflowCancelReq = 0x0104;
export const FrameWorkflowCancelResult = 0x0105;
export const FrameWorkflowStepEvent = 0x0106;
export const FrameWorkflowComplete = 0x0107;
export const FrameWorkflowError = 0x0108;

const workflowSchemas: Record<number, Field[]> = {
  [FrameWorkflowSubmitReq]: [
    f(2, Kind.Text, true), f(3, Kind.Bytes, false), f(4, Kind.Map, false), f(5, Kind.Uint, false),
    f(6, Kind.Text, false), f(7, Kind.Text, false), f(8, Kind.Text, false), f(9, Kind.Text, false),
    f(10, Kind.Map, false), f(11, Kind.Uint, true),
  ],
  [FrameWorkflowSubmitResult]: [f(2, Kind.Text, true), f(3, Kind.Uint, true)],
  [FrameWorkflowStatusReq]: [f(2, Kind.Text, true)],
  [FrameWorkflowStatusResult]: [
    f(2, Kind.Text, true), f(3, Kind.Uint, true), f(4, Kind.Uint, false), f(5, Kind.Text, false),
    f(6, Kind.Uint, false), f(7, Kind.Text, false),
  ],
  [FrameWorkflowCancelReq]: [f(2, Kind.Text, true), f(3, Kind.Text, false)],
  [FrameWorkflowCancelResult]: [f(2, Kind.Text, true), f(3, Kind.Uint, true)],
  [FrameWorkflowStepEvent]: [
    f(2, Kind.Text, true), f(3, Kind.Uint, true), f(4, Kind.Uint, true), f(5, Kind.Uint, false),
    f(6, Kind.Text, false), f(7, Kind.Uint, false), f(8, Kind.Bytes, false), f(9, Kind.Text, false),
  ],
  [FrameWorkflowComplete]: [
    f(2, Kind.Text, true), f(3, Kind.Uint, true), f(4, Kind.Uint, true), f(5, Kind.Bytes, false),
    f(6, Kind.Uint, false), f(7, Kind.Text, false),
  ],
  [FrameWorkflowError]: [f(2, Kind.Uint, true), f(3, Kind.Text, true), f(4, Kind.Uint, false), f(5, Kind.Text, false)],
};

function workflowFrameHasCorr(ft: number): boolean {
  return ft !== FrameWorkflowStepEvent && ft !== FrameWorkflowComplete;
}

export function validateWorkflowPayload(ft: number, payload: Buffer): CborMap {
  const bad = mkMalformed("npamp/workflow: malformed_request");
  const schema = workflowSchemas[ft];
  if (schema === undefined) {
    throw bad(`0x${ft.toString(16)} is not a Workflow frame type`);
  }
  const m = decodeMap(payload, bad);
  checkFrameKind(m, ft, bad);
  // corr (1) is REQUIRED on every corr-bearing frame; the task-scoped
  // WORKFLOW_STEP_EVENT / WORKFLOW_COMPLETE carry no corr (§4.2, §5.2).
  if (workflowFrameHasCorr(ft)) {
    checkCorr(m, bad);
  }
  checkFields(m, schema, bad);
  return m;
}

// ---------- NPAMP-KNOWLEDGE (spec/companion/8b §4-§9) ----------

export const FrameKnowledgeQueryReq = 0x0100;
export const FrameKnowledgeQueryResult = 0x0101;
export const FrameKnowledgeQueryStreamData = 0x0102;
export const FrameKnowledgeQueryStreamEnd = 0x0103;
export const FrameKnowledgeSubscribeReq = 0x0104;
export const FrameKnowledgeSubscribeAck = 0x0105;
export const FrameKnowledgeUpdate = 0x0106;
export const FrameKnowledgeCredit = 0x0107;
export const FrameKnowledgeUnsubscribe = 0x0108;
export const FrameKnowledgeError = 0x0109;

const knowledgeSchemas: Record<number, Field[]> = {
  [FrameKnowledgeQueryReq]: [
    f(2, Kind.Text, false), f(3, Kind.Text, false), f(4, Kind.Text, false), f(5, Kind.Text, false),
    f(6, Kind.Uint, false), f(8, Kind.Text, false), f(9, Kind.Bytes, false),
  ],
  [FrameKnowledgeQueryResult]: [
    f(2, Kind.Array, true), f(3, Kind.Bool, true), f(4, Kind.Bytes, false), f(5, Kind.Uint, false), f(6, Kind.Bool, false),
  ],
  [FrameKnowledgeQueryStreamData]: [f(2, Kind.Array, true)],
  [FrameKnowledgeQueryStreamEnd]: [f(2, Kind.Array, false), f(3, Kind.Bool, true)],
  [FrameKnowledgeSubscribeReq]: [
    f(2, Kind.Text, false), f(3, Kind.Text, false), f(4, Kind.Text, false), f(5, Kind.Text, false),
    f(7, Kind.Text, false), f(8, Kind.Bool, false), f(9, Kind.Uint, true),
  ],
  [FrameKnowledgeSubscribeAck]: [f(2, Kind.Bytes, true), f(3, Kind.Uint, true), f(4, Kind.Bool, false)],
  [FrameKnowledgeUpdate]: [f(2, Kind.Bytes, true), f(3, Kind.Uint, true), f(4, Kind.Array, false), f(5, Kind.Array, false)],
  [FrameKnowledgeCredit]: [f(2, Kind.Bytes, true), f(3, Kind.Uint, true), f(4, Kind.Uint, false)],
  [FrameKnowledgeUnsubscribe]: [f(2, Kind.Bytes, true)],
  [FrameKnowledgeError]: [f(2, Kind.Uint, true), f(3, Kind.Text, true), f(4, Kind.Uint, false), f(5, Kind.Bytes, false)],
};

export function validateKnowledgePayload(ft: number, payload: Buffer): CborMap {
  const bad = mkMalformed("npamp/knowledge: malformed_request");
  const schema = knowledgeSchemas[ft];
  if (schema === undefined) {
    throw bad(`0x${ft.toString(16)} is not a Knowledge operation frame type`);
  }
  const m = decodeMap(payload, bad);
  checkFrameKind(m, ft, bad);
  checkCorr(m, bad);
  checkFields(m, schema, bad);
  // §6.5: a KNOWLEDGE_UPDATE MUST carry at least one of results (4) or removed (5).
  if (ft === FrameKnowledgeUpdate) {
    if (!m.has(4) && !m.has(5)) {
      throw bad("KNOWLEDGE_UPDATE carries neither results (4) nor removed (5) (§6.5)");
    }
  }
  return m;
}

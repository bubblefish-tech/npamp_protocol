// Corpus-grading conformance test for the native-channel deterministic-CBOR body
// decoders (draft-bubblefish-npamp-01). It grades the TypeScript validators in
// src/npamp_bodies.ts against the SHARED conformance corpus
// (test-vectors/v1/conformance-corpus.json) — the same independent grader the Go
// reference is graded against. For each op-group it decodes every vector:
//   - a "valid"/"acceptable" vector MUST decode without error, and its decoded
//     frame_kind (and corr, where the vector pins one) MUST match `expected`;
//   - an "invalid" (MUST-reject) vector MUST throw a decode error.
// The corpus is not modified, and no vector is special-cased: the validators are
// the only thing under test.

import { test } from "node:test";
import assert from "node:assert";
import { readFileSync } from "node:fs";

import {
  validateMemoryPayload,
  validateStreamPayload,
  validateCapabilityPayload,
  validateImmunePayload,
  validateSettlementPayload,
  validateTelemetryPayload,
  validateCommercePayload,
  validateInteractionPayload,
  validateWorkflowPayload,
  validateKnowledgePayload,
} from "../src/npamp_bodies.ts";
import { CborMap, type CborValue } from "../src/npamp_cbor.ts";

type Validator = (ft: number, payload: Buffer) => CborMap;

// The eight native channels this deliverable adds, plus memory/stream (already in
// the corpus) as codec cross-checks. Keyed by the corpus `op` string.
const VALIDATORS: Record<string, Validator> = {
  "memory.body.decode": validateMemoryPayload,
  "stream.body.decode": validateStreamPayload,
  "capability.body.decode": validateCapabilityPayload,
  "immune.body.decode": validateImmunePayload,
  "settlement.body.decode": validateSettlementPayload,
  "telemetry.body.decode": validateTelemetryPayload,
  "commerce.body.decode": validateCommercePayload,
  "interaction.body.decode": validateInteractionPayload,
  "workflow.body.decode": validateWorkflowPayload,
  "knowledge.body.decode": validateKnowledgePayload,
};

// The eight channels that are the deliverable of this task (graded strictly).
const TARGET_CHANNELS = [
  "capability.body.decode",
  "immune.body.decode",
  "settlement.body.decode",
  "telemetry.body.decode",
  "commerce.body.decode",
  "interaction.body.decode",
  "workflow.body.decode",
  "knowledge.body.decode",
];

interface Vector {
  tcId: number;
  comment?: string;
  in: { frameType: number; body: string };
  result: "valid" | "acceptable" | "invalid";
  expected?: { frame_kind?: number; corr?: string };
  flags?: string[];
}

interface TestGroup {
  op: string;
  tests: Vector[];
}

const corpusUrl = new URL("../../../test-vectors/v1/conformance-corpus.json", import.meta.url);
const corpus = JSON.parse(readFileSync(corpusUrl, "utf8")) as { testGroups: TestGroup[] };
const groups = new Map<string, TestGroup>(corpus.testGroups.map((g) => [g.op, g]));

// gradeVector applies one vector and returns nothing on success, or throws an
// AssertionError describing exactly which vector failed and how.
function gradeVector(op: string, validate: Validator, v: Vector): void {
  const buf = Buffer.from(v.in.body, "hex");
  const label = `${op} tcId=${v.tcId} (${v.comment ?? ""})`;

  if (v.result === "invalid") {
    // MUST-reject: the decoder MUST throw. A decoder that ignores its input would
    // fail here — this is the real gate.
    assert.throws(
      () => validate(v.in.frameType, buf),
      (err: unknown) => err instanceof Error,
      `MUST-reject vector decoded OK (no error thrown): ${label}`,
    );
    return;
  }

  // valid / acceptable: MUST decode without error.
  let m: CborMap;
  try {
    m = validate(v.in.frameType, buf);
  } catch (err) {
    assert.fail(`valid vector threw: ${label}\n  -> ${(err as Error).message}`);
  }

  // Check the decoded frame_kind matches the expected value the corpus pins.
  const exp = v.expected ?? {};
  if (exp.frame_kind !== undefined) {
    const fk = m.get(0);
    assert.strictEqual(
      typeof fk === "bigint" ? Number(fk) : fk,
      exp.frame_kind,
      `frame_kind mismatch: ${label}`,
    );
  }
  // Check the decoded corr (envelope key 1) matches, where the vector pins one.
  if (exp.corr !== undefined) {
    const corr: CborValue | undefined = m.get(1);
    assert.ok(Buffer.isBuffer(corr), `corr not a byte string: ${label}`);
    assert.strictEqual((corr as Buffer).toString("hex"), exp.corr, `corr mismatch: ${label}`);
  }
}

// Register one node:test per op-group. Every vector in the group must pass.
for (const [op, validate] of Object.entries(VALIDATORS)) {
  test(op, () => {
    const g = groups.get(op);
    assert.ok(g, `op-group ${op} not found in corpus`);
    assert.ok(g.tests.length > 0, `op-group ${op} has no vectors`);
    let valid = 0;
    let reject = 0;
    for (const v of g.tests) {
      gradeVector(op, validate, v);
      if (v.result === "invalid") {
        reject++;
      } else {
        valid++;
      }
    }
    console.log(`  [${op}] valid/acceptable=${valid} reject=${reject} total=${g.tests.length} ALL PASS`);
  });
}

// A coverage guard: every one of the eight target channels MUST be present in the
// corpus and carry at least one valid AND at least one reject vector (so a green
// run cannot come from an empty or one-sided group).
test("target-channel coverage", () => {
  for (const op of TARGET_CHANNELS) {
    const g = groups.get(op);
    assert.ok(g, `target channel ${op} missing from corpus`);
    const valid = g.tests.filter((t) => t.result !== "invalid").length;
    const reject = g.tests.filter((t) => t.result === "invalid").length;
    assert.ok(valid > 0, `${op} has no valid vectors`);
    assert.ok(reject > 0, `${op} has no MUST-reject vectors`);
  }
});

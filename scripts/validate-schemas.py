#!/usr/bin/env python3
"""Validate every in-tree N-PAMP conformance / KAT vector against its JSON Schema (draft 2020-12).

A real STRUCTURAL verifier that complements the SHA-256 byte-pin (verify-pins.ps1): the pin catches any
change to the bytes, this catches a *malformed* vector edit — a missing required key, a wrong JSON type,
a non-hex byte string, a wrong-length hash — at author time, before the pin is recomputed. Uses the
`jsonschema` library's Draft202012Validator. Exit 0 only if every (vector, schema) pair validates and
every schema is itself a valid draft-2020-12 schema; exit 1 on any missing file, invalid schema, or
validation error.
"""
import json
import os
import sys

try:
    from jsonschema import Draft202012Validator
except ImportError:
    print("SCHEMA VALIDATION: SKIP (python 'jsonschema' not installed)", file=sys.stderr)
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # GitHub/scripts -> GitHub/
VEC = os.path.join(ROOT, "test-vectors", "v1")
SCH = os.path.join(ROOT, "test-vectors", "schemas")

# (vector file, schema file) — every vector in test-vectors/v1 paired with its schema.
PAIRS = [
    ("conformance-corpus.json", "conformance-corpus.schema.json"),
    ("transcript-kat.json", "transcript-kat.schema.json"),
    ("key-schedule-kat.json", "key-schedule-kat.schema.json"),
    ("finished-kat.json", "finished-kat.schema.json"),
    ("certverify-kat.json", "certverify-kat.schema.json"),
    ("kem-wire-kat.json", "kem-wire-kat.schema.json"),
    ("handshake-flow-kat.json", "handshake-flow-kat.schema.json"),
]


def main():
    fail = 0
    for vec, sch in PAIRS:
        vp = os.path.join(VEC, vec)
        sp = os.path.join(SCH, sch)
        if not os.path.exists(vp):
            print(f"MISSING vector : {vec}")
            fail += 1
            continue
        if not os.path.exists(sp):
            print(f"MISSING schema : {sch}")
            fail += 1
            continue
        try:
            with open(sp, encoding="utf-8") as f:
                schema = json.load(f)
            Draft202012Validator.check_schema(schema)  # the schema itself must be valid draft 2020-12
            with open(vp, encoding="utf-8") as f:
                data = json.load(f)
            Draft202012Validator(schema).validate(data)  # the vector must satisfy the schema
            print(f"ok      : {vec} <- {sch}")
        except Exception as e:  # noqa: BLE001 - report any schema/validation/parse failure as a gate failure
            first = str(e).splitlines()[0] if str(e) else ""
            print(f"INVALID : {vec} <- {sch}\n    {type(e).__name__}: {first}")
            fail += 1
    print()
    if fail:
        print(f"SCHEMA VALIDATION: {fail} failure(s)")
        sys.exit(1)
    print(f"SCHEMA VALIDATION: ALL PASS ({len(PAIRS)} vectors)")
    sys.exit(0)


if __name__ == "__main__":
    main()

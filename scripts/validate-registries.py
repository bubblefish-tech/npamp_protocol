#!/usr/bin/env python3
"""Validate every N-PAMP code-point registry CSV against its JSON Schema (draft 2020-12).

A structural verifier for the registries, mirroring validate-schemas.py (which does the same for
the test-vector KATs). For each registry it (1) converts the CSV to a JSON array of row objects
(header row -> object keys), coercing the declared-integer columns from their CSV string form to
int so the schema's integer/range constraints actually apply; (2) checks the schema is itself a
valid draft-2020-12 schema and validates the array against it (catches wrong-format code point,
missing required column, empty required string, out-of-declared-range value, out-of-enum token);
and (3) runs a duplicate/overlap pass that JSON Schema CANNOT express -- JSON Schema's uniqueItems
only compares whole objects, never a single field across rows, so duplicate code points must be
caught here. Exit 0 only if every registry validates AND has no duplicate/overlapping code points
and every schema is a valid draft-2020-12 schema; exit 1 on any failure; exit 2 if jsonschema is
absent (matching validate-schemas.py's SKIP contract so CI installs it and gates instead of skips).
"""
import csv
import json
import os
import sys

try:
    from jsonschema import Draft202012Validator
except ImportError:
    print("REGISTRY VALIDATION: SKIP (python 'jsonschema' not installed)", file=sys.stderr)
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # GitHub/scripts -> GitHub/
REG = os.path.join(ROOT, "registries")
SCH = os.path.join(ROOT, "registries", "schemas")

# Per registry: schema file, the column that carries the code point, and which columns are integers
# (so the CSV string is coerced to int before schema validation -- CSV has no types of its own).
#   code_point_col = None  -> registry keyed by a name, not a hex code point (profiles). Its hex
#                             `code` column is still schema-checked for format; only the duplicate
#                             pass keys on the name.
REGISTRIES = [
    {"csv": "channels.csv",             "schema": "channels.schema.json",
     "code_col": "channel_id",  "int_cols": []},
    {"csv": "frame_types_reserved.csv", "schema": "frame_types_reserved.schema.json",
     "code_col": "frame_type",  "int_cols": []},
    {"csv": "tlv_tags.csv",             "schema": "tlv_tags.schema.json",
     "code_col": "tag",         "int_cols": []},
    {"csv": "profiles.csv",             "schema": "profiles.schema.json",
     "code_col": "code",        "int_cols": []},
    {"csv": "kem.csv",                  "schema": "kem.schema.json",
     "code_col": "code_point",  "int_cols": []},
    {"csv": "aead.csv",                 "schema": "aead.schema.json",
     "code_col": "code_point",  "int_cols": ["key_bytes", "nonce_bytes", "tag_bytes"]},
    {"csv": "signatures.csv",           "schema": "signatures.schema.json",
     "code_col": "code_point",  "int_cols": []},
    {"csv": "bridge_protocol_ids.csv",  "schema": "bridge_protocol_ids.schema.json",
     "code_col": "protocol_id", "int_cols": []},
]


def csv_to_rows(path, int_cols):
    """Read a registry CSV into a list of row dicts (header row -> keys).

    Empty CSV cells stay as "" so a required-but-blank column trips the schema's minLength/enum
    instead of vanishing. Declared-integer columns are coerced to int; a non-integer there is left
    as the original string so the schema's `type: integer` check reports it rather than crashing here.
    """
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            return rows
        for raw in reader:
            row = dict(raw)
            for col in int_cols:
                v = row.get(col, "")
                if isinstance(v, str) and v.strip().lstrip("-").isdigit():
                    row[col] = int(v.strip())
            rows.append(row)
    return rows


def parse_codepoint(token):
    """Parse a code-point token into an inclusive (low, high) integer range for overlap detection.

    Accepts a single hex point '0x0001' -> (1, 1) and an inclusive range '0x0035-0x0036' -> (53, 54).
    Returns None for a token that is neither (e.g. a profile NAME, or a malformed value the schema
    pass already flagged) so the duplicate pass simply skips it and does not mask a schema error.
    """
    if not isinstance(token, str):
        return None
    t = token.strip()
    try:
        if "-" in t:
            lo_s, hi_s = t.split("-", 1)
            lo, hi = int(lo_s, 16), int(hi_s, 16)
            return (lo, hi) if lo <= hi else (hi, lo)
        return (int(t, 16), int(t, 16))
    except ValueError:
        return None


def find_duplicate_codepoints(rows, code_col):
    """Return a list of human-readable duplicate/overlap findings for the code-point column.

    Uniqueness rules, grounded in how the real registries are structured:
      * EXACT duplicate token (same string appears on two rows) is always a finding.
      * PARTIAL overlap of two numeric intervals -- they intersect but neither fully contains the
        other (e.g. 0x0000-0x0002 vs 0x0002-0x0004) -- is a finding: it is an ambiguous, almost
        certainly accidental collision.
      * FULL containment (one interval nested inside another, e.g. the point 0x0100 inside the
        umbrella range 0x0100-0xFFFF) is NOT a finding: frame_types_reserved.csv and
        bridge_protocol_ids.csv deliberately register a broad catch-all range together with
        specific carve-out assignments inside it. Flagging that would be a false positive on the
        real data, so containment is allowed and only genuine partial overlaps and exact dups fail.
    Non-hex tokens (profile names, or values the schema already rejected) are compared only for
    exact string duplication, the correct uniqueness rule for a name-keyed registry.
    """
    findings = []
    seen_tokens = {}
    intervals = []  # (low, high, token, row_index)
    for i, row in enumerate(rows):
        tok = row.get(code_col, "")
        if tok in seen_tokens:
            findings.append(f"duplicate {code_col} {tok!r} (rows {seen_tokens[tok]} and {i})")
        else:
            seen_tokens[tok] = i
        rng = parse_codepoint(tok)
        if rng is not None:
            intervals.append((rng[0], rng[1], tok, i))
    # Pairwise PARTIAL-overlap detection on the numeric (hex) tokens only. Full containment of one
    # interval within another is the legitimate umbrella+carve-out pattern and is intentionally allowed.
    for a in range(len(intervals)):
        lo_a, hi_a, tok_a, ia = intervals[a]
        for b in range(a + 1, len(intervals)):
            lo_b, hi_b, tok_b, ib = intervals[b]
            intersect = lo_a <= hi_b and lo_b <= hi_a
            if not intersect:
                continue
            a_contains_b = lo_a <= lo_b and hi_b <= hi_a
            b_contains_a = lo_b <= lo_a and hi_a <= hi_b
            if a_contains_b or b_contains_a:
                continue  # nested carve-out inside an umbrella range: allowed
            findings.append(
                f"partial-overlapping {code_col} {tok_a!r} (row {ia}) and {tok_b!r} (row {ib})"
            )
    return findings


def main():
    fail = 0
    for r in REGISTRIES:
        csv_path = os.path.join(REG, r["csv"])
        sch_path = os.path.join(SCH, r["schema"])
        if not os.path.exists(csv_path):
            print(f"MISSING csv    : {r['csv']}")
            fail += 1
            continue
        if not os.path.exists(sch_path):
            print(f"MISSING schema : {r['schema']}")
            fail += 1
            continue
        try:
            with open(sch_path, encoding="utf-8") as f:
                schema = json.load(f)
            Draft202012Validator.check_schema(schema)  # the schema itself must be valid draft 2020-12
            rows = csv_to_rows(csv_path, r["int_cols"])
            validator = Draft202012Validator(schema)
            errors = sorted(validator.iter_errors(rows), key=lambda e: list(e.path))
            dups = find_duplicate_codepoints(rows, r["code_col"])
            if errors or dups:
                print(f"INVALID : {r['csv']} <- {r['schema']}")
                for e in errors:
                    loc = "/".join(str(p) for p in e.path) or "<root>"
                    print(f"    schema  @ {loc}: {e.message}")
                for d in dups:
                    print(f"    dup     : {d}")
                fail += 1
            else:
                print(f"ok      : {r['csv']} <- {r['schema']}  ({len(rows)} rows)")
        except Exception as e:  # noqa: BLE001 - any parse/schema failure is a gate failure
            first = str(e).splitlines()[0] if str(e) else ""
            print(f"INVALID : {r['csv']} <- {r['schema']}\n    {type(e).__name__}: {first}")
            fail += 1
    print()
    if fail:
        print(f"REGISTRY VALIDATION: {fail} failure(s)")
        sys.exit(1)
    print(f"REGISTRY VALIDATION: ALL PASS ({len(REGISTRIES)} registries)")
    sys.exit(0)


if __name__ == "__main__":
    main()

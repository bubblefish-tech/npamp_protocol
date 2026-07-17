#!/usr/bin/env python3
"""Validate registries/frame_types_channel.csv against its JSON Schema AND against the Go consts.

This is the per-channel companion to validate-registries.py. The flat frame_types_reserved.csv is
one all-channel table (system frames, coarse reserved ranges, the Control handshake); it CANNOT
express the per-channel frame-type namespace (core specification section 4.6) in which the SAME
numeric frame_type recurs on different channels. This registry does, and this validator enforces the
two invariants JSON Schema cannot:

  (1) COMPOSITE-KEY uniqueness. (channel_id, frame_type) is unique; go_const is globally unique;
      channel_name is consistent per channel_id and matches channels.csv. band agrees with the code
      point (application <=> frame_type >= 0x0100; companion-extension <=> 0x0030 <= ft <= 0x00FF).

  (2) LOCKSTEP with the Go reference implementation, both directions:
        forward  -- every CSV row's go_const, read from impl/go/<go_file>, has value == frame_type.
        reverse  -- every channel-specific FrameType constant declared in impl/go (value >= 0x0030,
                    excluding the all-channel system frames 0x0001-0x000A) appears as a CSV row.
      A drifted impl (a renamed/re-valued/added/removed frame const) fails the gate.

NON-CIRCULARITY (F3). The registry's expected values (name, frame_type, band, description) are
authored from the channels' companion specifications section 3 -- the independent authority -- NOT
generated from the Go source. This validator confirms the Go IMPLEMENTATION agrees with that
spec-authored registry; it is a cross-check between two independently produced artifacts, not a
tautology. Do NOT regenerate this CSV from the Go consts: that would make the check circular.

Exit 0 iff the CSV validates against the schema AND all uniqueness/band checks pass AND the Go
consts are in exact lockstep; exit 1 on any failure; exit 2 if jsonschema is absent (matching the
SKIP contract of validate-registries.py so CI installs it and gates rather than skips)."""
import argparse
import csv
import json
import os
import re
import sys

try:
    from jsonschema import Draft202012Validator
except ImportError:
    print("FRAME-TYPE-CHANNEL VALIDATION: SKIP (python 'jsonschema' not installed)", file=sys.stderr)
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
# Default layout: this script lives in GitHub/scripts/. Overridable via CLI for out-of-tree runs.
DEFAULT_ROOT = os.path.dirname(HERE)
DEFAULT_CSV = os.path.join(DEFAULT_ROOT, "registries", "frame_types_channel.csv")
DEFAULT_SCHEMA = os.path.join(DEFAULT_ROOT, "registries", "schemas", "frame_types_channel.schema.json")
DEFAULT_CHANNELS = os.path.join(DEFAULT_ROOT, "registries", "channels.csv")
DEFAULT_IMPL_GO = os.path.join(DEFAULT_ROOT, "impl", "go")

# A Go FrameType constant declaration, e.g.:  FrameMemoryCreateReq          FrameType = 0x0100
GO_FRAME_RE = re.compile(r"^\s*(Frame[A-Za-z0-9]+)\s+FrameType\s*=\s*0x([0-9A-Fa-f]+)")
# System (all-channel) frame types, defined once in frametypes.go and registered in
# frame_types_reserved.csv -- NOT channel-specific, so excluded from the reverse cross-check.
SYSTEM_FRAME_MAX = 0x000A


def load_rows(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_channels(path):
    """channel_id (lowercased hex) -> channel name, from registries/channels.csv."""
    out = {}
    for row in load_rows(path):
        out[row["channel_id"].lower()] = row["name"]
    return out


def scan_go_consts(impl_go_dir):
    """Return {go_file: {go_const: value_int}} for every FrameType constant in impl/go/*.go.

    Skips _test.go files. Includes the system frames too; callers filter by value where needed.
    """
    out = {}
    for fn in sorted(os.listdir(impl_go_dir)):
        if not fn.endswith(".go") or fn.endswith("_test.go"):
            continue
        consts = {}
        with open(os.path.join(impl_go_dir, fn), encoding="utf-8") as f:
            for line in f:
                m = GO_FRAME_RE.match(line)
                if m:
                    consts[m.group(1)] = int(m.group(2), 16)
        if consts:
            out[fn] = consts
    return out


def main():
    ap = argparse.ArgumentParser(description="Validate the per-channel frame-type registry against schema + Go consts.")
    ap.add_argument("--csv", default=DEFAULT_CSV)
    ap.add_argument("--schema", default=DEFAULT_SCHEMA)
    ap.add_argument("--channels", default=DEFAULT_CHANNELS)
    ap.add_argument("--impl-go", default=DEFAULT_IMPL_GO)
    args = ap.parse_args()

    failures = []

    for label, path in (("csv", args.csv), ("schema", args.schema),
                        ("channels", args.channels), ("impl-go dir", args.impl_go)):
        if not os.path.exists(path):
            print(f"MISSING {label}: {path}")
            sys.exit(1)

    with open(args.schema, encoding="utf-8") as f:
        schema = json.load(f)
    Draft202012Validator.check_schema(schema)

    rows = load_rows(args.csv)
    validator = Draft202012Validator(schema)
    for e in sorted(validator.iter_errors(rows), key=lambda e: list(e.path)):
        loc = "/".join(str(p) for p in e.path) or "<root>"
        failures.append(f"schema  @ {loc}: {e.message}")

    channels = load_channels(args.channels)
    go = scan_go_consts(args.impl_go)

    # ---- (1) uniqueness / consistency / band ------------------------------------------------
    seen_key = {}      # (channel_id, frame_type) -> row index
    seen_const = {}    # go_const -> row index
    chan_name = {}     # channel_id -> channel_name (first seen)
    for i, r in enumerate(rows):
        cid = r["channel_id"].lower()
        ft = r["frame_type"].lower()
        key = (cid, ft)
        if key in seen_key:
            failures.append(f"duplicate (channel_id, frame_type) {r['channel_id']},{r['frame_type']} (rows {seen_key[key]} and {i})")
        else:
            seen_key[key] = i

        gc = r["go_const"]
        if gc in seen_const:
            failures.append(f"duplicate go_const {gc!r} (rows {seen_const[gc]} and {i})")
        else:
            seen_const[gc] = i

        if cid not in channels:
            failures.append(f"row {i}: channel_id {r['channel_id']} not in channels.csv")
        elif channels[cid] != r["channel_name"]:
            failures.append(f"row {i}: channel_name {r['channel_name']!r} != channels.csv {channels[cid]!r} for {r['channel_id']}")

        if cid in chan_name and chan_name[cid] != r["channel_name"]:
            failures.append(f"row {i}: channel_name {r['channel_name']!r} inconsistent with earlier {chan_name[cid]!r} for {r['channel_id']}")
        chan_name.setdefault(cid, r["channel_name"])

        ftv = int(ft, 16)
        band = r["band"]
        if ftv >= 0x0100 and band != "application":
            failures.append(f"row {i}: {r['frame_type']} is >= 0x0100 but band={band!r} (expected 'application')")
        elif 0x0030 <= ftv <= 0x00FF and band != "companion-extension":
            failures.append(f"row {i}: {r['frame_type']} is in 0x0030-0x00FF but band={band!r} (expected 'companion-extension')")
        elif ftv < 0x0030:
            failures.append(f"row {i}: {r['frame_type']} is below the channel-specific space (< 0x0030); a system frame belongs in frame_types_reserved.csv, not here")

    # ---- (2a) forward cross-check: CSV go_const -> Go value ----------------------------------
    for i, r in enumerate(rows):
        gf, gc, ft = r["go_file"], r["go_const"], int(r["frame_type"], 16)
        if gf not in go:
            failures.append(f"row {i}: go_file {gf} defines no FrameType constants (or is absent) under {args.impl_go}")
            continue
        if gc not in go[gf]:
            failures.append(f"row {i}: {gc} not declared in {gf}")
        elif go[gf][gc] != ft:
            failures.append(f"row {i}: {gc} in {gf} = 0x{go[gf][gc]:04X} but registry frame_type = {r['frame_type']}")

    # ---- (2b) reverse cross-check: every channel-specific Go const is registered -------------
    registered = {(r["go_file"], r["go_const"]) for r in rows}
    for gf, consts in go.items():
        for gc, val in consts.items():
            if val <= SYSTEM_FRAME_MAX:
                continue  # all-channel system frame; registered in frame_types_reserved.csv
            if (gf, gc) not in registered:
                failures.append(f"unregistered Go frame const {gc} = 0x{val:04X} in {gf} (add a row to {os.path.basename(args.csv)})")

    print(f"rows: {len(rows)}   channels-with-frames: {len(chan_name)}   go-files-scanned: {len(go)}")
    if failures:
        for msg in failures:
            print(f"    FAIL: {msg}")
        print(f"\nFRAME-TYPE-CHANNEL VALIDATION: {len(failures)} failure(s)")
        sys.exit(1)
    app = sum(1 for r in rows if int(r["frame_type"], 16) >= 0x0100)
    ext = len(rows) - app
    print(f"FRAME-TYPE-CHANNEL VALIDATION: ALL PASS ({app} application-band + {ext} companion-extension rows, Go consts in lockstep)")
    sys.exit(0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Assert the rendered registries doc page has not drifted from the registry CSVs.

The docs page `docs/registries.md` renders each code-point registry as a hand-authored
Markdown table that MIRRORS the machine-readable CSV under `registries/` (the same
convention the core spec pages spec/03..07 already use). A hand-authored mirror can
silently drift from its CSV; `scripts/validate-registries.py` validates the CSV against
its JSON Schema but says NOTHING about the rendered page. This script closes that gap.

For each registry it (1) locates the registry's section in the page and extracts the first
Markdown table under it; (2) checks the page table has exactly as many data rows as the
CSV; and (3) for every CSV row, finds the page row whose leading (code-point) cell matches
the CSV's key column and asserts every other CSV cell value is present in that page row.
Comparison is normalized for pure typography only -- dash variants (-, en, em) collapse to
'-', a Markdown-escaped '\\|' collapses to '|', whitespace collapses, case is ignored -- so
en-dash ranges and em-dash names in the prose page do not read as drift, while a missing
row, a wrong code point, or a changed value DOES.

Exit 0 only if every registry's rendered table matches its CSV; exit 1 on any drift or if a
section/table is missing; exit 2 if an input file is absent. Stdlib only (csv + re); no new
dependency on the deliberately-lean docs toolchain.
"""
import csv
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # GitHub/scripts -> GitHub/
REG = os.path.join(ROOT, "registries")
PAGE = os.path.join(ROOT, "docs", "registries.md")

# Allow overriding page path and registries dir for local verification: argv[1]=page, argv[2]=regdir.
if len(sys.argv) >= 2:
    PAGE = os.path.abspath(sys.argv[1])
if len(sys.argv) >= 3:
    REG = os.path.abspath(sys.argv[2])

# Per registry: CSV file, the "##" section heading text in the page, and the CSV column that
# carries the row key (a hex code point, or the profile name for the name-keyed profiles registry).
REGISTRIES = [
    {"csv": "channels.csv",             "heading": "Channel registry",           "key": "channel_id"},
    {"csv": "frame_types_reserved.csv", "heading": "Frame-type registry",        "key": "frame_type"},
    {"csv": "tlv_tags.csv",             "heading": "TLV type registry",          "key": "tag"},
    {"csv": "profiles.csv",             "heading": "Profile registry",           "key": "profile"},
    {"csv": "kem.csv",                  "heading": "KEM-suite registry",         "key": "code_point"},
    {"csv": "aead.csv",                 "heading": "AEAD-suite registry",        "key": "code_point"},
    {"csv": "signatures.csv",           "heading": "Signature-scheme registry",  "key": "code_point"},
    {"csv": "bridge_protocol_ids.csv",  "heading": "Bridge protocol-ID registry","key": "protocol_id"},
]


def norm(s):
    """Collapse typographic-only differences so real drift stands out.

    Dash variants (hyphen-minus, en dash, em dash) -> '-'; Markdown-escaped pipe '\\|' -> '|';
    runs of whitespace -> single space; case folded; surrounding whitespace stripped.
    """
    if s is None:
        s = ""
    s = s.replace("–", "-").replace("—", "-")  # en dash, em dash -> '-'
    s = s.replace("\\|", "|")
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s


def extract_table_rows(page_text, heading):
    """Return the list of data rows (each a list of normalized cell strings) of the first
    Markdown table appearing after the given '## <heading>' section, or None if not found."""
    # Anchor on the section heading line, then take everything up to the next '## ' heading.
    m = re.search(r"^##\s+" + re.escape(heading) + r"\s*$", page_text, re.MULTILINE)
    if not m:
        return None
    rest = page_text[m.end():]
    nxt = re.search(r"^##\s+", rest, re.MULTILINE)
    section = rest[: nxt.start()] if nxt else rest
    # Collect the first contiguous block of table lines (lines that start with '|').
    table_lines = []
    started = False
    for line in section.splitlines():
        if line.lstrip().startswith("|"):
            table_lines.append(line.strip())
            started = True
        elif started:
            break  # end of the first table block
    if len(table_lines) < 3:
        return None  # need header + separator + >=1 data row
    data = []
    for line in table_lines[2:]:  # skip header row and the |---|---| separator
        # Split on unescaped pipes; drop the empty first/last cells from the leading/trailing '|'.
        cells = re.split(r"(?<!\\)\|", line)
        cells = [c for c in cells]
        if cells and cells[0].strip() == "":
            cells = cells[1:]
        if cells and cells[-1].strip() == "":
            cells = cells[:-1]
        data.append([norm(c) for c in cells])
    return data


def main():
    if not os.path.exists(PAGE):
        print(f"MISSING page   : {PAGE}")
        sys.exit(2)
    with open(PAGE, encoding="utf-8") as f:
        page_text = f.read()

    fail = 0
    for r in REGISTRIES:
        csv_path = os.path.join(REG, r["csv"])
        if not os.path.exists(csv_path):
            print(f"MISSING csv    : {r['csv']}")
            fail += 1
            continue
        with open(csv_path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            csv_rows = [dict(row) for row in reader]
            fields = reader.fieldnames or []

        page_rows = extract_table_rows(page_text, r["heading"])
        if page_rows is None:
            print(f"MISSING table  : '{r['heading']}' section/table not found in page")
            fail += 1
            continue

        problems = []
        if len(page_rows) != len(csv_rows):
            problems.append(f"row count: page has {len(page_rows)}, CSV has {len(csv_rows)}")

        # Index page rows by their normalized leading (code-point / key) cell.
        page_by_key = {}
        for pr in page_rows:
            if pr:
                page_by_key.setdefault(pr[0], pr)

        for row in csv_rows:
            key_norm = norm(row.get(r["key"], ""))
            pr = page_by_key.get(key_norm)
            if pr is None:
                problems.append(f"key {row.get(r['key'])!r} missing from page table")
                continue
            page_row_text = " | ".join(pr)
            for col in fields:
                val = norm(row.get(col, ""))
                if val and val not in page_row_text:
                    problems.append(
                        f"row {row.get(r['key'])!r} col {col!r}: CSV value not found in page row"
                    )

        if problems:
            print(f"DRIFT   : {r['csv']} vs '{r['heading']}'")
            for p in problems:
                print(f"    {p}")
            fail += 1
        else:
            print(f"ok      : {r['csv']} == '{r['heading']}'  ({len(csv_rows)} rows)")

    print()
    if fail:
        print(f"REGISTRIES-DOC DRIFT CHECK: {fail} failure(s)")
        sys.exit(1)
    print(f"REGISTRIES-DOC DRIFT CHECK: ALL PASS ({len(REGISTRIES)} registries)")
    sys.exit(0)


if __name__ == "__main__":
    main()

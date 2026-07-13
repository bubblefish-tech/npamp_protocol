#!/usr/bin/env python3
"""Verify every markdown link in llms.txt (and every '# File:' separator in llms-full.txt) resolves to a real file.

A link-integrity gate for the LLM-ingestion index files, complementing validate-schemas.py (structural
KAT validation) and validate-registries.py (registry validation). llms.txt follows the llmstxt.org
convention: an H1, a blockquote summary, then H2 sections of markdown bullet links `[name](path): desc`.
This script parses out every inline markdown link target `(...)`, drops external references (http/https/
mailto/other-scheme URLs) and pure in-page anchors (`#...`), strips any `#fragment` or `?query` suffix,
resolves each remaining target relative to the repo root, and asserts the file exists. It then does the
same for llms-full.txt's `# File: <path>` separators. Exit 0 only if every referenced path resolves;
exit 1 listing each broken link with its source file and line; exit 2 if llms.txt itself is missing.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)  # GitHub/scripts -> GitHub/

LLMS = os.path.join(ROOT, "llms.txt")
LLMS_FULL = os.path.join(ROOT, "llms-full.txt")

# Inline markdown link target: the (...) part of [label](target). Labels may contain balanced-free text
# (including backtick code spans); targets never contain a space or a closing paren in this repo.
LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
# llms-full.txt inline-file separator.
FILE_SEP_RE = re.compile(r"^# File:\s+(\S+)\s*$")

# A target is "external" (not a repo path) if it carries a URL scheme like http:, https:, mailto:.
SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:")


def is_local_target(target: str) -> bool:
    """True if target should resolve to a file in this repo (not a URL or an in-page anchor)."""
    if not target or target.startswith("#"):
        return False  # pure in-page anchor
    if SCHEME_RE.match(target):
        return False  # http:, https:, mailto:, etc. -- external
    return True


def strip_suffix(target: str) -> str:
    """Drop any #fragment or ?query so the bare path is what we test on disk."""
    return target.split("#", 1)[0].split("?", 1)[0]


def collect_llms_links(path: str):
    """Yield (line_no, target) for every local markdown link target in an llms.txt-style file."""
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            for target in LINK_RE.findall(line):
                if is_local_target(target):
                    yield line_no, target


def collect_file_seps(path: str):
    """Yield (line_no, target) for every '# File: <path>' separator in llms-full.txt."""
    with open(path, encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            m = FILE_SEP_RE.match(line)
            if m:
                yield line_no, m.group(1)


def check(source_name: str, entries) -> int:
    """Resolve each (line, target); print one line per link; return the count of broken links."""
    broken = 0
    for line_no, target in entries:
        bare = strip_suffix(target)
        resolved = os.path.normpath(os.path.join(ROOT, bare))
        if os.path.isfile(resolved):
            print(f"ok      : {source_name}:{line_no} -> {target}")
        else:
            print(f"BROKEN  : {source_name}:{line_no} -> {target}")
            broken += 1
    return broken


def main():
    if not os.path.isfile(LLMS):
        print(f"MISSING : llms.txt (expected at {LLMS})")
        sys.exit(2)

    broken = 0
    checked = 0

    llms_entries = list(collect_llms_links(LLMS))
    checked += len(llms_entries)
    broken += check("llms.txt", llms_entries)

    if os.path.isfile(LLMS_FULL):
        full_entries = list(collect_file_seps(LLMS_FULL))
        checked += len(full_entries)
        broken += check("llms-full.txt", full_entries)
    else:
        print("note    : llms-full.txt not present -- skipping its '# File:' separators")

    print()
    if broken:
        print(f"LLMS-TXT CHECK: {broken} broken link(s) of {checked} checked")
        sys.exit(1)
    print(f"LLMS-TXT CHECK: ALL PASS ({checked} links resolve)")
    sys.exit(0)


if __name__ == "__main__":
    main()

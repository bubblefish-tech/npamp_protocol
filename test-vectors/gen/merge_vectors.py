#!/usr/bin/env python3
# Merge an oracle's vector group(s) into the conformance corpus (BOTH copies), writing LF line
# endings so the git-committed bytes match the worktree (the corpus files are `eol=lf` in
# .gitattributes; writing LF here keeps the pinned SHA-256 stable in CI — the CRLF-drift trap).
#
# Idempotent: a group whose `op` already exists is REPLACED, not duplicated.
#
# Run: python3 test-vectors/gen/merge_vectors.py [oracle_script.py ...]
#   default oracles: stream_oracle.py
import json, os, subprocess, sys

GEN = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(GEN))  # test-vectors/gen -> repo root
CORPORA = [
    os.path.join(ROOT, 'test-vectors', 'v1', 'conformance-corpus.json'),
    os.path.join(ROOT, 'harness', 'runner', 'corpus', 'conformance-corpus.json'),
]


def run_oracle(name):
    out = subprocess.check_output([sys.executable, os.path.join(GEN, name)])
    return json.loads(out)


def merge(corpus_path, groups):
    with open(corpus_path, 'r', encoding='utf-8') as f:
        c = json.load(f)
    ops = {g['op'] for g in groups}
    c['testGroups'] = [g for g in c['testGroups'] if g['op'] not in ops] + list(groups)
    # newline='\n' disables platform newline translation -> LF on every OS (CRLF-drift guard).
    with open(corpus_path, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(c, f, indent=2)
        f.write('\n')
    return [g['op'] for g in groups]


def main():
    oracles = sys.argv[1:] or ['stream_oracle.py']
    groups = []
    for o in oracles:
        groups.extend(run_oracle(o))
    for cp in CORPORA:
        merged = merge(cp, groups)
        print('merged', merged, '->', os.path.relpath(cp, ROOT))


if __name__ == '__main__':
    main()

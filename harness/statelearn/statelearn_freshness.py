#!/usr/bin/env python3
# Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.
"""harness/statelearn/statelearn_freshness.py -- the T18.2 durable-gate FRESHNESS check.

The deterministic, Java-free complement to diff_model.py, and the second half of the durable
state-machine conformance gate (the first half being diff_model.py's model<->table
equivalence check).

## What each half proves, and why both are needed

diff_model.py answers: "do the COMMITTED learned models still agree with the CURRENT
draft-derived table?" (model <-> table consistency). It structurally CANNOT answer the other
half, because the learned models are static JSON: a model learned against an OLD SDK can still
match an unchanged table forever. So a green diff on its own does not establish that the
committed evidence describes the SDK that ships today.

This script answers exactly that missing half, WITHOUT re-running the ~14-minute LearnLib
learn (which needs Java + a 7.87 MB jar and reads a timing window over net.Pipe, so it is not
a deterministic per-commit gate -- that is the workflow_dispatch full-learn job / run.sh).
It pins, at learn time, a content hash of:

  INPUTS  -- everything that compiles into the SUL binary and therefore determines the
             learned behaviour: the whole impl/go module's non-test sources + module files
             (the real SDK the SUL drives), the Go SUL driver (sul/*.go), the three Java
             LearnLib harness files, and learn-config.json (the algorithm / alphabet /
             EQ-oracle parameters that shaped the learn).
  OUTPUTS -- the learned models themselves (learned-initiator.json, learned-responder.json).

and re-checks them:

  * an INPUT hash mismatch  => the SDK / SUL driver / harness / learn parameters changed since
                               the learn; the committed models are STALE. FAIL, and demand a
                               relearn. This false-reds on a cosmetic edit to any pinned file
                               and that is CORRECT -- the same fail-closed trade verify-pins.ps1
                               makes; the cost is one local relearn per impl change, cheap at
                               phase-close cadence. (Do not reach for semantic/AST hashing.)
  * an OUTPUT hash mismatch => a learned model changed with NO recorded relearn: it was
                               hand-edited (e.g. doctored to match a changed table). FAIL: a
                               model may only change through a full relearn that also
                               regenerates this manifest atomically.

## What this is NOT

This is NOT an m-completeness proof and makes no such claim. The equivalence check the full
learn runs is a randomized Wp-method sample (probabilistic, bounded by learn-config.json's
eq_rnd_length / eq_bound_tests_per_query) -- NOT the exhaustive, absolutely m-complete Wp of
Chow (1978) / Fujiwara et al. (1991), which is exponential in the extra-state bound and
infeasible here (~145k episodes at depth 2 over the timeout-probed net.Pipe). This freshness
gate proves only that the committed evidence is fresh (learned from today's implementation)
and not fabricated, so diff_model.py's green verdict is known to be ABOUT the current
implementation rather than a stale or doctored snapshot.

## Hashing

hash = SHA-256 of the file's LF-normalized bytes (every b"\\r\\n" -> b"\\n" before hashing), so
a Windows CRLF worktree and a committed-LF blob hash identically (the pinned-vector CRLF
lesson: never pin a CRLF worktree hash). The SAME function generates and verifies, so the
manifest is self-consistent by construction; a genuine content change is the only thing that
moves a hash.

## Usage

  python statelearn_freshness.py                 # CHECK (default): selftest, then verify the
                                                 #   manifest against the tree. exit 1 on drift.
  python statelearn_freshness.py --generate      # (re)generate statelearn-provenance.json from
                                                 #   the CURRENT tree -- run ONLY as the final
                                                 #   step of a full relearn, never to paper over
                                                 #   a drift the check just reported.
  python statelearn_freshness.py --selftest-only # run only the failing-fixture selftest.

exit 0 = fresh (or selftest ok); 1 = drift / fabrication detected; 2 = gate is broken (its
own failing fixture did not fail -- inert-check discipline: refuse to run rather than pass).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent          # .../harness/statelearn
REPO_ROOT = HERE.parent.parent                  # .../GitHub (the publishable slice root)
IMPL_GO = REPO_ROOT / "impl" / "go"
MANIFEST_PATH = HERE / "statelearn-provenance.json"

HASH_ALGO = "sha256-lf-normalized"


def lf_hash(path: Path) -> str:
    """SHA-256 of the file's LF-normalized bytes. CRLF -> LF first so a Windows worktree and
    the committed-LF blob hash identically (never pin a CRLF worktree hash)."""
    data = path.read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def _rel(path: Path) -> str:
    """Repo-root-relative POSIX path (portable across the Windows worktree and CI Linux)."""
    return path.resolve().relative_to(REPO_ROOT).as_posix()


def enumerate_inputs() -> list[Path]:
    """Every file that compiles into the SUL binary and therefore fixes the learned behaviour.

    Deliberately a broad, no-judgment set (per the durable-gate design): the WHOLE impl/go
    module, not a hand-picked 'state-machine-relevant' subset -- a change to root-package frame
    parsing or AEAD accept/reject shifts learned behaviour just as a sdk/ change does. Test
    files (*_test.go) are excluded because `go build` (not `go test`) links the SUL, so they
    cannot change the learned machine; pinning them would false-red on a test-only edit.
    """
    inputs: list[Path] = []

    # 1. The whole impl/go module: all non-test Go sources + the module files.
    for p in sorted(IMPL_GO.rglob("*.go")):
        if p.name.endswith("_test.go"):
            continue
        inputs.append(p)
    for name in ("go.mod", "go.sum"):
        p = IMPL_GO / name
        if p.exists():
            inputs.append(p)

    # 2. The Go SUL driver (drives the real, unmodified SDK over net.Pipe).
    for p in sorted((HERE / "sul").glob("*.go")):
        if p.name.endswith("_test.go"):
            continue
        inputs.append(p)

    # 3. The Java LearnLib harness (learner + process-SUL adapter + model serializer).
    for name in ("GoProcessSUL.java", "LearnedModel.java", "NpampStateLearner.java"):
        p = HERE / name
        if p.exists():
            inputs.append(p)

    # 4. The learn parameters: algorithm, alphabet, EQ-oracle class + bound, seed.
    inputs.append(HERE / "learn-config.json")

    return inputs


def output_models() -> list[Path]:
    """The learned models this manifest vouches for (the OUTPUTS of the learn)."""
    return [HERE / "learned-initiator.json", HERE / "learned-responder.json"]


def build_manifest() -> dict:
    inputs = {}
    for p in enumerate_inputs():
        if not p.exists():
            raise FileNotFoundError(f"pinned input does not exist: {p}")
        inputs[_rel(p)] = lf_hash(p)
    outputs = {}
    for p in output_models():
        if not p.exists():
            raise FileNotFoundError(f"learned model does not exist (run the full learn): {p}")
        outputs[_rel(p)] = lf_hash(p)
    return {
        "_doc": (
            "Provenance baseline for the T18.2 state-machine conformance gate. The committed "
            "learned-*.json under outputs were learned by NpampStateLearner.java driving the "
            "real impl/go SDK, whose source (+ the SUL driver, the Java harness, and the learn "
            "parameters) is pinned under inputs at the hashes below. statelearn_freshness.py "
            "fails if any input hash changed (models stale -> relearn) or any output hash "
            "changed without a relearn (model fabricated). This is a freshness + "
            "non-fabrication check, NOT an m-completeness proof (see the module docstring)."
        ),
        "hash_algo": HASH_ALGO,
        "learn_config_ref": "harness/statelearn/learn-config.json",
        "full_learn_recipe": "harness/statelearn/run.sh  (Windows: README.md 'Run on Windows')",
        "regenerate_with": "python harness/statelearn/statelearn_freshness.py --generate  (ONLY as the last step of a full relearn)",
        "inputs": inputs,
        "outputs": outputs,
    }


def check_manifest(manifest: dict, *, root_here: Path = HERE, root_repo: Path = REPO_ROOT) -> list[str]:
    """Recompute every pinned hash from the tree and compare against the manifest. Returns a
    list of human-readable failure lines (empty == fresh)."""
    failures: list[str] = []
    if manifest.get("hash_algo") != HASH_ALGO:
        failures.append(
            f"manifest hash_algo={manifest.get('hash_algo')!r} != expected {HASH_ALGO!r}"
        )
        return failures

    for kind in ("inputs", "outputs"):
        for rel, expected in manifest.get(kind, {}).items():
            p = root_repo / rel
            if not p.exists():
                failures.append(f"[{kind}] MISSING: {rel} is pinned but no longer exists")
                continue
            actual = lf_hash(p)
            if actual != expected:
                if kind == "inputs":
                    failures.append(
                        f"[inputs] CHANGED: {rel}\n"
                        f"           pinned {expected[:16]}... != current {actual[:16]}...\n"
                        f"           => the SDK/harness changed since the learn; the committed "
                        f"learned models are STALE.\n"
                        f"           Re-run the full learn (run.sh / the statelearn-full "
                        f"workflow) and regenerate this manifest."
                    )
                else:
                    failures.append(
                        f"[outputs] CHANGED: {rel}\n"
                        f"           pinned {expected[:16]}... != current {actual[:16]}...\n"
                        f"           => a learned model changed with no recorded relearn "
                        f"(hand-edited / fabricated).\n"
                        f"           A model may change ONLY via a full relearn that also "
                        f"regenerates this manifest."
                    )
    return failures


def selftest() -> bool:
    """Inert-check discipline: build a synthetic CLEAN baseline in a temp dir, generate a
    manifest for it, then MUTATE one pinned file and confirm the check FLAGS the mutation.
    A gate whose own failing fixture does not fail is broken and must refuse to run.

    Built from a synthetic baseline (never the live tree) so the fixture proves the check
    reacts to an injected fault, not to whatever state the real tree happens to be in.
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        f = tmp / "pinned.txt"
        f.write_bytes(b"baseline content\nline two\n")
        manifest = {
            "hash_algo": HASH_ALGO,
            "inputs": {"pinned.txt": lf_hash(f)},
            "outputs": {},
        }
        # (a) clean baseline must pass.
        clean = check_manifest(manifest, root_here=tmp, root_repo=tmp)
        if clean:
            print("selftest: BROKEN -- clean synthetic baseline reported drift:", clean, file=sys.stderr)
            return False
        # (b) inject one byte of drift; the check MUST flag it.
        f.write_bytes(b"baseline content\nline two MUTATED\n")
        drifted = check_manifest(manifest, root_here=tmp, root_repo=tmp)
        if not drifted:
            print("selftest: BROKEN -- injected input mutation was NOT flagged; gate is inert.", file=sys.stderr)
            return False
        # (c) an output mutation must also flag.
        g = tmp / "model.json"
        g.write_bytes(b'{"state":"q0"}\n')
        m2 = {"hash_algo": HASH_ALGO, "inputs": {}, "outputs": {"model.json": lf_hash(g)}}
        g.write_bytes(b'{"state":"q1"}\n')
        if not check_manifest(m2, root_here=tmp, root_repo=tmp):
            print("selftest: BROKEN -- injected output mutation was NOT flagged; gate is inert.", file=sys.stderr)
            return False
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description="T18.2 state-machine conformance FRESHNESS gate.")
    ap.add_argument("--generate", action="store_true",
                    help="(re)generate statelearn-provenance.json from the current tree "
                         "(ONLY as the last step of a full relearn).")
    ap.add_argument("--selftest-only", action="store_true",
                    help="run only the failing-fixture selftest and exit.")
    args = ap.parse_args()

    # Inert-check discipline: the gate proves it can fail BEFORE it is trusted to pass.
    if not selftest():
        print("statelearn-freshness: SELFTEST FAILED -- gate is broken, refusing to run (exit 2).")
        sys.exit(2)
    if args.selftest_only:
        print("statelearn-freshness: selftest OK (clean passes; input + output mutations both flagged).")
        sys.exit(0)

    if args.generate:
        manifest = build_manifest()
        # newline="\n": write LF regardless of platform, so the committed manifest matches
        # the .gitattributes eol=lf rule and a Windows regenerate does not churn CRLF.
        MANIFEST_PATH.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n")
        n_in, n_out = len(manifest["inputs"]), len(manifest["outputs"])
        print(f"statelearn-freshness: wrote {MANIFEST_PATH.name} "
              f"({n_in} inputs + {n_out} outputs pinned, {HASH_ALGO}).")
        sys.exit(0)

    if not MANIFEST_PATH.exists():
        print(f"statelearn-freshness: FAIL -- {MANIFEST_PATH.name} does not exist; "
              f"run --generate as the last step of a full learn.")
        sys.exit(1)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    failures = check_manifest(manifest)
    if failures:
        print(f"statelearn-freshness: FAIL -- {len(failures)} provenance mismatch(es):")
        for line in failures:
            print("  " + line.replace("\n", "\n  "))
        sys.exit(1)
    n_in, n_out = len(manifest.get("inputs", {})), len(manifest.get("outputs", {}))
    print(f"statelearn-freshness: PASS -- {n_in} inputs + {n_out} learned models match their "
          f"pinned provenance (models are fresh w.r.t. the current implementation and unmodified).")
    sys.exit(0)


if __name__ == "__main__":
    main()

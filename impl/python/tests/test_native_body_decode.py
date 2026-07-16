"""Corpus-graded conformance for the eight NPAMP native-channel body decoders
(Capability, Immune, Settlement, Telemetry, Commerce, Interaction, Workflow,
Knowledge). The SHARED corpus (test-vectors/v1/conformance-corpus.json) is the
independent grader: for each op-group every vector is decoded and

  - result "valid" / "acceptable"  MUST decode without error (and, where the vector
    carries an `expected` block, the decoded frame_kind and corr MUST match it);
  - result "invalid"               MUST raise a decode error (MUST-reject vectors).

The corpus is authored independently of this implementation (the Go reference emits
it), so a passing run is non-circular (F3). Run directly (PYTHONPATH=impl/python) or
via pytest.
"""
import os
import json

from npamp import native_bodies as nb

CORPUS = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "test-vectors", "v1", "conformance-corpus.json"
)

OP_GROUPS = (
    "capability.body.decode",
    "immune.body.decode",
    "settlement.body.decode",
    "telemetry.body.decode",
    "commerce.body.decode",
    "interaction.body.decode",
    "workflow.body.decode",
    "knowledge.body.decode",
)

# A vector whose result is one of these MUST decode OK; anything else ("invalid") MUST reject.
_ACCEPT = {"valid", "acceptable"}


def _load_groups():
    with open(CORPUS, "rb") as fh:
        corpus = json.loads(fh.read())
    by_op = {g["op"]: g for g in corpus["testGroups"]}
    missing = [op for op in OP_GROUPS if op not in by_op]
    assert not missing, f"corpus is missing op-groups: {missing}"
    return by_op


def _grade_group(op, group):
    """Grade one op-group; return (valid_pass, reject_pass). Raises AssertionError on any
    vector the decoder handles incorrectly."""
    validate = nb.VALIDATORS[op]
    valid_pass = reject_pass = 0
    for t in group["tests"]:
        tc = t["tcId"]
        ft = t["in"]["frameType"]
        body = bytes.fromhex(t["in"]["body"])
        must_accept = t["result"] in _ACCEPT

        if must_accept:
            try:
                m = validate(ft, body)
            except nb.CborError as e:
                raise AssertionError(f"[{op} tc{tc}] expected DECODE OK, got reject: {e}")
            exp = t.get("expected")
            if exp is not None:
                if "frame_kind" in exp:
                    fk, present = m.get(0)
                    assert present and fk == exp["frame_kind"], (
                        f"[{op} tc{tc}] frame_kind mismatch: got {fk!r} want {exp['frame_kind']!r}"
                    )
                if "corr" in exp:
                    corr, present = m.get(1)
                    got = corr.hex() if present and isinstance(corr, (bytes, bytearray)) else None
                    assert got == exp["corr"], (
                        f"[{op} tc{tc}] corr mismatch: got {got!r} want {exp['corr']!r}"
                    )
            valid_pass += 1
        else:
            try:
                validate(ft, body)
            except nb.CborError:
                reject_pass += 1
            else:
                raise AssertionError(
                    f"[{op} tc{tc}] MUST-reject vector decoded OK (decoder ignored a fault): "
                    f"{t.get('comment', '')}"
                )
    return valid_pass, reject_pass


def _make_group_test(op):
    def test(op=op):
        groups = _load_groups()
        vp, rp = _grade_group(op, groups[op])
        # Every group has at least one valid AND one MUST-reject vector; a decoder that
        # accepted everything (or rejected everything) fails one side. Guard both.
        assert vp > 0 and rp > 0, f"[{op}] degenerate: valid_pass={vp} reject_pass={rp}"
    return test


# Emit one test function per op-group so pytest reports each channel independently.
for _op in OP_GROUPS:
    _name = "test_" + _op.split(".")[0] + "_body_decode"
    globals()[_name] = _make_group_test(_op)


if __name__ == "__main__":
    groups = _load_groups()
    fails = 0
    total_valid = total_reject = 0
    for op in OP_GROUPS:
        try:
            vp, rp = _grade_group(op, groups[op])
            total_valid += vp
            total_reject += rp
            print(f"PASS {op}: {vp} valid/acceptable decoded, {rp} MUST-reject rejected")
        except AssertionError as e:
            print(f"FAIL {op}: {e}")
            fails += 1
    print(f"--- totals: {total_valid} valid, {total_reject} reject; {fails} group(s) failed")
    raise SystemExit(1 if fails else 0)

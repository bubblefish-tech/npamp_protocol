"""CBOR nesting-depth resource guard for the Python N-PAMP body decoder.

Mirrors the Go reference guard (impl/go/memory_cbor.go, cborMaxNestingDepth = 8)
against the spec-derived, non-circular conformance vectors:

  - REJECT: eight 0x81 (array-of-one) headers followed by 0x00 (scalar at
    depth 9) -> CborDepthExceededError.
  - ACCEPT: seven 0x81 headers followed by 0x00 (scalar at depth 8) -> decodes.
"""
import pytest

from npamp import native_bodies as nb


def test_depth_9_scalar_rejected_with_depth_exceeded():
    # Eight 0x81 (array, 1 element) headers + a 0x00 scalar: the scalar sits at
    # depth 9 (outermost array = depth 1, ..., 8th nested array = depth 8, its
    # element = depth 9). MUST be rejected with the depth-exceeded error.
    b = b"\x81" * 8 + b"\x00"
    with pytest.raises(nb.CborDepthExceededError):
        nb.cbor_decode_top(b)


def test_depth_8_scalar_accepted():
    # Seven 0x81 headers + a 0x00 scalar: the scalar sits at depth 8 (outermost
    # array = depth 1, ..., 7th nested array = depth 7, its element = depth 8).
    # MUST be accepted (decodes without error).
    b = b"\x81" * 7 + b"\x00"
    v = nb.cbor_decode_top(b)
    # Structural sanity: 7 singleton arrays nested around a scalar 0.
    for _ in range(7):
        assert isinstance(v, list) and len(v) == 1
        v = v[0]
    assert v == 0

# frozen_string_literal: true

# CBOR nesting-depth resource guard test for the Ruby N-PAMP body decoder.
#
# Mirrors the Go reference guard (impl/go/memory_cbor.go, cborMaxNestingDepth = 8)
# against the spec-derived, non-circular conformance vectors:
#   - REJECT: eight 0x81 (array-of-one) headers followed by 0x00 (scalar at
#     depth 9) -> Npamp::CBOR::DepthExceededError.
#   - ACCEPT: seven 0x81 headers followed by 0x00 (scalar at depth 8) -> decodes.
#
# Run from impl/ruby:  ruby test/cbor_depth_guard_test.rb

require_relative "../lib/npamp/native_cbor"

$failures = 0

def check(name, ok)
  puts "#{ok ? 'PASS' : 'FAIL'} #{name}"
  $failures += 1 unless ok
end

# Eight 0x81 (array, 1 element) headers + a 0x00 scalar: the scalar sits at
# depth 9 (outermost array = depth 1, ..., 8th nested array = depth 8, its
# element = depth 9). MUST be rejected with the depth-exceeded error.
reject_bytes = ("\x81".b * 8) + "\x00".b
rejected_right = false
begin
  Npamp::CBOR.decode_top(reject_bytes)
rescue Npamp::CBOR::DepthExceededError
  rejected_right = true
rescue StandardError
  rejected_right = false
end
check("depth_9_scalar_rejected_with_depth_exceeded", rejected_right)

# Seven 0x81 headers + a 0x00 scalar: the scalar sits at depth 8 (outermost
# array = depth 1, ..., 7th nested array = depth 7, its element = depth 8).
# MUST be accepted (decodes without error).
accept_bytes = ("\x81".b * 7) + "\x00".b
accepted_ok = false
begin
  Npamp::CBOR.decode_top(accept_bytes)
  accepted_ok = true
rescue StandardError
  accepted_ok = false
end
check("depth_8_scalar_accepted", accepted_ok)

puts($failures.zero? ? "ALL PASS (2/2)" : "FAILURES: #{$failures}")
exit($failures.zero? ? 0 : 1)

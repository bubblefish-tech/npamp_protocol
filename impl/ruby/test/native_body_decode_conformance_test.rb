# frozen_string_literal: true

# Corpus-grading conformance test for the eight N-PAMP native operation-body decoders
# (capability, immune, settlement, telemetry, commerce, interaction, workflow,
# knowledge). It grades the Ruby decoders in lib/npamp/native_bodies.rb against the
# SHARED cross-language conformance corpus at test-vectors/v1/conformance-corpus.json —
# the same independently-generated corpus the Go/Python oracles grade — mirroring the
# way the wire suite (conformance_test.rb) reproduces the cross-language golden vectors.
#
# For each of the eight <channel>.body.decode op-groups, every vector is decoded:
#   * result "valid" / "acceptable"  -> the body MUST decode without error, and the
#     decoded frame_kind (and corr, where the vector declares an expected corr) MUST
#     match the corpus's expected values;
#   * result "invalid" (a MUST-reject vector) -> the decode MUST raise an error.
#
# The corpus is the independent grader: it is neither weakened nor special-cased here.
# Prints one line per op-group and a final tally; exits 1 if any vector is graded wrong.

require "json"
require_relative "../lib/npamp/native_bodies"

CORPUS_PATH = File.expand_path("../../../test-vectors/v1/conformance-corpus.json", __dir__)

# The eight native channels graded here (their op-group is "<name>.body.decode").
CHANNELS = %w[capability immune settlement telemetry commerce interaction workflow knowledge].freeze

# A vector whose result is one of these MUST decode OK; any other result MUST be rejected.
ACCEPT_RESULTS = %w[valid acceptable].freeze

$failures = 0
$valid_pass = 0
$reject_pass = 0

def fail!(msg)
  puts "FAIL - #{msg}"
  $failures += 1
end

# grade_group runs every vector in one <channel>.body.decode group and returns
# [ok_count, total] while accumulating global pass/fail tallies.
def grade_group(channel, group)
  validator = Npamp::NativeBody::VALIDATORS.fetch(channel)
  ok = 0
  group["tests"].each do |t|
    tc = t["tcId"]
    ft = t.dig("in", "frameType")
    body = [t.dig("in", "body")].pack("H*")
    must_accept = ACCEPT_RESULTS.include?(t["result"])

    begin
      m = validator.call(ft, body)
      if must_accept
        exp = t["expected"] || {}
        fk, = m.get(0)
        if exp.key?("frame_kind") && fk != exp["frame_kind"]
          fail!("#{channel} tc#{tc}: frame_kind #{fk} != expected #{exp['frame_kind']}")
          next
        end
        if exp.key?("corr")
          corr, has = m.get(1)
          got = has && corr.is_a?(Npamp::CBOR::Bytes) ? corr.to_hex : nil
          if got != exp["corr"]
            fail!("#{channel} tc#{tc}: corr #{got.inspect} != expected #{exp['corr'].inspect}")
            next
          end
        end
        $valid_pass += 1
        ok += 1
      else
        # A MUST-reject vector that decoded without error is a grading failure.
        fail!("#{channel} tc#{tc}: MUST-reject vector (#{t['result']}) decoded without error")
      end
    rescue Npamp::NativeBody::Malformed, Npamp::CBOR::Error => e
      if must_accept
        fail!("#{channel} tc#{tc}: valid vector rejected: #{e.message}")
      else
        $reject_pass += 1
        ok += 1
      end
    end
  end
  [ok, group["tests"].length]
end

corpus = JSON.parse(File.read(CORPUS_PATH))
groups = corpus.fetch("testGroups")

CHANNELS.each do |channel|
  op = "#{channel}.body.decode"
  group = groups.find { |g| g["op"] == op }
  if group.nil?
    fail!("#{op}: op-group not found in corpus")
    next
  end
  ok, total = grade_group(channel, group)
  status = ok == total ? "ok  " : "FAIL"
  puts "#{status} - #{op}: #{ok}/#{total} vectors graded correctly"
end

puts "valid/acceptable decoded OK: #{$valid_pass}   MUST-reject rejected: #{$reject_pass}"
puts($failures.zero? ? "ALL PASS (8/8 channels)" : "FAILURES: #{$failures}")
exit($failures.zero? ? 0 : 1)

# frozen_string_literal: true

# Standards-derived, NON-CIRCULAR known-answer test for the draft-00 transcript construction
# (binding spec/10 section 3). Ruby mirror of the Go/Python/TS reference tests against the SAME
# pinned, FIPS-180-4-anchored vector (test-vectors/v1/transcript-kat.json).
#
# Three legs: ANCHOR (SHA-256("abc") == FIPS 180-4), ORACLE (in-test manual byte-constructor, no
# Transcript), IMPL (the real Npamp::Transcript). Run: ruby test/transcript_kat.rb
#
# Absorption is driven straight from the vector's frame/TLV order; the cut points are encoded as a
# (frame index, TLV index) map -> transcript-hash name, which IS the spec section 3 structure:
#   - SERVER_HELLO (frame 1) final TLV  -> th_kem
#   - SERVER_AUTH  (frame 2) TLV 0 / 1  -> th_sid / th_scv (th_scv excludes the frame's Finished TLV)
#   - CLIENT_AUTH  (frame 3) TLV 0 / 1  -> th_cid / th_ccv (th_ccv excludes the frame's Finished TLV)

require "json"
require "openssl"
require_relative "../lib/npamp"

VEC = File.expand_path("../../../test-vectors/v1", __dir__)
TRANSCRIPT_KAT_SHA256 = "fab6d852497b6ff56405595e9a014d0c45cabc5cde80a60a17444b337d556ee5"

# (frame index, TLV index within that frame) -> transcript-hash point name.
CUT_POINTS = { [1, 4] => "th_kem", [2, 0] => "th_sid", [2, 1] => "th_scv", [3, 0] => "th_cid", [3, 1] => "th_ccv" }.freeze
POINT_ORDER = %w[th_kem th_sid th_scv th_cid th_ccv].freeze

$failures = 0

def check(name, ok)
  if ok
    puts "PASS #{name}"
  else
    puts "FAIL #{name}"
    $failures += 1
  end
end

def load_kat
  raw = File.read(File.join(VEC, "transcript-kat.json"), mode: "rb")
  got = OpenSSL::Digest.new("SHA256").hexdigest(raw)
  raise "transcript KAT vector SHA-256 mismatch (swapped vector?): #{got}" unless got == TRANSCRIPT_KAT_SHA256

  JSON.parse(raw)
end

def trim_hex(str)
  str[0, 2].downcase == "0x" ? str[2..] : str
end

# Walk the vector frames/TLVs in order; snapshot at each spec section 3 cut point.
def drive(kat, add_frame_type, add_tlv, snap)
  points = {}
  kat["frames"].each_with_index do |frame, fi|
    add_frame_type.call(Integer(trim_hex(frame["frame_type"]), 16))
    frame["tlvs"].each_with_index do |tlv, ti|
      add_tlv.call(Integer(trim_hex(tlv["type"]), 16), [tlv["value"]].pack("H*").b)
      points[CUT_POINTS[[fi, ti]]] = snap.call if CUT_POINTS.key?([fi, ti])
    end
  end
  points
end

def check_points(leg, kat, points)
  exp = kat["expected_transcript_points"]
  ok = points.keys.sort == POINT_ORDER.sort
  check("transcript_#{leg}_cut_point_set", ok)
  POINT_ORDER.each do |name|
    check("transcript_#{leg}_#{name}", points[name] == exp[name])
  end
end

def test_fips180_anchor
  kat = load_kat
  fips = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
  ascii = kat["fips180_4_sha256_abc"]["input_ascii"]
  check("transcript_anchor_sha256_abc", OpenSSL::Digest.new("SHA256").hexdigest(ascii) == fips)
  check("transcript_anchor_vector_digest", kat["fips180_4_sha256_abc"]["digest"] == fips)
end

def test_oracle
  kat = load_kat
  buf = "".b
  add_frame_type = ->(v) { buf << [(v >> 8) & 0xFF, v & 0xFF].pack("C2").b }
  add_tlv = lambda do |type_, value|
    buf << [(type_ >> 8) & 0xFF, type_ & 0xFF].pack("C2").b
    buf << [(value.bytesize >> 8) & 0xFF, value.bytesize & 0xFF].pack("C2").b
    buf << value
  end
  snap = -> { OpenSSL::Digest.new("SHA256").hexdigest(buf) }
  check_points("oracle", kat, drive(kat, add_frame_type, add_tlv, snap))
end

def test_impl
  kat = load_kat
  constants_ok = [Npamp::FRAME_CLIENT_HELLO, Npamp::FRAME_SERVER_HELLO,
                  Npamp::FRAME_SERVER_AUTH, Npamp::FRAME_CLIENT_AUTH] == [0x0100, 0x0101, 0x0102, 0x0103]
  check("transcript_impl_frame_type_constants", constants_ok)
  tr = Npamp::Transcript.new
  add_frame_type = ->(v) { tr.add_frame_type(v) }
  add_tlv = ->(type_, value) { tr.add_tlv(type_, value) }
  snap = -> { Npamp.to_hex(tr.hash(true)) }
  check_points("impl", kat, drive(kat, add_frame_type, add_tlv, snap))
end

test_fips180_anchor
test_oracle
test_impl

puts($failures.zero? ? "ALL PASS" : "FAILURES: #{$failures}")
exit($failures.zero? ? 0 : 1)

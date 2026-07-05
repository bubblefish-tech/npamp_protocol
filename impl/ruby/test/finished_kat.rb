# frozen_string_literal: true

# Standards-derived, NON-CIRCULAR known-answer test for the draft-00 Finished verify_data
# (binding spec/10 section 6.2; RFC 8446 4.4.4): verify_data = HMAC(finished_key, transcript_hash)
# under the profile hash (SHA-256 at Standard). Ruby mirror of the Go/Python/TS reference tests
# against the SAME pinned vector (test-vectors/v1/finished-kat.json).
#
# Three legs: ANCHOR (HMAC-SHA-256 reproduces RFC 4231 TC1/TC2), ORACLE (independent OpenSSL::HMAC,
# no compute_finished), IMPL (compute_finished + verify_finished accept/reject). Run:
#   ruby test/finished_kat.rb

require "json"
require "openssl"
require_relative "../lib/npamp"

VEC = File.expand_path("../../../test-vectors/v1", __dir__)
FINISHED_KAT_SHA256 = "25c21b0bd3b3b6b77862f4a819f81ff5e4ff42e4b1d70af81feeedc5aad73c7f"

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
  raw = File.read(File.join(VEC, "finished-kat.json"), mode: "rb")
  got = OpenSSL::Digest.new("SHA256").hexdigest(raw)
  raise "Finished KAT vector SHA-256 mismatch (swapped vector?): #{got}" unless got == FINISHED_KAT_SHA256

  JSON.parse(raw)
end

def hx(str)
  [str].pack("H*").b
end

# Standard HMAC-SHA-256, independent of compute_finished.
def hmac_oracle(key, data)
  OpenSSL::HMAC.digest("SHA256", key, data)
end

def test_rfc4231_anchor
  kat = load_kat
  [["TC1", kat["rfc4231_hmac_sha256"]["tc1"]], ["TC2", kat["rfc4231_hmac_sha256"]["tc2"]]].each do |label, tc|
    got = Npamp.to_hex(hmac_oracle(hx(tc["key"]), hx(tc["data"])))
    check("finished_anchor_rfc4231_#{label}", got == tc["hmac_sha256"])
  end
end

def test_oracle
  kat = load_kat
  nn = kat["npamp_inputs"]
  exp = kat["expected"]
  check("finished_oracle_server",
        Npamp.to_hex(hmac_oracle(hx(nn["finished_key_server"]), hx(nn["th_scv"]))) == exp["verify_data_server"])
  check("finished_oracle_client",
        Npamp.to_hex(hmac_oracle(hx(nn["finished_key_client"]), hx(nn["th_ccv"]))) == exp["verify_data_client"])
end

def test_impl
  kat = load_kat
  nn = kat["npamp_inputs"]
  exp = kat["expected"]
  [
    ["server", nn["finished_key_server"], nn["th_scv"], exp["verify_data_server"]],
    ["client", nn["finished_key_client"], nn["th_ccv"], exp["verify_data_client"]]
  ].each do |name, fk, th, want|
    fkb = hx(fk)
    thb = hx(th)
    wantb = hx(want)
    check("finished_impl_#{name}_compute", Npamp.to_hex(Npamp.compute_finished(fkb, thb, true)) == want)
    check("finished_impl_#{name}_verify_accept", Npamp.verify_finished(fkb, thb, wantb, true))
    bad = wantb.dup
    bad.setbyte(0, bad.getbyte(0) ^ 0x01)
    check("finished_impl_#{name}_verify_reject_tamper", !Npamp.verify_finished(fkb, thb, bad, true))
  end
end

test_rfc4231_anchor
test_oracle
test_impl

puts($failures.zero? ? "ALL PASS" : "FAILURES: #{$failures}")
exit($failures.zero? ? 0 : 1)

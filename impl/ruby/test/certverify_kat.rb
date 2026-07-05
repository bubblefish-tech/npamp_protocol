# frozen_string_literal: true

# Standards-derived, NON-CIRCULAR known-answer test for the draft-00 CertVerify (binding spec/10
# section 6.1; RFC 8446 4.4.3 structure; Ed25519 per RFC 8032). The value is
# u16(0x0807) | Ed25519(priv, signing_input), signing_input = 64*0x20 | context | 0x00 | TH. Ruby
# mirror of the Go/Python/TS reference tests against the SAME pinned vector
# (test-vectors/v1/certverify-kat.json).
#
# Three legs: ANCHOR (the src Ed25519 helpers reproduce RFC 8032 TEST1/TEST2 keys + signatures),
# ORACLE (rebuild signing_input by hand + sign with an independently-constructed key, no src signing
# functions), IMPL (cert_verify_signing_input + sign_cert_verify reproduce the vector;
# verify_cert_verify accepts the correct value but rejects a role/context mismatch, a wrong
# transcript, a wrong scheme, and a truncated signature). Run: ruby test/certverify_kat.rb

require "json"
require "openssl"
require_relative "../lib/npamp"

VEC = File.expand_path("../../../test-vectors/v1", __dir__)
CERTVERIFY_KAT_SHA256 = "f56ec6ba250ba8f8c6c84214a16f580a3e476e9b2cfd05720c3352de299fe555"

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
  raw = File.read(File.join(VEC, "certverify-kat.json"), mode: "rb")
  got = OpenSSL::Digest.new("SHA256").hexdigest(raw)
  raise "CertVerify KAT vector SHA-256 mismatch (swapped vector?): #{got}" unless got == CERTVERIFY_KAT_SHA256

  JSON.parse(raw)
end

def hx(str)
  [str].pack("H*").b
end

# Oracle signing-input + key, independent of the src signing functions.
def oracle_priv(seed)
  OpenSSL::PKey.new_raw_private_key("ED25519", hx(seed))
end

def oracle_signing_input(ctx, th)
  ("\x20".b * 64) + ctx.b + "\x00".b + th
end

def test_rfc8032_anchor
  kat = load_kat
  [["TEST1", kat["rfc8032_ed25519"]["test1"]], ["TEST2", kat["rfc8032_ed25519"]["test2"]]].each do |label, v|
    priv = Npamp.ed25519_private_key_from_seed(hx(v["seed"]))
    check("certverify_anchor_#{label}_pubkey", Npamp.to_hex(priv.raw_public_key) == v["public_key"])
    check("certverify_anchor_#{label}_signature", Npamp.to_hex(priv.sign(nil, hx(v["message"]))) == v["signature"])
    # ed25519_public_key_from_raw round-trips for verification.
    pub = Npamp.ed25519_public_key_from_raw(hx(v["public_key"]))
    check("certverify_anchor_#{label}_verify", pub.verify(nil, hx(v["signature"]), hx(v["message"])))
  end
end

def test_oracle
  kat = load_kat
  nn = kat["npamp_inputs"]
  exp = kat["expected"]
  ctx = kat["contexts"]
  [
    ["server", ctx["server"], nn["server_seed"], nn["th_sid"], exp["signing_input_server"], exp["signature_server"]],
    ["client", ctx["client"], nn["client_seed"], nn["th_cid"], exp["signing_input_client"], exp["signature_client"]]
  ].each do |name, c, seed, th, want_si, want_sig|
    si = oracle_signing_input(c, hx(th))
    check("certverify_oracle_#{name}_signing_input", Npamp.to_hex(si) == want_si)
    check("certverify_oracle_#{name}_signature", Npamp.to_hex(oracle_priv(seed).sign(nil, si)) == want_sig)
  end
end

def test_impl
  kat = load_kat
  nn = kat["npamp_inputs"]
  exp = kat["expected"]
  ctx = kat["contexts"]
  check("certverify_impl_server_context_constant", Npamp::CONTEXT_SERVER_CERTVERIFY == ctx["server"])
  check("certverify_impl_client_context_constant", Npamp::CONTEXT_CLIENT_CERTVERIFY == ctx["client"])
  [
    ["server", true, nn["server_seed"], nn["server_pub"], nn["th_sid"], exp["signing_input_server"], exp["certverify_value_server"]],
    ["client", false, nn["client_seed"], nn["client_pub"], nn["th_cid"], exp["signing_input_client"], exp["certverify_value_client"]]
  ].each do |name, is_server, seed, pub_hex, th, want_si, want_val|
    priv = Npamp.ed25519_private_key_from_seed(hx(seed))
    pub = Npamp.ed25519_public_key_from_raw(hx(pub_hex))
    thb = hx(th)

    check("certverify_impl_#{name}_signing_input", Npamp.to_hex(Npamp.cert_verify_signing_input(is_server, thb)) == want_si)
    val = Npamp.sign_cert_verify(priv, is_server, thb)
    check("certverify_impl_#{name}_value", Npamp.to_hex(val) == want_val)

    check("certverify_impl_#{name}_verify_accept", Npamp.verify_cert_verify(pub, is_server, thb, val))
    # Domain separation: the opposite role must FAIL (different context string).
    check("certverify_impl_#{name}_reject_role_mismatch", !Npamp.verify_cert_verify(pub, !is_server, thb, val))
    # Transcript binding: a different transcript hash must FAIL.
    wrong = thb.dup
    wrong.setbyte(0, wrong.getbyte(0) ^ 0x01)
    check("certverify_impl_#{name}_reject_wrong_transcript", !Npamp.verify_cert_verify(pub, is_server, wrong, val))
    # Scheme guard: a non-Ed25519 scheme code point must FAIL.
    bad_scheme = val.dup
    bad_scheme[0, 2] = Npamp.uint_to_be(Npamp::SIG_MLDSA87, 2)
    check("certverify_impl_#{name}_reject_wrong_scheme", !Npamp.verify_cert_verify(pub, is_server, thb, bad_scheme))
    # Length guard: an Ed25519 signature is exactly 64 octets; a truncated value must FAIL.
    truncated = val[0, val.bytesize - 1]
    check("certverify_impl_#{name}_reject_truncated", !Npamp.verify_cert_verify(pub, is_server, thb, truncated))
  end
end

test_rfc8032_anchor
test_oracle
test_impl

puts($failures.zero? ? "ALL PASS" : "FAILURES: #{$failures}")
exit($failures.zero? ? 0 : 1)

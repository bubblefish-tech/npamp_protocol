# frozen_string_literal: true

# Standards-derived, NON-CIRCULAR known-answer test for the draft-00 key schedule
# (binding spec/10 section 5; draft-00 section 7.4 HKDF-Expand-Label + section 7.5 traffic keys).
# Ruby mirror of the Go/Python/TS reference tests against the SAME pinned vector
# (test-vectors/v1/key-schedule-kat.json). The vector stores NO N-PAMP output bytes (storing them
# would be circular); it stores external RFC anchors and fixed inputs only.
#
# Four legs:
#   ANCHOR  - raw HKDF-Extract/Expand reproduce RFC 5869 Appendix A.1 TC1 (impl primitives AND the
#             in-test oracle primitives), so the oracle's HKDF is itself anchored before use.
#   ORACLE  - an INDEPENDENT in-test HKDF-Expand-Label (prefix is a PARAMETER; it rebuilds the
#             HkdfLabel bytes from RFC 8446 section 7.1 and runs its own HKDF-Expand, never calling
#             the impl) reproduces RFC 8448 section 3 with the "tls13 " prefix: key/iv/finished.
#   IMPL    - the real Npamp key-schedule functions equal the PROVEN oracle applied with the
#             "n-pamp " prefix: handshake_secret ladder (c_hs/s_hs/master), finished_key, and the
#             s2c handshake AEAD key/iv via derive_traffic_secret/derive_key_iv.
# The test computes the golden N-PAMP outputs via the proven oracle; it does NOT hardcode them.
# Run: ruby test/key_schedule_kat.rb

require "json"
require "openssl"
require_relative "../lib/npamp"

VEC = File.expand_path("../../../test-vectors/v1", __dir__)
KEY_SCHEDULE_KAT_SHA256 = "e108f5cfdf99a378d7b677792448c8046abf3c630fc23fd8ea2ccb3927f2691c"

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
  raw = File.read(File.join(VEC, "key-schedule-kat.json"), mode: "rb")
  got = OpenSSL::Digest.new("SHA256").hexdigest(raw)
  raise "key-schedule KAT vector SHA-256 mismatch (swapped vector?): #{got}" unless got == KEY_SCHEDULE_KAT_SHA256

  JSON.parse(raw)
end

def hx(str)
  [str].pack("H*").b
end

# ---------------------------------------------------------------------------
# Independent in-test oracle. These reimplement RFC 5869 HKDF and RFC 8446
# section 7.1 HKDF-Expand-Label from the spec text with OpenSSL::HMAC only; they
# do NOT call Npamp.hkdf_expand / Npamp.hkdf_expand_label, so the oracle and the
# impl must agree independently (non-circularity). SHA-256 only (Standard profile).
# ---------------------------------------------------------------------------

# RFC 5869 section 2.2: PRK = HMAC-Hash(salt, IKM).
def oracle_hkdf_extract(salt, ikm)
  OpenSSL::HMAC.digest("SHA256", salt, ikm)
end

# RFC 5869 section 2.3: T(0)="", T(i)=HMAC(PRK, T(i-1)||info||i); OKM = first L octets.
def oracle_hkdf_expand(prk, info, length)
  out = "".b
  t = "".b
  counter = 1
  while out.bytesize < length
    t = OpenSSL::HMAC.digest("SHA256", prk, t + info + [counter].pack("C").b)
    out << t
    counter += 1
  end
  out[0, length]
end

# RFC 8446 section 7.1: HkdfLabel = uint16(length) || uint8(len(prefix+label)) ||
# (prefix+label) || uint8(len(context)) || context. The prefix is a PARAMETER so the
# same oracle proves the "tls13 " construction (RFC 8448) and judges the "n-pamp " one.
def oracle_expand_label(secret, prefix, label, context, length)
  full = (prefix + label).b
  context = context.b
  info = [length].pack("n").b
  info << [full.bytesize].pack("C").b
  info << full
  info << [context.bytesize].pack("C").b
  info << context
  oracle_hkdf_expand(secret.b, info, length)
end

# ANCHOR: raw HKDF-Extract/Expand reproduce RFC 5869 TC1 - for the impl primitives
# AND the in-test oracle primitives, so the oracle's HKDF is anchored before leg C/D use it.
def test_rfc5869_anchor
  kat = load_kat
  tc = kat["rfc5869_tc1"]
  salt = hx(tc["salt"])
  ikm = hx(tc["ikm"])
  info = hx(tc["info"])
  l = tc["L"]
  prk = tc["prk"]
  okm = tc["okm"]

  check("ks_anchor_impl_extract", Npamp.to_hex(Npamp.hkdf_extract(salt, ikm, true)) == prk)
  check("ks_anchor_impl_expand", Npamp.to_hex(Npamp.hkdf_expand(hx(prk), info, l, OpenSSL::Digest.new("SHA256"))) == okm)
  check("ks_anchor_oracle_extract", Npamp.to_hex(oracle_hkdf_extract(salt, ikm)) == prk)
  check("ks_anchor_oracle_expand", Npamp.to_hex(oracle_hkdf_expand(hx(prk), info, l)) == okm)
end

# ORACLE: the independent HKDF-Expand-Label reproduces RFC 8448 (tls13 prefix).
def test_oracle_rfc8448
  kat = load_kat
  v = kat["rfc8448_expand_label"]
  secret = hx(v["client_handshake_traffic_secret"])
  check("ks_oracle_rfc8448_key", Npamp.to_hex(oracle_expand_label(secret, "tls13 ", "key", "".b, 16)) == v["write_key"])
  check("ks_oracle_rfc8448_iv", Npamp.to_hex(oracle_expand_label(secret, "tls13 ", "iv", "".b, 12)) == v["write_iv"])
  check("ks_oracle_rfc8448_finished", Npamp.to_hex(oracle_expand_label(secret, "tls13 ", "finished", "".b, 32)) == v["finished_key"])
end

# IMPL: the real Npamp key schedule equals the proven oracle applied with the "n-pamp " prefix.
def test_impl
  kat = load_kat
  nn = kat["npamp_inputs"]
  pfx = nn["label_prefix"] # "n-pamp "
  check("ks_impl_label_prefix_constant", Npamp::LABEL_PREFIX == pfx)

  mlkem_ss = hx(nn["ikm_mlkem_ss"]) # ML-KEM shared secret (IKM, concatenated first per ADR-0005)
  x25519_ss = hx(nn["ikm_x25519_ss"]) # X25519 shared secret (IKM, concatenated second)
  th_kem = hx(nn["th_kem"])
  th_ccv = hx(nn["th_ccv"])
  zeros32 = "\x00".b * 32

  # handshake_secret = HKDF-Extract(32 zero octets, ML-KEM_SS || X25519_SS).
  hs = Npamp.derive_handshake_secret(mlkem_ss, x25519_ss, true)
  check("ks_impl_handshake_secret", hs == oracle_hkdf_extract(zeros32, mlkem_ss + x25519_ss))

  c_hs = Npamp.derive_client_handshake_secret(hs, th_kem, true)
  check("ks_impl_c_hs", c_hs == oracle_expand_label(hs, pfx, "c hs", th_kem, 32))

  s_hs = Npamp.derive_server_handshake_secret(hs, th_kem, true)
  check("ks_impl_s_hs", s_hs == oracle_expand_label(hs, pfx, "s hs", th_kem, 32))

  master = Npamp.derive_master_secret(hs, th_ccv, true)
  check("ks_impl_master", master == oracle_expand_label(hs, pfx, "master", th_ccv, 32))

  # finished_key: client from c_hs, server from s_hs; empty context.
  check("ks_impl_finished_key_client",
        Npamp.derive_finished_key(c_hs, true) == oracle_expand_label(c_hs, pfx, "finished", "".b, 32))
  check("ks_impl_finished_key_server",
        Npamp.derive_finished_key(s_hs, true) == oracle_expand_label(s_hs, pfx, "finished", "".b, 32))

  # s2c handshake AEAD from s_hs: dir=ServerToClient=1, epoch=0,
  # suite=AES-256-GCM=0x0001 per registries/aead.csv (= the impl's AEAD_AES256_GCM =
  # npamp.AEADAES256GCM in the Go reference); 0x0002 is ChaCha20-Poly1305. The section 7.5
  # traffic context binds this AEAD code point. channel=Control=0x0000.
  dir = 1
  epoch = 0
  suite = Npamp::AEAD_AES256_GCM
  channel = Npamp::CHAN_CONTROL
  ts = Npamp.derive_traffic_secret(s_hs, dir, epoch, suite, channel, true)
  key, iv = Npamp.derive_key_iv(ts, true)

  # Oracle traffic context: dir(1) || epoch(8 BE) || suite(2 BE) || channel(2 BE).
  ctx = [dir].pack("C").b + [epoch].pack("Q>").b + [suite].pack("n").b + [channel].pack("n").b
  ts_oracle = oracle_expand_label(s_hs, pfx, "traffic", ctx, 32)
  check("ks_impl_s2c_traffic_secret", ts == ts_oracle)
  check("ks_impl_s2c_key", key == oracle_expand_label(ts_oracle, pfx, "key", "".b, 32))
  check("ks_impl_s2c_iv", iv == oracle_expand_label(ts_oracle, pfx, "iv", "".b, 12))
end

test_rfc5869_anchor
test_oracle_rfc8448
test_impl

puts($failures.zero? ? "ALL PASS" : "FAILURES: #{$failures}")
exit($failures.zero? ? 0 : 1)

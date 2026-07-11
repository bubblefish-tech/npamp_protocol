# frozen_string_literal: true

# Byte-pinned handshake-flow KAT (issue #60, class golden-interop). Unlike the standards-anchored
# primitive KATs, this vector pins the Go reference's SERIALIZED handshake artifacts so every
# language impl reproduces them byte-for-byte. The CLIENT_HELLO whole-frame assertion is the one
# that catches draft-00-vs-draft-01 wire drift (e.g. a fixed 4-octet ProfileOffer vs the draft-01
# one-octet form). Ruby mirror of impl/go/handshakeflow_kat_test.go against the SAME pinned vector
# (test-vectors/v1/handshake-flow-kat.json).
#
# Legs:
#   KEM  - self-validating input: decapsulate the pinned ML-KEM-768 ciphertext under the pinned
#          d||z seed and recover mlkem_shared_secret; run X25519 with the pinned privates and recover
#          x25519_shared_secret; rebuild kem_share (ek||client_pub) and kem_ciphertext (ct||server_pub)
#          and assert byte-equality. ML-KEM has no encap/decap surface in Ruby's OpenSSL binding, so
#          the decapsulation and the encapsulation-key extraction run through the system `openssl`
#          CLI (OpenSSL 3.5+, real ML-KEM). If no ML-KEM-capable openssl is found the KEM leg SKIPS
#          honestly rather than fabricating a pass.
#   FRAMES - rebuild CLIENT_HELLO/SERVER_HELLO/SERVER_AUTH/CLIENT_AUTH and the two AUTH plaintexts
#          through the real Npamp code path (TLV encode, Frame#marshal, seal_aes256gcm) and assert
#          WHOLE-frame byte-equality.
#   LADDER - drive the real Npamp::Transcript + key schedule (handshake_secret ladder, c_hs/s_hs,
#          master, finished keys, traffic secret/key/iv for c_hs/s_hs/app_c2s/app_s2c) and the real
#          CertVerify/Finished, asserting every transcript point, secret, key, iv, and MAC.
#   GUARD - a one-octet flip of the server CertVerify signature AND of the client Finished MAC must
#          REJECT; the untouched values must still verify.
#
# Run: ruby test/handshake_flow_kat.rb

require "json"
require "openssl"
require "open3"
require "tmpdir"
require_relative "../lib/npamp"

VEC = File.expand_path("../../../test-vectors/v1", __dir__)
HANDSHAKE_FLOW_KAT_SHA256 = "cf1d3c1fba550f3742e4de16d0f86d3beeafeb56efff90f85ff16165063c0fc9"

# ML-KEM-768 wire sizes (FIPS 203): ciphertext 1088, encapsulation key 1184.
MLKEM768_CIPHERTEXT_SIZE = 1088
MLKEM768_EK_SIZE = 1184

$failures = 0
$skips = 0

def check(name, ok)
  if ok
    puts "PASS #{name}"
  else
    puts "FAIL #{name}"
    $failures += 1
  end
end

def skip(name, reason)
  puts "SKIP #{name} (#{reason})"
  $skips += 1
end

def load_kat
  raw = File.read(File.join(VEC, "handshake-flow-kat.json"), mode: "rb")
  got = OpenSSL::Digest.new("SHA256").hexdigest(raw)
  raise "handshake-flow KAT vector SHA-256 mismatch (swapped vector?): #{got}" unless got == HANDSHAKE_FLOW_KAT_SHA256

  JSON.parse(raw)
end

def hx(str)
  [str].pack("H*").b
end

# ---------------------------------------------------------------------------
# ML-KEM-768 via the system `openssl` CLI. Ruby's OpenSSL binding (OpenSSL::PKey)
# exposes no KEM encapsulate/decapsulate methods and cannot build an ML-KEM key
# from its 64-octet d||z seed, so this leg shells out to a real OpenSSL 3.5+ CLI.
# The operations are genuine crypto (seed -> keygen -> decapsulate / pubkey), not
# an echo of the expected bytes: a wrong seed or ciphertext yields a wrong secret.
# ---------------------------------------------------------------------------

def find_mlkem_openssl
  %w[openssl].each do |cmd|
    out, status = Open3.capture2e(cmd, "list", "-kem-algorithms")
    return cmd if status.success? && out.downcase.include?("ml-kem-768")
  rescue Errno::ENOENT, Errno::EACCES
    next
  end
  nil
end

# Recover the ML-KEM-768 shared secret by decapsulating `ct` (1088 octets) under
# the d||z `seed_hex`, through the real openssl KEM path.
def mlkem_decapsulate(openssl, seed_hex, ct)
  Dir.mktmpdir do |d|
    priv = File.join(d, "priv.pem")
    ctf = File.join(d, "ct.bin")
    ssf = File.join(d, "ss.bin")
    out, st = Open3.capture2e(openssl, "genpkey", "-algorithm", "ML-KEM-768",
                              "-pkeyopt", "hexseed:#{seed_hex}", "-out", priv)
    raise "openssl genpkey failed: #{out}" unless st.success?

    File.binwrite(ctf, ct)
    out, st = Open3.capture2e(openssl, "pkeyutl", "-decap", "-inkey", priv, "-in", ctf, "-out", ssf)
    raise "openssl pkeyutl -decap failed: #{out}" unless st.success?

    File.binread(ssf)
  end
end

# Extract the raw 1184-octet ML-KEM-768 encapsulation (public) key built from the
# d||z `seed_hex`. The DER SubjectPublicKeyInfo wraps the raw key; the raw ek is
# its final MLKEM768_EK_SIZE octets.
def mlkem_encapsulation_key(openssl, seed_hex)
  Dir.mktmpdir do |d|
    priv = File.join(d, "priv.pem")
    der = File.join(d, "pub.der")
    out, st = Open3.capture2e(openssl, "genpkey", "-algorithm", "ML-KEM-768",
                              "-pkeyopt", "hexseed:#{seed_hex}", "-out", priv)
    raise "openssl genpkey failed: #{out}" unless st.success?

    out, st = Open3.capture2e(openssl, "pkey", "-in", priv, "-pubout", "-outform", "DER", "-out", der)
    raise "openssl pkey -pubout failed: #{out}" unless st.success?

    File.binread(der)[-MLKEM768_EK_SIZE, MLKEM768_EK_SIZE]
  end
end

# ---------------------------------------------------------------------------
# Wire helpers (canonical TLV Type(2)||Length(2)||Value; cleartext + sealed frames).
# ---------------------------------------------------------------------------

def tlv(type_, value)
  value = value.b
  Npamp.uint_to_be(type_, 2) + Npamp.uint_to_be(value.bytesize, 2) + value
end

# CLIENT_HELLO / SERVER_HELLO are cleartext frames on the Control channel, seq 0.
def cleartext_frame(ftype, payload)
  f = Npamp::Frame.new(ftype: ftype, channel: Npamp::CHAN_CONTROL, seq: 0)
  f.payload = payload
  f.marshal
end

# SERVER_AUTH / CLIENT_AUTH are AEAD-sealed under the per-direction handshake
# traffic key derived from the c_hs/s_hs handshake secret (FLAG_ENC, Control, seq 0).
# The AAD is the 21-octet header prefix over the SEALED payload length (pt + 16 tag).
def seal_auth_frame(ftype, base_secret, direction, plaintext)
  ts = Npamp.derive_traffic_secret(base_secret, direction, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_CONTROL, true)
  key, iv = Npamp.derive_key_iv(ts, true)
  f = Npamp::Frame.new(flags: Npamp::FLAG_ENC, ftype: ftype, channel: Npamp::CHAN_CONTROL, seq: 0)
  aad = f.header_prefix(plaintext.bytesize + 16)
  f.payload = Npamp.seal_aes256gcm(key, iv, 0, aad, plaintext)
  f.marshal
end

def assert_hex(name, got, want_hex)
  check(name, Npamp.to_hex(got) == want_hex)
end

# Direction constants (draft-00 7.5 traffic context): client->server=0, server->client=1.
DIR_C2S = 0
DIR_S2C = 1

# ---------------------------------------------------------------------------
# The flow. Returns the derived material the mutation-guard leg reuses.
# ---------------------------------------------------------------------------

def run_flow # rubocop:disable Metrics/AbcSize, Metrics/MethodLength
  kat = load_kat
  inp = kat["inputs"]
  exp = kat["expected"]

  client_x25519_priv = OpenSSL::PKey.new_raw_private_key("X25519", hx(inp["client_x25519_private"]))
  server_x25519_priv = OpenSSL::PKey.new_raw_private_key("X25519", hx(inp["server_x25519_private"]))
  client_x25519_pub = client_x25519_priv.raw_public_key
  server_x25519_pub = server_x25519_priv.raw_public_key

  # --- KEM leg: self-validating pinned ML-KEM ciphertext + X25519. ---
  openssl = find_mlkem_openssl
  mlkem_ct = hx(inp["mlkem_ciphertext"])
  check("kem_mlkem_ciphertext_size", mlkem_ct.bytesize == MLKEM768_CIPHERTEXT_SIZE)

  # The pinned kem_ciphertext = ML-KEM ciphertext (1088) || server X25519 public (32).
  kem_ciphertext = mlkem_ct + server_x25519_pub
  check("kem_ciphertext_frame_bytes", Npamp.to_hex(kem_ciphertext) == exp["kem"]["kem_ciphertext"])
  check("kem_ciphertext_front_is_pinned_mlkem_ct",
        kem_ciphertext[0, MLKEM768_CIPHERTEXT_SIZE] == mlkem_ct)

  # X25519 shared secret through the real Ruby OpenSSL ECDH path.
  x25519_ss = client_x25519_priv.derive(OpenSSL::PKey.new_raw_public_key("X25519", server_x25519_pub))
  check("kem_x25519_shared_secret", Npamp.to_hex(x25519_ss) == inp["x25519_shared_secret"])

  if openssl
    mlkem_ss = mlkem_decapsulate(openssl, inp["mlkem768_seed_dz"], mlkem_ct)
    check("kem_mlkem_decapsulate_recovers_shared_secret",
          Npamp.to_hex(mlkem_ss) == inp["mlkem_shared_secret"])
    ek = mlkem_encapsulation_key(openssl, inp["mlkem768_seed_dz"])
    kem_share = ek + client_x25519_pub
    check("kem_share_frame_bytes", Npamp.to_hex(kem_share) == exp["kem"]["kem_share"])
  else
    skip("kem_mlkem_decapsulate_recovers_shared_secret", "no ML-KEM-capable openssl CLI found")
    skip("kem_share_frame_bytes", "no ML-KEM-capable openssl CLI found")
    # Fall back to the pinned values for the downstream frame/ladder legs so the
    # rest of the flow is still exercised (the ML-KEM secret is self-validated above
    # only when a CLI is present).
    mlkem_ss = hx(inp["mlkem_shared_secret"])
    kem_share = hx(exp["kem"]["kem_share"])
  end

  # --- FRAMES leg: CLIENT_HELLO / SERVER_HELLO whole-frame byte-equality. ---
  ch_payload = tlv(Npamp::TLV_PROFILE_OFFER, [0x01].pack("C")) + # ProfileStandard = 0x01 (one octet)
               tlv(0x03, Npamp.uint_to_be(Npamp::KEM_X25519_MLKEM768, 2)) +
               tlv(0x05, Npamp.uint_to_be(Npamp::SIG_ED25519, 2)) +
               tlv(0x0C, Npamp.uint_to_be(Npamp::AEAD_AES256_GCM, 2)) +
               tlv(0x07, kem_share)
  ch_frame = cleartext_frame(Npamp::FRAME_CLIENT_HELLO, ch_payload)
  check("frame_client_hello", Npamp.to_hex(ch_frame) == exp["frames"]["client_hello"])

  sh_payload = tlv(0x02, [0x01].pack("C")) +
               tlv(0x04, Npamp.uint_to_be(Npamp::KEM_X25519_MLKEM768, 2)) +
               tlv(0x06, Npamp.uint_to_be(Npamp::SIG_ED25519, 2)) +
               tlv(0x0D, Npamp.uint_to_be(Npamp::AEAD_AES256_GCM, 2)) +
               tlv(0x08, kem_ciphertext)
  sh_frame = cleartext_frame(Npamp::FRAME_SERVER_HELLO, sh_payload)
  check("frame_server_hello", Npamp.to_hex(sh_frame) == exp["frames"]["server_hello"])

  # --- LADDER leg: transcript + key schedule + CertVerify/Finished. ---
  tr = Npamp::Transcript.new
  tr.add_frame_type(Npamp::FRAME_CLIENT_HELLO)
  tr.add_tlv(Npamp::TLV_PROFILE_OFFER, [0x01].pack("C"))
  tr.add_tlv(0x03, Npamp.uint_to_be(Npamp::KEM_X25519_MLKEM768, 2))
  tr.add_tlv(0x05, Npamp.uint_to_be(Npamp::SIG_ED25519, 2))
  tr.add_tlv(0x0C, Npamp.uint_to_be(Npamp::AEAD_AES256_GCM, 2))
  tr.add_tlv(0x07, kem_share)
  tr.add_frame_type(Npamp::FRAME_SERVER_HELLO)
  tr.add_tlv(0x02, [0x01].pack("C"))
  tr.add_tlv(0x04, Npamp.uint_to_be(Npamp::KEM_X25519_MLKEM768, 2))
  tr.add_tlv(0x06, Npamp.uint_to_be(Npamp::SIG_ED25519, 2))
  tr.add_tlv(0x0D, Npamp.uint_to_be(Npamp::AEAD_AES256_GCM, 2))
  tr.add_tlv(0x08, kem_ciphertext)
  th_kem = tr.hash(true)
  assert_hex("transcript_th_kem", th_kem, exp["transcript"]["th_kem"])

  hs = Npamp.derive_handshake_secret(mlkem_ss, x25519_ss, true)
  assert_hex("secret_handshake_secret", hs, exp["secrets"]["handshake_secret"])
  c_hs = Npamp.derive_client_handshake_secret(hs, th_kem, true)
  s_hs = Npamp.derive_server_handshake_secret(hs, th_kem, true)
  assert_hex("secret_c_hs", c_hs, exp["secrets"]["c_hs_secret"])
  assert_hex("secret_s_hs", s_hs, exp["secrets"]["s_hs_secret"])

  server_ed = Npamp.ed25519_private_key_from_seed(hx(inp["server_identity_ed25519_seed"]))
  client_ed = Npamp.ed25519_private_key_from_seed(hx(inp["client_identity_ed25519_seed"]))
  server_pub = server_ed.raw_public_key
  client_pub = client_ed.raw_public_key

  # SERVER_AUTH.
  tr.add_frame_type(Npamp::FRAME_SERVER_AUTH)
  tr.add_tlv(0x09, server_pub)
  th_sid = tr.hash(true)
  assert_hex("transcript_th_sid", th_sid, exp["transcript"]["th_sid"])
  s_cv = Npamp.sign_cert_verify(server_ed, true, th_sid)
  assert_hex("cert_verify_server", s_cv, exp["cert_verify"]["server"])
  check("cert_verify_server_accepts",
        Npamp.verify_cert_verify(Npamp.ed25519_public_key_from_raw(server_pub), true, th_sid, s_cv))
  tr.add_tlv(0x0A, s_cv)
  th_scv = tr.hash(true)
  assert_hex("transcript_th_scv", th_scv, exp["transcript"]["th_scv"])
  s_fin_key = Npamp.derive_finished_key(s_hs, true)
  assert_hex("finished_key_server", s_fin_key, exp["finished_keys"]["server"])
  s_fin = Npamp.compute_finished(s_fin_key, th_scv, true)
  assert_hex("finished_server", s_fin, exp["finished"]["server"])
  tr.add_tlv(0x0B, s_fin)
  server_auth_plain = tlv(0x09, server_pub) + tlv(0x0A, s_cv) + tlv(0x0B, s_fin)
  check("auth_plaintext_server", Npamp.to_hex(server_auth_plain) == exp["auth_plaintext"]["server_auth"])
  server_auth_frame = seal_auth_frame(Npamp::FRAME_SERVER_AUTH, s_hs, DIR_S2C, server_auth_plain)
  check("frame_server_auth", Npamp.to_hex(server_auth_frame) == exp["frames"]["server_auth"])

  # CLIENT_AUTH.
  tr.add_frame_type(Npamp::FRAME_CLIENT_AUTH)
  tr.add_tlv(0x09, client_pub)
  th_cid = tr.hash(true)
  assert_hex("transcript_th_cid", th_cid, exp["transcript"]["th_cid"])
  c_cv = Npamp.sign_cert_verify(client_ed, false, th_cid)
  assert_hex("cert_verify_client", c_cv, exp["cert_verify"]["client"])
  check("cert_verify_client_accepts",
        Npamp.verify_cert_verify(Npamp.ed25519_public_key_from_raw(client_pub), false, th_cid, c_cv))
  tr.add_tlv(0x0A, c_cv)
  th_ccv = tr.hash(true)
  assert_hex("transcript_th_ccv", th_ccv, exp["transcript"]["th_ccv"])
  c_fin_key = Npamp.derive_finished_key(c_hs, true)
  assert_hex("finished_key_client", c_fin_key, exp["finished_keys"]["client"])
  c_fin = Npamp.compute_finished(c_fin_key, th_ccv, true)
  assert_hex("finished_client", c_fin, exp["finished"]["client"])
  client_auth_plain = tlv(0x09, client_pub) + tlv(0x0A, c_cv) + tlv(0x0B, c_fin)
  check("auth_plaintext_client", Npamp.to_hex(client_auth_plain) == exp["auth_plaintext"]["client_auth"])
  client_auth_frame = seal_auth_frame(Npamp::FRAME_CLIENT_AUTH, c_hs, DIR_C2S, client_auth_plain)
  check("frame_client_auth", Npamp.to_hex(client_auth_frame) == exp["frames"]["client_auth"])

  master = Npamp.derive_master_secret(hs, th_ccv, true)
  assert_hex("secret_master", master, exp["secrets"]["master_secret"])

  # Traffic secret/key/iv for each phase.
  [
    ["c_hs", c_hs, DIR_C2S],
    ["s_hs", s_hs, DIR_S2C],
    ["app_c2s", master, DIR_C2S],
    ["app_s2c", master, DIR_S2C]
  ].each do |name, parent, dir|
    ts = Npamp.derive_traffic_secret(parent, dir, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_CONTROL, true)
    key, iv = Npamp.derive_key_iv(ts, true)
    assert_hex("secret_#{name}_traffic_secret", ts, exp["secrets"]["#{name}_traffic_secret"])
    assert_hex("secret_#{name}_key", key, exp["secrets"]["#{name}_key"])
    assert_hex("secret_#{name}_iv", iv, exp["secrets"]["#{name}_iv"])
  end

  { server_pub: server_pub, th_sid: th_sid, s_cv: s_cv,
    c_fin_key: c_fin_key, th_ccv: th_ccv, c_fin: c_fin }
end

# --- GUARD leg: a one-octet flip in the server CertVerify signature AND in the
# client Finished MAC must REJECT; the untouched values must still verify. ---
def run_mutation_guards(m)
  server_pub_key = Npamp.ed25519_public_key_from_raw(m[:server_pub])

  bad_cv = m[:s_cv].dup
  bad_cv.setbyte(bad_cv.bytesize - 1, bad_cv.getbyte(bad_cv.bytesize - 1) ^ 0x01)
  check("guard_server_certverify_flip_rejects",
        !Npamp.verify_cert_verify(server_pub_key, true, m[:th_sid], bad_cv))

  bad_fin = m[:c_fin].dup
  bad_fin.setbyte(0, bad_fin.getbyte(0) ^ 0x01)
  check("guard_client_finished_flip_rejects",
        !Npamp.verify_finished(m[:c_fin_key], m[:th_ccv], bad_fin, true))

  # Sanity: the untouched signature and MAC still verify.
  check("guard_unmutated_server_certverify_accepts",
        Npamp.verify_cert_verify(server_pub_key, true, m[:th_sid], m[:s_cv]))
  check("guard_unmutated_client_finished_accepts",
        Npamp.verify_finished(m[:c_fin_key], m[:th_ccv], m[:c_fin], true))
end

material = run_flow
run_mutation_guards(material)

if $failures.zero?
  puts($skips.zero? ? "ALL PASS" : "ALL PASS (#{$skips} skipped: no ML-KEM openssl CLI)")
  exit 0
else
  puts "FAILURES: #{$failures}"
  exit 1
end

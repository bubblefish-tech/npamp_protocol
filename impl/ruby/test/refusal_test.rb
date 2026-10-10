# frozen_string_literal: true

# Behaviour check, not a conformance vector: the open Ruby module implements the Standard
# profile only, so every key-schedule, transcript and Finished primitive refuses a non-Standard
# profile with Npamp::NoSuiteForProfile and still succeeds at Standard. No external authority
# (RFC or FIPS) defines this module's scope. Prints one line per check and exits 1 on failure.

require_relative "../lib/npamp"

$failures = 0

def check(name, ok)
  if ok
    puts "PASS #{name}"
  else
    puts "FAIL #{name}"
    $failures += 1
  end
end

def refused(name)
  threw = false
  begin
    yield
  rescue Npamp::NoSuiteForProfile
    threw = true
  rescue StandardError => e
    puts "     wrong exception for #{name}: #{e.class}"
  end
  check("non-standard refused: #{name}", threw)
end

secret = "\x11".b * 32
th = "\x22".b * 32

check("standard control: hkdf_extract", Npamp.hkdf_extract("\x00".b * 32, secret, true).bytesize == 32)
check("standard control: derive_traffic_secret",
      Npamp.derive_traffic_secret(secret, 0, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_CONTROL, true).bytesize == 32)
key, iv = Npamp.derive_key_iv(secret, true)
check("standard control: derive_key_iv", key.bytesize == 32 && iv.bytesize == 12)
check("standard control: derive_handshake_secret", Npamp.derive_handshake_secret(secret, secret, true).bytesize == 32)
check("standard control: derive_finished_key", Npamp.derive_finished_key(secret, true).bytesize == 32)
check("standard control: transcript hash", Npamp::Transcript.new.hash(true).bytesize == 32)
mac = Npamp.compute_finished(secret, th, true)
check("standard control: finished verifies", Npamp.verify_finished(secret, th, mac, true))

refused("hkdf_extract") { Npamp.hkdf_extract("\x00".b * 48, secret, false) }
refused("hkdf_expand sha512") { Npamp.hkdf_expand(secret, "info".b, 48, OpenSSL::Digest.new("SHA512")) }
refused("hkdf_expand_label") { Npamp.hkdf_expand_label(secret, "key", "".b, 32, false) }
refused("derive_traffic_secret") do
  Npamp.derive_traffic_secret(secret, 0, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_CONTROL, false)
end
refused("derive_key_iv") { Npamp.derive_key_iv(secret, false) }
refused("derive_handshake_secret") { Npamp.derive_handshake_secret(secret, secret, false) }
refused("derive_client_handshake_secret") { Npamp.derive_client_handshake_secret(secret, th, false) }
refused("derive_server_handshake_secret") { Npamp.derive_server_handshake_secret(secret, th, false) }
refused("derive_master_secret") { Npamp.derive_master_secret(secret, th, false) }
refused("derive_finished_key") { Npamp.derive_finished_key(secret, false) }
refused("Transcript#hash") { Npamp::Transcript.new.hash(false) }
refused("compute_finished") { Npamp.compute_finished(secret, th, false) }
refused("verify_finished") { Npamp.verify_finished(secret, th, th, false) }

puts($failures.zero? ? "ALL PASS" : "FAILURES: #{$failures}")
exit($failures.zero? ? 0 : 1)

# frozen_string_literal: true

# Independent crypto KAT: drive N-PAMP's AES-256-GCM seal/open through Google
# Project Wycheproof vectors (C2SP/wycheproof), via the dependency-free flat
# corpus _shared/wycheproof/aesgcm_kat.tsv (keySize=256, ivSize=96, tagSize=128).
#
# These vectors are authored by an independent authority and encode KNOWN ATTACKS
# (truncated tags, modified ciphertext) that our self-generated golden vectors
# never include -- so a shared bug between our impls cannot pass them.
#
# Trick: seal_aes256gcm(key, iv, seq, ...) derives nonce = iv XOR (0^4||seq); with
# seq == 0 the nonce IS the given IV, so each vector exercises the REAL seal/open
# path.
#
# Exit 0 iff every vector behaves exactly as Wycheproof labels it.

require_relative "../lib/npamp"

def main
  tsv_path = ARGV[0]
  if tsv_path.nil? || tsv_path.empty?
    warn "usage: ruby kat_aesgcm.rb <path-to-aesgcm_kat.tsv>"
    return 1
  end

  total = 0
  passed = 0
  fails = []

  File.read(tsv_path, mode: "rb").split("\n").each do |raw|
    line = raw.chomp("\r")
    next if line.empty? || line.start_with?("#")

    tc, result, key_h, iv_h, aad_h, msg_h, ct_h, tag_h = line.split("\t")
    key = [key_h].pack("H*")
    iv = [iv_h].pack("H*")
    aad = [aad_h.to_s].pack("H*")
    msg = [msg_h.to_s].pack("H*")
    sealed = [ct_h.to_s].pack("H*") + [tag_h.to_s].pack("H*")

    ok = true
    reason = ""

    case result
    when "valid"
      if Npamp.seal_aes256gcm(key, iv, 0, aad, msg) != sealed
        ok = false
        reason = "encrypt mismatch"
      elsif Npamp.open_aes256gcm(key, iv, 0, aad, sealed) != msg
        ok = false
        reason = "decrypt mismatch"
      end
    when "invalid"
      begin
        Npamp.open_aes256gcm(key, iv, 0, aad, sealed)
        ok = false
        reason = "accepted an invalid vector"
      rescue StandardError
        # correct: rejected
      end
    else # "acceptable"
      begin
        if Npamp.open_aes256gcm(key, iv, 0, aad, sealed) != msg
          ok = false
          reason = "acceptable but wrong plaintext"
        end
      rescue StandardError
        # rejection is acceptable
      end
    end

    total += 1
    if ok
      passed += 1
    else
      fails << [tc, result, reason]
    end
  end

  puts "AES-256-GCM Wycheproof KAT (ruby): #{passed}/#{total} passed"
  fails.first(15).each do |tc, result, reason|
    puts "  FAIL tcId=#{tc} result=#{result}: #{reason}"
  end

  fails.empty? && total.positive? ? 0 : 1
end

exit(main) if $PROGRAM_NAME == __FILE__

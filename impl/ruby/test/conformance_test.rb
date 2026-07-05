# frozen_string_literal: true

# Conformance test for the N-PAMP Ruby reference (draft-bubblefish-npamp-00).
# Reproduces the four cross-language golden vectors plus five property tests.
# Prints one line per check and exits 1 if any check fails. Mirrors the
# Java/Python/Go/Rust suites (9 checks).

require_relative "../lib/npamp"

HDR   = "4e50414d20000100000000000000000000000000000d880c250000000000000000000000"
NONCE = "010203040404040c0c0c0c04"
AEAD  = "3fe8b79f95b5697926b3395429c2c2466999c652f9346aeebb30bf"
TK    = "79372e2fb7f92d63e3a68099ff72514f310ebf6773deb0fa7ef45d013c652dcc"

$failures = 0

def check(name, ok)
  if ok
    puts "ok   - #{name}"
  else
    puts "FAIL - #{name}"
    $failures += 1
  end
end

def ramp(start, count)
  (0...count).map { |i| ((start + i) & 0xFF).chr }.join.b
end

# --- cross-language vector reproduction (values from the Go reference) ---

def vec_header
  f = Npamp::Frame.new(ftype: Npamp::FRAME_PING, channel: Npamp::CHAN_CONTROL, seq: 0)
  check("vec_header", Npamp.to_hex(f.marshal) == HDR)
end

def vec_nonce
  iv = ramp(0x01, 12)
  check("vec_nonce", Npamp.to_hex(Npamp.derive_nonce(iv, 0x0102030405060708)) == NONCE)
end

def vec_aead
  key = ramp(0x00, 32)
  iv = ramp(0x10, 12)
  aad = Npamp::Frame.new(ftype: Npamp::FRAME_PING, channel: Npamp::CHAN_CONTROL).header_prefix(11)
  sealed = Npamp.seal_aes256gcm(key, iv, 7, aad, "hello world".b)
  check("vec_aead", Npamp.to_hex(sealed) == AEAD)
end

def vec_traffic_key
  master = "\x2A".b * 48
  ts = Npamp.derive_traffic_secret(master, 0, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_CONTROL, false)
  tk, = Npamp.derive_key_iv(ts, false)
  check("vec_traffic_key", Npamp.to_hex(tk) == TK)
end

# --- property tests (mirror the Go/Rust/Java suites) ---

def roundtrip
  f = Npamp::Frame.new(ftype: 0x0100, channel: Npamp::CHAN_MEMORY, seq: 42,
                       flags: Npamp::FLAG_ENC, payload: "payload".b)
  g = Npamp::Frame.unmarshal(f.marshal)
  ok = g.flags == Npamp::FLAG_ENC && g.ftype == 0x0100 && g.channel == Npamp::CHAN_MEMORY &&
       g.seq == 42 && g.payload == "payload".b
  check("roundtrip", ok)
end

def crc_validated_first
  buf = Npamp::Frame.new(ftype: Npamp::FRAME_PING, channel: Npamp::CHAN_CONTROL).marshal.dup
  buf.setbyte(5, buf.getbyte(5) ^ 0xFF) # corrupt frame-type byte; CRC must reject first
  rejected = false
  begin
    Npamp::Frame.unmarshal(buf)
  rescue Npamp::FrameError => e
    rejected = e.message == "bad crc"
  end
  check("crc_validated_first", rejected)
end

def reserved_must_be_zero
  buf = Npamp::Frame.new(ftype: Npamp::FRAME_PING, channel: Npamp::CHAN_CONTROL).marshal.dup
  buf.setbyte(30, 1) # a reserved octet
  rejected = false
  begin
    Npamp::Frame.unmarshal(buf)
  rescue Npamp::FrameError => e
    rejected = e.message == "bad crc" || e.message == "reserved nonzero"
  end
  check("reserved_must_be_zero", rejected)
end

def aead_tamper_fails
  key = "\x00".b * 32
  iv = ramp(0x10, 12)
  aad = Npamp::Frame.new(ftype: Npamp::FRAME_PING, channel: Npamp::CHAN_CONTROL).header_prefix(5)
  sealed = Npamp.seal_aes256gcm(key, iv, 7, aad, "hello".b)
  open_ok = Npamp.open_aes256gcm(key, iv, 7, aad, sealed) == "hello".b
  tampered = aad.dup
  tampered.setbyte(5, tampered.getbyte(5) ^ 1)
  tamper_rejected = false
  begin
    Npamp.open_aes256gcm(key, iv, 7, tampered, sealed)
  rescue StandardError
    tamper_rejected = true
  end
  check("aead_tamper_fails", open_ok && tamper_rejected)
end

def hkdf_prefix_protocol_specific
  check("hkdf_prefix_protocol_specific",
        Npamp::LABEL_PREFIX == "n-pamp " && Npamp::LABEL_PREFIX != "tls13 ")
end

vec_header
vec_nonce
vec_aead
vec_traffic_key
roundtrip
crc_validated_first
reserved_must_be_zero
aead_tamper_fails
hkdf_prefix_protocol_specific

puts($failures.zero? ? "ALL PASS (9/9)" : "FAILURES: #{$failures}")
exit($failures.zero? ? 0 : 1)

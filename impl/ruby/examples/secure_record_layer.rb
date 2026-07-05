# frozen_string_literal: true

# Runnable example: the draft-00 secure record layer, end to end.
#
# Composes the OPEN-protocol primitives this port provides - the HKDF key
# schedule, the AES-256-GCM record layer, and the 36-octet frame codec - into
# one send -> receive round-trip over an in-memory "wire". Mirrors the Go
# reference's Example_secureRecordLayer (impl/go/example_test.go).
#
# The master secret is a fixed demo value; in a live session it is the
# handshake output (binding spec/10 section 5). Standard profile only
# (SHA-256, AES-256-GCM). Run from impl/ruby:
#
#   ruby examples/secure_record_layer.rb

require_relative "../lib/npamp"

# Direction octet (draft-00 7.5): client-to-server = 0.
DIR_CLIENT_TO_SERVER = 0

# 1. Key schedule: derive a per-(direction, channel, suite) traffic key + IV
#    from the master secret. In a live session the master secret is the
#    handshake output; here it is fixed so the example is deterministic.
master = "\x2B".b * 32
ts = Npamp.derive_traffic_secret(master, DIR_CLIENT_TO_SERVER, 0, Npamp::AEAD_AES256_GCM, Npamp::CHAN_MEMORY, true)
key, iv = Npamp.derive_key_iv(ts, true)

# 2. Sender: seal an application payload into an AEAD-protected frame on the
#    Memory channel. The AEAD associated data is the 21-octet header prefix, so
#    the ciphertext is bound to the frame's type/channel/seq/length - a
#    tampered header makes the open fail.
app_type = 0x0120 # application frame type (app-defined; this port is wire-only)
plaintext = "hello over n-pamp".b
seq = 0
out = Npamp::Frame.new(ftype: app_type, channel: Npamp::CHAN_MEMORY, seq: seq, flags: Npamp::FLAG_ENC)
aad = out.header_prefix(plaintext.bytesize + 16) # +16 = AES-256-GCM authentication tag
out.payload = Npamp.seal_aes256gcm(key, iv, seq, aad, plaintext)
wire = out.marshal

# 3. ... the `wire` bytes travel over any transport (the consumer supplies TCP/TLS) ...

# 4. Receiver: parse the frame (validates CRC32C/magic/version) and open the
#    payload under the same key/seq and the reconstructed header-prefix AAD.
inc = Npamp::Frame.unmarshal(wire)
raad = inc.header_prefix(inc.payload.bytesize)
opened = Npamp.open_aes256gcm(key, iv, inc.seq, raad, inc.payload)

puts "channel=#{inc.channel} seq=#{inc.seq} encrypted=#{(inc.flags & Npamp::FLAG_ENC) != 0}"
puts "recovered: #{opened}"
exit(opened == plaintext ? 0 : 1)

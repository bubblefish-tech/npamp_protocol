# frozen_string_literal: true

# N-PAMP (draft-bubblefish-npamp-00) conformance adapter (Ruby). A "testee": it reads
# length-prefixed JSON requests {op,in} on stdin and writes length-prefixed JSON responses
# {out|error|skipped} on stdout. Every operation is performed by CALLING the OPEN Ruby
# reference implementation in ../../impl/ruby/lib/npamp.rb -- this adapter contains no
# reimplementation of the protocol primitives; it only translates the wire contract into
# calls on Npamp.* and the Npamp::Frame class.
#
# Windows note: binary stdio (text mode would corrupt the byte framing via CRLF
# translation) and a flush after every response.

require "json"
require_relative "../../../impl/ruby/lib/npamp"

# Decode a lowercase-hex field from the request "in" object into a binary String.
def hx(input, key)
  s = input[key]
  return "".b if s.nil? || s.empty?

  [s].pack("H*").b
end

def handle(req)
  op = req["op"]
  input = req["in"] || {}

  case op
  when "header.encode"
    # Build the 21-octet header prefix and the 36-byte frame header using the reference
    # Frame#header_prefix, Npamp.crc32c and Npamp.uint_to_be -- the real impl functions.
    frame = Npamp::Frame.new(
      version: input["ver"].to_i,
      flags: input["flags"].to_i,
      ftype: input["frameType"].to_i,
      channel: input["channel"].to_i,
      seq: input["seq"].to_i
    )
    prefix = frame.header_prefix(input["payloadLength"].to_i)
    header = "\x00".b * Npamp::HEADER_SIZE
    header[0, 21] = prefix
    header[21, 4] = Npamp.uint_to_be(Npamp.crc32c(prefix), 4)
    # octets 25..35 reserved, already zero
    { "out" => { "frame" => Npamp.to_hex(header) } }

  when "header.decode"
    buf = hx(input, "frame")
    begin
      # Npamp::Frame.unmarshal performs the real MUST-reject checks (crc-first, magic,
      # version, reserved-zero, length) and parses every field.
      frame = Npamp::Frame.unmarshal(buf)
    rescue Npamp::FrameError => e
      return { "error" => e.message }
    end
    {
      "out" => {
        "magic" => "NPAM",
        "ver" => frame.version,
        "flags" => frame.flags,
        "frameType" => frame.ftype,
        "channel" => frame.channel,
        "seq" => frame.seq,
        "payloadLength" => Npamp.be_to_uint(buf[17, 4]),
        "crc32c" => Npamp.to_hex(buf[21, 4]),
        "reservedZero" => true
      }
    }

  when "crc32c"
    octets = hx(input, "octets")
    crc = Npamp.crc32c(octets) # real Castagnoli CRC32C from the reference impl
    { "out" => { "crc32c" => Npamp.to_hex(Npamp.uint_to_be(crc, 4)) } }

  when "tlv.decode"
    buf = hx(input, "tlv")
    return { "error" => "truncated tlv" } if buf.bytesize < 4

    # Big-endian field parsing via the reference Npamp.be_to_uint.
    typ = Npamp.be_to_uint(buf[0, 2])
    length = Npamp.be_to_uint(buf[2, 2])
    return { "error" => "unknown forward-incompatible TLV (high bit set)" } if (typ & 0x8000) != 0
    return { "error" => "tlv length mismatch" } if length != buf.bytesize - 4

    { "out" => { "type" => typ, "length" => length, "value" => Npamp.to_hex(buf[4..] || "".b) } }

  when "aead.seal"
    return { "skipped" => "suite not implemented: #{input['suite']}" } if input["suite"] != "AES-256-GCM"

    key = hx(input, "key")
    nonce = hx(input, "nonce")
    aad = hx(input, "aad")
    pt = hx(input, "pt")
    begin
      # Npamp.seal_aes256gcm derives its nonce as derive_nonce(iv, seq); with seq == 0 the
      # derived nonce equals the supplied iv, so iv := nonce, seq := 0 makes the reference
      # seal operate on exactly the contract's nonce.
      sealed = Npamp.seal_aes256gcm(key, nonce, 0, aad, pt)
    rescue StandardError => e
      return { "error" => e.message }
    end
    { "out" => { "sealed" => Npamp.to_hex(sealed) } }

  when "aead.open"
    return { "skipped" => "suite not implemented: #{input['suite']}" } if input["suite"] != "AES-256-GCM"

    key = hx(input, "key")
    nonce = hx(input, "nonce")
    aad = hx(input, "aad")
    sealed = hx(input, "sealed")
    begin
      pt = Npamp.open_aes256gcm(key, nonce, 0, aad, sealed)
    rescue StandardError
      return { "error" => "authentication failed" }
    end
    { "out" => { "pt" => Npamp.to_hex(pt) } }

  when "hkdf.expand"
    hash = input["hash"]
    digest =
      case hash
      when "sha256" then OpenSSL::Digest.new("SHA256")
      when "sha384" then OpenSSL::Digest.new("SHA384")
      else
        return { "skipped" => "hash not implemented: #{hash}" }
      end
    prk = hx(input, "prk")
    info = hx(input, "info")
    length = input["length"].to_i
    begin
      # Npamp.hkdf_expand is RFC 5869 sec 2.3 HKDF-Expand (PRK = secret, no extract step).
      okm = Npamp.hkdf_expand(prk, info, length, digest)
    rescue StandardError => e
      return { "error" => e.message }
    end
    { "out" => { "okm" => Npamp.to_hex(okm) } }

  when "profile.check"
    # Profile/KEM acceptance invariants, expressed against the reference KEM constants.
    profile = input["profile"]
    kem = input["kem"]
    kem_id =
      case kem
      when "X25519MLKEM768" then Npamp::KEM_X25519_MLKEM768
      when "X25519MLKEM1024" then Npamp::KEM_X25519_MLKEM1024
      end
    return { "error" => "unknown KEM: #{kem}" } if kem_id.nil?

    if profile == "Sovereign" && kem_id == Npamp::KEM_X25519_MLKEM768
      return { "error" => "Sovereign MUST NOT accept X25519MLKEM768" }
    end
    if profile == "High" && kem_id == Npamp::KEM_X25519_MLKEM768
      return { "error" => "High minimum KEM is X25519MLKEM1024" }
    end

    { "out" => { "accepted" => true } }

  else
    { "skipped" => "op not implemented: #{op}" }
  end
end

def main
  rd = $stdin
  wr = $stdout
  rd.binmode
  wr.binmode

  loop do
    lp = rd.read(4)
    break if lp.nil? || lp.bytesize < 4

    n = lp.unpack1("V") # 4-byte little-endian length
    body = n.zero? ? "".b : rd.read(n)
    break if body.nil? || body.bytesize < n

    resp =
      begin
        handle(JSON.parse(body))
      rescue StandardError => e
        { "error" => "adapter exception: #{e.message}" }
      end

    ob = JSON.generate(resp).b
    wr.write([ob.bytesize].pack("V"))
    wr.write(ob)
    wr.flush
  end
end

main if $PROGRAM_NAME == __FILE__

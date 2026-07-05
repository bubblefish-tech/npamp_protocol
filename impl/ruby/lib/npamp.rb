# frozen_string_literal: true

# Open reference implementation of the N-PAMP wire format (draft-bubblefish-npamp-00).
#
# OPEN protocol layer only: framing, registries, the AEAD record layer, and the
# HKDF-Expand-Label key schedule. No proprietary methods, parameters, or weights.
#
# Pure Ruby + stdlib OpenSSL. CRC32C is implemented manually (Castagnoli, reflected);
# Zlib.crc32 is the IEEE polynomial and must not be used here.

require "openssl"

module Npamp
  HEADER_SIZE = 36
  PROTOCOL_VERSION = 0x2
  MAGIC = "NPAM".b
  ALPN = "n-pamp/2"
  LABEL_PREFIX = "n-pamp " # protocol-specific; NOT "tls13 "

  FLAG_URG  = 0x01
  FLAG_ENC  = 0x02
  FLAG_COMP = 0x04
  FLAG_FRAG = 0x08

  CHAN_CONTROL = 0x0000
  CHAN_MEMORY  = 0x0001
  CHAN_IMMUNE  = 0x0005
  CHAN_AUDIT   = 0x000B
  CHAN_BRIDGE  = 0x000D
  CHAN_SPATIAL = 0x0013

  FRAME_PING            = 0x0001
  FRAME_PONG            = 0x0002
  FRAME_CLOSE           = 0x0003
  FRAME_FLOW_UPDATE     = 0x000A
  CHANNEL_SPECIFIC_BASE = 0x0100

  TLV_PROFILE_OFFER  = 0x01
  TLV_KEM_CIPHERTEXT = 0x08
  TLV_ANOMALY_CHARGE = 0x12

  KEM_X25519_MLKEM768  = 0x11EC
  KEM_X25519_MLKEM1024 = 0x11ED

  AEAD_AES256_GCM       = 0x0001
  AEAD_CHACHA20_POLY1305 = 0x0002

  SIG_ED25519 = 0x0807
  SIG_MLDSA87 = 0x0905

  # CRC32C (Castagnoli, reflected) - identical to Go hash/crc32 Castagnoli.
  # poly 0x82F63B78, init/xorout 0xFFFFFFFF. Returns an unsigned 32-bit integer.
  def self.crc32c(data)
    poly = 0x82F63B78
    crc = 0xFFFFFFFF
    data.each_byte do |b|
      crc ^= b
      8.times do
        crc = (crc & 1) != 0 ? (crc >> 1) ^ poly : (crc >> 1)
      end
    end
    crc ^ 0xFFFFFFFF
  end

  class FrameError < StandardError; end

  # Encode an unsigned integer as a big-endian byte string of the given width.
  def self.uint_to_be(value, width)
    out = String.new(capacity: width)
    (width - 1).downto(0) do |i|
      out << ((value >> (i * 8)) & 0xFF).chr
    end
    out.b
  end

  # Decode a big-endian byte string slice into an unsigned integer.
  def self.be_to_uint(bytes)
    v = 0
    bytes.each_byte { |b| v = (v << 8) | b }
    v
  end

  class Frame
    attr_accessor :version, :flags, :ftype, :channel, :seq, :payload

    def initialize(ftype: 0, channel: 0, seq: 0, flags: 0, version: 0, payload: "".b)
      @version = version
      @flags = flags
      @ftype = ftype
      @channel = channel
      @seq = seq
      @payload = payload.b
    end

    # The 21-octet header prefix. Big-endian throughout. This is also the AEAD AAD.
    def header_prefix(payload_len)
      ver = @version.zero? ? PROTOCOL_VERSION : @version
      out = "\x00".b * 21
      out[0, 4] = MAGIC
      out.setbyte(4, ((ver << 4) | (@flags & 0x0F)) & 0xFF)
      out[5, 2] = Npamp.uint_to_be(@ftype, 2)
      out[7, 2] = Npamp.uint_to_be(@channel, 2)
      out[9, 8] = Npamp.uint_to_be(@seq, 8)
      out[17, 4] = Npamp.uint_to_be(payload_len, 4)
      out
    end

    # Serialize the full 36-byte header (prefix | u32 crc32c(prefix) | 11 zero octets)
    # followed by the payload.
    def marshal
      prefix = header_prefix(@payload.bytesize)
      out = "\x00".b * (HEADER_SIZE + @payload.bytesize)
      out[0, 21] = prefix
      out[21, 4] = Npamp.uint_to_be(Npamp.crc32c(prefix), 4)
      # octets 25..36 reserved, already zero
      out[HEADER_SIZE, @payload.bytesize] = @payload if @payload.bytesize.positive?
      out
    end

    # Parse a full frame. CRC is checked FIRST so no field is trusted before the
    # integrity check passes.
    def self.unmarshal(buf)
      buf = buf.b
      raise FrameError, "short header" if buf.bytesize < HEADER_SIZE

      got = Npamp.be_to_uint(buf[21, 4])
      raise FrameError, "bad crc" if got != Npamp.crc32c(buf[0, 21])
      raise FrameError, "bad magic" if buf[0, 4] != MAGIC

      ver = buf.getbyte(4) >> 4
      raise FrameError, "bad version" if ver != PROTOCOL_VERSION

      (25...HEADER_SIZE).each do |i|
        raise FrameError, "reserved nonzero" if buf.getbyte(i) != 0
      end

      plen = Npamp.be_to_uint(buf[17, 4])
      raise FrameError, "length mismatch" if plen != buf.bytesize - HEADER_SIZE

      Frame.new(
        version: ver,
        flags: buf.getbyte(4) & 0x0F,
        ftype: Npamp.be_to_uint(buf[5, 2]),
        channel: Npamp.be_to_uint(buf[7, 2]),
        seq: Npamp.be_to_uint(buf[9, 8]),
        payload: buf[HEADER_SIZE..] || "".b
      )
    end
  end

  # Per-frame AEAD nonce (draft-00 7.5): IV XOR left-zero-padded seq. No channel.
  # With seq == 0 the nonce equals the IV.
  def self.derive_nonce(iv, seq)
    n = "\x00".b * 12
    n[4, 8] = uint_to_be(seq, 8)
    out = String.new(capacity: 12).b
    12.times { |i| out << (n.getbyte(i) ^ iv.getbyte(i)).chr }
    out
  end

  # AES-256-GCM seal. Returns ciphertext || tag (16-byte tag).
  def self.seal_aes256gcm(key, iv, seq, aad, pt)
    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.encrypt
    cipher.key = key.b
    cipher.iv = derive_nonce(iv, seq)
    cipher.auth_data = aad.b
    sealed = cipher.update(pt.b) + cipher.final
    sealed + cipher.auth_tag(16)
  end

  # AES-256-GCM open. Input is ciphertext || tag. Raises OpenSSL::Cipher::CipherError
  # (a RuntimeError subclass) on tag/AAD mismatch -> the frame is rejected.
  def self.open_aes256gcm(key, iv, seq, aad, sealed)
    sealed = sealed.b
    raise OpenSSL::Cipher::CipherError, "ciphertext shorter than tag" if sealed.bytesize < 16

    tag = sealed[-16, 16]
    ct = sealed[0, sealed.bytesize - 16]
    cipher = OpenSSL::Cipher.new("aes-256-gcm")
    cipher.decrypt
    cipher.key = key.b
    cipher.iv = derive_nonce(iv, seq)
    cipher.auth_tag = tag
    cipher.auth_data = aad.b
    cipher.update(ct) + cipher.final
  end

  # HKDF-Expand-Label (draft-00 key schedule). HKDF-Expand only (RFC 5869 sec 2.3);
  # the supplied secret IS the PRK, there is no extract step.
  # SHA-256 when standard == true, SHA-384 when standard == false ("high" profile).
  def self.hkdf_expand_label(secret, label, context, length, standard)
    full = (LABEL_PREFIX + label).b
    info = uint_to_be(length, 2)
    info << full.bytesize.chr
    info << full
    info << context.bytesize.chr
    info << context.b
    digest = standard ? OpenSSL::Digest.new("SHA256") : OpenSSL::Digest.new("SHA384")
    hkdf_expand(secret.b, info, length, digest)
  end

  # RFC 5869 section 2.3 HKDF-Expand. PRK is the given secret; no extract step.
  def self.hkdf_expand(prk, info, length, digest)
    hash_len = digest.digest_length
    raise ArgumentError, "length too large for HKDF-Expand" if length > 255 * hash_len

    out = "".b
    t = "".b
    counter = 1
    while out.bytesize < length
      t = OpenSSL::HMAC.digest(digest, prk, t + info + counter.chr)
      out << t
      counter += 1
    end
    out[0, length]
  end

  # traffic secret: context = dir(1) | epoch(8 BE) | suite(2 BE) | channel(2 BE);
  # label "traffic"; output 32 (SHA-256) or 48 (SHA-384).
  def self.derive_traffic_secret(master, direction, epoch, suite, channel, standard)
    ctx = direction.chr.b
    ctx << uint_to_be(epoch, 8)
    ctx << uint_to_be(suite, 2)
    ctx << uint_to_be(channel, 2)
    hlen = standard ? 32 : 48
    hkdf_expand_label(master, "traffic", ctx, hlen, standard)
  end

  # key/iv = HkdfExpandLabel(secret,"key",[],32) / (...,"iv",[],12).
  def self.derive_key_iv(secret, standard)
    key = hkdf_expand_label(secret, "key", "".b, 32, standard)
    iv = hkdf_expand_label(secret, "iv", "".b, 12, standard)
    [key, iv]
  end

  # RFC 5869 section 2.2 HKDF-Extract: PRK = HMAC-Hash(salt, IKM). SHA-256 when
  # standard, SHA-384 when "high". Per RFC 5869, an absent salt defaults to HashLen
  # zero octets; the draft-00 binding (spec/10 section 5) uses that 32-zero-octet
  # default salt for the handshake-secret extract at the Standard profile.
  def self.hkdf_extract(salt, ikm, standard)
    digest = standard ? OpenSSL::Digest.new("SHA256") : OpenSSL::Digest.new("SHA384")
    salt = ("\x00".b * digest.digest_length) if salt.nil? || salt.empty?
    OpenSSL::HMAC.digest(digest, salt.b, ikm.b)
  end

  # handshake_secret (binding spec/10 section 5; ML-KEM-first per ADR-0005). The two
  # inputs are the post-quantum and classical KEM shared secrets (IKM); they are
  # concatenated with the ML-KEM shared secret FIRST, then HKDF-Extract'd under the
  # default salt of HashLen zero octets (32 at the Standard profile).
  def self.derive_handshake_secret(mlkem_ss, x25519_ss, standard)
    ikm = mlkem_ss.b + x25519_ss.b
    hlen = standard ? 32 : 48
    hkdf_extract("\x00".b * hlen, ikm, standard)
  end

  # c_hs (binding spec/10 section 5): HKDF-Expand-Label(handshake_secret, "c hs",
  # th_kem, HashLen). The "n-pamp " prefix is added by hkdf_expand_label.
  def self.derive_client_handshake_secret(handshake_secret, th_kem, standard)
    hkdf_expand_label(handshake_secret, "c hs", th_kem.b, standard ? 32 : 48, standard)
  end

  # s_hs (binding spec/10 section 5): HKDF-Expand-Label(handshake_secret, "s hs",
  # th_kem, HashLen).
  def self.derive_server_handshake_secret(handshake_secret, th_kem, standard)
    hkdf_expand_label(handshake_secret, "s hs", th_kem.b, standard ? 32 : 48, standard)
  end

  # master (binding spec/10 section 5): HKDF-Expand-Label(handshake_secret, "master",
  # th_ccv, HashLen). Bound to th_ccv (the client-CertVerify cut), NOT th_kem.
  def self.derive_master_secret(handshake_secret, th_ccv, standard)
    hkdf_expand_label(handshake_secret, "master", th_ccv.b, standard ? 32 : 48, standard)
  end

  # finished_key (binding spec/10 section 6.2 / section 5.4): HKDF-Expand-Label(secret,
  # "finished", "" /* empty context */, HashLen). The client Finished key derives from
  # c_hs; the server Finished key derives from s_hs.
  def self.derive_finished_key(secret, standard)
    hkdf_expand_label(secret, "finished", "".b, standard ? 32 : 48, standard)
  end

  # Lowercase hex encoding helper (mirrors the reference .hex() output).
  def self.to_hex(bytes)
    bytes.b.unpack1("H*")
  end

  # --------------------------------------------------------------------------
  # Handshake binding layer (draft-00 binding spec/10): transcript, Finished,
  # CertVerify. Pure stdlib OpenSSL; no proprietary methods or parameters.
  # --------------------------------------------------------------------------

  # Handshake frame types (spec 1), carried on the control channel.
  FRAME_CLIENT_HELLO = 0x0100
  FRAME_SERVER_HELLO = 0x0101
  FRAME_SERVER_AUTH  = 0x0102
  FRAME_CLIENT_AUTH  = 0x0103

  # CertVerify context strings (spec 6.1).
  CONTEXT_SERVER_CERTVERIFY = "N-PAMP draft-00, server CertificateVerify"
  CONTEXT_CLIENT_CERTVERIFY = "N-PAMP draft-00, client CertificateVerify"

  # Transcript accumulates the draft-00 handshake transcript (binding spec/10 sec 3)
  # and hashes it at a cut point. Per-TLV granularity: add_frame_type appends the
  # 2-octet frame type ONLY (not the rest of the 36-octet header - the spec 3/7.1
  # divergence from RFC 8446 4.4.1); add_tlv appends Type(2 BE) | Length(2 BE) |
  # Value. A point = hash over all bytes absorbed so far (SHA-256 at Standard,
  # SHA-384 at High/Sovereign).
  class Transcript
    def initialize
      @buf = "".b
    end

    # Append the frame type as exactly 2 octets big-endian.
    def add_frame_type(ftype)
      @buf << Npamp.uint_to_be(ftype & 0xFFFF, 2)
    end

    # Append Type(2 BE) | Length(2 BE) | Value.
    def add_tlv(type_, value)
      value = value.b
      @buf << Npamp.uint_to_be(type_ & 0xFFFF, 2)
      @buf << Npamp.uint_to_be(value.bytesize, 2)
      @buf << value
    end

    # Hash over all bytes absorbed so far. SHA-256 when standard, else SHA-384.
    def hash(standard)
      digest = standard ? OpenSSL::Digest.new("SHA256") : OpenSSL::Digest.new("SHA384")
      digest.digest(@buf)
    end
  end

  # Finished (binding spec/10 6.2; RFC 8446 4.4.4): verify_data =
  # HMAC(finished_key, transcript_hash) under the profile hash (SHA-256 at
  # Standard, SHA-384 at High/Sovereign).
  def self.compute_finished(finished_key, transcript_hash, standard)
    OpenSSL::HMAC.digest(standard ? "SHA256" : "SHA384", finished_key.b, transcript_hash.b)
  end

  # Recompute the Finished MAC and constant-time-compare it to the received
  # verify_data. A length mismatch is rejected before the fixed-length compare.
  def self.verify_finished(finished_key, transcript_hash, verify_data, standard)
    expected = compute_finished(finished_key, transcript_hash, standard)
    verify_data = verify_data.b
    return false if expected.bytesize != verify_data.bytesize

    OpenSSL.fixed_length_secure_compare(expected, verify_data)
  end

  # Build an Ed25519 private key from its raw 32-octet seed (RFC 8032).
  def self.ed25519_private_key_from_seed(seed)
    OpenSSL::PKey.new_raw_private_key("ED25519", seed.b)
  end

  # Build an Ed25519 public key from its raw 32-octet encoding (RFC 8032).
  def self.ed25519_public_key_from_raw(raw)
    OpenSSL::PKey.new_raw_public_key("ED25519", raw.b)
  end

  # The 6.1 signing input: 64 octets of 0x20, the role context string, a 0x00
  # separator, then the transcript hash - TLS-1.3-style domain separation
  # (RFC 8446 4.4.3).
  def self.cert_verify_signing_input(is_server, transcript_hash)
    ctx = (is_server ? CONTEXT_SERVER_CERTVERIFY : CONTEXT_CLIENT_CERTVERIFY).b
    ("\x20".b * 64) + ctx + "\x00".b + transcript_hash.b
  end

  # The CertVerify TLV value: u16(0x0807, Ed25519) | Ed25519(priv, signing_input).
  def self.sign_cert_verify(private_key, is_server, transcript_hash)
    sig = private_key.sign(nil, cert_verify_signing_input(is_server, transcript_hash))
    uint_to_be(SIG_ED25519, 2) + sig
  end

  # Check a CertVerify TLV value against the signer's public key, role, and
  # transcript hash. Rejects a non-Ed25519 scheme, a wrong-length signature, a
  # role/context mismatch, or a wrong transcript.
  def self.verify_cert_verify(public_key, is_server, transcript_hash, value)
    value = value.b
    return false if value.bytesize < 2
    return false if be_to_uint(value[0, 2]) != SIG_ED25519

    sig = value[2..] || "".b
    return false if sig.bytesize != 64 # Ed25519 signatures are exactly 64 octets (RFC 8032 5.1.6)

    public_key.verify(nil, sig, cert_verify_signing_input(is_server, transcript_hash))
  rescue OpenSSL::PKey::PKeyError
    false
  end
end

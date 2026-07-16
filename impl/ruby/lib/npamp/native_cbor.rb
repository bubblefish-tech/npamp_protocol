# frozen_string_literal: true

# Minimal deterministic (canonical) CBOR codec for the N-PAMP native operation-body
# rails (spec/companion §4; RFC 8949 §4.2.1 core-deterministic). This is the Ruby
# port of the Go reference codec impl/go/memory_cbor.go: it decodes exactly the subset
# the native bodies use — unsigned integers, negative integers, byte strings, text
# strings, arrays, maps, and the simple values false/true/null, all definite-length,
# shortest-form, with map keys in canonical (bytewise-of-encoded-key) ascending order.
#
# It is deliberately NOT a general CBOR library: on decode it REJECTS anything outside
# this subset (indefinite lengths, non-shortest integer/length encodings, tags, floats
# and other simple values, and out-of-order or duplicate map keys) — precisely what a
# deterministic-encoding receiver MUST reject.
#
# Pure Ruby + stdlib. No third-party gem.

module Npamp
  module CBOR
    # Error is raised for any input outside the deterministic subset. A raised Error is
    # the decode-time signal that a frame body MUST be rejected.
    class Error < StandardError; end

    # Bytes wraps a CBOR byte string (major 2). It is a distinct type from a Ruby
    # String (which represents a CBOR text string, major 3) so a schema can require one
    # and reject the other — the memory_cbor.go []byte-vs-string distinction.
    class Bytes
      attr_reader :value

      def initialize(value)
        @value = value.b
      end

      def bytesize
        @value.bytesize
      end

      # Lowercase hex of the underlying bytes (used to compare a decoded corr against a
      # corpus vector's expected corr).
      def to_hex
        @value.unpack1("H*")
      end

      def ==(other)
        other.is_a?(Bytes) && other.value == @value
      end
    end

    # Map is a CBOR map (major 5) preserving canonical key order. Each entry keeps the
    # decoded key, the canonical encoding of the key (used for ordering/equality during
    # decode), and the decoded value. Keys in the native bodies are always unsigned or
    # negative integers; get(uint) scans for an integer key.
    class Map
      attr_reader :entries # array of [key, key_enc(binary String), value]

      def initialize
        @entries = []
      end

      def add(key, key_enc, value)
        @entries << [key, key_enc, value]
      end

      # get returns [value, true] for an integer key that is present, else [nil, false].
      def get(key)
        @entries.each do |k, _ke, v|
          return [v, true] if k.is_a?(Integer) && k == key
        end
        [nil, false]
      end

      # keys returns every decoded key in canonical order (used for the forward-compat
      # key scan).
      def keys
        @entries.map { |k, _ke, _v| k }
      end
    end

    # byte_less reports whether a sorts strictly before b in bytewise (shorter-prefix-
    # first, then lexicographic) order — RFC 8949 §4.2.1 canonical map-key ordering.
    # a and b are binary (ASCII-8BIT) strings, so String#<=> compares bytewise.
    def self.byte_less(a, b)
      la = a.bytesize
      lb = b.bytesize
      return la < lb if la != lb

      (a <=> b) < 0
    end

    # decode_top decodes a single canonical CBOR item and requires it to consume all of
    # buf (no trailing bytes) — the shape of a frame payload.
    def self.decode_top(buf)
      buf = buf.b
      value, off = decode(buf, 0)
      raise Error, "trailing bytes after top-level item" if off != buf.bytesize

      value
    end

    # decode decodes one item from buf starting at off, returning [value, next_off]. It
    # enforces the deterministic subset strictly.
    def self.decode(buf, off)
      raise Error, "truncated input" if off >= buf.bytesize

      ib = buf.getbyte(off)
      major = ib >> 5
      ai = ib & 0x1f

      if major == 7
        # Simple values / floats. Only false(20)/true(21)/null(22) are in the
        # deterministic subset; floats (25/26/27), other simple values, and the break
        # stop (31) are rejected.
        case ai
        when 20 then return [false, off + 1]
        when 21 then return [true, off + 1]
        when 22 then return [nil, off + 1]
        else raise Error, "unsupported simple value or float"
        end
      end

      arg, hdr = decode_arg(ai, buf, off)
      n = off + hdr

      case major
      when 0 # unsigned int
        [arg, n]
      when 1 # negative int: value = -1 - arg
        raise Error, "negative integer out of range" if arg > 0x7FFF_FFFF_FFFF_FFFF

        [-1 - arg, n]
      when 2, 3 # byte string / text string
        endp = n + arg
        raise Error, "truncated string" if arg > buf.bytesize || endp > buf.bytesize || endp < n

        payload = buf[n...endp]
        if major == 2
          [Bytes.new(payload), endp]
        else
          [payload.dup.force_encoding(Encoding::UTF_8), endp]
        end
      when 4 # array
        # Each element is at least one byte, so a declared count larger than the
        # remaining input cannot be satisfied — reject before iterating (huge-count DoS
        # guard, mirrors memory_cbor.go).
        raise Error, "truncated array" if arg > (buf.bytesize - n)

        out = []
        o = n
        arg.times do
          el, o = decode(buf, o)
          out << el
        end
        [out, o]
      when 5 # map
        # Each entry is a key plus a value (at least two bytes), so a declared count
        # larger than the remaining input cannot be satisfied — reject before iterating.
        raise Error, "truncated map" if arg > (buf.bytesize - n)

        m = Map.new
        o = n
        prev_key_enc = nil
        arg.times do
          key_start = o
          key, o = decode(buf, o)
          key_enc = buf[key_start...o]
          # Canonical order: each key MUST sort strictly after the previous one. A key
          # that does not is either out of order or a duplicate — both rejected.
          if !prev_key_enc.nil? && !byte_less(prev_key_enc, key_enc)
            raise Error, "map keys not in canonical ascending order (or duplicate)"
          end

          prev_key_enc = key_enc
          val, o = decode(buf, o)
          m.add(key, key_enc, val)
        end
        [m, o]
      else # major 6 (tags) — unsupported
        raise Error, "unsupported major type (tag)"
      end
    end

    # decode_arg reads the argument for additional-information value ai at buf[off],
    # enforcing shortest-form (RFC 8949 §4.2.1) and rejecting indefinite lengths.
    # Returns [argument, header_length] where header_length includes the leading byte.
    def self.decode_arg(ai, buf, off)
      if ai < 24
        [ai, 1]
      elsif ai == 24
        raise Error, "truncated argument" if off + 2 > buf.bytesize

        v = buf.getbyte(off + 1)
        raise Error, "integer/length not in shortest form" if v < 24 # could have fit in the initial byte

        [v, 2]
      elsif ai == 25
        raise Error, "truncated argument" if off + 3 > buf.bytesize

        v = (buf.getbyte(off + 1) << 8) | buf.getbyte(off + 2)
        raise Error, "integer/length not in shortest form" if v < (1 << 8)

        [v, 3]
      elsif ai == 26
        raise Error, "truncated argument" if off + 5 > buf.bytesize

        v = 0
        (1..4).each { |i| v = (v << 8) | buf.getbyte(off + i) }
        raise Error, "integer/length not in shortest form" if v < (1 << 16)

        [v, 5]
      elsif ai == 27
        raise Error, "truncated argument" if off + 9 > buf.bytesize

        v = 0
        (1..8).each { |i| v = (v << 8) | buf.getbyte(off + i) }
        raise Error, "integer/length not in shortest form" if v < (1 << 32)

        [v, 9]
      elsif ai == 31
        raise Error, "indefinite-length item (non-deterministic)"
      else # 28, 29, 30 are reserved
        raise Error, "reserved additional-information value"
      end
    end
  end
end

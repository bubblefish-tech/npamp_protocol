# frozen_string_literal: true

# N-PAMP native operation-body decode + MUST-reject enforcement (spec/companion §4–§9),
# the Ruby port of the Go reference validators
# (impl/go/{capability,immune,settlement,telemetry,commerce,interaction,workflow,
# knowledge}_bodies.go). Each channel's payload is a deterministic-CBOR map (decoded by
# native_cbor.rb); this layer adds the per-frame field schemas and the structural
# MUST-reject rules the spec requires:
#
#   * the common envelope (frame_kind (0) MUST equal the frame type; corr (1) MUST be a
#     non-empty byte string of 1–64 bytes, where the channel carries a corr),
#   * required/typed body fields per frame type,
#   * the forward-compatibility key rule (accept an unknown non-negative integer key,
#     reject an unknown negative or non-integer key),
#   * and the per-channel nested / cross-field rules (immune gossip descriptors and
#     items, telemetry report content + nested metric/event/health, commerce monetary
#     amounts and settlement-leg party membership, knowledge update results-or-removed).
#
# Value-level and cross-frame semantics that require live per-exchange state are the
# responder's to apply and are NOT decided here — this is the structural payload-decode
# surface the shared conformance corpus grades.
#
# Pure Ruby + stdlib. Depends only on native_cbor.rb.

require_relative "native_cbor"

module Npamp
  module NativeBody
    # Malformed is raised for any structural fault a responder reports as its channel's
    # malformed_request error. A raised Malformed (or an Npamp::CBOR::Error from the
    # decode step) is the signal that a frame body MUST be rejected.
    class Malformed < StandardError; end

    # kind_ok reports whether a decoded CBOR value has the required kind. The kinds map
    # to the Go cborKind table plus :number (a metric/amount value that may be an
    # unsigned OR a negative integer — the two numeric shapes the deterministic codec
    # produces, floats being outside the subset).
    def self.kind_ok(value, kind)
      case kind
      when :uint   then value.is_a?(Integer) && value >= 0
      when :number then value.is_a?(Integer)
      when :text   then value.is_a?(String)
      when :bytes  then value.is_a?(Npamp::CBOR::Bytes)
      when :array  then value.is_a?(Array)
      when :map    then value.is_a?(Npamp::CBOR::Map)
      when :bool   then value == true || value == false
      else false
      end
    end

    # forward_compat enforces the §4.3 key rule on a decoded map: an unknown
    # non-negative integer key is accepted; an unknown NEGATIVE integer key, or a
    # non-integer key, MUST be rejected. (Major-0 items decode to a non-negative
    # Integer, major-1 to a negative Integer, so the sign test is exact.)
    def self.forward_compat(m)
      m.keys.each do |k|
        if k.is_a?(Integer)
          raise Malformed, "unknown negative key #{k} (reserved)" if k < 0
        else
          raise Malformed, "non-integer map key"
        end
      end
    end

    # check_fields enforces a schema's required/typed fields and then the forward-compat
    # key rule on a decoded map. schema is an array of [key, kind, required]. It does not
    # validate the envelope keys the caller checks separately.
    def self.check_fields(m, schema)
      schema.each do |key, kind, required|
        value, present = m.get(key)
        unless present
          raise Malformed, "missing required field (key #{key})" if required

          next
        end
        raise Malformed, "field (key #{key}) has the wrong CBOR type" unless kind_ok(value, kind)
      end
      forward_compat(m)
    end

    # decode_map decodes a frame payload and requires it to be a top-level CBOR map.
    def self.decode_map(body)
      v = Npamp::CBOR.decode_top(body)
      raise Malformed, "payload is not a CBOR map" unless v.is_a?(Npamp::CBOR::Map)

      v
    end

    # check_frame_kind enforces the common-envelope frame_kind (0): present, an unsigned
    # integer, and equal to the frame type ft.
    def self.check_frame_kind(m, ft)
      fk, ok = m.get(0)
      raise Malformed, "missing frame_kind (0)" unless ok
      raise Malformed, "frame_kind (0) is not an unsigned int" unless fk.is_a?(Integer) && fk >= 0
      raise Malformed, "frame_kind #{fk} contradicts frame type #{ft}" unless fk == ft
    end

    # check_corr enforces the common-envelope corr (1): present and a non-empty byte
    # string of 1–64 bytes.
    def self.check_corr(m)
      corr, ok = m.get(1)
      raise Malformed, "missing corr (1)" unless ok
      unless corr.is_a?(Npamp::CBOR::Bytes) && corr.bytesize >= 1 && corr.bytesize <= 64
        raise Malformed, "corr (1) must be a non-empty byte string of 1-64 bytes"
      end
    end

    # validate_standard runs the shared decode + frame_kind + corr + schema pipeline used
    # by every channel whose envelope carries a REQUIRED corr, then yields the decoded map
    # to an optional per-channel nested block. Returns the decoded map.
    def self.validate_standard(ft, body, schemas)
      schema = schemas[ft]
      raise Malformed, "0x#{format('%04X', ft)} is not an operation frame type of this channel" if schema.nil?

      m = decode_map(body)
      check_frame_kind(m, ft)
      check_corr(m)
      check_fields(m, schema)
      yield m if block_given?
      m
    end

    # ---- NPAMP-CAP (spec/companion/84) ----------------------------------------------
    CAPABILITY_SCHEMAS = {
      0x0100 => [[2, :text, true], [3, :text, true], [4, :map, false], [5, :text, false],
                 [6, :text, false], [7, :uint, false], [8, :text, false], [9, :uint, true]],
      0x0101 => [[2, :map, true], [3, :text, true]],
      0x0102 => [[2, :text, true], [3, :text, true], [4, :map, false], [5, :text, false],
                 [6, :uint, false], [7, :uint, true]],
      0x0103 => [[2, :map, true], [3, :text, true]],
      0x0104 => [[2, :text, true], [3, :bool, false], [4, :text, false], [5, :uint, true]],
      0x0105 => [[2, :text, true], [3, :text, true], [4, :uint, false]],
      0x0106 => [[2, :text, false], [3, :text, false], [4, :text, false], [5, :bool, false],
                 [6, :uint, false], [7, :bytes, false], [8, :uint, true]],
      0x0107 => [[2, :array, true], [3, :bool, true], [4, :bytes, false]],
      0x0108 => [[2, :uint, true], [3, :text, true], [4, :uint, false], [5, :text, false]],
      0x0060 => [[2, :map, true], [3, :array, false], [4, :uint, true]],
      0x0061 => [[2, :text, true], [3, :text, true]],
      0x0062 => [[2, :text, true], [3, :bytes, true], [4, :uint, true]],
      0x0063 => [[2, :text, true], [3, :bytes, true]]
    }.freeze

    def self.validate_capability(ft, body)
      validate_standard(ft, body, CAPABILITY_SCHEMAS)
    end

    # ---- NPAMP-IMMUNE (spec/companion/85) -------------------------------------------
    IMMUNE_SCHEMAS = {
      0x0100 => [[2, :text, true], [3, :uint, true], [4, :uint, true], [5, :text, false],
                 [6, :text, false], [7, :text, false], [8, :bytes, false], [9, :uint, false],
                 [10, :text, false]],
      0x0101 => [[2, :uint, true], [3, :text, false]],
      0x0102 => [[2, :uint, true], [3, :text, true], [4, :uint, false]],
      0x00C0 => [[2, :array, true], [3, :bool, false]],
      0x00C1 => [[2, :array, false], [3, :array, false], [4, :uint, false]],
      0x00C2 => [[2, :array, true]],
      0x00C3 => [[2, :array, true]],
      0x00C4 => [[2, :bytes, true], [3, :uint, true], [4, :uint, false]]
    }.freeze

    GOSSIP_DESCRIPTOR_SCHEMA = [[0, :bytes, true], [1, :uint, true], [2, :uint, false], [3, :uint, false],
                                [4, :bytes, false], [5, :text, false], [6, :text, false], [7, :uint, false],
                                [8, :bytes, false], [9, :bytes, false]].freeze

    GOSSIP_ITEM_SCHEMA = [[0, :bytes, true], [1, :uint, true], [2, :uint, false], [3, :uint, false],
                          [4, :bytes, false], [5, :text, false], [6, :text, false], [7, :uint, false],
                          [8, :bytes, true]].freeze

    def self.validate_immune(ft, body)
      validate_standard(ft, body, IMMUNE_SCHEMAS) do |m|
        case ft
        when 0x00C0 then validate_gossip_array(m, GOSSIP_DESCRIPTOR_SCHEMA)
        when 0x00C3 then validate_gossip_array(m, GOSSIP_ITEM_SCHEMA)
        end
      end
    end

    # validate_gossip_array validates each element of the items(2) array against a nested
    # gossip_descriptor / gossip_item schema (keys start at 0, no envelope). An empty
    # array is permitted; a non-map element or one that fails its schema is malformed.
    def self.validate_gossip_array(m, nested)
      items, = m.get(2)
      arr = items.is_a?(Array) ? items : (raise Malformed, "items (2) is not an array")
      arr.each_with_index do |el, i|
        raise Malformed, "items[#{i}] is not a CBOR map" unless el.is_a?(Npamp::CBOR::Map)

        check_fields(el, nested)
      end
    end

    # ---- NPAMP-SETTLEMENT (spec/companion/86) ---------------------------------------
    SETTLEMENT_SCHEMAS = {
      0x0100 => [[2, :text, true], [3, :text, false], [4, :text, false], [5, :text, false],
                 [6, :text, false], [7, :text, false], [8, :uint, true]],
      0x0101 => [[2, :text, true], [3, :text, true], [4, :text, false]],
      0x0102 => [[2, :text, true], [3, :text, false], [4, :uint, true]],
      0x0103 => [[2, :map, true]],
      0x0104 => [[2, :uint, true], [3, :text, true], [4, :uint, false], [5, :text, false]],
      0x00A0 => [[2, :text, true], [3, :bytes, true], [4, :text, false], [5, :uint, false],
                 [6, :text, false], [7, :uint, true]],
      0x00A1 => [[2, :text, true], [3, :text, true], [4, :text, false]]
    }.freeze

    def self.validate_settlement(ft, body)
      validate_standard(ft, body, SETTLEMENT_SCHEMAS)
    end

    # ---- NPAMP-TELEMETRY (spec/companion/87) ----------------------------------------
    TELEMETRY_SCHEMAS = {
      0x0101 => [[2, :array, false], [3, :array, false], [4, :array, false],
                 [5, :uint, false], [6, :uint, false], [7, :uint, true]],
      0x0102 => [[2, :bytes, true], [3, :uint, true], [4, :array, false]],
      0x0103 => [[2, :bytes, true]],
      0x0104 => [[2, :bytes, true], [3, :uint, true], [4, :uint, false]],
      0x0105 => [[2, :uint, true], [3, :text, false], [4, :bytes, false]]
    }.freeze

    METRIC_SCHEMA = [[0, :text, true], [1, :uint, true], [2, :uint, true], [3, :number, true],
                     [4, :text, false], [5, :map, false], [6, :uint, false]].freeze
    EVENT_SCHEMA = [[0, :text, true], [1, :uint, true], [2, :uint, false],
                    [3, :map, false], [4, :text, false], [5, :uint, false]].freeze
    HEALTH_SCHEMA = [[0, :text, true], [1, :uint, true], [2, :uint, true],
                     [3, :text, false], [4, :map, false]].freeze

    TELEMETRY_REPORT = 0x0100

    def self.validate_telemetry(ft, body)
      known = ft == TELEMETRY_REPORT || TELEMETRY_SCHEMAS.key?(ft)
      raise Malformed, "0x#{format('%04X', ft)} is not a Telemetry operation frame type" unless known

      m = decode_map(body)
      check_frame_kind(m, ft)
      return validate_telemetry_report(m) if ft == TELEMETRY_REPORT

      # Every non-REPORT Telemetry frame carries a REQUIRED, non-empty 1-64 B corr (1).
      check_corr(m)
      check_fields(m, TELEMETRY_SCHEMAS[ft])
      m
    end

    # validate_telemetry_report validates a TELEMETRY_REPORT (0x0100) body (§5): its
    # corr (1) is CONDITIONAL (present iff the batch answers a subscription, in which
    # case sub_id (2) MUST also be present; a standalone report MUST omit both);
    # batch_seq (3) is REQUIRED; and the report MUST carry content — at least one of
    # metrics (4), events (5), health (6) present and non-empty, each element validated
    # against its nested schema.
    def self.validate_telemetry_report(m)
      corr, has_corr = m.get(1)
      _sub, has_sub_id = m.get(2)
      if has_corr
        unless corr.is_a?(Npamp::CBOR::Bytes) && corr.bytesize >= 1 && corr.bytesize <= 64
          raise Malformed, "corr (1) must be a byte string of 1-64 bytes"
        end
        raise Malformed, "subscribed report carries corr (1) but omits sub_id (2)" unless has_sub_id

        sub, = m.get(2)
        raise Malformed, "sub_id (2) must be a byte string" unless sub.is_a?(Npamp::CBOR::Bytes)
      elsif has_sub_id
        raise Malformed, "standalone report carries sub_id (2) without corr (1)"
      end

      bs, ok = m.get(3)
      raise Malformed, "missing required batch_seq (3)" unless ok
      raise Malformed, "batch_seq (3) is not an unsigned int" unless bs.is_a?(Integer) && bs >= 0

      non_empty = 0
      [[4, METRIC_SCHEMA, "metric"], [5, EVENT_SCHEMA, "event"], [6, HEALTH_SCHEMA, "health"]].each do |key, schema, what|
        val, present = m.get(key)
        next unless present
        raise Malformed, "#{what} array (key #{key}) is not a CBOR array" unless val.is_a?(Array)

        non_empty += 1 unless val.empty?
        val.each do |el|
          raise Malformed, "#{what} array element is not a CBOR map" unless el.is_a?(Npamp::CBOR::Map)

          check_fields(el, schema)
        end
      end
      raise Malformed, "TELEMETRY_REPORT carries no metrics, events, or health" if non_empty.zero?

      forward_compat(m)
      m
    end

    # ---- NPAMP-COMMERCE (spec/companion/88) -----------------------------------------
    COMMERCE_SCHEMAS = {
      0x0100 => [[2, :text, true], [3, :text, true], [4, :map, true], [5, :text, false],
                 [6, :text, false], [7, :text, false], [8, :map, false], [9, :text, false],
                 [10, :bytes, false], [11, :text, false], [12, :text, false], [13, :uint, true]],
      0x0101 => [[2, :text, true], [3, :text, true]],
      0x0102 => [[2, :text, true], [3, :uint, true]],
      0x0103 => [[2, :map, true]],
      0x0104 => [[2, :text, true], [3, :text, false], [4, :uint, true]],
      0x0105 => [[2, :text, true], [3, :text, true]],
      0x0106 => [[2, :text, true], [3, :uint, true]],
      0x0107 => [[2, :text, true], [3, :text, true], [4, :text, false]],
      0x0108 => [[2, :array, true], [3, :array, true], [4, :text, false], [5, :map, false],
                 [6, :text, false], [7, :uint, true]],
      0x0109 => [[2, :text, true], [3, :text, true]],
      0x010A => [[2, :text, true], [3, :uint, true], [4, :array, false], [5, :text, false], [6, :uint, true]],
      0x010B => [[2, :text, true], [3, :text, true]],
      0x010C => [[2, :text, true], [3, :uint, true]],
      0x010D => [[2, :text, true], [3, :text, true], [4, :array, false], [5, :array, false]],
      0x010E => [[2, :uint, true], [3, :text, true], [4, :uint, false], [5, :text, false]]
    }.freeze

    def self.validate_commerce(ft, body)
      validate_standard(ft, body, COMMERCE_SCHEMAS) do |m|
        case ft
        when 0x0100
          av, present = m.get(4)
          validate_commerce_amount(av) if present
        when 0x0108
          parties = commerce_parties(m)
          legs, = m.get(3)
          (legs || []).each { |lg| validate_commerce_leg(lg, parties) }
        end
      end
    end

    def self.commerce_parties(m)
      pv, = m.get(2)
      set = {}
      (pv || []).each do |p|
        raise Malformed, "a `parties` element is not a text string" unless p.is_a?(String)

        set[p] = true
      end
      set
    end

    def self.validate_commerce_leg(v, parties)
      raise Malformed, "a settlement leg is not a CBOR map" unless v.is_a?(Npamp::CBOR::Map)

      frm, ok = v.get(0)
      raise Malformed, "a leg omits REQUIRED `from` (0)" unless ok
      raise Malformed, "a leg `from` (0) is not a text string" unless frm.is_a?(String)

      to, ok = v.get(1)
      raise Malformed, "a leg omits REQUIRED `to` (1)" unless ok
      raise Malformed, "a leg `to` (1) is not a text string" unless to.is_a?(String)

      amt, ok = v.get(2)
      raise Malformed, "a leg omits REQUIRED `amount` (2)" unless ok

      validate_commerce_amount(amt)
      raise Malformed, "leg `from` names a party not in `parties`" unless parties[frm]
      raise Malformed, "leg `to` names a party not in `parties`" unless parties[to]

      forward_compat(v)
    end

    def self.validate_commerce_amount(v)
      raise Malformed, "`amount` is not a CBOR map" unless v.is_a?(Npamp::CBOR::Map)

      units, ok = v.get(0)
      raise Malformed, "`amount` omits REQUIRED units (0)" unless ok
      raise Malformed, "`amount` units (0) is not an integer" unless units.is_a?(Integer)

      scale, ok = v.get(1)
      raise Malformed, "`amount` omits REQUIRED scale (1)" unless ok
      raise Malformed, "`amount` scale (1) is not an unsigned int" unless scale.is_a?(Integer) && scale >= 0

      cur, ok = v.get(2)
      raise Malformed, "`amount` omits REQUIRED currency (2)" unless ok
      raise Malformed, "`amount` currency (2) is not a text string" unless cur.is_a?(String)

      forward_compat(v)
    end

    # ---- NPAMP-INTERACT (spec/companion/89) -----------------------------------------
    INTERACTION_SCHEMAS = {
      0x0100 => [[2, :uint, true], [3, :text, false], [4, :map, false], [5, :bool, false]],
      0x0101 => [],
      0x0102 => [[2, :uint, true], [3, :text, true], [4, :array, false], [5, :map, false], [6, :uint, false]],
      0x0103 => [[2, :uint, true]],
      0x0104 => [[2, :text, true], [3, :uint, false], [4, :map, false], [5, :uint, false]],
      0x0105 => [[2, :uint, true], [3, :text, false]],
      0x0106 => [[2, :uint, false]],
      0x0107 => [[2, :uint, true], [3, :text, true], [4, :uint, false], [5, :text, false]]
    }.freeze

    def self.validate_interaction(ft, body)
      validate_standard(ft, body, INTERACTION_SCHEMAS)
    end

    # ---- NPAMP-WORKFLOW (spec/companion/8a) -----------------------------------------
    WORKFLOW_SCHEMAS = {
      0x0100 => [[2, :text, true], [3, :bytes, false], [4, :map, false], [5, :uint, false],
                 [6, :text, false], [7, :text, false], [8, :text, false], [9, :text, false],
                 [10, :map, false], [11, :uint, true]],
      0x0101 => [[2, :text, true], [3, :uint, true]],
      0x0102 => [[2, :text, true]],
      0x0103 => [[2, :text, true], [3, :uint, true], [4, :uint, false], [5, :text, false],
                 [6, :uint, false], [7, :text, false]],
      0x0104 => [[2, :text, true], [3, :text, false]],
      0x0105 => [[2, :text, true], [3, :uint, true]],
      0x0106 => [[2, :text, true], [3, :uint, true], [4, :uint, true], [5, :uint, false],
                 [6, :text, false], [7, :uint, false], [8, :bytes, false], [9, :text, false]],
      0x0107 => [[2, :text, true], [3, :uint, true], [4, :uint, true], [5, :bytes, false],
                 [6, :uint, false], [7, :text, false]],
      0x0108 => [[2, :uint, true], [3, :text, true], [4, :uint, false], [5, :text, false]]
    }.freeze

    # WORKFLOW_STEP_EVENT (0x0106) and WORKFLOW_COMPLETE (0x0107) are unsolicited,
    # task-scoped notifications that carry NO corr (§4.2, §5.2).
    WORKFLOW_NO_CORR = [0x0106, 0x0107].freeze

    def self.validate_workflow(ft, body)
      schema = WORKFLOW_SCHEMAS[ft]
      raise Malformed, "0x#{format('%04X', ft)} is not a Workflow frame type" if schema.nil?

      m = decode_map(body)
      check_frame_kind(m, ft)
      check_corr(m) unless WORKFLOW_NO_CORR.include?(ft)
      check_fields(m, schema)
      m
    end

    # ---- NPAMP-KNOWLEDGE (spec/companion/8b) ----------------------------------------
    KNOWLEDGE_SCHEMAS = {
      0x0100 => [[2, :text, false], [3, :text, false], [4, :text, false], [5, :text, false],
                 [6, :uint, false], [8, :text, false], [9, :bytes, false]],
      0x0101 => [[2, :array, true], [3, :bool, true], [4, :bytes, false], [5, :uint, false], [6, :bool, false]],
      0x0102 => [[2, :array, true]],
      0x0103 => [[2, :array, false], [3, :bool, true]],
      0x0104 => [[2, :text, false], [3, :text, false], [4, :text, false], [5, :text, false],
                 [7, :text, false], [8, :bool, false], [9, :uint, true]],
      0x0105 => [[2, :bytes, true], [3, :uint, true], [4, :bool, false]],
      0x0106 => [[2, :bytes, true], [3, :uint, true], [4, :array, false], [5, :array, false]],
      0x0107 => [[2, :bytes, true], [3, :uint, true], [4, :uint, false]],
      0x0108 => [[2, :bytes, true]],
      0x0109 => [[2, :uint, true], [3, :text, true], [4, :uint, false], [5, :bytes, false]]
    }.freeze

    KNOWLEDGE_UPDATE = 0x0106

    def self.validate_knowledge(ft, body)
      validate_standard(ft, body, KNOWLEDGE_SCHEMAS) do |m|
        if ft == KNOWLEDGE_UPDATE
          _r, has_results = m.get(4)
          _x, has_removed = m.get(5)
          unless has_results || has_removed
            raise Malformed, "KNOWLEDGE_UPDATE carries neither results (4) nor removed (5)"
          end
        end
      end
    end

    # Dispatch table: op-group base name -> validator. Each validator takes (ft, body)
    # and returns the decoded CBOR map, raising Malformed / Npamp::CBOR::Error on any
    # MUST-reject fault.
    VALIDATORS = {
      "capability"  => method(:validate_capability),
      "immune"      => method(:validate_immune),
      "settlement"  => method(:validate_settlement),
      "telemetry"   => method(:validate_telemetry),
      "commerce"    => method(:validate_commerce),
      "interaction" => method(:validate_interaction),
      "workflow"    => method(:validate_workflow),
      "knowledge"   => method(:validate_knowledge)
    }.freeze
  end
end

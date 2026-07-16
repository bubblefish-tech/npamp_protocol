// Open reference implementation of the N-PAMP native-channel body validators
// (draft-bubblefish-npamp-01). OPEN protocol layer only. No proprietary methods.
//
// A native operation-channel frame payload is a deterministic-CBOR map (NpampCbor,
// the shared codec). This file adds, per channel, the common envelope check (§4.2
// frame_kind + correlation key), the per-frame-type body field schemas
// (required/typed), the forward-compatibility rule (accept an unknown non-negative
// integer key, reject an unknown negative or non-integer key), and the nested-
// structure MUST-reject rules each channel adds. It is a straight port of the Go
// reference validators impl/go/{memory,stream,capability,immune,settlement,
// telemetry,commerce,interaction,workflow,knowledge}_bodies.go and their TypeScript
// counterpart impl/typescript/src/npamp_bodies.ts.
//
// Each validate<Channel>Payload(ft, payload) returns the decoded CBORMap on success
// and THROWS on any structural fault. Throwing-on-reject is the whole contract the
// corpus MUST-reject vectors grade.
import Foundation

/// A structural fault in a native-channel body (a MUST-reject).
public struct BodyError: Error {
    public let message: String
    public init(_ message: String) { self.message = message }
}

/// Deterministic-CBOR body validators for the ten N-PAMP native operation channels.
public enum NpampBodies {

    // ---------- shared field-schema machinery (port of memory_bodies.go) ----------

    /// The expected CBOR type of a body field.
    enum Kind {
        case uint, text, bytes, array, map, bool, number
    }

    /// A single required/typed field of a body schema.
    struct Field {
        let key: UInt64
        let kind: Kind
        let required: Bool
        init(_ key: UInt64, _ kind: Kind, _ required: Bool) {
            self.key = key
            self.kind = kind
            self.required = required
        }
    }

    private static func isUint(_ v: CBOR?) -> Bool {
        if case .uint = v { return true }
        return false
    }

    private static func isInt(_ v: CBOR?) -> Bool {
        switch v {
        case .uint, .nint: return true
        default: return false
        }
    }

    private static func matchesKind(_ v: CBOR, _ k: Kind) -> Bool {
        switch k {
        case .uint: if case .uint = v { return true }; return false
        case .text: if case .text = v { return true }; return false
        case .bytes: if case .bytes = v { return true }; return false
        case .array: if case .array = v { return true }; return false
        case .map: if case .map = v { return true }; return false
        case .bool: if case .bool = v { return true }; return false
        case .number:
            switch v {
            case .uint, .nint: return true
            default: return false
            }
        }
    }

    // forwardCompatKeys enforces the §4.3/§4.4 rule: an unknown non-negative integer
    // key is accepted; an unknown NEGATIVE integer key (.nint), or a non-integer key,
    // MUST be rejected.
    private static func forwardCompatKeys(_ m: CBORMap, _ prefix: String) throws {
        for k in m.keys() {
            switch k {
            case .uint:
                continue
            case .nint:
                throw bad(prefix, "unknown negative key (reserved)")
            default:
                throw bad(prefix, "non-integer map key")
            }
        }
    }

    private static func checkFields(_ m: CBORMap, _ schema: [Field], _ prefix: String) throws {
        for fld in schema {
            guard let val = m.get(fld.key) else {
                if fld.required { throw bad(prefix, "missing required field (key \(fld.key))") }
                continue
            }
            if !matchesKind(val, fld.kind) {
                throw bad(prefix, "field (key \(fld.key)) has the wrong CBOR type")
            }
        }
        try forwardCompatKeys(m, prefix)
    }

    private static func decodeMap(_ payload: [UInt8], _ prefix: String) throws -> CBORMap {
        let v: CBOR
        do {
            v = try NpampCbor.decodeTop(payload)
        } catch let e as CBORError {
            throw bad(prefix, e.message)
        }
        guard case let .map(m) = v else {
            throw bad(prefix, "payload is not a CBOR map")
        }
        return m
    }

    private static func checkFrameKind(_ m: CBORMap, _ ft: Int, _ prefix: String) throws {
        guard let fk = m.get(0) else { throw bad(prefix, "missing frame_kind (0)") }
        guard case let .uint(fkv) = fk else { throw bad(prefix, "frame_kind (0) is not an unsigned int") }
        if fkv != UInt64(ft) {
            throw bad(prefix, "frame_kind \(fkv) contradicts frame type \(ft)")
        }
    }

    private static func checkCorr(_ m: CBORMap, _ prefix: String) throws {
        guard let corr = m.get(1) else { throw bad(prefix, "missing corr (1)") }
        guard case let .bytes(b) = corr, b.count >= 1, b.count <= 64 else {
            throw bad(prefix, "corr (1) must be a byte string of 1-64 bytes")
        }
    }

    private static func bad(_ prefix: String, _ msg: String) -> BodyError {
        BodyError("\(prefix): \(msg)")
    }

    private static func F(_ key: UInt64, _ kind: Kind, _ required: Bool) -> Field {
        Field(key, kind, required)
    }

    // ---------- NPAMP-MEMORY (spec/companion/81 §4-§8) ----------

    private static let memorySchemas: [Int: [Field]] = [
        0x0100: [F(2, .text, true), F(3, .text, false), F(4, .text, false), F(5, .text, false),
                 F(6, .text, false), F(7, .text, false), F(8, .text, false), F(9, .text, false),
                 F(10, .map, false), F(11, .uint, true)],
        0x0101: [F(2, .text, true), F(3, .text, true)],
        0x0102: [F(2, .text, true), F(3, .uint, true)],
        0x0103: [F(2, .map, true)],
        0x0104: [F(2, .text, true), F(3, .text, false), F(4, .text, false), F(5, .text, false),
                 F(6, .text, false), F(7, .text, false), F(8, .text, false), F(9, .map, false),
                 F(10, .uint, true)],
        0x0105: [F(2, .text, true), F(3, .text, true)],
        0x0106: [F(2, .text, true), F(3, .uint, true)],
        0x0107: [F(2, .text, true), F(3, .text, true)],
        0x0108: [F(2, .text, false), F(3, .text, false), F(4, .text, false), F(5, .text, false),
                 F(6, .text, false), F(7, .uint, false), F(8, .text, false), F(9, .bytes, false),
                 F(10, .uint, true)],
        0x0109: [F(2, .array, true), F(3, .bool, true), F(4, .bytes, false), F(5, .uint, false),
                 F(6, .bool, false)],
        0x010a: [F(2, .array, true)],
        0x010b: [F(2, .array, false), F(3, .bool, true)],
        0x010c: [],
        0x010d: [F(2, .text, true), F(3, .text, false), F(4, .uint, false), F(5, .map, false)],
        0x010e: [F(2, .uint, true), F(3, .text, true), F(4, .uint, false), F(5, .text, false)],
        0x0035: [F(2, .text, true), F(3, .text, false), F(4, .uint, true)],
        0x0036: [F(2, .text, true), F(3, .uint, true)],
    ]

    public static func validateMemoryPayload(_ ft: Int, _ payload: [UInt8]) throws -> CBORMap {
        let p = "npamp/memory: malformed_request"
        guard let schema = memorySchemas[ft] else { throw bad(p, "\(ft) is not a Memory operation frame type") }
        let m = try decodeMap(payload, p)
        try checkFrameKind(m, ft, p)
        try checkCorr(m, p)
        try checkFields(m, schema, p)
        return m
    }

    // ---------- NPAMP-STREAM (spec/companion/80 §4-§5) ----------

    private static let streamSchemas: [Int: [Field]] = [
        0x0100: [F(2, .uint, true), F(3, .uint, true), F(4, .text, false), F(5, .uint, false)],
        0x0101: [F(2, .uint, true), F(3, .bytes, true), F(4, .uint, false)],
        0x0102: [F(2, .uint, true)],
        0x0103: [F(2, .uint, true), F(3, .uint, true)],
        0x0104: [F(2, .uint, true)],
    ]

    public static func validateStreamPayload(_ ft: Int, _ payload: [UInt8]) throws -> CBORMap {
        let p = "npamp/stream: malformed"
        guard let schema = streamSchemas[ft] else { throw bad(p, "\(ft) is not a Stream frame type") }
        let m = try decodeMap(payload, p)
        try checkFrameKind(m, ft, p)
        // Envelope key 1 is sub_stream_id -- an Unsigned int, unlike the byte-string corr.
        guard m.has(1) else { throw bad(p, "missing sub_stream_id (1)") }
        if !isUint(m.get(1)) { throw bad(p, "sub_stream_id (1) is not an unsigned int") }
        try checkFields(m, schema, p)
        return m
    }

    // ---------- NPAMP-CAP (spec/companion/84 §4-§8) ----------

    private static let capabilitySchemas: [Int: [Field]] = [
        0x0100: [F(2, .text, true), F(3, .text, true), F(4, .map, false), F(5, .text, false),
                 F(6, .text, false), F(7, .uint, false), F(8, .text, false), F(9, .uint, true)],
        0x0101: [F(2, .map, true), F(3, .text, true)],
        0x0102: [F(2, .text, true), F(3, .text, true), F(4, .map, false), F(5, .text, false),
                 F(6, .uint, false), F(7, .uint, true)],
        0x0103: [F(2, .map, true), F(3, .text, true)],
        0x0104: [F(2, .text, true), F(3, .bool, false), F(4, .text, false), F(5, .uint, true)],
        0x0105: [F(2, .text, true), F(3, .text, true), F(4, .uint, false)],
        0x0106: [F(2, .text, false), F(3, .text, false), F(4, .text, false), F(5, .bool, false),
                 F(6, .uint, false), F(7, .bytes, false), F(8, .uint, true)],
        0x0107: [F(2, .array, true), F(3, .bool, true), F(4, .bytes, false)],
        0x0108: [F(2, .uint, true), F(3, .text, true), F(4, .uint, false), F(5, .text, false)],
        0x0060: [F(2, .map, true), F(3, .array, false), F(4, .uint, true)],
        0x0061: [F(2, .text, true), F(3, .text, true)],
        0x0062: [F(2, .text, true), F(3, .bytes, true), F(4, .uint, true)],
        0x0063: [F(2, .text, true), F(3, .bytes, true)],
    ]

    public static func validateCapabilityPayload(_ ft: Int, _ payload: [UInt8]) throws -> CBORMap {
        let p = "npamp/capability: malformed_request"
        guard let schema = capabilitySchemas[ft] else { throw bad(p, "\(ft) is not a Capability operation frame type") }
        let m = try decodeMap(payload, p)
        try checkFrameKind(m, ft, p)
        try checkCorr(m, p)
        try checkFields(m, schema, p)
        return m
    }

    // ---------- NPAMP-IMMUNE (spec/companion/85 §4-§8) ----------

    private static let immuneReportReq = 0x0100
    private static let immuneGossipAdvertise = 0x00c0
    private static let immuneGossipPullResult = 0x00c3

    private static let immuneSchemas: [Int: [Field]] = [
        0x0100: [F(2, .text, true), F(3, .uint, true), F(4, .uint, true), F(5, .text, false),
                 F(6, .text, false), F(7, .text, false), F(8, .bytes, false), F(9, .uint, false),
                 F(10, .text, false)],
        0x0101: [F(2, .uint, true), F(3, .text, false)],
        0x0102: [F(2, .uint, true), F(3, .text, true), F(4, .uint, false)],
        0x00c0: [F(2, .array, true), F(3, .bool, false)],
        0x00c1: [F(2, .array, false), F(3, .array, false), F(4, .uint, false)],
        0x00c2: [F(2, .array, true)],
        0x00c3: [F(2, .array, true)],
        0x00c4: [F(2, .bytes, true), F(3, .uint, true), F(4, .uint, false)],
    ]

    private static let gossipDescriptorSchema: [Field] = [
        F(0, .bytes, true), F(1, .uint, true), F(2, .uint, false), F(3, .uint, false),
        F(4, .bytes, false), F(5, .text, false), F(6, .text, false), F(7, .uint, false),
        F(8, .bytes, false), F(9, .bytes, false),
    ]
    private static let gossipItemSchema: [Field] = [
        F(0, .bytes, true), F(1, .uint, true), F(2, .uint, false), F(3, .uint, false),
        F(4, .bytes, false), F(5, .text, false), F(6, .text, false), F(7, .uint, false),
        F(8, .bytes, true),
    ]

    private static func validateGossipArray(_ m: CBORMap, _ nested: [Field], _ p: String) throws {
        guard case let .array(items)? = m.get(2) else { throw bad(p, "items (2) is not an array") }
        for (i, el) in items.enumerated() {
            guard case let .map(em) = el else { throw bad(p, "items[\(i)] is not a CBOR map") }
            try checkFields(em, nested, p)
        }
    }

    public static func validateImmunePayload(_ ft: Int, _ payload: [UInt8]) throws -> CBORMap {
        let p = "npamp/immune: malformed_request"
        guard let schema = immuneSchemas[ft] else { throw bad(p, "\(ft) is not an Immune operation frame type") }
        let m = try decodeMap(payload, p)
        try checkFrameKind(m, ft, p)
        try checkCorr(m, p)
        try checkFields(m, schema, p)
        if ft == immuneGossipAdvertise {
            try validateGossipArray(m, gossipDescriptorSchema, p)
        } else if ft == immuneGossipPullResult {
            try validateGossipArray(m, gossipItemSchema, p)
        }
        return m
    }

    // ---------- NPAMP-SETTLEMENT (spec/companion/86 §4-§8) ----------

    private static let settlementSchemas: [Int: [Field]] = [
        0x0100: [F(2, .text, true), F(3, .text, false), F(4, .text, false), F(5, .text, false),
                 F(6, .text, false), F(7, .text, false), F(8, .uint, true)],
        0x0101: [F(2, .text, true), F(3, .text, true), F(4, .text, false)],
        0x0102: [F(2, .text, true), F(3, .text, false), F(4, .uint, true)],
        0x0103: [F(2, .map, true)],
        0x0104: [F(2, .uint, true), F(3, .text, true), F(4, .uint, false), F(5, .text, false)],
        0x00a0: [F(2, .text, true), F(3, .bytes, true), F(4, .text, false), F(5, .uint, false),
                 F(6, .text, false), F(7, .uint, true)],
        0x00a1: [F(2, .text, true), F(3, .text, true), F(4, .text, false)],
    ]

    public static func validateSettlementPayload(_ ft: Int, _ payload: [UInt8]) throws -> CBORMap {
        let p = "npamp/settlement: malformed_request"
        guard let schema = settlementSchemas[ft] else { throw bad(p, "\(ft) is not a Settlement operation frame type") }
        let m = try decodeMap(payload, p)
        try checkFrameKind(m, ft, p)
        try checkCorr(m, p)
        try checkFields(m, schema, p)
        return m
    }

    // ---------- NPAMP-TELEMETRY (spec/companion/87 §4-§8) ----------

    private static let telemetryReport = 0x0100
    private static let telemetryError = 0x0105

    private static let telemetrySchemas: [Int: [Field]] = [
        0x0101: [F(2, .array, false), F(3, .array, false), F(4, .array, false),
                 F(5, .uint, false), F(6, .uint, false), F(7, .uint, true)],
        0x0102: [F(2, .bytes, true), F(3, .uint, true), F(4, .array, false)],
        0x0103: [F(2, .bytes, true)],
        0x0104: [F(2, .bytes, true), F(3, .uint, true), F(4, .uint, false)],
        0x0105: [F(2, .uint, true), F(3, .text, false), F(4, .bytes, false)],
    ]

    private static let metricSchema: [Field] = [
        F(0, .text, true), F(1, .uint, true), F(2, .uint, true), F(3, .number, true),
        F(4, .text, false), F(5, .map, false), F(6, .uint, false),
    ]
    private static let eventSchema: [Field] = [
        F(0, .text, true), F(1, .uint, true), F(2, .uint, false),
        F(3, .map, false), F(4, .text, false), F(5, .uint, false),
    ]
    private static let healthSchema: [Field] = [
        F(0, .text, true), F(1, .uint, true), F(2, .uint, true),
        F(3, .text, false), F(4, .map, false),
    ]

    public static func validateTelemetryPayload(_ ft: Int, _ payload: [UInt8]) throws -> CBORMap {
        let p = "npamp/telemetry: malformed_payload"
        guard ft >= telemetryReport && ft <= telemetryError else {
            throw bad(p, "\(ft) is not a Telemetry operation frame type")
        }
        let m = try decodeMap(payload, p)
        try checkFrameKind(m, ft, p)
        if ft == telemetryReport {
            return try validateTelemetryReport(m, p)
        }
        // Every non-REPORT Telemetry frame carries a REQUIRED, non-empty corr (1) (§4.1).
        try checkCorr(m, p)
        try checkFields(m, telemetrySchemas[ft]!, p)
        return m
    }

    // validateTelemetryReport: corr (1) is CONDITIONAL (present iff the batch answers
    // a subscription, in which case sub_id (2) MUST also be present; a standalone
    // report MUST omit both); batch_seq (3) is REQUIRED; the report MUST carry content
    // (at least one of metrics(4)/events(5)/health(6) present and non-empty).
    private static func validateTelemetryReport(_ m: CBORMap, _ p: String) throws -> CBORMap {
        let hasCorr = m.has(1)
        let hasSubID = m.has(2)
        if hasCorr {
            guard case let .bytes(cb) = m.get(1)!, cb.count >= 1, cb.count <= 64 else {
                throw bad(p, "corr (1) must be a byte string of 1-64 bytes")
            }
            if !hasSubID { throw bad(p, "subscribed report carries corr (1) but omits sub_id (2)") }
            if case .bytes = m.get(2)! {} else { throw bad(p, "sub_id (2) must be a byte string") }
        } else if hasSubID {
            throw bad(p, "standalone report carries sub_id (2) without corr (1)")
        }

        guard m.has(3) else { throw bad(p, "missing required batch_seq (3)") }
        if !isUint(m.get(3)) { throw bad(p, "batch_seq (3) is not an unsigned int") }

        var nonEmpty = 0
        let content: [(key: UInt64, schema: [Field], what: String)] = [
            (4, metricSchema, "metric"),
            (5, eventSchema, "event"),
            (6, healthSchema, "health"),
        ]
        for c in content {
            guard let v = m.get(c.key) else { continue }
            guard case let .array(arr) = v else {
                throw bad(p, "\(c.what) array (key \(c.key)) is not a CBOR array")
            }
            if !arr.isEmpty { nonEmpty += 1 }
            for el in arr {
                guard case let .map(em) = el else { throw bad(p, "\(c.what) array element is not a CBOR map") }
                try checkFields(em, c.schema, p)
            }
        }
        if nonEmpty == 0 { throw bad(p, "TELEMETRY_REPORT carries no metrics, events, or health") }

        try forwardCompatKeys(m, p)
        return m
    }

    // ---------- NPAMP-COMMERCE (spec/companion/88 §4-§8) ----------

    private static let commerceMandateCreateReq = 0x0100
    private static let commerceIntentProposeReq = 0x0108

    private static let commerceSchemas: [Int: [Field]] = [
        0x0100: [F(2, .text, true), F(3, .text, true), F(4, .map, true), F(5, .text, false),
                 F(6, .text, false), F(7, .text, false), F(8, .map, false), F(9, .text, false),
                 F(10, .bytes, false), F(11, .text, false), F(12, .text, false), F(13, .uint, true)],
        0x0101: [F(2, .text, true), F(3, .text, true)],
        0x0102: [F(2, .text, true), F(3, .uint, true)],
        0x0103: [F(2, .map, true)],
        0x0104: [F(2, .text, true), F(3, .text, false), F(4, .uint, true)],
        0x0105: [F(2, .text, true), F(3, .text, true)],
        0x0106: [F(2, .text, true), F(3, .uint, true)],
        0x0107: [F(2, .text, true), F(3, .text, true), F(4, .text, false)],
        0x0108: [F(2, .array, true), F(3, .array, true), F(4, .text, false), F(5, .map, false),
                 F(6, .text, false), F(7, .uint, true)],
        0x0109: [F(2, .text, true), F(3, .text, true)],
        0x010a: [F(2, .text, true), F(3, .uint, true), F(4, .array, false), F(5, .text, false), F(6, .uint, true)],
        0x010b: [F(2, .text, true), F(3, .text, true)],
        0x010c: [F(2, .text, true), F(3, .uint, true)],
        0x010d: [F(2, .text, true), F(3, .text, true), F(4, .array, false), F(5, .array, false)],
        0x010e: [F(2, .uint, true), F(3, .text, true), F(4, .uint, false), F(5, .text, false)],
    ]

    private static func validateCommerceAmount(_ v: CBOR?, _ p: String) throws {
        guard case let .map(am)? = v else { throw bad(p, "`amount` is not a CBOR map (§4.3)") }
        guard am.has(0) else { throw bad(p, "`amount` omits REQUIRED units (0) (§4.3)") }
        if !isInt(am.get(0)) { throw bad(p, "`amount` units (0) is not an integer (§4.3)") }
        guard am.has(1) else { throw bad(p, "`amount` omits REQUIRED scale (1) (§4.3)") }
        if !isUint(am.get(1)) { throw bad(p, "`amount` scale (1) is not an unsigned int (§4.3)") }
        guard am.has(2) else { throw bad(p, "`amount` omits REQUIRED currency (2) (§4.3)") }
        guard case .text = am.get(2)! else { throw bad(p, "`amount` currency (2) is not a text string (§4.3)") }
        try forwardCompatKeys(am, p)
    }

    private static func validateCommerceLeg(_ v: CBOR, _ parties: Set<String>, _ p: String) throws {
        guard case let .map(leg) = v else { throw bad(p, "a settlement leg is not a CBOR map (§6.6)") }
        guard leg.has(0) else { throw bad(p, "a leg omits REQUIRED `from` (0) (§6.6)") }
        guard case let .text(frm) = leg.get(0)! else { throw bad(p, "a leg `from` (0) is not a text string (§6.6)") }
        guard leg.has(1) else { throw bad(p, "a leg omits REQUIRED `to` (1) (§6.6)") }
        guard case let .text(to) = leg.get(1)! else { throw bad(p, "a leg `to` (1) is not a text string (§6.6)") }
        guard leg.has(2) else { throw bad(p, "a leg omits REQUIRED `amount` (2) (§6.6)") }
        try validateCommerceAmount(leg.get(2), p)
        if !parties.contains(frm) { throw bad(p, "leg `from` names a party not in `parties` (§6.6)") }
        if !parties.contains(to) { throw bad(p, "leg `to` names a party not in `parties` (§6.6)") }
        try forwardCompatKeys(leg, p)
    }

    private static func validateCommerceNested(_ ft: Int, _ m: CBORMap, _ p: String) throws {
        if ft == commerceMandateCreateReq {
            if let av = m.get(4) { try validateCommerceAmount(av, p) }
        } else if ft == commerceIntentProposeReq {
            var parties = Set<String>()
            if case let .array(pv)? = m.get(2) {
                for party in pv {
                    guard case let .text(s) = party else { throw bad(p, "a `parties` element is not a text string (§6.6)") }
                    parties.insert(s)
                }
            }
            if case let .array(lv)? = m.get(3) {
                for lg in lv { try validateCommerceLeg(lg, parties, p) }
            }
        }
    }

    public static func validateCommercePayload(_ ft: Int, _ payload: [UInt8]) throws -> CBORMap {
        let p = "npamp/commerce: malformed_request"
        guard let schema = commerceSchemas[ft] else { throw bad(p, "\(ft) is not a Commerce operation frame type") }
        let m = try decodeMap(payload, p)
        try checkFrameKind(m, ft, p)
        try checkCorr(m, p)
        try checkFields(m, schema, p)
        try validateCommerceNested(ft, m, p)
        return m
    }

    // ---------- NPAMP-INTERACT (spec/companion/89 §4-§8) ----------

    private static let interactionSchemas: [Int: [Field]] = [
        0x0100: [F(2, .uint, true), F(3, .text, false), F(4, .map, false), F(5, .bool, false)],
        0x0101: [],
        0x0102: [F(2, .uint, true), F(3, .text, true), F(4, .array, false), F(5, .map, false), F(6, .uint, false)],
        0x0103: [F(2, .uint, true)],
        0x0104: [F(2, .text, true), F(3, .uint, false), F(4, .map, false), F(5, .uint, false)],
        0x0105: [F(2, .uint, true), F(3, .text, false)],
        0x0106: [F(2, .uint, false)],
        0x0107: [F(2, .uint, true), F(3, .text, true), F(4, .uint, false), F(5, .text, false)],
    ]

    public static func validateInteractionPayload(_ ft: Int, _ payload: [UInt8]) throws -> CBORMap {
        let p = "npamp/interaction: malformed_request"
        guard let schema = interactionSchemas[ft] else { throw bad(p, "\(ft) is not an Interaction operation frame type") }
        let m = try decodeMap(payload, p)
        try checkFrameKind(m, ft, p)
        try checkCorr(m, p)
        try checkFields(m, schema, p)
        return m
    }

    // ---------- NPAMP-WORKFLOW (spec/companion/8a §4-§8) ----------

    private static let workflowStepEvent = 0x0106
    private static let workflowComplete = 0x0107

    private static let workflowSchemas: [Int: [Field]] = [
        0x0100: [F(2, .text, true), F(3, .bytes, false), F(4, .map, false), F(5, .uint, false),
                 F(6, .text, false), F(7, .text, false), F(8, .text, false), F(9, .text, false),
                 F(10, .map, false), F(11, .uint, true)],
        0x0101: [F(2, .text, true), F(3, .uint, true)],
        0x0102: [F(2, .text, true)],
        0x0103: [F(2, .text, true), F(3, .uint, true), F(4, .uint, false), F(5, .text, false),
                 F(6, .uint, false), F(7, .text, false)],
        0x0104: [F(2, .text, true), F(3, .text, false)],
        0x0105: [F(2, .text, true), F(3, .uint, true)],
        0x0106: [F(2, .text, true), F(3, .uint, true), F(4, .uint, true), F(5, .uint, false),
                 F(6, .text, false), F(7, .uint, false), F(8, .bytes, false), F(9, .text, false)],
        0x0107: [F(2, .text, true), F(3, .uint, true), F(4, .uint, true), F(5, .bytes, false),
                 F(6, .uint, false), F(7, .text, false)],
        0x0108: [F(2, .uint, true), F(3, .text, true), F(4, .uint, false), F(5, .text, false)],
    ]

    public static func validateWorkflowPayload(_ ft: Int, _ payload: [UInt8]) throws -> CBORMap {
        let p = "npamp/workflow: malformed_request"
        guard let schema = workflowSchemas[ft] else { throw bad(p, "\(ft) is not a Workflow frame type") }
        let m = try decodeMap(payload, p)
        try checkFrameKind(m, ft, p)
        // corr (1) is REQUIRED on every corr-bearing frame; the task-scoped
        // WORKFLOW_STEP_EVENT / WORKFLOW_COMPLETE carry no corr (§4.2, §5.2).
        if ft != workflowStepEvent && ft != workflowComplete {
            try checkCorr(m, p)
        }
        try checkFields(m, schema, p)
        return m
    }

    // ---------- NPAMP-KNOWLEDGE (spec/companion/8b §4-§9) ----------

    private static let knowledgeUpdate = 0x0106

    private static let knowledgeSchemas: [Int: [Field]] = [
        0x0100: [F(2, .text, false), F(3, .text, false), F(4, .text, false), F(5, .text, false),
                 F(6, .uint, false), F(8, .text, false), F(9, .bytes, false)],
        0x0101: [F(2, .array, true), F(3, .bool, true), F(4, .bytes, false), F(5, .uint, false), F(6, .bool, false)],
        0x0102: [F(2, .array, true)],
        0x0103: [F(2, .array, false), F(3, .bool, true)],
        0x0104: [F(2, .text, false), F(3, .text, false), F(4, .text, false), F(5, .text, false),
                 F(7, .text, false), F(8, .bool, false), F(9, .uint, true)],
        0x0105: [F(2, .bytes, true), F(3, .uint, true), F(4, .bool, false)],
        0x0106: [F(2, .bytes, true), F(3, .uint, true), F(4, .array, false), F(5, .array, false)],
        0x0107: [F(2, .bytes, true), F(3, .uint, true), F(4, .uint, false)],
        0x0108: [F(2, .bytes, true)],
        0x0109: [F(2, .uint, true), F(3, .text, true), F(4, .uint, false), F(5, .bytes, false)],
    ]

    public static func validateKnowledgePayload(_ ft: Int, _ payload: [UInt8]) throws -> CBORMap {
        let p = "npamp/knowledge: malformed_request"
        guard let schema = knowledgeSchemas[ft] else { throw bad(p, "\(ft) is not a Knowledge operation frame type") }
        let m = try decodeMap(payload, p)
        try checkFrameKind(m, ft, p)
        try checkCorr(m, p)
        try checkFields(m, schema, p)
        // §6.5: a KNOWLEDGE_UPDATE MUST carry at least one of results (4) or removed (5).
        if ft == knowledgeUpdate && !m.has(4) && !m.has(5) {
            throw bad(p, "KNOWLEDGE_UPDATE carries neither results (4) nor removed (5) (§6.5)")
        }
        return m
    }
}

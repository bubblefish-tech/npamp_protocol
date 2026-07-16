<?php

/**
 * N-PAMP native-channel operation-body decoders (draft-bubblefish-npamp-01).
 *
 * Deterministic-CBOR (RFC 8949 §4.2.1 core-deterministic) decode plus the
 * structural MUST-reject enforcement for the eight native operation channels:
 * Capability (§84), Immune (§85), Settlement (§86), Telemetry (§87),
 * Commerce (§88), Interaction (§89), Workflow (§8a), Knowledge (§8b).
 *
 * This is the PHP counterpart of the Go reference (impl/go/{memory_cbor,
 * capability_bodies, immune_bodies, settlement_bodies, telemetry_bodies,
 * commerce_bodies, interaction_bodies, workflow_bodies, knowledge_bodies}.go).
 * It matches the behaviour, not the syntax: same deterministic-CBOR subset, same
 * common envelope (frame_kind + corr), same per-frame key schemas, same
 * forward-compatibility rule (accept unknown non-negative integer keys, reject
 * unknown negative or non-integer keys), and the same channel-specific nested and
 * cross-field MUST-reject clauses.
 *
 * No external dependency: the CBOR codec is pure PHP (there is no ext-cbor in the
 * base install and the deterministic subset a receiver MUST reject is narrower
 * than a general library's accept set anyway).
 */

declare(strict_types=1);

namespace Sh\Bubblefish\Npamp;

/**
 * Raised when input is not valid *deterministic* CBOR: truncated, trailing bytes
 * after the top-level item, an integer/length not in shortest form, an
 * indefinite-length item, a float / unsupported simple value, a tag, or map keys
 * that are not in strictly-ascending canonical order (which also rejects a
 * duplicate key). These are exactly the encodings a deterministic-encoding
 * receiver MUST reject (RFC 8949 §4.2.1).
 */
final class CborException extends \RuntimeException
{
}

/**
 * Raised when a payload is well-formed deterministic CBOR but violates a channel
 * body contract: not a map, a frame_kind that contradicts the frame type, a
 * missing/mistyped corr, a missing required field, a field of the wrong CBOR
 * major type, an unknown negative / non-integer key, or a channel-specific nested
 * or cross-field rule (spec §4-§9, malformed_request).
 */
final class BodyException extends \RuntimeException
{
}

/** A CBOR unsigned integer (major type 0). */
final class CUint
{
    public function __construct(public int $v)
    {
    }
}

/** A CBOR negative integer (major type 1); $v is the (negative) integer value. */
final class CNint
{
    public function __construct(public int $v)
    {
    }
}

/** A CBOR byte string (major type 2). $v holds the raw bytes. */
final class CBytes
{
    public function __construct(public string $v)
    {
    }
}

/** A CBOR text string (major type 3). $v holds the UTF-8 bytes. */
final class CText
{
    public function __construct(public string $v)
    {
    }
}

/** A CBOR array (major type 4). $v is a list of decoded values. */
final class CArr
{
    /** @param array<int,mixed> $v */
    public function __construct(public array $v)
    {
    }
}

/** One entry of a decoded CBOR map: the canonical key encoding, key, and value. */
final class CborEntry
{
    public function __construct(public string $keyEnc, public mixed $key, public mixed $val)
    {
    }
}

/**
 * A CBOR map (major type 5) preserving canonical (bytewise-of-encoded-key) order.
 * Keys are themselves decoded CBOR values; entries are kept in the order the
 * deterministic decoder accepted them (which it proved to be strictly ascending).
 */
final class CMap
{
    /** @param CborEntry[] $entries */
    public function __construct(public array $entries)
    {
    }

    /**
     * Look up the value for an unsigned-integer key (the form every N-PAMP
     * envelope/body key takes). Returns [value, present].
     *
     * @return array{0:mixed,1:bool}
     */
    public function get(int $uintKey): array
    {
        $ke = self::encodeUintHead($uintKey);
        foreach ($this->entries as $e) {
            if ($e->keyEnc === $ke) {
                return [$e->val, true];
            }
        }
        return [null, false];
    }

    /**
     * Canonical CBOR encoding of an unsigned-integer key (major 0, shortest form).
     * Used to match the keyEnc captured verbatim by the decoder, so lookups agree
     * with the on-wire canonical form byte-for-byte.
     */
    public static function encodeUintHead(int $arg): string
    {
        $mb = 0x00; // major 0 << 5
        if ($arg < 24) {
            return chr($mb | $arg);
        }
        if ($arg < 0x100) {
            return chr($mb | 24) . chr($arg);
        }
        if ($arg < 0x10000) {
            return chr($mb | 25) . pack('n', $arg);
        }
        if ($arg < 0x100000000) {
            return chr($mb | 26) . pack('N', $arg);
        }
        return chr($mb | 27) . pack('J', $arg);
    }
}

/**
 * Minimal deterministic (canonical) CBOR decoder for N-PAMP operation bodies.
 *
 * Accepts exactly the subset the native bodies use — unsigned integers, negative
 * integers, byte strings, text strings, arrays, maps, and the simple values
 * false/true/null — all definite-length, shortest-form, with map keys in canonical
 * ascending order. It REJECTS everything outside that subset (indefinite lengths,
 * non-shortest integer/length encodings, tags, floats, other simple values, and
 * out-of-order or duplicate map keys), which is precisely what a
 * deterministic-encoding receiver MUST reject.
 */
final class Cbor
{
    /**
     * Decode a single deterministic-CBOR item and require that it consumes all of
     * $b (no trailing bytes) — the shape of a frame payload.
     */
    public static function decodeTop(string $b): mixed
    {
        [$v, $n] = self::decode($b, 0);
        if ($n !== strlen($b)) {
            throw new CborException('npamp/cbor: trailing bytes after top-level item');
        }
        return $v;
    }

    /**
     * Decode one item at offset $off. Returns [value, nextOffset]. Enforces the
     * deterministic subset strictly.
     *
     * @return array{0:mixed,1:int}
     */
    private static function decode(string $b, int $off): array
    {
        $len = strlen($b);
        if ($off >= $len) {
            throw new CborException('npamp/cbor: truncated input');
        }
        $ib = ord($b[$off]);
        $major = $ib >> 5;
        $ai = $ib & 0x1f;

        if ($major === 7) {
            // Simple values / floats: only false(20)/true(21)/null(22) are in the
            // deterministic subset. Floats (25/26/27), other simple values, and the
            // break stop (31) are rejected.
            switch ($ai) {
                case 20:
                    return [false, $off + 1];
                case 21:
                    return [true, $off + 1];
                case 22:
                    return [null, $off + 1];
                default:
                    throw new CborException('npamp/cbor: unsupported simple value or float');
            }
        }

        [$arg, $hdr] = self::decodeArg($ai, $b, $off);
        $n = $off + $hdr;

        switch ($major) {
            case 0: // unsigned int
                return [new CUint($arg), $n];
            case 1: // negative int: value = -1 - arg
                if ($arg < 0) {
                    // $arg overflowed PHP_INT (>= 2^63): out of int64 range, not used
                    // by any native body — reject rather than wrap to a bogus value.
                    throw new CborException('npamp/cbor: negative integer out of range');
                }
                return [new CNint(-1 - $arg), $n];
            case 2: // byte string
            case 3: // text string
                $end = $n + $arg;
                if ($arg < 0 || $end > $len || $end < $n) {
                    throw new CborException('npamp/cbor: truncated string');
                }
                $payload = $arg === 0 ? '' : substr($b, $n, $arg);
                return [$major === 2 ? new CBytes($payload) : new CText($payload), $end];
            case 4: // array
                // Each element is at least one byte, so a declared count larger than
                // the remaining input cannot be satisfied — reject before allocating
                // on the attacker-controlled count.
                if ($arg < 0 || $arg > ($len - $n)) {
                    throw new CborException('npamp/cbor: truncated array');
                }
                $items = [];
                $o = $n;
                for ($i = 0; $i < $arg; $i++) {
                    [$el, $eo] = self::decode($b, $o);
                    $items[] = $el;
                    $o = $eo;
                }
                return [new CArr($items), $o];
            case 5: // map
                if ($arg < 0 || $arg > ($len - $n)) {
                    throw new CborException('npamp/cbor: truncated map');
                }
                $entries = [];
                $o = $n;
                $prevKeyEnc = null;
                for ($i = 0; $i < $arg; $i++) {
                    $keyStart = $o;
                    [$key, $ko] = self::decode($b, $o);
                    $keyEnc = substr($b, $keyStart, $ko - $keyStart);
                    // Canonical order: each key MUST sort strictly after the previous
                    // one (this also rejects a duplicate key).
                    if ($prevKeyEnc !== null && !self::byteLess($prevKeyEnc, $keyEnc)) {
                        throw new CborException('npamp/cbor: map keys not in canonical ascending order (or duplicate)');
                    }
                    $prevKeyEnc = $keyEnc;
                    $o = $ko;
                    [$val, $vo] = self::decode($b, $o);
                    $o = $vo;
                    $entries[] = new CborEntry($keyEnc, $key, $val);
                }
                return [new CMap($entries), $o];
            default: // major 6 (tags) — unsupported in the deterministic subset
                throw new CborException('npamp/cbor: unsupported major type (tag)');
        }
    }

    /**
     * Read the argument for additional-information $ai from b[$off], enforcing
     * shortest-form (RFC 8949 §4.2.1) and rejecting indefinite lengths. Returns
     * [argument, headerLength]. The shortest-form checks compare the high bytes to
     * zero (equivalent to the value < 1<<k tests) so no wide-integer arithmetic is
     * needed.
     *
     * @return array{0:int,1:int}
     */
    private static function decodeArg(int $ai, string $b, int $off): array
    {
        $len = strlen($b);
        if ($ai < 24) {
            return [$ai, 1];
        }
        if ($ai === 24) {
            if ($off + 2 > $len) {
                throw new CborException('npamp/cbor: truncated argument');
            }
            $v = ord($b[$off + 1]);
            if ($v < 24) { // could have fit in the initial byte
                throw new CborException('npamp/cbor: integer/length not in shortest form');
            }
            return [$v, 2];
        }
        if ($ai === 25) {
            if ($off + 3 > $len) {
                throw new CborException('npamp/cbor: truncated argument');
            }
            if (ord($b[$off + 1]) === 0) { // high byte zero => value < 256
                throw new CborException('npamp/cbor: integer/length not in shortest form');
            }
            $v = (ord($b[$off + 1]) << 8) | ord($b[$off + 2]);
            return [$v, 3];
        }
        if ($ai === 26) {
            if ($off + 5 > $len) {
                throw new CborException('npamp/cbor: truncated argument');
            }
            if (ord($b[$off + 1]) === 0 && ord($b[$off + 2]) === 0) { // value < 1<<16
                throw new CborException('npamp/cbor: integer/length not in shortest form');
            }
            /** @var array{1:int} $u */
            $u = unpack('N', substr($b, $off + 1, 4));
            return [$u[1], 5];
        }
        if ($ai === 27) {
            if ($off + 9 > $len) {
                throw new CborException('npamp/cbor: truncated argument');
            }
            if (substr($b, $off + 1, 4) === "\x00\x00\x00\x00") { // value < 1<<32
                throw new CborException('npamp/cbor: integer/length not in shortest form');
            }
            /** @var array{1:int} $u */
            $u = unpack('J', substr($b, $off + 1, 8));
            return [$u[1], 9]; // may be negative on >=2^63 overflow; callers guard
        }
        if ($ai === 31) {
            throw new CborException('npamp/cbor: indefinite-length item (non-deterministic)');
        }
        // 28, 29, 30 are reserved.
        throw new CborException('npamp/cbor: reserved additional-information value');
    }

    /**
     * Report whether $a sorts strictly before $b in bytewise (shorter-prefix-first,
     * then lexicographic-by-unsigned-byte) order — RFC 8949 §4.2.1 canonical
     * map-key ordering.
     */
    private static function byteLess(string $a, string $b): bool
    {
        $la = strlen($a);
        $lb = strlen($b);
        if ($la !== $lb) {
            return $la < $lb;
        }
        return strcmp($a, $b) < 0;
    }
}

/**
 * Structural decoders + MUST-reject enforcement for the eight native operation
 * channels. Each public decoder returns the decoded envelope map (a CMap) on
 * success and throws BodyException / CborException on any MUST-reject input.
 */
final class Bodies
{
    // Expected CBOR kinds for a body field.
    public const K_UINT = 0;
    public const K_TEXT = 1;
    public const K_BYTES = 2;
    public const K_ARRAY = 3;
    public const K_MAP = 4;
    public const K_BOOL = 5;
    // K_NUMBER: a CBOR unsigned int OR a negative int (Telemetry MetricSample value
    // §5.1, Commerce amount units §4.3). Floats are outside the deterministic subset.
    public const K_NUMBER = 6;

    private static function kindOk(mixed $v, int $k): bool
    {
        switch ($k) {
            case self::K_UINT:
                return $v instanceof CUint;
            case self::K_TEXT:
                return $v instanceof CText;
            case self::K_BYTES:
                return $v instanceof CBytes;
            case self::K_ARRAY:
                return $v instanceof CArr;
            case self::K_MAP:
                return $v instanceof CMap;
            case self::K_BOOL:
                return is_bool($v);
            case self::K_NUMBER:
                return $v instanceof CUint || $v instanceof CNint;
            default:
                return false;
        }
    }

    /**
     * Enforce a schema's required/typed fields, then the forward-compatibility key
     * rule, on a decoded map. Envelope keys (0/1) are validated by the caller; they
     * are tolerated here by the forward-compat scan (they are non-negative keys).
     *
     * @param array<int,array{0:int,1:int,2:bool}> $schema list of [key, kind, required]
     */
    private static function checkFields(CMap $m, array $schema): void
    {
        foreach ($schema as $f) {
            [$key, $kind, $required] = $f;
            [$val, $present] = $m->get($key);
            if (!$present) {
                if ($required) {
                    throw new BodyException("missing required field (key $key)");
                }
                continue;
            }
            if (!self::kindOk($val, $kind)) {
                throw new BodyException("field (key $key) has the wrong CBOR type");
            }
        }
        self::forwardCompat($m);
    }

    /**
     * Forward compatibility: accept an unknown non-negative integer key; reject an
     * unknown negative integer key or any non-integer key.
     */
    private static function forwardCompat(CMap $m): void
    {
        foreach ($m->entries as $e) {
            $k = $e->key;
            if ($k instanceof CUint) {
                continue; // known or unknown-non-negative: both accepted
            }
            if ($k instanceof CNint) {
                throw new BodyException('unknown negative key (reserved)');
            }
            throw new BodyException('non-integer map key');
        }
    }

    /** Decode the top-level payload and require it to be a CBOR map. */
    private static function decodeMap(string $body): CMap
    {
        $v = Cbor::decodeTop($body);
        if (!($v instanceof CMap)) {
            throw new BodyException('payload is not a CBOR map');
        }
        return $v;
    }

    /** frame_kind (0) MUST be an unsigned int equal to the frame type. */
    private static function requireFrameKind(CMap $m, int $ft): void
    {
        [$fk, $ok] = $m->get(0);
        if (!$ok) {
            throw new BodyException('missing frame_kind (0)');
        }
        if (!($fk instanceof CUint)) {
            throw new BodyException('frame_kind (0) is not an unsigned int');
        }
        if ($fk->v !== $ft) {
            throw new BodyException('frame_kind contradicts frame type');
        }
    }

    /** corr (1) MUST be a byte string of 1-64 bytes. */
    private static function requireCorr(CMap $m): void
    {
        [$corr, $ok] = $m->get(1);
        if (!$ok) {
            throw new BodyException('missing corr (1)');
        }
        if (!($corr instanceof CBytes) || strlen($corr->v) < 1 || strlen($corr->v) > 64) {
            throw new BodyException('corr (1) must be a byte string of 1-64 bytes');
        }
    }

    // ---------------------------------------------------------------------
    // Dispatch
    // ---------------------------------------------------------------------

    /**
     * Decode + validate a native body for the given corpus op-group.
     * $op is one of the eight "<channel>.body.decode" op strings.
     */
    public static function decode(string $op, int $ft, string $body): CMap
    {
        switch ($op) {
            case 'capability.body.decode':
                return self::capability($ft, $body);
            case 'immune.body.decode':
                return self::immune($ft, $body);
            case 'settlement.body.decode':
                return self::settlement($ft, $body);
            case 'telemetry.body.decode':
                return self::telemetry($ft, $body);
            case 'commerce.body.decode':
                return self::commerce($ft, $body);
            case 'interaction.body.decode':
                return self::interaction($ft, $body);
            case 'workflow.body.decode':
                return self::workflow($ft, $body);
            case 'knowledge.body.decode':
                return self::knowledge($ft, $body);
            default:
                throw new BodyException("unknown op-group $op");
        }
    }

    // ---------------------------------------------------------------------
    // Capability (spec/companion/84) — envelope frame_kind + byte-string corr.
    // ---------------------------------------------------------------------

    /** @return array<int,array<int,array{0:int,1:int,2:bool}>> */
    private static function capabilitySchemas(): array
    {
        [$u, $t, $b, $a, $m, $bo] = [self::K_UINT, self::K_TEXT, self::K_BYTES, self::K_ARRAY, self::K_MAP, self::K_BOOL];
        return [
            0x0100 => [[2, $t, true], [3, $t, true], [4, $m, false], [5, $t, false], [6, $t, false], [7, $u, false], [8, $t, false], [9, $u, true]],
            0x0101 => [[2, $m, true], [3, $t, true]],
            0x0102 => [[2, $t, true], [3, $t, true], [4, $m, false], [5, $t, false], [6, $u, false], [7, $u, true]],
            0x0103 => [[2, $m, true], [3, $t, true]],
            0x0104 => [[2, $t, true], [3, $bo, false], [4, $t, false], [5, $u, true]],
            0x0105 => [[2, $t, true], [3, $t, true], [4, $u, false]],
            0x0106 => [[2, $t, false], [3, $t, false], [4, $t, false], [5, $bo, false], [6, $u, false], [7, $b, false], [8, $u, true]],
            0x0107 => [[2, $a, true], [3, $bo, true], [4, $b, false]],
            0x0108 => [[2, $u, true], [3, $t, true], [4, $u, false], [5, $t, false]],
            0x0060 => [[2, $m, true], [3, $a, false], [4, $u, true]],
            0x0061 => [[2, $t, true], [3, $t, true]],
            0x0062 => [[2, $t, true], [3, $b, true], [4, $u, true]],
            0x0063 => [[2, $t, true], [3, $b, true]],
        ];
    }

    private static function capability(int $ft, string $body): CMap
    {
        $schemas = self::capabilitySchemas();
        if (!isset($schemas[$ft])) {
            throw new BodyException('not a Capability operation frame type');
        }
        $m = self::decodeMap($body);
        self::requireFrameKind($m, $ft);
        self::requireCorr($m);
        self::checkFields($m, $schemas[$ft]);
        return $m;
    }

    // ---------------------------------------------------------------------
    // Immune (spec/companion/85) — envelope + nested gossip descriptor/item.
    // ---------------------------------------------------------------------

    private static function immune(int $ft, string $body): CMap
    {
        [$u, $t, $b, $a, $bo] = [self::K_UINT, self::K_TEXT, self::K_BYTES, self::K_ARRAY, self::K_BOOL];
        $schemas = [
            0x0100 => [[2, $t, true], [3, $u, true], [4, $u, true], [5, $t, false], [6, $t, false], [7, $t, false], [8, $b, false], [9, $u, false], [10, $t, false]],
            0x0101 => [[2, $u, true], [3, $t, false]],
            0x0102 => [[2, $u, true], [3, $t, true], [4, $u, false]],
            0x00C0 => [[2, $a, true], [3, $bo, false]],
            0x00C1 => [[2, $a, false], [3, $a, false], [4, $u, false]],
            0x00C2 => [[2, $a, true]],
            0x00C3 => [[2, $a, true]],
            0x00C4 => [[2, $b, true], [3, $u, true], [4, $u, false]],
        ];
        if (!isset($schemas[$ft])) {
            throw new BodyException('not an Immune operation frame type');
        }
        $m = self::decodeMap($body);
        self::requireFrameKind($m, $ft);
        self::requireCorr($m);
        self::checkFields($m, $schemas[$ft]);

        // §6.4 gossip_descriptor / §6.5 gossip_item nested required-key enforcement.
        $descriptorSchema = [[0, $b, true], [1, $u, true], [2, $u, false], [3, $u, false], [4, $b, false], [5, $t, false], [6, $t, false], [7, $u, false], [8, $b, false], [9, $b, false]];
        $itemSchema = [[0, $b, true], [1, $u, true], [2, $u, false], [3, $u, false], [4, $b, false], [5, $t, false], [6, $t, false], [7, $u, false], [8, $b, true]];
        if ($ft === 0x00C0) {
            self::validateGossipArray($m, $descriptorSchema);
        } elseif ($ft === 0x00C3) {
            self::validateGossipArray($m, $itemSchema);
        }
        return $m;
    }

    /**
     * Validate each element of the items(2) array of a gossip frame against a
     * nested schema (each element is a map with keys starting at 0, no envelope).
     * An empty array is permitted.
     *
     * @param array<int,array{0:int,1:int,2:bool}> $nested
     */
    private static function validateGossipArray(CMap $m, array $nested): void
    {
        [$itemsV, $ok] = $m->get(2);
        if (!$ok || !($itemsV instanceof CArr)) {
            throw new BodyException('gossip items (2) is not an array');
        }
        foreach ($itemsV->v as $el) {
            if (!($el instanceof CMap)) {
                throw new BodyException('a gossip item is not a CBOR map');
            }
            self::checkFields($el, $nested);
        }
    }

    // ---------------------------------------------------------------------
    // Settlement (spec/companion/86) — envelope + schema.
    // ---------------------------------------------------------------------

    private static function settlement(int $ft, string $body): CMap
    {
        [$u, $t, $b, $m2] = [self::K_UINT, self::K_TEXT, self::K_BYTES, self::K_MAP];
        $schemas = [
            0x0100 => [[2, $t, true], [3, $t, false], [4, $t, false], [5, $t, false], [6, $t, false], [7, $t, false], [8, $u, true]],
            0x0101 => [[2, $t, true], [3, $t, true], [4, $t, false]],
            0x0102 => [[2, $t, true], [3, $t, false], [4, $u, true]],
            0x0103 => [[2, $m2, true]],
            0x0104 => [[2, $u, true], [3, $t, true], [4, $u, false], [5, $t, false]],
            0x00A0 => [[2, $t, true], [3, $b, true], [4, $t, false], [5, $u, false], [6, $t, false], [7, $u, true]],
            0x00A1 => [[2, $t, true], [3, $t, true], [4, $t, false]],
        ];
        if (!isset($schemas[$ft])) {
            throw new BodyException('not a Settlement operation frame type');
        }
        $m = self::decodeMap($body);
        self::requireFrameKind($m, $ft);
        self::requireCorr($m);
        self::checkFields($m, $schemas[$ft]);
        return $m;
    }

    // ---------------------------------------------------------------------
    // Telemetry (spec/companion/87) — conditional corr; REPORT content rule.
    // ---------------------------------------------------------------------

    private static function telemetry(int $ft, string $body): CMap
    {
        [$u, $t, $b, $a, $n] = [self::K_UINT, self::K_TEXT, self::K_BYTES, self::K_ARRAY, self::K_NUMBER];
        $schemas = [
            0x0101 => [[2, $a, false], [3, $a, false], [4, $a, false], [5, $u, false], [6, $u, false], [7, $u, true]],
            0x0102 => [[2, $b, true], [3, $u, true], [4, $a, false]],
            0x0103 => [[2, $b, true]],
            0x0104 => [[2, $b, true], [3, $u, true], [4, $u, false]],
            0x0105 => [[2, $u, true], [3, $t, false], [4, $b, false]],
        ];
        // Telemetry frame set: REPORT (0x0100) plus the schema'd frames.
        if ($ft !== 0x0100 && !isset($schemas[$ft])) {
            throw new BodyException('not a Telemetry operation frame type');
        }
        $m = self::decodeMap($body);
        self::requireFrameKind($m, $ft);

        if ($ft === 0x0100) {
            return self::telemetryReport($m);
        }

        // Every non-REPORT Telemetry frame carries a REQUIRED corr (§4.1).
        self::requireCorr($m);
        self::checkFields($m, $schemas[$ft]);
        return $m;
    }

    /**
     * TELEMETRY_REPORT (§5): corr (1) is CONDITIONAL — present iff the batch answers
     * a subscription, in which case sub_id (2) MUST also be present (a byte string);
     * a standalone report MUST omit both. batch_seq (3) is REQUIRED. At least one of
     * metrics (4) / events (5) / health (6) MUST be present and non-empty, and every
     * element of a present array is validated against its nested schema.
     */
    private static function telemetryReport(CMap $m): CMap
    {
        $nn = self::K_NUMBER;
        $u = self::K_UINT;
        $t = self::K_TEXT;
        $mp = self::K_MAP;
        $metricSchema = [[0, $t, true], [1, $u, true], [2, $u, true], [3, $nn, true], [4, $t, false], [5, $mp, false], [6, $u, false]];
        $eventSchema = [[0, $t, true], [1, $u, true], [2, $u, false], [3, $mp, false], [4, $t, false], [5, $u, false]];
        $healthSchema = [[0, $t, true], [1, $u, true], [2, $u, true], [3, $t, false], [4, $mp, false]];

        [$corr, $hasCorr] = $m->get(1);
        [$sub, $hasSubID] = $m->get(2);
        if ($hasCorr) {
            if (!($corr instanceof CBytes) || strlen($corr->v) < 1 || strlen($corr->v) > 64) {
                throw new BodyException('corr (1) must be a byte string of 1-64 bytes');
            }
            if (!$hasSubID) {
                throw new BodyException('subscribed report carries corr (1) but omits sub_id (2)');
            }
            if (!($sub instanceof CBytes)) {
                throw new BodyException('sub_id (2) must be a byte string');
            }
        } elseif ($hasSubID) {
            throw new BodyException('standalone report carries sub_id (2) without corr (1)');
        }

        [$bs, $okBs] = $m->get(3);
        if (!$okBs) {
            throw new BodyException('missing required batch_seq (3)');
        }
        if (!($bs instanceof CUint)) {
            throw new BodyException('batch_seq (3) is not an unsigned int');
        }

        $nonEmpty = 0;
        foreach ([[4, $metricSchema], [5, $eventSchema], [6, $healthSchema]] as $c) {
            [$key, $schema] = $c;
            [$val, $present] = $m->get($key);
            if (!$present) {
                continue;
            }
            if (!($val instanceof CArr)) {
                throw new BodyException("content array (key $key) is not a CBOR array");
            }
            if (count($val->v) > 0) {
                $nonEmpty++;
            }
            foreach ($val->v as $el) {
                if (!($el instanceof CMap)) {
                    throw new BodyException('a content array element is not a CBOR map');
                }
                self::checkFields($el, $schema);
            }
        }
        if ($nonEmpty === 0) {
            throw new BodyException('TELEMETRY_REPORT carries no metrics, events, or health');
        }

        self::forwardCompat($m);
        return $m;
    }

    // ---------------------------------------------------------------------
    // Commerce (spec/companion/88) — envelope + nested amount / leg-party.
    // ---------------------------------------------------------------------

    private static function commerce(int $ft, string $body): CMap
    {
        [$u, $t, $b, $a, $m2] = [self::K_UINT, self::K_TEXT, self::K_BYTES, self::K_ARRAY, self::K_MAP];
        $schemas = [
            0x0100 => [[2, $t, true], [3, $t, true], [4, $m2, true], [5, $t, false], [6, $t, false], [7, $t, false], [8, $m2, false], [9, $t, false], [10, $b, false], [11, $t, false], [12, $t, false], [13, $u, true]],
            0x0101 => [[2, $t, true], [3, $t, true]],
            0x0102 => [[2, $t, true], [3, $u, true]],
            0x0103 => [[2, $m2, true]],
            0x0104 => [[2, $t, true], [3, $t, false], [4, $u, true]],
            0x0105 => [[2, $t, true], [3, $t, true]],
            0x0106 => [[2, $t, true], [3, $u, true]],
            0x0107 => [[2, $t, true], [3, $t, true], [4, $t, false]],
            0x0108 => [[2, $a, true], [3, $a, true], [4, $t, false], [5, $m2, false], [6, $t, false], [7, $u, true]],
            0x0109 => [[2, $t, true], [3, $t, true]],
            0x010A => [[2, $t, true], [3, $u, true], [4, $a, false], [5, $t, false], [6, $u, true]],
            0x010B => [[2, $t, true], [3, $t, true]],
            0x010C => [[2, $t, true], [3, $u, true]],
            0x010D => [[2, $t, true], [3, $t, true], [4, $a, false], [5, $a, false]],
            0x010E => [[2, $u, true], [3, $t, true], [4, $u, false], [5, $t, false]],
        ];
        if (!isset($schemas[$ft])) {
            throw new BodyException('not a Commerce operation frame type');
        }
        $m = self::decodeMap($body);
        self::requireFrameKind($m, $ft);
        self::requireCorr($m);
        self::checkFields($m, $schemas[$ft]);

        if ($ft === 0x0100) {
            // §6.1: amount (4) is REQUIRED and is a §4.3 monetary amount.
            [$av, $ok] = $m->get(4);
            if ($ok) {
                self::commerceAmount($av);
            }
        } elseif ($ft === 0x0108) {
            // §6.6: every settlement leg's from/to MUST be a named party.
            $parties = self::commerceParties($m);
            [$lv] = $m->get(3);
            $legs = $lv instanceof CArr ? $lv->v : [];
            foreach ($legs as $lg) {
                self::commerceLeg($lg, $parties);
            }
        }
        return $m;
    }

    /**
     * §4.3 monetary amount: units (0) a signed integer, scale (1) an unsigned int,
     * currency (2) a text string — all REQUIRED — plus the forward-compat key rule.
     */
    private static function commerceAmount(mixed $v): void
    {
        if (!($v instanceof CMap)) {
            throw new BodyException('`amount` is not a CBOR map (§4.3)');
        }
        [$units, $ok] = $v->get(0);
        if (!$ok) {
            throw new BodyException('`amount` omits REQUIRED units (0) (§4.3)');
        }
        if (!($units instanceof CUint) && !($units instanceof CNint)) {
            throw new BodyException('`amount` units (0) is not an integer (§4.3)');
        }
        [$scale, $ok] = $v->get(1);
        if (!$ok || !($scale instanceof CUint)) {
            throw new BodyException('`amount` scale (1) is not an unsigned int (§4.3)');
        }
        [$cur, $ok] = $v->get(2);
        if (!$ok || !($cur instanceof CText)) {
            throw new BodyException('`amount` currency (2) is not a text string (§4.3)');
        }
        self::forwardCompat($v);
    }

    /**
     * Read the `parties` array (key 2) of a settlement-intent proposal into a set,
     * rejecting a non-text element (§6.6).
     *
     * @return array<string,bool>
     */
    private static function commerceParties(CMap $m): array
    {
        [$pv] = $m->get(2);
        $arr = $pv instanceof CArr ? $pv->v : [];
        $set = [];
        foreach ($arr as $p) {
            if (!($p instanceof CText)) {
                throw new BodyException('a `parties` element is not a text string (§6.6)');
            }
            $set[$p->v] = true;
        }
        return $set;
    }

    /**
     * §6.6 leg shape { from (0): tstr, to (1): tstr, amount (2): amount } where
     * from/to MUST be named parties; validates the nested amount and forward-compat.
     *
     * @param array<string,bool> $parties
     */
    private static function commerceLeg(mixed $v, array $parties): void
    {
        if (!($v instanceof CMap)) {
            throw new BodyException('a settlement leg is not a CBOR map (§6.6)');
        }
        [$frm, $ok] = $v->get(0);
        if (!$ok || !($frm instanceof CText)) {
            throw new BodyException('a leg `from` (0) is missing or not a text string (§6.6)');
        }
        [$to, $ok] = $v->get(1);
        if (!$ok || !($to instanceof CText)) {
            throw new BodyException('a leg `to` (1) is missing or not a text string (§6.6)');
        }
        [$amt, $ok] = $v->get(2);
        if (!$ok) {
            throw new BodyException('a leg omits REQUIRED `amount` (2) (§6.6)');
        }
        self::commerceAmount($amt);
        if (!isset($parties[$frm->v])) {
            throw new BodyException('leg `from` names a party not in `parties` (§6.6)');
        }
        if (!isset($parties[$to->v])) {
            throw new BodyException('leg `to` names a party not in `parties` (§6.6)');
        }
        self::forwardCompat($v);
    }

    // ---------------------------------------------------------------------
    // Interaction (spec/companion/89) — envelope + schema.
    // ---------------------------------------------------------------------

    private static function interaction(int $ft, string $body): CMap
    {
        [$u, $t, $a, $m2, $bo] = [self::K_UINT, self::K_TEXT, self::K_ARRAY, self::K_MAP, self::K_BOOL];
        $schemas = [
            0x0100 => [[2, $u, true], [3, $t, false], [4, $m2, false], [5, $bo, false]],
            0x0101 => [],
            0x0102 => [[2, $u, true], [3, $t, true], [4, $a, false], [5, $m2, false], [6, $u, false]],
            0x0103 => [[2, $u, true]],
            0x0104 => [[2, $t, true], [3, $u, false], [4, $m2, false], [5, $u, false]],
            0x0105 => [[2, $u, true], [3, $t, false]],
            0x0106 => [[2, $u, false]],
            0x0107 => [[2, $u, true], [3, $t, true], [4, $u, false], [5, $t, false]],
        ];
        if (!isset($schemas[$ft])) {
            throw new BodyException('not an Interaction operation frame type');
        }
        $m = self::decodeMap($body);
        self::requireFrameKind($m, $ft);
        self::requireCorr($m);
        self::checkFields($m, $schemas[$ft]);
        return $m;
    }

    // ---------------------------------------------------------------------
    // Workflow (spec/companion/8a) — conditional corr (STEP_EVENT/COMPLETE none).
    // ---------------------------------------------------------------------

    private static function workflow(int $ft, string $body): CMap
    {
        [$u, $t, $b, $m2] = [self::K_UINT, self::K_TEXT, self::K_BYTES, self::K_MAP];
        $schemas = [
            0x0100 => [[2, $t, true], [3, $b, false], [4, $m2, false], [5, $u, false], [6, $t, false], [7, $t, false], [8, $t, false], [9, $t, false], [10, $m2, false], [11, $u, true]],
            0x0101 => [[2, $t, true], [3, $u, true]],
            0x0102 => [[2, $t, true]],
            0x0103 => [[2, $t, true], [3, $u, true], [4, $u, false], [5, $t, false], [6, $u, false], [7, $t, false]],
            0x0104 => [[2, $t, true], [3, $t, false]],
            0x0105 => [[2, $t, true], [3, $u, true]],
            0x0106 => [[2, $t, true], [3, $u, true], [4, $u, true], [5, $u, false], [6, $t, false], [7, $u, false], [8, $b, false], [9, $t, false]],
            0x0107 => [[2, $t, true], [3, $u, true], [4, $u, true], [5, $b, false], [6, $u, false], [7, $t, false]],
            0x0108 => [[2, $u, true], [3, $t, true], [4, $u, false], [5, $t, false]],
        ];
        if (!isset($schemas[$ft])) {
            throw new BodyException('not a Workflow frame type');
        }
        $m = self::decodeMap($body);
        self::requireFrameKind($m, $ft);
        // STEP_EVENT (0x0106) and COMPLETE (0x0107) carry NO corr (§4.2, §5.2).
        if ($ft !== 0x0106 && $ft !== 0x0107) {
            self::requireCorr($m);
        }
        self::checkFields($m, $schemas[$ft]);
        return $m;
    }

    // ---------------------------------------------------------------------
    // Knowledge (spec/companion/8b) — envelope + UPDATE results-or-removed.
    // ---------------------------------------------------------------------

    private static function knowledge(int $ft, string $body): CMap
    {
        [$u, $t, $b, $a, $bo] = [self::K_UINT, self::K_TEXT, self::K_BYTES, self::K_ARRAY, self::K_BOOL];
        $schemas = [
            0x0100 => [[2, $t, false], [3, $t, false], [4, $t, false], [5, $t, false], [6, $u, false], [8, $t, false], [9, $b, false]],
            0x0101 => [[2, $a, true], [3, $bo, true], [4, $b, false], [5, $u, false], [6, $bo, false]],
            0x0102 => [[2, $a, true]],
            0x0103 => [[2, $a, false], [3, $bo, true]],
            0x0104 => [[2, $t, false], [3, $t, false], [4, $t, false], [5, $t, false], [7, $t, false], [8, $bo, false], [9, $u, true]],
            0x0105 => [[2, $b, true], [3, $u, true], [4, $bo, false]],
            0x0106 => [[2, $b, true], [3, $u, true], [4, $a, false], [5, $a, false]],
            0x0107 => [[2, $b, true], [3, $u, true], [4, $u, false]],
            0x0108 => [[2, $b, true]],
            0x0109 => [[2, $u, true], [3, $t, true], [4, $u, false], [5, $b, false]],
        ];
        if (!isset($schemas[$ft])) {
            throw new BodyException('not a Knowledge operation frame type');
        }
        $m = self::decodeMap($body);
        self::requireFrameKind($m, $ft);
        self::requireCorr($m);
        self::checkFields($m, $schemas[$ft]);

        // §6.5: a KNOWLEDGE_UPDATE MUST carry at least one of results (4) or removed (5).
        if ($ft === 0x0106) {
            [, $hasResults] = $m->get(4);
            [, $hasRemoved] = $m->get(5);
            if (!$hasResults && !$hasRemoved) {
                throw new BodyException('KNOWLEDGE_UPDATE carries neither results (4) nor removed (5) (§6.5)');
            }
        }
        return $m;
    }
}

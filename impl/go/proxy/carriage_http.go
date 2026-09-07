// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"fmt"
	"net/http"
	"sort"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// httpCarriageKind is the NPAMP-CC-HTTP §4.2 key-1 `kind` discriminant. Only the
// two non-streaming kinds are implemented (see doc.go, "Not yet built").
type httpCarriageKind uint64

const (
	httpKindRequest  httpCarriageKind = 1
	httpKindResponse httpCarriageKind = 2
	// httpKindStreamData = 3, httpKindStreamEnd = 4 -- NOT YET BUILT (doc.go).
)

// httpCarriageObject is the decoded form of NPAMP-CC-HTTP §4's HTTP-Carriage
// Object. Field names/comments cite the §4.2 object-key table; only the keys this
// build carries (1,2,3,6,8,9) are represented -- authority (4), scheme (5), reason
// (7), trailers (10), and passthrough (11) are NOT YET BUILT (doc.go) and are
// never emitted or expected.
type httpCarriageObject struct {
	Kind    httpCarriageKind
	Method  string     // key 2, request only
	Target  string     // key 3, request only
	Status  int        // key 6, response only
	Headers []headerKV // key 8, both kinds (§4.4 order-preserving [name,value] pairs)
	Body    []byte     // key 9, both kinds
}

// headerKV is one §4.4 field entry: [name (text), value (bstr)]. Order is
// significant and MUST be preserved (§4.4: "carriage class MUST preserve that
// order and MUST NOT combine, split, or reorder fields").
type headerKV struct {
	Name  string
	Value []byte
}

// encodeHTTPHeaders converts an http.Header (which Go itself stores
// case-normalized and grouped by name, order of *values within a name*
// preserved) into the §4.4 field-entry list, lower-casing every field name per
// §4.4 ("a sender MUST lowercase ASCII field names before carriage"). Go's
// http.Header has no total across-name order of arrival to preserve (the
// stdlib does not expose header receipt order), so entries are emitted in
// ascending name order with each name's own value order preserved -- a
// deterministic, round-trippable order, not a claim of the original wire order.
func encodeHTTPHeaders(h http.Header) []headerKV {
	names := make([]string, 0, len(h))
	for k := range h {
		names = append(names, k)
	}
	sort.Strings(names)
	out := make([]headerKV, 0, len(h))
	for _, k := range names {
		lk := toLowerASCII(k)
		for _, v := range h[k] {
			out = append(out, headerKV{Name: lk, Value: []byte(v)})
		}
	}
	return out
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// isPseudoHeader reports whether name (already lower-cased) is one of the HTTP/2
// pseudo-headers §4.4 forbids inside the headers/trailers array (their
// information is carried in the typed object keys instead).
func isPseudoHeader(name string) bool {
	switch name {
	case ":method", ":scheme", ":authority", ":path", ":status":
		return true
	default:
		return false
	}
}

// encodeHTTPCarriageRequest builds the §4 HTTP-Carriage Object for a request
// (kind=1) as a deterministic-CBOR map (§4.1) via the already-graded
// npamp.EncodeCanonicalCBOR primitive. Ascending-key canonical ordering is a
// property of that shared codec (RFC 8949 §4.2.1 core-deterministic map-key
// ordering coincides with ascending numeric order for these single-byte keys),
// not something this function re-implements.
func encodeHTTPCarriageRequest(method, target string, h http.Header, body []byte) []byte {
	m := map[uint64]any{
		1: uint64(httpKindRequest),
		2: method,
		3: target,
	}
	if hdrs := encodeHTTPHeaders(h); len(hdrs) > 0 {
		m[8] = headersToCBOR(hdrs)
	}
	if len(body) > 0 {
		m[9] = body
	}
	return npamp.EncodeCanonicalCBOR(m)
}

// encodeHTTPCarriageResponse builds the §4 HTTP-Carriage Object for a response
// (kind=2).
func encodeHTTPCarriageResponse(status int, h http.Header, body []byte) []byte {
	m := map[uint64]any{
		1: uint64(httpKindResponse),
		6: uint64(status),
	}
	if hdrs := encodeHTTPHeaders(h); len(hdrs) > 0 {
		m[8] = headersToCBOR(hdrs)
	}
	if len(body) > 0 {
		m[9] = body
	}
	return npamp.EncodeCanonicalCBOR(m)
}

func headersToCBOR(hdrs []headerKV) []any {
	out := make([]any, len(hdrs))
	for i, kv := range hdrs {
		out[i] = []any{kv.Name, kv.Value}
	}
	return out
}

// errCarriageMalformed is returned for any §4.7 agreement-check or §4.1
// structural-validity failure. Every failure of this codec MUST be reported to
// the peer as BRIDGE_ERROR code EnvelopeMalformed (§6.2 table); the caller (not
// this codec, which knows nothing of frames) is responsible for that mapping.
type errCarriageMalformed struct{ reason string }

func (e *errCarriageMalformed) Error() string {
	return fmt.Sprintf("npamp/proxy: HTTP-Carriage Object malformed: %s", e.reason)
}

// decodeHTTPCarriageObject parses foreign (the Bridge frame's Foreign payload)
// as a §4 HTTP-Carriage Object and applies the §4.7 agreement checks this
// package owns (they are HTTP-carriage-specific, not part of the generic Bridge
// decoder in impl/go/bridge_bodies.go). wantKind is the kind the caller's frame
// type/message_kind implies (§2.2); a mismatch is agreement-check failure 1.
func decodeHTTPCarriageObject(foreign []byte, wantKind httpCarriageKind) (httpCarriageObject, error) {
	v, err := npamp.DecodeCanonicalCBOR(foreign)
	if err != nil {
		return httpCarriageObject{}, &errCarriageMalformed{reason: fmt.Sprintf("not valid deterministic CBOR: %v", err)}
	}
	m, ok := v.(map[uint64]any)
	if !ok {
		return httpCarriageObject{}, &errCarriageMalformed{reason: "top-level item is not a map"}
	}

	kindRaw, ok := m[1]
	if !ok {
		return httpCarriageObject{}, &errCarriageMalformed{reason: "missing REQUIRED key 1 (kind)"}
	}
	kindU, ok := kindRaw.(uint64)
	if !ok {
		return httpCarriageObject{}, &errCarriageMalformed{reason: "key 1 (kind) is not an unsigned integer"}
	}
	kind := httpCarriageKind(kindU)
	// §4.7 check 1: kind MUST correspond to the frame type/message_kind the caller
	// already determined.
	if kind != wantKind {
		return httpCarriageObject{}, &errCarriageMalformed{reason: fmt.Sprintf("object kind %d disagrees with frame type (want %d)", kind, wantKind)}
	}

	obj := httpCarriageObject{Kind: kind}

	switch kind {
	case httpKindRequest:
		method, ok := m[2].(string)
		if !ok || method == "" {
			return httpCarriageObject{}, &errCarriageMalformed{reason: "request missing REQUIRED key 2 (method)"}
		}
		target, ok := m[3].(string)
		if !ok || target == "" {
			return httpCarriageObject{}, &errCarriageMalformed{reason: "request missing REQUIRED key 3 (target)"}
		}
		if _, present := m[6]; present {
			return httpCarriageObject{}, &errCarriageMalformed{reason: "request MUST NOT carry key 6 (status)"}
		}
		obj.Method, obj.Target = method, target
	case httpKindResponse:
		statusRaw, ok := m[6]
		if !ok {
			return httpCarriageObject{}, &errCarriageMalformed{reason: "response missing REQUIRED key 6 (status)"}
		}
		statusU, ok := statusRaw.(uint64)
		if !ok || statusU < 100 || statusU > 599 {
			return httpCarriageObject{}, &errCarriageMalformed{reason: "key 6 (status) is not a valid HTTP status code"}
		}
		if _, present := m[2]; present {
			return httpCarriageObject{}, &errCarriageMalformed{reason: "response MUST NOT carry key 2 (method)"}
		}
		if _, present := m[3]; present {
			return httpCarriageObject{}, &errCarriageMalformed{reason: "response MUST NOT carry key 3 (target)"}
		}
		obj.Status = int(statusU)
	default:
		return httpCarriageObject{}, &errCarriageMalformed{reason: fmt.Sprintf("unsupported object kind %d (streaming kinds 3/4 not yet built)", kind)}
	}

	if hdrsRaw, present := m[8]; present {
		hdrs, err := decodeHeaderList(hdrsRaw)
		if err != nil {
			return httpCarriageObject{}, err
		}
		for _, kv := range hdrs {
			if isPseudoHeader(kv.Name) {
				// §4.4: a receiver that finds a pseudo-header in headers/trailers MUST
				// reject the frame (agreement-check family, §4.7 item 4).
				return httpCarriageObject{}, &errCarriageMalformed{reason: fmt.Sprintf("pseudo-header %q present in headers array", kv.Name)}
			}
		}
		obj.Headers = hdrs
	}
	if bodyRaw, present := m[9]; present {
		body, ok := bodyRaw.([]byte)
		if !ok {
			return httpCarriageObject{}, &errCarriageMalformed{reason: "key 9 (body) is not a byte string"}
		}
		obj.Body = body
	}

	return obj, nil
}

func decodeHeaderList(raw any) ([]headerKV, error) {
	arr, ok := raw.([]any)
	if !ok {
		return nil, &errCarriageMalformed{reason: "key 8 (headers) is not an array"}
	}
	out := make([]headerKV, 0, len(arr))
	for _, entryRaw := range arr {
		entry, ok := entryRaw.([]any)
		if !ok || len(entry) != 2 {
			return nil, &errCarriageMalformed{reason: "a headers entry is not a 2-element [name, value] array"}
		}
		name, ok := entry[0].(string)
		if !ok {
			return nil, &errCarriageMalformed{reason: "a headers entry's name is not a text string"}
		}
		val, ok := entry[1].([]byte)
		if !ok {
			return nil, &errCarriageMalformed{reason: "a headers entry's value is not a byte string"}
		}
		out = append(out, headerKV{Name: name, Value: val})
	}
	return out, nil
}

// toHTTPHeader converts the decoded §4.4 field-entry list back into an
// http.Header, preserving multi-value fields (Add, not Set, per entry) and
// order within a name.
func toHTTPHeader(hdrs []headerKV) http.Header {
	h := make(http.Header, len(hdrs))
	for _, kv := range hdrs {
		h.Add(kv.Name, string(kv.Value))
	}
	return h
}

// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// NPAMP-CC-JSONRPC (spec/companion/20_carriage_jsonrpc.md) carriage codec — the
// second carriage leg of E2.4/R10 (doc.go). This file carries a JSON-RPC 2.0
// object octet-for-octet as the Bridge frame's foreign message (§2, §3): it
// never re-serializes, reorders, or rewrites the carried object; every function
// here either BUILDS the original octets once (encode side, where this package
// IS the originating peer) or PARSES a copy to extract routing/correlation
// fields WITHOUT ever substituting a re-encoding for the wire bytes (decode
// side, §3 "MUST NOT substitute a re-serialization of its parse for the
// carried octets").

// errJSONRPCMalformed reports a §3/§4/§5/§6/§7 structural or agreement-check
// failure. Every failure here MUST be reported to the peer as BRIDGE_ERROR code
// EnvelopeMalformed (§6 table); the caller (not this codec) maps it.
type errJSONRPCMalformed struct{ reason string }

func (e *errJSONRPCMalformed) Error() string {
	return fmt.Sprintf("npamp/proxy: JSON-RPC object malformed: %s", e.reason)
}

// jsonrpcParsed is the minimal set of fields this carriage class needs from a
// parsed JSON-RPC 2.0 object (§4/§5/§6/§7); Raw is always the untouched input
// octets and is what actually gets carried on the wire.
type jsonrpcParsed struct {
	Raw       []byte
	Method    string // present (possibly "") on Request/Notification
	HasMethod bool
	ID        json.RawMessage // non-nil iff the object has an "id" member (§4 vs §7)
	HasResult bool
	Result    json.RawMessage // the raw "result" member, when HasResult
	HasError  bool
	Error     json.RawMessage // the raw "error" member, when HasError
}

// parseJSONRPCObject parses raw as a JSON-RPC 2.0 Object (§3: "MUST contain a
// jsonrpc member equal to the string 2.0") and classifies which members are
// present. It never discards raw; Raw is always the exact input.
func parseJSONRPCObject(raw []byte) (jsonrpcParsed, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return jsonrpcParsed{}, &errJSONRPCMalformed{reason: fmt.Sprintf("not a JSON object: %v", err)}
	}
	verRaw, ok := fields["jsonrpc"]
	if !ok {
		return jsonrpcParsed{}, &errJSONRPCMalformed{reason: "missing REQUIRED jsonrpc member"}
	}
	var ver string
	if err := json.Unmarshal(verRaw, &ver); err != nil || ver != "2.0" {
		return jsonrpcParsed{}, &errJSONRPCMalformed{reason: `jsonrpc member is not the string "2.0"`}
	}
	p := jsonrpcParsed{Raw: append([]byte(nil), raw...)}
	if idRaw, present := fields["id"]; present {
		p.ID = idRaw
	}
	if methodRaw, present := fields["method"]; present {
		p.HasMethod = true
		if err := json.Unmarshal(methodRaw, &p.Method); err != nil {
			return jsonrpcParsed{}, &errJSONRPCMalformed{reason: "method member is not a string"}
		}
	}
	if resultRaw, present := fields["result"]; present {
		p.HasResult = true
		p.Result = resultRaw
	}
	if errRaw, present := fields["error"]; present {
		p.HasError = true
		p.Error = errRaw
	}
	return p, nil
}

// jsonrpcCorrelationID derives the §8.2 correlation_id from a Request's id
// member: the UTF-8 octets of that id's exact JSON token (quotes included for
// a string id), EXCEPT for a Null id (§8.4), where a fresh random 16-octet id
// is required because the literal token `null` does not guarantee uniqueness
// across concurrent Null-id Requests.
func jsonrpcCorrelationID(id json.RawMessage) ([]byte, error) {
	if bytes.Equal(bytes.TrimSpace(id), []byte("null")) {
		return newCorrelationID()
	}
	if len(id) == 0 || len(id) > 255 {
		return nil, &errJSONRPCMalformed{reason: fmt.Sprintf("id token is %d octets (0 or >255 cannot form a correlation_id)", len(id))}
	}
	return append([]byte(nil), id...), nil
}

// encodeJSONRPCRequest builds a JSON-RPC 2.0 Request object carrying an id
// (§4) as the exact octets this package (the originating peer) produces, and
// returns the derived correlation_id (§8.2) alongside it. params, when nil, is
// omitted from the object (JSON-RPC 2.0 permits an absent params member).
func encodeJSONRPCRequest(method string, params any, id any) (wire []byte, corrID []byte, err error) {
	obj := map[string]any{"jsonrpc": "2.0", "method": method, "id": id}
	if params != nil {
		obj["params"] = params
	}
	wire, err = json.Marshal(obj)
	if err != nil {
		return nil, nil, fmt.Errorf("npamp/proxy: encode JSON-RPC request: %w", err)
	}
	parsed, perr := parseJSONRPCObject(wire)
	if perr != nil {
		return nil, nil, perr // cannot happen for well-formed input, but never trust silently
	}
	corrID, err = jsonrpcCorrelationID(parsed.ID)
	if err != nil {
		return nil, nil, err
	}
	return wire, corrID, nil
}

// encodeJSONRPCNotification builds a JSON-RPC 2.0 Notification object — a
// Request with no id member (§7).
func encodeJSONRPCNotification(method string, params any) ([]byte, error) {
	obj := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		obj["params"] = params
	}
	wire, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("npamp/proxy: encode JSON-RPC notification: %w", err)
	}
	return wire, nil
}

// decodeJSONRPCRequestOrNotification parses an inbound BRIDGE_REQUEST or
// BRIDGE_NOTIFY foreign message and applies the §4/§7 structural checks: a
// Request MUST carry an id member (§4); a Notification MUST NOT (§7).
func decodeJSONRPCRequestOrNotification(foreign []byte, wantNotify bool) (jsonrpcParsed, error) {
	p, err := parseJSONRPCObject(foreign)
	if err != nil {
		return jsonrpcParsed{}, err
	}
	if !p.HasMethod {
		return jsonrpcParsed{}, &errJSONRPCMalformed{reason: "Request/Notification missing REQUIRED method member"}
	}
	hasID := p.ID != nil
	if wantNotify && hasID {
		return jsonrpcParsed{}, &errJSONRPCMalformed{reason: "carried an id member under BRIDGE_NOTIFY (§7: a Notification MUST NOT have an id)"}
	}
	if !wantNotify && !hasID {
		return jsonrpcParsed{}, &errJSONRPCMalformed{reason: "Request has no id member (§4: use BRIDGE_NOTIFY for a Notification)"}
	}
	return p, nil
}

// decodeJSONRPCSuccessResponse parses an inbound BRIDGE_RESPONSE foreign
// message and applies the §5 structural check: exactly a result member, no
// error member.
func decodeJSONRPCSuccessResponse(foreign []byte) (jsonrpcParsed, error) {
	p, err := parseJSONRPCObject(foreign)
	if err != nil {
		return jsonrpcParsed{}, err
	}
	if p.HasError {
		return jsonrpcParsed{}, &errJSONRPCMalformed{reason: "a Response carrying an error member MUST be carried as BRIDGE_ERROR, not BRIDGE_RESPONSE (§5/§6)"}
	}
	if !p.HasResult {
		return jsonrpcParsed{}, &errJSONRPCMalformed{reason: "success Response missing REQUIRED result member"}
	}
	return p, nil
}

// decodeJSONRPCErrorResponse parses an inbound BRIDGE_ERROR foreign message
// carrying a foreign JSON-RPC error Response (§6) — NOT an N-PAMP transport
// error (that is a distinct wire shape, disambiguated by the caller via the
// envelope content_type before reaching this function).
func decodeJSONRPCErrorResponse(foreign []byte) (jsonrpcParsed, error) {
	p, err := parseJSONRPCObject(foreign)
	if err != nil {
		return jsonrpcParsed{}, err
	}
	if !p.HasError {
		return jsonrpcParsed{}, &errJSONRPCMalformed{reason: "BRIDGE_ERROR foreign JSON-RPC object missing REQUIRED error member"}
	}
	return p, nil
}

// jsonrpcMethodAgrees is the §4/§7 agreement check: the BridgeEnvelope `method`
// field MUST equal the carried object's method member byte-for-byte.
func jsonrpcMethodAgrees(envelopeMethod []byte, obj jsonrpcParsed) bool {
	return string(envelopeMethod) == obj.Method
}

// jsonrpcEnvelope builds the BridgeEnvelope for a JSON-RPC frame (§4/§5/§6/§7
// field tables). kind/method vary per call site; content_type is always JSON
// (0x01) for every frame this class defines.
func jsonrpcEnvelope(protocol npamp.BridgeProtocol, kind npamp.BridgeMessageKind, corrID []byte, method string) npamp.BridgeEnvelope {
	env := npamp.BridgeEnvelope{
		Protocol:      protocol,
		Kind:          kind,
		ContentType:   npamp.BridgeContentJSON,
		CorrelationID: corrID,
	}
	if method != "" {
		env.Method = []byte(method)
	}
	return env
}

// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package supplychain

import (
	"encoding/json"
	"testing"
)

// TestPAEMatchesDSSESpecWorkedExample is the F3 non-circular oracle for PAE: the exact
// worked example from DSSE's own protocol.md (fetched this session, verbatim):
//
//	SERIALIZED_BODY: "hello world"
//	PAYLOAD_TYPE: "http://example.com/HelloWorld"
//	Result: "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
//
// 29 = len("http://example.com/HelloWorld"), 11 = len("hello world") — both independently
// counted here, not merely copied from the spec's own arithmetic.
func TestPAEMatchesDSSESpecWorkedExample(t *testing.T) {
	payloadType := "http://example.com/HelloWorld"
	body := "hello world"
	if len(payloadType) != 29 {
		t.Fatalf("len(payloadType) = %d, want 29 (independent recount of the DSSE spec's own example)", len(payloadType))
	}
	if len(body) != 11 {
		t.Fatalf("len(body) = %d, want 11", len(body))
	}
	got := string(PAE(payloadType, []byte(body)))
	want := "DSSEv1 29 http://example.com/HelloWorld 11 hello world"
	if got != want {
		t.Fatalf("PAE(%q, %q) = %q, want %q (DSSE protocol.md's own worked example)", payloadType, body, got, want)
	}
}

func TestPAEEmptyBody(t *testing.T) {
	got := string(PAE("t", nil))
	want := "DSSEv1 1 t 0 "
	if got != want {
		t.Fatalf("PAE(%q, nil) = %q, want %q", "t", got, want)
	}
}

// TestPAEChangesWithInput is the A4 mutation-surviving test: a PAE implementation that
// ignores either argument (e.g. hardcoding the length or the body) fails this test.
func TestPAEChangesWithInput(t *testing.T) {
	a := PAE("type-a", []byte("body-a"))
	b := PAE("type-b", []byte("body-a"))
	if string(a) == string(b) {
		t.Fatal("two different payloadType inputs produced the same PAE encoding — payloadType is being ignored")
	}
	c := PAE("type-a", []byte("body-c"))
	if string(a) == string(c) {
		t.Fatal("two different body inputs produced the same PAE encoding — body is being ignored")
	}
}

// TestPAEIsUnambiguousAcrossFieldBoundary proves PAE's length-prefixing actually prevents
// the classic "concatenation collision" a naive type+SP+body encoding would suffer: two
// (type, body) pairs whose naive concatenations coincide MUST still produce distinct PAE
// encodings, because the embedded decimal lengths differ.
func TestPAEIsUnambiguousAcrossFieldBoundary(t *testing.T) {
	a := PAE("ab", []byte("cd")) // naive concat: "ab" + "cd" = "abcd"
	b := PAE("abc", []byte("d")) // naive concat: "abc" + "d"  = "abcd"
	if string(a) == string(b) {
		t.Fatal("PAE(\"ab\",\"cd\") == PAE(\"abc\",\"d\") — length-prefixing is not preventing a field-boundary collision")
	}
}

func TestEnvelopeJSONShape(t *testing.T) {
	env := Envelope{
		Payload:     "cGF5bG9hZA==",
		PayloadType: InTotoPayloadType,
		Signatures:  []Signature{{KeyID: "k1", Sig: "c2ln"}},
	}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("Unmarshal into map: %v", err)
	}
	for _, key := range []string{"payload", "payloadType", "signatures"} {
		if _, ok := m[key]; !ok {
			t.Fatalf("marshaled envelope is missing required DSSE field %q: %s", key, raw)
		}
	}
	sigs, ok := m["signatures"].([]any)
	if !ok || len(sigs) != 1 {
		t.Fatalf("signatures = %v, want a 1-element array", m["signatures"])
	}
	sig0, ok := sigs[0].(map[string]any)
	if !ok {
		t.Fatalf("signatures[0] = %v, want an object", sigs[0])
	}
	if _, ok := sig0["sig"]; !ok {
		t.Fatal("signatures[0] is missing required field \"sig\"")
	}
}

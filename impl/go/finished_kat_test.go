package npamp

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"
)

// finishedKAT mirrors test-vectors/v1/finished-kat.json (ADR-0010):
// verify_data = HMAC-SHA256(finished_key, transcript_hash) with the HMAC
// primitive anchored to RFC 4231 TC1/TC2, fixed finished_key fixtures, and the
// Transcript KAT's TH_sCV / TH_cCV as the covered points (spec/10 section
// 6.2).
type finishedKAT struct {
	Expected struct {
		Client string `json:"verify_data_client"`
		Server string `json:"verify_data_server"`
	} `json:"expected"`
	Inputs struct {
		FinishedKeyClient string `json:"finished_key_client"`
		FinishedKeyServer string `json:"finished_key_server"`
		THCCV             string `json:"th_ccv"`
		THSCV             string `json:"th_scv"`
	} `json:"npamp_inputs"`
	RFC4231 struct {
		TC1 struct {
			Data string `json:"data"`
			MAC  string `json:"hmac_sha256"`
			Key  string `json:"key"`
		} `json:"tc1"`
		TC2 struct {
			Data string `json:"data"`
			MAC  string `json:"hmac_sha256"`
			Key  string `json:"key"`
		} `json:"tc2"`
	} `json:"rfc4231_hmac_sha256"`
}

// hmacSHA256 is the test's oracle: crypto/hmac applied directly, independent
// of ComputeFinished's wiring.
func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func TestFinishedKAT(t *testing.T) {
	var kat finishedKAT
	loadKAT(t, "finished-kat.json", &kat)

	// Anchor (RFC 4231 TC1/TC2): prove the HMAC-SHA-256 primitive.
	for name, tc := range map[string]struct{ Data, MAC, Key string }{
		"tc1": {kat.RFC4231.TC1.Data, kat.RFC4231.TC1.MAC, kat.RFC4231.TC1.Key},
		"tc2": {kat.RFC4231.TC2.Data, kat.RFC4231.TC2.MAC, kat.RFC4231.TC2.Key},
	} {
		got := hmacSHA256(mustHex(t, name+".key", tc.Key), mustHex(t, name+".data", tc.Data))
		if !bytes.Equal(got, mustHex(t, name+".hmac", tc.MAC)) {
			t.Fatalf("HMAC-SHA-256 does not reproduce RFC 4231 %s", name)
		}
	}

	cases := []struct {
		role        string
		finishedKey []byte
		th          []byte
		want        []byte
	}{
		{"server", mustHex(t, "finished_key_server", kat.Inputs.FinishedKeyServer),
			mustHex(t, "th_scv", kat.Inputs.THSCV), mustHex(t, "verify_data_server", kat.Expected.Server)},
		{"client", mustHex(t, "finished_key_client", kat.Inputs.FinishedKeyClient),
			mustHex(t, "th_ccv", kat.Inputs.THCCV), mustHex(t, "verify_data_client", kat.Expected.Client)},
	}
	for _, c := range cases {
		// Oracle leg: independent crypto/hmac reproduces the vector.
		if !bytes.Equal(hmacSHA256(c.finishedKey, c.th), c.want) {
			t.Fatalf("%s: oracle HMAC does not reproduce the vector", c.role)
		}
		// Impl leg: ComputeFinished reproduces it through the real code path.
		if got := ComputeFinished(c.finishedKey, c.th, ProfileStandard); !bytes.Equal(got, c.want) {
			t.Fatalf("%s: ComputeFinished = %x, want %x", c.role, got, c.want)
		}
		// VerifyFinished accepts the correct MAC ...
		if err := VerifyFinished(c.finishedKey, c.th, c.want, ProfileStandard); err != nil {
			t.Fatalf("%s: VerifyFinished rejected the correct verify_data: %v", c.role, err)
		}
		// ... and rejects a corrupted one and a wrong-key one.
		bad := bytes.Clone(c.want)
		bad[0] ^= 0x01
		if err := VerifyFinished(c.finishedKey, c.th, bad, ProfileStandard); !errors.Is(err, ErrFinishedMismatch) {
			t.Fatalf("%s: corrupted verify_data not rejected (err=%v)", c.role, err)
		}
		wrongKey := bytes.Clone(c.finishedKey)
		wrongKey[0] ^= 0x01
		if err := VerifyFinished(wrongKey, c.th, c.want, ProfileStandard); !errors.Is(err, ErrFinishedMismatch) {
			t.Fatalf("%s: wrong finished_key not rejected (err=%v)", c.role, err)
		}
	}

	// Cross-direction guard: the server MAC keyed with the client key (or over
	// the client transcript point) MUST NOT verify.
	if err := VerifyFinished(
		mustHex(t, "finished_key_client", kat.Inputs.FinishedKeyClient),
		mustHex(t, "th_scv", kat.Inputs.THSCV),
		mustHex(t, "verify_data_server", kat.Expected.Server),
		ProfileStandard,
	); !errors.Is(err, ErrFinishedMismatch) {
		t.Fatalf("server verify_data verified under the client finished_key (err=%v)", err)
	}
}

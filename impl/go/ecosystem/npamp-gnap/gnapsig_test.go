// Copyright (c) 2026 BubbleFish Technologies, Inc. Apache-2.0.

package npampgnap

import (
	"crypto/ed25519"
	"testing"
)

var sigTestSeed = []byte{
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
}

func sigTestKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(sigTestSeed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("priv.Public() did not return ed25519.PublicKey")
	}
	return pub, priv
}

func TestRequiredComponents(t *testing.T) {
	cases := []struct {
		hasBody, hasAuth bool
		want             []string
	}{
		{false, false, []string{"@method", "@target-uri"}},
		{true, false, []string{"@method", "@target-uri", "content-digest"}},
		{false, true, []string{"@method", "@target-uri", "authorization"}},
		{true, true, []string{"@method", "@target-uri", "content-digest", "authorization"}},
	}
	for _, c := range cases {
		got := RequiredComponents(c.hasBody, c.hasAuth)
		if len(got) != len(c.want) {
			t.Fatalf("RequiredComponents(%v,%v) = %v, want %v", c.hasBody, c.hasAuth, got, c.want)
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Fatalf("RequiredComponents(%v,%v)[%d] = %q, want %q", c.hasBody, c.hasAuth, i, got[i], c.want[i])
			}
		}
	}
}

func TestBuildSignatureBaseRejectsMissingValue(t *testing.T) {
	if _, err := BuildSignatureBase([]string{"@method"}, map[string]string{}, SignatureParams{}); err != ErrUnknownComponent {
		t.Fatalf("BuildSignatureBase(missing value) error = %v, want ErrUnknownComponent", err)
	}
}

func TestBuildSignatureBaseDeterministic(t *testing.T) {
	values := map[string]string{"@method": "POST", "@target-uri": "https://as.example/grant"}
	params := SignatureParams{Created: 1000, Alg: AlgTag}
	a, err := BuildSignatureBase([]string{"@method", "@target-uri"}, values, params)
	if err != nil {
		t.Fatalf("BuildSignatureBase: %v", err)
	}
	b, err := BuildSignatureBase([]string{"@method", "@target-uri"}, values, params)
	if err != nil {
		t.Fatalf("BuildSignatureBase: %v", err)
	}
	if string(a) != string(b) {
		t.Fatalf("BuildSignatureBase produced non-deterministic output:\n%s\nvs\n%s", a, b)
	}
	// TestBuildSignatureBaseChangesWithComponents (A4): the base must actually depend on the
	// covered-component values, not just their names.
	values2 := map[string]string{"@method": "GET", "@target-uri": "https://as.example/grant"}
	c, err := BuildSignatureBase([]string{"@method", "@target-uri"}, values2, params)
	if err != nil {
		t.Fatalf("BuildSignatureBase: %v", err)
	}
	if string(a) == string(c) {
		t.Fatal("BuildSignatureBase produced identical output for POST and GET @method values")
	}
}

func TestSignThenVerifyRoundTrips(t *testing.T) {
	pub, priv := sigTestKeypair(t)
	components := []string{"@method", "@target-uri"}
	values := map[string]string{"@method": "POST", "@target-uri": "https://as.example/grant"}
	params := SignatureParams{Created: 1700000000, Alg: AlgTag}

	_, sig, err := Sign(priv, components, values, params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(pub, components, values, params, sig); err != nil {
		t.Fatalf("Verify(genuine signature) = %v, want nil", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	pub, priv := sigTestKeypair(t)
	components := []string{"@method", "@target-uri"}
	values := map[string]string{"@method": "POST", "@target-uri": "https://as.example/grant"}
	params := SignatureParams{Created: 1700000000}

	_, sig, err := Sign(priv, components, values, params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tampered := append([]byte(nil), sig...)
	tampered[0] ^= 0xFF
	if err := Verify(pub, components, values, params, tampered); err != ErrKeyProofMismatch {
		t.Fatalf("Verify(tampered signature) = %v, want ErrKeyProofMismatch", err)
	}
}

func TestVerifyRejectsTamperedCoveredValue(t *testing.T) {
	pub, priv := sigTestKeypair(t)
	components := []string{"@method", "@target-uri"}
	values := map[string]string{"@method": "POST", "@target-uri": "https://as.example/grant"}
	params := SignatureParams{Created: 1700000000}

	_, sig, err := Sign(priv, components, values, params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tamperedValues := map[string]string{"@method": "POST", "@target-uri": "https://attacker.example/grant"}
	if err := Verify(pub, components, tamperedValues, params, sig); err != ErrKeyProofMismatch {
		t.Fatalf("Verify(tampered @target-uri) = %v, want ErrKeyProofMismatch", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	_, priv := sigTestKeypair(t)
	wrongPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	components := []string{"@method", "@target-uri"}
	values := map[string]string{"@method": "POST", "@target-uri": "https://as.example/grant"}
	params := SignatureParams{Created: 1700000000}

	_, sig, err := Sign(priv, components, values, params)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := Verify(wrongPub, components, values, params, sig); err != ErrKeyProofMismatch {
		t.Fatalf("Verify(wrong key) = %v, want ErrKeyProofMismatch", err)
	}
}

func TestContentDigestChangesWithBody(t *testing.T) {
	a := ContentDigest([]byte("body-a"))
	b := ContentDigest([]byte("body-b"))
	if a == b {
		t.Fatal("ContentDigest produced identical output for two different bodies")
	}
	if ContentDigest([]byte("body-a")) != a {
		t.Fatal("ContentDigest is not deterministic for the same input")
	}
}

func TestBuildSignatureInputHeaderIncludesLabelAndParams(t *testing.T) {
	got := BuildSignatureInputHeader("sig1", []string{"@method", "@target-uri"}, SignatureParams{Created: 1700000000, Alg: AlgTag})
	want := `sig1=("@method" "@target-uri");created=1700000000;alg="ed25519"`
	if got != want {
		t.Fatalf("BuildSignatureInputHeader = %q, want %q", got, want)
	}
}

func TestBuildSignatureHeaderEncodesSfBinary(t *testing.T) {
	got := BuildSignatureHeader("sig1", []byte{0x01, 0x02, 0x03})
	want := `sig1=:AQID:`
	if got != want {
		t.Fatalf("BuildSignatureHeader = %q, want %q", got, want)
	}
}

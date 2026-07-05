// Command npamp-kat is the Go port of the reference cross-language KAT runner. It
// drives N-PAMP's AES-256-GCM seal/open through Google Project Wycheproof vectors
// (C2SP/wycheproof) via the dependency-free flat corpus
// _shared/wycheproof/aesgcm_kat.tsv (keySize=256, ivSize=96, tagSize=128).
//
// These vectors are authored by an independent authority and encode KNOWN ATTACKS
// (truncated tags, modified ciphertext) that our self-generated golden vectors
// never include, so a shared bug between our impls cannot pass them.
//
// Trick: SealAES256GCM(key, iv, seq, ...) derives nonce = iv XOR (0^4||seq); with
// seq=0 the nonce IS the given IV, so each vector exercises the REAL seal/open
// path. Exit 0 iff every vector behaves exactly as Wycheproof labels it.
package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

// hexToKey decodes a 32-octet hex string into the fixed-size AES-256 key array.
func hexToKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return k, err
	}
	if len(b) != 32 {
		return k, fmt.Errorf("key is %d octets, want 32", len(b))
	}
	copy(k[:], b)
	return k, nil
}

// hexToIV decodes a 12-octet hex string into the fixed-size 96-bit IV array.
func hexToIV(s string) ([12]byte, error) {
	var iv [12]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return iv, err
	}
	if len(b) != 12 {
		return iv, fmt.Errorf("iv is %d octets, want 12", len(b))
	}
	copy(iv[:], b)
	return iv, nil
}

type failure struct {
	tc     string
	result string
	reason string
}

func main() {
	var tsvPath string
	if len(os.Args) > 1 {
		tsvPath = os.Args[1]
	} else {
		// Mirror the reference default: <repo-root>/_shared/wycheproof/aesgcm_kat.tsv,
		// where repo-root is four levels above impl/go.
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintln(os.Stderr, "cannot determine working directory:", err)
			os.Exit(1)
		}
		tsvPath = filepath.Join(wd, "..", "..", "..", "..", "_shared", "wycheproof", "aesgcm_kat.tsv")
	}

	raw, err := os.ReadFile(tsvPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot read corpus:", err)
		os.Exit(1)
	}

	total, passed := 0, 0
	var fails []failure

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 8 {
			fmt.Fprintf(os.Stderr, "malformed line (%d fields, want 8): %q\n", len(fields), line)
			os.Exit(1)
		}
		tc, result := fields[0], fields[1]
		keyHex, ivHex, aadHex := fields[2], fields[3], fields[4]
		msgHex, ctHex, tagHex := fields[5], fields[6], fields[7]

		key, err := hexToKey(keyHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcId=%s key decode: %v\n", tc, err)
			os.Exit(1)
		}
		iv, err := hexToIV(ivHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcId=%s iv decode: %v\n", tc, err)
			os.Exit(1)
		}
		aad, err := hex.DecodeString(aadHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcId=%s aad decode: %v\n", tc, err)
			os.Exit(1)
		}
		msg, err := hex.DecodeString(msgHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcId=%s msg decode: %v\n", tc, err)
			os.Exit(1)
		}
		ct, err := hex.DecodeString(ctHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcId=%s ct decode: %v\n", tc, err)
			os.Exit(1)
		}
		tag, err := hex.DecodeString(tagHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "tcId=%s tag decode: %v\n", tc, err)
			os.Exit(1)
		}
		sealed := append(append([]byte{}, ct...), tag...)

		ok, reason := true, ""
		switch result {
		case "valid":
			got, err := npamp.SealAES256GCM(key, iv, 0, aad, msg)
			if err != nil {
				ok, reason = false, "seal errored: "+err.Error()
			} else if !bytes.Equal(got, sealed) {
				ok, reason = false, "encrypt mismatch"
			} else {
				pt, err := npamp.OpenAES256GCM(key, iv, 0, aad, sealed)
				if err != nil {
					ok, reason = false, "decrypt errored: "+err.Error()
				} else if !bytes.Equal(pt, msg) {
					ok, reason = false, "decrypt mismatch"
				}
			}
		case "invalid":
			if _, err := npamp.OpenAES256GCM(key, iv, 0, aad, sealed); err == nil {
				ok, reason = false, "accepted an invalid vector"
			}
			// A non-nil error is the correct, expected behavior: rejected.
		default: // "acceptable"
			if pt, err := npamp.OpenAES256GCM(key, iv, 0, aad, sealed); err == nil {
				if !bytes.Equal(pt, msg) {
					ok, reason = false, "acceptable but wrong plaintext"
				}
			}
			// Rejection of an acceptable vector is allowed.
		}

		total++
		if ok {
			passed++
		} else {
			fails = append(fails, failure{tc, result, reason})
		}
	}

	fmt.Printf("AES-256-GCM Wycheproof KAT (go): %d/%d passed\n", passed, total)
	for i, f := range fails {
		if i >= 15 {
			break
		}
		fmt.Printf("  FAIL tcId=%s result=%s: %s\n", f.tc, f.result, f.reason)
	}
	if len(fails) == 0 && total > 0 {
		os.Exit(0)
	}
	os.Exit(1)
}

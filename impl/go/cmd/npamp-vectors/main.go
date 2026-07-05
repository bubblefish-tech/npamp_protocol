// Command npamp-vectors emits the cross-language conformance vectors as JSON.
// Every other reference implementation must reproduce these bytes exactly.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	npamp "github.com/bubblefish-tech/npamp_protocol/impl/go"
)

type vectors struct {
	Spec        string `json:"spec"`
	HeaderPing  string `json:"header_ping_control_seq0"`
	Nonce       string `json:"nonce_iv1to12_seq0102"`
	AEADSeal    string `json:"aes256gcm_seal_helloworld"`
	TrafficKey  string `json:"traffic_key_sha384"`
}

func main() {
	// 1. Golden header: PING on Control, seq 0, empty payload.
	f := &npamp.Frame{Type: uint16(npamp.FramePing), Channel: uint16(npamp.ChanControl), Seq: 0}
	hdr, _ := f.MarshalBinary()

	// 2. Nonce: iv = 01..0C, seq = 0x0102030405060708.
	var iv [12]byte
	for i := range iv {
		iv[i] = byte(i + 1)
	}
	n := npamp.DeriveNonce(iv, 0x0102030405060708)

	// 3. AEAD seal: fixed key 00..1F, iv 10..1B, seq 7, aad = header prefix, pt = "hello world".
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	var iv2 [12]byte
	for i := range iv2 {
		iv2[i] = byte(0x10 + i)
	}
	aad := make([]byte, 21)
	(&npamp.Frame{Type: uint16(npamp.FramePing), Channel: uint16(npamp.ChanControl)}).HeaderPrefix(aad, 11)
	sealed, _ := npamp.SealAES256GCM(key, iv2, 7, aad, []byte("hello world"))

	// 4. Key schedule: master = 48 x 0x2A (SHA-384 length), High profile, traffic secret -> key.
	master := make([]byte, 48)
	for i := range master {
		master[i] = 0x2A
	}
	ts, _ := npamp.DeriveTrafficSecret(master, npamp.DirClientToServer, 0, npamp.AEADAES256GCM, npamp.ChanControl, npamp.ProfileHigh)
	tk, _, _ := npamp.DeriveKeyIV(ts, npamp.ProfileHigh)

	out := vectors{
		Spec:       "draft-bubblefish-npamp-00",
		HeaderPing: hex.EncodeToString(hdr),
		Nonce:      hex.EncodeToString(n[:]),
		AEADSeal:   hex.EncodeToString(sealed),
		TrafficKey: hex.EncodeToString(tk[:]),
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}

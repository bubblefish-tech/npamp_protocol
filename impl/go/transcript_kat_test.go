package npamp

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// transcriptKAT mirrors test-vectors/v1/transcript-kat.json (ADR-0009): fixed
// frame/TLV fixtures whose expected TH_* points were produced by an
// independent per-TLV byte-constructor + FIPS 180-4 SHA-256, pinning the
// spec/10 section 3 divergence from RFC 8446 section 4.4.1 (2-octet frame
// type only, per-TLV granularity).
type transcriptKAT struct {
	Expected map[string]string `json:"expected_transcript_points"`
	FIPS     struct {
		Digest string `json:"digest"`
		Input  string `json:"input_ascii"`
	} `json:"fips180_4_sha256_abc"`
	Frames []struct {
		FrameType string `json:"frame_type"`
		Name      string `json:"name"`
		TLVs      []struct {
			Name  string `json:"name"`
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"tlvs"`
	} `json:"frames"`
}

func TestTranscriptKAT(t *testing.T) {
	var kat transcriptKAT
	loadKAT(t, "transcript-kat.json", &kat)

	// Anchor (FIPS 180-4): prove the test's hash primitive before trusting
	// any TH point.
	abc := sha256.Sum256([]byte(kat.FIPS.Input))
	if hex.EncodeToString(abc[:]) != kat.FIPS.Digest {
		t.Fatal("SHA-256 does not reproduce the FIPS 180-4 'abc' digest")
	}

	if len(kat.Frames) != 4 {
		t.Fatalf("vector has %d frames, want 4", len(kat.Frames))
	}
	for i, wantTLVs := range []int{5, 5, 3, 3} {
		if len(kat.Frames[i].TLVs) != wantTLVs {
			t.Fatalf("frame %d has %d TLVs, want %d", i, len(kat.Frames[i].TLVs), wantTLVs)
		}
	}

	// The five cut points of spec/10 section 3, expressed as (frame, TLV)
	// positions after which the transcript hash is taken. tlvsAbsorbed is the
	// count of the frame's TLVs absorbed at the point (the frame type is
	// absorbed with the first TLV of its frame).
	points := []struct {
		key          string
		frame        int
		tlvsAbsorbed int
	}{
		{"th_kem", 1, 5}, // through SERVER_HELLO complete
		{"th_sid", 2, 1}, // ... || 0x0102 || ServerIdentityKey
		{"th_scv", 2, 2}, // ... || ServerCertVerify (excludes ServerFinished)
		{"th_cid", 3, 1}, // ... || ServerFinished || 0x0103 || ClientIdentityKey
		{"th_ccv", 3, 2}, // ... || ClientCertVerify (excludes ClientFinished)
	}

	// Oracle leg: an independent byte-constructor (frame type as 2-octet BE;
	// TLV as Type(2 BE) || Length(2 BE) || Value), built inline so a bug in
	// TLV.Encode or Transcript cannot hide here.
	var oracleBuf []byte
	oracleAt := map[string]string{}
	implT := NewTranscript(ProfileStandard)
	implAt := map[string]string{}

	next := 0
	for fi, fr := range kat.Frames {
		ft := mustHexU16(t, "frame_type", fr.FrameType)
		oracleBuf = append(oracleBuf, byte(ft>>8), byte(ft))
		implT.AddFrameType(FrameType(ft))
		for ti, v := range fr.TLVs {
			typ := mustHexU16(t, v.Name+".type", v.Type)
			val := mustHex(t, v.Name+".value", v.Value)
			oracleBuf = append(oracleBuf, byte(typ>>8), byte(typ), byte(len(val)>>8), byte(len(val)))
			oracleBuf = append(oracleBuf, val...)
			implT.AddTLV(TLV{Type: TLVType(typ), Value: val})
			for next < len(points) && points[next].frame == fi && points[next].tlvsAbsorbed == ti+1 {
				d := sha256.Sum256(oracleBuf)
				oracleAt[points[next].key] = hex.EncodeToString(d[:])
				implAt[points[next].key] = hex.EncodeToString(implT.Sum())
				next++
			}
		}
	}
	if next != len(points) {
		t.Fatalf("only %d of %d cut points reached", next, len(points))
	}

	for _, p := range points {
		want, ok := kat.Expected[p.key]
		if !ok {
			t.Fatalf("vector missing expected point %s", p.key)
		}
		if oracleAt[p.key] != want {
			t.Errorf("oracle leg: %s = %s, want %s", p.key, oracleAt[p.key], want)
		}
		if implAt[p.key] != want {
			t.Errorf("impl leg: Transcript %s = %s, want %s", p.key, implAt[p.key], want)
		}
	}
}

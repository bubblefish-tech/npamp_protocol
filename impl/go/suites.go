package npamp

// ALPN is the N-PAMP application-layer protocol negotiation identifier (draft-00 section 9.1).
const ALPN = "n-pamp/2"

// KEMID is a key-encapsulation-mechanism code point (draft-00 section 7.1).
type KEMID uint16

const (
	KEMX25519MLKEM768  KEMID = 0x11ec // Standard, High
	KEMX25519MLKEM1024 KEMID = 0x11ed // High, Sovereign
)

// AEADID is an authenticated-encryption suite code point (draft-00 section 7.2).
type AEADID uint16

const (
	AEADAES256GCM        AEADID = 0x0001
	AEADChaCha20Poly1305 AEADID = 0x0002
)

// SigID is a signature-algorithm code point (draft-00 section 7.3).
type SigID uint16

const (
	SigEd25519 SigID = 0x0807 // all profiles
	SigMLDSA87 SigID = 0x0905 // High, Sovereign
)

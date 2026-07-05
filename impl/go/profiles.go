package npamp

// Profile is an N-PAMP security profile (draft-00 section 6). The profiles share
// one wire format and differ only in cryptographic primitives and operational
// requirements. Code points 0x00 and 0x04..0xFF are reserved.
type Profile uint8

const (
	ProfileStandard  Profile = 0x01
	ProfileHigh      Profile = 0x02
	ProfileSovereign Profile = 0x03
)

// Valid reports whether p is one of the three defined profiles.
func (p Profile) Valid() bool { return p >= ProfileStandard && p <= ProfileSovereign }

// KDFHash returns the profile's KDF hash name (draft-00 section 6 invariants):
// SHA-256 at Standard, SHA-384 at High and Sovereign.
func (p Profile) KDFHash() string {
	if p == ProfileStandard {
		return "SHA-256"
	}
	return "SHA-384"
}

// MinKEM returns the minimum KEM code point for p (draft-00 section 6 invariants).
func (p Profile) MinKEM() KEMID {
	if p == ProfileStandard {
		return KEMX25519MLKEM768
	}
	return KEMX25519MLKEM1024
}

func (p Profile) String() string {
	switch p {
	case ProfileStandard:
		return "Standard"
	case ProfileHigh:
		return "High"
	case ProfileSovereign:
		return "Sovereign"
	default:
		return "reserved"
	}
}

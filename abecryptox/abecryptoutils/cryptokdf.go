package abecryptoutils

import (
	_ "crypto"
	"fmt"
	"github.com/pqabelian/abec/abecryptox/abecryptoutils/internal"
)

// The abecryptox-layer is responsible for generating Rand Seeds for the underling crypto-scheme.
// The abecryptox-layer uses Key-Derivation Function(KDF) to generates Rand Seeds from Root Seeds.
// In such a mechanism, the abecryptox-layer implements a KDF such that
// (1) the PRFOutputBytesLen should be the same as the RandBytesLen required by the underlying crypto-scheme.
// (2) the PRFKeyBytesLen is sufficient to guarantee the KDF's security.
// KMAC256 is used as a KDF as specified in 4.4 of [1].
//
// [1]https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf
const (
	PRFKeyBytesLen    = 64
	PRFOutputBytesLen = 64
)

const domainSeparationCustomizationString = "PQABELIAN"

func KDF(key []byte, input []byte) (output []byte, err error) {
	if len(key) != PRFKeyBytesLen {
		return nil, fmt.Errorf("KDF: the input key has an invalid length (%d)", len(key))
	}
	kmac256 := internal.NewKMAC256(key, PRFOutputBytesLen, []byte(domainSeparationCustomizationString))
	kmac256.Write(input)
	return kmac256.Sum(nil), nil
}

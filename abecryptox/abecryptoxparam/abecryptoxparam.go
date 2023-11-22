package abecryptoxparam

import (
	"encoding/binary"
	"errors"
	"github.com/cryptosuite/pqringct"
	"github.com/cryptosuite/pqringctx/pqringctxapi"
)

// ABE can support at most 2^32 different CryptoSchemes
// The different versions of 'same' CryptoSchemes are regarded as different CryptoSchemes.
type CryptoScheme uint32

const (
	CryptoSchemePQRingCT  CryptoScheme = 0
	CryptoSchemePQRingCTX CryptoScheme = 1 // supporting full-privacy and pseudonym-privacy
)

type PrivacyLevel uint8

const (
	PrivacyLevelRINGCT    PrivacyLevel = 0 //	hide the payer in ring, hide the amount by commitment,
	PrivacyLevelPSEUDONYM PrivacyLevel = 1 //	pseudonym, i.e., hide the real identity
	// PrivacyLevelRINGCTSA  PrivacyLevel = 2 //	(not supported at this moment) hide the payer in ring, hide the amount by commitment, hide the payee by SA
)

// The public parameters for the supported crypto-schemes.
// PQRingCTPP is the public parameter for CryptoSchemePQRingCT.
var PQRingCTPP = pqringct.Initialize([]byte("Welcome to Post Quantum World! From the Abelian Team"))
var PQRingCTXPP = pqringctxapi.InitializePQRingCTX([]byte("Welcome to Post Quantum World! From the Abelian Team"))

// Serialize use little endian to serialize a uint32 number
func (c CryptoScheme) Serialize() []byte {
	res := make([]byte, 4)
	binary.LittleEndian.PutUint32(res, uint32(c))
	return res
}

func Deserialize(content []byte) (CryptoScheme, error) {
	if len(content) != 4 {
		return CryptoSchemePQRingCT, errors.New("invalid length")
	}
	return CryptoScheme(binary.LittleEndian.Uint32(content)), nil
}

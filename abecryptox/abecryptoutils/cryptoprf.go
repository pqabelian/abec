package abecryptoutils

import (
	_ "crypto"
)

// The abecryptox-layer is responsible for generating Rand Seeds for the underling crypto-scheme.
// The abecryptox-layer uses a PRF to generates Rand Seeds from Root Seeds.
// In such a mechanism, the abecryptox-layer implements a PRF such that
// (1) the PRFOutputBytesLen should be the same as the RandBytesLen required by the underlying crypto-scheme.
// (2) the PRFKeyBytesLen is sufficient to guarantee the PRF's security.
// we use SHA3-512-based-HMAC as a PRF.
const PRFKeyBytesLen = 64
const PRFOutputBytesLen = 64

func PRF(key []byte, input []byte) (output []byte) {
	return nil
}

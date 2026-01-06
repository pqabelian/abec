package nakamotopowaconcagua

import "github.com/abesuite/abec/wire"

// SealHashPreImage returns the content of header that is used to compute SealHash in NakamotoPowAconcagua.
//
// The returned bytes has length 80.
// To try a nonce of uint32, put the nonce into the last 4 bytes of this []byte.
// See sealHashPreImage() and VerifySeal().
// This function is only use in demo of CPU mining.
func SealHashPreImage(header *wire.BlockHeader) ([]byte, error) {
	return sealHashPreImage(header)
}

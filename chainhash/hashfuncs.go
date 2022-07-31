package chainhash

import (
	"crypto/sha256"
	"golang.org/x/crypto/sha3"
)

// HashB calculates hash(b) and returns the resulting bytes.
func HashB(b []byte) []byte {
	hash := sha256.Sum256(b)
	return hash[:]
}

// HashH calculates hash(b) and returns the resulting bytes as a Hash.
func HashH(b []byte) Hash {
	return Hash(sha256.Sum256(b))
}

// DoubleHashB calculates hash(hash(b)) and returns the resulting bytes.
func DoubleHashB(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

// DoubleHashH calculates hash(hash(b)) and returns the resulting bytes as a
// Hash.
func DoubleHashH(b []byte) Hash {
	first := sha256.Sum256(b)
	return Hash(sha256.Sum256(first[:]))
}

// todo: (EthashPoW)
//	ChainHash() is used where chain is required, such as block (header) hash and merkle tree.
// We still use Hash function with 256-bit output, to be compatible with the current BlockHeader type.
func ChainHash(b []byte) Hash {
	return sha3.Sum256(b)
}

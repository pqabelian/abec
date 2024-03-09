package internal

import (
	"encoding/binary"
	"golang.org/x/crypto/sha3"
	"hash"
)

// This file provides functions for creating KMAC instance
//
//
// KMAC implementations is based on NIST SP 800-185 [1]
//
// [1] https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf

const (
	// "When used as a MAC, applications of this Recommendation shall
	// not select an output length L that is less than 32 bits, and
	// shall only select an output length less than 64 bits after a
	// careful risk analysis is performed."
	// 64 bits was selected for safety.
	kmacMinimumOutputSize = 8

	// used to define functions based on cSHAKE
	functionName = "KMAC"
)

// KMAC specific context
type kmac struct {
	sha3.ShakeHash     // cSHAKE context and Read/Write operations
	outputLen      int // tag size

	// initBlock is the KMAC specific initialization set of bytes. It is initialized
	// by newKMAC function and stores the key, encoded by the method specified in 4.3 of [1].
	// It is stored here in order for Reset() to be able to put context into
	// initial state.
	initBlock []byte
}

// NewKMAC128 creates a new instance of KMAC128 which providing 128 bits of security
// using the given key, which must have 16 bytes or more, generating the given tagSize
// bytes output and using the given domainSeparationCustomizationString.
// The implementation is based-on sha3.NewCShake128
// Note that unlike other hash implementations in the standard library,
// the returned Hash does not implement encoding.BinaryMarshaler
// or encoding.BinaryUnmarshaler.
func NewKMAC128(key []byte, outputLen int, domainSeparationCustomizationString []byte) hash.Hash {
	if len(key) < 16 {
		panic("Key must not be smaller than security strength")
	}

	c := sha3.NewCShake128([]byte(functionName), domainSeparationCustomizationString)
	return newKMAC(key, outputLen, c)
}

// NewKMAC256 creates a new instance of KMAC256 which providing 256 bits of security using
// the given key, which must have 32 bytes or more, generating the given tagSize
// bytes output and using the given domainSeparationCustomizationString.
// The implementation is based-on sha3.NewCShake256
// Note that unlike other hash implementations in the standard library,
// the returned Hash does not implement encoding.BinaryMarshaler
// or encoding.BinaryUnmarshaler.
func NewKMAC256(key []byte, outputLen int, domainSeparationCustomizationString []byte) hash.Hash {
	if len(key) < 32 {
		panic("Key must not be smaller than security strength")
	}
	c := sha3.NewCShake256([]byte(functionName), domainSeparationCustomizationString)
	return newKMAC(key, outputLen, c)
}

func newKMAC(key []byte, outputLen int, c sha3.ShakeHash) hash.Hash {
	if outputLen < kmacMinimumOutputSize {
		panic("tagSize is too small")
	}

	k := &kmac{ShakeHash: c, outputLen: outputLen}

	// leftEncode returns max 9 bytes
	k.initBlock = make([]byte, 0, 9+len(key))
	k.initBlock = append(k.initBlock, leftEncode(uint64(len(key)*8))...)
	k.initBlock = append(k.initBlock, key...)
	k.Write(bytepad(k.initBlock, k.BlockSize()))
	return k
}

// Reset resets the hash to initial state.
func (k *kmac) Reset() {
	k.ShakeHash.Reset()
	k.Write(bytepad(k.initBlock, k.ShakeHash.BlockSize()))
}

// BlockSize returns the hash block size.
func (k *kmac) BlockSize() int {
	return k.ShakeHash.BlockSize()
}

// Size returns the size of output.
func (k *kmac) Size() int {
	return k.outputLen
}

// Sum appends the current KMAC to b and returns the resulting slice.
// It does not change the underlying hash state.
func (k *kmac) Sum(b []byte) []byte {
	dup := k.ShakeHash.Clone()

	// right_encode(outputLen)
	dup.Write(rightEncode(uint64(k.outputLen * 8)))
	hash := make([]byte, k.outputLen)

	dup.Read(hash)
	return append(b, hash...)
}

// Clone returns copy of a KMAC context within its current state.
func (k *kmac) Clone() sha3.ShakeHash {
	b := make([]byte, len(k.initBlock))
	copy(b, k.initBlock)

	return &kmac{
		ShakeHash: k.ShakeHash.Clone(),
		outputLen: k.outputLen,
		initBlock: b,
	}
}

// bytepad prepends an encoding of the integer w to an input string X, then pads
// the result with zeros until it is a byte string whose length in bytes is a multiple of w
//
// specified in 2.3.3 of [1].
//
// copied from golang.org/x/crypto/sha3/shake.go
func bytepad(input []byte, w int) []byte {
	// leftEncode always returns max 9 bytes
	buf := make([]byte, 0, 9+len(input)+w)
	buf = append(buf, leftEncode(uint64(w))...)
	buf = append(buf, input...)
	padlen := w - (len(buf) % w)
	return append(buf, make([]byte, padlen)...)
}

// leftEncode encodes the integer x as a byte string in a way that can be unambiguously parsed
// from the beginning of the string by inserting the length of the byte string before the byte string
// representation of x.
//
// specified in 2.3.1 of [1].
//
// copied from golang.org/x/crypto/sha3/shake.go
func leftEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[1:], value)
	// Trim all but last leading zero bytes
	i := byte(1)
	for i < 8 && b[i] == 0 {
		i++
	}
	// Prepend number of encoded bytes
	b[i-1] = 9 - i
	return b[i-1:]
}

// rightEncode encodes the integer x as a byte string in a way that can be
// unambiguously parsed from the end of the string by inserting the length
// of the byte string after the byte string representation of x
//
// specified in 2.3.1 of [1].
func rightEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[:8], value)
	// Trim all but last leading zero bytes
	i := byte(0)
	for i < 7 && b[i] == 0 {
		i++
	}
	// Append number of encoded bytes
	b[8] = 8 - i
	return b[i:]
}

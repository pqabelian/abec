package ethash

import (
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"math/big"
	"testing"
	"time"
)

func hashToBigTest1(hash *chainhash.Hash) *big.Int {
	// As (hash Hash) String() returns the Hash as the hexadecimal string of the byte-reversed hash,
	// to make the big.Int value to be consistent with the displayed string, here also reverse it.
	// todo: optimize: directly use hash, rather than buf,since buf need allocate new memory
	buf := make([]byte, chainhash.HashSize)
	for i := 0; i < chainhash.HashSize/2; i++ {
		buf[i], buf[chainhash.HashSize-1-i] = hash[chainhash.HashSize-1-i], hash[i]
	}

	return new(big.Int).SetBytes(buf)
}

func hashToBigTest2(hash chainhash.Hash) *big.Int {
	// As (hash Hash) String() returns the Hash as the hexadecimal string of the byte-reversed hash,
	// to make the big.Int value to be consistent with the displayed string, here also reverse it.
	// todo: optimize: directly use hash, rather than buf,since buf need allocate new memory
	buf := make([]byte, chainhash.HashSize)
	for i := 0; i < chainhash.HashSize/2; i++ {
		buf[i], buf[chainhash.HashSize-1-i] = hash[chainhash.HashSize-1-i], hash[i]
	}

	return new(big.Int).SetBytes(buf)
}

func TestHashToBig(t *testing.T) {

	hash2 := chainhash.ChainHash([]byte("test"))

	start := time.Now()
	for i := 0; i < 100000000; i++ {
		//hashToBigTest2(hash2)
		//hashToBigTest1(&hash2)
		hashToBig(hash2)
	}
	elapsed := time.Since(start)
	fmt.Println("input hash, new buf:", elapsed)
	//fmt.Println("input pointer, new buf:", elapsed)
	//fmt.Println("input pointer, no new buf:", elapsed)
	// input hash, new buf: 2.351µs
	// input hash, new buf: 3.049µs
	// input hash, new buf: 2.928µs

	//input hash, new buf: 10.37741ms
	//input hash, new buf: 10.850817ms
	//input hash, new buf: 11.962192ms
	// input hash, new buf: 9.594273486s

	// input pointer, new buf: 12.729171ms
	// input pointer, new buf: 11.551211ms
	// input pointer, new buf: 11.693859ms
	//	input pointer, new buf: 10.259681615s

	// input pointer, no new buf: 11.720529ms
	// input pointer, no new buf: 14.85422ms
	// input pointer, no new buf: 11.496395ms
	// input pointer, no new buf: 10.714495779s

	//hash1 := chainhash.ChainHash([]byte("test"))
	//start := time.Now()
	//hashToBigTest1(&hash1)
	//elapsed := time.Since(start)
	//fmt.Println("input pointer, new buf:", elapsed)
	////input pointer, new buf: 2.806µs
	//// input pointer, new buf: 2.702µs
	//// input pointer, new buf: 5.979µs

	//hash := chainhash.ChainHash([]byte("test"))
	//start := time.Now()
	//hashToBig(&hash)
	//elapsed := time.Since(start)
	//fmt.Println("input pointer, no new buf:", elapsed)
	//// input pointer, no new buf: 2.78µs
	//// input pointer, no new buf: 2.593µs
	//// input pointer, no new buf: 2.721µs

	//if a.Cmp(b) == 0 {
	//	fmt.Println("a equal b")
	//}
	//
	//if a.Cmp(c) == 0 {
	//	fmt.Println("a equal c")
	//}
}

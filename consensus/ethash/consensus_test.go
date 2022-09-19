package ethash

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"golang.org/x/crypto/sha3"
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

func TestVerifySealFast(t *testing.T) {
	contentHashBytes, _ := hex.DecodeString("fc08e94e72a8c97961a13848c26887755cc39820a7f3b8ad8bb3f7decbfe253f")
	mixDigestBytes, _ := hex.DecodeString("718933ca9e97ce3b609e3249f23438268cdeecabb3087a080bed09c6429fd015")
	nonce := uint64(1090297)
	contentHash, _ := chainhash.NewHash(contentHashBytes)
	mixDigest, _ := chainhash.NewHash(mixDigestBytes)

	seedTmp := make([]byte, chainhash.HashSize+8)
	copy(seedTmp, contentHash[:])
	binary.LittleEndian.PutUint64(seedTmp[chainhash.HashSize:], nonce)

	// we use the standard SHA3-512, rather than LegacyKeccak512
	// seed = crypto.Keccak512(seed)
	//seed := make([]byte, 64)
	seed := sha3.Sum512(seedTmp)
	//copy(seed, hashTmp[:])

	sealHash := chainhash.ChainHash(append(seed[:], mixDigest[:]...))

	//	Optimization: directly copy the codes of hashToBig() here, rather call the function hashToBig(),
	//	since TrySeal() will be called in very frequently in mining.
	//	This part codes must match with that in VerifySeal().
	for i := 0; i < chainhash.HashSize/2; i++ {
		sealHash[i], sealHash[chainhash.HashSize-1-i] = sealHash[chainhash.HashSize-1-i], sealHash[i]
	}

	fmt.Println("VerifySealFast(): contentHash=", hex.EncodeToString(contentHash[:]), "nonceExt=", nonce, "mixdigest=", hex.EncodeToString(mixDigest[:]), "seal hash=", hex.EncodeToString(sealHash[:]))
}

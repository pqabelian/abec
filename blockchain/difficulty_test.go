package blockchain

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/abesuite/abec/chainhash"
)

func TestHashAndBigInt(t *testing.T) {
	hashBytes, err := hex.DecodeString("00000000000000000000000000000000000000000000000000000000000000000000000000002011")
	if err != nil {
		fmt.Println(err)
	}
	//hash, err := chainhash.NewHash(hashBytes)
	//if err != nil {
	//	fmt.Println(err)
	//}

	a := new(big.Int).SetBytes(hashBytes)

	fmt.Println("bigInt:", a)

	fmt.Println("bytes:", a.Bytes())

	buf := make([]byte, chainhash.HashSize)
	bigintBytes := a.FillBytes(buf)
	fmt.Println(bigintBytes)

	fmt.Println("TEST DIFFICULTY")

	//	todo: bits has only 32 bit, can denote large difficulty?
	bits := uint32(0x1d017c38)
	targetDifficulty := CompactToBig(bits)
	one := new(big.Int).SetInt64(1)

	//	todo: targetDifficulty <= 2^256?
	difficultyBytes := make([]byte, chainhash.HashSize)
	difficultyBytes = targetDifficulty.FillBytes(difficultyBytes)
	fmt.Println("difficultyBits: 0x1d017c38")
	fmt.Println("difficultyBytes:", difficultyBytes)
	fmt.Println("difficultyString:", hex.EncodeToString(difficultyBytes))

	targetsubone := new(big.Int).SetBytes(targetDifficulty.Bytes())
	targetsubone.Sub(targetsubone, one)
	targetsuboneBytes := make([]byte, chainhash.HashSize)
	targetsuboneBytes = targetsubone.FillBytes(targetsuboneBytes)
	fmt.Println("-1 Bytes:", targetsuboneBytes)
	fmt.Println("-1 String:", hex.EncodeToString(targetsuboneBytes))

	targetaddone := new(big.Int).SetBytes(targetDifficulty.Bytes())
	targetaddone.Add(targetaddone, one)
	targetaddoneBytes := make([]byte, chainhash.HashSize)
	targetaddoneBytes = targetaddone.FillBytes(targetaddoneBytes)
	fmt.Println("+1 Bytes:", targetaddoneBytes)
	fmt.Println("+1 String:", hex.EncodeToString(targetaddoneBytes))

	//bits = uint32(0x1c07ae7b)
	//targetDifficulty = CompactToBig(bits)
	//
	////	todo: targetDifficulty <= 2^256?
	//difficultyBytes = make([]byte, chainhash.HashSize)
	//difficultyBytes = targetDifficulty.FillBytes(difficultyBytes)
	//fmt.Println("difficultyBits: 0x1c07ae7b")
	//fmt.Println("difficultyBytes:", difficultyBytes)
	//fmt.Println("difficultyString:", hex.EncodeToString(difficultyBytes))

	//	CUDA
	//	uint64_t upper64OfBoundary = (uint64_t)(u64)((u256)current.boundary >> 192);
	//	where current.boundary is h256
	//using u256 = boost::multiprecision::number<boost::multiprecision::cpp_int_backend<256, 256,
	//	boost::multiprecision::unsigned_magnitude, boost::multiprecision::unchecked, void>>;

}

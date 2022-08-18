package chainhash

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestZeroHash(t *testing.T) {
	blockHashs := make([]*Hash, 3)

	hash0 := Hash{}
	binary.BigEndian.PutUint32(hash0[0:4], uint32(0x01))
	//	todo: (EthashPoW) validity check of coinbaseTx should check this: the first 4 bytes is the block height.

	//hash1 := chainhash.Hash{}
	//binary.BigEndian.PutUint64(hash1[0:8], extraNonce)
	hash1 := ZeroHash
	hash2 := ZeroHash
	//	todo: (EthashPoW) validity check of coinbaseTx will not check these two hashes, to leave it free

	binary.BigEndian.PutUint64(hash1[0:8], uint64(0x2))
	binary.BigEndian.PutUint64(hash2[0:8], uint64(0x3))

	blockHashs[0] = &hash0
	blockHashs[1] = &hash1
	blockHashs[2] = &hash2

	fmt.Println(blockHashs[0])
	fmt.Println(blockHashs[1])
	fmt.Println(blockHashs[2])

	fmt.Println(hex.EncodeToString(blockHashs[0][:]))
	fmt.Println(hex.EncodeToString(blockHashs[1][:]))
	fmt.Println(hex.EncodeToString(blockHashs[2][:]))
}

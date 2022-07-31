package wire

import (
	"bytes"
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"testing"
)

func TestBlockHeader_BlockHash(t *testing.T) {
	ver := int32(0x10000000)
	verEthash := int32(BlockVersionEthashPow)

	prevBlk := chainhash.ChainHash([]byte("prevblk"))
	merkroot := chainhash.ChainHash([]byte("merkleroot"))
	// time
	bits := uint32(1)

	heightEthash := int32(40000)

	nonce := uint32(1)
	nonceExt := uint64(2)
	mixDigest := chainhash.ChainHash([]byte("mixdigest"))

	bh := NewBlockHeader(ver, &prevBlk, &merkroot, bits, nonce)

	bhEthash := NewBlockHeaderEthash(verEthash, &prevBlk, &merkroot, bits, heightEthash, nonceExt, &mixDigest)

	fmt.Println(bh.BlockHash())

	fmt.Println(bhEthash.BlockHash())

	fmt.Println(bhEthash.BlockHashEthash())
}

func TestBlockHeader_BtcEncode(t *testing.T) {
	ver := int32(0x10000000)
	verEthash := int32(BlockVersionEthashPow)

	prevBlk := chainhash.ChainHash([]byte("prevblk"))
	merkroot := chainhash.ChainHash([]byte("merkleroot"))
	// time
	bits := uint32(1)

	heightEthash := int32(40000)

	nonce := uint32(1)
	nonceExt := uint64(2)
	mixDigest := chainhash.ChainHash([]byte("mixdigest"))

	bh := NewBlockHeader(ver, &prevBlk, &merkroot, bits, nonce)

	bhEthash := NewBlockHeaderEthash(verEthash, &prevBlk, &merkroot, bits, heightEthash, nonceExt, &mixDigest)

	w := bytes.NewBuffer(make([]byte, 0, blockHeaderLen))
	err := bh.BtcEncode(w, 0, 0)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(w.Bytes())
	fmt.Println("hash by encode (v1):", chainhash.DoubleHashH(w.Bytes()))
	fmt.Println("hash by object (v1):", bh.BlockHash())

	weth := bytes.NewBuffer(make([]byte, 0, blockHeaderLenEthash))
	err = bhEthash.BtcEncode(weth, 0, 0)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(weth.Bytes())
	fmt.Println("hash by encode (v2):", chainhash.ChainHash(weth.Bytes()))
	fmt.Println("hash by object (v2):", bhEthash.BlockHash())
	fmt.Println("hash by object (v2) (ethash):", bhEthash.BlockHashEthash())

	fmt.Println("Decode:")

	rbh := BlockHeader{}
	rbh.BtcDecode(w, 0, 0)
	if rbh.Nonce != bh.Nonce {
		fmt.Println("wrong in Decode")
	}
	fmt.Println("recovered BH hash by object (v1):", rbh.BlockHash())

	rbhEth := BlockHeader{}
	rbhEth.BtcDecode(weth, 0, 0)
	if rbhEth.NonceExt != bhEthash.NonceExt {
		fmt.Println("wrong in Decode for ethhash")
	}
	fmt.Println("recovered BH hash by object (v2):", rbhEth.BlockHash())
	fmt.Println("recovered BH hash by object (v2) (ethash):", rbhEth.BlockHashEthash())
}

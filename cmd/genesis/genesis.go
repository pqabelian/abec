package main

import (
	"encoding/hex"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abepqringct"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"log"
	"time"
)

func main() {
	gensis()
}
func gensis() {
	seed := []byte{
		0, 0, 0, 1,
		219, 217, 91, 2, 159, 136, 1, 196, 124, 21, 172, 45, 38, 93, 166, 104, 63, 44, 77, 35, 189, 247, 110, 45, 52, 145, 117, 158, 38, 15, 152, 122,
		61, 254, 149, 166, 25, 239, 148, 229, 111, 42, 136, 249, 231, 100, 67, 134, 20, 80, 87, 78, 169, 196, 253, 137, 98, 107, 133, 174, 161, 254, 106, 236,
	}
	fmt.Printf("seed = %s\n",hex.EncodeToString(seed))
	serializedSeed, mpk, _, _, err := abepqringct.MasterKeyGen(seed, abecrypto.CryptoSchemePQRINGCT)
	if err!=nil{
		log.Fatalf("error in MasterKeyGen")
	}
	fmt.Println(serializedSeed)
	txOutDescs:=make([]*abepqringct.AbeTxOutDesc,1)
	for i := 0; i < len(txOutDescs); i++ {
		txOutDescs[i]=abepqringct.NewAbeTxOutDesc(mpk,5120000000)
	}
	cbTxTemplate:=&wire.MsgTxAbe{
		Version:   wire.TxVersion,
		TxIns:     []*wire.TxInAbe{
			{
				SerialNumber: chainhash.ZeroHash[:],
				PreviousOutPointRing: wire.OutPointRing{
					Version: wire.TxVersion,
					BlockHashs: []*chainhash.Hash{
						&chainhash.ZeroHash,
						{
							0x48, 0x68, 0x46,
						}, //this value can be covered by any value as a nonce of coinbase
						{
							/*This is the first block of abe*/
							0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
							0x68, 0x65, 0x20, 0x66, 0x69, 0x72, 0x73, 0x74, 0x20,
							0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x6f, 0x66, 0x20,
							0x61, 0x62, 0x65,
						}, //this value can be any value
					},
					OutPoints: []*wire.OutPointAbe{
						{
							TxHash: chainhash.ZeroHash, // empty hash value
							Index:  0,                  // the index will be limited in a special range
						},
					},
				},
			},
		},
		TxOuts:    nil,
		TxFee:     5120000000, //as the vin
		TxMemo:    []byte{0,1,2,3,4,5,6,7,8,9,10,11,12,13,15},
		TxWitness: nil,
	}
	genesisCoinbaseTx, err := abepqringct.CoinbaseTxGen(txOutDescs, cbTxTemplate)
	if err!=nil{
		log.Fatalf("error in CoinbaseTxGen")
	}
	fmt.Println("txoscript:")
	for i := 0; i < len(genesisCoinbaseTx.TxOuts[0].TxoScript); i++ {
		fmt.Printf("%#02X, ",genesisCoinbaseTx.TxOuts[0].TxoScript[i])
		if i %16==15{
			fmt.Println()
		}
	}
	fmt.Println()
	fmt.Println("txwitness:")
	for i := 0; i < len(genesisCoinbaseTx.TxWitness); i++ {
		fmt.Printf("%#02X, ",genesisCoinbaseTx.TxWitness[i])
		if i %16 == 15{
			fmt.Println()
		}
	}
	genesisMerkleRoot := genesisCoinbaseTx.TxHash()
	fmt.Println("coinbase tx hash:")
	for i := 0; i < len(genesisMerkleRoot); i++ {
		fmt.Printf("%#2x, ", genesisMerkleRoot[i])
	}
	fmt.Println()
	currentTime := time.Now()
	fmt.Println("Time:")
	fmt.Printf("%#x", currentTime.Unix())
	fmt.Println()
	genesisBlock := wire.MsgBlockAbe{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  chainhash.Hash{},
			MerkleRoot: genesisMerkleRoot,
			Timestamp:  currentTime,
			Bits:       0x1e01ffff,
			Nonce:      0,
		},
		Transactions: []*wire.MsgTxAbe{genesisCoinbaseTx},
	}
	for i := uint32(0); i <= ^uint32(0); i++ {
		genesisBlock.Header.Nonce = i
		hash := genesisBlock.Header.BlockHash()
		targetDifficulty := blockchain.CompactToBig(genesisBlock.Header.Bits)
		if blockchain.HashToBig(&hash).Cmp(targetDifficulty) <= 0 {
			fmt.Println("Successful!")
			fmt.Println("genesis block hash:")
			for i := 0; i < len(hash); i++ {
				fmt.Printf("%#.2x, ", hash[i])
			}
			fmt.Println()
			fmt.Println("Nonce:")
			fmt.Printf("%#x", genesisBlock.Header.Nonce)
			return
		}
	}
	return
}
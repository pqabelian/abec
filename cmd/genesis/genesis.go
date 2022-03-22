package main

import (
	"encoding/hex"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"log"
	"os"
	"time"
)

func main() {
	gensis()
}
func gensis() {
	f, err := os.OpenFile("genesisblock.txt", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		log.Fatalln("error open output file")
	}
	defer f.Close()
	seed := []byte{
		//0, 0, 0, 2,
		219, 217, 91, 2, 159, 136, 1, 196, 124, 21, 172, 45, 38, 93, 166, 104, 63, 44, 77, 35, 189, 247, 110, 45, 52, 145, 117, 158, 38, 15, 152, 122,
		61, 254, 149, 166, 25, 239, 148, 229, 111, 42, 136, 249, 231, 100, 67, 134, 20, 80, 87, 78, 169, 196, 253, 137, 98, 107, 133, 174, 161, 254, 106, 236,
	}
	_, err = fmt.Fprintf(f, "seed = %s\n", hex.EncodeToString(seed))
	if err != nil {
		panic(err)
	}
	//retSerializedCryptoAddress, retSerializedVSk, retSerializedASksp, retSerializedASksn, err := abecrypto.CryptoPP.AbeCryptoAddressGen(seed)
	retSerializedCryptoAddress, _, _, _, err := abecrypto.CryptoPP.AbeCryptoAddressGen(seed)
	if err != nil {
		log.Fatalf("error in MasterKeyGen")
	}
	fmt.Println(hex.EncodeToString(retSerializedCryptoAddress))
	fmt.Fprintln(f, seed)
	return
	txOutDescs := make([]*abecrypto.AbeTxOutDesc, 1)
	for i := 0; i < len(txOutDescs); i++ {
		txOutDescs[i] = abecrypto.NewAbeTxOutDesc(retSerializedCryptoAddress, 205_799_813_685_247)
	}
	cbTxTemplate := &wire.MsgTxAbe{
		Version: wire.TxVersion,
		TxIns: []*wire.TxInAbe{
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
		TxOuts: nil,
		TxFee:  205_799_813_685_247, //as the vin
		TxMemo: []byte{ // "All my life's efforts, but to complete the ordinary life"
			0x41, 0x6c, 0x6c, 0x20, 0x6d, 0x79, 0x20, 0x6c, 0x69, 0x66, 0x65, 0x27, 0x73, 0x20, 0x65, 0x66,
			0x66, 0x6f, 0x72, 0x74, 0x73, 0x2c, 0x20, 0x62, 0x75, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x63, 0x6f,
			0x6d, 0x70, 0x6c, 0x65, 0x74, 0x65, 0x20, 0x74, 0x68, 0x65, 0x20, 0x6f, 0x72, 0x64, 0x69, 0x6e,
			0x61, 0x72, 0x79, 0x20, 0x6c, 0x69, 0x66, 0x65,
		},
		TxWitness: nil,
	}
	genesisCoinbaseTx, err := abecrypto.CryptoPP.CoinbaseTxGen(txOutDescs, cbTxTemplate)
	if err != nil {
		log.Fatalf("error in CoinbaseTxGen")
	}
	fmt.Fprintln(f, "txoscript:")
	for i := 0; i < len(genesisCoinbaseTx.TxOuts[0].TxoScript); i++ {
		fmt.Fprintf(f, "%#02X, ", genesisCoinbaseTx.TxOuts[0].TxoScript[i])
		if i%16 == 15 {
			fmt.Fprintln(f)
		}
	}
	fmt.Fprintln(f)
	fmt.Fprintln(f, "txwitness:")
	for i := 0; i < len(genesisCoinbaseTx.TxWitness); i++ {
		fmt.Fprintf(f, "%#02X, ", genesisCoinbaseTx.TxWitness[i])
		if i%16 == 15 {
			fmt.Fprintln(f)
		}
	}
	genesisMerkleRoot := genesisCoinbaseTx.TxHash()
	fmt.Fprintln(f, "coinbase tx hash:")
	for i := 0; i < len(genesisMerkleRoot); i++ {
		fmt.Fprintf(f, "%#2x, ", genesisMerkleRoot[i])
	}
	fmt.Fprintln(f)
	currentTime := time.Now()
	fmt.Fprintln(f, "Time:")
	fmt.Fprintf(f, "%#x", currentTime.Unix())
	fmt.Fprintln(f)
	genesisBlock := wire.MsgBlockAbe{
		Header: wire.BlockHeader{
			Version:    1,
			PrevBlock:  chainhash.Hash{},
			MerkleRoot: genesisMerkleRoot,
			Timestamp:  currentTime,
			Bits:       0x1e01ffff, // TODO(adjust difficult...need to estimate the speed of whole network):256s per block？
			Nonce:      0,
		},
		Transactions: []*wire.MsgTxAbe{genesisCoinbaseTx},
	}
	for i := uint32(0); i <= ^uint32(0); i++ {
		genesisBlock.Header.Nonce = i
		hash := genesisBlock.Header.BlockHash()
		targetDifficulty := blockchain.CompactToBig(genesisBlock.Header.Bits)
		if blockchain.HashToBig(&hash).Cmp(targetDifficulty) <= 0 {
			fmt.Fprintln(f, "Successful!")
			fmt.Fprintln(f, "genesis block hash:")
			for i := 0; i < len(hash); i++ {
				fmt.Fprintf(f, "%#.2x, ", hash[i])
			}
			fmt.Fprintln(f)
			fmt.Fprintln(f, "Nonce:")
			fmt.Fprintf(f, "%#x", genesisBlock.Header.Nonce)
			return
		}
	}
	return
}

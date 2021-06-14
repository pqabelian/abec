package pqringctparam

import (
	"github.com/cryptosuite/pqringct"
)

var CryptoPP *pqringct.PublicParameter = pqringct.DefaultPP

// todo: when multiple versions are supported simultaneously, and if necessary, initial multiple nullSerialNumbers
var nullSerialNumber []byte = []byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

//	todo:
func GetMasterPublicKeyLen(version uint32) uint32 {
	return CryptoPP.GetMasterPublicKeyByteLen()
}

/*
Based on the (crypto-scheme) version of the Txo, return the maxAllowedLen
*/
/*func GetTxoScriptLen(version uint32) uint32 {
	// todo: call cryptoPP.methods
	return CryptoPP.GetTxoByteLen()
}*/

func GetTxoSerializeSize(version uint32) uint32 {
	// todo: call cryptoPP.methods
	return CryptoPP.GetTxoSerializeSize()
}

func GetTrTxWitnessSize(txVersion uint32, inputRingSizes []int, outputTxoNum uint8) uint32 {
	//	todo: call cryptoPP.methods
	return CryptoPP.GetTrTxWitnessSerializeSize(inputRingSizes, outputTxoNum)
}

func GetTxMemoMaxLen(version uint32) uint32 {
	// todo: call cryptoPP.methods
	return 32
}

func GetTxWitnessMaxLen(version uint32) uint32 {
	// todo: call cryptoPP.methods
	return func(a, b uint32) uint32 {
		if a > b {
			return a
		}
		return b
	}(CryptoPP.GetCbTxWitnessMaxLen(), CryptoPP.GetTrTxWitnessMaxLen())

}

func GetMaxCoinValue(version uint32) uint64 {
	// todo: call cryptoPP.methods
	return 1
}

func GetCoinbaseTxWitnessLen(version uint32, txOutNum int) uint32 {
	// todo: call cryptoPP.methods
	return 1
}

// todo: remove this
func GetTxWitnessItemMaxLen(version uint32) uint32 {
	// todo: call cryptoPP.methods
	return 1
}

/*
The length of serialNumber will be small, e.g. 32 or 64 bytes.
TxoSerialNumberLen and underlying (Hash) algorothm will keep unchange.
*/
func GetTxoSerialNumberLen(version uint32) int {
	// todo: call cryptoPP.methods
	return 32
}

func GetNullSerialNumber(version uint32) []byte {
	return nullSerialNumber
}

func GetInputMaxNum(version uint32) int {
	// todo
	return 5
}

func GetOutputMaxNum(version uint32) int {
	// todo
	return 5
}

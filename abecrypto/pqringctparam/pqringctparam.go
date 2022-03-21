package pqringctparam

import "github.com/cryptosuite/pqringct"

var CryptoPP = pqringct.DefaultPPV2

// todo: when multiple versions are supported simultaneously, and if necessary, initial multiple nullSerialNumbers
var nullSerialNumber []byte = []byte{
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
}

//	todo:
func GetMasterPublicKeyLen(version uint32) uint32 {
	return uint32(CryptoPP.GetPublicKeyByteLen())
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
	return uint32(CryptoPP.GetTxoSerializeSize(version))
}

/*
The input rings for one transction should have the same ringVersions
*/
func GetTrTxWitnessSize(txVersion uint32, inputRingVersion uint32, inputRingSizes []int, outputTxoNum uint8) uint32 {
	//	todo: call cryptoPP.methods
	return uint32(CryptoPP.GetTrTxWitnessSerializeSize(txVersion, inputRingVersion, inputRingSizes, outputTxoNum))
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
		// TODO(20220320): decide the parameter
	}(uint32(CryptoPP.GetCbTxWitnessMaxLen(version, 5)), uint32(CryptoPP.GetTrTxWitnessMaxLen(version)))

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

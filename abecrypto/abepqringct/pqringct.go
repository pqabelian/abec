package abepqringct

import "github.com/cryptosuite/pqringct"

var cryptoPP *pqringct.PublicParameter = pqringct.DefaultPP

// todo: when multiple versions are supported simultaneously, and if necessary, initial multiple nullSerialNumbers
var nullSerialNumber []byte

/*
Based on the (crypto-scheme) version of the Txo, return the maxAllowedLen
*/
func GetTxoScriptMaxLen(version uint16) uint32 {
	// todo: call cryptoPP.methods
	return 1
}

func GetTxMemoMaxLen(version uint16) uint32 {
	// todo: call cryptoPP.methods
	return 1
}

func GetTxWitnessMaxLen(version uint16) uint32 {
	// todo: call cryptoPP.methods
	return 1
}

/*
The length of serialNumber will be small, e.g. 32 or 64 bytes.
*/
func GetTxoSerialNumberLen(version uint16) int {
	// todo: call cryptoPP.methods
	return 1
}

func GetNullSerialNumber(version uint16) []byte {
	return nullSerialNumber
}

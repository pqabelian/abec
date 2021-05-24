package abepqringct

// todo: when multiple versions are supported simultaneously, and if necessary, initial multiple nullSerialNumbers
var nullSerialNumber []byte

/*
Based on the (crypto-scheme) version of the Txo, return the maxAllowedLen
*/
func GetTxoScriptMaxLen(version uint32) uint32 {
	// todo: call cryptoPP.methods
	return 1
}

func GetTxMemoMaxLen(version uint32) uint32 {
	// todo: call cryptoPP.methods
	return 1
}

func GetTxWitnessMaxLen(version uint32) uint32 {
	// todo: call cryptoPP.methods
	return 1
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
*/
func GetTxoSerialNumberLen(version uint32) int {
	// todo: call cryptoPP.methods
	return 1
}

func GetNullSerialNumber(version uint32) []byte {
	return nullSerialNumber
}

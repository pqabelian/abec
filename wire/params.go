package wire

type WireParam struct {
	version              uint32
	blockNumPerRingGroup uint8
	txRingSize           uint8
	txInputMaxNum        uint8
	txOutputMaxNum       uint8
	defaultTxInputAlloc  uint8
}

var wireParamV1 = WireParam{
	version:              1,
	blockNumPerRingGroup: 3,
	txRingSize:           7,
	txInputMaxNum:        5,
	txOutputMaxNum:       5,
	defaultTxInputAlloc:  3,
}

// if more versions are supported
/*var wireParamV2 = WireParam{
	version: 1,
	blockNumPerRingGroup: 3,
	txRingSize: 7,
	txInputMaxNum: 5,
	txOutputMaxNum: 5,
	defaultTxInputAlloc: 3,
}*/

func GetCurrentWireVersion() uint32 {
	return wireParamV1.version
}

func GetWireParamBlockNumPerRingGroup(version uint32) uint8 {
	if version == wireParamV1.version {
		return wireParamV1.blockNumPerRingGroup
	}
	// if more versions are supported
	/*	if version == wireParamV2.version{
		return wireParamV2.blockNumPerRingGroup
	}*/

	return 0
}

func GetWireParamTxRingSize(version uint32) uint8 {
	if version == wireParamV1.version {
		return wireParamV1.txRingSize
	}
	// if more versions are supported
	/*	if version == wireParamV2.version{
		return wireParamV2.blockNumPerRingGroup
	}*/

	return 0
}

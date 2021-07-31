package wire

type WireParam struct {
	wireVersion          uint32
	blockNumPerRingGroup uint8
	blockVersion         uint32
	txVersion            uint32
	txRingSize           uint8
	txInputMaxNum        uint8
	txOutputMaxNum       uint8
	defaultTxInputAlloc  uint8
}

var wireParamV1 = WireParam{
	wireVersion:          1,
	blockNumPerRingGroup: 3,
	blockVersion:         1,
	txVersion:            1,
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

func GetCurrentBlockVersion() uint32 {
	return wireParamV1.blockVersion
}

func GetCurrentTxVersion() uint32 {
	return wireParamV1.txVersion
}

func GetWireParamBlockNumPerRingGroup(version uint32) uint8 {
	if version == wireParamV1.wireVersion {
		return wireParamV1.blockNumPerRingGroup
	}
	// if more versions are supported
	/*	if version == wireParamV2.version{
		return wireParamV2.blockNumPerRingGroup
	}*/

	return 0
}

func GetWireParamTxRingSize(version uint32) uint8 {
	if version == wireParamV1.wireVersion {
		return wireParamV1.txRingSize
	}
	// if more versions are supported
	/*	if version == wireParamV2.version{
		return wireParamV2.blockNumPerRingGroup
	}*/

	return 0
}
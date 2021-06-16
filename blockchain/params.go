package blockchain

type BlockchainParam struct {
	blockchainVersion    uint32
	txWitnessScaleFactor float32
}

var blockchainParamV1 = BlockchainParam{
	blockchainVersion:    1,
	txWitnessScaleFactor: 0.5,
}

func GetWireParamTxWitnessScaleFactor(version uint32) float32 {
	if version == blockchainParamV1.blockchainVersion {
		return blockchainParamV1.txWitnessScaleFactor
	}
	return 0
}

package ctaut

type AutTxo struct {
	Version   uint32
	TxoScript []byte
}

type AutCoinbaseTx struct {
	Version   uint32
	Vin       uint64
	TxOuts    []*AutTxo
	TxWitness []byte
}

type AutTransferTx struct {
	Version   uint32
	TxIns     []*AutTxo
	TxOuts    []*AutTxo
	TxWitness []byte
}

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

// AutTransferTx is only used to generate/verify TxOuts and balance proof.
//
// As a result, TxIns directly and only contain AutTxo.
type AutTransferTx struct {
	Version   uint32
	TxIns     []*AutTxo
	TxOuts    []*AutTxo
	TxWitness []byte
}

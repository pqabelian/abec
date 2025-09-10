package ctaut

type CTAutTxo struct {
	Version   uint32
	TxoScript []byte
}
type CTAutCoinbaseTx struct {
	Version   uint32
	Vin       uint64
	TxOuts    []*CTAutTxo
	TxWitness []byte
}

type CTAutTransferTx struct {
	Version   uint32
	TxIns     []*CTAutTxo
	TxOuts    []*CTAutTxo
	TxWitness []byte
}

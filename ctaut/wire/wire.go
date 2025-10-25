package wire

import (
	"io"

	"github.com/abesuite/abec/wire"
)

type AutTxo struct {
	Version   uint32
	TxoScript []byte
}

func (txo *AutTxo) SerializeSize() int {
	return 4 + wire.VarIntSerializeSize(uint64(len(txo.TxoScript))) + len(txo.TxoScript)
}
func (txo *AutTxo) Serialize(w io.Writer) error {
	err := wire.WriteVarInt(w, 0, uint64(txo.Version))
	if err != nil {
		return err
	}
	err = wire.WriteVarBytes(w, 0, txo.TxoScript)
	if err != nil {
		return err
	}
	return nil
}

// For aconcagua:
// - hidden value script is 10959
// - publuc value script is 9
const MaxAUTValueScriptLength = 16 * 1024

func (txo *AutTxo) Deserialize(r io.Reader) error {
	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	txo.Version = uint32(version)
	if txo.TxoScript, err = wire.ReadVarBytes(r, 0, MaxAUTValueScriptLength, "aut txo script"); err != nil {
		return err
	}
	return nil
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

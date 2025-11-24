package wire

import (
	"bytes"
	"fmt"
	"github.com/abesuite/abec/wire"
	"math"
)

type AutTxo struct {
	Version   uint32 // Inherit the AutScriptVersion
	TxoScript []byte
}

func (txo *AutTxo) SerializeSize() int {
	return wire.VarIntSerializeSize(uint64(txo.Version)) +
		wire.VarIntSerializeSize(uint64(len(txo.TxoScript))) + len(txo.TxoScript)
}

func (txo *AutTxo) Serialize() ([]byte, error) {
	w := bytes.NewBuffer(make([]byte, 0, txo.SerializeSize()))

	err := wire.WriteVarInt(w, 0, uint64(txo.Version))
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(w, 0, txo.TxoScript)
	if err != nil {
		return nil, err
	}
	return w.Bytes(), nil
}

// For aconcagua:
// - hidden value script is 10959
// - public value script is 9

const MaxAutTxoScriptLength = 16 * 1024

func (txo *AutTxo) Deserialize(serializedAutTxo []byte) error {
	r := bytes.NewBuffer(serializedAutTxo)

	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if version > math.MaxUint32 {
		return fmt.Errorf("readed version (%d) is too big", version)
	}
	txo.Version = uint32(version)

	if txo.TxoScript, err = wire.ReadVarBytes(r, 0, MaxAutTxoScriptLength, "autTxo.TxoScript"); err != nil {
		return err
	}
	return nil
}

type AutCoinbaseTx struct {
	Version   uint32 // AutScriptVersion
	Vin       uint64
	TxOuts    []*AutTxo
	TxWitness []byte
}

// AutTransferTx is only used to generate/verify TxOuts and balance proof.
//
// As a result, TxIns directly and only contain AutTxo.
type AutTransferTx struct {
	Version   uint32 // AutScriptVersion
	TxIns     []*AutTxo
	TxOuts    []*AutTxo
	TxWitness []byte
}

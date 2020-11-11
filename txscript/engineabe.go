package txscript

import (
	"fmt"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/abesuite/abec/abecrypto/abesalrs"
)

// TypeFlags is a bitmask defining which type of item should engine verify.
type TypeFlags uint32

const (
	// ItemInput indicates that input should be verified
	ItemInput TypeFlags = 1 << iota

	// ItemOutput indicates that output should be verified
	ItemOutput

	// ItemBalance indicates that balance should be verified
	ItemBalance
)

// EngineAbe is the virtual machine that verify the signature of the transaction.
type EngineAbe struct {
	txHash          *chainhash.Hash
	msgTx           *wire.MsgTxAbe
	txInIndex       int
	txOutIndex      int
	utxoRing        *blockchain.UtxoRingEntry
	flags           TypeFlags
}

// Execute verify the signature of the transaction.
func (vm *EngineAbe) Execute() (err error) {

	if vm.flags & ItemInput == ItemInput {
		// Get message hash.
		txMsgHash := vm.txHash
		// Find correspondent signature. Will be changed in the future.
		signature := vm.msgTx.TxWitness.Witnesses[vm.txInIndex]
		// Collect all the outputs in the ring, which can be used to form derived public key ring later.
		txConsumed := vm.utxoRing.TxOuts()

		// Convert message hash to bytes.
		msg := txMsgHash.CloneBytes()
		// Deserialize signature
		sig, err := abesalrs.DeserializeSignature(signature)
		if err != nil {
			return fmt.Errorf("error occurs when deserializing signature %v", err)
		}

		// Form public key ring.
		derivedPubKey := make([]abesalrs.DerivedPubKey, 0, len(txConsumed))
		for i := 0 ; i < len(txConsumed) ; i++{
			dpk, err := abesalrs.DeseralizeDerivedPubKey(txConsumed[i].AddressScript)
			if err != nil {
				return fmt.Errorf("error occurs when deserializing addressScript %v", err)
			}
			derivedPubKey = append(derivedPubKey, *dpk)
		}
		dpkRing := &abesalrs.DpkRing{
			Dpks:      derivedPubKey,
			R:         len(txConsumed),
		}

		// Verify signature.
		_, succeed, err := abesalrs.Verify(msg, dpkRing, sig)
		if !succeed {
			return fmt.Errorf("script verify failed")
		}
	}

	// todo
	if vm.flags & ItemOutput == ItemOutput {
		return nil
	}

	// todo
	if vm.flags & ItemBalance == ItemBalance {
		return nil
	}

	return nil
}

// NewEngineAbe returns a new script engine for the transaction hash,
// signature and transaction ring consumed
func NewEngineAbe(txHash *chainhash.Hash, msgTx *wire.MsgTxAbe, txInIndex int, txOutIndex int, utxoRing *blockchain.UtxoRingEntry, flags TypeFlags) (*EngineAbe, error) {

	vm := EngineAbe{txHash: txHash, msgTx: msgTx, txInIndex: txInIndex, txOutIndex: txOutIndex, utxoRing: utxoRing, flags: flags}

	return &vm, nil
}

// decrepted
// NewEngineAbe returns a new script engine for the transaction hash,
// signature and transaction ring consumed
//func NewEngineAbe2(txMsgHash *chainhash.Hash, signature []byte, txConsumed []*wire.TxOutAbe) (*EngineAbe, error) {
//
//	if len(signature) == 0 {
//		return nil, scriptError(ErrNoData, "no data in signature when constructing script engine")
//	}
//
//	if len(txConsumed) == 0 {
//		return nil, scriptError(ErrNoData, "no data in transaction output ring when constructing script engine")
//	}
//
//	vm := EngineAbe{txMsgHash: txMsgHash, signature: signature, txConsumed: txConsumed}
//
//	return &vm, nil
//}

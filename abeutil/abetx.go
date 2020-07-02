package abeutil

import (
	"bytes"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"io"
)

// TxIndexUnknown is the value returned for a transaction index that is unknown.
// This is typically because the transaction has not been inserted into a block
// yet.
const TxAbeIndexUnknown = -1

// Tx defines a bitcoin transaction that provides easier and more efficient
// manipulation of raw transactions.  It also memoizes the hash for the
// transaction on its first access so subsequent accesses don't have to repeat
// the relatively expensive hashing operations.
type TxAbe struct {
	msgTx  *wire.MsgTxAbe  // Underlying MsgTx
	txHash *chainhash.Hash // Cached transaction hash
	//	txPersistentHash	*chainhash.Hash // Cached transaction witness hash
	//	txHasTxoDetails *bool // if the transaction has txo details
	txHasWitness *bool // If the transaction has witness data
	txIndex      int   // Position within a block or TxIndexUnknown
}

// MsgTx returns the underlying wire.MsgTx for the transaction.
func (tx *TxAbe) MsgTx() *wire.MsgTxAbe {
	// Return the cached transaction.
	return tx.msgTx
}

func (tx *TxAbe) IsCoinBase() bool {
	return tx.msgTx.IsCoinBase()
}

/*// Hash returns the hash of the transaction.  This is equivalent to
// calling TxHash on the underlying wire.MsgTx, however it caches the
// result so subsequent calls are more efficient.
func (tx *TxAbe) ContentHash() *chainhash.Hash {
	// Return the cached hash if it has already been generated.
	if tx.txContentHash != nil {
		return tx.txContentHash
	}

	// Cache the hash and return it.
	hash := tx.msgTx.TxContentHash()
	tx.txContentHash = &hash
	return &hash
}
*/

func (tx *TxAbe) Hash() *chainhash.Hash {
	// Return the cached hash if it has already been generated.
	if tx.txHash != nil {
		return tx.txHash
	}

	// Cache the hash and return it.
	hash := tx.msgTx.TxHash()
	tx.txHash = &hash
	return &hash
}

/*// Hash returns the hash of the transaction.  This is equivalent to
// calling TxHash on the underlying wire.MsgTx, however it caches the
// result so subsequent calls are more efficient.
func (tx *TxAbe) PersistentHash() *chainhash.Hash {
	// Return the cached hash if it has already been generated.
	if tx.txPersistentHash != nil {
		return tx.txPersistentHash
	}

	// Cache the hash and return it.
	hash := tx.msgTx.TxPersistentHash()
	tx.txPersistentHash = &hash
	return &hash
}*/

// HasWitness returns false if none of the inputs within the transaction
// contain witness data, true false otherwise. This equivalent to calling
// HasWitness on the underlying wire.MsgTx, however it caches the result so
// subsequent calls are more efficient.
func (tx *TxAbe) HasWitness() bool {
	if tx.txHasWitness != nil {
		return *tx.txHasWitness
	}

	hasWitness := tx.msgTx.HasWitness()
	tx.txHasWitness = &hasWitness
	return hasWitness
}

// Index returns the saved index of the transaction within a block.  This value
// will be TxIndexUnknown if it hasn't already explicitly been set.
func (tx *TxAbe) Index() int {
	return tx.txIndex
}

// SetIndex sets the index of the transaction in within a block.
func (tx *TxAbe) SetIndex(index int) {
	tx.txIndex = index
}

// NewTx returns a new instance of a bitcoin transaction given an underlying
// wire.MsgTx.  See Tx.
func NewTxAbe(msgTx *wire.MsgTxAbe) *TxAbe {
	return &TxAbe{
		msgTx:   msgTx,
		txIndex: TxAbeIndexUnknown,
	}
}

// NewTxFromBytes returns a new instance of a bitcoin transaction given the
// serialized bytes.  See Tx.
func NewTxAbeFromBytes(serializedTx []byte) (*Tx, error) {
	br := bytes.NewReader(serializedTx)
	return NewTxFromReader(br)
}

// NewTxFromReader returns a new instance of a bitcoin transaction given a
// Reader to deserialize the transaction.  See Tx.
func NewTxAbeFromReader(r io.Reader) (*TxAbe, error) {
	// Deserialize the bytes into a MsgTx.
	var msgTx wire.MsgTxAbe
	err := msgTx.Deserialize(r)
	if err != nil {
		return nil, err
	}

	tx := TxAbe{
		msgTx:   &msgTx,
		txIndex: TxAbeIndexUnknown,
	}
	return &tx, nil
}

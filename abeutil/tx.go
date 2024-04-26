package abeutil

import (
	"bytes"
	"io"

	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

// TxIndexUnknown is the value returned for a transaction index that is unknown.
// This is typically because the transaction has not been inserted into a block
// yet.
const TxIndexUnknown = -1
const TxAbeIndexUnknown = -1

// Tx defines a bitcoin transaction that provides easier and more efficient
// manipulation of raw transactions.  It also memoizes the hash for the
// transaction on its first access so subsequent accesses don't have to repeat
// the relatively expensive hashing operations.
type Tx struct {
	msgTx         *wire.MsgTx     // Underlying MsgTx
	txHash        *chainhash.Hash // Cached transaction hash
	txHashWitness *chainhash.Hash // Cached transaction witness hash
	txHasWitness  *bool           // If the transaction has witness data
	txIndex       int             // Position within a block or TxIndexUnknown
}

type TxAbe struct {
	msgTx         *wire.MsgTxAbe  // Underlying MsgTx
	txHash        *chainhash.Hash // Cached transaction content hash
	txWitnessHash *chainhash.Hash // Cached transaction witness hash
	//	txPersistentHash	*chainhash.Hash // Cached transaction witness hash
	//	txHasTxoDetails *bool // if the transaction has txo details
	txHasWitness *bool // If the transaction has witness data
	txIndex      int   // Position within a block or TxIndexUnknown
}

// MsgTx returns the underlying wire.MsgTx for the transaction.
func (t *Tx) MsgTx() *wire.MsgTx {
	// Return the cached transaction.
	return t.msgTx
}

func (tx *TxAbe) MsgTx() *wire.MsgTxAbe {
	// Return the cached transaction.
	return tx.msgTx
}

func (tx *TxAbe) InvType() wire.InvType {
	if tx.msgTx != nil && tx.msgTx.HasWitness() {
		return wire.InvTypeWitnessTx
	}
	return wire.InvTypeTx
}

func (tx *TxAbe) IsCoinBase() (bool, error) {
	return tx.msgTx.IsCoinBase()
}

// Hash returns the hash of the transaction.  This is equivalent to
// calling TxHash on the underlying wire.MsgTx, however it caches the
// result so subsequent calls are more efficient.
func (t *Tx) Hash() *chainhash.Hash {
	// Return the cached hash if it has already been generated.
	if t.txHash != nil {
		return t.txHash
	}

	// Cache the hash and return it.
	hash := t.msgTx.TxHash()
	t.txHash = &hash
	return &hash
}

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

// TxId() return TxHash(), which is the hash of TxContent (without witness), as the TxId.
//
//	In logic, outPoint should use (TxId, index).
func (tx *TxAbe) TxId() wire.TxId {
	if tx.txHash == nil {
		// Cache the hash
		hash := tx.msgTx.TxHash()
		tx.txHash = &hash
	}

	// Return the cached hash
	txId := wire.TxId(*tx.txHash)
	return txId
}

// WitnessHash returns the hash the transaction witness.
// This is equivalent to calling TxWitnessHash on the underlying wire.MsgTx, however it
// caches the result so subsequent calls are more efficient.
func (tx *TxAbe) WitnessHash() *chainhash.Hash {
	// Return the cached hash if it has already been generated.
	if tx.txWitnessHash != nil {
		return tx.txWitnessHash
	}

	// Cache the hash and return it.
	tx.txWitnessHash = tx.msgTx.TxWitnessHash()
	return tx.txWitnessHash
}

// WitnessHash returns the witness hash (wtxid) of the transaction.  This is
// equivalent to calling WitnessHash on the underlying wire.MsgTx, however it
// caches the result so subsequent calls are more efficient.
/*func (t *Tx) WitnessHash() *chainhash.Hash {
	// Return the cached hash if it has already been generated.
	if t.txHashWitness != nil {
		return t.txHashWitness
	}

	// Cache the hash and return it.
	hash := t.msgTx.WitnessHash()
	t.txHashWitness = &hash
	return &hash
}*/

// HasWitness returns false if none of the inputs within the transaction
// contain witness data, true false otherwise. This equivalent to calling
// HasWitness on the underlying wire.MsgTx, however it caches the result so
// subsequent calls are more efficient.
/*func (t *Tx) HasWitness() bool {
	if t.txHashWitness != nil {
		return *t.txHasWitness
	}

	hasWitness := t.msgTx.HasWitness()
	t.txHasWitness = &hasWitness
	return hasWitness
}*/

func (tx *TxAbe) HasWitness() bool {
	hasWitness := tx.msgTx.HasWitness()
	tx.txHasWitness = &hasWitness
	return hasWitness
}

// Index returns the saved index of the transaction within a block.  This value
// will be TxIndexUnknown if it hasn't already explicitly been set.
/*func (t *Tx) Index() int {
	return t.txIndex
}*/

func (tx *TxAbe) Index() int {
	return tx.txIndex
}

// SetIndex sets the index of the transaction in within a block.
func (t *Tx) SetIndex(index int) {
	t.txIndex = index
}

func (tx *TxAbe) SetIndex(index int) {
	tx.txIndex = index
}

// NewTx returns a new instance of a bitcoin transaction given an underlying
// wire.MsgTx.  See Tx.
func NewTx(msgTx *wire.MsgTx) *Tx {
	return &Tx{
		msgTx:   msgTx,
		txIndex: TxIndexUnknown,
	}
}

func NewTxAbe(msgTx *wire.MsgTxAbe) *TxAbe {
	return &TxAbe{
		msgTx:   msgTx,
		txIndex: TxAbeIndexUnknown,
	}
}

// NewTxFromBytes returns a new instance of a bitcoin transaction given the
// serialized bytes.  See Tx.
func NewTxFromBytes(serializedTx []byte) (*Tx, error) {
	br := bytes.NewReader(serializedTx)
	return NewTxFromReader(br)
}

func NewTxAbeFromBytes(serializedTx []byte) (*TxAbe, error) {
	br := bytes.NewReader(serializedTx)
	return NewTxAbeFromReader(br)
}

// NewTxFromReader returns a new instance of a bitcoin transaction given a
// Reader to deserialize the transaction.  See Tx.
func NewTxFromReader(r io.Reader) (*Tx, error) {
	// Deserialize the bytes into a MsgTx.
	var msgTx wire.MsgTx
	err := msgTx.Deserialize(r)
	if err != nil {
		return nil, err
	}

	t := Tx{
		msgTx:   &msgTx,
		txIndex: TxIndexUnknown,
	}
	return &t, nil
}

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

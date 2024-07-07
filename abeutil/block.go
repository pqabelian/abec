package abeutil

import (
	"bytes"
	"fmt"
	"github.com/abesuite/abec/aut"
	"io"

	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

// OutOfRangeError describes an error due to accessing an element that is out
// of range.
type OutOfRangeError string

// BlockHeightUnknown is the value returned for a block height that is unknown.
// This is typically because the block has not been inserted into the main chain
// yet.
const BlockHeightUnknown = int32(-1)

// Error satisfies the error interface and prints human-readable errors.
func (e OutOfRangeError) Error() string {
	return string(e)
}

// Block defines a abe block that provides easier and more efficient
// manipulation of raw blocks.  It also memoizes hashes for the block and its
// transactions on their first access so subsequent accesses don't have to
// repeat the relatively expensive hashing operations.
type Block struct {
	msgBlock                 *wire.MsgBlock  // Underlying MsgBlock
	serializedBlock          []byte          // Serialized bytes for the block
	serializedBlockNoWitness []byte          // Serialized bytes for block w/o witness data
	blockHash                *chainhash.Hash // Cached block hash
	blockHeight              int32           // Height in the main block chain
	transactions             []*Tx           // Transactions
	txnsGenerated            bool            // ALL wrapped transactions generated
}

// Abe to do
type BlockAbe struct {
	msgBlock                 *wire.MsgBlockAbe // Underlying MsgBlock
	serializedBlock          []byte            // Serialized bytes for the block
	serializedBlockNoWitness []byte            // Serialized bytes for block w/o witness data
	blockHash                *chainhash.Hash   // Cached block hash
	blockHeight              int32             // Height in the main block chain
	transactions             []*TxAbe          // Transactions
	txnsGenerated            bool              // ALL wrapped transactions generated

	autTransactions  []aut.Transaction
	autTxnsGenerated bool
}

// Abe to do
type PrunedBlock struct {
	msgPrunedBlock        *wire.MsgPrunedBlock // Underlying MsgBlock
	serializedPrunedBlock []byte               // Serialized bytes for the block
	blockHash             *chainhash.Hash      // Cached block hash
	blockHeight           int32                // Height in the main block chain
	txnsGenerated         bool                 // ALL wrapped transactions generated
}

// Abe to do
type NeedSet struct {
	msgNeedSet        *wire.MsgNeedSet // Underlying MsgBlock
	serializedNeedSet []byte           // Serialized bytes for the block
}

func (b *NeedSet) MsgNeedSet() *wire.MsgNeedSet {
	// Return the cached block.
	return b.msgNeedSet
}

// Abe to do
type NeedSetResult struct {
	msgNeedSetResult        *wire.MsgNeedSetResult // Underlying MsgBlock
	serializedNeedSetResult []byte                 // Serialized bytes for the block
}

func (b *NeedSetResult) MsgNeedSetResult() *wire.MsgNeedSetResult {
	// Return the cached block.
	return b.msgNeedSetResult
}

// MsgBlock returns the underlying wire.MsgBlock for the Block.
func (b *Block) MsgBlock() *wire.MsgBlock {
	// Return the cached block.
	return b.msgBlock
}

// Abe to do
func (b *BlockAbe) MsgBlock() *wire.MsgBlockAbe {
	// Return the cached block.
	return b.msgBlock
}
func (b *PrunedBlock) MsgPrunedBlock() *wire.MsgPrunedBlock {
	// Return the cached block.
	return b.msgPrunedBlock
}

// Bytes returns the serialized bytes for the Block.  This is equivalent to
// calling Serialize on the underlying wire.MsgBlock, however it caches the
// result so subsequent calls are more efficient.
func (b *Block) Bytes() ([]byte, error) {
	// Return the cached serialized bytes if it has already been generated.
	if len(b.serializedBlock) != 0 {
		return b.serializedBlock, nil
	}

	// Serialize the MsgBlock.
	w := bytes.NewBuffer(make([]byte, 0, b.msgBlock.SerializeSize()))
	err := b.msgBlock.Serialize(w)
	if err != nil {
		return nil, err
	}
	serializedBlock := w.Bytes()

	// Cache the serialized bytes and return them.
	b.serializedBlock = serializedBlock
	return serializedBlock, nil
}

func (b *BlockAbe) Bytes() ([]byte, error) {
	// Return the cached serialized bytes if it has already been generated.
	if len(b.serializedBlock) != 0 {
		return b.serializedBlock, nil
	}

	// Serialize the MsgBlock.
	w := bytes.NewBuffer(make([]byte, 0, b.msgBlock.SerializeSize()))
	err := b.msgBlock.Serialize(w)
	if err != nil {
		return nil, err
	}
	serializedBlock := w.Bytes()

	// Cache the serialized bytes and return them.
	b.serializedBlock = serializedBlock
	return serializedBlock, nil
}
func (b *PrunedBlock) Bytes() ([]byte, error) {
	// Return the cached serialized bytes if it has already been generated.
	if len(b.serializedPrunedBlock) != 0 {
		return b.serializedPrunedBlock, nil
	}

	// Serialize the MsgBlock.
	w := bytes.NewBuffer(make([]byte, 0, b.msgPrunedBlock.SerializeSize()))
	err := b.msgPrunedBlock.Serialize(w)
	if err != nil {
		return nil, err
	}
	serializedBlock := w.Bytes()

	// Cache the serialized bytes and return them.
	b.serializedPrunedBlock = serializedBlock
	return serializedBlock, nil
}

func (b *BlockAbe) BytesNoWitness() ([]byte, error) {
	// Return the cached serialized bytes if it has already been generated.
	if len(b.serializedBlockNoWitness) != 0 {
		return b.serializedBlockNoWitness, nil
	}

	// Serialize the MsgBlock.
	var w bytes.Buffer
	err := b.msgBlock.SerializeNoWitness(&w)
	if err != nil {
		return nil, err
	}
	serializedBlock := w.Bytes()

	// Cache the serialized bytes and return them.
	b.serializedBlockNoWitness = serializedBlock
	return serializedBlock, nil
}

// BytesNoWitness returns the serialized bytes for the block with transactions
// encoded without any witness data.
func (b *Block) BytesNoWitness() ([]byte, error) {
	// Return the cached serialized bytes if it has already been generated.
	if len(b.serializedBlockNoWitness) != 0 {
		return b.serializedBlockNoWitness, nil
	}

	// Serialize the MsgBlock.
	var w bytes.Buffer
	err := b.msgBlock.SerializeNoWitness(&w)
	if err != nil {
		return nil, err
	}
	serializedBlock := w.Bytes()

	// Cache the serialized bytes and return them.
	b.serializedBlockNoWitness = serializedBlock
	return serializedBlock, nil
}

// Hash returns the block identifier hash for the Block.  This is equivalent to
// calling BlockHash on the underlying wire.MsgBlock, however it caches the
// result so subsequent calls are more efficient.
func (b *Block) Hash() *chainhash.Hash {
	// Return the cached block hash if it has already been generated.
	if b.blockHash != nil {
		return b.blockHash
	}

	// Cache the block hash and return it.
	hash := b.msgBlock.BlockHash()
	b.blockHash = &hash
	return &hash
}

// Abe to do
func (b *BlockAbe) Hash() *chainhash.Hash {
	// Return the cached block hash if it has already been generated.
	if b.blockHash != nil {
		return b.blockHash
	}

	// Cache the block hash and return it.
	hash := b.msgBlock.BlockHash()
	b.blockHash = &hash
	return &hash
}

func (b *PrunedBlock) Hash() *chainhash.Hash {
	// Return the cached block hash if it has already been generated.
	if b.blockHash != nil {
		return b.blockHash
	}

	// Cache the block hash and return it.
	hash := b.msgPrunedBlock.BlockHash()
	b.blockHash = &hash
	return &hash
}

// Tx returns a wrapped transaction (btcutil.Tx) for the transaction at the
// specified index in the Block.  The supplied index is 0 based.  That is to
// say, the first transaction in the block is txNum 0.  This is nearly
// equivalent to accessing the raw transaction (wire.MsgTx) from the
// underlying wire.MsgBlock, however the wrapped transaction has some helpful
// properties such as caching the hash so subsequent calls are more efficient.
func (b *Block) Tx(txNum int) (*Tx, error) {
	// Ensure the requested transaction is in range.
	numTx := uint64(len(b.msgBlock.Transactions))
	if txNum < 0 || uint64(txNum) >= numTx {
		str := fmt.Sprintf("transaction index %d is out of range - max %d",
			txNum, numTx-1)
		return nil, OutOfRangeError(str)
	}

	// Generate slice to hold all of the wrapped transactions if needed.
	if len(b.transactions) == 0 {
		b.transactions = make([]*Tx, numTx)
	}

	// Return the wrapped transaction if it has already been generated.
	if b.transactions[txNum] != nil {
		return b.transactions[txNum], nil
	}

	// Generate and cache the wrapped transaction and return it.
	newTx := NewTx(b.msgBlock.Transactions[txNum])
	newTx.SetIndex(txNum)
	b.transactions[txNum] = newTx
	return newTx, nil
}

// Transactions returns a slice of wrapped transactions (btcutil.Tx) for all
// transactions in the Block.  This is nearly equivalent to accessing the raw
// transactions (wire.MsgTx) in the underlying wire.MsgBlock, however it
// instead provides easy access to wrapped versions (btcutil.Tx) of them.
func (b *Block) Transactions() []*Tx {
	// Return transactions if they have ALL already been generated.  This
	// flag is necessary because the wrapped transactions are lazily
	// generated in a sparse fashion.
	if b.txnsGenerated {
		return b.transactions
	}

	// Generate slice to hold all of the wrapped transactions if needed.
	if len(b.transactions) == 0 {
		b.transactions = make([]*Tx, len(b.msgBlock.Transactions))
	}

	// Generate and cache the wrapped transactions for all that haven't
	// already been done.
	for i, tx := range b.transactions {
		if tx == nil {
			newTx := NewTx(b.msgBlock.Transactions[i])
			newTx.SetIndex(i)
			b.transactions[i] = newTx
		}
	}

	b.txnsGenerated = true
	return b.transactions
}

// Abe to do
func (b *BlockAbe) Transactions() []*TxAbe {
	// Return transactions if they have ALL already been generated.  This
	// flag is necessary because the wrapped transactions are lazily
	// generated in a sparse fashion.
	if b.txnsGenerated {
		return b.transactions
	}

	// Generate slice to hold all of the wrapped transactions if needed.
	if len(b.transactions) == 0 {
		b.transactions = make([]*TxAbe, len(b.msgBlock.Transactions))
	}

	// Generate and cache the wrapped transactions for all that haven't
	// already been done.
	for i, tx := range b.transactions {
		if tx == nil {
			newTx := NewTxAbe(b.msgBlock.Transactions[i])
			newTx.SetIndex(i)
			if !newTx.HasWitness() {
				newTx.txWitnessHash = b.msgBlock.WitnessHashs[i]
			}
			b.transactions[i] = newTx
		}
	}

	b.txnsGenerated = true
	return b.transactions
}

// AUTTransactions returns the AutTransaction hosted by the transaction in the block.
// If they have been parsed, just return, otherwise, parse and return.
// refactored by Alice on 2024.03.01
func (b *BlockAbe) AUTTransactions() []aut.Transaction {
	// Return transactions if they have ALL already been generated.  This
	// flag is necessary because the wrapped transactions are lazily
	// generated in a sparse fashion.
	if b.autTxnsGenerated {
		return b.autTransactions
	}

	// Generate slice to hold all of the wrapped transactions if needed.
	if len(b.autTransactions) == 0 {
		b.autTransactions = make([]aut.Transaction, 0, len(b.msgBlock.Transactions))
	}

	// Generate and cache the wrapped autTransactions for all that haven't
	// already been done.
	for i, txAbe := range b.Transactions() {
		isCb, err := txAbe.IsCoinBase()
		if err != nil {
			//	this should not happen
			log.Warnf("AUTTransactions: error happens when calling IsCoinBase() on the %d-th transaction of the block: %v", i, err)
			continue
		}
		if isCb {
			continue
		}

		autTx, err := txAbe.AUTTransaction()
		if err != nil {
			//	this should not happen
			log.Warnf("AUTTransactions: error happens when getting AutTransaction from the %d-th transaction (%s) of the block: %v", i, txAbe.Hash(), err)
			continue
		}
		if autTx == nil {
			log.Debugf("AUTTransactions: skip non-AUT transaction %s", txAbe.Hash())
			continue
		}
		b.autTransactions = append(b.autTransactions, autTx)
	}

	b.autTxnsGenerated = true
	return b.autTransactions
}

// TxHash returns the hash for the requested transaction number in the Block.
// The supplied index is 0 based.  That is to say, the first transaction in the
// block is txNum 0.  This is equivalent to calling TxHash on the underlying
// wire.MsgTx, however it caches the result so subsequent calls are more
// efficient.
func (b *Block) TxHash(txNum int) (*chainhash.Hash, error) {
	// Attempt to get a wrapped transaction for the specified index.  It
	// will be created lazily if needed or simply return the cached version
	// if it has already been generated.
	tx, err := b.Tx(txNum)
	if err != nil {
		return nil, err
	}

	// Defer to the wrapped transaction which will return the cached hash if
	// it has already been generated.
	return tx.Hash(), nil
}

// TxLoc returns the offsets and lengths of each transaction in a raw block.
// It is used to allow fast indexing into transactions within the raw byte
// stream.
func (b *Block) TxLoc() ([]wire.TxLoc, error) {
	rawMsg, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	rbuf := bytes.NewBuffer(rawMsg)

	var mblock wire.MsgBlock
	txLocs, err := mblock.DeserializeTxLoc(rbuf)
	if err != nil {
		return nil, err
	}
	return txLocs, err
}

func (b *BlockAbe) TxLoc() ([]wire.TxAbeLoc, error) {
	var offset, witOffset int
	// todo(MLP):
	if b.msgBlock.Header.Version >= int32(wire.BlockVersionEthashPow) {
		offset, witOffset = 120+wire.VarIntSerializeSize(uint64(len(b.msgBlock.Transactions))), 8
	} else {
		offset, witOffset = 80+wire.VarIntSerializeSize(uint64(len(b.msgBlock.Transactions))), 8
	}
	txs := b.Transactions()
	res := make([]wire.TxAbeLoc, len(txs))
	for i := 0; i < len(txs); i++ {
		res[i].TxStart = offset
		txLen := txs[i].MsgTx().SerializeSize()
		res[i].TxLen, offset = txLen, offset+txLen

		res[i].WitnessStart = witOffset
		witLen := chainhash.HashSize + len(txs[i].MsgTx().TxWitness)
		res[i].WitnessLen, witOffset = witLen, witOffset+witLen+4
	}
	return res, nil
}

// Height returns the saved height of the block in the block chain.  This value
// will be BlockHeightUnknown if it hasn't already explicitly been set.
func (b *Block) Height() int32 {
	return b.blockHeight
}

// SetHeight sets the height of the block in the block chain.
func (b *Block) SetHeight(height int32) {
	b.blockHeight = height
}

// Height returns the saved height of the block in the block chain.  This value
// will be BlockHeightUnknown if it hasn't already explicitly been set.
func (b *BlockAbe) Height() int32 {
	return b.blockHeight
}

// SetHeight sets the height of the block in the block chain.
func (b *BlockAbe) SetHeight(height int32) {
	b.blockHeight = height

	////	todo (ethmining): 202207
	//if b.msgBlock != nil {
	//	b.msgBlock.Header.Height = height
	//}
}

// NewBlock returns a new instance of a bitcoin block given an underlying
// wire.MsgBlock.  See Block.
func NewBlock(msgBlock *wire.MsgBlock) *Block {
	return &Block{
		msgBlock:    msgBlock,
		blockHeight: BlockHeightUnknown,
	}
}

func NewBlockAbe(msgBlock *wire.MsgBlockAbe) *BlockAbe {
	return &BlockAbe{
		msgBlock:    msgBlock,
		blockHeight: BlockHeightUnknown,
	}
}

// NewBlockFromBytes returns a new instance of a bitcoin block given the
// serialized bytes.  See Block.
func NewBlockFromBytes(serializedBlock []byte) (*Block, error) {
	br := bytes.NewReader(serializedBlock)
	b, err := NewBlockFromReader(br)
	if err != nil {
		return nil, err
	}
	b.serializedBlock = serializedBlock
	return b, nil
}

// NewBlockFromBytesAbe uses serialized block without witness
func NewBlockFromBytesAbe(serializedBlock []byte) (*BlockAbe, error) {
	br := bytes.NewReader(serializedBlock)
	b, err := NewBlockFromReaderAbe(br)
	if err != nil {
		return nil, err
	}
	b.serializedBlock = serializedBlock
	return b, nil
}

func NewSimplifiedBlockFromBytes(serializedBlock []byte) (*wire.MsgSimplifiedBlock, error) {
	br := bytes.NewReader(serializedBlock)
	res := &wire.MsgSimplifiedBlock{}
	err := res.Deserialize(br)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// NewBlockFromReader returns a new instance of a bitcoin block given a
// Reader to deserialize the block.  See Block.
func NewBlockFromReader(r io.Reader) (*Block, error) {
	// Deserialize the bytes into a MsgBlock.
	var msgBlock wire.MsgBlock
	err := msgBlock.Deserialize(r)
	if err != nil {
		return nil, err
	}

	b := Block{
		msgBlock:    &msgBlock,
		blockHeight: BlockHeightUnknown,
	}
	return &b, nil
}

// NewBlockFromReaderAbe returns a new instance of an abec block given a
// Reader to deserialize the block.  See BlockAbe.
func NewBlockFromReaderAbe(r io.Reader) (*BlockAbe, error) {
	// Deserialize the bytes into a MsgBlock.
	var msgBlock wire.MsgBlockAbe
	err := msgBlock.DeserializeNoWitness(r)
	if err != nil {
		return nil, err
	}

	b := BlockAbe{
		msgBlock:    &msgBlock,
		blockHeight: BlockHeightUnknown,
	}
	return &b, nil
}

// NewBlockFromBlockAndBytes returns a new instance of a bitcoin block given
// an underlying wire.MsgBlock and the serialized bytes for it.  See Block.
func NewBlockFromBlockAndBytes(msgBlock *wire.MsgBlock, serializedBlock []byte) *Block {
	return &Block{
		msgBlock:        msgBlock,
		serializedBlock: serializedBlock,
		blockHeight:     BlockHeightUnknown,
	}
}

func NewBlockFromBlockAndBytesAbe(msgBlock *wire.MsgBlockAbe, serializedBlock []byte) *BlockAbe {
	return &BlockAbe{
		msgBlock:        msgBlock,
		serializedBlock: serializedBlock,
		blockHeight:     BlockHeightUnknown,
	}
}

func NewPrunedBlockFromPrunedBlockAndBytesAbe(msgBlock *wire.MsgPrunedBlock, serializedBlock []byte) *PrunedBlock {
	hash := msgBlock.BlockHash()
	return &PrunedBlock{
		msgPrunedBlock:        msgBlock,
		serializedPrunedBlock: serializedBlock,
		blockHash:             &hash,
		blockHeight:           0,
		txnsGenerated:         false,
	}
}
func NewNeedSet(needset *wire.MsgNeedSet, serialized []byte) *NeedSet {
	return &NeedSet{
		msgNeedSet:        needset,
		serializedNeedSet: serialized,
	}
}
func NewNeedSetResult(needsetResult *wire.MsgNeedSetResult, serialized []byte) *NeedSetResult {
	return &NeedSetResult{
		msgNeedSetResult:        needsetResult,
		serializedNeedSetResult: serialized,
	}
}

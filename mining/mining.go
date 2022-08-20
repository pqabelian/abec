package mining

import (
	"container/heap"
	"encoding/binary"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/txscript"
	"github.com/abesuite/abec/wire"
	"time"
)

const (
	// MinHighPriority is the minimum priority value that allows a
	// transaction to be considered high priority.
	MinHighPriority = abeutil.SatoshiPerBitcoin * 144.0 / 250

	//	todo: (EthashPoW) remove this constant to avoid misusing it as an exact value
	// blockHeaderOverhead is the max number of bytes it takes to serialize
	// a block header and max possible transaction count.
	// blockHeaderOverhead = wire.MaxBlockHeaderPayload + wire.MaxVarIntPayload

	// CoinbaseFlags is added to the coinbase script of a generated block
	// and is used to monitor BIP16 support as well as blocks that are
	// generated via btcd.
	CoinbaseFlags = "/P2SH/btcd/" // this is the coinbase message, can write by ourselves
)

// TxDesc is a descriptor about a transaction in a transaction source along with
// additional metadata.
type TxDesc struct {
	// Tx is the transaction associated with the entry.
	Tx *abeutil.Tx

	// Added is the time when the entry was added to the source pool.
	Added time.Time

	// Height is the block height when the entry was added to the the source
	// pool.
	Height int32

	// Fee is the total fee the transaction associated with the entry pays.
	Fee int64

	// FeePerKB is the fee the transaction pays in Satoshi per 1000 bytes.
	FeePerKB int64
}

type TxDescAbe struct {
	// Tx is the transaction associated with the entry.
	Tx *abeutil.TxAbe

	// Added is the time when the entry was added to the source pool.
	Added time.Time

	// Height is the block height when the entry was added to the source
	// pool.
	Height int32

	// Fee is the total fee the transaction associated with the entry pays.
	Fee uint64

	// FeePerKB is the fee the transaction pays in Satoshi per 1000 bytes.
	FeePerKB uint64
}

// TxSource represents a source of transactions to consider for inclusion in
// new blocks.
//
// The interface contract requires that all of these methods are safe for
// concurrent access with respect to the source.
type TxSource interface {
	// LastUpdated returns the last time a transaction was added to or
	// removed from the source pool.
	LastUpdated() time.Time

	// MiningDescs returns a slice of mining descriptors for all the
	// transactions in the source pool.
	MiningDescs() []*TxDescAbe

	// HaveTransaction returns whether or not the passed transaction hash
	// exists in the source pool.
	HaveTransaction(hash *chainhash.Hash) bool
}

// txPrioItemAbe houses a transaction along with extra information that allows the
// transaction to be prioritized and track dependencies on other transactions
// which have not been mined into a block yet.
type txPrioItemAbe struct {
	tx       *abeutil.TxAbe
	fee      uint64
	priority float64
	feePerKB uint64
}

// txPriorityQueueLessFunc describes a function that can be used as a compare
// function for a transaction priority queue (txPriorityQueue).
type txPriorityQueueLessFuncAbe func(*txPriorityQueueAbe, int, int) bool

// txPriorityQueueAbe implements a priority queue of txPrioItemAbe elements that
// supports an arbitrary compare function as defined by txPriorityQueueLessFunc.
type txPriorityQueueAbe struct {
	lessFunc txPriorityQueueLessFuncAbe
	items    []*txPrioItemAbe
}

// Len returns the number of items in the priority queue.  It is part of the
// heap.Interface implementation.
func (pq *txPriorityQueueAbe) Len() int {
	return len(pq.items)
}

// Less returns whether the item in the priority queue with index i should sort
// before the item with index j by deferring to the assigned less function.  It
// is part of the heap.Interface implementation.
func (pq *txPriorityQueueAbe) Less(i, j int) bool {
	return pq.lessFunc(pq, i, j)
}

// Swap swaps the items at the passed indices in the priority queue.  It is
// part of the heap.Interface implementation.
func (pq *txPriorityQueueAbe) Swap(i, j int) {
	pq.items[i], pq.items[j] = pq.items[j], pq.items[i]
}

// Push pushes the passed item onto the priority queue.  It is part of the
// heap.Interface implementation.
func (pq *txPriorityQueueAbe) Push(x interface{}) {
	pq.items = append(pq.items, x.(*txPrioItemAbe))
}

// Pop removes the highest priority item (according to Less) from the priority
// queue and returns it.  It is part of the heap.Interface implementation.
func (pq *txPriorityQueueAbe) Pop() interface{} {
	n := len(pq.items)
	item := pq.items[n-1]
	pq.items[n-1] = nil
	pq.items = pq.items[0 : n-1]
	return item
}

// SetLessFunc sets the compare function for the priority queue to the provided
// function.  It also invokes heap.Init on the priority queue using the new
// function so it can immediately be used with heap.Push/Pop.
func (pq *txPriorityQueueAbe) SetLessFunc(lessFunc txPriorityQueueLessFuncAbe) {
	pq.lessFunc = lessFunc
	heap.Init(pq)
}

// txPQByPriorityAbe sorts a txPriorityQueueAbe by transaction priority and then fees
// per kilobyte.
func txPQByPriorityAbe(pq *txPriorityQueueAbe, i, j int) bool {
	// Using > here so that pop gives the highest priority item as opposed
	// to the lowest.  Sort by priority first, then fee.
	if pq.items[i].priority == pq.items[j].priority {
		return pq.items[i].feePerKB > pq.items[j].feePerKB
	}
	return pq.items[i].priority > pq.items[j].priority
}

// txPQByFeeAbe sorts a txPriorityQueueAbe by fees per kilobyte and then transaction
// priority.
func txPQByFeeAbe(pq *txPriorityQueueAbe, i, j int) bool {
	// Using > here so that pop gives the highest fee item as opposed
	// to the lowest.  Sort by fee first, then priority.
	if pq.items[i].feePerKB == pq.items[j].feePerKB {
		return pq.items[i].priority > pq.items[j].priority
	}
	return pq.items[i].feePerKB > pq.items[j].feePerKB
}

// newTxPriorityQueueAbe returns a new transaction priority queue that reserves the
// passed amount of space for the elements.  The new priority queue uses either
// the txPQByPriorityAbe or the txPQByFeeAbe compare function depending on the
// sortByFee parameter and is already initialized for use with heap.Push/Pop.
// The priority queue can grow larger than the reserved space, but extra copies
// of the underlying array can be avoided by reserving a sane value.
func newTxPriorityQueueAbe(reserve int, sortByFee bool) *txPriorityQueueAbe {
	pq := &txPriorityQueueAbe{
		items: make([]*txPrioItemAbe, 0, reserve),
	}
	if sortByFee {
		pq.SetLessFunc(txPQByFeeAbe)
	} else {
		pq.SetLessFunc(txPQByPriorityAbe)
	}
	return pq
}

// BlockTemplate houses a block that has yet to be solved along with additional
// details about the fees and the number of signature operations for each
// transaction in the block.
type BlockTemplate struct {
	// Block is a block that is ready to be solved by miners.  Thus, it is
	// completely valid with the exception of satisfying the proof-of-work
	// requirement.
	Block    *wire.MsgBlock
	BlockAbe *wire.MsgBlockAbe

	// Fees contains the amount of fees each transaction in the generated
	// template pays in base units.  Since the first transaction is the
	// coinbase, the first entry (offset 0) will contain the negative of the
	// sum of the fees of all other transactions.
	Fees []uint64

	// SigOpCosts contains the number of signature operations each
	// transaction in the generated template performs.
	SigOpCosts []int64

	// Height is the height at which the block template connects to the main
	// chain.
	Height int32

	// ValidPayAddress indicates whether or not the template coinbase pays
	// to an address or is redeemable by anyone.  See the documentation on
	// NewBlockTemplate for details on which this can be useful to generate
	// templates without a coinbase payment address.
	ValidPayAddress bool

	// WitnessCommitment is a commitment to the witness data (if any)
	// within the block. This field will only be populted once segregated
	// witness has been activated, and the block contains a transaction
	// which has witness data.
	WitnessCommitment []byte

	// todo: (EthashPoW)
	//CoinbaseTxPart1      []byte
	//CoinbaseTxPart2      []byte
	//ConbaseTxWitnessHash *chainhash.Hash
	SiblingHashes []*chainhash.Hash
}

// mergeUtxoView adds all of the entries in viewB to viewA.  The result is that
// viewA will contain all of its original entries plus all of the entries
// in viewB.  It will replace any entries in viewB which also exist in viewA
// if the entry in viewA is spent.
func mergeUtxoView(viewA *blockchain.UtxoViewpoint, viewB *blockchain.UtxoViewpoint) {
	viewAEntries := viewA.Entries()
	for outpoint, entryB := range viewB.Entries() {
		if entryA, exists := viewAEntries[outpoint]; !exists ||
			entryA == nil || entryA.IsSpent() {

			viewAEntries[outpoint] = entryB
		}
	}
}

// standardCoinbaseScript returns a standard script suitable for use as the
// signature script of the coinbase transaction of a new block.  In particular,
// it starts with the block height that is required by version 2 blocks and adds
// the extra nonce as well as additional coinbase flags.
func standardCoinbaseScript(nextBlockHeight int32, extraNonce uint64) ([]byte, error) {
	return txscript.NewScriptBuilder().AddInt64(int64(nextBlockHeight)).
		AddInt64(int64(extraNonce)).AddData([]byte(CoinbaseFlags)).
		Script()
}

// createCoinbaseTx returns a coinbase transaction paying an appropriate subsidy
// based on the passed block height to the provided address.  When the address
// is nil, the coinbase transaction will instead be redeemable by anyone.
//
// See the comment for NewBlockTemplate for more information about why the nil
// address handling is useful.
func createCoinbaseTx(params *chaincfg.Params, coinbaseScript []byte, nextBlockHeight int32, addr abeutil.Address) (*abeutil.Tx, error) {
	// Create the script to pay to the provided payment address if one was
	// specified.  Otherwise create a script that allows the coinbase to be
	// redeemable by anyone.
	var pkScript []byte
	if addr != nil {
		var err error
		pkScript, err = txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		scriptBuilder := txscript.NewScriptBuilder()
		pkScript, err = scriptBuilder.AddOp(txscript.OP_TRUE).Script()
		if err != nil {
			return nil, err
		}
	}

	tx := wire.NewMsgTx(int32(wire.TxVersion))
	tx.AddTxIn(&wire.TxIn{
		// Coinbase transactions have no inputs, so previous outpoint is
		// zero hash and max index.
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex),
		SignatureScript: coinbaseScript,
		Sequence:        wire.MaxTxInSequenceNum,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    int64(blockchain.CalcBlockSubsidy(nextBlockHeight, params)),
		PkScript: pkScript,
	})
	return abeutil.NewTx(tx), nil
}

//	TODO(ABE): may be the total number of  outputs of coinbase transaction should be confined to 1,
//	 it will need to modify the process of checking block and transaction
// TODO(abe): when we use 1,2,5,10 for testing, we need add a algorithm to adjust the coin value in coinbase transaction
/*func createCoinbaseTxAbe(params *chaincfg.Params, extraNonce uint64, nextBlockHeight int32, addr abeutil.MasterAddress) (*abeutil.TxAbe, error) {
	////origin
	//coinbaseTxIn := wire.NewStandardCoinbaseTxIn(nextBlockHeight, extraNonce)
	//
	//addressScript, err := txscript.PayToAddressScriptAbe(addr)
	//if err != nil {
	//	return nil, err
	//}
	//txOut := wire.TxOutAbe{}
	//txOut.AddressScript = addressScript
	////	TODO (ABE.MUST): for salrs test, we set fix value 100 ABE
	////	txOut.ValueScript = blockchain.CalcBlockSubsidy(nextBlockHeight, params)
	////	for genesis block, this value is 1000 * 10000000
	////	For the test version of salrs, the fix-denotation is 100ABE, that is the fee and the value script must be 100.
	////	and the valuescript in coinbase transaction is 400. THIS IS JUST FOR TEST.
	////txOut.ValueScript = 400 * abeutil.NeutrinoPerAbe      //TODO(abe):this value shoule be reduce as the increasing block
	//txOut.ValueScript = blockchain.CalcBlockSubsidy(nextBlockHeight, params)
	//tx := wire.NewMsgTxAbe(wire.TxVersion)
	//tx.AddTxIn(coinbaseTxIn)
	//tx.AddTxOut(&txOut)
	//tx.TxWitness = &wire.TxWitnessAbe{}

	// for testing 1,2,5,10
	tx := wire.NewMsgTxAbe(wire.TxVersion)
	coinbaseTxIn := wire.NewStandardCoinbaseTxIn(nextBlockHeight, extraNonce, tx.Version)
	tx.AddTxIn(coinbaseTxIn)
	//
	TotalSubsidies := blockchain.CalcBlockSubsidy(nextBlockHeight, params)
	tx.TxFee=TotalSubsidies   // record the subsidied to add the tx fee in block
	// TODO(abe): for testing 1,2,5,10, we may use more than one outputs in  coinbase transaction
	//  divide the value script in to differennt tx out
	coinValues:=[]int64{500,200,100,50,20,10,5,2,1}
	for TotalSubsidies !=0{
		i:=0
		for TotalSubsidies < coinValues[i]* abeutil.NeutrinoPerAbe{
			i++
		}
		TotalSubsidies -=coinValues[i]* abeutil.NeutrinoPerAbe
		txOut := wire.TxOutAbe{}
		addressScript, err := txscript.PayToAddressScriptAbe(addr)
		if err != nil {
			return nil, err
		}
		txOut.AddressScript = addressScript
		txOut.ValueScript=coinValues[i]* abeutil.NeutrinoPerAbe
		tx.AddTxOut(&txOut)
	}
	//reserve 3 output for backward adjust
	for i:=0;i<3;i++{
		txOut := wire.TxOutAbe{}
		addressScript, err := txscript.PayToAddressScriptAbe(addr)
		if err != nil {
			return nil, err
		}
		txOut.AddressScript = addressScript
		txOut.ValueScript=0
		tx.AddTxOut(&txOut)
	}
	tx.TxWitness = &wire.TxWitnessAbe{}

	return abeutil.NewTxAbe(tx), nil
}*/

/*
todo: create a coinbaseTx template, where the TxOuts, the TxFee, and TxWitness are set to be 'fake' ones, and TxMemo is set to null
*/
func createCoinbaseTxAbeMsgTemplate(nextBlockHeight int32, txOutNum int) (*wire.MsgTxAbe, error) {
	//	When a new msgTx is created for a new transaction, it should use the current Txversion
	// msgTx := wire.NewMsgTxAbe(wire.TxVersion)
	msgTx := wire.NewMsgTxAbe(wire.TxVersion)

	//	one TxIn
	//	For coinbase transaction, as there is no real consumed coin, the TxIn is set by particular policy,
	//	which depends on the TxVersion
	coinbaseTxIn, err := wire.NewStandardCoinbaseTxIn(nextBlockHeight, msgTx.Version)
	if err != nil {
		return nil, err
	}
	msgTx.AddTxIn(coinbaseTxIn)
	txoSizeApprxo, err := abecryptoparam.GetTxoSerializeSizeApprox(msgTx.Version)
	if err != nil {
		return nil, err
	}
	tempTxOut := &wire.TxOutAbe{
		//	Txo inherits the version from the Tx
		Version: msgTx.Version,
		//	TxoSerialize here is used to occupy the space
		TxoScript: make([]byte, txoSizeApprxo),
	}

	//	one or multiple TxoOuts
	//	Set the TxOuts and the later TxWitness to occupy block size
	for i := 0; i < txOutNum; i++ {
		msgTx.AddTxOut(tempTxOut)
	}

	//msgTx.TxFee = abecryptoparam.GetMaxCoinValue(msgTx.Version)
	msgTx.TxFee = 0 // txFee will be serialized with 8bytes.
	//	todo: 202207. This txMemo value is unnecessary. We could remove it.
	msgTx.TxMemo = []byte{byte(msgTx.Version >> 24), byte(msgTx.Version >> 16), byte(msgTx.Version >> 8), byte(msgTx.Version)}
	//	TxWitnessSerializeSize here is used to occupy space.
	txWitnessSizeApprox, err := abecryptoparam.GetCbTxWitnessSerializeSizeApprox(msgTx.Version, txOutNum)
	if err != nil {
		return nil, err
	}
	msgTx.TxWitness = make([]byte, txWitnessSizeApprox)

	return msgTx, nil
}

// spendTransaction updates the passed view by marking the inputs to the passed
// transaction as spent.  It also adds all outputs in the passed transaction
// which are not provably unspendable as available unspent transaction outputs.
func spendTransaction(utxoView *blockchain.UtxoViewpoint, tx *abeutil.Tx, height int32) error {
	for _, txIn := range tx.MsgTx().TxIn {
		entry := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if entry != nil {
			entry.Spend()
		}
	}

	utxoView.AddTxOuts(tx, height)
	return nil
}

//	todo(ABE): the block is unknown yet, use hainhash.ZeroHash as the block hash consuming the serialNumber
func spendTransactionAbe(utxoRingView *blockchain.UtxoRingViewpoint, tx *abeutil.TxAbe) error {
	for _, txIn := range tx.MsgTx().TxIns {
		entry := utxoRingView.LookupEntry(txIn.PreviousOutPointRing.Hash())
		if entry != nil {
			entry.Spend(txIn.SerialNumber, &chainhash.ZeroHash)
		}
	}
	return nil
}

// logSkippedDeps logs any dependencies which are also skipped as a result of
// skipping a transaction while generating a block template at the trace level.
func logSkippedDeps(tx *abeutil.Tx, deps map[chainhash.Hash]*txPrioItemAbe) {
	if deps == nil {
		return
	}

	for _, item := range deps {
		log.Tracef("Skipping tx %s since it depends on %s\n",
			item.tx.Hash(), tx.Hash())
	}
}

// MinimumMedianTime returns the minimum allowed timestamp for a block building
// on the end of the provided best chain.  In particular, it is one second after
// the median timestamp of the last several blocks per the chain consensus
// rules.
func MinimumMedianTime(chainState *blockchain.BestState) time.Time {
	return chainState.MedianTime.Add(time.Second)
}

// medianAdjustedTime returns the current time adjusted to ensure it is at least
// one second after the median timestamp of the last several blocks per the
// chain consensus rules.
func medianAdjustedTime(chainState *blockchain.BestState, timeSource blockchain.MedianTimeSource) time.Time {
	// The timestamp for the block must not be before the median timestamp
	// of the last several blocks.  Thus, choose the maximum between the
	// current time and one second after the past median time.  The current
	// timestamp is truncated to a second boundary before comparison since a
	// block timestamp does not supported a precision greater than one
	// second.
	newTimestamp := timeSource.AdjustedTime()
	minTimestamp := MinimumMedianTime(chainState)
	if newTimestamp.Before(minTimestamp) {
		newTimestamp = minTimestamp
	}

	return newTimestamp
}

// BlkTmplGenerator provides a type that can be used to generate block templates
// based on a given mining policy and source of transactions to choose from.
// It also houses additional state required in order to ensure the templates
// are built on top of the current best chain and adhere to the consensus rules.
type BlkTmplGenerator struct {
	policy       *Policy
	chainParams  *chaincfg.Params
	txSource     TxSource
	chain        *blockchain.BlockChain
	timeSource   blockchain.MedianTimeSource
	sigCache     *txscript.SigCache
	hashCache    *txscript.HashCache
	witnessCache *txscript.WitnessCache
}

// NewBlkTmplGenerator returns a new block template generator for the given
// policy using transactions from the provided transaction source.
//
// The additional state-related fields are required in order to ensure the
// templates are built on top of the current best chain and adhere to the
// consensus rules.
func NewBlkTmplGenerator(policy *Policy, params *chaincfg.Params,
	txSource TxSource, chain *blockchain.BlockChain,
	timeSource blockchain.MedianTimeSource,
	sigCache *txscript.SigCache,
	hashCache *txscript.HashCache,
	witnessCache *txscript.WitnessCache) *BlkTmplGenerator {

	return &BlkTmplGenerator{
		policy:       policy,
		chainParams:  params,
		txSource:     txSource,
		chain:        chain,
		timeSource:   timeSource,
		sigCache:     sigCache,
		hashCache:    hashCache,
		witnessCache: witnessCache,
	}
}

// NewBlockTemplate returns a new block template that is ready to be solved
// using the transactions from the passed transaction source pool and a coinbase
// that either pays to the passed address if it is not nil, or a coinbase that
// is redeemable by anyone if the passed address is nil.  The nil address
// functionality is useful since there are cases such as the getblocktemplate
// RPC where external mining software is responsible for creating their own
// coinbase which will replace the one generated for the block template.  Thus
// the need to have configured address can be avoided.
//
// The transactions selected and included are prioritized according to several
// factors.  First, each transaction has a priority calculated based on its
// value, age of inputs, and size.  Transactions which consist of larger
// amounts, older inputs, and small sizes have the highest priority.  Second, a
// fee per kilobyte is calculated for each transaction.  Transactions with a
// higher fee per kilobyte are preferred.  Finally, the block generation related
// policy settings are all taken into account.
//
// Transactions which only spend outputs from other transactions already in the
// block chain are immediately added to a priority queue which either
// prioritizes based on the priority (then fee per kilobyte) or the fee per
// kilobyte (then priority) depending on whether or not the BlockPrioritySize
// policy setting allots space for high-priority transactions.
//
// Once the high-priority area (if configured) has been filled with
// transactions, or the priority falls below what is considered high-priority,
// the priority queue is updated to prioritize by fees per kilobyte (then
// priority).
//
// When the fees per kilobyte drop below the TxMinFreeFee policy setting, the
// transaction will be skipped unless the BlockMinSize policy setting is
// nonzero, in which case the block will be filled with the low-fee/free
// transactions until the block size reaches that minimum size.
//
// Any transactions which would cause the block to exceed the BlockMaxSize
// policy setting, exceed the maximum allowed signature operations per block, or
// otherwise cause the block to be invalid are skipped.
//
// Given the above, a block generated by this function is of the following form:
//
//   -----------------------------------  --  --
//  |      Coinbase Transaction         |   |   |
//  |-----------------------------------|   |   |
//  |                                   |   |   | ----- policy.BlockPrioritySize
//  |   High-priority Transactions      |   |   |
//  |                                   |   |   |
//  |-----------------------------------|   | --
//  |                                   |   |
//  |                                   |   |
//  |                                   |   |--- policy.BlockMaxSize
//  |  Transactions prioritized by fee  |   |
//  |  until <= policy.TxMinFreeFee     |   |
//  |                                   |   |
//  |                                   |   |
//  |                                   |   |
//  |-----------------------------------|   |
//  |  Low-fee/Non high-priority (free) |   |
//  |  transactions (while block size   |   |
//  |  <= policy.BlockMinSize)          |   |
//   -----------------------------------  --
func (g *BlkTmplGenerator) NewBlockTemplate(payToAddress []byte) (*BlockTemplate, error) {
	// Extend the most recently known best block.
	best := g.chain.BestSnapshot()
	nextBlockHeight := best.Height + 1

	// Create a standard coinbase transaction paying to the provided
	// address.  NOTE: The coinbase value will be updated to include the
	// fees from the selected transactions later after they have actually
	// been selected.  It is created here to detect any errors early
	// before potentially doing a lot of work below.  The extra nonce helps
	// ensure the transaction is not a duplicate transaction (paying the
	// same value to the same public key address would otherwise be an
	// identical transaction for block version 1).
	//extraNonce := uint64(0)

	coinbaseTxMsg, err := createCoinbaseTxAbeMsgTemplate(nextBlockHeight, 1)
	if err != nil {
		return nil, err
	}
	subsidy := blockchain.CalcBlockSubsidy(nextBlockHeight, g.chainParams)

	// Get the current source transactions and create a priority queue to
	// hold the transactions which are ready for inclusion into a block
	// along with some priority related and fee metadata.  Reserve the same
	// number of items that are available for the priority queue.  Also,
	// choose the initial sort order for the priority queue based on whether
	// or not there is an area allocated for high-priority transactions.
	sourceTxns := g.txSource.MiningDescs()
	sortedByFee := g.policy.BlockPrioritySize == 0
	priorityQueue := newTxPriorityQueueAbe(len(sourceTxns), sortedByFee)

	// Create a slice to hold the transactions to be included in the
	// generated block with reserved space.  Also create a utxo view to
	// house all of the input transactions so multiple lookups can be
	// avoided.
	blockTxns := make([]*abeutil.TxAbe, 0, len(sourceTxns)+1)
	coinbaseTx := abeutil.NewTxAbe(coinbaseTxMsg)
	blockTxns = append(blockTxns, coinbaseTx)
	blockUtxoRings := blockchain.NewUtxoRingViewpoint()

	// Create slices to hold the fees and number of signature operations
	// for each of the selected transactions and add an entry for the
	// coinbase.  This allows the code below to simply append details about
	// a transaction as it is selected for inclusion in the final block.
	// However, since the total fees aren't known yet, use a dummy value for
	// the coinbase fee which will be updated later.
	txFees := make([]uint64, 0, len(sourceTxns)+1)
	txFees = append(txFees, 0) // Updated once known

	log.Debugf("Considering %d transactions for inclusion to new block",
		len(sourceTxns))

	//	todo: (EthashPow)
	//	blockHeaderOverhead is the max number of bytes it takes to serialize a block header and max possible transaction count.
	//	It is a maximum possible value, rather than an accurate value.
	// blockHeaderOverhead := wire.MaxBlockHeaderPayload + wire.MaxVarIntPayload
	blockHeaderOverhead := wire.MaxBlockHeaderPayload
	if nextBlockHeight >= g.chainParams.BlockHeightEthashPoW {
		blockHeaderOverhead = wire.MaxBlockHeaderPayloadEthash
	}
	blockHeaderOverhead += wire.MaxVarIntPayload

mempoolLoop:
	for _, txDesc := range sourceTxns {
		// A block can't have more than one coinbase or contain
		// non-finalized transactions.
		tx := txDesc.Tx
		isCb, err := blockchain.IsCoinBaseAbe(tx)
		if isCb {
			log.Tracef("Skipping coinbase tx %s", tx.Hash())
			continue
		}

		// Fetch all of the utxoRings referenced by the this transaction.
		utxoRings, err := g.chain.FetchUtxoRingView(tx)
		if err != nil {
			log.Warnf("Unable to fetch utxoRing view for tx %s: %v",
				tx.Hash(), err)
			continue
		}

		// If utxoRing of one of the transaction inputs does not exist,
		// skip this transaction.
		for _, txIn := range tx.MsgTx().TxIns {
			entry := utxoRings.LookupEntry(txIn.PreviousOutPointRing.Hash())
			if entry == nil || entry.IsSpent(txIn.SerialNumber) {
				log.Tracef("Skipping tx %s because it "+
					"references unspent output %s "+
					"which is not available",
					tx.Hash(), txIn.String())
				continue mempoolLoop
			}
		}

		prioItem := &txPrioItemAbe{tx: tx}
		// Calculate the final transaction priority using the input
		// value age sum as well as the adjusted transaction size.
		// Current formula is: sum(inputAge) / adjustedTxSize
		prioItem.priority = CalcPriorityAbe(tx.MsgTx(), utxoRings, nextBlockHeight)

		// Calculate the fee in Neutrino/kB.
		prioItem.feePerKB = txDesc.FeePerKB
		prioItem.fee = txDesc.Fee

		// Add the transaction to the priority queue to mark it ready
		// for inclusion in the block
		heap.Push(priorityQueue, prioItem)

		// Merge the referenced outputs from the input transactions to
		// this transaction into the block utxoRing view.  This allows the
		// code below to avoid a second lookup.
		//	todo(ABE): how to prevent double spending
		//mergeUtxoView(blockUtxos, utxos)
		//	if blockUtxoRings.Entries() has the same utxoRing, just replace, as the utxoRing in utxoRings is queried from the latest database
		for ringHash, utxoRing := range utxoRings.Entries() {
			blockUtxoRings.Entries()[ringHash] = utxoRing
		}
	}

	log.Tracef("Priority queue len %d", priorityQueue.Len())

	// The starting block size is the size of the block header plus the max
	// possible transaction count size, plus the size of the coinbase
	// transaction.
	//	todo(ABE): ABE does not use weight, while use size only.
	// blockWeight := (blockHeaderOverhead * blockchain.WitnessScaleFactor) + uint32(blockchain.GetTransactionWeightAbe(coinbaseTx))
	blockSize := uint32((blockHeaderOverhead) + coinbaseTx.MsgTx().SerializeSize())
	totalFee := uint64(0)

	// Choose which transactions make it into the block.
	for priorityQueue.Len() > 0 {
		// Grab the highest priority (or highest fee per kilobyte
		// depending on the sort order) transaction.
		prioItem := heap.Pop(priorityQueue).(*txPrioItemAbe)
		tx := prioItem.tx

		// Enforce maximum block weight.  Also check for overflow.
		txSize := uint32(tx.MsgTx().SerializeSize())
		blockPlusTxSize := blockSize + txSize
		if blockPlusTxSize < blockSize || blockPlusTxSize >= g.policy.BlockMaxSize {
			log.Tracef("Skipping tx %s because it would exceed "+
				"the max block size", tx.Hash())
			continue
		}

		// Skip free transactions once the block is larger than the
		// minimum block size.
		if sortedByFee &&
			prioItem.feePerKB < uint64(g.policy.TxMinFreeFee) &&
			blockPlusTxSize >= g.policy.BlockMinSize {

			log.Tracef("Skipping tx %s with feePerKB %d "+
				"< TxMinFreeFee %d and block size %d >= "+
				"minBlockSize %d", tx.Hash(), prioItem.feePerKB,
				g.policy.TxMinFreeFee, blockPlusTxSize,
				g.policy.BlockMinSize)
			continue
		}

		// Prioritize by fee per kilobyte once the block is larger than
		// the priority size or there are no more high-priority
		// transactions.
		// todo abe, prioritySize?
		if !sortedByFee &&
			(blockPlusTxSize >= g.policy.BlockPrioritySize || prioItem.priority <= MinHighPriority) {

			log.Tracef("Switching to sort by fees per "+
				"kilobyte blockSize %d >= BlockPrioritySize "+
				"%d || priority %.2f <= minHighPriority %.2f",
				blockPlusTxSize, g.policy.BlockPrioritySize,
				prioItem.priority, MinHighPriority)

			sortedByFee = true
			priorityQueue.SetLessFunc(txPQByFeeAbe)

			// Put the transaction back into the priority queue and
			// skip it so it is re-priortized by fees if it won't
			// fit into the high-priority section or the priority
			// is too low.  Otherwise this transaction will be the
			// final one in the high-priority section, so just fall
			// though to the code below so it is added now.
			if blockPlusTxSize > g.policy.BlockPrioritySize || prioItem.priority < MinHighPriority {
				heap.Push(priorityQueue, prioItem)
				continue
			}
		}

		// Ensure the transaction inputs pass all of the necessary
		// preconditions before allowing it to be added to the block.
		//	todo(ABE): check double spending
		err := blockchain.CheckTransactionInputsAbe(tx, nextBlockHeight, blockUtxoRings, g.chainParams)
		if err != nil {
			log.Tracef("Skipping tx %s due to error in "+
				"CheckTransactionInputs: %v", tx.Hash(), err)
			continue
		}

		/*	todo(ABE): for ABE, the witness verification is the most expensive, we can optimize this part.
			In particular, for each tx in mp.pool, there is an additional filed, to identify whether the tx's witness has been verified.
			Other information, e.g., the inputs's double-spending may change, but as long as the txhash does not change, the witness does not need to verify again
		*/
		err = blockchain.ValidateTransactionScriptsAbe(tx, blockUtxoRings, g.witnessCache)
		if err != nil {
			log.Tracef("Skipping tx %s due to error in "+
				"ValidateTransactionScripts: %v", tx.Hash(), err)
			continue
		}

		// Spend the transaction inputs in the block utxoRing view and add
		// an entry for it to ensure any transactions which reference
		// this one have it available as an input and can ensure they
		// aren't double spending.
		spendTransactionAbe(blockUtxoRings, tx)

		// Add the transaction to the block, increment counters, and
		// save the fees and signature operation counts to the block
		// template.
		blockTxns = append(blockTxns, tx)
		blockSize += txSize
		totalFee += prioItem.fee
		txFees = append(txFees, prioItem.fee)

		log.Tracef("Adding tx %s (priority %.2f, feePerKB %.2f)",
			prioItem.tx.Hash(), prioItem.priority, prioItem.feePerKB)
	}

	// Now that the actual transactions have been selected, update the
	// block size for the real transaction count and coinbase value with
	// the total fees accordingly.
	//blockWeight -= wire.MaxVarIntPayload -
	//	(uint32(wire.VarIntSerializeSize(uint64(len(blockTxns)))) *
	//		blockchain.WitnessScaleFactor)
	blockSize -= wire.MaxVarIntPayload - uint32(wire.VarIntSerializeSize(uint64(len(blockTxns))))

	coinbaseTxMsg.TxFee = subsidy + totalFee
	// txFees[0] = -totalFee
	txOutDescs := make([]*abecrypto.AbeTxOutputDesc, 1)
	txOutDescs[0] = abecrypto.NewAbeTxOutDesc(payToAddress, coinbaseTxMsg.TxFee)

	coinbaseTxMsg, err = abecrypto.CoinbaseTxGen(txOutDescs, coinbaseTxMsg)
	if err != nil {
		return nil, err
	}
	coinbaseTx = abeutil.NewTxAbe(coinbaseTxMsg)
	blockTxns[0] = coinbaseTx

	//	todo(ABE): Does ABE need to store a commitment of the hash for the witnesses of transactions?

	// Calculate the required difficulty for the block.  The timestamp
	// is potentially adjusted to ensure it comes after the median time of
	// the last several blocks per the chain consensus rules.
	ts := medianAdjustedTime(best, g.timeSource)
	reqDifficulty, err := g.chain.CalcNextRequiredDifficulty(ts)
	if err != nil {
		return nil, err
	}

	// Calculate the next expected block version based on the state of the
	// rule change deployments.
	nextBlockVersion, err := g.chain.CalcNextBlockVersion()
	if err != nil {
		return nil, err
	}

	// Create a new block ready to be solved.
	//	todo: (EthashPoW)
	var merkleRoot *chainhash.Hash
	var siblingHashes []*chainhash.Hash

	if nextBlockHeight >= g.chainParams.BlockHeightEthashPoW {
		merkleRoot, siblingHashes = blockchain.BuildMerkleTreeStoreAbeEthash(blockTxns)
	} else {
		merkles := blockchain.BuildMerkleTreeStoreAbe(blockTxns, false)
		merkleRoot = merkles[len(merkles)-1]
	}

	var msgBlock wire.MsgBlockAbe
	msgBlock.Header = wire.BlockHeader{
		Version:    nextBlockVersion,
		PrevBlock:  best.Hash,
		MerkleRoot: *merkleRoot,
		Timestamp:  ts,
		Bits:       reqDifficulty,
		Height:     nextBlockHeight, // todo: (EthashPow)
	}
	for _, tx := range blockTxns {
		if err := msgBlock.AddTransaction(tx.MsgTx()); err != nil {
			return nil, err
		}
	}

	// Finally, perform a full check on the created block against the chain
	// consensus rules to ensure it properly connects to the current best
	// chain with no issues.
	block := abeutil.NewBlockAbe(&msgBlock)
	block.SetHeight(nextBlockHeight)
	if err := g.chain.CheckConnectBlockTemplateAbe(block); err != nil {
		return nil, err
	}

	log.Debugf("Created new block template (%d transactions, %d in "+
		"fees, %d size, target difficulty "+"%064x)", len(msgBlock.Transactions), totalFee, blockSize, blockchain.CompactToBig(msgBlock.Header.Bits))

	return &BlockTemplate{
		BlockAbe:        &msgBlock,
		Fees:            txFees,
		Height:          nextBlockHeight,
		ValidPayAddress: payToAddress != nil,
		SiblingHashes:   siblingHashes, // todo: (EthashPow)
	}, nil
}

// UpdateBlockTime updates the timestamp in the header of the passed block to
// the current time while taking into account the median time of the last
// several blocks to ensure the new time is after that time per the chain
// consensus rules.  Finally, it will update the target difficulty if needed
// based on the new time for the test networks since their target difficulty can
// change based upon time.
func (g *BlkTmplGenerator) UpdateBlockTime(msgBlock *wire.MsgBlock) error {
	// The new timestamp is potentially adjusted to ensure it comes after
	// the median time of the last several blocks per the chain consensus
	// rules.
	newTime := medianAdjustedTime(g.chain.BestSnapshot(), g.timeSource)
	msgBlock.Header.Timestamp = newTime

	// Recalculate the difficulty if running on a network that requires it.
	if g.chainParams.ReduceMinDifficulty {
		difficulty, err := g.chain.CalcNextRequiredDifficulty(newTime)
		if err != nil {
			return err
		}
		msgBlock.Header.Bits = difficulty
	}

	return nil
}

func (g *BlkTmplGenerator) UpdateBlockTimeAbe(msgBlock *wire.MsgBlockAbe) error {
	// The new timestamp is potentially adjusted to ensure it comes after
	// the median time of the last several blocks per the chain consensus
	// rules.
	newTime := medianAdjustedTime(g.chain.BestSnapshot(), g.timeSource)
	msgBlock.Header.Timestamp = newTime

	// Recalculate the difficulty if running on a network that requires it.
	if g.chainParams.ReduceMinDifficulty {
		difficulty, err := g.chain.CalcNextRequiredDifficulty(newTime)
		if err != nil {
			return err
		}
		msgBlock.Header.Bits = difficulty
	}

	return nil
}

func (g *BlkTmplGenerator) UpdateBlockTimeAbeEthash(blockTemplate *BlockTemplate) error {
	// The new timestamp is potentially adjusted to ensure it comes after
	// the median time of the last several blocks per the chain consensus
	// rules.
	newTime := medianAdjustedTime(g.chain.BestSnapshot(), g.timeSource)
	blockTemplate.BlockAbe.Header.Timestamp = newTime

	// Recalculate the difficulty if running on a network that requires it.
	if g.chainParams.ReduceMinDifficulty {
		difficulty, err := g.chain.CalcNextRequiredDifficulty(newTime)
		if err != nil {
			return err
		}
		blockTemplate.BlockAbe.Header.Bits = difficulty
	}

	return nil
}

// UpdateExtraNonce updates the extra nonce in the coinbase script of the passed
// block by regenerating the coinbase script with the passed value and block
// height.  It also recalculates and updates the new merkle root that results
// from changing the coinbase script.
func (g *BlkTmplGenerator) UpdateExtraNonce(msgBlock *wire.MsgBlock, blockHeight int32, extraNonce uint64) error {
	coinbaseScript, err := standardCoinbaseScript(blockHeight, extraNonce)
	if err != nil {
		return err
	}
	if len(coinbaseScript) > blockchain.MaxCoinbaseScriptLen {
		return fmt.Errorf("coinbase transaction script length "+
			"of %d is out of range (min: %d, max: %d)",
			len(coinbaseScript), blockchain.MinCoinbaseScriptLen,
			blockchain.MaxCoinbaseScriptLen)
	}
	msgBlock.Transactions[0].TxIn[0].SignatureScript = coinbaseScript

	// TODO(davec): A btcutil.Block should use saved in the state to avoid
	// recalculating all of the other transaction hashes.
	// block.Transactions[0].InvalidateCache()

	// Recalculate the merkle root with the updated extra nonce.
	block := abeutil.NewBlock(msgBlock)
	merkles := blockchain.BuildMerkleTreeStore(block.Transactions(), false)
	msgBlock.Header.MerkleRoot = *merkles[len(merkles)-1]
	return nil
}

func (g *BlkTmplGenerator) UpdateExtraNonceAbe(msgBlock *wire.MsgBlockAbe, extraNonce uint64) error {
	//	todo: 202207, here, we can use an update StandardCoinbaseTxIn ?
	//coinbaseTxIn, err := wire.NewStandardCoinbaseTxIn(blockHeight, wire.TxVersion)
	//if err != nil {
	//	return err
	//}
	//msgBlock.Transactions[0].TxIns[0] = coinbaseTxIn

	//	todo: 202207, the first 8 bytes of coinbaseTx.PreviousOutPointRing.BlockHashs[1] is used to store the ExtraNonce.
	binary.BigEndian.PutUint64(msgBlock.Transactions[0].TxIns[0].PreviousOutPointRing.BlockHashs[1][0:8], extraNonce)

	// Recalculate the merkle root with the updated extra nonce.
	block := abeutil.NewBlockAbe(msgBlock) //	This is important. By this new block, block.Transactions() will be re-generated.
	merkles := blockchain.BuildMerkleTreeStoreAbe(block.Transactions(), false)
	msgBlock.Header.MerkleRoot = *merkles[len(merkles)-1]
	return nil
}

// todo: (EthashPoW) Confirm and Optimization
//	UpdateExtraNonceAbeEthash() updates extraNonce in the coinbaseTx of blockTemplate,
//	which is designed to be the first 8 bytes of coinbaseTx.PreviousOutPointRing.BlockHashs[1].
//	As a result, the siblinghashes and merkleroot are also updated accordingly.
func (g *BlkTmplGenerator) UpdateExtraNonceAbeEthash(blockTemplate *BlockTemplate, extraNonce uint64) error {
	//hash1 := chainhash.Hash{}
	//binary.BigEndian.PutUint64(hash1[0:8], extraNonce)
	//blockTemplate.BlockAbe.Transactions[0].TxIns[0].PreviousOutPointRing.BlockHashs[1] = &hash1

	// the first 8 bytes of coinbaseTx.PreviousOutPointRing.BlockHashs[1] is used to store the ExtraNonce.
	binary.BigEndian.PutUint64(blockTemplate.BlockAbe.Transactions[0].TxIns[0].PreviousOutPointRing.BlockHashs[1][0:8], extraNonce)

	//	This new coinbaseTx will make the later coinbaseTx.Hash()[:] return the hash of the updated coinbaseTx.
	coinbaseTx := abeutil.NewTxAbe(blockTemplate.BlockAbe.Transactions[0])

	// Recalculate the merkle root with the updated extra nonce.
	//	Consistent with the codes in BuildMerkleTreeStoreAbeEthash
	tmp := make([]byte, chainhash.HashSize*2)
	// chainhash.DoubleHashH(tx Hash || witness Hash)
	copy(tmp[:chainhash.HashSize], coinbaseTx.Hash()[:])
	copy(tmp[chainhash.HashSize:], coinbaseTx.WitnessHash()[:])

	newCbTxHash := chainhash.ChainHash(tmp)

	//	SiblingHashes update
	blockTemplate.SiblingHashes[0] = &newCbTxHash

	//	MerkleRoot update
	blockTemplate.BlockAbe.Header.MerkleRoot = *blockchain.ComputeMerkleRootBySiblingHashes(blockTemplate.SiblingHashes)

	return nil
}

// BestSnapshot returns information about the current best chain block and
// related state as of the current point in time using the chain instance
// associated with the block template generator.  The returned state must be
// treated as immutable since it is shared by all callers.
//
// This function is safe for concurrent access.
func (g *BlkTmplGenerator) BestSnapshot() *blockchain.BestState {
	return g.chain.BestSnapshot()
}

// TxSource returns the associated transaction source.
//
// This function is safe for concurrent access.
func (g *BlkTmplGenerator) TxSource() TxSource {
	return g.txSource
}

package blockchain

/*
	this file implements the BlockChain including the process of new block
	appending to the blockchain
*/
import (
	"container/list"
	"fmt"
	"github.com/pqabelian/abec/abeutil"
	"github.com/pqabelian/abec/aut"
	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/consensus/ethash"
	"github.com/pqabelian/abec/database"
	"github.com/pqabelian/abec/txscript"
	"github.com/pqabelian/abec/wire"
	"math/big"
	"strings"
	"sync"
	"time"
)

var (
	// MaxOrphanBlocks is the maximum number of orphan blocks that can be
	// queued.
	MaxOrphanBlocks = 10
)

// BlockLocator is used to help locate a specific block.  The algorithm for
// building the block locator is to add the hashes in reverse order until
// the genesis block is reached.  In order to keep the list of locator hashes
// to a reasonable number of entries, first the most recent previous 12 block
// hashes are added, then the step is doubled each loop iteration to
// exponentially decrease the number of hashes as a function of the distance
// from the block being located.
//
// For example, assume a block chain with a side chain as depicted below:
//
//	genesis -> 1 -> 2 -> ... -> 15 -> 16  -> 17  -> 18
//	                              \-> 16a -> 17a
//
// The block locator for block 17a would be the hashes of blocks:
// [17a 16a 15 14 13 12 11 10 9 8 7 6 4 genesis]
type BlockLocator []*chainhash.Hash

// orphanBlock represents a block that we don't yet have the parent for.  It
// is a normal block plus an expiration time to prevent caching the orphan
// forever.
type orphanBlock struct {
	block      *abeutil.Block
	expiration time.Time
}

type orphanBlockAbe struct {
	block      *abeutil.BlockAbe
	expiration time.Time
}

// BestState houses information about the current best block and other info
// related to the state of the main chain as it exists from the point of view of
// the current best block.
//
// The BestSnapshot method can be used to obtain access to this information
// in a concurrent safe manner and the data will not be changed out from under
// the caller when chain state changes occur as the function name implies.
// However, the returned snapshot must be treated as immutable since it is
// shared by all callers.
type BestState struct {
	Hash chainhash.Hash // The hash of the block.
	// todo: (ethmining), the BlockHeader's prevBlock is set using this hash. Thus, need to set the hash based on the update situation
	Height    int32  // The height of the block.
	Bits      uint32 // The difficulty bits of the block.
	BlockSize uint64 // The size of the block.
	//	todo(ABE): ABE does not ues weight.
	BlockWeight uint64    // The weight of the block.
	NumTxns     uint64    // The number of txns in the block.
	TotalTxns   uint64    // The total number of txns in the chain.
	MedianTime  time.Time // Median time as per CalcPastMedianTime.
}

// newBestState returns a new best stats instance for the given parameters.
func newBestState(node *blockNode, blockSize, blockWeight, numTxns,
	totalTxns uint64, medianTime time.Time) *BestState {

	return &BestState{
		Hash:        node.hash,
		Height:      node.height,
		Bits:        node.bits,
		BlockSize:   blockSize,
		BlockWeight: blockWeight,
		NumTxns:     numTxns,
		TotalTxns:   totalTxns,
		MedianTime:  medianTime,
	}
}

// FakePoWHeightScope specify the height would skip PoW in range.
//
// To verify block in some height again, this param would be kept by database.
type BlockHeightScope struct {
	StartHeight int32
	EndHeight   int32
}

// BlockChain provides functions for working with the bitcoin block chain.
// It includes functionality such as rejecting duplicate blocks, ensuring blocks
// follow all rules, orphan handling, checkpoint handling, and best chain
// selection with reorganization.
type BlockChain struct {
	// The following fields are set when the instance is created and can't
	// be changed afterwards, so there is no need to protect them with a
	// separate mutex.
	nodeType            wire.NodeType
	checkpoints         []chaincfg.Checkpoint
	checkpointsByHeight map[int32]*chaincfg.Checkpoint // initialized by checkpoints

	// FakePoWHeightScopes keeps the fake pow in height range
	// which would ONLY set by non-mainnet
	fakePoWHeightScopes []BlockHeightScope
	workedHeightScope   []BlockHeightScope

	db           database.DB
	chainParams  *chaincfg.Params
	timeSource   MedianTimeSource // modified when communicating with peers
	sigCache     *txscript.SigCache
	witnessCache *txscript.WitnessCache
	indexManager IndexManager
	hashCache    *txscript.HashCache

	// The following fields are calculated based upon the provided chain
	// parameters.  They are also set when the instance is created and
	// can't be changed afterwards, so there is no need to protect them with
	// a separate mutex.
	minRetargetTimespan int64 // target timespan / adjustment factor
	maxRetargetTimespan int64 // target timespan * adjustment factor
	blocksPerRetarget   int32 // target timespan / target time per block

	// Added by Alice, 2024.05.11, for DSA
	// todo(DSA): review
	// todo: find reference
	minRetargetTimespanDSA int64 // target timespan DSA / adjustment factor
	maxRetargetTimespanDSA int64 // target timespan DSA * adjustment factor
	blocksPerRetargetDSA   int32 // target timespan DSA / target time per block DSA

	// chainLock protects concurrent access to the vast majority of the
	// fields in this struct below this point.
	chainLock sync.RWMutex

	// These fields are related to the memory block index.  They both have
	// their own locks, however they are often also protected by the chain
	// lock to help prevent logic races when blocks are being processed.
	//
	// index houses the entire block index in memory.  The block index is
	// a tree-shaped structure.
	//
	// bestChain tracks the current active chain by making use of an
	// efficient chain view into the block index.
	index     *blockIndex
	bestChain *chainView

	// These fields are related to handling of orphan blocks.  They are
	// protected by a combination of the chain lock and the orphan lock.
	orphanLock       sync.RWMutex
	orphansBTCD      map[chainhash.Hash]*orphanBlock
	orphansAbe       map[chainhash.Hash]*orphanBlockAbe
	prevOrphans      map[chainhash.Hash][]*orphanBlock
	prevOrphansAbe   map[chainhash.Hash][]*orphanBlockAbe
	oldestOrphanBTCD *orphanBlock
	oldestOrphanAbe  *orphanBlockAbe

	// These fields are related to checkpoint handling.  They are protected
	// by the chain lock.
	nextCheckpoint *chaincfg.Checkpoint
	checkpointNode *blockNode

	// The state is used as a fairly efficient way to cache information
	// about the current best chain state that is returned to callers when
	// requested.  It operates on the principle of MVCC such that any time a
	// new block becomes the best block, the state pointer is replaced with
	// a new struct and the old state is left untouched.  In this way,
	// multiple callers can be pointing to different best chain states.
	// This is acceptable for most callers because the state is only being
	// queried at a specific point in time.
	//
	// In addition, some of the fields are stored in the database so the
	// chain state can be quickly reconstructed on load.
	stateLock     sync.RWMutex
	stateSnapshot *BestState

	// The following caches are used to efficiently keep track of the
	// current deployment threshold state of each rule change deployment.
	//
	// This information is stored in the database so it can be quickly
	// reconstructed on load.
	//
	// warningCaches caches the current deployment threshold state for blocks
	// in each of the **possible** deployments.  This is used in order to
	// detect when new unrecognized rule changes are being voted on and/or
	// have been activated such as will be the case when older versions of
	// the software are being used
	//
	// deploymentCaches caches the current deployment threshold state for
	// blocks in each of the actively defined deployments.
	warningCaches    []thresholdStateCache
	deploymentCaches []thresholdStateCache

	// The following fields are used to determine if certain warnings have
	// already been shown.
	//
	// unknownRulesWarned refers to warnings due to unknown rules being
	// activated.
	//
	// unknownVersionsWarned refers to warnings due to unknown versions
	// being mined.
	unknownRulesWarned    bool
	unknownVersionsWarned bool

	// The notifications field stores a slice of callbacks to be executed on
	// certain blockchain events.
	notificationsLock sync.RWMutex
	notifications     []NotificationCallback
}

func (b *BlockChain) FakePoWHeightScopes() []BlockHeightScope {
	res := make([]BlockHeightScope, 0, len(b.workedHeightScope)+len(b.fakePoWHeightScopes))
	res = append(res, b.workedHeightScope...)
	res = append(res, b.fakePoWHeightScopes...)

	return res
}

// HaveBlock returns whether or not the chain instance has the block represented
// by the passed hash.  This includes checking the various places a block can
// be like part of the main chain, on a side chain, or in the orphan pool.
//
// This function is safe for concurrent access.
func (b *BlockChain) HaveBlock(hash *chainhash.Hash) (bool, error) {
	exists, err := b.blockExists(hash)
	if err != nil {
		return false, err
	}
	return exists || b.IsKnownOrphan(hash), nil
}

// IsKnownOrphan returns whether the passed hash is currently a known orphan.
// Keep in mind that only a limited number of orphans are held onto for a
// limited amount of time, so this function must not be used as an absolute
// way to test if a block is an orphan block.  A full block (as opposed to just
// its hash) must be passed to ProcessBlock for that purpose.  However, calling
// ProcessBlock with an orphan that already exists results in an error, so this
// function provides a mechanism for a caller to intelligently detect *recent*
// duplicate orphans and react accordingly.
//
// This function is safe for concurrent access.
func (b *BlockChain) IsKnownOrphan(hash *chainhash.Hash) bool {
	// Protect concurrent access.  Using a read lock only so multiple
	// readers can query without blocking each other.
	b.orphanLock.RLock()
	_, exists := b.orphansAbe[*hash]
	b.orphanLock.RUnlock()

	return exists
}

// GetOrphanRoot returns the head of the chain for the provided hash from the
// map of orphan blocks.
//
// This function is safe for concurrent access.
func (b *BlockChain) GetOrphanRoot(hash *chainhash.Hash) *chainhash.Hash {
	// Protect concurrent access.  Using a read lock only so multiple
	// readers can query without blocking each other.
	b.orphanLock.RLock()
	defer b.orphanLock.RUnlock()

	// Keep looping while the parent of each orphaned block is
	// known and is an orphan itself.
	orphanRoot := hash
	prevHash := hash
	for {
		orphan, exists := b.orphansAbe[*prevHash]
		if !exists {
			break
		}
		orphanRoot = prevHash
		prevHash = &orphan.block.MsgBlock().Header.PrevBlock
	}

	return orphanRoot
}

// removeOrphanBlock removes the passed orphan block from the orphan pool and
// previous orphan index.
func (b *BlockChain) removeOrphanBlockBTCD(orphan *orphanBlock) {
	// Protect concurrent access.
	b.orphanLock.Lock()
	defer b.orphanLock.Unlock()

	// Remove the orphan block from the orphan pool.
	orphanHash := orphan.block.Hash()
	delete(b.orphansBTCD, *orphanHash)

	// Remove the reference from the previous orphan index too.  An indexing
	// for loop is intentionally used over a range here as range does not
	// reevaluate the slice on each iteration nor does it adjust the index
	// for the modified slice.
	prevHash := &orphan.block.MsgBlock().Header.PrevBlock
	orphans := b.prevOrphans[*prevHash]
	for i := 0; i < len(orphans); i++ {
		hash := orphans[i].block.Hash()
		if hash.IsEqual(orphanHash) {
			copy(orphans[i:], orphans[i+1:])
			orphans[len(orphans)-1] = nil
			orphans = orphans[:len(orphans)-1]
			i--
		}
	}
	b.prevOrphans[*prevHash] = orphans

	// Remove the map entry altogether if there are no longer any orphans
	// which depend on the parent hash.
	if len(b.prevOrphans[*prevHash]) == 0 {
		delete(b.prevOrphans, *prevHash)
	}
}

// removeOrphanBlockAbe removes the passed orphan block from the orphan pool and
// previous orphan index.
//
//	Abe todo
func (b *BlockChain) removeOrphanBlockAbe(orphan *orphanBlockAbe) {
	// Protect concurrent access.
	b.orphanLock.Lock()
	defer b.orphanLock.Unlock()

	// Remove the orphan block from the orphan pool.
	orphanHash := orphan.block.Hash()
	delete(b.orphansAbe, *orphanHash)

	// Remove the reference from the previous orphan index too.  An indexing
	// for loop is intentionally used over a range here as range does not
	// reevaluate the slice on each iteration nor does it adjust the index
	// for the modified slice.
	prevHash := &orphan.block.MsgBlock().Header.PrevBlock
	orphans := b.prevOrphansAbe[*prevHash]
	for i := 0; i < len(orphans); i++ {
		hash := orphans[i].block.Hash()
		if hash.IsEqual(orphanHash) {
			copy(orphans[i:], orphans[i+1:])
			orphans[len(orphans)-1] = nil
			orphans = orphans[:len(orphans)-1]
			i--
		}
	}
	b.prevOrphansAbe[*prevHash] = orphans

	// Remove the map entry altogether if there are no longer any orphans
	// which depend on the parent hash.
	if len(b.prevOrphansAbe[*prevHash]) == 0 {
		delete(b.prevOrphansAbe, *prevHash)
	}
}

// addOrphanBlock adds the passed block (which is already determined to be
// an orphan prior calling this function) to the orphan pool.  It lazily cleans
// up any expired blocks so a separate cleanup poller doesn't need to be run.
// It also imposes a maximum limit on the number of outstanding orphan
// blocks and will remove the oldest received orphan block if the limit is
// exceeded.
func (b *BlockChain) addOrphanBlock(block *abeutil.BlockAbe) {
	// Remove expired orphan blocks.
	for _, oBlock := range b.orphansAbe {
		if time.Now().After(oBlock.expiration) {
			b.removeOrphanBlockAbe(oBlock)
			continue
		}

		// Update the oldest orphan block pointer so it can be discarded
		// in case the orphan pool fills up.
		if b.oldestOrphanAbe == nil || oBlock.expiration.Before(b.oldestOrphanAbe.expiration) {
			b.oldestOrphanAbe = oBlock
		}
	}

	// Limit orphan blocks to prevent memory exhaustion.
	if len(b.orphansAbe)+1 > MaxOrphanBlocks {
		// Remove the oldest orphan to make room for the new one.
		b.removeOrphanBlockAbe(b.oldestOrphanAbe)
		b.oldestOrphanAbe = nil
	}

	// Protect concurrent access.  This is intentionally done here instead
	// of near the top since removeOrphanBlock does its own locking and
	// the range iterator is not invalidated by removing map entries.
	b.orphanLock.Lock()
	defer b.orphanLock.Unlock()

	// Insert the block into the orphan map with an expiration time
	// 1 hour from now.
	expiration := time.Now().Add(time.Hour)
	oBlock := &orphanBlockAbe{
		block:      block,
		expiration: expiration,
	}
	b.orphansAbe[*block.Hash()] = oBlock

	// Add to previous hash lookup index for faster dependency lookups.
	prevHash := &block.MsgBlock().Header.PrevBlock
	b.prevOrphansAbe[*prevHash] = append(b.prevOrphansAbe[*prevHash], oBlock)
}

// SequenceLock represents the converted relative lock-time in seconds, and
// absolute block-height for a transaction input's relative lock-times.
// According to SequenceLock, after the referenced input has been confirmed
// within a block, a transaction spending that input can be included into a
// block either after 'seconds' (according to past median time), or once the
// 'BlockHeight' has been reached.
type SequenceLock struct {
	Seconds     int64
	BlockHeight int32
}

// CalcSequenceLock computes a relative lock-time SequenceLock for the passed
// transaction using the passed UtxoViewpoint to obtain the past median time
// for blocks in which the referenced inputs of the transactions were included
// within. The generated SequenceLock lock can be used in conjunction with a
// block height, and adjusted median block time to determine if all the inputs
// referenced within a transaction have reached sufficient maturity allowing
// the candidate transaction to be included in a block.
//
// This function is safe for concurrent access.
func (b *BlockChain) CalcSequenceLock(tx *abeutil.Tx, utxoView *UtxoViewpoint, mempool bool) (*SequenceLock, error) {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	return b.calcSequenceLock(b.bestChain.Tip(), tx, utxoView, mempool)
}

// calcSequenceLock computes the relative lock-times for the passed
// transaction. See the exported version, CalcSequenceLock for further details.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) calcSequenceLock(node *blockNode, tx *abeutil.Tx, utxoView *UtxoViewpoint, mempool bool) (*SequenceLock, error) {
	// A value of -1 for each relative lock type represents a relative time
	// lock value that will allow a transaction to be included in a block
	// at any given height or time. This value is returned as the relative
	// lock time in the case that BIP 68 is disabled, or has not yet been
	// activated.
	sequenceLock := &SequenceLock{Seconds: -1, BlockHeight: -1}

	// The sequence locks semantics are always active for transactions
	// within the mempool.
	csvSoftforkActive := mempool

	// If we're performing block validation, then we need to query the BIP9
	// state.
	if !csvSoftforkActive {
		// Obtain the latest BIP9 version bits state for the
		// CSV-package soft-fork deployment. The adherence of sequence
		// locks depends on the current soft-fork state.
		csvState, err := b.deploymentState(node.parent, chaincfg.DeploymentCSV)
		if err != nil {
			return nil, err
		}
		csvSoftforkActive = csvState == ThresholdActive
	}

	// If the transaction's version is less than 2, and BIP 68 has not yet
	// been activated then sequence locks are disabled. Additionally,
	// sequence locks don't apply to coinbase transactions Therefore, we
	// return sequence lock values of -1 indicating that this transaction
	// can be included within a block at any given height or time.
	mTx := tx.MsgTx()
	sequenceLockActive := mTx.Version >= 2 && csvSoftforkActive
	if !sequenceLockActive || IsCoinBase(tx) {
		return sequenceLock, nil
	}

	// Grab the next height from the PoV of the passed blockNode to use for
	// inputs present in the mempool.
	nextHeight := node.height + 1

	for txInIndex, txIn := range mTx.TxIn {
		utxo := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if utxo == nil {
			str := fmt.Sprintf("output %v referenced from "+
				"transaction %s:%d either does not exist or "+
				"has already been spent", txIn.PreviousOutPoint,
				tx.Hash(), txInIndex)
			return sequenceLock, ruleError(ErrMissingTxOut, str)
		}

		// If the input height is set to the mempool height, then we
		// assume the transaction makes it into the next block when
		// evaluating its sequence blocks.
		inputHeight := utxo.BlockHeight()
		if inputHeight == 0x7fffffff {
			inputHeight = nextHeight
		}

		// Given a sequence number, we apply the relative time lock
		// mask in order to obtain the time lock delta required before
		// this input can be spent.
		sequenceNum := txIn.Sequence
		relativeLock := int64(sequenceNum & wire.SequenceLockTimeMask)

		switch {
		// Relative time locks are disabled for this input, so we can
		// skip any further calculation.
		case sequenceNum&wire.SequenceLockTimeDisabled == wire.SequenceLockTimeDisabled:
			continue
		case sequenceNum&wire.SequenceLockTimeIsSeconds == wire.SequenceLockTimeIsSeconds:
			// This input requires a relative time lock expressed
			// in seconds before it can be spent.  Therefore, we
			// need to query for the block prior to the one in
			// which this input was included within so we can
			// compute the past median time for the block prior to
			// the one which included this referenced output.
			prevInputHeight := inputHeight - 1
			if prevInputHeight < 0 {
				prevInputHeight = 0
			}
			blockNode := node.Ancestor(prevInputHeight)
			medianTime := blockNode.CalcPastMedianTime()

			// Time based relative time-locks as defined by BIP 68
			// have a time granularity of RelativeLockSeconds, so
			// we shift left by this amount to convert to the
			// proper relative time-lock. We also subtract one from
			// the relative lock to maintain the original lockTime
			// semantics.
			timeLockSeconds := (relativeLock << wire.SequenceLockTimeGranularity) - 1
			timeLock := medianTime.Unix() + timeLockSeconds
			if timeLock > sequenceLock.Seconds {
				sequenceLock.Seconds = timeLock
			}
		default:
			// The relative lock-time for this input is expressed
			// in blocks so we calculate the relative offset from
			// the input's height as its converted absolute
			// lock-time. We subtract one from the relative lock in
			// order to maintain the original lockTime semantics.
			blockHeight := inputHeight + int32(relativeLock-1)
			if blockHeight > sequenceLock.BlockHeight {
				sequenceLock.BlockHeight = blockHeight
			}
		}
	}

	return sequenceLock, nil
}

// LockTimeToSequence converts the passed relative locktime to a sequence
// number in accordance to BIP-68.
// See: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
//   - (Compatibility)
func LockTimeToSequence(isSeconds bool, locktime uint32) uint32 {
	// If we're expressing the relative lock time in blocks, then the
	// corresponding sequence number is simply the desired input age.
	if !isSeconds {
		return locktime
	}

	// Set the 22nd bit which indicates the lock time is in seconds, then
	// shift the locktime over by 9 since the time granularity is in
	// 512-second intervals (2^9). This results in a max lock-time of
	// 33,553,920 seconds, or 1.1 years.
	return wire.SequenceLockTimeIsSeconds |
		locktime>>wire.SequenceLockTimeGranularity
}

// getReorganizeNodes finds the fork point between the main chain and the passed
// node and returns a list of block nodes that would need to be detached from
// the main chain and a list of block nodes that would need to be attached to
// the fork point (which will be the end of the main chain after detaching the
// returned list of block nodes) in order to reorganize the chain such that the
// passed node is the new end of the main chain.  The lists will be empty if the
// passed node is not on a side chain.
//
// This function may modify node statuses in the block index without flushing.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) getReorganizeNodes(node *blockNode) (*list.List, *list.List) {
	attachNodes := list.New()
	detachNodes := list.New()

	// Do not reorganize to a known invalid chain. Ancestors deeper than the
	// direct parent are checked below but this is a quick check before doing
	// more unnecessary work.
	if b.index.NodeStatus(node.parent).KnownInvalid() {
		b.index.SetStatusFlags(node, statusInvalidAncestor)
		return detachNodes, attachNodes
	}

	// Find the fork point (if any) adding each block to the list of nodes
	// to attach to the main tree.  Push them onto the list in reverse order
	// so they are attached in the appropriate order when iterating the list
	// later.
	forkNode := b.bestChain.FindFork(node)
	invalidChain := false
	for n := node; n != nil && n != forkNode; n = n.parent {
		if b.index.NodeStatus(n).KnownInvalid() {
			invalidChain = true
			break
		}
		attachNodes.PushFront(n)
	}

	// If any of the node's ancestors are invalid, unwind attachNodes, marking
	// each one as invalid for future reference.
	if invalidChain {
		var next *list.Element
		for e := attachNodes.Front(); e != nil; e = next {
			next = e.Next()
			n := attachNodes.Remove(e).(*blockNode)
			b.index.SetStatusFlags(n, statusInvalidAncestor)
		}
		return detachNodes, attachNodes
	}

	// Start from the end of the main chain and work backwards until the
	// common ancestor adding each block to the list of nodes to detach from
	// the main chain.
	for n := b.bestChain.Tip(); n != nil && n != forkNode; n = n.parent {
		detachNodes.PushBack(n)
	}

	return detachNodes, attachNodes
}

// getReorganizeNodesAbe finds the fork point between the main chain and the passed
// node and returns a list of block nodes that would need to be detached from
// the main chain and a list of block nodes that would need to be attached to
// the fork point (which will be the end of the main chain after detaching the
// returned list of block nodes) in order to reorganize the chain such that the
// passed node is the new end of the main chain.  The lists will be empty if the
// passed node is not on a side chain.
//
// This function may modify node statuses in the block index without flushing.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) getReorganizeNodesAbe(node *blockNode) (*list.List, *list.List) {
	attachNodes := list.New()
	detachNodes := list.New()

	// Do not reorganize to a known invalid chain. Ancestors deeper than the
	// direct parent are checked below but this is a quick check before doing
	// more unnecessary work.
	if b.index.NodeStatus(node.parent).KnownInvalid() {
		b.index.SetStatusFlags(node, statusInvalidAncestor)
		return detachNodes, attachNodes
	}

	// Find the fork point (if any) adding each block to the list of nodes
	// to attach to the main tree.  Push them onto the list in reverse order
	// so they are attached in the appropriate order when iterating the list
	// later.
	forkNode := b.bestChain.FindFork(node)
	invalidChain := false
	for n := node; n != nil && n != forkNode; n = n.parent {
		if b.index.NodeStatus(n).KnownInvalid() {
			invalidChain = true
			break
		}
		attachNodes.PushFront(n)
	}

	// If any of the node's ancestors are invalid, unwind attachNodes, marking
	// each one as invalid for future reference.
	if invalidChain {
		var next *list.Element
		for e := attachNodes.Front(); e != nil; e = next {
			next = e.Next()
			n := attachNodes.Remove(e).(*blockNode)
			b.index.SetStatusFlags(n, statusInvalidAncestor)
		}
		return detachNodes, attachNodes
	}

	// Start from the end of the main chain and work backwards until the
	// common ancestor adding each block to the list of nodes to detach from
	// the main chain.
	for n := b.bestChain.Tip(); n != nil && n != forkNode; n = n.parent {
		detachNodes.PushBack(n)
	}

	return detachNodes, attachNodes
}

// connectBlock handles connecting the passed node/block to the end of the main
// (best) chain.
//
// This passed utxo view must have all referenced txos the block spends marked
// as spent and all of the new txos the block creates added to it.  In addition,
// the passed stxos slice must be populated with all of the information for the
// spent txos.  This approach is used because the connection validation that
// must happen prior to calling this function requires the same details, so
// it would be inefficient to repeat it.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) connectBlock(node *blockNode, block *abeutil.Block,
	view *UtxoViewpoint, stxos []SpentTxOut) error {

	// Make sure it's extending the end of the best chain.
	prevHash := &block.MsgBlock().Header.PrevBlock
	if !prevHash.IsEqual(&b.bestChain.Tip().hash) {
		return AssertError("connectBlock must be called with a block " +
			"that extends the main chain")
	}

	// Sanity check the correct number of stxos are provided.
	if len(stxos) != countSpentOutputs(block) {
		return AssertError("connectBlock called with inconsistent " +
			"spent transaction out information")
	}

	// No warnings about unknown rules or versions until the chain is
	// current.
	if b.isCurrent() {
		// Warn if any unknown new rules are either about to activate or
		// have already been activated.
		if err := b.warnUnknownRuleActivations(node); err != nil {
			return err
		}

		// Warn if a high enough percentage of the last blocks have
		// unexpected versions.
		if err := b.warnUnknownVersions(node); err != nil {
			return err
		}
	}

	// Write any block status changes to DB before updating best state.
	err := b.index.flushToDB()
	if err != nil {
		return err
	}

	// Generate a new best state snapshot that will be used to update the
	// database and later memory if all database updates are successful.
	b.stateLock.RLock()
	curTotalTxns := b.stateSnapshot.TotalTxns
	b.stateLock.RUnlock()
	numTxns := uint64(len(block.MsgBlock().Transactions))
	blockSize := uint64(block.MsgBlock().SerializeSize())
	blockWeight := uint64(GetBlockWeight(block))
	state := newBestState(node, blockSize, blockWeight, numTxns,
		curTotalTxns+numTxns, node.CalcPastMedianTime())

	// Atomically insert info into the database.
	err = b.db.Update(func(dbTx database.Tx) error {
		// Update best block state.
		err := dbPutBestState(dbTx, state, node.workSum)
		if err != nil {
			return err
		}

		// Add the block hash and height to the block index which tracks
		// the main chain.
		err = dbPutBlockIndex(dbTx, block.Hash(), node.height)
		if err != nil {
			return err
		}

		// Update the utxo set using the state of the utxo view.  This
		// entails removing all of the utxos spent and adding the new
		// ones created by the block.
		err = dbPutUtxoView(dbTx, view)
		if err != nil {
			return err
		}

		// Update the transaction spend journal by adding a record for
		// the block that contains all txos spent by it.
		err = dbPutSpendJournalEntry(dbTx, block.Hash(), stxos)
		if err != nil {
			return err
		}

		// Allow the index manager to call each of the currently active
		// optional indexes with the block being connected so they can
		// update themselves accordingly.
		if b.indexManager != nil {
			err := b.indexManager.ConnectBlock(dbTx, block, stxos)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Prune fully spent entries and mark all entries in the view unmodified
	// now that the modifications have been committed to the database.
	view.commit()

	// This node is now the end of the best chain.
	b.bestChain.SetTip(node)

	// Update the state for the best block.  Notice how this replaces the
	// entire struct instead of updating the existing one.  This effectively
	// allows the old version to act as a snapshot which callers can use
	// freely without needing to hold a lock for the duration.  See the
	// comments on the state variable for more details.
	b.stateLock.Lock()
	b.stateSnapshot = state
	b.stateLock.Unlock()

	// Notify the caller that the block was connected to the main chain.
	// The caller would typically want to react with actions such as
	// updating wallets.
	func() {
		b.chainLock.Unlock()
		defer b.chainLock.Lock()

		b.sendNotification(NTBlockConnected, block)
	}()
	return nil
}

// connectBlockAbe handles connecting the passed node/block to the end of the main
// (best) chain.
//
// This passed utxo ring view must have all referenced txos the block spends marked
// as spent and all of the new txos the block creates added to it.  In addition,
// the passed stxos slice must be populated with all of the information for the
// spent txos.  This approach is used because the connection validation that
// must happen prior to calling this function requires the same details, so
// it would be inefficient to repeat it.
//
// This function MUST be called with the chain state lock held (for writes).
//  1. Ensure it is extending the best chain and the number of stxos are correct.
//  2. Update best state, block index (height->block hash and block hash->height), write utxo ring of database
//     and add spent txos journal in database (block hash->txos)
//  3. Update index manager if exists (todo)
//  4. Send NTBlockConnected notification
//
// todo_DONE(MLP): reviewed on 2024.01.04
func (b *BlockChain) connectBlockAbe(node *blockNode, block *abeutil.BlockAbe,
	view *UtxoRingViewpoint, stxos []*SpentTxOutAbe,
	autView *AUTViewpoint, sauts []SpentAUT,
) error {

	// Make sure it's extending the end of the best chain.
	prevHash := &block.MsgBlock().Header.PrevBlock
	if !prevHash.IsEqual(&b.bestChain.Tip().hash) {
		return AssertError("connectBlock must be called with a block " +
			"that extends the main chain")
	}

	// Sanity check the correct number of stxos are provided.
	if len(stxos) != countSpentOutputsAbe(block) {
		return AssertError("connectBlock called with inconsistent " +
			"spent transaction out information")
	}
	if len(sauts) != countSpentOutputsAUT(block) {
		return AssertError("connectBlock called with inconsistent " +
			"spent aut transaction information")
	}

	// No warnings about unknown rules or versions until the chain is
	// current.
	//	todo(ABE.MUST)
	/*	if b.isCurrent() {
		// Warn if any unknown new rules are either about to activate or
		// have already been activated.
		if err := b.warnUnknownRuleActivations(node); err != nil {
			return err
		}

		// Warn if a high enough percentage of the last blocks have
		// unexpected versions.
		if err := b.warnUnknownVersions(node); err != nil {
			return err
		}
	}*/

	// Write any block status changes to DB before updating best state.
	err := b.index.flushToDB()
	if err != nil {
		return err
	}

	// Generate a new best state snapshot that will be used to update the
	// database and later memory if all database updates are successful.
	b.stateLock.RLock()
	curTotalTxns := b.stateSnapshot.TotalTxns
	b.stateLock.RUnlock()
	numTxns := uint64(len(block.MsgBlock().Transactions))
	blockSize := uint64(block.MsgBlock().SerializeSize())
	//	todo(ABE): ABE does not use weight, while use size only.
	//	blockWeight := uint64(GetBlockWeightAbe(block))
	blockWeight := blockSize
	state := newBestState(node, blockSize, blockWeight, numTxns,
		curTotalTxns+numTxns, node.CalcPastMedianTime())

	// Atomically insert info into the database.
	err = b.db.Update(func(dbTx database.Tx) error {
		// Update best block state.
		err := dbPutBestState(dbTx, state, node.workSum)
		if err != nil {
			return err
		}

		// Add the block hash and height to the block index which tracks
		// the main chain.
		err = dbPutBlockIndex(dbTx, block.Hash(), node.height)
		if err != nil {
			return err
		}

		// Update the utxo set using the state of the utxo view.  This
		// entails removing all of the utxos spent and adding the new
		// ones created by the block.
		// todo_DONE(MLP): reviewed on 2024.01.04
		err = dbPutUtxoRingView(dbTx, view)
		if err != nil {
			return err
		}

		err = dbPutAUTView(dbTx, autView, node.height, node.hash)
		if err != nil {
			return err
		}

		// Update the transaction spend journal by adding a record for
		// the block that contains all txos spent by it.
		// todo_DONE(MLP): reviewed on 2024.01.04
		err = dbPutSpendJournalEntryAbe(dbTx, block.Hash(), stxos)
		if err != nil {
			return err
		}

		err = dbPutSpendJournalEntryAUT(dbTx, block.Hash(), sauts)
		if err != nil {
			return err
		}

		// Allow the index manager to call each of the currently active
		// optional indexes with the block being connected so they can
		// update themselves accordingly.
		//	todo : indexManager
		if b.indexManager != nil {
			err := b.indexManager.ConnectBlockAbe(dbTx, block, stxos)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Prune fully spent entries and mark all entries in the view unmodified
	// now that the modifications have been committed to the database.
	view.commit()
	autView.commit()

	// This node is now the end of the best chain.
	b.bestChain.SetTip(node)

	// Update the state for the best block.  Notice how this replaces the
	// entire struct instead of updating the existing one.  This effectively
	// allows the old version to act as a snapshot which callers can use
	// freely without needing to hold a lock for the duration.  See the
	// comments on the state variable for more details.
	b.stateLock.Lock()
	b.stateSnapshot = state
	b.stateLock.Unlock()

	// Notify the caller that the block was connected to the main chain.
	// The caller would typically want to react with actions such as
	// updating wallets.
	func() {
		b.chainLock.Unlock()
		defer b.chainLock.Lock()

		b.sendNotification(NTBlockConnected, block)
	}()

	return nil
}

// disconnectBlock handles disconnecting the passed node/block from the end of
// the main (best) chain.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) disconnectBlock(node *blockNode, block *abeutil.Block, view *UtxoViewpoint) error {
	// Make sure the node being disconnected is the end of the best chain.
	if !node.hash.IsEqual(&b.bestChain.Tip().hash) {
		return AssertError("disconnectBlock must be called with the " +
			"block at the end of the main chain")
	}

	// Load the previous block since some details for it are needed below.
	prevNode := node.parent
	var prevBlock *abeutil.Block
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		prevBlock, err = dbFetchBlockByNode(dbTx, prevNode)
		return err
	})
	if err != nil {
		return err
	}

	// Write any block status changes to DB before updating best state.
	err = b.index.flushToDB()
	if err != nil {
		return err
	}

	// Generate a new best state snapshot that will be used to update the
	// database and later memory if all database updates are successful.
	b.stateLock.RLock()
	curTotalTxns := b.stateSnapshot.TotalTxns
	b.stateLock.RUnlock()
	numTxns := uint64(len(prevBlock.MsgBlock().Transactions))
	blockSize := uint64(prevBlock.MsgBlock().SerializeSize())
	blockWeight := uint64(GetBlockWeight(prevBlock))
	newTotalTxns := curTotalTxns - uint64(len(block.MsgBlock().Transactions))
	state := newBestState(prevNode, blockSize, blockWeight, numTxns,
		newTotalTxns, prevNode.CalcPastMedianTime())

	err = b.db.Update(func(dbTx database.Tx) error {
		// Update best block state.
		err := dbPutBestState(dbTx, state, node.workSum)
		if err != nil {
			return err
		}

		// Remove the block hash and height from the block index which
		// tracks the main chain.
		err = dbRemoveBlockIndex(dbTx, block.Hash(), node.height)
		if err != nil {
			return err
		}

		// Update the utxo set using the state of the utxo view.  This
		// entails restoring all of the utxos spent and removing the new
		// ones created by the block.
		err = dbPutUtxoView(dbTx, view)
		if err != nil {
			return err
		}

		// Before we delete the spend journal entry for this back,
		// we'll fetch it as is so the indexers can utilize if needed.
		stxos, err := dbFetchSpendJournalEntry(dbTx, block)
		if err != nil {
			return err
		}

		// Update the transaction spend journal by removing the record
		// that contains all txos spent by the block.
		err = dbRemoveSpendJournalEntry(dbTx, block.Hash())
		if err != nil {
			return err
		}

		// Allow the index manager to call each of the currently active
		// optional indexes with the block being disconnected so they
		// can update themselves accordingly.
		if b.indexManager != nil {
			err := b.indexManager.DisconnectBlock(dbTx, block, stxos)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Prune fully spent entries and mark all entries in the view unmodified
	// now that the modifications have been committed to the database.
	view.commit()

	// This node's parent is now the end of the best chain.
	b.bestChain.SetTip(node.parent)

	// Update the state for the best block.  Notice how this replaces the
	// entire struct instead of updating the existing one.  This effectively
	// allows the old version to act as a snapshot which callers can use
	// freely without needing to hold a lock for the duration.  See the
	// comments on the state variable for more details.
	b.stateLock.Lock()
	b.stateSnapshot = state
	b.stateLock.Unlock()

	// Notify the caller that the block was disconnected from the main
	// chain.  The caller would typically want to react with actions such as
	// updating wallets.
	func() {
		b.chainLock.Unlock()
		defer b.chainLock.Lock()
		b.sendNotification(NTBlockDisconnected, block)
	}()

	return nil
}

// disconnectBlockAbe
// Abe to do
// todo_DONE(MLP): reviewed on 2024.01.05
func (b *BlockChain) disconnectBlockAbe(node *blockNode, block *abeutil.BlockAbe,
	view *UtxoRingViewpoint, viewToDel *UtxoRingViewpoint,
	autView *AUTViewpoint, infoToDel map[string]struct{}) error {
	// Make sure the node being disconnected is the end of the best chain.
	if !node.hash.IsEqual(&b.bestChain.Tip().hash) {
		return AssertError("disconnectBlock must be called with the " +
			"block at the end of the main chain")
	}

	// Load the previous block since some details for it are needed below.
	prevNode := node.parent
	var prevBlock *abeutil.BlockAbe
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		prevBlock, err = dbFetchBlockByNodeAbe(dbTx, prevNode)
		return err
	})
	if err != nil {
		return err
	}

	// Write any block status changes to DB before updating best state.
	err = b.index.flushToDB()
	if err != nil {
		return err
	}

	// Generate a new best state snapshot that will be used to update the
	// database and later memory if all database updates are successful.
	b.stateLock.RLock()
	curTotalTxns := b.stateSnapshot.TotalTxns
	b.stateLock.RUnlock()
	numTxns := uint64(len(prevBlock.MsgBlock().Transactions))
	blockSize := uint64(prevBlock.MsgBlock().SerializeSize())
	//	todo(ABE): ABE does not use weight, while use size only.
	//	blockWeight := uint64(GetBlockWeight(prevBlock))
	blockWeight := blockSize
	newTotalTxns := curTotalTxns - uint64(len(block.MsgBlock().Transactions))
	state := newBestState(prevNode, blockSize, blockWeight, numTxns,
		newTotalTxns, prevNode.CalcPastMedianTime())

	err = b.db.Update(func(dbTx database.Tx) error {
		// Update best block state.
		err := dbPutBestState(dbTx, state, node.workSum)
		if err != nil {
			return err
		}

		// Remove the block hash and height from the block index which
		// tracks the main chain.
		err = dbRemoveBlockIndex(dbTx, block.Hash(), node.height)
		if err != nil {
			return err
		}

		// Update the utxo set using the state of the utxo view.  This
		// entails restoring all the utxos spent and removing the new
		// ones created by the block.
		//	Abe to do: Update the utxo set using the state of the utxo view.
		//	This entails restoring all the utxos spent
		err = dbPutUtxoRingView(dbTx, view)
		if err != nil {
			return err
		}

		//	Abe to do
		//	removing the new utxoRings created by the block and its previous successive 2 blocks (only is block.height%3==2)
		err = dbRemoveUtxoRingView(dbTx, viewToDel)
		if err != nil {
			return err
		}

		err = dbPutAUTView(dbTx, autView, node.height, node.hash)
		if err != nil {
			return err
		}

		// remove the new AUT with registration transaction
		err = dbRemoveAUTInfo(dbTx, infoToDel, node.height, node.hash)
		if err != nil {
			return err
		}

		// Before we delete the spend journal entry for this back,
		// we'll fetch it as is so the indexers can utilize if needed.
		stxos, err := dbFetchSpendJournalEntryAbe(dbTx, block)
		if err != nil {
			return err
		}

		// TODO(MLPAUT) transfer spent aut information to indexer manager
		_, err = dbFetchSpendJournalEntryAUT(dbTx, block)
		if err != nil {
			return err
		}

		// Update the transaction spend journal by removing the record
		// that contains all txos spent by the block.
		err = dbRemoveSpendJournalEntry(dbTx, block.Hash())
		if err != nil {
			return err
		}

		err = dbRemoveSpendJournalEntryAUT(dbTx, block.Hash())
		if err != nil {
			return err
		}

		// Allow the index manager to call each of the currently active
		// optional indexes with the block being disconnected so they
		// can update themselves accordingly.
		//	todo(ABE.MUST)
		if b.indexManager != nil {
			err := b.indexManager.DisconnectBlockAbe(dbTx, block, stxos)
			if err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	// Prune fully spent entries and mark all entries in the view unmodified
	// now that the modifications have been committed to the database.
	//	Abe to do: Note that some rings committed to tha database may be deleted in next(previous) block's disconnection.
	//	The checks can detect abnormal cases. The deleted rings will be removed from view after all blocks are disconnected.
	view.commit()
	autView.commit()

	// This node's parent is now the end of the best chain.
	b.bestChain.SetTip(node.parent)

	// Update the state for the best block.  Notice how this replaces the
	// entire struct instead of updating the existing one.  This effectively
	// allows the old version to act as a snapshot which callers can use
	// freely without needing to hold a lock for the duration.  See the
	// comments on the state variable for more details.
	b.stateLock.Lock()
	b.stateSnapshot = state
	b.stateLock.Unlock()

	// Notify the caller that the block was disconnected from the main
	// chain.  The caller would typically want to react with actions such as
	// updating wallets.
	invalidRingHashs := make([]chainhash.Hash, 0, len(viewToDel.entries))
	for hash, _ := range viewToDel.entries {
		invalidRingHashs = append(invalidRingHashs, hash)
	}

	func() {
		b.chainLock.Unlock()
		defer b.chainLock.Lock()

		b.sendNotification(NTBlockDisconnected, block)
		if len(invalidRingHashs) != 0 {
			b.sendNotification(NTInvalidRing, invalidRingHashs)
		}
	}()
	return nil
}

// countSpentOutputs returns the number of utxos the passed block spends.
func countSpentOutputs(block *abeutil.Block) int {
	// Exclude the coinbase transaction since it can't spend anything.
	var numSpent int
	for _, tx := range block.Transactions()[1:] {
		numSpent += len(tx.MsgTx().TxIn)
	}
	return numSpent
}

func countSpentOutputsAbe(block *abeutil.BlockAbe) int {
	// Exclude the coinbase transaction since it can't spend anything.
	var numSpent = 0
	for _, tx := range block.Transactions()[1:] {
		numSpent += len(tx.MsgTx().TxIns)
	}
	return numSpent
}

func countSpentOutputsAUT(block *abeutil.BlockAbe) int {
	// Exclude the transfer transaction which is not an AUT transaction
	var num = 0
	for _, tx := range block.Transactions()[1:] {
		//if autTx, isAUTTx := tx.AUTTransaction(); isAUTTx {
		//	if autTx.Type() < aut.ReRegistration {
		//		// it seems that we do not need saut for those type
		//	}
		//	num++
		//}

		autTx, err := tx.AUTTransaction()
		if err != nil {
			//	This should not happen
			log.Warnf("countSpentOutputsAUT: error happens when extracting AutTransaction from Tx %s: %v", tx.Hash(), err)
		}
		if autTx != nil {
			if autTx.Type() < aut.ReRegistration {
				// just record them, but it seems that do not need saut for those type
			}
			num++
		}

	}
	return num
}

// reorganizeChainAbe reorganizes the block chain by disconnecting the nodes in the
// detachNodes list and connecting the nodes in the attach list.  It expects
// that the lists are already in the correct order and are in sync with the
// end of the current best chain.  Specifically, nodes that are being
// disconnected must be in reverse order (think of popping them off the end of
// the chain) and nodes the are being attached must be in forwards order
// (think pushing them onto the end of the chain).
//
// This function may modify node statuses in the block index without flushing.
//
// This function MUST be called with the chain state lock held (for writes).
//
//		Abe todo
//	  1. Ensure the first node of detach nodes match the best block
//	  2. Ensure the parent block of last detach node match the parent block of first attach node
//	  3. Detach each block (only for valid test)
//	      1. Fetch the block data and all inputs
//	      2. Disconnect all transactions from utxo ring view (disconnectTransactions)
//	      3. If block height matches the certain height, add utxo rings generated by it to viewToDelAll for deleting later
//	  4. Delete all the rings generated by detach nodes (?)
//	  5. Attach each block (only for valid test)
//	      1. If is tagged as valid before, just connect (connectTransactions), otherwise, check and connect (checkConnectBlockAbe)
//	      2. If block height matches the certain height, generate new utxo rings
//	  6. Detach each block and attach each block really
//
// todo_DONE(MLP): reviewed on 2024.01.05
func (b *BlockChain) reorganizeChainAbe(detachNodes, attachNodes *list.List) error {
	// Nothing to do if no reorganize nodes were provided.
	if detachNodes.Len() == 0 && attachNodes.Len() == 0 {
		return nil
	}

	// Ensure the provided nodes match the current best chain.
	tip := b.bestChain.Tip()
	if detachNodes.Len() != 0 {
		firstDetachNode := detachNodes.Front().Value.(*blockNode)
		if firstDetachNode.hash != tip.hash {
			return AssertError(fmt.Sprintf("reorganize nodes to detach are "+
				"not for the current best chain -- first detach node %v, "+
				"current chain %v", &firstDetachNode.hash, &tip.hash))
		}
	}

	// Ensure the provided nodes are for the same fork point.
	if attachNodes.Len() != 0 && detachNodes.Len() != 0 {
		firstAttachNode := attachNodes.Front().Value.(*blockNode)
		lastDetachNode := detachNodes.Back().Value.(*blockNode)
		if firstAttachNode.parent.hash != lastDetachNode.parent.hash {
			return AssertError(fmt.Sprintf("reorganize nodes do not have the "+
				"same fork point -- first attach parent %v, last detach "+
				"parent %v", &firstAttachNode.parent.hash,
				&lastDetachNode.parent.hash))
		}
	}

	// Track the old and new best chains heads.
	oldBest := tip
	newBest := tip

	// All the blocks to detach and related spend journal entries needed
	// to unspend transaction outputs in the blocks being disconnected must
	// be loaded from the database during the reorg check phase below and
	// then they are needed again when doing the actual database updates.
	// Rather than doing two loads, cache the loaded data into these slices.
	detachBlocks := make([]*abeutil.BlockAbe, 0, detachNodes.Len())
	detachSpentTxOuts := make([][]*SpentTxOutAbe, 0, detachNodes.Len())
	detachSpentAUTs := make([][]SpentAUT, 0, detachNodes.Len())
	attachBlocks := make([]*abeutil.BlockAbe, 0, attachNodes.Len())

	// Disconnect all the blocks back to the point of the fork.  This
	// entails loading the blocks and their associated spent txos from the
	// database and using that information to unspend all the spent txos
	// and remove the utxos created by the blocks.
	view := NewUtxoRingViewpoint()
	view.SetBestHash(&oldBest.hash)
	viewToDelAll := NewUtxoRingViewpoint()
	viewToDelAll.SetBestHash(&oldBest.hash)

	autView := NewAUTViewpoint()
	autView.SetBestHash(&oldBest.hash)
	var autInfoToDel map[string]struct{}

	for e := detachNodes.Front(); e != nil; e = e.Next() {
		n := e.Value.(*blockNode)
		blockHeader := n.Header()
		log.Debugf("DETACH: Block %s (seal hash %s, height %d) is trying to detach", n.hash, ethash.SealHash(&blockHeader), n.height)

		var block *abeutil.BlockAbe
		err := b.db.View(func(dbTx database.Tx) error {
			var err error
			block, err = dbFetchBlockByNodeAbe(dbTx, n)
			return err
		})
		if err != nil {
			return err
		}
		if n.hash != *block.Hash() {
			return AssertError(fmt.Sprintf("detach block node hash %v (height "+
				"%v) does not match previous parent block hash %v", &n.hash,
				n.height, block.Hash()))
		}

		//	Abe to do: why to read from databse, we can directly use the SpendJournal to obtain the related UtxoRings
		/*		// Load all of the utxos referenced by the block that aren't
				// already in the view.
				err = view.fetchInputUtxoRings(b.db, block)
				if err != nil {
					return err
				}*/

		// Load all of the spent txos for the block from the spend
		// journal.
		var stxos []*SpentTxOutAbe
		var sauts []SpentAUT
		err = b.db.View(func(dbTx database.Tx) error {
			stxos, err = dbFetchSpendJournalEntryAbe(dbTx, block)
			if err != nil {
				return err
			}
			sauts, err = dbFetchSpendJournalEntryAUT(dbTx, block)
			return err
		})
		if err != nil {
			return err
		}

		// Store the loaded block and spend journal entry for later.
		detachBlocks = append(detachBlocks, block)
		detachSpentTxOuts = append(detachSpentTxOuts, stxos)
		detachSpentAUTs = append(detachSpentAUTs, sauts)

		// todo_DONE(MLP): reviewed on 2024.01.05
		// view loads all the related UtxoRingEntries of the TxIns of the transactions in block, using stxos.
		err = view.disconnectTransactions(b.db, block, stxos)
		if err != nil {
			return err
		}

		autInfoToDel, err = autView.disconnectTransactions(b.db, block, sauts)
		if err != nil {
			return err
		}

		//	Abe to do new UtxoRings if n.height % 2 == 0
		//	These utxoRings should will be deleted from database
		//	TODO: when BlockNumPerRingGroup or TxoRingSize change, it may cause fork.
		//	The mapping between BlockNumPerRingGroup/TxoRingSize and height is hardcoded in wire.GetBlockNumPerRingGroup/TxoRingSize.
		blockNumPerRingGroup := int32(wire.GetBlockNumPerRingGroupByBlockHeight(n.height))
		//		if n.height%3 == 2 {
		//if n.height%wire.BlockNumPerRingGroup == wire.BlockNumPerRingGroup-1 {
		if n.height%blockNumPerRingGroup == blockNumPerRingGroup-1 {
			viewToDelAll.SetBestHash(&n.hash)
			//	todo_DONE(MLP): reviewed on 2024.01.05
			// err = viewToDelAll.newUtxoRingEntries(b.db, n, block)
			err = viewToDelAll.newUtxoRingEntriesMLP(b.db, n, block)
			if err != nil {
				return err
			}
		}

		newBest = n.parent
	}

	//	Abe to do
	//	if a UtxoRing obtained by unspend (from higher blocks) is in the viewRingsToDel (from lower blocks), the UtxoRing should have len(serialNumbers) == 0
	//	just enhance checks
	//	and such UtxoRings should be removed from view, since view will be used in the latter attach
	//	when attaching, the utxoRings in view should not be fetched from database, since the database is still storing the data for old main chain
	//	Note that In general, len(viewRingsToDel.entries) < len(view.entries), we range the viewRingsToDel.entries
	/*	for outPointRingHash, utxoRingEntry := range view.entries {
		ringToDel := viewRingsToDel.entries[outPointRingHash]
		if ringToDel != nil {
			if len(utxoRingEntry.serialNumbers) > 0 {
				return AssertError(fmt.Sprintf("detaching utxoRing (ringHeight = %d, outPointHash = %v) fail: the serialNumbers List should be empty, but not",
					utxoRingEntry.ringBlockHeight, utxoRingEntry.outPointRing.Hash()))
			}
		}
	}*/
	for ringHash, _ := range viewToDelAll.entries {
		ringFromStxo := view.entries[ringHash]
		if ringFromStxo != nil {
			if len(ringFromStxo.serialNumbers) > 0 {
				return AssertError(fmt.Sprintf("detaching utxoRing (ringHeight = %d, outPointHash = %v) fail: the serialNumbers List should be empty, but not",
					ringFromStxo.ringBlockHeight, ringFromStxo.outPointRing.Hash()))
			}
			delete(view.entries, ringHash)
			// TODO put the ring hash to sync manager
			// Then the sync manager clean the mempool
		} else {
			// This may happen, since view only loaded those appeared in TxIn.
			// Do Nothing.
		}
	}

	for autIdentifierKey := range autInfoToDel {
		entry := autView.entries[autIdentifierKey]
		if entry != nil {
			delete(autView.entries, autIdentifierKey)
		} else {
			// ?
		}
	}

	// Set the fork point only if there are nodes to attach since otherwise
	// blocks are only being disconnected and thus there is no fork point.
	var forkNode *blockNode
	if attachNodes.Len() > 0 {
		forkNode = newBest
	}

	// Perform several checks to verify each block that needs to be attached
	// to the main chain can be connected without violating any rules and
	// without actually connecting the block.
	//
	// NOTE: These checks could be done directly when connecting a block,
	// however the downside to that approach is that if any of these checks
	// fail after disconnecting some blocks or attaching others, all the
	// operations have to be rolled back to get the chain back into the
	// state it was before the rule violation (or other failure).  There are
	// at least a couple of ways accomplish that rollback, but both involve
	// tweaking the chain and/or database.  This approach catches these
	// issues before ever modifying the chain.
	for e := attachNodes.Front(); e != nil; e = e.Next() {
		n := e.Value.(*blockNode)
		blockHeader := n.Header()
		log.Debugf("ATTACH: Block %s (seal hash %s, height %d) is trying to attach", n.hash, ethash.SealHash(&blockHeader), n.height)

		var block *abeutil.BlockAbe
		err := b.db.View(func(dbTx database.Tx) error {
			var err error
			block, err = dbFetchBlockByNodeAbe(dbTx, n)
			return err
		})
		if err != nil {
			return err
		}

		// Store the loaded block for later.
		attachBlocks = append(attachBlocks, block)

		// Skip checks if node has already been fully validated. Although
		// checkConnectBlock gets skipped, we still need to update the UTXO
		// view.
		if b.index.NodeStatus(n).KnownValid() {
			err = view.fetchInputUtxoRings(b.db, block)
			if err != nil {
				return err
			}

			err = view.connectTransactions(block, nil)
			if err != nil {
				return err
			}

			err = autView.fetchInputAUTUtxos(b.db, block)
			if err != nil {
				return err
			}

			err = autView.connectTransactions(block, nil)
			if err != nil {
				return err
			}
			/*			newBest = n
						continue*/
		} else {
			// Notice the spent txout details are not requested here and
			// thus will not be generated.  This is done because the state
			// is not being immediately written to the database, so it is
			// not needed.
			//
			// In the case the block is determined to be invalid due to a
			// rule violation, mark it as invalid and mark all of its
			// descendants as having an invalid ancestor.
			err = b.checkConnectBlockAbe(n, block, view, nil, autView, nil)
			if err != nil {
				if ruleErr, ok := err.(RuleError); ok {
					if ruleErr.ErrorCode == ErrWitnessMissing {
						b.index.SetStatusFlags(n, statusWitnessMissing)
					} else {
						b.index.SetStatusFlags(n, statusValidateFailed)
						for de := e.Next(); de != nil; de = de.Next() {
							dn := de.Value.(*blockNode)
							b.index.SetStatusFlags(dn, statusInvalidAncestor)
						}
					}
				}
				return err
			}
			b.index.SetStatusFlags(n, statusValid)
		}

		newBest = n

		//	Abe to do: new UtxoRings if n.height % 3 == 2
		//	TODO: when BlockNumPerRingGroup or TxoRingSize change, it may cause fork.
		//	The mapping between BlockNumPerRingGroup/TxoRingSize and height is hardcoded in wire.GetBlockNumPerRingGroup/TxoRingSize.
		//	Here we should call blockNumPerRingGroup = wire.GetBlockNumPerRingGroup()
		//	At this moment (no fork due to BlockNumPerRingGroup/TxoRingSize change), we directly use the constant.
		blockNumPerRingGroup := int32(wire.GetBlockNumPerRingGroupByBlockHeight(n.height))
		//if n.height%3 == 2 {
		//if n.height%wire.BlockNumPerRingGroup == wire.BlockNumPerRingGroup-1 {
		if n.height%blockNumPerRingGroup == blockNumPerRingGroup-1 {
			//	todo(MLPAUT):
			//err = view.newUtxoRingEntries(b.db, n, block)
			err = view.newUtxoRingEntriesMLP(b.db, n, block)
			if err != nil {
				return err
			}
		}

	}

	// Reset the view for the actual connection code below.  This is
	// required because the view was previously modified when checking if
	// the reorg would be successful and the connection code requires the
	// view to be valid from the viewpoint of each block being connected or
	// disconnected.
	view = NewUtxoRingViewpoint()
	view.SetBestHash(&b.bestChain.Tip().hash)
	autView = NewAUTViewpoint()
	autView.SetBestHash(&b.bestChain.Tip().hash)

	// Disconnect blocks from the main chain.
	for i, e := 0, detachNodes.Front(); e != nil; i, e = i+1, e.Next() {
		n := e.Value.(*blockNode)
		block := detachBlocks[i]
		log.Debugf("DETACH: Block %s (seal hash %s, height %d) is detaching", n.hash, ethash.SealHash(&block.MsgBlock().Header), n.height)

		viewToDel := NewUtxoRingViewpoint()
		viewToDel.SetBestHash(block.Hash())
		var infoToDel map[string]struct{}

		//	Abe to do: why to read from databse, we can directly use the SpendJournal to obtain the related UtxoRings
		// Load all of the utxos referenced by the block that aren't
		/*		// already in the view.
				err := view.fetchInputUtxos(b.db, block)
				if err != nil {
					return err
				}*/

		// Update the view to unspend all the spent txos and remove
		// the utxos created by the block.
		// view loaded the UtxoRingEntries appeared in TxIns of block, by using detachSpentTxOuts[].
		err := view.disconnectTransactions(b.db, block, detachSpentTxOuts[i])
		if err != nil {
			return err
		}

		infoToDel, err = autView.disconnectTransactions(b.db, block, detachSpentAUTs[i])
		if err != nil {
			return err
		}

		//	Abe to do
		//	view.disconnectTransactions update the view for this block, the following b.disconnectBlock persist the changes for this block to the database
		//	So, here we need to generate the utxoRings that need to be deleted from database
		//	TODO: when BlockNumPerRingGroup or TxoRingSize change, it may cause fork.
		//	The mapping between BlockNumPerRingGroup/TxoRingSize and height is hardcoded in wire.GetBlockNumPerRingGroup/TxoRingSize.
		//	Here we should call blockNumPerRingGroup = wire.GetBlockNumPerRingGroup()
		//	At this moment (no fork due to BlockNumPerRingGroup/TxoRingSize change), we directly use the constant.
		blockNumPerRingGroup := int32(wire.GetBlockNumPerRingGroupByBlockHeight(n.height))
		//if n.height%3 == 2 {
		//if n.height%wire.BlockNumPerRingGroup == wire.BlockNumPerRingGroup-1 {
		if n.height%blockNumPerRingGroup == blockNumPerRingGroup-1 {
			//	todo(MLPAUT):
			// err = viewToDel.newUtxoRingEntries(b.db, n, block)
			err = viewToDel.newUtxoRingEntriesMLP(b.db, n, block)
			if err != nil {
				return err
			}
		}

		for ringHash, _ := range viewToDel.entries {
			ringFromStxo := view.entries[ringHash]
			if ringFromStxo != nil {
				if len(ringFromStxo.serialNumbers) > 0 {
					return AssertError(fmt.Sprintf("detaching utxoRing (ringHeight = %d, outPointHash = %v) fail: the serialNumbers List should be empty, but not",
						ringFromStxo.ringBlockHeight, ringFromStxo.outPointRing.Hash()))
				}
				delete(view.entries, ringHash)
			} else {
				// added by Alice on 2024.01.05
				// This may happen, since view loaded only UtxoRingEntries appeared in TxIns of blocks.
			}
		}

		for autIdentifierKey := range infoToDel {
			entry := autView.entries[autIdentifierKey]
			if entry != nil {
				delete(autView.entries, autIdentifierKey)
			} else {
				// ?
			}
		}

		// Update the database and chain state.
		// todo_DONE(MLP): reviewed on 2024.01.05
		err = b.disconnectBlockAbe(n, block, view, viewToDel, autView, infoToDel)
		if err != nil {
			return err
		}

	}

	//	Abe to do
	//	remove rings from the view which restored from stxos, the resulting view will be ready for attach
	for ringHash, _ := range viewToDelAll.entries {
		ringFromStxo := view.entries[ringHash]
		if ringFromStxo != nil {
			// added by Alice, on 2024.01.05
			// This should not happen, since viewToDel above has been removed one by one.
			// todo(MLP): review on 2024.01.06
			return AssertError(fmt.Sprintf("unexcepted case happens: detaching utxoRing (ringHeight = %d, outPointHash = %v) fail: view still contains ringHash in viewToDelAll",
				ringFromStxo.ringBlockHeight, ringFromStxo.outPointRing.Hash()))

			if len(ringFromStxo.serialNumbers) > 0 {
				return AssertError(fmt.Sprintf("detaching utxoRing (ringHeight = %d, outPointHash = %v) fail: the serialNumbers List should be empty, but not",
					ringFromStxo.ringBlockHeight, ringFromStxo.outPointRing.Hash()))
			}
			delete(view.entries, ringHash)
		}
	}

	// Connect the new best chain blocks.
	for i, e := 0, attachNodes.Front(); e != nil; i, e = i+1, e.Next() {
		n := e.Value.(*blockNode)
		block := attachBlocks[i]
		log.Debugf("ATTACH: Block %s (seal hash %s, height %d) is attaching", n.hash, ethash.SealHash(&block.MsgBlock().Header), n.height)

		// Load all of the utxos referenced by the block that aren't
		// already in the view.
		err := view.fetchInputUtxoRings(b.db, block)
		if err != nil {
			return err
		}

		err = autView.fetchInputAUTUtxos(b.db, block)
		if err != nil {
			return err
		}

		// Update the view to mark all utxos referenced by the block
		// as spent and add all transactions being created by this block
		// to it.  Also, provide an stxo slice so the spent txout
		// details are generated.
		stxos := make([]*SpentTxOutAbe, 0, countSpentOutputsAbe(block))
		err = view.connectTransactions(block, &stxos)
		if err != nil {
			return err
		}

		sauts := make([]SpentAUT, 0, countSpentOutputsAUT(block))
		err = autView.connectTransactions(block, &sauts)
		if err != nil {
			return err
		}

		//	Abe to do: new UtxoRings if n.height % 3 == 2
		//	TODO: when BlockNumPerRingGroup or TxoRingSize change, it may cause fork.
		//	The mapping between BlockNumPerRingGroup/TxoRingSize and height is hardcoded in wire.GetBlockNumPerRingGroup/TxoRingSize.
		//	Here we should call blockNumPerRingGroup = wire.GetBlockNumPerRingGroup()
		//	At this moment (no fork due to BlockNumPerRingGroup/TxoRingSize change), we directly use the constant.
		blockNumPerRingGroup := int32(wire.GetBlockNumPerRingGroupByBlockHeight(n.height))
		// if n.height%3 == 2 {
		//if n.height%wire.BlockNumPerRingGroup == wire.BlockNumPerRingGroup-1 {
		if n.height%blockNumPerRingGroup == blockNumPerRingGroup-1 {
			//	todo_DONE(MLP): reviewed on 2024.01.05
			// err = view.newUtxoRingEntries(b.db, n, block)
			err = view.newUtxoRingEntriesMLP(b.db, n, block)
			if err != nil {
				return err
			}
		}

		// Update the database and chain state.
		err = b.connectBlockAbe(n, block, view, stxos, autView, sauts)
		if err != nil {
			return err
		}
	}

	// Log the point where the chain forked and old and new best chain
	// heads.
	if forkNode != nil {
		log.Infof("REORGANIZE: Chain forks at %v (height %v)", forkNode.hash,
			forkNode.height)
	}
	log.Infof("REORGANIZE: Old best chain head was %v (height %v)",
		&oldBest.hash, oldBest.height)
	log.Infof("REORGANIZE: New best chain head is %v (height %v)",
		newBest.hash, newBest.height)

	return nil
}

// connectBestChainAbe handles connecting the passed block to the chain while
// respecting proper chain selection according to the chain with the most
// proof of work.  In the typical case, the new block simply extends the main
// chain.  However, it may also be extending (or creating) a side chain (fork)
// which may or may not end up becoming the main chain depending on which fork
// cumulatively has the most proof of work.  It returns whether or not the block
// ended up on the main chain (either due to extending the main chain or causing
// a reorganization to become the main chain).
//
// The flags modify the behavior of this function as follows:
//   - BFFastAdd: Avoids several expensive transaction validation operations.
//     This is useful when using checkpoints.
//
// This function MUST be called with the chain state lock held (for writes).
//
//		Abe todo
//	  1. If it is the next block of current best block (main chain)
//	    1. Check and connect block on the chain (checkConnectBlockAbe) (including witness check)
//	    2. If matches the specific height, generate new utxo rings and add them into ring view (newUtxoRingEntries)
//	    3. Update and store the new best state, block index, utxo rings and spent journal (connectBlockAbe)
//	    4. Mark the new block as valid in database
//	  2. If it is not the next block of current best block
//	    1. Log and return if worksum is smaller than main chain (we do not check the inputs and witness)
//	    2. Find detachNodes and attachNode (getReorganizeNodesAbe)
//	    3. Reorganize the chain (reorganizeChainAbe)
//
// todo_DONE(MLP): reviewed on 2024.01.05
func (b *BlockChain) connectBestChainAbe(node *blockNode, block *abeutil.BlockAbe, flags BehaviorFlags) (bool, error) {
	fastAdd := flags&BFFastAdd == BFFastAdd

	flushIndexState := func() {
		// Intentionally ignore errors writing updated node status to DB. If
		// it fails to write, it's not the end of the world. If the block is
		// valid, we flush in connectBlock and if the block is invalid, the
		// worst that can happen is we revalidate the block after a restart.
		if writeErr := b.index.flushToDB(); writeErr != nil {
			log.Warnf("Error flushing block index changes to disk: %v",
				writeErr)
		}
	}

	// We are extending the main (best) chain with a new block.  This is the
	// most common case.
	parentHash := &block.MsgBlock().Header.PrevBlock
	if parentHash.IsEqual(&b.bestChain.Tip().hash) {
		// Skip checks if node has already been fully validated.
		fastAdd = fastAdd || b.index.NodeStatus(node).KnownValid()

		// Perform several checks to verify the block can be connected
		// to the main chain without violating any rules and without
		// actually connecting the block.
		view := NewUtxoRingViewpoint()
		view.SetBestHash(parentHash)
		stxos := make([]*SpentTxOutAbe, 0, countSpentOutputsAbe(block))

		autView := NewAUTViewpoint()
		autView.SetBestHash(parentHash)
		sauts := make([]SpentAUT, 0, countSpentOutputsAUT(block))

		if !fastAdd || b.nodeType == wire.FullNode {
			// todo_DONE(MLP): reviewed on 2024.01.04
			err := b.checkConnectBlockAbe(node, block, view, &stxos, autView, &sauts)
			if err == nil {
				b.index.SetStatusFlags(node, statusValid)
			} else if _, ok := err.(RuleError); ok {
				b.index.SetStatusFlags(node, statusValidateFailed)
			} else {
				return false, err
			}

			flushIndexState()

			if err != nil {
				return false, err
			}
		} else {
			// In the fast add case the code to check the block connection
			// was skipped, so the utxo view needs to load the referenced
			// utxos, spend them, and add the new utxos being created by
			// this block.
			err := view.fetchInputUtxoRings(b.db, block)
			if err != nil {
				return false, err
			}
			// todo_DONE(MLP): reviewed on 2024.01.04
			err = view.connectTransactions(block, &stxos)
			if err != nil {
				return false, err
			}

			err = autView.fetchInputAUTUtxos(b.db, block)
			if err != nil {
				return false, err
			}
			err = autView.connectTransactions(block, &sauts)
			if err != nil {
				return false, err
			}
		}

		//	TODO: generating new UtxoRingEntry if currentblock.height%2 = 0
		//if node.height%2 == 0 {
		//	TODO: when BlockNumPerRingGroup or TxoRingSize change, it may cause fork.
		//	The mapping between BlockNumPerRingGroup/TxoRingSize and height is hardcoded in wire.GetBlockNumPerRingGroup/TxoRingSize.
		//	Here we should call blockNumPerRingGroup = wire.GetBlockNumPerRingGroup()
		//	At this moment (no fork due to BlockNumPerRingGroup/TxoRingSize change), we directly use the constant.
		blockNumPerRingGroup := int32(wire.GetBlockNumPerRingGroupByBlockHeight(node.height))
		//if node.height%wire.BlockNumPerRingGroup == wire.BlockNumPerRingGroup-1 {
		if node.height%blockNumPerRingGroup == blockNumPerRingGroup-1 {
			//	todo_DONE(MLP): reviewed on 2024.01.04
			// err := view.newUtxoRingEntries(b.db, node, block)
			err := view.newUtxoRingEntriesMLP(b.db, node, block)
			if err != nil {
				return false, err
			}
		}

		// Connect the block to the main chain.
		//	ToDo(ABE): Here stxos is used as input, all precious are setting stxos
		//	todo_DONE(MLP): reviewed on 2024.01.04
		err := b.connectBlockAbe(node, block, view, stxos, autView, sauts)
		if err != nil {
			// If we got hit with a rule error, then we'll mark
			// that status of the block as invalid and flush the
			// index state to disk before returning with the error.
			if _, ok := err.(RuleError); ok {
				b.index.SetStatusFlags(
					node, statusValidateFailed,
				)
			}

			flushIndexState()

			return false, err
		}

		// If this is fast add, or this block node isn't yet marked as
		// valid, then we'll update its status and flush the state to
		// disk again.
		if fastAdd || !b.index.NodeStatus(node).KnownValid() {
			b.index.SetStatusFlags(node, statusValid)
			flushIndexState()
		}

		return true, nil
	}
	if fastAdd {
		log.Warnf("fastAdd set in the side chain case? %v\n",
			block.Hash())
	}

	// We're extending (or creating) a side chain, but the cumulative
	// work for this new side chain is not enough to make it the new chain.
	if node.workSum.Cmp(b.bestChain.Tip().workSum) <= 0 {
		// Log information about how the block is forking the chain.
		fork := b.bestChain.FindFork(node)
		if fork.hash.IsEqual(parentHash) {
			log.Infof("FORK: Block %v (seal hash %v) forks the chain at height %d"+
				"/block %v, but does not cause a reorganize",
				node.hash, ethash.SealHash(&block.MsgBlock().Header), fork.height, fork.hash)
		} else {
			log.Infof("EXTEND FORK: Block %v (seal hash %v) extends a side chain "+
				"which forks the chain at height %d/block %v",
				node.hash, ethash.SealHash(&block.MsgBlock().Header), fork.height, fork.hash)
		}

		return false, nil
	}

	// We're extending (or creating) a side chain and the cumulative work
	// for this new side chain is more than the old best chain, so this side
	// chain needs to become the main chain.  In order to accomplish that,
	// find the common ancestor of both sides of the fork, disconnect the
	// blocks that form the (now) old fork from the main chain, and attach
	// the blocks that form the new chain to the main chain starting at the
	// common ancenstor (the point where the chain forked).
	detachNodes, attachNodes := b.getReorganizeNodesAbe(node)

	// Reorganize the chain.
	log.Infof("REORGANIZE: Block %v (seal hash %v) at height %d is causing a reorganize.", node.hash, ethash.SealHash(&block.MsgBlock().Header), node.height)
	// todo_DONE(MLP): reviewed on 2024.01.05
	err := b.reorganizeChainAbe(detachNodes, attachNodes)

	// Either getReorganizeNodes or reorganizeChain could have made unsaved
	// changes to the block index, so flush regardless of whether there was an
	// error. The index would only be dirty if the block failed to connect, so
	// we can ignore any errors writing.
	if writeErr := b.index.flushToDB(); writeErr != nil {
		log.Warnf("Error flushing block index changes to disk: %v", writeErr)
	}

	return err == nil, err
}

// isCurrent returns whether or not the chain believes it is current.  Several
// factors are used to guess, but the key factors that allow the chain to
// believe it is current are:
//   - Latest block height is after the latest checkpoint (if enabled)
//   - Latest block has a timestamp newer than 24 hours ago
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) isCurrent() bool {
	// Not current if the latest main (best) chain height is before the
	// latest known good checkpoint (when checkpoints are enabled).
	checkpoint := b.LatestCheckpoint()
	if checkpoint != nil && b.bestChain.Tip().height < checkpoint.Height {
		return false
	}

	// Not current if the latest best block has a timestamp before 24 hours
	// ago.
	//
	// The chain appears to be current if none of the checks reported
	// otherwise.
	//TODO(abe): if the node stop running more than one day, this check will be false
	minus24Hours := b.timeSource.AdjustedTime().Add(-24 * time.Hour).Unix()
	return b.bestChain.Tip().timestamp >= minus24Hours
}

// IsCurrent returns whether or not the chain believes it is current.  Several
// factors are used to guess, but the key factors that allow the chain to
// believe it is current are:
//   - Latest block height is after the latest checkpoint (if enabled)
//   - Latest block has a timestamp newer than 24 hours ago
//
// This function is safe for concurrent access.
func (b *BlockChain) IsCurrent() bool {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	return b.isCurrent()
}

// BestSnapshot returns information about the current best chain block and
// related state as of the current point in time.  The returned instance must be
// treated as immutable since it is shared by all callers.
//
// This function is safe for concurrent access.
func (b *BlockChain) BestSnapshot() *BestState {
	b.stateLock.RLock()
	snapshot := b.stateSnapshot
	b.stateLock.RUnlock()
	return snapshot
}

func (b *BlockChain) BestChainWorkSum() *big.Int {
	bestNode := b.bestChain.Tip()
	return bestNode.workSum
}

// HeaderByHash returns the block header identified by the given hash or an
// error if it doesn't exist. Note that this will return headers from both the
// main and side chains.
func (b *BlockChain) HeaderByHash(hash *chainhash.Hash) (wire.BlockHeader, error) {
	node := b.index.LookupNode(hash)
	if node == nil {
		err := fmt.Errorf("block %s is not known", hash)
		return wire.BlockHeader{}, err
	}

	return node.Header(), nil
}

// MainChainHasBlock returns whether or not the block with the given hash is in
// the main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) MainChainHasBlock(hash *chainhash.Hash) bool {
	node := b.index.LookupNode(hash)
	return node != nil && b.bestChain.Contains(node)
}

// BlockLocatorFromHash returns a block locator for the passed block hash.
// See BlockLocator for details on the algorithm used to create a block locator.
//
// In addition to the general algorithm referenced above, this function will
// return the block locator for the latest known tip of the main (best) chain if
// the passed hash is not currently known.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockLocatorFromHash(hash *chainhash.Hash) BlockLocator {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()
	node := b.index.LookupNode(hash)
	locator := b.bestChain.blockLocator(node)
	return locator
}

// LatestBlockLocator returns a block locator for the latest known tip of the
// main (best) chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) LatestBlockLocator() (BlockLocator, error) {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	locator := b.bestChain.BlockLocator(nil)
	return locator, nil
}

// BlockHeightByHash returns the height of the block with the given hash in the
// main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockHeightByHash(hash *chainhash.Hash) (int32, error) {
	node := b.index.LookupNode(hash)
	if node == nil || !b.bestChain.Contains(node) {
		str := fmt.Sprintf("block %s is not in the main chain", hash)
		return 0, errNotInMainChain(str)
	}

	return node.height, nil
}

// BlockHashByHeight returns the hash of the block at the given height in the
// main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockHashByHeight(blockHeight int32) (*chainhash.Hash, error) {
	node := b.bestChain.NodeByHeight(blockHeight)
	if node == nil {
		str := fmt.Sprintf("no block at height %d exists", blockHeight)
		return nil, errNotInMainChain(str)

	}

	return &node.hash, nil
}

// HeightRange returns a range of block hashes for the given start and end
// heights.  It is inclusive of the start height and exclusive of the end
// height.  The end height will be limited to the current main chain height.
//
// This function is safe for concurrent access.
func (b *BlockChain) HeightRange(startHeight, endHeight int32) ([]chainhash.Hash, error) {
	// Ensure requested heights are sane.
	if startHeight < 0 {
		return nil, fmt.Errorf("start height of fetch range must not "+
			"be less than zero - got %d", startHeight)
	}
	if endHeight < startHeight {
		return nil, fmt.Errorf("end height of fetch range must not "+
			"be less than the start height - got start %d, end %d",
			startHeight, endHeight)
	}

	// There is nothing to do when the start and end heights are the same,
	// so return now to avoid the chain view lock.
	if startHeight == endHeight {
		return nil, nil
	}

	// Grab a lock on the chain view to prevent it from changing due to a
	// reorg while building the hashes.
	b.bestChain.mtx.Lock()
	defer b.bestChain.mtx.Unlock()

	// When the requested start height is after the most recent best chain
	// height, there is nothing to do.
	latestHeight := b.bestChain.tip().height
	if startHeight > latestHeight {
		return nil, nil
	}

	// Limit the ending height to the latest height of the chain.
	if endHeight > latestHeight+1 {
		endHeight = latestHeight + 1
	}

	// Fetch as many as are available within the specified range.
	hashes := make([]chainhash.Hash, 0, endHeight-startHeight)
	for i := startHeight; i < endHeight; i++ {
		hashes = append(hashes, b.bestChain.nodeByHeight(i).hash)
	}
	return hashes, nil
}

// HeightToHashRange returns a range of block hashes for the given start height
// and end hash, inclusive on both ends.  The hashes are for all blocks that are
// ancestors of endHash with height greater than or equal to startHeight.  The
// end hash must belong to a block that is known to be valid.
//
// This function is safe for concurrent access.
func (b *BlockChain) HeightToHashRange(startHeight int32,
	endHash *chainhash.Hash, maxResults int) ([]chainhash.Hash, error) {

	endNode := b.index.LookupNode(endHash)
	if endNode == nil {
		return nil, fmt.Errorf("no known block header with hash %v", endHash)
	}
	if !b.index.NodeStatus(endNode).KnownValid() {
		return nil, fmt.Errorf("block %v is not yet validated", endHash)
	}
	endHeight := endNode.height

	if startHeight < 0 {
		return nil, fmt.Errorf("start height (%d) is below 0", startHeight)
	}
	if startHeight > endHeight {
		return nil, fmt.Errorf("start height (%d) is past end height (%d)",
			startHeight, endHeight)
	}

	resultsLength := int(endHeight - startHeight + 1)
	if resultsLength > maxResults {
		return nil, fmt.Errorf("number of results (%d) would exceed max (%d)",
			resultsLength, maxResults)
	}

	// Walk backwards from endHeight to startHeight, collecting block hashes.
	node := endNode
	hashes := make([]chainhash.Hash, resultsLength)
	for i := resultsLength - 1; i >= 0; i-- {
		hashes[i] = node.hash
		node = node.parent
	}
	return hashes, nil
}

// IntervalBlockHashes returns hashes for all blocks that are ancestors of
// endHash where the block height is a positive multiple of interval.
//
// This function is safe for concurrent access.
func (b *BlockChain) IntervalBlockHashes(endHash *chainhash.Hash, interval int,
) ([]chainhash.Hash, error) {

	endNode := b.index.LookupNode(endHash)
	if endNode == nil {
		return nil, fmt.Errorf("no known block header with hash %v", endHash)
	}
	if !b.index.NodeStatus(endNode).KnownValid() {
		return nil, fmt.Errorf("block %v is not yet validated", endHash)
	}
	endHeight := endNode.height

	resultsLength := int(endHeight) / interval
	hashes := make([]chainhash.Hash, resultsLength)

	b.bestChain.mtx.Lock()
	defer b.bestChain.mtx.Unlock()

	blockNode := endNode
	for index := int(endHeight) / interval; index > 0; index-- {
		// Use the bestChain chainView for faster lookups once lookup intersects
		// the best chain.
		blockHeight := int32(index * interval)
		if b.bestChain.contains(blockNode) {
			blockNode = b.bestChain.nodeByHeight(blockHeight)
		} else {
			blockNode = blockNode.Ancestor(blockHeight)
		}

		hashes[index-1] = blockNode.hash
	}

	return hashes, nil
}

// locateInventory returns the node of the block after the first known block in
// the locator along with the number of subsequent nodes needed to either reach
// the provided stop hash or the provided max number of entries.
//
// In addition, there are two special cases:
//
//   - When no locators are provided, the stop hash is treated as a request for
//     that block, so it will either return the node associated with the stop hash
//     if it is known, or nil if it is unknown
//   - When locators are provided, but none of them are known, nodes starting
//     after the genesis block will be returned
//
// This is primarily a helper function for the locateBlocks and locateHeaders
// functions.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) locateInventory(locator BlockLocator, hashStop *chainhash.Hash, maxEntries uint32) (*blockNode, uint32) {
	// There are no block locators so a specific block is being requested
	// as identified by the stop hash.
	stopNode := b.index.LookupNode(hashStop) // from the hashStop node
	if len(locator) == 0 {
		if stopNode == nil {
			// No blocks with the stop hash were found so there is
			// nothing to do.
			return nil, 0
		}
		return stopNode, 1
	}

	// Find the most recent locator block hash in the main chain.  In the
	// case none of the hashes in the locator are in the main chain, fall
	// back to the genesis block.
	startNode := b.bestChain.Genesis() // default it is genesis block hash
	for _, hash := range locator {     // the for loop will find a block node in the best chain
		//	todo(ABE): if locator[0] does not have corresponging block in b.bestchain,
		//	todo(ABE): it implies that the peer who sent locator has a fork that is different from b.
		node := b.index.LookupNode(hash) // hash in the locator  will be check whether it is at bestchain
		if node != nil && b.bestChain.Contains(node) {
			startNode = node
			break
		}
	}

	// Start at the block after the most recently known block.  When there
	// is no next block it means the most recently known block is the tip of
	// the best chain, so there is nothing more to do.
	startNode = b.bestChain.Next(startNode) // next block node
	if startNode == nil {                   // if the start node is best block
		return nil, 0
	}

	// Calculate how many entries are needed.
	total := uint32((b.bestChain.Tip().height - startNode.height) + 1)
	if stopNode != nil && b.bestChain.Contains(stopNode) &&
		stopNode.height >= startNode.height {

		total = uint32((stopNode.height - startNode.height) + 1)
	}
	if total > maxEntries {
		total = maxEntries
	}

	return startNode, total
}

// locateBlocks returns the hashes of the blocks after the first known block in
// the locator until the provided stop hash is reached, or up to the provided
// max number of block hashes.
//
// See the comment on the exported function for more details on special cases.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) locateBlocks(locator BlockLocator, hashStop *chainhash.Hash, maxHashes uint32) ([]chainhash.Hash, []int32) {
	// Find the node after the first known block in the locator and the
	// total number of nodes after it needed while respecting the stop hash
	// and max entries.
	node, total := b.locateInventory(locator, hashStop, maxHashes)
	if total == 0 {
		return nil, nil
	}

	// Populate and return the found hashes.
	hashes := make([]chainhash.Hash, 0, total)
	heights := make([]int32, 0, total)
	for i := uint32(0); i < total; i++ {
		hashes = append(hashes, node.hash)
		heights = append(heights, node.height)
		node = b.bestChain.Next(node)
	}
	return hashes, heights
}

// LocateBlocks returns the hashes of the blocks after the first known block in
// the locator until the provided stop hash is reached, or up to the provided
// max number of block hashes.
//
// In addition, there are two special cases:
//
//   - When no locators are provided, the stop hash is treated as a request for
//     that block, so it will either return the stop hash itself if it is known,
//     or nil if it is unknown
//   - When locators are provided, but none of them are known, hashes starting
//     after the genesis block will be returned
//
// This function is safe for concurrent access.
func (b *BlockChain) LocateBlocks(locator BlockLocator, hashStop *chainhash.Hash, maxHashes uint32) ([]chainhash.Hash, []int32) {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	hashes, heights := b.locateBlocks(locator, hashStop, maxHashes)
	return hashes, heights
}

// locateHeaders returns the headers of the blocks after the first known block
// in the locator until the provided stop hash is reached, or up to the provided
// max number of block headers.
//
// See the comment on the exported function for more details on special cases.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) locateHeaders(locator BlockLocator, hashStop *chainhash.Hash, maxHeaders uint32) []wire.BlockHeader {
	// Find the node after the first known block in the locator and the
	// total number of nodes after it needed while respecting the stop hash
	// and max entries.
	node, total := b.locateInventory(locator, hashStop, maxHeaders)
	if total == 0 {
		return nil
	}

	// Populate and return the found headers.
	headers := make([]wire.BlockHeader, 0, total)
	for i := uint32(0); i < total; i++ {
		headers = append(headers, node.Header())
		node = b.bestChain.Next(node)
	}
	return headers
}

// LocateHeaders returns the headers of the blocks after the first known block
// in the locator until the provided stop hash is reached, or up to a max of
// wire.MaxBlockHeadersPerMsg headers.
//
// In addition, there are two special cases:
//
//   - When no locators are provided, the stop hash is treated as a request for
//     that header, so it will either return the header for the stop hash itself
//     if it is known, or nil if it is unknown
//   - When locators are provided, but none of them are known, headers starting
//     after the genesis block will be returned
//
// This function is safe for concurrent access.
func (b *BlockChain) LocateHeaders(locator BlockLocator, hashStop *chainhash.Hash) []wire.BlockHeader {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	headers := b.locateHeaders(locator, hashStop, wire.MaxBlockHeadersPerMsg)
	return headers
}

// IndexManager provides a generic interface that the is called when blocks are
// connected and disconnected to and from the tip of the main chain for the
// purpose of supporting optional indexes.
type IndexManager interface {
	// Init is invoked during chain initialize in order to allow the index
	// manager to initialize itself and any indexes it is managing.  The
	// channel parameter specifies a channel the caller can close to signal
	// that the process should be interrupted.  It can be nil if that
	// behavior is not desired.
	Init(*BlockChain, <-chan struct{}) error

	// ConnectBlock is invoked when a new block has been connected to the
	// main chain. The set of output spent within a block is also passed in
	// so indexers can access the previous output scripts input spent if
	// required.
	ConnectBlock(database.Tx, *abeutil.Block, []SpentTxOut) error
	ConnectBlockAbe(database.Tx, *abeutil.BlockAbe, []*SpentTxOutAbe) error

	// DisconnectBlock is invoked when a block has been disconnected from
	// the main chain. The set of outputs scripts that were spent within
	// this block is also returned so indexers can clean up the prior index
	// state for this block.
	DisconnectBlock(database.Tx, *abeutil.Block, []SpentTxOut) error
	DisconnectBlockAbe(database.Tx, *abeutil.BlockAbe, []*SpentTxOutAbe) error
}

// Config is a descriptor which specifies the blockchain instance configuration.
type Config struct {
	// DB defines the database which houses the blocks and will be used to
	// store all metadata created by this package such as the utxo set.
	//
	// This field is required.
	DB database.DB

	// Interrupt specifies a channel the caller can close to signal that
	// long running operations, such as catching up indexes or performing
	// database migrations, should be interrupted.
	//
	// This field can be nil if the caller does not desire the behavior.
	Interrupt <-chan struct{}

	// ChainParams identifies which chain parameters the chain is associated
	// with.
	//
	// This field is required.
	ChainParams *chaincfg.Params

	// Checkpoints hold caller-defined checkpoints that should be added to
	// the default checkpoints in ChainParams.  Checkpoints must be sorted
	// by height.
	//
	// This field can be nil if the caller does not wish to specify any
	// checkpoints.
	Checkpoints []chaincfg.Checkpoint

	// FakePowHeightScopes hold caller-defined fake pow height scope that should be added to
	// ChainParams and database.
	//
	// This field can be nil if the caller does not wish to specify any
	// fake pow height scope.
	FakePowHeightScopes []BlockHeightScope

	// TimeSource defines the median time source to use for things such as
	// block processing and determining whether or not the chain is current.
	//
	// The caller is expected to keep a reference to the time source as well
	// and add time samples from other peers on the network so the local
	// time is adjusted to be in agreement with other peers.
	TimeSource MedianTimeSource

	// SigCache defines a signature cache to use when when validating
	// signatures.  This is typically most useful when individual
	// transactions are already being validated prior to their inclusion in
	// a block such as what is usually done via a transaction memory pool.
	//
	// This field can be nil if the caller is not interested in using a
	// signature cache.
	SigCache *txscript.SigCache

	// IndexManager defines an index manager to use when initializing the
	// chain and connecting and disconnecting blocks.
	//
	// This field can be nil if the caller does not wish to make use of an
	// index manager.
	IndexManager IndexManager

	// HashCache defines a transaction hash mid-state cache to use when
	// validating transactions. This cache has the potential to greatly
	// speed up transaction validation as re-using the pre-calculated
	// mid-state eliminates the O(N^2) validation complexity due to the
	// SigHashAll flag.
	//
	// This field can be nil if the caller is not interested in using a
	// signature cache.
	HashCache *txscript.HashCache

	// WitnessCache defines a transaction witness cache to store the already
	// validated transactions to speed up block verification.
	WitnessCache *txscript.WitnessCache

	NodeType wire.NodeType
}

// New returns a BlockChain instance using the provided configuration details.
func New(config *Config) (*BlockChain, error) {
	// Enforce required config fields.
	if config.DB == nil {
		return nil, AssertError("blockchain.New database is nil")
	}
	if config.ChainParams == nil {
		return nil, AssertError("blockchain.New chain parameters nil")
	}
	if config.TimeSource == nil {
		return nil, AssertError("blockchain.New timesource is nil")
	}

	// Generate a checkpoint by height map from the provided checkpoints
	// and assert the provided checkpoints are sorted by height as required.
	var checkpointsByHeight map[int32]*chaincfg.Checkpoint
	var prevCheckpointHeight int32
	if len(config.Checkpoints) > 0 {
		checkpointsByHeight = make(map[int32]*chaincfg.Checkpoint)
		for i := range config.Checkpoints {
			checkpoint := &config.Checkpoints[i]
			if checkpoint.Height <= prevCheckpointHeight {
				return nil, AssertError("blockchain.New " +
					"checkpoints are not sorted by height")
			}

			checkpointsByHeight[checkpoint.Height] = checkpoint
			prevCheckpointHeight = checkpoint.Height
		}
	}

	params := config.ChainParams
	targetTimespan := int64(params.TargetTimespan / time.Second)
	targetTimePerBlock := int64(params.TargetTimePerBlock / time.Second)

	// Added by Alice, 2024.05.11, for DSA
	// todo(DSA): review
	targetTimespanDSA := int64(params.TargetTimespanDSA / time.Second)
	targetTimePerBlockDSA := int64(params.TargetTimePerBlockDSA / time.Second)

	adjustmentFactor := params.RetargetAdjustmentFactor
	b := BlockChain{
		nodeType:            config.NodeType,
		checkpoints:         config.Checkpoints,
		checkpointsByHeight: checkpointsByHeight,
		fakePoWHeightScopes: config.FakePowHeightScopes,
		db:                  config.DB,
		chainParams:         params,
		timeSource:          config.TimeSource,
		sigCache:            config.SigCache,
		witnessCache:        config.WitnessCache,
		indexManager:        config.IndexManager,
		minRetargetTimespan: targetTimespan / adjustmentFactor,
		maxRetargetTimespan: targetTimespan * adjustmentFactor,
		blocksPerRetarget:   int32(targetTimespan / targetTimePerBlock),
		// Added by Alice, 2024.05.11, for DSA
		// todo(DSA): review
		minRetargetTimespanDSA: targetTimespanDSA / adjustmentFactor,
		maxRetargetTimespanDSA: targetTimespanDSA * adjustmentFactor,
		blocksPerRetargetDSA:   int32(targetTimespanDSA / targetTimePerBlockDSA),
		index:                  newBlockIndex(config.DB, params),
		hashCache:              config.HashCache,
		bestChain:              newChainView(nil),
		orphansBTCD:            make(map[chainhash.Hash]*orphanBlock),
		orphansAbe:             make(map[chainhash.Hash]*orphanBlockAbe),
		prevOrphans:            make(map[chainhash.Hash][]*orphanBlock),
		prevOrphansAbe:         make(map[chainhash.Hash][]*orphanBlockAbe),
		warningCaches:          newThresholdCaches(vbNumBits),
		deploymentCaches:       newThresholdCaches(chaincfg.DefinedDeployments),
	}

	// Initialize the chain state from the passed database.  When the db
	// does not yet contain any chain state, both it and the chain state
	// will be initialized to contain only the genesis block.
	if err := b.initChainState(); err != nil {
		return nil, err
	}

	if len(b.fakePoWHeightScopes) != 0 {
		heightRanges := make([]string, len(b.fakePoWHeightScopes))
		for i := 0; i < len(b.fakePoWHeightScopes); i++ {
			heightRanges[i] = fmt.Sprintf("[%d,%d]",
				b.fakePoWHeightScopes[i].StartHeight, b.fakePoWHeightScopes[i].EndHeight)
		}
		log.Infof("block in following height range %s would skip pow check", strings.Join(heightRanges, " "))
	}

	// Perform any upgrades to the various chain-specific buckets as needed.
	if err := b.maybeUpgradeDbBuckets(config.Interrupt); err != nil {
		return nil, err
	}

	// Initialize and catch up all of the currently active optional indexes
	// as needed.
	if config.IndexManager != nil {
		err := config.IndexManager.Init(&b, config.Interrupt)
		if err != nil {
			return nil, err
		}
	}

	// Initialize rule change threshold state caches.
	if err := b.initThresholdCaches(); err != nil {
		return nil, err
	}

	bestNode := b.bestChain.Tip()
	log.Infof("Chain state (height %d, hash %v, totaltx %d, work %v)",
		bestNode.height, bestNode.hash, b.stateSnapshot.TotalTxns,
		bestNode.workSum)

	return &b, nil
}

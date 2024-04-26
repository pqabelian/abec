package syncmgr

import (
	"container/list"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/consensus/ethash"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/mempool"
	peerpkg "github.com/abesuite/abec/peer"
	"github.com/abesuite/abec/wire"
)

const (
	// minInFlightBlocks is the minimum number of blocks that should be
	// in the request queue for headers-first mode before requesting
	// more.
	minInFlightBlocks = 10

	// maxRejectedTxns is the maximum number of rejected transactions
	// hashes to store in memory.
	maxRejectedTxns = 1000

	// maxRequestedBlocks is the maximum number of requested block
	// hashes to store in memory.
	maxRequestedBlocks = wire.MaxInvPerMsg

	// maxRequestedTxns is the maximum number of requested transactions
	// hashes to store in memory.
	maxRequestedTxns = wire.MaxInvPerMsg

	// maxStallDuration is the time after which we will disconnect our
	// current sync peer if we haven't made progress.
	maxStallDuration = 3 * time.Minute

	// stallSampleInterval the interval at which we will check to see if our
	// sync has stalled.
	stallSampleInterval = 30 * time.Second
)

// zeroHash is the zero value hash (all zeros).  It is defined as a convenience.
var zeroHash chainhash.Hash

// newPeerMsg signifies a newly connected peer to the block handler.
type newPeerMsg struct {
	peer *peerpkg.Peer
}

// blockMsgAbe packages a block message and the peer it came from together
// so the block handler has access to that information.
type blockMsgAbe struct {
	block *abeutil.BlockAbe
	peer  *peerpkg.Peer
	reply chan struct{}
}

type prunedBlockMsg struct {
	block *abeutil.PrunedBlock
	peer  *peerpkg.Peer
	reply chan struct{}
}

type needSetMsg struct {
	needset *abeutil.NeedSet
	peer    *peerpkg.Peer
}

type needSetResultMsg struct {
	result *abeutil.NeedSetResult
	peer   *peerpkg.Peer
	reply  chan struct{}
}

// invMsg packages an inv message and the peer it came from together
// so the block handler has access to that information.
type invMsg struct {
	inv  *wire.MsgInv
	peer *peerpkg.Peer
}

// headersMsg packages a headers message and the peer it came from
// together so the block handler has access to that information.
type headersMsg struct {
	headers *wire.MsgHeaders
	peer    *peerpkg.Peer
}

// notFoundMsg packages a bitcoin notfound message and the peer it came from
// together so the block handler has access to that information.
type notFoundMsg struct {
	notFound *wire.MsgNotFound
	peer     *peerpkg.Peer
}

// donePeerMsg signifies a newly disconnected peer to the block handler.
type donePeerMsg struct {
	peer *peerpkg.Peer
}

// txMsgAbe packages a tx message and the peer it came from together
// so the block handler has access to that information.
type txMsgAbe struct {
	tx    *abeutil.TxAbe
	peer  *peerpkg.Peer
	reply chan struct{}
}

// getSyncPeerMsg is a message type to be sent across the message channel for
// retrieving the current sync peer.
type getSyncPeerMsg struct {
	reply chan int32
}

// processBlockResponse is a response sent to the reply channel of a
// processBlockMsg.
type processBlockResponse struct {
	isOrphan bool
	err      error
}

// processBlockMsgAbe is a message type to be sent across the message channel
// for requested a block is processed.  Note this call differs from blockMsg
// above in that blockMsg is intended for blocks that came from peers and have
// extra handling whereas this message essentially is just a concurrent safe
// way to call ProcessBlock on the internal block chain instance.
type processBlockMsgAbe struct {
	block *abeutil.BlockAbe
	flags blockchain.BehaviorFlags
	reply chan processBlockResponse
}

// isCurrentMsg is a message type to be sent across the message channel for
// requesting whether or not the sync manager believes it is synced with the
// currently connected peers.
type isCurrentMsg struct {
	reply chan bool
}

// pauseMsg is a message type to be sent across the message channel for
// pausing the sync manager.  This effectively provides the caller with
// exclusive access over the manager until a receive is performed on the
// unpause channel.
type pauseMsg struct {
	unpause <-chan struct{}
}

// headerNode is used as a node in a list of headers that are linked together
// between checkpoints.
type headerNode struct {
	height int32
	hash   *chainhash.Hash
}

// peerSyncState stores additional information that the SyncManager tracks
// about a peer.
type peerSyncState struct {
	syncCandidate    bool
	requestQueue     []*wire.InvVect
	requestedTxns    map[chainhash.Hash]struct{}
	requestedBlocks  map[chainhash.Hash]struct{}
	requestedNeedSet map[chainhash.Hash]struct{}
}

func (p peerSyncState) ExistRequestedNeedSet(blockHash chainhash.Hash) bool {
	_, ok := p.requestedNeedSet[blockHash]
	return ok
}
func (p peerSyncState) RemoveRequestedNeedSet(blockHash chainhash.Hash) {
	delete(p.requestedNeedSet, blockHash)
}

// limitAdd is a helper function for maps that require a maximum limit by
// evicting a random value if adding the new value would cause it to
// overflow the maximum allowed.
func limitAdd(m map[chainhash.Hash]struct{}, hash chainhash.Hash, limit int) {
	if len(m)+1 > limit {
		// Remove a random entry from the map.  For most compilers, Go's
		// range statement iterates starting at a random item although
		// that is not 100% guaranteed by the spec.  The iteration order
		// is not important here because an adversary would have to be
		// able to pull off preimage attacks on the hashing function in
		// order to target eviction of specific entries anyways.
		for txHash := range m {
			delete(m, txHash)
			break
		}
	}
	m[hash] = struct{}{}
}

// SyncManager is used to communicate block related messages with peers. The
// SyncManager is started as by executing Start() in a goroutine. Once started,
// it selects peers to sync from and starts the initial block download. Once the
// chain is in sync, the SyncManager handles incoming block and header
// notifications and relays announcements of new blocks to peers.
type SyncManager struct {
	nodeType       wire.NodeType
	peerNotifier   PeerNotifier
	started        int32
	shutdown       int32
	chain          *blockchain.BlockChain
	ethash         *ethash.Ethash // todo: (ethmining)
	txMemPool      *mempool.TxPool
	chainParams    *chaincfg.Params
	progressLogger *blockProgressLogger
	msgChan        chan interface{}
	wg             sync.WaitGroup
	quit           chan struct{}

	// These fields should only be accessed from the blockHandler thread
	rejectedTxns     map[chainhash.Hash]struct{}
	requestedTxns    map[chainhash.Hash]struct{}
	requestedBlocks  map[chainhash.Hash]struct{}
	syncPeer         *peerpkg.Peer
	peerStates       map[*peerpkg.Peer]*peerSyncState
	lastProgressTime time.Time

	// The following fields are used for headers-first mode.
	headersFirstMode bool
	headerList       *list.List
	startHeader      *list.Element
	nextCheckpoint   *chaincfg.Checkpoint

	// An optional fee estimator.
	feeEstimator *mempool.FeeEstimator
}

func (sm *SyncManager) ExistRequestedNeedSetInPeerStates(p *peerpkg.Peer, blockHash chainhash.Hash) (bool, bool) {
	state, exist := sm.peerStates[p]
	if !exist {
		return false, false
	}
	_, ok := state.requestedNeedSet[blockHash]
	return true, ok
}

func (sm *SyncManager) RemoveRequestedNeedSetInPeerStates(p *peerpkg.Peer, blockHash chainhash.Hash) {
	if _, exist := sm.peerStates[p]; exist {
		delete(sm.peerStates[p].requestedNeedSet, blockHash)
	}
	return
}

// resetHeaderState sets the headers-first mode state to values appropriate for
// syncing from a new peer.
func (sm *SyncManager) resetHeaderState(newestHash *chainhash.Hash, newestHeight int32) {
	sm.headersFirstMode = false
	sm.headerList.Init()
	sm.startHeader = nil

	// When there is a next checkpoint, add an entry for the latest known
	// block into the header pool.  This allows the next downloaded header
	// to prove it links to the chain properly.
	if sm.nextCheckpoint != nil {
		node := headerNode{height: newestHeight, hash: newestHash}
		sm.headerList.PushBack(&node)
	}
}

// findNextHeaderCheckpoint returns the next checkpoint after the passed height.
// It returns nil when there is not one either because the height is already
// later than the final checkpoint or some other reason such as disabled
// checkpoints.
func (sm *SyncManager) findNextHeaderCheckpoint(height int32) *chaincfg.Checkpoint {
	checkpoints := sm.chain.Checkpoints()
	if len(checkpoints) == 0 {
		return nil
	}

	// There is no next checkpoint if the height is already after the final
	// checkpoint.
	finalCheckpoint := &checkpoints[len(checkpoints)-1]
	if height >= finalCheckpoint.Height {
		return nil
	}

	// Find the next checkpoint.
	nextCheckpoint := finalCheckpoint
	for i := len(checkpoints) - 2; i >= 0; i-- {
		if height >= checkpoints[i].Height {
			break
		}
		nextCheckpoint = &checkpoints[i]
	}
	return nextCheckpoint
}

// WitnessNeeded report whether block witness is needed in sync process
// For full node, any time it request a block, witness is needed
// For other type node, any witness in block after last checkpoint is needed
func (sm *SyncManager) WitnessNeeded() bool {
	if sm.nodeType.IsFullNode() {
		return true
	}

	if sm.nextCheckpoint == nil {
		return true
	}

	return false
}

func (sm *SyncManager) MaybeSyncPeer(p *peerpkg.Peer) bool {
	// If peer is a full node.
	if p.IsFullNode() {
		return true
	}

	bestSnapShot := sm.chain.BestSnapshot()
	currentHeight := bestSnapShot.Height

	if p.LastBlock() < currentHeight {
		log.Debugf("peer %v height %v is lower than our height %v, skipping", p, p.LastBlock(), currentHeight)
		return false
	}

	witnessNeeded := sm.WitnessNeeded()

	if !witnessNeeded {
		return true
	}

	if !p.IsWitnessEnabled() {
		log.Debugf("peer %v not witness enabled, skipping", p)
		return false
	}

	if p.WitnessServiceHeight() <= uint32(currentHeight) {
		return true
	}

	return false
}

// startSync will choose the best peer among the available candidate peers to
// download/sync the blockchain from.  When syncing is already running, it
// simply returns.  It also examines the candidates for any which are no longer
// candidates and removes them as needed.
func (sm *SyncManager) startSync() {
	// Return now if we're already syncing.
	if sm.syncPeer != nil {
		return
	}

	best := sm.chain.BestSnapshot()
	var higherPeers, equalPeers []*peerpkg.Peer
	for peer, state := range sm.peerStates {
		if !state.syncCandidate {
			continue
		}

		// Remove sync candidate peers that are no longer candidates due
		// to passing their latest known block.  NOTE: The < is
		// intentional as opposed to <=.  While technically the peer
		// doesn't have a later block when it's equal, it will likely
		// have one soon so it is a reasonable choice.  It also allows
		// the case where both are at 0 such as during regression test.
		if peer.LastBlock() < best.Height {
			state.syncCandidate = false
			continue
		}

		if !sm.MaybeSyncPeer(peer) {
			continue
		}

		// If the peer is at the same height as us, we'll add it a set
		// of backup peers in case we do not find one with a higher
		// height. If we are synced up with all of our peers, all of
		// them will be in this set.
		if peer.LastBlock() == best.Height {
			equalPeers = append(equalPeers, peer)
			continue
		}

		// This peer has a height greater than our own, we'll consider
		// it in the set of better peers from which we'll randomly
		// select.
		higherPeers = append(higherPeers, peer)
	}

	// Pick randomly from the set of peers greater than our block height,
	// falling back to a random peer of the same height if none are greater.
	//
	// TODO(conner): Use a better algorithm to ranking peers based on
	// observed metrics and/or sync in parallel.
	var bestPeer *peerpkg.Peer
	switch {
	case len(higherPeers) > 0:
		bestPeer = higherPeers[rand.Intn(len(higherPeers))]

	case len(equalPeers) > 0:
		bestPeer = equalPeers[rand.Intn(len(equalPeers))]
	}

	// Start syncing from the best peer if one was selected.
	if bestPeer != nil {
		// Clear the requestedBlocks if the sync peer changes, otherwise
		// we may ignore blocks we need that the last sync peer failed
		// to send.
		sm.requestedBlocks = make(map[chainhash.Hash]struct{})

		locator, err := sm.chain.LatestBlockLocator()
		//	todo(ABE): the locator contains the block hashes for this node
		if err != nil {
			log.Errorf("Failed to get block locator for the "+
				"latest block: %v", err)
			return
		}

		log.Infof("Syncing to block height %d from peer %v",
			bestPeer.LastBlock(), bestPeer.Addr())

		// When the current height is less than a known checkpoint we
		// can use block headers to learn about which blocks comprise
		// the chain up to the checkpoint and perform less validation
		// for them.  This is possible since each header contains the
		// hash of the previous header and a merkle root.  Therefore if
		// we validate all of the received headers link together
		// properly and the checkpoint hashes match, we can be sure the
		// hashes for the blocks in between are accurate.  Further, once
		// the full blocks are downloaded, the merkle root is computed
		// and compared against the value in the header which proves the
		// full block hasn't been tampered with.
		//
		// Once we have passed the final checkpoint, or checkpoints are
		// disabled, use standard inv messages learn about the blocks
		// and fully validate them.  Finally, regression test mode does
		// not support the headers-first approach so do normal block
		// downloads when in regression test mode.
		if sm.nextCheckpoint != nil &&
			best.Height < sm.nextCheckpoint.Height &&
			sm.chainParams != &chaincfg.RegressionNetParams {

			bestPeer.PushGetHeadersMsg(locator, sm.nextCheckpoint.Hash)
			sm.headersFirstMode = true
			log.Infof("Downloading headers for blocks %d to "+
				"%d from peer %s", best.Height+1,
				sm.nextCheckpoint.Height, bestPeer.Addr())
		} else {
			bestPeer.PushGetBlocksMsg(locator, &zeroHash)
		}
		sm.syncPeer = bestPeer

		// Reset the last progress time now that we have a non-nil
		// syncPeer to avoid instantly detecting it as stalled in the
		// event the progress time hasn't been updated recently.
		sm.lastProgressTime = time.Now()
	} else {
		log.Warnf("No sync peer candidates available")
	}
}

// isSyncCandidate returns whether or not the peer is a candidate to consider
// syncing from.
func (sm *SyncManager) isSyncCandidate(peer *peerpkg.Peer) bool {
	// Typically a peer is not a candidate for sync if it's not a full node,
	// however regression test is special in that the regression tool is
	// not a full node and still needs to be considered a sync candidate.
	if sm.chainParams == &chaincfg.RegressionNetParams {
		// The peer is not a candidate if it's not coming from localhost
		// or the hostname can't be determined for some reason.
		host, _, err := net.SplitHostPort(peer.Addr())
		if err != nil {
			return false
		}

		if host != "127.0.0.1" && host != "localhost" {
			return false
		}
	} else {
		// The peer is not a candidate for sync if it's not a full
		// node.
		//  todo (abe): the condition may change after we modify the service flag
		//// the full node would fetch all witness, so the candidate must be a full node
		//if sm.nodeType == wire.FullNode && !peer.IsFullNode() {
		//	return false
		//}
		//// the semi-full node/normal node can sync with a full node or a semi-full node
		//if sm.nodeType != wire.FullNode && sm.WitnessNeeded() && !peer.IsNormalNode() {
		//	return false
		//}
		nodeServices := peer.Services()
		if nodeServices&wire.SFNodeNetwork != wire.SFNodeNetwork || !peer.IsWitnessEnabled() {
			return false
		}
	}

	// Candidate if all checks passed.
	return true
}

// handleNewPeerMsg deals with new peers that have signalled they may
// be considered as a sync peer (they have already successfully negotiated).  It
// also starts syncing if needed.  It is invoked from the syncHandler goroutine.
func (sm *SyncManager) handleNewPeerMsg(peer *peerpkg.Peer) {
	// Ignore if in the process of shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return
	}

	log.Infof("New valid peer %s (%s) with height %d", peer, peer.UserAgent(), peer.StartingHeight())

	// Initialize the peer state
	isSyncCandidate := sm.isSyncCandidate(peer)
	sm.peerStates[peer] = &peerSyncState{
		syncCandidate:    isSyncCandidate,
		requestedTxns:    make(map[chainhash.Hash]struct{}),
		requestedBlocks:  make(map[chainhash.Hash]struct{}),
		requestedNeedSet: make(map[chainhash.Hash]struct{}),
	}

	// Start syncing by choosing the best candidate if needed.
	if isSyncCandidate && sm.syncPeer == nil {
		sm.startSync()
	}
}

// handleStallSample will switch to a new sync peer if the current one has
// stalled. This is detected when by comparing the last progress timestamp with
// the current time, and disconnecting the peer if we stalled before reaching
// their highest advertised block.
func (sm *SyncManager) handleStallSample() {
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return
	}

	// If we don't have an active sync peer, exit early.
	if sm.syncPeer == nil {
		return
	}

	// If the stall timeout has not elapsed, exit early.
	if time.Since(sm.lastProgressTime) <= maxStallDuration {
		return
	}

	// Check to see that the peer's sync state exists.
	state, exists := sm.peerStates[sm.syncPeer]
	if !exists {
		return
	}

	sm.clearRequestedState(state)

	disconnectSyncPeer := sm.shouldDCStalledSyncPeer()
	sm.updateSyncPeer(disconnectSyncPeer)
}

// shouldDCStalledSyncPeer determines whether or not we should disconnect a
// stalled sync peer. If the peer has stalled and its reported height is greater
// than our own best height, we will disconnect it. Otherwise, we will keep the
// peer connected in case we are already at tip.
func (sm *SyncManager) shouldDCStalledSyncPeer() bool {
	lastBlock := sm.syncPeer.LastBlock()
	startHeight := sm.syncPeer.StartingHeight()

	var peerHeight int32
	if lastBlock > startHeight {
		peerHeight = lastBlock
	} else {
		peerHeight = startHeight
	}

	// If we've stalled out yet the sync peer reports having more blocks for
	// us we will disconnect them. This allows us at tip to not disconnect
	// peers when we are equal or they temporarily lag behind us.
	best := sm.chain.BestSnapshot()
	return peerHeight > best.Height
}

// handleDonePeerMsg deals with peers that have signalled they are done.  It
// removes the peer as a candidate for syncing and in the case where it was
// the current sync peer, attempts to select a new best peer to sync from.  It
// is invoked from the syncHandler goroutine.
func (sm *SyncManager) handleDonePeerMsg(peer *peerpkg.Peer) {
	state, exists := sm.peerStates[peer]
	if !exists {
		log.Warnf("Received done peer message for unknown peer %s", peer)
		return
	}

	// Remove the peer from the list of candidate peers.
	delete(sm.peerStates, peer)

	log.Infof("Lost peer %s", peer)

	sm.clearRequestedState(state)

	if peer == sm.syncPeer {
		// Update the sync peer. The server has already disconnected the
		// peer before signaling to the sync manager.
		sm.updateSyncPeer(false)
	}
}

// clearRequestedState wipes all expected transactions and blocks from the sync
// manager's requested maps that were requested under a peer's sync state, This
// allows them to be rerequested by a subsequent sync peer.
func (sm *SyncManager) clearRequestedState(state *peerSyncState) {
	// Remove requested transactions from the global map so that they will
	// be fetched from elsewhere next time we get an inv.
	for txHash := range state.requestedTxns {
		delete(sm.requestedTxns, txHash)
	}

	// Remove requested blocks from the global map so that they will be
	// fetched from elsewhere next time we get an inv.
	// TODO: we could possibly here check which peers have these blocks
	// and request them now to speed things up a little.
	for blockHash := range state.requestedBlocks {
		delete(sm.requestedBlocks, blockHash)
	}
}

// updateSyncPeer choose a new sync peer to replace the current one. If
// dcSyncPeer is true, this method will also disconnect the current sync peer.
// If we are in header first mode, any header state related to prefetching is
// also reset in preparation for the next sync peer.
func (sm *SyncManager) updateSyncPeer(dcSyncPeer bool) {
	log.Debugf("Updating sync peer, no progress for: %v",
		time.Since(sm.lastProgressTime))

	// First, disconnect the current sync peer if requested.
	if dcSyncPeer {
		sm.syncPeer.Disconnect()
	}

	// Reset any header state before we choose our next active sync peer.
	if sm.headersFirstMode {
		best := sm.chain.BestSnapshot()
		sm.resetHeaderState(&best.Hash, best.Height)
	}

	sm.syncPeer = nil
	sm.startSync()
}

// handleTxMsgAbe handles transaction messages from all peers.
func (sm *SyncManager) handleTxMsgAbe(tmsg *txMsgAbe) {
	peer := tmsg.peer
	state, exists := sm.peerStates[peer]
	if !exists {
		log.Warnf("Received tx message from unknown peer %s", peer)
		return
	}

	// log.Debugf("Receive tx message whose hash is %s from peer %s", tmsg.tx.MsgTx().TxHash().String(), peer)

	// NOTE:  BitcoinJ, and possibly other wallets, don't follow the spec of
	// sending an inventory message and allowing the remote peer to decide
	// whether or not they want to request the transaction via a getdata
	// message.  Unfortunately, the reference implementation permits
	// unrequested data, so it has allowed wallets that don't follow the
	// spec to proliferate.  While this is not ideal, there is no check here
	// to disconnect peers for sending unsolicited transactions to provide
	// interoperability.
	txHash := tmsg.tx.Hash()

	// Ignore transactions that we have already rejected.  Do not
	// send a reject message here because if the transaction was already
	// rejected, the transaction was unsolicited.
	if _, exists = sm.rejectedTxns[*txHash]; exists {
		log.Debugf("Ignoring unsolicited previously rejected "+
			"transaction %v from %s", txHash, peer)
		return
	}

	// Process the transaction to include validation, insertion in the
	// memory pool, orphan handling, etc.
	acceptedTx, err := sm.txMemPool.ProcessTransactionAbe(tmsg.tx,
		true, true, mempool.Tag(peer.ID()), false)

	// Remove transaction from request maps. Either the mempool/chain
	// already knows about it and as such we shouldn't have any more
	// instances of trying to fetch it, or we failed to insert and thus
	// we'll retry next time we get an inv.
	delete(state.requestedTxns, *txHash)
	delete(sm.requestedTxns, *txHash)

	if err != nil {
		// Do not request this transaction again until a new block
		// has been processed.
		//sm.rejectedTxns[*txHash] = struct{}{}
		//sm.limitMap(sm.rejectedTxns, maxRejectedTxns)
		limitAdd(sm.rejectedTxns, *txHash, maxRejectedTxns)

		// When the error is a rule error, it means the transaction was
		// simply rejected as opposed to something actually going wrong,
		// so log it as such.  Otherwise, something really did go wrong,
		// so log it as an actual error.
		if _, ok := err.(mempool.RuleError); ok {
			log.Debugf("Rejected transaction %v from %s: %v",
				txHash, peer, err)
		} else {
			log.Errorf("Failed to process transaction %v: %v",
				txHash, err)
		}

		// Convert the error into an appropriate reject message and
		// send it.
		code, reason := mempool.ErrToRejectErr(err)
		peer.PushRejectMsg(wire.CmdTx, code, reason, txHash, false)
		return
	}

	//	todo(ABE):
	if acceptedTx == nil {
		return
	}
	acceptedTxs := make([]*mempool.TxDescAbe, 1)
	acceptedTxs[0] = acceptedTx
	sm.peerNotifier.AnnounceNewTransactions(acceptedTxs)
	log.Debugf("Accepted tx %s at height %v", acceptedTx.Tx.Hash().String(), acceptedTx.Height)
}

// current returns true if we believe we are synced with our peers, false if we
// still have blocks to check
func (sm *SyncManager) current() bool {
	if !sm.chain.IsCurrent() {
		return false
	}

	// if blockChain thinks we are current and we have no syncPeer it
	// is probably right.
	if sm.syncPeer == nil {
		return true
	}

	// No matter what chain thinks, if we are below the block we are syncing
	// to we are not current.
	if sm.chain.BestSnapshot().Height < sm.syncPeer.LastBlock() {
		return false
	}
	return true
}

//	todo(ABE): Remove BTCD
//// handleBlockMsg handles block messages from all peers.
//func (sm *SyncManager) handleBlockMsgBTCD(bmsg *blockMsg) {
//	peer := bmsg.peer
//	state, exists := sm.peerStates[peer]
//	if !exists {
//		log.Warnf("Received block message from unknown peer %s", peer)
//		return
//	}
//
//	// If we didn't ask for this block then the peer is misbehaving.
//	blockHash := bmsg.block.Hash()
//	if _, exists = state.requestedBlocks[*blockHash]; !exists {
//		// The regression test intentionally sends some blocks twice
//		// to test duplicate block insertion fails.  Don't disconnect
//		// the peer or ignore the block when we're in regression test
//		// mode in this case so the chain code is actually fed the
//		// duplicate blocks.
//		if sm.chainParams != &chaincfg.RegressionNetParams {
//			log.Warnf("Got unrequested block %v from %s -- "+
//				"disconnecting", blockHash, peer.Addr())
//			peer.Disconnect()
//			return
//		}
//	}
//
//	// When in headers-first mode, if the block matches the hash of the
//	// first header in the list of headers that are being fetched, it's
//	// eligible for less validation since the headers have already been
//	// verified to link together and are valid up to the next checkpoint.
//	// Also, remove the list entry for all blocks except the checkpoint
//	// since it is needed to verify the next round of headers links
//	// properly.
//	isCheckpointBlock := false
//	behaviorFlags := blockchain.BFNone
//	if sm.headersFirstMode {
//		firstNodeEl := sm.headerList.Front()
//		if firstNodeEl != nil {
//			firstNode := firstNodeEl.Value.(*headerNode)
//			if blockHash.IsEqual(firstNode.hash) {
//				//	todo(ABE): for headersFirstMode, the flag behaviorFlags is set to blockchain.BFFastAdd, which implies less validation
//				behaviorFlags |= blockchain.BFFastAdd
//				if firstNode.hash.IsEqual(sm.nextCheckpoint.Hash) {
//					isCheckpointBlock = true
//				} else {
//					sm.headerList.Remove(firstNodeEl)
//				}
//			}
//		}
//	}
//
//	// Remove block from request maps. Either chain will know about it and
//	// so we shouldn't have any more instances of trying to fetch it, or we
//	// will fail the insert and thus we'll retry next time we get an inv.
//	delete(state.requestedBlocks, *blockHash)
//	delete(sm.requestedBlocks, *blockHash)
//
//	// Process the block to include validation, best chain selection, orphan
//	// handling, etc.
//	_, isOrphan, err := sm.chain.ProcessBlockBTCD(bmsg.block, behaviorFlags)
//	if err != nil {
//		// When the error is a rule error, it means the block was simply
//		// rejected as opposed to something actually going wrong, so log
//		// it as such.  Otherwise, something really did go wrong, so log
//		// it as an actual error.
//		if _, ok := err.(blockchain.RuleError); ok {
//			log.Infof("Rejected block %v from %s: %v", blockHash,
//				peer, err)
//		} else {
//			log.Errorf("Failed to process block %v: %v",
//				blockHash, err)
//		}
//		if dbErr, ok := err.(database.Error); ok && dbErr.ErrorCode ==
//			database.ErrCorruption {
//			panic(dbErr)
//		}
//
//		// Convert the error into an appropriate reject message and
//		// send it.
//		code, reason := mempool.ErrToRejectErr(err)
//		peer.PushRejectMsg(wire.CmdBlock, code, reason, blockHash, false)
//		return
//	}
//
//	// Meta-data about the new block this peer is reporting. We use this
//	// below to update this peer's latest block height and the heights of
//	// other peers based on their last announced block hash. This allows us
//	// to dynamically update the block heights of peers, avoiding stale
//	// heights when looking for a new sync peer. Upon acceptance of a block
//	// or recognition of an orphan, we also use this information to update
//	// the block heights over other peers who's invs may have been ignored
//	// if we are actively syncing while the chain is not yet current or
//	// who may have lost the lock announcement race.
//	var heightUpdate int32
//	var blkHashUpdate *chainhash.Hash
//
//	// Request the parents for the orphan block from the peer that sent it.
//	if isOrphan {
//		// We've just received an orphan block from a peer. In order
//		// to update the height of the peer, we try to extract the
//		// block height from the scriptSig of the coinbase transaction.
//		// Extraction is only attempted if the block's version is
//		// high enough (ver 2+).
//		header := &bmsg.block.MsgBlock().Header
//		if blockchain.ShouldHaveSerializedBlockHeight(header) {
//			coinbaseTx := bmsg.block.Transactions()[0]
//			cbHeight, err := blockchain.ExtractCoinbaseHeight(coinbaseTx)
//			if err != nil {
//				log.Warnf("Unable to extract height from "+
//					"coinbase tx: %v", err)
//			} else {
//				log.Debugf("Extracted height of %v from "+
//					"orphan block", cbHeight)
//				heightUpdate = cbHeight
//				blkHashUpdate = blockHash
//			}
//		}
//
//		orphanRoot := sm.chain.GetOrphanRoot(blockHash)
//		locator, err := sm.chain.LatestBlockLocator()
//		if err != nil {
//			log.Warnf("Failed to get block locator for the "+
//				"latest block: %v", err)
//		} else {
//			peer.PushGetBlocksMsg(locator, orphanRoot)
//		}
//	} else {
//		if peer == sm.syncPeer {
//			sm.lastProgressTime = time.Now()
//		}
//
//		// When the block is not an orphan, log information about it and
//		// update the chain state.
//		sm.progressLogger.LogBlockHeight(bmsg.block)
//
//		// Update this peer's latest block height, for future
//		// potential sync node candidacy.
//		best := sm.chain.BestSnapshot()
//		heightUpdate = best.Height
//		blkHashUpdate = &best.Hash
//
//		// Clear the rejected transactions.
//		// todo(ABE): Why ?
//		sm.rejectedTxns = make(map[chainhash.Hash]struct{})
//	}
//
//	// Update the block height for this peer. But only send a message to
//	// the server for updating peer heights if this is an orphan or our
//	// chain is "current". This avoids sending a spammy amount of messages
//	// if we're syncing the chain from scratch.
//	if blkHashUpdate != nil && heightUpdate != 0 {
//		peer.UpdateLastBlockHeight(heightUpdate)
//		if isOrphan || sm.current() {
//			//		todo (ABE): it seems to have some problem.
//			go sm.peerNotifier.UpdatePeerHeights(blkHashUpdate, heightUpdate,
//				peer)
//		}
//	}
//
//	// Nothing more to do if we aren't in headers-first mode.
//	if !sm.headersFirstMode {
//		//	todo(ABE): GetBlockMsg-->, <--InvMsg, GetData with block-inv -->, <--BlockMsg
//		return
//	}
//
//	// This is headers-first mode, so if the block is not a checkpoint
//	// request more blocks using the header list when the request queue is
//	// getting short.
//	if !isCheckpointBlock {
//		if sm.startHeader != nil &&
//			len(state.requestedBlocks) < minInFlightBlocks {
//			sm.fetchHeaderBlocks()
//		}
//		return
//	}
//
//	// This is headers-first mode and the block is a checkpoint.  When
//	// there is a next checkpoint, get the next round of headers by asking
//	// for headers starting from the block after this one up to the next
//	// checkpoint.
//	prevHeight := sm.nextCheckpoint.Height
//	prevHash := sm.nextCheckpoint.Hash
//	sm.nextCheckpoint = sm.findNextHeaderCheckpoint(prevHeight)
//	if sm.nextCheckpoint != nil {
//		locator := blockchain.BlockLocator([]*chainhash.Hash{prevHash})
//		err := peer.PushGetHeadersMsg(locator, sm.nextCheckpoint.Hash)
//		if err != nil {
//			log.Warnf("Failed to send getheaders message to "+
//				"peer %s: %v", peer.Addr(), err)
//			return
//		}
//		log.Infof("Downloading headers for blocks %d to %d from "+
//			"peer %s", prevHeight+1, sm.nextCheckpoint.Height,
//			sm.syncPeer.Addr())
//		return
//	}
//
//	// This is headers-first mode, the block is a checkpoint, and there are
//	// no more checkpoints, so switch to normal mode by requesting blocks
//	// from the block after this one up to the end of the chain (zero hash).
//	sm.headersFirstMode = false
//	sm.headerList.Init()
//	log.Infof("Reached the final checkpoint -- switching to normal mode")
//	locator := blockchain.BlockLocator([]*chainhash.Hash{blockHash})
//	err = peer.PushGetBlocksMsg(locator, &zeroHash)
//	if err != nil {
//		log.Warnf("Failed to send getblocks message to peer %s: %v",
//			peer.Addr(), err)
//		return
//	}
//}

//	todo(ABE):
//
// handleBlockMsgAbe handles block messages from all peers.
func (sm *SyncManager) handleBlockMsgAbe(bmsg *blockMsgAbe) {
	peer := bmsg.peer
	state, exists := sm.peerStates[peer]
	if !exists {
		log.Warnf("Received block message from unknown peer %s", peer)
		return
	}

	// If we didn't ask for this block then the peer is misbehaving.
	blockHash := bmsg.block.Hash()
	if _, exists = state.requestedBlocks[*blockHash]; !exists {
		// The regression test intentionally sends some blocks twice
		// to test duplicate block insertion fails.  Don't disconnect
		// the peer or ignore the block when we're in regression test
		// mode in this case so the chain code is actually fed the
		// duplicate blocks.
		if sm.chainParams != &chaincfg.RegressionNetParams {
			log.Warnf("Got unrequested block %v from %s -- "+
				"disconnecting", blockHash, peer.Addr())
			peer.Disconnect()
			return
		}
	}

	// When in headers-first mode, if the block matches the hash of the
	// first header in the list of headers that are being fetched, it's
	// eligible for less validation since the headers have already been
	// verified to link together and are valid up to the next checkpoint.
	// Also, remove the list entry for all blocks except the checkpoint
	// since it is needed to verify the next round of headers links
	// properly.
	isCheckpointBlock := false
	behaviorFlags := blockchain.BFNone
	if sm.headersFirstMode {
		firstNodeEl := sm.headerList.Front()
		if firstNodeEl != nil {
			firstNode := firstNodeEl.Value.(*headerNode)
			if blockHash.IsEqual(firstNode.hash) {
				behaviorFlags |= blockchain.BFFastAdd
				if firstNode.hash.IsEqual(sm.nextCheckpoint.Hash) {
					isCheckpointBlock = true
				} else {
					sm.headerList.Remove(firstNodeEl)
				}
			}
		}
	}

	// for fake pow mode
	if sm.chainParams.Net != wire.MainNet {
		fakePoWHeightScopes := sm.chain.FakePoWHeightScopes()
		if len(fakePoWHeightScopes) != 0 {
			blockHeight := wire.ExtractCoinbaseHeight(bmsg.block.MsgBlock().Transactions[0])
			for _, scope := range fakePoWHeightScopes {
				if scope.StartHeight <= blockHeight && blockHeight <= scope.EndHeight {
					behaviorFlags |= blockchain.BFNoPoWCheck
					break
				}
			}
		}
	}

	// Remove block from request maps. Either chain will know about it and
	// so we shouldn't have any more instances of trying to fetch it, or we
	// will fail the insert and thus we'll retry next time we get an inv.
	delete(state.requestedBlocks, *blockHash)
	delete(sm.requestedBlocks, *blockHash)

	numTx := len(bmsg.block.MsgBlock().Transactions)
	if numTx == 0 {
		log.Infof("Rejected block %v from %s: block without any transactions", blockHash, peer)
		peer.Disconnect()
		return
	}

	witnessNeeded := sm.WitnessNeeded()
	if witnessNeeded {
		if !bmsg.block.MsgBlock().HasWitness() {
			log.Infof("Rejected block %v from %s: block without witness but we request with needing witness", blockHash, peer)
			peer.Disconnect()
			return
		}
	}

	// Process the block to include validation, best chain selection, orphan
	// handling, etc.
	//	todo (EthashPoW): 202207
	_, isOrphan, err := sm.chain.ProcessBlockAbe(bmsg.block, sm.ethash, behaviorFlags)
	if err != nil {
		// When the error is a rule error, it means the block was simply
		// rejected as opposed to something actually going wrong, so log
		// it as such.  Otherwise, something really did go wrong, so log
		// it as an actual error.
		if _, ok := err.(blockchain.RuleError); ok {
			log.Infof("Rejected block %v from %s: %v", blockHash,
				peer, err)
		} else {
			log.Errorf("Failed to process block %v: %v",
				blockHash, err)
		}
		if dbErr, ok := err.(database.Error); ok && dbErr.ErrorCode ==
			database.ErrCorruption {
			panic(dbErr)
		}

		// Convert the error into an appropriate reject message and
		// send it.
		code, reason := mempool.ErrToRejectErr(err)
		peer.PushRejectMsg(wire.CmdBlock, code, reason, blockHash, false)
		return
	}

	// Meta-data about the new block this peer is reporting. We use this
	// below to update this peer's latest block height and the heights of
	// other peers based on their last announced block hash. This allows us
	// to dynamically update the block heights of peers, avoiding stale
	// heights when looking for a new sync peer. Upon acceptance of a block
	// or recognition of an orphan, we also use this information to update
	// the block heights over other peers who's invs may have been ignored
	// if we are actively syncing while the chain is not yet current or
	// who may have lost the lock announcement race.
	var heightUpdate int32
	var blkHashUpdate *chainhash.Hash

	// Request the parents for the orphan block from the peer that sent it.
	if isOrphan {
		// We've just received an orphan block from a peer. In order
		// to update the height of the peer, we try to extract the
		// block height from the scriptSig of the coinbase transaction.
		// Extraction is only attempted if the block's version is
		// high enough (ver 2+).
		// todo (ABE): does abec have height stored in coinbase?
		header := &bmsg.block.MsgBlock().Header
		if blockchain.ShouldHaveSerializedBlockHeight(header) {
			coinbaseTx := bmsg.block.Transactions()[0]
			cbHeight, err := blockchain.ExtractCoinbaseHeightAbe(coinbaseTx)
			if err != nil {
				log.Warnf("Unable to extract height from "+
					"coinbase tx: %v", err)
			} else {
				log.Debugf("Extracted height of %v from "+
					"orphan block", cbHeight)
				heightUpdate = cbHeight
				blkHashUpdate = blockHash
			}
		}

		orphanRoot := sm.chain.GetOrphanRoot(blockHash)
		locator, err := sm.chain.LatestBlockLocator()
		if err != nil {
			log.Warnf("Failed to get block locator for the "+
				"latest block: %v", err)
		} else {
			peer.PushGetBlocksMsg(locator, orphanRoot)
		}
	} else {
		if peer == sm.syncPeer {
			sm.lastProgressTime = time.Now()
		}

		// When the block is not an orphan, log information about it and
		// update the chain state.
		sm.progressLogger.LogBlockHeightAbe(bmsg.block)

		// Update this peer's latest block height, for future
		// potential sync node candidacy.
		best := sm.chain.BestSnapshot()
		heightUpdate = best.Height
		blkHashUpdate = &best.Hash

		// Clear the rejected transactions.
		sm.rejectedTxns = make(map[chainhash.Hash]struct{})
	}

	// Update the block height for this peer. But only send a message to
	// the server for updating peer heights if this is an orphan or our
	// chain is "current". This avoids sending a spammy amount of messages
	// if we're syncing the chain from scratch.
	if blkHashUpdate != nil && heightUpdate != 0 {
		peer.UpdateLastBlockHeight(heightUpdate)
		if heightUpdate > peer.AnnouncedHeight() {
			peer.UpdateAnnouncedHeight(heightUpdate)
		}
		if isOrphan || sm.current() {
			go sm.peerNotifier.UpdatePeerHeights(blkHashUpdate, heightUpdate,
				peer)
		}
	}

	// Nothing more to do if we aren't in headers-first mode.
	if !sm.headersFirstMode {
		return
	}

	// This is headers-first mode, so if the block is not a checkpoint
	// request more blocks using the header list when the request queue is
	// getting short.
	if !isCheckpointBlock {
		if sm.startHeader != nil &&
			len(state.requestedBlocks) < minInFlightBlocks {
			sm.fetchHeaderBlocks()
		}
		return
	}

	// This is headers-first mode and the block is a checkpoint.  When
	// there is a next checkpoint, get the next round of headers by asking
	// for headers starting from the block after this one up to the next
	// checkpoint.
	prevHeight := sm.nextCheckpoint.Height
	prevHash := sm.nextCheckpoint.Hash
	sm.nextCheckpoint = sm.findNextHeaderCheckpoint(prevHeight)
	if sm.nextCheckpoint != nil {
		locator := blockchain.BlockLocator([]*chainhash.Hash{prevHash})
		err := peer.PushGetHeadersMsg(locator, sm.nextCheckpoint.Hash)
		if err != nil {
			log.Warnf("Failed to send getheaders message to "+
				"peer %s: %v", peer.Addr(), err)
			return
		}
		log.Infof("Downloading headers for blocks %d to %d from "+
			"peer %s", prevHeight+1, sm.nextCheckpoint.Height,
			sm.syncPeer.Addr())
		return
	}

	// This is headers-first mode, the block is a checkpoint, and there are
	// no more checkpoints, so switch to normal mode by requesting blocks
	// from the block after this one up to the end of the chain (zero hash).
	sm.headersFirstMode = false
	sm.headerList.Init()
	log.Infof("Reached the final checkpoint -- switching to normal mode")
	locator := blockchain.BlockLocator([]*chainhash.Hash{blockHash})
	err = peer.PushGetBlocksMsg(locator, &zeroHash)
	if err != nil {
		log.Warnf("Failed to send getblocks message to peer %s: %v",
			peer.Addr(), err)
		return
	}
}

// handlePrunedBlockMsgAbe handles prunedblock messages from all peers.
func (sm *SyncManager) handlePrunedBlockMsgAbe(bmsg *prunedBlockMsg) {
	defer func() {
		if bmsg.reply != nil {
			bmsg.reply <- struct{}{}
		}
	}()
	peer := bmsg.peer
	state, exists := sm.peerStates[peer]
	if !exists {
		log.Warnf("Received pruned block message from unknown peer %s", peer)
		return
	}

	// log.Debugf("Receive pruned block hash %s from peer %s", bmsg.block.Hash().String(), peer)

	// If we didn't ask for this block then the peer is misbehaving.
	blockHash := bmsg.block.Hash()
	if _, exists = state.requestedBlocks[*blockHash]; !exists {
		// The regression test intentionally sends some blocks twice
		// to test duplicate block insertion fails.  Don't disconnect
		// the peer or ignore the block when we're in regression test
		// mode in this case so the chain code is actually fed the
		// duplicate blocks.
		if sm.chainParams != &chaincfg.RegressionNetParams {
			log.Warnf("Got unrequested block %v from %s -- "+
				"disconnecting", blockHash, peer.Addr())
			peer.Disconnect()
			return
		}
	}

	// When in headers-first mode, if the block matches the hash of the
	// first header in the list of headers that are being fetched, it's
	// eligible for less validation since the headers have already been
	// verified to link together and are valid up to the next checkpoint.
	// Also, remove the list entry for all blocks except the checkpoint
	// since it is needed to verify the next round of headers links
	// properly.
	isCheckpointBlock := false
	behaviorFlags := blockchain.BFNone
	if sm.headersFirstMode {
		firstNodeEl := sm.headerList.Front()
		if firstNodeEl != nil {
			firstNode := firstNodeEl.Value.(*headerNode)
			if blockHash.IsEqual(firstNode.hash) {
				behaviorFlags |= blockchain.BFFastAdd
				if firstNode.hash.IsEqual(sm.nextCheckpoint.Hash) {
					isCheckpointBlock = true
				} else {
					sm.headerList.Remove(firstNodeEl)
				}
			}
		}
	}

	// Remove block from request maps. Either chain will know about it and
	// so we shouldn't have any more instances of trying to fetch it, or we
	// will fail the insert and thus we'll retry next time we get an inv.
	delete(state.requestedBlocks, *blockHash)
	delete(sm.requestedBlocks, *blockHash)

	var msgBlockAbe wire.MsgBlockAbe
	msgBlockAbe.Header = bmsg.block.MsgPrunedBlock().Header
	// Add the coinbase transaction to the block
	msgBlockAbe.Transactions = make([]*wire.MsgTxAbe, 1, len(bmsg.block.MsgPrunedBlock().TransactionHashes)+1)
	msgBlockAbe.WitnessHashs = make([]*chainhash.Hash, 1, len(bmsg.block.MsgPrunedBlock().WitnessHashs)+1)
	msgBlockAbe.Transactions[0] = bmsg.block.MsgPrunedBlock().CoinbaseTx
	witHash := chainhash.DoubleHashH(bmsg.block.MsgPrunedBlock().CoinbaseTx.TxWitness)
	msgBlockAbe.WitnessHashs[0] = &witHash
	needSet := make([]chainhash.Hash, 0, len(bmsg.block.MsgPrunedBlock().TransactionHashes))
	txmap := make(map[chainhash.Hash]*wire.MsgTxAbe)
	// try to restore the block with the help of local transaction pool
	for i := 0; i < len(bmsg.block.MsgPrunedBlock().TransactionHashes); i++ {
		txHash := bmsg.block.MsgPrunedBlock().TransactionHashes[i]
		if tx, err := sm.txMemPool.FetchTransaction(&txHash); err != nil {
			needSet = append(needSet, txHash)
		} else {
			txhash := tx.MsgTx().TxHash()
			txmap[txhash] = tx.MsgTx()
		}
	}

	// wait the needsetResult
	if len(needSet) != 0 {
		log.Debugf("Missing %v transactions in pruned block %s from peer %s, sending needset message...", len(needSet), bmsg.block.Hash().String(), peer)
		syncPeerState, exists := sm.peerStates[peer]
		if !exists {
			log.Warnf("Received pruned block message from unknown peer %s", peer)
			return
		}
		syncPeerState.requestedNeedSet[*blockHash] = struct{}{}
		txs, err := peer.PushNeedSetMsg(*blockHash, needSet)
		if txs == nil || err != nil {
			log.Infof("Rejected block %v from %s: %v", blockHash,
				peer, err)
			return
		}

		log.Debugf("Receive need set result containing %v transactions from peer %s, restoring...", len(txs), peer)

		for _, tx := range txs {
			txhash := tx.TxHash()
			txmap[txhash] = tx
		}
	}

	// restore
	for i := 0; i < len(bmsg.block.MsgPrunedBlock().TransactionHashes); i++ {
		txHash := bmsg.block.MsgPrunedBlock().TransactionHashes[i]
		tx, ok := txmap[txHash]
		if !ok {
			log.Infof("Rejected block %v from %s: incorrect needsetresult", blockHash, peer)
			peer.PushRejectMsg(wire.CmdPrunedBlock, wire.RejectInvalid, "incorrect needsetresult", blockHash, false)
			return
		}
		msgBlockAbe.Transactions = append(msgBlockAbe.Transactions, tx)
		witnessHash := chainhash.DoubleHashH(tx.TxWitness)
		msgBlockAbe.WitnessHashs = append(msgBlockAbe.WitnessHashs, &witnessHash)
	}

	block := abeutil.NewBlockAbe(&msgBlockAbe)
	// Process the block to include validation, best chain selection, orphan
	// handling, etc.
	_, isOrphan, err := sm.chain.ProcessBlockAbe(block, sm.ethash, behaviorFlags)
	if err != nil {
		// When the error is a rule error, it means the block was simply
		// rejected as opposed to something actually going wrong, so log
		// it as such.  Otherwise, something really did go wrong, so log
		// it as an actual error.
		if _, ok := err.(blockchain.RuleError); ok {
			log.Infof("Rejected block %v from %s: %v", blockHash,
				peer, err)
		} else {
			log.Errorf("Failed to process block %v: %v",
				blockHash, err)
		}
		if dbErr, ok := err.(database.Error); ok && dbErr.ErrorCode ==
			database.ErrCorruption {
			panic(dbErr)
		}

		// Convert the error into an appropriate reject message and
		// send it.
		code, reason := mempool.ErrToRejectErr(err)
		peer.PushRejectMsg(wire.CmdBlock, code, reason, blockHash, false)
		return
	}

	// Meta-data about the new block this peer is reporting. We use this
	// below to update this peer's latest block height and the heights of
	// other peers based on their last announced block hash. This allows us
	// to dynamically update the block heights of peers, avoiding stale
	// heights when looking for a new sync peer. Upon acceptance of a block
	// or recognition of an orphan, we also use this information to update
	// the block heights over other peers who's invs may have been ignored
	// if we are actively syncing while the chain is not yet current or
	// who may have lost the lock announcement race.
	var heightUpdate int32
	var blkHashUpdate *chainhash.Hash

	// Request the parents for the orphan block from the peer that sent it.
	if isOrphan {
		// We've just received an orphan block from a peer. In order
		// to update the height of the peer, we try to extract the
		// block height from the coinbase transaction.
		coinbaseTx := block.Transactions()[0]
		cbHeight, err := blockchain.ExtractCoinbaseHeightAbe(coinbaseTx)
		if err != nil {
			log.Warnf("Unable to extract height from "+
				"coinbase tx: %v", err)
		} else {
			log.Debugf("Extracted height of %v from "+
				"orphan block", cbHeight)
			heightUpdate = cbHeight
			blkHashUpdate = blockHash
		}

		orphanRoot := sm.chain.GetOrphanRoot(blockHash)
		locator, err := sm.chain.LatestBlockLocator()
		if err != nil {
			log.Warnf("Failed to get block locator for the "+
				"latest block: %v", err)
		} else {
			peer.PushGetBlocksMsg(locator, orphanRoot)
		}
	} else {
		if peer == sm.syncPeer {
			sm.lastProgressTime = time.Now()
		}

		// When the block is not an orphan, log information about it and
		// update the chain state.
		sm.progressLogger.LogBlockHeightAbe(block)

		// Update this peer's latest block height, for future
		// potential sync node candidacy.
		best := sm.chain.BestSnapshot()
		heightUpdate = best.Height
		blkHashUpdate = &best.Hash

		// Clear the rejected transactions.
		sm.rejectedTxns = make(map[chainhash.Hash]struct{})
	}

	// Update the block height for this peer. But only send a message to
	// the server for updating peer heights if this is an orphan or our
	// chain is "current". This avoids sending a spammy amount of messages
	// if we're syncing the chain from scratch.
	if blkHashUpdate != nil && heightUpdate != 0 {
		peer.UpdateLastBlockHeight(heightUpdate)
		if heightUpdate > peer.AnnouncedHeight() {
			peer.UpdateAnnouncedHeight(heightUpdate)
		}
		peer.UpdateLastAnnouncedBlock(blkHashUpdate)
		if isOrphan || sm.current() {
			go sm.peerNotifier.UpdatePeerHeights(blkHashUpdate, heightUpdate,
				peer)
		}
	}

	// Nothing more to do if we aren't in headers-first mode.
	if !sm.headersFirstMode {
		return
	}

	// This is headers-first mode, so if the block is not a checkpoint
	// request more blocks using the header list when the request queue is
	// getting short.
	if !isCheckpointBlock {
		if sm.startHeader != nil &&
			len(state.requestedBlocks) < minInFlightBlocks {
			sm.fetchHeaderBlocks()
		}
		return
	}

	// This is headers-first mode and the block is a checkpoint.  When
	// there is a next checkpoint, get the next round of headers by asking
	// for headers starting from the block after this one up to the next
	// checkpoint.
	prevHeight := sm.nextCheckpoint.Height
	prevHash := sm.nextCheckpoint.Hash
	sm.nextCheckpoint = sm.findNextHeaderCheckpoint(prevHeight)
	if sm.nextCheckpoint != nil {
		locator := blockchain.BlockLocator([]*chainhash.Hash{prevHash})
		err := peer.PushGetHeadersMsg(locator, sm.nextCheckpoint.Hash)
		if err != nil {
			log.Warnf("Failed to send getheaders message to "+
				"peer %s: %v", peer.Addr(), err)
			return
		}
		log.Infof("Downloading headers for blocks %d to %d from "+
			"peer %s", prevHeight+1, sm.nextCheckpoint.Height,
			sm.syncPeer.Addr())
		return
	}

	// This is headers-first mode, the block is a checkpoint, and there are
	// no more checkpoints, so switch to normal mode by requesting blocks
	// from the block after this one up to the end of the chain (zero hash).
	sm.headersFirstMode = false
	sm.headerList.Init()
	log.Infof("Reached the final checkpoint -- switching to normal mode")
	locator := blockchain.BlockLocator([]*chainhash.Hash{blockHash})
	err = peer.PushGetBlocksMsg(locator, &zeroHash)
	if err != nil {
		log.Warnf("Failed to send getblocks message to peer %s: %v",
			peer.Addr(), err)
		return
	}
}

//func (sm *SyncManager) handleNeedSetMsg(imsg *needSetMsg) {
//	peer := imsg.peer
//	_, exists := sm.peerStates[peer]
//	if !exists {
//		log.Warnf("Received needset message from unknown peer %s", peer)
//		return
//	}
//
//	hashes := imsg.needset.MsgNeedSet().Hashes
//	blockHash := imsg.needset.MsgNeedSet().BlockHash
//
//	log.Debugf("Receive needset message requiring %v transactions in block %s from peer %s", len(hashes), blockHash.String(), peer)
//
//	block, err := sm.chain.BlockByHashAbe(&blockHash)
//	if err != nil {
//		return
//	}
//	originTxs := block.Transactions()
//	txhashMap := make(map[chainhash.Hash]*abeutil.TxAbe)
//	for i := 0; i < len(originTxs); i++ {
//		txhash := originTxs[i].Hash()
//		txhashMap[*txhash] = originTxs[i]
//	}
//	rtxs := make([]*wire.MsgTxAbe, len(hashes))
//	for i, txhash := range hashes {
//		rtxs[i] = txhashMap[txhash].MsgTx()
//	}
//	//result := wire.NewMsgNeedSetResult(blockHash, rtxs)
//
//	log.Debugf("Send needsetresult message containing %v transactions in block %s to peer %s", len(hashes), blockHash.String(), peer)
//	msg := wire.NewMsgNeedSetResult(blockHash, rtxs)
//	peer.QueueMessageWithEncoding(msg, nil, wire.WitnessEncoding)
//}

//func (sm *SyncManager) handleNeedSetResultMsg(imsg *needSetResultMsg) {
//	peer := imsg.peer
//	_, exists := sm.peerStates[peer]
//	if !exists {
//		log.Warnf("Received inv message from unknown peer %s", peer)
//		return
//	}
//	// Request the advertised inventory if we don't already have it.  Also,
//	// request parent blocks of orphans if we receive one we already have.
//	// Finally, attempt to detect potential stalls due to long side chains
//	// we already have and request more blocks to prevent them.
//	<- imsg
//}

// fetchHeaderBlocks creates and sends a request to the syncPeer for the next
// list of blocks to be downloaded based on the current list of headers.
func (sm *SyncManager) fetchHeaderBlocks() {
	// Nothing to do if there is no start header.
	if sm.startHeader == nil {
		log.Warnf("fetchHeaderBlocks called with no start header")
		return
	}

	// Build up a getdata request for the list of blocks the headers
	// describe.  The size hint will be limited to wire.MaxInvPerMsg by
	// the function, so no need to double check it here.
	gdmsg := wire.NewMsgGetDataSizeHint(uint(sm.headerList.Len()))
	numRequested := 0
	for e := sm.startHeader; e != nil; e = e.Next() {
		node, ok := e.Value.(*headerNode)
		if !ok {
			log.Warn("Header list node type is not a headerNode")
			continue
		}

		iv := wire.NewInvVect(wire.InvTypeBlock, node.hash)
		haveInv, err := sm.haveInventory(iv)
		if err != nil {
			log.Warnf("Unexpected failure when checking for "+
				"existing inventory during header block "+
				"fetch: %v", err)
		}
		if !haveInv {
			syncPeerState := sm.peerStates[sm.syncPeer]

			sm.requestedBlocks[*node.hash] = struct{}{}
			syncPeerState.requestedBlocks[*node.hash] = struct{}{}

			// If we're fetching from a witness enabled peer
			// post-fork, then ensure that we receive all the
			// witness data in the blocks.
			// todo(ABE): for ABE, even for WitnessEnabled peer, we may do not want receive the witness
			//	todo(ABE): for blocks before checkpoint, we do not need to check the transactions' witness
			if sm.WitnessNeeded() {
				iv.Type = wire.InvTypeWitnessBlock
			}

			gdmsg.AddInvVect(iv)
			numRequested++
		}
		sm.startHeader = e.Next()
		if numRequested >= wire.MaxInvPerMsg {
			break
		}
	}
	if len(gdmsg.InvList) > 0 {
		sm.syncPeer.QueueMessage(gdmsg, nil)
	}
}

// handleHeadersMsg handles block header messages from all peers.  Headers are
// requested when performing a headers-first sync.
func (sm *SyncManager) handleHeadersMsg(hmsg *headersMsg) {
	peer := hmsg.peer
	_, exists := sm.peerStates[peer]
	if !exists {
		log.Warnf("Received headers message from unknown peer %s", peer)
		return
	}

	// The remote peer is misbehaving if we didn't request headers.
	msg := hmsg.headers
	numHeaders := len(msg.Headers)
	if !sm.headersFirstMode {
		//	todo(ABE): when requesting blockds before nectcheckpoint, sm uses HeadersFirstMode (by setting this flag)
		log.Warnf("Got %d unrequested headers from %s -- "+
			"disconnecting", numHeaders, peer.Addr())
		peer.Disconnect()
		return
	}

	// Nothing to do for an empty headers message.
	if numHeaders == 0 {
		return
	}

	// Process all of the received headers ensuring each one connects to the
	// previous and that checkpoints match.
	receivedCheckpoint := false
	var finalHash *chainhash.Hash
	for _, blockHeader := range msg.Headers {
		blockHash := blockHeader.BlockHash()
		finalHash = &blockHash

		// Ensure there is a previous header to compare against.
		prevNodeEl := sm.headerList.Back()
		if prevNodeEl == nil {
			log.Warnf("Header list does not contain a previous" +
				"element as expected -- disconnecting peer")
			peer.Disconnect()
			return
		}

		// Ensure the header properly connects to the previous one and
		// add it to the list of headers.
		node := headerNode{hash: &blockHash}
		prevNode := prevNodeEl.Value.(*headerNode)
		if prevNode.hash.IsEqual(&blockHeader.PrevBlock) {
			node.height = prevNode.height + 1
			e := sm.headerList.PushBack(&node)
			if sm.startHeader == nil {
				sm.startHeader = e
			}
		} else {
			log.Warnf("Received block header that does not "+
				"properly connect to the chain from peer %s "+
				"-- disconnecting", peer.Addr())
			peer.Disconnect()
			return
		}

		// Verify the header at the next checkpoint height matches.
		if node.height == sm.nextCheckpoint.Height {
			if node.hash.IsEqual(sm.nextCheckpoint.Hash) {
				receivedCheckpoint = true
				log.Infof("Verified downloaded block "+
					"header against checkpoint at height "+
					"%d/hash %s", node.height, node.hash)
			} else {
				log.Warnf("Block header at height %d/hash "+
					"%s from peer %s does NOT match "+
					"expected checkpoint hash of %s -- "+
					"disconnecting", node.height,
					node.hash, peer.Addr(),
					sm.nextCheckpoint.Hash)
				peer.Disconnect()
				return
			}
			break
		}
	}

	// When this header is a checkpoint, switch to fetching the blocks for
	// all of the headers since the last checkpoint.
	if receivedCheckpoint {
		// Since the first entry of the list is always the final block
		// that is already in the database and is only used to ensure
		// the next header links properly, it must be removed before
		// fetching the blocks.
		sm.headerList.Remove(sm.headerList.Front())
		log.Infof("Received %v block headers: Fetching blocks",
			sm.headerList.Len())
		sm.progressLogger.SetLastLogTime(time.Now())
		sm.fetchHeaderBlocks()
		return
	}

	// This header is not a checkpoint, so request the next batch of
	// headers starting from the latest known header and ending with the
	// next checkpoint.
	locator := blockchain.BlockLocator([]*chainhash.Hash{finalHash})
	err := peer.PushGetHeadersMsg(locator, sm.nextCheckpoint.Hash)
	if err != nil {
		log.Warnf("Failed to send getheaders message to "+
			"peer %s: %v", peer.Addr(), err)
		return
	}
}

// haveInventory returns whether or not the inventory represented by the passed
// inventory vector is known.  This includes checking all of the various places
// inventory can be when it is in different states such as blocks that are part
// of the main chain, on a side chain, in the orphan pool, and transactions that
// are in the memory pool (either the main pool or orphan pool).
func (sm *SyncManager) haveInventory(invVect *wire.InvVect) (bool, error) {
	switch invVect.Type {
	case wire.InvTypeWitnessBlock:
		fallthrough
	case wire.InvTypeBlock:
		fallthrough
	case wire.InvTypePrunedBlock:
		// Ask chain if the block is known to it in any form (main
		// chain, side chain, or orphan).
		return sm.chain.HaveBlock(&invVect.Hash)

	case wire.InvTypeWitnessTx:
		fallthrough
	case wire.InvTypeTx:
		// Ask the transaction memory pool if the transaction is known
		// to it in any form (main pool or orphan).
		if sm.txMemPool.HaveTransaction(&invVect.Hash) {
			return true, nil
		}

		// Check if the transaction exists from the point of view of the
		// end of the main chain.  Note that this is only a best effort
		// since it is expensive to check existence of every output and
		// the only purpose of this check is to avoid downloading
		// already known transactions.  Only the first two outputs are
		// checked because the vast majority of transactions consist of
		// two outputs where one is some form of "pay-to-somebody-else"
		// and the other is a change output.
		//	TODO(ABE): ABE cannot do such a such check, as the outpoint is not stored, instead,they are orgainized into rings.
		//	To Address this problem, we can use the peer evaluation or store tha map from outpoint to ringhash.
		//	Actually, such a check does not function much:an such a transaction will be regarded as a orphan or doubles-spend transaction.
		/*		prevOut := wire.OutPoint{Hash: invVect.Hash}
				for i := uint32(0); i < 2; i++ {
					prevOut.Index = i
					entry, err := sm.chain.FetchUtxoEntry(prevOut)
					if err != nil {
						return false, err
					}
					if entry != nil && !entry.IsSpent() {
						return true, nil
					}
				}*/

		return false, nil
	}

	// The requested inventory is is an unsupported type, so just claim
	// it is known to avoid requesting it.
	return true, nil
}

// handleInvMsg handles inv messages from all peers.
// We examine the inventory advertised by the remote peer and act accordingly.
func (sm *SyncManager) handleInvMsg(imsg *invMsg) {
	peer := imsg.peer
	state, exists := sm.peerStates[peer]
	if !exists {
		log.Warnf("Received inv message from unknown peer %s", peer)
		return
	}

	// Attempt to find the final block in the inventory list.  There may
	// not be one.
	lastBlock := -1
	invVects := imsg.inv.InvList
	for i := len(invVects) - 1; i >= 0; i-- {
		if invVects[i].Type == wire.InvTypeBlock ||
			invVects[i].Type == wire.InvTypeWitnessBlock ||
			invVects[i].Type == wire.InvTypePrunedBlock {
			//	todo(ABE): for block-invMsg, for block, there is only InvTypeBlock? without InvTypeWitnessTx
			lastBlock = i
			break
		}
	}

	// If this inv contains a block announcement, and this isn't coming from
	// our current sync peer or we're current, then update the last
	// announced block for this peer. We'll use this information later to
	// update the heights of peers based on blocks we've accepted that they
	// previously announced.
	//	todo(ABE): what sm.current() means should be further studied.
	if lastBlock != -1 && (peer != sm.syncPeer || sm.current()) {
		peer.UpdateLastAnnouncedBlock(&invVects[lastBlock].Hash)
	}

	// Ignore invs from peers that aren't the sync if we are not current.
	// Helps prevent fetching a mass of orphans.
	if peer != sm.syncPeer && !sm.current() {
		return
	}

	// If our chain is current and a peer announces a block we already
	// know of, then update their current block height.
	//	todo(ABE): the peer which sends the inVMsg has a LastBlock that is lower than this peer's
	if lastBlock != -1 && sm.current() {
		blkHeight, err := sm.chain.BlockHeightByHash(&invVects[lastBlock].Hash)
		if err == nil {
			peer.UpdateLastBlockHeight(blkHeight)
			if blkHeight > peer.AnnouncedHeight() {
				peer.UpdateAnnouncedHeight(blkHeight)
			}
			peer.UpdateLastAnnouncedBlock(&invVects[lastBlock].Hash)
		}
	}

	// Request the advertised inventory if we don't already have it.  Also,
	// request parent blocks of orphans if we receive one we already have.
	// Finally, attempt to detect potential stalls due to long side chains
	// we already have and request more blocks to prevent them.
	for i, iv := range invVects {
		// Ignore unsupported inventory types.
		//	todo (ABE): InvTypeFilteredBlock is not supported. ?
		switch iv.Type {
		case wire.InvTypeBlock:
		case wire.InvTypeTx:
		case wire.InvTypeWitnessBlock:
		case wire.InvTypeWitnessTx:
		case wire.InvTypePrunedBlock:
		default:
			continue
		}

		// Add the inventory to the cache of known inventory
		// for the peer.
		peer.AddKnownInventory(iv)

		// Ignore inventory when we're in headers-first mode.
		if sm.headersFirstMode {
			// todo (ABE): In headersFirstMode, the process is
			// GetHeaders -->, <-- Headers, GetData with inv -->, <-- Blocks
			continue
		}

		// Request the inventory if we don't already have it.
		haveInv, err := sm.haveInventory(iv)
		if err != nil {
			log.Warnf("Unexpected failure when checking for "+
				"existing inventory during inv message "+
				"processing: %v", err)
			continue
		}
		if !haveInv {
			if iv.Type == wire.InvTypeTx || iv.Type == wire.InvTypeWitnessTx {
				// Skip the transaction if it has already been
				// rejected.
				if _, exists := sm.rejectedTxns[iv.Hash]; exists {
					continue
				}
			}
			if iv.Type == wire.InvTypePrunedBlock {
				state.requestQueue = append(state.requestQueue, iv)
				continue
			}

			// Ignore invs block invs from non-witness enabled
			// peers, as after segwit activation we only want to
			// download from peers that can provide us full witness
			// data for blocks.
			//	todo (ABE): for ABE, when a new peer is syncing blocks before some checkpoint, does this apply?
			//	todo (ABE): there are only two cases for receiving invMsg:
			//	todo (ABE): (1) as an received reply for GetBlocks request
			//	todo (ABE): (2) some miner announce its new found block candidate
			//	todo (ABE): (3) in the pushBlockMsg of getData of the syning peer, the peer may send a invMsg with its latest block
			if !peer.IsWitnessEnabled() && iv.Type == wire.InvTypeWitnessBlock {
				continue
			}

			// Add it to the request queue.
			//	todo (ABE): the above case (3) will trigger here and later GetData by inv.
			state.requestQueue = append(state.requestQueue, iv)
			continue
		}

		if iv.Type == wire.InvTypeBlock || iv.Type == wire.InvTypeWitnessBlock {
			// The block is an orphan block that we already have.
			// When the existing orphan was processed, it requested
			// the missing parent blocks.  When this scenario
			// happens, it means there were more blocks missing
			// than are allowed into a single inventory message.  As
			// a result, once this peer requested the final
			// advertised block, the remote peer noticed and is now
			// resending the orphan block as an available block
			// to signal there are more missing blocks that need to
			// be requested.
			if sm.chain.IsKnownOrphan(&iv.Hash) {
				// Request blocks starting at the latest known
				// up to the root of the orphan that just came
				// in.
				orphanRoot := sm.chain.GetOrphanRoot(&iv.Hash)
				locator, err := sm.chain.LatestBlockLocator()
				if err != nil {
					log.Errorf("PEER: Failed to get block "+
						"locator for the latest block: "+
						"%v", err)
					continue
				}
				peer.PushGetBlocksMsg(locator, orphanRoot)
				continue
			}

			// We already have the final block advertised by this
			// inventory message, so force a request for more.  This
			// should only happen if we're on a really long side
			// chain.
			if i == lastBlock {
				// Request blocks after this one up to the
				// final one the remote peer knows about (zero
				// stop hash).
				locator := sm.chain.BlockLocatorFromHash(&iv.Hash)
				peer.PushGetBlocksMsg(locator, &zeroHash)
			}
		}

	}

	// Request as much as possible at once.  Anything that won't fit into
	// the request will be requested on the next inv message.
	numRequested := 0
	gdmsg := wire.NewMsgGetData()
	requestQueue := state.requestQueue
	for len(requestQueue) != 0 {
		iv := requestQueue[0]
		requestQueue[0] = nil
		requestQueue = requestQueue[1:]

		switch iv.Type {
		case wire.InvTypeWitnessBlock:
			fallthrough
		case wire.InvTypeBlock:
			// Request the block if there is not already a pending
			// request.
			if _, exists := sm.requestedBlocks[iv.Hash]; !exists {
				limitAdd(sm.requestedBlocks, iv.Hash, maxRequestedBlocks)
				limitAdd(state.requestedBlocks, iv.Hash, maxRequestedBlocks)

				if sm.WitnessNeeded() {
					iv.Type = wire.InvTypeWitnessBlock
				}

				gdmsg.AddInvVect(iv)
				numRequested++
			}
		case wire.InvTypePrunedBlock:
			if _, exists := sm.requestedBlocks[iv.Hash]; !exists {
				limitAdd(sm.requestedBlocks, iv.Hash, maxRequestedBlocks)
				limitAdd(state.requestedBlocks, iv.Hash, maxRequestedBlocks)
				gdmsg.AddInvVect(iv)
				numRequested++
			}

		case wire.InvTypeWitnessTx:
			fallthrough
		case wire.InvTypeTx:
			// Request the transaction if there is not already a
			// pending request.
			if _, exists := sm.requestedTxns[iv.Hash]; !exists {
				//sm.requestedTxns[iv.Hash] = struct{}{}
				//sm.limitMap(sm.requestedTxns, maxRequestedTxns)
				//state.requestedTxns[iv.Hash] = struct{}{}
				limitAdd(sm.requestedTxns, iv.Hash, maxRequestedTxns)
				limitAdd(state.requestedTxns, iv.Hash, maxRequestedTxns)

				// If the peer is capable, request the txn
				// including all witness data.
				if peer.IsWitnessEnabled() {
					iv.Type = wire.InvTypeWitnessTx
				}

				gdmsg.AddInvVect(iv)
				numRequested++
			}
		}

		if numRequested >= wire.MaxInvPerMsg {
			break
		}
	}
	state.requestQueue = requestQueue
	if len(gdmsg.InvList) > 0 {
		peer.QueueMessage(gdmsg, nil)
	}
}

//// limitMap is a helper function for maps that require a maximum limit by
//// evicting a random transaction if adding a new value would cause it to
//// overflow the maximum allowed.
//func (sm *SyncManager) limitMap(m map[chainhash.Hash]struct{}, limit int) {
//	if len(m)+1 > limit {
//		// Remove a random entry from the map.  For most compilers, Go's
//		// range statement iterates starting at a random item although
//		// that is not 100% guaranteed by the spec.  The iteration order
//		// is not important here because an adversary would have to be
//		// able to pull off preimage attacks on the hashing function in
//		// order to target eviction of specific entries anyways.
//		for txHash := range m {
//			delete(m, txHash)
//			return
//		}
//	}
//}

// blockHandler is the main handler for the sync manager.  It must be run as a
// goroutine.  It processes block and inv messages in a separate goroutine
// from the peer handlers so the block (MsgBlock) messages are handled by a
// single thread without needing to lock memory data structures.  This is
// important because the sync manager controls which blocks are needed and how
// the fetching should proceed.
func (sm *SyncManager) blockHandler() {
	stallTicker := time.NewTicker(stallSampleInterval)
	defer stallTicker.Stop()

out:
	for {
		select {
		case m := <-sm.msgChan:
			switch msg := m.(type) {
			case *newPeerMsg:
				sm.handleNewPeerMsg(msg.peer)

			case *txMsgAbe:
				sm.handleTxMsgAbe(msg)
				msg.reply <- struct{}{}

			case *blockMsgAbe:
				sm.handleBlockMsgAbe(msg)
				msg.reply <- struct{}{}

			case *prunedBlockMsg:
				sm.handlePrunedBlockMsgAbe(msg)

			//case *needSetMsg:
			//	sm.handleNeedSetMsg(msg)

			case *invMsg:
				sm.handleInvMsg(msg)

			case *headersMsg:
				sm.handleHeadersMsg(msg)

			case *donePeerMsg:
				sm.handleDonePeerMsg(msg.peer)

			case getSyncPeerMsg:
				var peerID int32
				if sm.syncPeer != nil {
					peerID = sm.syncPeer.ID()
				}
				msg.reply <- peerID

			case processBlockMsgAbe:
				//	todo (EthashPoW): 202207
				_, isOrphan, err := sm.chain.ProcessBlockAbe(msg.block, sm.ethash, msg.flags)
				if err != nil {
					msg.reply <- processBlockResponse{
						isOrphan: false,
						err:      err,
					}
					continue
				}

				msg.reply <- processBlockResponse{
					isOrphan: isOrphan,
					err:      nil,
				}

			case isCurrentMsg:
				msg.reply <- sm.current()

			case pauseMsg:
				// Wait until the sender unpauses the manager.
				<-msg.unpause

			default:
				log.Warnf("Invalid message type in block "+
					"handler: %T", msg)
			}

		case <-stallTicker.C:
			sm.handleStallSample()

		case <-sm.quit:
			break out
		}
	}

	sm.wg.Done()
	log.Trace("Block handler done")
}

// handleBlockchainNotification handles notifications from blockchain.  It does
// things such as request orphan block parents and relay accepted blocks to
// connected peers.
//
//	todo (ABE):
func (sm *SyncManager) handleBlockchainNotification(notification *blockchain.Notification) {
	switch notification.Type {
	// A block has been accepted into the block chain.  Relay it to other
	// peers.
	case blockchain.NTBlockAccepted:
		// Don't relay if we are not current. Other peers that are
		// current should already know about it.
		if !sm.current() {
			return
		}

		block, ok := notification.Data.(*abeutil.BlockAbe)
		if !ok {
			log.Warnf("Chain accepted notification is not a block.")
			break
		}

		// Generate the inventory vector and relay it.
		//iv := wire.NewInvVect(wire.InvTypeBlock, block.Hash())
		iv := wire.NewInvVect(wire.InvTypePrunedBlock, block.Hash())
		sm.peerNotifier.RelayInventory(iv, block.MsgBlock().Header)

	// A block has been connected to the main block chain.
	case blockchain.NTBlockConnected:
		block, ok := notification.Data.(*abeutil.BlockAbe)
		if !ok {
			log.Warnf("Chain connected notification is not a block.")
			break
		}

		// Remove all of the transactions (except the coinbase) in the
		// connected block from the transaction pool.  Secondly, remove any
		// transactions which are now double spends as a result of these
		// new transactions.  Finally, remove any transaction that is
		// no longer an orphan. Transactions which depend on a confirmed
		// transaction are NOT removed recursively because they are still
		// valid.
		//	todo(ABE): mempool will not contain the transactions that double-spend those in mainchain.
		for _, tx := range block.Transactions()[1:] {
			sm.txMemPool.RemoveTransactionAbe(tx)    // remove this transaction from the mempool
			sm.txMemPool.RemoveDoubleSpendsAbe(tx)   // remove the transactions that spend the same outpoint
			sm.txMemPool.RemoveOrphanAbe(tx)         // remove this transaction from the orphan pool
			sm.peerNotifier.TransactionConfirmed(tx) // the transaction is confirmed
			sm.txMemPool.ProcessOrphansAbe(tx)       //	remove the orphans that double-spend the txIns of tx
			//sm.peerNotifier.AnnounceNewTransactions(acceptedTxs)
			//todo(ABE): for ABE, sm does not need to sm.peerNotifier.AnnounceNewTransactions(acceptedTx),
			// as tx is propagated with blocks, and may be announced when verify the block.
		}

		// Register block with the fee estimator, if it exists.
		if sm.feeEstimator != nil {
			err := sm.feeEstimator.RegisterBlock(block)

			// If an error is somehow generated then the fee estimator
			// has entered an invalid state. Since it doesn't know how
			// to recover, create a new one.
			if err != nil {
				sm.feeEstimator = mempool.NewFeeEstimator(
					mempool.DefaultEstimateFeeMaxRollback,
					mempool.DefaultEstimateFeeMinRegisteredBlocks)
			}
		}

	// A block has been disconnected from the main block chain.
	case blockchain.NTBlockDisconnected:
		block, ok := notification.Data.(*abeutil.BlockAbe)
		if !ok {
			log.Warnf("Chain disconnected notification is not a block.")
			break
		}

		// Reinsert all of the transactions (except the coinbase) into
		// the transaction pool.
		for _, tx := range block.Transactions()[1:] {
			_, _, err := sm.txMemPool.MaybeAcceptTransactionAbe(tx,
				false, false)
			if err != nil {
				// Remove the transaction and all transactions
				// that depend on it if it wasn't accepted into
				// the transaction pool.
				sm.txMemPool.RemoveTransactionAbe(tx)
			}
		}

		// Rollback previous block recorded by the fee estimator.
		if sm.feeEstimator != nil {
			sm.feeEstimator.Rollback(block.Hash())
		}

	case blockchain.NTInvalidRing:
		hashs, ok := notification.Data.([]chainhash.Hash)
		if !ok {
			log.Warnf("Chain disconnected notification is not a slice of chainhash.Hash.")
			break
		}
		// In Abelian, remove a block means those transactions dependent
		// to the rings generated by this block would be invalid
		// So this situation should be handled in here.
		for i := 0; i < len(hashs); i++ {
			// Lastly, remove the transaction depends on those ring hash
			// at help of map wire.TxPool.outpointsAbe
			sm.txMemPool.RemoveTransactionAbeByRingHash(hashs[i])
		}
	}
}

// NewPeer informs the sync manager of a newly active peer.
func (sm *SyncManager) NewPeer(peer *peerpkg.Peer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return
	}
	sm.msgChan <- &newPeerMsg{peer: peer}
}

// QueueTx adds the passed transaction message and peer to the block handling
// queue. Responds to the done channel argument after the tx message is
// processed.
//func (sm *SyncManager) QueueTx(tx *abeutil.Tx, peer *peerpkg.Peer, done chan struct{}) {
//	// Don't accept more transactions if we're shutting down.
//	if atomic.LoadInt32(&sm.shutdown) != 0 {
//		done <- struct{}{}
//		return
//	}
//
//	sm.msgChan <- &txMsg{tx: tx, peer: peer, reply: done}
//}

func (sm *SyncManager) QueueTxAbe(tx *abeutil.TxAbe, peer *peerpkg.Peer, done chan struct{}) {
	// Don't accept more transactions if we're shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		done <- struct{}{}
		return
	}

	sm.msgChan <- &txMsgAbe{tx: tx, peer: peer, reply: done}
}

// QueueBlock adds the passed block message and peer to the block handling
// queue. Responds to the done channel argument after the block message is
// processed.
//	todo(ABE):
//func (sm *SyncManager) QueueBlock(block *abeutil.Block, peer *peerpkg.Peer, done chan struct{}) {
//	// Don't accept more blocks if we're shutting down.
//	if atomic.LoadInt32(&sm.shutdown) != 0 {
//		done <- struct{}{}
//		return
//	}
//
//	sm.msgChan <- &blockMsg{block: block, peer: peer, reply: done}
//}

func (sm *SyncManager) QueueBlockAbe(block *abeutil.BlockAbe, peer *peerpkg.Peer, done chan struct{}) {
	// Don't accept more blocks if we're shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		done <- struct{}{}
		return
	}

	sm.msgChan <- &blockMsgAbe{block: block, peer: peer, reply: done}
}

func (sm *SyncManager) QueuePrunedBlock(block *abeutil.PrunedBlock, peer *peerpkg.Peer, done chan struct{}) {
	// Don't accept more blocks if we're shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		done <- struct{}{}
		return
	}

	sm.msgChan <- &prunedBlockMsg{block: block, peer: peer, reply: done}
}

//func (sm *SyncManager) QueueNeedSet(needset *abeutil.NeedSet, peer *peerpkg.Peer) {
//	// Don't accept more blocks if we're shutting down.
//	if atomic.LoadInt32(&sm.shutdown) != 0 {
//		return
//	}
//
//	sm.msgChan <- &needSetMsg{needset: needset, peer: peer}
//}
//
//func (sm *SyncManager) QueueNeedSetResult(res *abeutil.NeedSetResult, peer *peerpkg.Peer, done chan struct{}) {
//	// Don't accept more blocks if we're shutting down.
//	if atomic.LoadInt32(&sm.shutdown) != 0 {
//		done <- struct{}{}
//		return
//	}
//
//	sm.msgChan <- &needSetResultMsg{result: res, peer: peer, reply: done}
//}

// QueueInv adds the passed inv message and peer to the block handling queue.
func (sm *SyncManager) QueueInv(inv *wire.MsgInv, peer *peerpkg.Peer) {
	// No channel handling here because peers do not need to block on inv
	// messages.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return
	}

	sm.msgChan <- &invMsg{inv: inv, peer: peer}
}

// QueueHeaders adds the passed headers message and peer to the block handling
// queue.
func (sm *SyncManager) QueueHeaders(headers *wire.MsgHeaders, peer *peerpkg.Peer) {
	// No channel handling here because peers do not need to block on
	// headers messages.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return
	}

	sm.msgChan <- &headersMsg{headers: headers, peer: peer}
}

// QueueNotFound adds the passed notfound message and peer to the block handling
// queue.
func (sm *SyncManager) QueueNotFound(notFound *wire.MsgNotFound, peer *peerpkg.Peer) {
	// No channel handling here because peers do not need to block on
	// reject messages.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return
	}

	sm.msgChan <- &notFoundMsg{notFound: notFound, peer: peer}
}

// DonePeer informs the blockmanager that a peer has disconnected.
func (sm *SyncManager) DonePeer(peer *peerpkg.Peer) {
	// Ignore if we are shutting down.
	if atomic.LoadInt32(&sm.shutdown) != 0 {
		return
	}

	sm.msgChan <- &donePeerMsg{peer: peer}
}

// Start begins the core block handler which processes block and inv messages.
func (sm *SyncManager) Start() {
	// Already started?
	if atomic.AddInt32(&sm.started, 1) != 1 {
		return
	}

	log.Trace("Starting sync manager")
	sm.wg.Add(1)
	go sm.blockHandler()
}

// Stop gracefully shuts down the sync manager by stopping all asynchronous
// handlers and waiting for them to finish.
func (sm *SyncManager) Stop() error {
	if atomic.AddInt32(&sm.shutdown, 1) != 1 {
		log.Warnf("Sync manager is already in the process of " +
			"shutting down")
		return nil
	}

	log.Infof("Sync manager shutting down")
	close(sm.quit)
	sm.wg.Wait()
	return nil
}

// SyncPeerID returns the ID of the current sync peer, or 0 if there is none.
func (sm *SyncManager) SyncPeerID() int32 {
	reply := make(chan int32)
	sm.msgChan <- getSyncPeerMsg{reply: reply}
	return <-reply
}

// ProcessBlock makes use of ProcessBlock on an internal instance of a block
// chain.
//	todo(ABE):
//func (sm *SyncManager) ProcessBlockBTCD(block *abeutil.Block, flags blockchain.BehaviorFlags) (bool, error) {
//	reply := make(chan processBlockResponse, 1)
//	sm.msgChan <- processBlockMsgBTCD{block: block, flags: flags, reply: reply}
//	response := <-reply
//	return response.isOrphan, response.err
//}

func (sm *SyncManager) ProcessBlock(block *abeutil.BlockAbe, flags blockchain.BehaviorFlags) (bool, error) {
	reply := make(chan processBlockResponse, 1)
	sm.msgChan <- processBlockMsgAbe{block: block, flags: flags, reply: reply}
	response := <-reply
	return response.isOrphan, response.err
}

// IsCurrent returns whether or not the sync manager believes it is synced with
// the connected peers.
func (sm *SyncManager) IsCurrent() bool {
	reply := make(chan bool)
	sm.msgChan <- isCurrentMsg{reply: reply}
	return <-reply
}

// Pause pauses the sync manager until the returned channel is closed.
//
// Note that while paused, all peer and block processing is halted.  The
// message sender should avoid pausing the sync manager for long durations.
func (sm *SyncManager) Pause() chan<- struct{} {
	c := make(chan struct{})
	sm.msgChan <- pauseMsg{c}
	return c
}

// New constructs a new SyncManager. Use Start to begin processing asynchronous
// block, tx, and inv updates.
func New(config *Config) (*SyncManager, error) {
	sm := SyncManager{
		nodeType:        config.NodeType,
		peerNotifier:    config.PeerNotifier,
		chain:           config.Chain,
		txMemPool:       config.TxMemPool,
		ethash:          config.Ethash, // todo: (EthashPoW)
		chainParams:     config.ChainParams,
		rejectedTxns:    make(map[chainhash.Hash]struct{}),
		requestedTxns:   make(map[chainhash.Hash]struct{}),
		requestedBlocks: make(map[chainhash.Hash]struct{}),
		peerStates:      make(map[*peerpkg.Peer]*peerSyncState),
		progressLogger:  newBlockProgressLogger("Processed", log),
		msgChan:         make(chan interface{}, config.MaxPeers*3),
		headerList:      list.New(),
		quit:            make(chan struct{}),
		feeEstimator:    config.FeeEstimator,
	}

	best := sm.chain.BestSnapshot()
	if !config.DisableCheckpoints {
		// Initialize the next checkpoint based on the current height.
		sm.nextCheckpoint = sm.findNextHeaderCheckpoint(best.Height)
		if sm.nextCheckpoint != nil {
			sm.resetHeaderState(&best.Hash, best.Height)
		}
	} else {
		log.Info("Checkpoints are disabled")
	}

	sm.chain.Subscribe(sm.handleBlockchainNotification)

	return &sm, nil
}

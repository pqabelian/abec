package syncmgr

import (
	"fmt"
	"time"

	"github.com/pqabelian/abec/abeutil"
	"github.com/pqabelian/abec/blockchain"
	"github.com/pqabelian/abec/blockchain/ruleerror"
	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/chainhash"
	peerpkg "github.com/pqabelian/abec/peer"
	"github.com/pqabelian/abec/wire"
)

const (
	// The deadline covers both local request queuing and remote responses.
	missingBlockTxTimeout = 30 * time.Second
	// Bound supplemental messages in the peer queue for each reconstruction.
	maxPendingBlockTxRequests = 16
)

// All reconstruction state belongs to blockHandler, including timer cleanup.
type pendingPrunedBlock struct {
	hash          chainhash.Hash
	msg           *prunedBlockMsg
	transactions  map[chainhash.Hash]*wire.MsgTxAbe
	missing       map[chainhash.Hash]chainhash.Hash // Transaction hash -> committed witness hash.
	useGetBlockTx bool
	unrequested   []chainhash.Hash
	inFlight      int // Queued or sent getblocktx requests, awaiting responses.
	timer         *time.Timer
	baseSize      uint64
	fullSize      uint64
}

type needSetResultMsg struct {
	result *wire.MsgNeedSetResult
	peer   *peerpkg.Peer
}

type blockTxMsg struct {
	result *wire.MsgBlockTx
	peer   *peerpkg.Peer
}

type prunedBlockTimeoutMsg struct {
	peer    *peerpkg.Peer
	hash    chainhash.Hash
	pending *pendingPrunedBlock
}

func (sm *SyncManager) notifyPrunedBlockProcessed(msg *prunedBlockMsg) {
	if msg.reply != nil {
		// Deliver buffered completion even when shutdown is already ready.
		select {
		case msg.reply <- struct{}{}:
			return
		default:
		}
		select {
		case msg.reply <- struct{}{}:
		case <-sm.quit:
		}
	}
}

func (sm *SyncManager) handlePrunedBlockMsgAbe(msg *prunedBlockMsg) {
	state, exists := sm.peerStates[msg.peer]
	if !exists {
		sm.notifyPrunedBlockProcessed(msg)
		return
	}
	hash := *msg.block.Hash()
	if _, requested := state.requestedBlocks[hash]; !requested &&
		sm.chainParams != &chaincfg.RegressionNetParams {
		log.Warnf("Received unrequested pruned block %v from %v", hash, msg.peer)
		msg.peer.Disconnect()
		sm.notifyPrunedBlockProcessed(msg)
		return
	}
	if sm.pendingPrunedBlockFor(msg.peer, hash) != nil {
		log.Warnf("Received duplicate pruned block %v from %v", hash, msg.peer)
		msg.peer.Disconnect()
		sm.notifyPrunedBlockProcessed(msg)
		return
	}
	if sm.pendingPrunedBlock != nil {
		getData := wire.NewMsgGetData()
		getData.AddInvVect(wire.NewInvVect(wire.InvTypeWitnessBlock, &hash))
		msg.peer.QueueMessage(getData, nil)
		sm.notifyPrunedBlockProcessed(msg)
		return
	}

	pending, err := sm.preparePrunedBlock(msg)
	if err != nil {
		if ruleErr, ok := err.(ruleerror.RuleError); ok && ruleErr.ErrorCode == ruleerror.ErrPreviousBlockUnknown {
			// Out-of-order blocks are legitimate. Let the ordinary block path
			// handle the orphan without starting supplemental requests.
			getData := wire.NewMsgGetData()
			getData.AddInvVect(wire.NewInvVect(wire.InvTypeWitnessBlock, &hash))
			msg.peer.QueueMessage(getData, nil)
			sm.notifyPrunedBlockProcessed(msg)
			return
		}
		log.Warnf("Cannot reconstruct pruned block %v from %v: %v", hash, msg.peer, err)
		delete(state.requestedBlocks, hash)
		delete(sm.requestedBlocks, hash)
		sm.notifyPrunedBlockProcessed(msg)
		msg.peer.Disconnect()
		return
	}
	sm.pendingPrunedBlock = pending
	if len(pending.missing) == 0 {
		sm.completePrunedBlock(state, hash)
		return
	}

	peer := msg.peer
	pending.timer = time.AfterFunc(missingBlockTxTimeout, func() {
		sm.enqueueMessage(&prunedBlockTimeoutMsg{peer, hash, pending})
	})
	if pending.useGetBlockTx {
		sm.requestPrunedBlockTxs(pending)
	} else {
		peer.QueueMessage(wire.NewMsgNeedSet(hash, pending.unrequested), nil)
	}
}

func (sm *SyncManager) pendingPrunedBlockFor(peer *peerpkg.Peer, hash chainhash.Hash) *pendingPrunedBlock {
	pending := sm.pendingPrunedBlock
	if pending != nil && pending.msg.peer == peer && pending.hash == hash {
		return pending
	}
	return nil
}

// preparePrunedBlock uses the same size accounting as MsgBlockAbe.SerializeSize
// and SerializeSizeStripped. Missing transactions also bound metadata growth.
func (sm *SyncManager) preparePrunedBlock(msg *prunedBlockMsg) (*pendingPrunedBlock, error) {
	block := msg.block.MsgPrunedBlock()
	if block.CoinbaseTx == nil {
		return nil, fmt.Errorf("missing coinbase transaction")
	}
	count := uint64(len(block.TransactionHashes)) + 1
	headerSize := uint64(block.Header.SerializeSize() + wire.VarIntSerializeSize(count))
	if count > (blockchain.MaxBlockBaseSizeMLPAUT-headerSize)/wire.MinTxAbePayload {
		return nil, fmt.Errorf("too many transactions for a block")
	}
	pending := &pendingPrunedBlock{
		hash:          *msg.block.Hash(),
		msg:           msg,
		transactions:  make(map[chainhash.Hash]*wire.MsgTxAbe),
		missing:       make(map[chainhash.Hash]chainhash.Hash),
		useGetBlockTx: msg.peer.UseGetBlockTx(),
		baseSize:      headerSize + uint64(block.CoinbaseTx.SerializeSize()),
		fullSize:      headerSize + uint64(block.CoinbaseTx.SerializeSizeFull()),
	}
	if pending.baseSize > blockchain.MaxBlockBaseSizeMLPAUT || pending.fullSize > wire.MaxBlockPayloadAbe {
		return nil, fmt.Errorf("coinbase exceeds block size limit")
	}
	coinbaseHash := block.CoinbaseTx.TxHash()
	for _, hash := range block.TransactionHashes {
		if _, duplicate := pending.missing[hash]; duplicate || hash == coinbaseHash {
			return nil, fmt.Errorf("duplicate transaction hash")
		}
		pending.missing[hash] = chainhash.Hash{}
	}
	if err := sm.chain.CheckPrunedBlock(block, sm.powConsensus); err != nil {
		return nil, err
	}
	for i, txHash := range block.TransactionHashes {
		pending.missing[txHash] = block.WitnessHashs[i]
		if tx, err := sm.txMemPool.FetchTransaction(&txHash); err == nil && tx.MsgTx().HasTxWitness() &&
			*tx.MsgTx().TxWitnessHash() == block.WitnessHashs[i] {
			if !addPrunedBlockTx(pending, tx.MsgTx()) {
				return nil, fmt.Errorf("mempool transaction exceeds block size limit")
			}
		} else {
			pending.unrequested = append(pending.unrequested, txHash)
		}
	}
	return pending, nil
}

// Keep only a bounded window in the peer queue, replenished by responses.
// The overall deadline also expires when none of this window can be sent.
func (sm *SyncManager) requestPrunedBlockTxs(pending *pendingPrunedBlock) {
	for pending.inFlight < maxPendingBlockTxRequests && len(pending.unrequested) > 0 {
		txHash := pending.unrequested[0]
		pending.unrequested = pending.unrequested[1:]
		pending.inFlight++
		pending.msg.peer.QueueMessage(wire.NewMsgGetBlockTx(pending.hash, txHash), nil)
	}
}

func (sm *SyncManager) finishPrunedBlockRequest(peer *peerpkg.Peer, hash chainhash.Hash) {
	pending := sm.pendingPrunedBlockFor(peer, hash)
	if pending == nil {
		return
	}
	sm.pendingPrunedBlock = nil
	if pending.timer != nil {
		pending.timer.Stop()
	}
	sm.notifyPrunedBlockProcessed(pending.msg)
	// A timer callback may already be queued. Leave only its identity token,
	// so it cannot keep the block and transactions alive after cleanup.
	pending.msg, pending.transactions, pending.missing = nil, nil, nil
	pending.unrequested = nil
}

func (sm *SyncManager) handlePrunedBlockTimeoutMsg(msg *prunedBlockTimeoutMsg) {
	state, exists := sm.peerStates[msg.peer]
	if !exists || sm.pendingPrunedBlock != msg.pending {
		return
	}
	log.Infof("Pruned block reconstruction deadline expired for %v with peer %v", msg.hash, msg.peer)
	// Local quota pressure can also cause expiry. Reset the connection to
	// discard unsent requests and credits; this is not a misbehavior penalty.
	sm.finishPrunedBlockRequest(msg.peer, msg.hash)
	delete(state.requestedBlocks, msg.hash)
	delete(sm.requestedBlocks, msg.hash)
	msg.peer.Disconnect()
}

func (sm *SyncManager) handleNeedSetResultMsg(msg *needSetResultMsg) {
	state, exists := sm.peerStates[msg.peer]
	if !exists {
		return
	}
	pending := sm.pendingPrunedBlockFor(msg.peer, msg.result.BlockHash)
	if pending == nil || pending.useGetBlockTx || len(msg.result.Txs) != len(pending.missing) {
		log.Warnf("Received unexpected needset response for block %v from %v", msg.result.BlockHash, msg.peer)
		sm.clearRequestedState(msg.peer, state)
		msg.peer.Disconnect()
		return
	}
	for _, tx := range msg.result.Txs {
		if !addPrunedBlockTx(pending, tx) {
			log.Warnf("Received invalid needset transaction for block %v from %v", msg.result.BlockHash, msg.peer)
			sm.clearRequestedState(msg.peer, state)
			msg.peer.Disconnect()
			return
		}
	}
	sm.completePrunedBlock(state, msg.result.BlockHash)
}

func (sm *SyncManager) handleBlockTxMsg(msg *blockTxMsg) {
	state, exists := sm.peerStates[msg.peer]
	if !exists {
		return
	}
	pending := sm.pendingPrunedBlockFor(msg.peer, msg.result.BlockHash)
	if pending == nil || !pending.useGetBlockTx || !addPrunedBlockTx(pending, msg.result.Tx) {
		log.Warnf("Received unexpected or invalid blocktx for block %v from %v", msg.result.BlockHash, msg.peer)
		sm.clearRequestedState(msg.peer, state)
		msg.peer.Disconnect()
		return
	}
	pending.inFlight--
	if len(pending.missing) == 0 {
		sm.completePrunedBlock(state, msg.result.BlockHash)
	} else {
		sm.requestPrunedBlockTxs(pending)
	}
}

func addPrunedBlockTx(pending *pendingPrunedBlock, tx *wire.MsgTxAbe) bool {
	if tx == nil || !tx.HasTxWitness() {
		return false
	}
	hash := tx.TxHash()
	witnessHash, requested := pending.missing[hash]
	if !requested || *tx.TxWitnessHash() != witnessHash {
		return false
	}
	baseSize, fullSize := uint64(tx.SerializeSize()), uint64(tx.SerializeSizeFull())
	if baseSize > blockchain.MaxBlockBaseSizeMLPAUT-pending.baseSize ||
		fullSize > wire.MaxBlockPayloadAbe-pending.fullSize {
		return false
	}
	pending.baseSize += baseSize
	pending.fullSize += fullSize
	pending.transactions[hash] = tx
	delete(pending.missing, hash)
	return true
}

func restorePrunedBlock(msg *wire.MsgPrunedBlock, transactions map[chainhash.Hash]*wire.MsgTxAbe) (*abeutil.BlockAbe, error) {
	if msg.CoinbaseTx == nil || !msg.CoinbaseTx.HasTxWitness() {
		return nil, fmt.Errorf("pruned block coinbase has no witness")
	}
	block := &wire.MsgBlockAbe{
		Header:       msg.Header,
		Transactions: []*wire.MsgTxAbe{msg.CoinbaseTx},
		WitnessHashs: []*chainhash.Hash{msg.CoinbaseTx.TxWitnessHash()},
	}
	for _, hash := range msg.TransactionHashes {
		tx := transactions[hash]
		if tx == nil || !tx.HasTxWitness() {
			return nil, fmt.Errorf("missing transaction or witness for %v", hash)
		}
		block.Transactions = append(block.Transactions, tx)
		block.WitnessHashs = append(block.WitnessHashs, tx.TxWitnessHash())
	}
	return abeutil.NewBlockAbe(block)
}

func (sm *SyncManager) completePrunedBlock(state *peerSyncState, hash chainhash.Hash) {
	pending := sm.pendingPrunedBlock
	defer sm.finishPrunedBlockRequest(pending.msg.peer, hash)
	block, err := restorePrunedBlock(pending.msg.block.MsgPrunedBlock(), pending.transactions)
	if err != nil {
		log.Warnf("Cannot restore block %v from %v: %v", hash, pending.msg.peer, err)
		delete(state.requestedBlocks, hash)
		delete(sm.requestedBlocks, hash)
		pending.msg.peer.PushRejectMsg(wire.CmdPrunedBlock, wire.RejectInvalid, err.Error(), &hash, false)
		return
	}
	// Reuse the ordinary block path for validation, checkpoints and progress.
	sm.handleBlockMsgAbe(&blockMsgAbe{block: block, peer: pending.msg.peer})
}

// QueueNeedSetResult delivers a supplemental transaction response to the owner
// of the reconstruction state. Input handlers never access peerStates directly.
func (sm *SyncManager) QueueNeedSetResult(result *wire.MsgNeedSetResult, peer *peerpkg.Peer) <-chan struct{} {
	return sm.queueMessage(&needSetResultMsg{result: result, peer: peer})
}

// QueueBlockTx delivers a single supplemental transaction to blockHandler.
func (sm *SyncManager) QueueBlockTx(result *wire.MsgBlockTx, peer *peerpkg.Peer) <-chan struct{} {
	return sm.queueMessage(&blockTxMsg{result: result, peer: peer})
}

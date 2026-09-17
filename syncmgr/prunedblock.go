package syncmgr

import (
	"fmt"
	"time"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	peerpkg "github.com/abesuite/abec/peer"
	"github.com/abesuite/abec/wire"
)

const (
	// The deadline covers both local request queuing and remote responses.
	missingBlockTxTimeout = 30 * time.Second
	// Bound supplemental messages in the peer queue for each reconstruction.
	maxPendingBlockTxRequests = 16
	// Bound the blocks retained while waiting for supplemental transactions.
	// Additional blocks are requested in full and use the normal block path.
	maxPendingPrunedBlocksPerPeer = 10
)

// All reconstruction state belongs to blockHandler, including timer cleanup.
type pendingPrunedBlock struct {
	msg           *prunedBlockMsg
	transactions  map[chainhash.Hash]*wire.MsgTxAbe
	missing       map[chainhash.Hash]struct{}
	useGetBlockTx bool
	unrequested   []chainhash.Hash
	inFlight      int // Queued or sent getblocktx requests, awaiting responses.
	timer         *time.Timer
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
	if _, exists := state.pendingPrunedBlocks[hash]; exists {
		log.Warnf("Received duplicate pruned block %v from %v", hash, msg.peer)
		msg.peer.Disconnect()
		sm.notifyPrunedBlockProcessed(msg)
		return
	}
	if len(state.pendingPrunedBlocks) >= maxPendingPrunedBlocksPerPeer {
		getData := wire.NewMsgGetData()
		getData.AddInvVect(wire.NewInvVect(wire.InvTypeWitnessBlock, &hash))
		msg.peer.QueueMessage(getData, nil)
		sm.notifyPrunedBlockProcessed(msg)
		return
	}

	pending := &pendingPrunedBlock{
		msg:           msg,
		transactions:  make(map[chainhash.Hash]*wire.MsgTxAbe),
		missing:       make(map[chainhash.Hash]struct{}),
		useGetBlockTx: msg.peer.UseGetBlockTx(),
	}
	var missing []chainhash.Hash
	for _, txHash := range msg.block.MsgPrunedBlock().TransactionHashes {
		if tx, err := sm.txMemPool.FetchTransaction(&txHash); err == nil && tx.MsgTx().HasTxWitness() {
			pending.transactions[txHash] = tx.MsgTx()
		} else if _, requested := pending.missing[txHash]; !requested {
			pending.missing[txHash] = struct{}{}
			missing = append(missing, txHash)
		}
	}
	state.pendingPrunedBlocks[hash] = pending
	if len(missing) == 0 {
		sm.completePrunedBlock(state, hash)
		return
	}

	peer := msg.peer
	pending.timer = time.AfterFunc(missingBlockTxTimeout, func() {
		select {
		case sm.msgChan <- &prunedBlockTimeoutMsg{peer, hash, pending}:
		case <-sm.quit:
		}
	})
	if pending.useGetBlockTx {
		pending.unrequested = missing
		sm.requestPrunedBlockTxs(pending)
	} else {
		peer.QueueMessage(wire.NewMsgNeedSet(hash, missing), nil)
	}
}

// Keep only a bounded window in the peer queue, replenished by responses.
// The overall deadline also expires when none of this window can be sent.
func (sm *SyncManager) requestPrunedBlockTxs(pending *pendingPrunedBlock) {
	for pending.inFlight < maxPendingBlockTxRequests && len(pending.unrequested) > 0 {
		txHash := pending.unrequested[0]
		pending.unrequested = pending.unrequested[1:]
		pending.inFlight++
		pending.msg.peer.QueueMessage(wire.NewMsgGetBlockTx(*pending.msg.block.Hash(), txHash), nil)
	}
}

func (sm *SyncManager) finishPrunedBlockRequest(state *peerSyncState, hash chainhash.Hash) {
	pending, exists := state.pendingPrunedBlocks[hash]
	if !exists {
		return
	}
	delete(state.pendingPrunedBlocks, hash)
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
	if !exists || state.pendingPrunedBlocks[msg.hash] != msg.pending {
		return
	}
	log.Infof("Pruned block reconstruction deadline expired for %v with peer %v", msg.hash, msg.peer)
	// Local quota pressure can also cause expiry. Reset the connection to
	// discard unsent requests and credits; this is not a misbehavior penalty.
	sm.finishPrunedBlockRequest(state, msg.hash)
	delete(state.requestedBlocks, msg.hash)
	delete(sm.requestedBlocks, msg.hash)
	msg.peer.Disconnect()
}

func (sm *SyncManager) handleNeedSetResultMsg(msg *needSetResultMsg) {
	state, exists := sm.peerStates[msg.peer]
	if !exists {
		return
	}
	pending := state.pendingPrunedBlocks[msg.result.BlockHash]
	if pending == nil || pending.useGetBlockTx || len(msg.result.Txs) != len(pending.missing) {
		log.Warnf("Received unexpected needset response for block %v from %v", msg.result.BlockHash, msg.peer)
		msg.peer.Disconnect()
		return
	}
	for _, tx := range msg.result.Txs {
		if !addPrunedBlockTx(pending, tx) {
			log.Warnf("Received invalid needset transaction for block %v from %v", msg.result.BlockHash, msg.peer)
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
	pending := state.pendingPrunedBlocks[msg.result.BlockHash]
	if pending == nil || !pending.useGetBlockTx || !addPrunedBlockTx(pending, msg.result.Tx) {
		log.Warnf("Received unexpected or invalid blocktx for block %v from %v", msg.result.BlockHash, msg.peer)
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
	if _, requested := pending.missing[hash]; !requested {
		return false
	}
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
	pending := state.pendingPrunedBlocks[hash]
	defer sm.finishPrunedBlockRequest(state, hash)
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
func (sm *SyncManager) QueueNeedSetResult(result *wire.MsgNeedSetResult, peer *peerpkg.Peer) {
	select {
	case sm.msgChan <- &needSetResultMsg{result: result, peer: peer}:
	case <-sm.quit:
	}
}

// QueueBlockTx delivers a single supplemental transaction to blockHandler.
func (sm *SyncManager) QueueBlockTx(result *wire.MsgBlockTx, peer *peerpkg.Peer) {
	select {
	case sm.msgChan <- &blockTxMsg{result: result, peer: peer}:
	case <-sm.quit:
	}
}

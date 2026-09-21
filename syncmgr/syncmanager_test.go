package syncmgr

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	_ "github.com/abesuite/abec/database/ffldb"
	"github.com/abesuite/abec/mempool"
	peerpkg "github.com/abesuite/abec/peer"
	"github.com/abesuite/abec/wire"
)

func init() {
	DisableLog()
}

func testSyncManager(t *testing.T) (*SyncManager, *peerpkg.Peer) {
	t.Helper()
	p := peerpkg.NewInboundPeer(&peerpkg.Config{})
	sm := &SyncManager{
		msgChan:         make(chan interface{}, 8),
		quit:            make(chan struct{}),
		chainParams:     &chaincfg.MainNetParams,
		txMemPool:       mempool.New(&mempool.Config{}),
		rejectedTxns:    make(map[chainhash.Hash]struct{}),
		requestedTxns:   make(map[chainhash.Hash]struct{}),
		requestedBlocks: make(map[chainhash.Hash]struct{}),
		peerStates:      make(map[*peerpkg.Peer]*peerSyncState),
	}
	sm.handleNewPeerMsg(p) // No services advertised, so no chain sync starts.
	t.Cleanup(func() { sm.Stop(); p.Disconnect() })
	return sm, p
}

func syncHandlerBarrier(t *testing.T, sm *SyncManager) {
	t.Helper()
	done := make(chan int32, 1)
	sm.msgChan <- getSyncPeerMsg{reply: done}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("sync handler blocked while waiting for network data")
	}
}

func TestNotFoundReleasesOnlyRequestedInventory(t *testing.T) {
	sm, p := testSyncManager(t)
	txHash, blockHash, otherHash := chainhash.Hash{1}, chainhash.Hash{2}, chainhash.Hash{3}
	state := sm.peerStates[p]
	sm.requestedTxns[txHash], state.requestedTxns[txHash] = struct{}{}, struct{}{}
	sm.requestedTxns[otherHash] = struct{}{} // Requested from another peer.
	sm.requestedBlocks[blockHash], state.requestedBlocks[blockHash] = struct{}{}, struct{}{}
	sm.Start()
	msg := wire.NewMsgNotFound()
	msg.AddInvVect(wire.NewInvVect(wire.InvTypeWitnessTx, &txHash))
	msg.AddInvVect(wire.NewInvVect(wire.InvTypeWitnessTx, &otherHash))
	msg.AddInvVect(wire.NewInvVect(wire.InvTypePrunedBlock, &blockHash))
	sm.QueueNotFound(msg, p)
	syncHandlerBarrier(t, sm)
	sm.Stop()
	if _, exists := sm.requestedTxns[txHash]; exists {
		t.Fatal("notfound left transaction globally in flight")
	}
	if len(state.requestedTxns) != 0 || len(state.requestedBlocks) != 0 {
		t.Fatal("notfound left inventory in the peer request state")
	}
	if _, exists := sm.requestedTxns[otherHash]; !exists {
		t.Fatal("unsolicited notfound canceled another peer's request")
	}
}

func TestPrunedBlockDoesNotBlockSync(t *testing.T) {
	sm, p := testSyncManager(t)
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx.TxWitness = []byte{1}
	txHash := tx.TxHash()
	msg := testPrunedBlock(t, sm, tx)
	block := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(msg, nil)
	state := sm.peerStates[p]
	state.requestedBlocks[*block.Hash()] = struct{}{}
	sm.requestedBlocks[*block.Hash()] = struct{}{}
	sm.rejectedTxns[txHash] = struct{}{} // Exercise ordinary tx dispatch without consensus setup.
	sm.Start()
	blockDone := make(chan struct{}, 1)
	admitted := sm.QueuePrunedBlock(block, p, blockDone)
	select {
	case <-admitted:
	case <-time.After(2 * time.Second):
		t.Fatal("pruned admission waited for supplemental responses")
	}
	select {
	case <-blockDone:
		t.Fatal("incomplete pruned block was marked processed")
	default:
	}
	ordinaryTx, err := abeutil.NewTxAbe(tx, nil)
	if err != nil {
		t.Fatal(err)
	}
	txDone := make(chan struct{}, 1)
	sm.QueueTxAbe(ordinaryTx, p, txDone)
	select {
	case <-txDone:
	case <-time.After(2 * time.Second):
		t.Fatal("ordinary transaction blocked behind supplemental download")
	}
	// Shutdown must cancel reconstruction and stop its timer without waiting
	// for the remote peer or the 30-second network timeout.
	sm.Stop()
	if sm.pendingPrunedBlock != nil {
		t.Fatal("shutdown retained pending reconstruction")
	}
}

func TestPrunedBlockResponseValidationAndTimeout(t *testing.T) {
	sm, p := testSyncManager(t)
	state := sm.peerStates[p]
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx.TxWitness = []byte{1}
	txHash, blockHash := tx.TxHash(), chainhash.Hash{1}
	pending := &pendingPrunedBlock{
		hash:         blockHash,
		msg:          &prunedBlockMsg{peer: p},
		transactions: make(map[chainhash.Hash]*wire.MsgTxAbe),
		missing:      map[chainhash.Hash]chainhash.Hash{txHash: *tx.TxWitnessHash()},
	}
	if addPrunedBlockTx(pending, wire.NewMsgTxAbe(wire.TxVersion_Height_0)) {
		t.Fatal("accepted a transaction without witness")
	}
	if !addPrunedBlockTx(pending, tx) || addPrunedBlockTx(pending, tx) {
		t.Fatal("requested transaction must be accepted exactly once")
	}
	sm.pendingPrunedBlock = pending
	state.requestedBlocks[blockHash] = struct{}{}
	sm.requestedBlocks[blockHash] = struct{}{}
	sm.handlePrunedBlockTimeoutMsg(&prunedBlockTimeoutMsg{p, blockHash, &pendingPrunedBlock{}})
	if sm.pendingPrunedBlock != pending {
		t.Fatal("stale timeout removed a newer request")
	}
	sm.handlePrunedBlockTimeoutMsg(&prunedBlockTimeoutMsg{p, blockHash, pending})
	if sm.pendingPrunedBlock != nil || len(state.requestedBlocks) != 0 || len(sm.requestedBlocks) != 0 {
		t.Fatal("timeout failed to release request state")
	}
}

func TestPrunedBlockDeadlineCoversUnsentRequests(t *testing.T) {
	sm, p := testSyncManager(t)
	state := sm.peerStates[p]
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx.TxWitness = []byte{1}
	msg := testPrunedBlock(t, sm, tx)
	block := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(msg, nil)
	hash := *block.Hash()
	state.requestedBlocks[hash], sm.requestedBlocks[hash] = struct{}{}, struct{}{}
	done := make(chan struct{}, 1)
	// This peer has no connection or output handler: no request can be sent.
	sm.handlePrunedBlockMsgAbe(&prunedBlockMsg{block: block, peer: p, reply: done})
	pending := sm.pendingPrunedBlock
	if pending == nil || pending.timer == nil {
		t.Fatal("unsent reconstruction has no overall deadline")
	}
	// Fire the real callback without waiting thirty seconds.
	pending.timer.Reset(0)
	select {
	case event := <-sm.msgChan:
		timeout, ok := event.(*prunedBlockTimeoutMsg)
		if !ok {
			t.Fatalf("unexpected event %T", event)
		}
		sm.handlePrunedBlockTimeoutMsg(timeout)
	case <-time.After(2 * time.Second):
		t.Fatal("deadline waited for request send completion")
	}
	select {
	case <-done:
	default:
		t.Fatal("deadline did not notify reconstruction completion")
	}
	if sm.pendingPrunedBlock != nil || len(state.requestedBlocks) != 0 || len(sm.requestedBlocks) != 0 {
		t.Fatal("deadline retained request state")
	}
	if pending.msg != nil || pending.transactions != nil || pending.missing != nil {
		t.Fatal("stale timer event retains reconstruction data")
	}
}

func TestPrunedBlockSupplementalWindow(t *testing.T) {
	sm, p := testSyncManager(t)
	msg := &wire.MsgPrunedBlock{Header: chaincfg.MainNetParams.GenesisBlock.Header}
	block := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(msg, nil)
	pending := &pendingPrunedBlock{
		hash:         *block.Hash(),
		msg:          &prunedBlockMsg{block: block, peer: p},
		transactions: make(map[chainhash.Hash]*wire.MsgTxAbe),
		missing:      make(map[chainhash.Hash]chainhash.Hash),
	}
	var first *wire.MsgTxAbe
	for i := 0; i < 2*maxPendingBlockTxRequests; i++ {
		tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
		tx.TxMemo, tx.TxWitness = []byte{byte(i)}, []byte{1}
		if i == 0 {
			first = tx
		}
		hash := tx.TxHash()
		pending.missing[hash] = *tx.TxWitnessHash()
		pending.unrequested = append(pending.unrequested, hash)
	}
	sm.pendingPrunedBlock = pending
	sm.requestPrunedBlockTxs(pending)
	if pending.inFlight != maxPendingBlockTxRequests || len(pending.unrequested) != maxPendingBlockTxRequests {
		t.Fatal("all missing transactions were queued instead of a bounded window")
	}
	sm.handleBlockTxMsg(&blockTxMsg{result: wire.NewMsgBlockTx(*block.Hash(), first), peer: p})
	if pending.inFlight != maxPendingBlockTxRequests || len(pending.unrequested) != maxPendingBlockTxRequests-1 {
		t.Fatal("response did not replenish exactly one request")
	}
	sm.finishPrunedBlockRequest(p, *block.Hash())
	if pending.unrequested != nil {
		t.Fatal("cleanup retained the unsent transaction queue")
	}
}

func TestRestorePrunedBlockTransactionOrder(t *testing.T) {
	coinbase := *chaincfg.MainNetParams.GenesisBlock.Transactions[0]
	coinbase.TxWitness = []byte{1}
	tx1 := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx1.TxWitness = []byte{2}
	tx2 := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx2.TxMemo, tx2.TxWitness = []byte{3}, []byte{4}
	h1, h2 := tx1.TxHash(), tx2.TxHash()
	msg := &wire.MsgPrunedBlock{
		Header: chaincfg.MainNetParams.GenesisBlock.Header, CoinbaseTx: &coinbase,
		TransactionHashes: []chainhash.Hash{h2, h1},
	}
	block, err := restorePrunedBlock(msg, map[chainhash.Hash]*wire.MsgTxAbe{h1: tx1, h2: tx2})
	if err != nil {
		t.Fatal(err)
	}
	if block.MsgBlock().Transactions[1] != tx2 || block.MsgBlock().Transactions[2] != tx1 {
		t.Fatal("restored order differs from pruned block order")
	}
	if _, err := restorePrunedBlock(msg, map[chainhash.Hash]*wire.MsgTxAbe{h1: tx1}); err == nil {
		t.Fatal("restored an incomplete block")
	}
}

func TestConcurrentPeerLifecycleAndSupplementalResponses(t *testing.T) {
	sm, p := testSyncManager(t)
	sm.Start()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			sm.NewPeer(p)
			sm.DonePeer(p)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			sm.QueueBlockTx(wire.NewMsgBlockTx(chainhash.Hash{}, nil), p)
		}
	}()
	wg.Wait()
	syncHandlerBarrier(t, sm)
}

func TestSupplementalResponsesCompleteBlock(t *testing.T) {
	sm, p := testSyncManager(t)
	tx1 := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx1.TxWitness = []byte{2}
	tx2 := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx2.TxMemo, tx2.TxWitness = []byte{3}, []byte{4}
	// The header is valid; full validation later rejects these empty bodies.
	msg := testPrunedBlock(t, sm, tx1, tx2)
	block := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(msg, nil)
	hash := *block.Hash()
	state := sm.peerStates[p]
	state.requestedBlocks[hash], sm.requestedBlocks[hash] = struct{}{}, struct{}{}
	done := make(chan struct{}, 1)
	sm.handlePrunedBlockMsgAbe(&prunedBlockMsg{block: block, peer: p, reply: done})
	if sm.pendingPrunedBlock == nil || sm.pendingPrunedBlock.inFlight != 2 {
		t.Fatal("valid header did not start single-transaction supplements")
	}
	sm.Start()
	defer sm.Stop()
	// Responses may arrive in a different order from the block.
	sm.QueueBlockTx(wire.NewMsgBlockTx(hash, tx2), p)
	syncHandlerBarrier(t, sm)
	select {
	case <-done:
		t.Fatal("partial response completed the block")
	default:
	}
	sm.QueueBlockTx(wire.NewMsgBlockTx(hash, tx1), p)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supplemental responses did not complete reconstruction")
	}
	sm.Stop()
	if sm.pendingPrunedBlock != nil || len(state.requestedBlocks) != 0 || len(sm.requestedBlocks) != 0 {
		t.Fatal("completed reconstruction retained request state")
	}
}

func TestUnrequestedNotFoundPreservesQueuedBlock(t *testing.T) {
	sm, p := testSyncManager(t)
	state := sm.peerStates[p]
	sent, queued := chainhash.Hash{1}, chainhash.Hash{2}
	for _, hash := range []chainhash.Hash{sent, queued} {
		state.requestedBlocks[hash], sm.requestedBlocks[hash] = struct{}{}, struct{}{}
	}
	requests := wire.NewMessageRequests()
	defer requests.Close()
	gd := wire.NewMsgGetData()
	gd.AddInvVect(wire.NewInvVect(wire.InvTypeWitnessBlock, &sent))
	requests.Add(gd) // The second block is still queued and has not been sent.
	nf := wire.NewMsgNotFound()
	nf.AddInvVect(gd.InvList[0])
	nf.AddInvVect(gd.InvList[0])
	nf.AddInvVect(wire.NewInvVect(wire.InvTypeWitnessBlock, &queued))
	var b bytes.Buffer
	if err := wire.WriteMessage(&b, nf, wire.ProtocolVersion, wire.MainNet); err != nil {
		t.Fatal(err)
	}
	_, decoded, _, err := wire.ReadMessageWithRequestsN(&b, wire.ProtocolVersion, wire.MainNet, wire.BaseEncoding, requests)
	if err != nil {
		t.Fatal(err)
	}
	sm.handleNotFoundMsg(&notFoundMsg{notFound: decoded.(*wire.MsgNotFound), peer: p})
	if _, ok := state.requestedBlocks[sent]; ok {
		t.Fatal("matching notfound did not cancel the sent request")
	}
	if _, ok := state.requestedBlocks[queued]; !ok {
		t.Fatal("unrequested notfound canceled inventory still waiting for quota")
	}
	if _, ok := sm.requestedBlocks[queued]; !ok {
		t.Fatal("unrequested notfound canceled the global sync request")
	}
}

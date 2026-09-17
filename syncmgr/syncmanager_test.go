package syncmgr

import (
	"bytes"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/database"
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
	msg := &wire.MsgPrunedBlock{
		Header:            chaincfg.MainNetParams.GenesisBlock.Header,
		CoinbaseTx:        chaincfg.MainNetParams.GenesisBlock.Transactions[0],
		TransactionHashes: []chainhash.Hash{txHash},
	}
	block := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(msg, nil)
	state := sm.peerStates[p]
	state.requestedBlocks[*block.Hash()] = struct{}{}
	sm.requestedBlocks[*block.Hash()] = struct{}{}
	sm.rejectedTxns[txHash] = struct{}{} // Exercise ordinary tx dispatch without consensus setup.
	sm.Start()
	blockDone := make(chan struct{}, 1)
	sm.QueuePrunedBlock(block, p, blockDone)
	syncHandlerBarrier(t, sm)
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
	if len(state.pendingPrunedBlocks) != 0 {
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
		msg:          &prunedBlockMsg{peer: p},
		transactions: make(map[chainhash.Hash]*wire.MsgTxAbe),
		missing:      map[chainhash.Hash]struct{}{txHash: {}},
	}
	if addPrunedBlockTx(pending, wire.NewMsgTxAbe(wire.TxVersion_Height_0)) {
		t.Fatal("accepted a transaction without witness")
	}
	if !addPrunedBlockTx(pending, tx) || addPrunedBlockTx(pending, tx) {
		t.Fatal("requested transaction must be accepted exactly once")
	}
	state.pendingPrunedBlocks[blockHash] = pending
	state.requestedBlocks[blockHash] = struct{}{}
	sm.requestedBlocks[blockHash] = struct{}{}
	sm.handlePrunedBlockTimeoutMsg(&prunedBlockTimeoutMsg{p, blockHash, &pendingPrunedBlock{}})
	if len(state.pendingPrunedBlocks) != 1 {
		t.Fatal("stale timeout removed a newer request")
	}
	sm.handlePrunedBlockTimeoutMsg(&prunedBlockTimeoutMsg{p, blockHash, pending})
	if len(state.pendingPrunedBlocks) != 0 || len(state.requestedBlocks) != 0 || len(sm.requestedBlocks) != 0 {
		t.Fatal("timeout failed to release request state")
	}
}

func TestPrunedBlockTimeoutStartsOnSendCompletion(t *testing.T) {
	sm, p := testSyncManager(t)
	state := sm.peerStates[p]
	hash := chainhash.Hash{1}
	pending := &pendingPrunedBlock{msg: &prunedBlockMsg{peer: p}}
	state.pendingPrunedBlocks[hash] = pending
	// A completion from a previous request must not start this one's timer.
	sm.handlePrunedBlockRequestSentMsg(&prunedBlockRequestSentMsg{p, hash, &pendingPrunedBlock{}})
	if pending.timer != nil {
		t.Fatal("stale send completion started the timeout")
	}
	sent := &prunedBlockRequestSentMsg{p, hash, pending}
	sm.handlePrunedBlockRequestSentMsg(sent)
	if pending.timer == nil {
		t.Fatal("send completion did not start the timeout")
	}
	sm.finishPrunedBlockRequest(state, hash)
	if pending.timer.Stop() {
		t.Fatal("completed reconstruction left its timer running")
	}
	pending.timer = nil
	// Responses may finish before blockHandler sees the send notification.
	sm.handlePrunedBlockRequestSentMsg(sent)
	if pending.timer != nil {
		t.Fatal("late send completion restarted a finished request")
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
			sm.QueueNeedSetResult(wire.NewMsgNeedSetResult(chainhash.Hash{}, nil), p)
		}
	}()
	wg.Wait()
	syncHandlerBarrier(t, sm)
}

func TestSupplementalResponsesCompleteBlock(t *testing.T) {
	for _, singleTx := range []bool{false, true} {
		name := "needset"
		if singleTx {
			name = "blocktx"
		}
		t.Run(name, func(t *testing.T) {
			sm, p := testSyncManager(t)
			dir := t.TempDir()
			db, err := database.Create("ffldb", filepath.Join(dir, "blocks"), wire.MainNet, wire.FullNode, filepath.Join(dir, "temporary.log"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			sm.chain, err = blockchain.New(&blockchain.Config{
				DB: db, ChainParams: &chaincfg.MainNetParams, NodeType: wire.FullNode,
				TimeSource: blockchain.NewMedianTime(),
			})
			if err != nil {
				t.Fatal(err)
			}
			coinbase := *chaincfg.MainNetParams.GenesisBlock.Transactions[0]
			coinbase.TxWitness = []byte{1}
			tx1 := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
			tx1.TxWitness = []byte{2}
			tx2 := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
			tx2.TxMemo, tx2.TxWitness = []byte{3}, []byte{4}
			// The existing genesis header makes chain processing return the
			// deterministic duplicate-block result, without PoW or mining.
			msg := &wire.MsgPrunedBlock{
				Header: chaincfg.MainNetParams.GenesisBlock.Header, CoinbaseTx: &coinbase,
				TransactionHashes: []chainhash.Hash{tx1.TxHash(), tx2.TxHash()},
				WitnessHashs:      []chainhash.Hash{*tx1.TxWitnessHash(), *tx2.TxWitnessHash()},
			}
			block := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(msg, nil)
			hash := *block.Hash()
			state := sm.peerStates[p]
			state.requestedBlocks[hash], sm.requestedBlocks[hash] = struct{}{}, struct{}{}
			done := make(chan struct{}, 1)
			sm.handlePrunedBlockMsgAbe(&prunedBlockMsg{block: block, peer: p, reply: done})
			state.pendingPrunedBlocks[hash].useGetBlockTx = singleTx
			sm.Start()
			defer sm.Stop()
			if singleTx {
				// Responses may arrive in a different order from the block.
				sm.QueueBlockTx(wire.NewMsgBlockTx(hash, tx2), p)
				syncHandlerBarrier(t, sm)
				select {
				case <-done:
					t.Fatal("partial response completed the block")
				default:
				}
				sm.QueueBlockTx(wire.NewMsgBlockTx(hash, tx1), p)
			} else {
				sm.QueueNeedSetResult(wire.NewMsgNeedSetResult(hash, []*wire.MsgTxAbe{tx2, tx1}), p)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("supplemental responses did not complete reconstruction")
			}
			sm.Stop()
			if len(state.pendingPrunedBlocks) != 0 || len(state.requestedBlocks) != 0 || len(sm.requestedBlocks) != 0 {
				t.Fatal("completed reconstruction retained request state")
			}
		})
	}
}

func TestUnrequestedNotFoundPreservesQueuedBlock(t *testing.T) {
	sm, p := testSyncManager(t)
	state := sm.peerStates[p]
	sent, queued := chainhash.Hash{1}, chainhash.Hash{2}
	for _, hash := range []chainhash.Hash{sent, queued} {
		state.requestedBlocks[hash], sm.requestedBlocks[hash] = struct{}{}, struct{}{}
	}
	requests := wire.NewMessageRequests(nil)
	defer requests.Close()
	gd := wire.NewMsgGetData()
	gd.AddInvVect(wire.NewInvVect(wire.InvTypeWitnessBlock, &sent))
	requests.Add(gd) // The second block has not passed the peer's quota yet.
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

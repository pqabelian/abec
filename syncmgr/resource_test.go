package syncmgr

import (
	"bytes"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pqabelian/abec/abeutil"
	"github.com/pqabelian/abec/blockchain"
	"github.com/pqabelian/abec/chainhash"
	peerpkg "github.com/pqabelian/abec/peer"
	"github.com/pqabelian/abec/wire"
)

func TestConcurrentStartStopCompletesCleanup(t *testing.T) {
	for i := 0; i < 256; i++ {
		sm := &SyncManager{msgChan: make(chan interface{}, 1), quit: make(chan struct{})}
		receipt := sm.QueueNotFound(wire.NewMsgNotFound(), nil)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() { <-start; sm.Start() })
		wg.Go(func() { <-start; sm.Stop() })
		close(start)
		wg.Wait()
		select {
		case <-receipt:
		default:
			t.Fatal("Stop returned before cleanup completed")
		}
	}
}

func TestPrunedBlockIncrementalSize(t *testing.T) {
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_464000_Aconcagua)
	tx.TxWitness, tx.AutWitness = []byte{1}, []byte{2}
	hash := tx.TxHash()
	for _, full := range []bool{false, true} {
		pending := &pendingPrunedBlock{
			transactions: make(map[chainhash.Hash]*wire.MsgTxAbe),
			missing:      map[chainhash.Hash]chainhash.Hash{hash: *tx.TxWitnessHash()},
		}
		if full {
			pending.fullSize = wire.MaxBlockPayloadAbe - uint64(tx.SerializeSizeFull()) + 1
		} else {
			pending.baseSize = blockchain.MaxBlockBaseSizeMLPAUT - uint64(tx.SerializeSize()) + 1
		}
		if addPrunedBlockTx(pending, tx) || len(pending.transactions) != 0 || len(pending.missing) != 1 {
			t.Fatal("over-limit transaction changed reconstruction state")
		}
		if full {
			pending.fullSize--
		} else {
			pending.baseSize--
		}
		if !addPrunedBlockTx(pending, tx) {
			t.Fatal("exact-boundary transaction was rejected")
		}
	}
}

func TestPrunedBlockPreparationAndGlobalSlot(t *testing.T) {
	sm, p := testSyncManager(t)
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx.TxWitness = []byte{2}
	hash := tx.TxHash()
	pruned := testPrunedBlock(t, sm, tx)
	msg := &prunedBlockMsg{block: abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(pruned, nil), peer: p}
	pending, err := sm.preparePrunedBlock(msg)
	if err != nil || !addPrunedBlockTx(pending, tx) {
		t.Fatalf("valid reconstruction rejected: %v", err)
	}
	restored, err := restorePrunedBlock(pruned, pending.transactions)
	if err != nil || pending.fullSize != uint64(restored.MsgBlock().SerializeSize()) || pending.baseSize != uint64(restored.MsgBlock().SerializeSizeStripped()) {
		t.Fatalf("incremental size disagrees with block serialization: %v", err)
	}
	for _, hashes := range [][]chainhash.Hash{{hash, hash}, {pruned.CoinbaseTx.TxHash()}} {
		invalid := *pruned
		invalid.TransactionHashes = hashes
		if _, err := sm.preparePrunedBlock(&prunedBlockMsg{block: abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(&invalid, nil), peer: p}); err == nil {
			t.Fatal("duplicate transaction identity entered reconstruction")
		}
	}
	blockHash := *msg.block.Hash()
	sm.peerStates[p].requestedBlocks[blockHash], sm.requestedBlocks[blockHash] = struct{}{}, struct{}{}
	sm.handlePrunedBlockMsgAbe(msg)
	other := peerpkg.NewInboundPeer(&peerpkg.Config{})
	t.Cleanup(other.Disconnect)
	sm.handleNewPeerMsg(other)
	next := *pruned
	next.Header.Timestamp = next.Header.Timestamp.Add(time.Second)
	nextBlock := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(&next, nil)
	nextHash := *nextBlock.Hash()
	sm.peerStates[other].requestedBlocks[nextHash], sm.requestedBlocks[nextHash] = struct{}{}, struct{}{}
	done := make(chan struct{}, 1)
	sm.handlePrunedBlockMsgAbe(&prunedBlockMsg{block: nextBlock, peer: other, reply: done})
	if sm.pendingPrunedBlock == nil || sm.pendingPrunedBlock.msg.peer != p {
		t.Fatal("another peer bypassed the global reconstruction slot")
	}
	select {
	case <-done:
	default:
		t.Fatal("fallback retained the rejected pruned message")
	}
	owner := sm.pendingPrunedBlock
	sm.handleNeedSetResultMsg(&needSetResultMsg{result: wire.NewMsgNeedSetResult(blockHash, nil), peer: other})
	sm.handleBlockTxMsg(&blockTxMsg{result: wire.NewMsgBlockTx(blockHash, nil), peer: other})
	sm.handleDonePeerMsg(other)
	if sm.pendingPrunedBlock != owner || len(owner.missing) != 1 {
		t.Fatal("another peer changed or released the active reconstruction")
	}
	sm.handleDonePeerMsg(p)
	if sm.pendingPrunedBlock != nil || owner.msg != nil {
		t.Fatal("owner disconnect retained reconstruction data")
	}
}

func TestQueueReceiptRetainsBudgetUntilShutdownDrain(t *testing.T) {
	for _, started := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			sm, p := testSyncManager(t)
			if started {
				sm.Start()
				sm.Pause()
			}
			budget := wire.NewPayloadBudget(64, 0)
			held, _ := budget.TryReserve(32, false)
			for i := 1; i < cap(sm.msgChan); i++ {
				sm.QueueBlockTx(wire.NewMsgBlockTx(chainhash.Hash{}, nil), p)
			}
			prunedDone := make(chan struct{}, 1)
			pruned := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(&wire.MsgPrunedBlock{}, nil)
			receipt := sm.QueuePrunedBlock(pruned, p, prunedDone)
			finished := make(chan struct{})
			go func() {
				<-receipt
				held.Release()
				close(finished)
			}()
			blocked, _ := budget.TryReserve(16, false)
			blockedDone := make(chan struct{})
			go func() {
				<-sm.QueueBlockTx(wire.NewMsgBlockTx(chainhash.Hash{}, nil), p)
				blocked.Release()
				close(blockedDone)
			}()
			synctest.Wait()
			if budget.Usage() != 48 {
				t.Fatal("queue wait returned while buffered messages still owned data")
			}
			sm.Stop()
			<-blockedDone
			synctest.Wait()
			if budget.Usage() != 0 || len(sm.msgChan) != 0 {
				t.Fatal("shutdown left queued data or its reservation")
			}
			select {
			case <-finished:
			default:
				t.Fatal("shutdown stranded an admission receipt")
			}
			select {
			case <-prunedDone:
			default:
				t.Fatal("shutdown discarded a pruned block without notifying its caller")
			}
		})
	}
}

func TestQueueReceiptDoesNotWaitForLaterMessages(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sm, p := testSyncManager(t)
		first := sm.QueueNotFound(wire.NewMsgNotFound(), p)
		unpause := sm.Pause()
		sm.Start()
		synctest.Wait()
		select {
		case <-first:
		default:
			t.Fatal("message receipt waited for the later pause")
		}
		next := sm.QueueNotFound(wire.NewMsgNotFound(), p)
		select {
		case <-next:
			t.Fatal("receipt completed before its paused message was handled")
		default:
		}
		close(unpause)
		<-next
	})
}

func TestNeedSetContentsValidatedDuringQueuedProcessing(t *testing.T) {
	tx1, tx2, other := wire.NewMsgTxAbe(wire.TxVersion_Height_0), wire.NewMsgTxAbe(wire.TxVersion_Height_0), wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx1.TxMemo, tx2.TxMemo, other.TxMemo = []byte{1}, []byte{2}, []byte{3}
	tx1.TxWitness, tx2.TxWitness, other.TxWitness = []byte{1}, []byte{2}, []byte{3}
	noWitness := *tx1
	noWitness.TxWitness = nil
	for _, tc := range []struct {
		name string
		txs  []*wire.MsgTxAbe
	}{
		{"missing", []*wire.MsgTxAbe{tx1}},
		{"duplicate", []*wire.MsgTxAbe{tx1, tx1}},
		{"unexpected", []*wire.MsgTxAbe{tx1, other}},
		{"extra", []*wire.MsgTxAbe{tx1, tx2, other}},
		{"missing witness", []*wire.MsgTxAbe{&noWitness, tx2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sm, p := testSyncManager(t)
			hash := chainhash.Hash{1}
			pending := &pendingPrunedBlock{
				hash: hash, msg: &prunedBlockMsg{peer: p},
				missing:      map[chainhash.Hash]chainhash.Hash{tx1.TxHash(): *tx1.TxWitnessHash(), tx2.TxHash(): *tx2.TxWitnessHash()},
				transactions: make(map[chainhash.Hash]*wire.MsgTxAbe),
			}
			sm.pendingPrunedBlock = pending
			sm.peerStates[p].requestedBlocks[hash], sm.requestedBlocks[hash] = struct{}{}, struct{}{}
			requests := wire.NewMessageRequests(wire.NewRequestCounter(512 * 1024 * 1024))
			defer requests.Close()
			if !requests.Add(wire.NewMsgNeedSet(hash, []chainhash.Hash{tx1.TxHash(), tx2.TxHash()})) {
				t.Fatal("needset request was not admitted")
			}
			var frame bytes.Buffer
			if _, err := wire.WriteMessageWithEncodingN(&frame, wire.NewMsgNeedSetResult(hash, tc.txs), wire.ProtocolVersion, wire.MainNet, wire.WitnessEncoding); err != nil {
				t.Fatal(err)
			}
			budget := wire.NewPayloadBudget(wire.MaxMessagePayload, 0)
			_, decoded, _, held, err := wire.ReadMessageWithBudgetN(&frame, wire.ProtocolVersion, wire.MainNet, wire.WitnessEncoding, requests, budget)
			if err != nil {
				t.Fatalf("matching response did not reach reconstruction validation: %v", err)
			}
			receipt := sm.QueueNeedSetResult(decoded.(*wire.MsgNeedSetResult), p)
			released := make(chan struct{})
			go func() { <-receipt; held.Release(); close(released) }()
			if budget.Usage() != wire.MaxMessagePayload {
				t.Fatal("response released resident capacity before content validation")
			}
			sm.Start()
			<-released
			sm.Stop()
			if sm.pendingPrunedBlock != nil || len(sm.requestedBlocks) != 0 || pending.transactions != nil || budget.Usage() != 0 {
				t.Fatal("invalid contents retained reconstruction data or capacity")
			}
		})
	}
}

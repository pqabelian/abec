package syncmgr

import (
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chainhash"
	peerpkg "github.com/abesuite/abec/peer"
	"github.com/abesuite/abec/wire"
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

func TestQueueReceiptWaitsUntilShutdownDrain(t *testing.T) {
	for _, started := range []bool{false, true} {
		synctest.Test(t, func(t *testing.T) {
			sm, p := testSyncManager(t)
			if started {
				sm.Start()
				sm.Pause()
			}
			for i := 1; i < cap(sm.msgChan); i++ {
				sm.QueueBlockTx(wire.NewMsgBlockTx(chainhash.Hash{}, nil), p)
			}
			prunedDone := make(chan struct{}, 1)
			pruned := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(&wire.MsgPrunedBlock{}, nil)
			receipt := sm.QueuePrunedBlock(pruned, p, prunedDone)
			finished := make(chan struct{})
			go func() {
				<-receipt
				close(finished)
			}()
			blockedDone := make(chan struct{})
			go func() {
				<-sm.QueueBlockTx(wire.NewMsgBlockTx(chainhash.Hash{}, nil), p)
				close(blockedDone)
			}()
			synctest.Wait()
			select {
			case <-finished:
				t.Fatal("queue receipt returned before processing or shutdown")
			default:
			}
			sm.Stop()
			<-blockedDone
			synctest.Wait()
			if len(sm.msgChan) != 0 {
				t.Fatal("shutdown left queued data")
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

func TestInvalidBlockTxContentsClearReconstruction(t *testing.T) {
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx.TxWitness = []byte{1}
	noWitness := *tx
	noWitness.TxWitness = nil
	unexpected := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	unexpected.TxMemo, unexpected.TxWitness = []byte{2}, []byte{3}
	for _, bad := range []*wire.MsgTxAbe{nil, &noWitness, unexpected} {
		sm, p := testSyncManager(t)
		hash := chainhash.Hash{1}
		pending := &pendingPrunedBlock{
			hash: hash, msg: &prunedBlockMsg{peer: p},
			missing:      map[chainhash.Hash]chainhash.Hash{tx.TxHash(): *tx.TxWitnessHash()},
			transactions: make(map[chainhash.Hash]*wire.MsgTxAbe),
			inFlight:     1,
		}
		sm.pendingPrunedBlock = pending
		sm.peerStates[p].requestedBlocks[hash], sm.requestedBlocks[hash] = struct{}{}, struct{}{}
		receipt := sm.QueueBlockTx(wire.NewMsgBlockTx(hash, bad), p)
		sm.Start()
		<-receipt
		sm.Stop()
		if sm.pendingPrunedBlock != nil || len(sm.requestedBlocks) != 0 || pending.transactions != nil {
			t.Fatal("invalid blocktx retained reconstruction data")
		}
	}
}

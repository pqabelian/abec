package syncmgr

import (
	"testing"
	"time"

	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
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

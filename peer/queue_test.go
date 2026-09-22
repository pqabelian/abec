package peer

import (
	"sync"
	"testing"
	"testing/synctest"

	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

func TestKnownInventoryUsesValueKeys(t *testing.T) {
	p := NewInboundPeer(&Config{})
	first := wire.NewInvVect(wire.InvTypeTx, &chainhash.Hash{1})
	p.AddKnownInventory(first)
	second := wire.NewInvVect(wire.InvTypeTx, &chainhash.Hash{1})
	if !p.knownInventory.Contains(*second) {
		t.Fatal("equal inventory hashes used different pointer keys")
	}
	first.Hash = chainhash.Hash{2}
	if !p.knownInventory.Contains(*second) {
		t.Fatal("known inventory retained the caller's mutable vector")
	}
}

func TestLastAnnouncedBlockOwnsHash(t *testing.T) {
	p := NewInboundPeer(&Config{})
	inventory := make([]wire.InvVect, wire.MaxInvPerMsg)
	inventory[len(inventory)-1].Hash = chainhash.Hash{1}
	source := &inventory[len(inventory)-1].Hash
	p.UpdateLastAnnouncedBlock(source)
	if p.LastAnnouncedBlock() == source {
		t.Fatal("last announcement retained the decoded inventory array")
	}
	*source = chainhash.Hash{2}
	if *p.LastAnnouncedBlock() != (chainhash.Hash{1}) {
		t.Fatal("last announcement changed with the source inventory")
	}
	p.UpdateLastAnnouncedBlock(nil)
	if p.LastAnnouncedBlock() != nil {
		t.Fatal("clearing the last announcement failed")
	}
}

func TestQueueOverflowDrainsConcurrentSenders(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p, _ := connectedMessagePeer(t)
		var wg sync.WaitGroup
		for i := 0; i < 2*outputBufferSize+1; i++ {
			wg.Go(func() {
				done := make(chan struct{}, 1)
				p.QueueMessage(requestTransactions(1), done)
				<-done
			})
		}
		wg.Wait()
		<-p.queueQuit
		<-p.outQuit
		if p.Connected() {
			t.Fatal("queue overflow retained a connection")
		}
	})
}

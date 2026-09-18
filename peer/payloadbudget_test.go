package peer

import (
	"bytes"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/wire"
)

func TestPayloadBudgetHeldThroughListener(t *testing.T) {
	limit := uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion))
	budget := wire.NewPayloadBudget(limit, 0)
	p, remote := budgetMessagePeer(t, wire.NewRequestCounter(512*1024*1024), budget)
	entered, finish := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(finish) }) }
	p.cfg.Listeners.OnTx = func(_ *Peer, _ *wire.MsgTxAbe) { close(entered); <-finish }
	go p.inHandler()
	t.Cleanup(func() { release(); p.Disconnect(); <-p.inQuit })
	if err := wire.WriteMessage(remote, wire.NewMsgTxAbe(wire.TxVersion_Height_0), wire.ProtocolVersion, wire.MainNet); err != nil {
		t.Fatal(err)
	}
	<-entered
	if budget.Usage() != limit {
		t.Fatal("decoded message released capacity before processing")
	}
	other, remoteOther := budgetMessagePeer(t, wire.NewRequestCounter(512*1024*1024), budget)
	go other.inHandler()
	t.Cleanup(func() { other.Disconnect(); <-other.inQuit })
	var frame bytes.Buffer
	wire.WriteMessage(&frame, wire.NewMsgTxAbe(wire.TxVersion_Height_0), wire.ProtocolVersion, wire.MainNet)
	if _, err := remoteOther.Write(frame.Bytes()[:wire.MessageHeaderSize]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-other.inQuit:
	case <-time.After(2 * time.Second):
		t.Fatal("overloaded reader waited for a body or reject write")
	}
	release()
	p.Disconnect()
	<-p.inQuit
	if budget.Usage() != 0 {
		t.Fatal("callback completion retained payload capacity")
	}
}

func TestQueuedMetadataReleasedOnSendAndDisconnect(t *testing.T) {
	budget := wire.NewPayloadBudget(64, 0)
	p, remote := budgetMessagePeer(t, wire.NewRequestCounter(0), budget)
	p.QueueMessage(requestTransactions(1), nil) // Cannot pass the request quota.
	done := make(chan struct{}, 1)
	p.QueueMessage(wire.NewMsgPing(1), done)
	expectCounterMessage(t, remote, wire.CmdPing)
	<-done
	if budget.Usage() != 45 { // varint upper bound + one inventory vector.
		t.Fatalf("unexpected queued metadata charge: %d", budget.Usage())
	}
	p.Disconnect()
	<-p.queueQuit
	<-p.outQuit
	if budget.Usage() != 0 {
		t.Fatal("disconnect retained queued metadata")
	}
}

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
		budget := wire.NewPayloadBudget(2*1024*1024, 0)
		p, _ := budgetMessagePeer(t, wire.NewRequestCounter(0), budget)
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
		if p.Connected() || budget.Usage() != 0 {
			t.Fatal("queue overflow retained a connection or queued metadata")
		}
	})
}

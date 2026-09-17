package peer

import (
	"bytes"
	"testing"
	"testing/synctest"
	"time"

	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

func TestGetDataDeadlineRequiresMatchedProgress(t *testing.T) {
	txs := make([]*wire.MsgTxAbe, 3)
	for i := range txs {
		txs[i] = wire.NewMsgTxAbe(wire.TxVersion_Height_0)
		txs[i].TxMemo = []byte{byte(i)}
	}
	unknown := wire.NewMsgNotFound()
	unknown.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &chainhash.Hash{99}))
	matched := wire.NewMsgNotFound()
	a := txs[0].TxHash()
	matched.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &a))
	matched.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &a))
	var input bytes.Buffer
	for _, msg := range []wire.Message{unknown, matched, matched, txs[1], txs[2]} {
		if err := wire.WriteMessage(&input, msg, wire.ProtocolVersion, wire.MainNet); err != nil {
			t.Fatal(err)
		}
	}
	p := testMessagePeer(t, input.Bytes())
	p.pendingRequest.Add(requestTransactions(2))
	deadlines := make(map[string]time.Time)
	generation := p.updateGetDataDeadline(deadlines, 0)
	if _, ok := deadlines[wire.CmdGetData]; !ok {
		t.Fatal("sending getdata did not start its deadline")
	}
	expired := time.Now().Add(-time.Second)
	deadlines[wire.CmdGetData] = expired
	readProgress := func() {
		t.Helper()
		if _, _, err := p.readMessage(wire.BaseEncoding); err != nil {
			t.Fatal(err)
		}
		generation = p.updateGetDataDeadline(deadlines, generation)
	}
	readProgress() // Unknown notfound cannot hide a stalled request.
	if deadlines[wire.CmdGetData] != expired {
		t.Fatal("unrequested notfound removed or extended the deadline")
	}
	// More outbound requests must not keep an unanswered batch alive.
	gd := wire.NewMsgGetData()
	c := txs[2].TxHash()
	gd.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &c))
	p.pendingRequest.Add(gd)
	generation = p.updateGetDataDeadline(deadlines, generation)
	if deadlines[wire.CmdGetData] != expired {
		t.Fatal("new getdata extended an unanswered batch's deadline")
	}
	readProgress() // A completes once; B and C still need a deadline.
	if generation != 1 || !deadlines[wire.CmdGetData].After(time.Now()) {
		t.Fatal("matching partial response did not preserve a live deadline")
	}
	deadlines[wire.CmdGetData] = expired
	readProgress() // Duplicate A cannot postpone the remaining requests.
	if generation != 1 || deadlines[wire.CmdGetData] != expired {
		t.Fatal("duplicate notfound postponed a stalled request")
	}
	readProgress() // B completes; C remains.
	if generation != 2 || !deadlines[wire.CmdGetData].After(time.Now()) {
		t.Fatal("remaining request lost its deadline after real progress")
	}
	readProgress() // C completes the batch.
	if _, ok := deadlines[wire.CmdGetData]; ok {
		t.Fatal("fully completed batch retained a stale deadline")
	}
}

func TestMatchingProgressCannotKeepOldRequestAlive(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		counter := wire.NewRequestCounter(512 * 1024 * 1024)
		p, remote := counterMessagePeer(t, counter)
		if err := remote.SetDeadline(time.Time{}); err != nil {
			t.Fatal(err)
		}
		go p.inHandler()
		stallDone := make(chan struct{})
		go func() { p.stallHandler(); close(stallDone) }()
		t.Cleanup(func() { p.Disconnect(); <-p.inQuit; <-stallDone })
		p.QueueMessage(requestTransactions(1), nil)
		expectCounterMessage(t, remote, wire.CmdGetData) // Never answer this one.
		for i := 1; i < int(idleTimeout/stallTickInterval); i++ {
			time.Sleep(stallTickInterval)
			request := wire.NewMsgGetData()
			request.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &chainhash.Hash{byte(i)}))
			p.QueueMessage(request, nil)
			expectCounterMessage(t, remote, wire.CmdGetData)
			nf := wire.NewMsgNotFound()
			nf.AddInvVect(request.InvList[0])
			if err := wire.WriteMessage(remote, nf, wire.ProtocolVersion, wire.MainNet); err != nil {
				t.Fatalf("matching progress closed the peer before its maximum age: %v", err)
			}
			synctest.Wait()
		}
		time.Sleep(stallTickInterval)
		synctest.Wait()
		select {
		case <-p.inQuit:
		default:
			t.Fatal("responses to newer requests postponed the oldest request indefinitely")
		}
		if count, size := counter.Usage(); count != 0 || size != 0 {
			t.Fatalf("expiry retained global request credit: %d, %d", count, size)
		}
	})
}

package peer

import (
	"bytes"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/wire"
)

// connectedMessagePeer connects a Peer to a simulated remote endpoint via net.Pipe.
// The Peer's queue/output handlers send requests that tests read from remote.
// Tests can also write responses back through remote; those tests must start
// the Peer's inHandler to receive them.
func connectedMessagePeer(t *testing.T) (*Peer, net.Conn) {
	t.Helper()
	local, remote := net.Pipe()
	p := newPeerBase(&Config{ChainParams: &chaincfg.MainNetParams}, false)
	p.conn = local
	atomic.StoreInt32(&p.connected, 1)
	p.stallControl = make(chan stallControlMsg, 128)
	go p.queueHandler()
	go p.outHandler()
	if err := remote.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		p.Disconnect()
		remote.Close()
		<-p.queueQuit
		<-p.outQuit
	})
	return p, remote
}

// expectPeerMessage reads one message sent by the Peer from the remote end
// and asserts its command. The decoded message is returned for payload checks.
func expectPeerMessage(t *testing.T, remote net.Conn, command string) wire.Message {
	t.Helper()
	msg, _, err := wire.ReadMessage(remote, wire.ProtocolVersion, wire.MainNet)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Command() != command {
		t.Fatalf("expected %s, got %s", command, msg.Command())
	}
	return msg
}

func requestTransactions(count int) *wire.MsgGetData {
	msg := wire.NewMsgGetData()
	for i := 0; i < count; i++ {
		tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
		tx.TxMemo = []byte{byte(i)}
		hash := tx.TxHash()
		msg.AddInvVect(wire.NewInvVect(wire.InvTypeTx, &hash))
	}
	return msg
}

func TestWriteFailureClearsPendingRequests(t *testing.T) {
	p, remote := connectedMessagePeer(t)
	// Close the simulated remote endpoint so the Peer's request write fails.
	remote.Close()
	p.QueueMessage(requestTransactions(1), nil)
	select {
	case <-p.quit:
	case <-time.After(2 * time.Second):
		t.Fatal("write failure did not disconnect the peer")
	}
	if p.pendingRequest.Expired(time.Now()) {
		t.Fatal("write failure left pending requests")
	}
}

func TestDirectTransactionRelayReachesListener(t *testing.T) {
	p, remote := connectedMessagePeer(t)
	received := make(chan *wire.MsgTxAbe, 1)
	p.cfg.Listeners.OnTx = func(_ *Peer, tx *wire.MsgTxAbe) { received <- tx }
	go p.inHandler()
	t.Cleanup(func() { p.Disconnect(); <-p.inQuit })
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	if err := wire.WriteMessage(remote, tx, wire.ProtocolVersion, wire.MainNet); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		if got.TxHash() != tx.TxHash() {
			t.Fatal("listener received a different transaction")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("direct transaction did not reach the normal listener")
	}
	if p.pendingRequest.Expired(time.Now()) {
		t.Fatal("direct relay created a pending request")
	}
}

func TestDirectTransactionDoesNotResetDownloadDeadline(t *testing.T) {
	var input bytes.Buffer
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	if err := wire.WriteMessage(&input, tx, wire.ProtocolVersion, wire.MainNet); err != nil {
		t.Fatal(err)
	}
	p := testMessagePeer(t, input.Bytes())
	p.pendingRequest.Add(requestTransactions(1)) // A different transaction hash.
	expired := time.Now().Add(-time.Second)
	deadlines := map[string]time.Time{wire.CmdGetData: expired}
	if _, _, err := p.readMessage(wire.BaseEncoding); err != nil {
		t.Fatal(err)
	}
	if generation := p.updateGetDataDeadline(deadlines, 0); generation != 0 || deadlines[wire.CmdGetData] != expired {
		t.Fatal("direct transaction relay postponed the requested transaction deadline")
	}
}

func TestPeerSendsFullGetDataBatchWithoutQuota(t *testing.T) {
	p, remote := connectedMessagePeer(t)
	request := requestTransactions(64)
	done := make(chan struct{}, 1)
	p.QueueMessage(request, done)
	got := expectPeerMessage(t, remote, wire.CmdGetData).(*wire.MsgGetData)
	if len(got.InvList) != len(request.InvList) {
		t.Fatal("getdata was split by a response byte quota")
	}
	<-done
	if count, _ := p.pendingRequest.GetDataStatus(); count != len(request.InvList) {
		t.Fatalf("sent requests were not registered: %d", count)
	}
	p.Disconnect()
	if p.pendingRequest.Expired(time.Now()) {
		t.Fatal("disconnect retained pending requests")
	}
}

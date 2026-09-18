package peer

import (
	"bytes"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/wire"
)

// counterMessagePeer connects a Peer to a simulated remote endpoint via net.Pipe.
// The Peer's queue/output handlers send requests that tests read from remote.
// Tests can also write responses back through remote; those tests must start
// the Peer's inHandler to receive them.
func counterMessagePeer(t *testing.T, counter *wire.RequestCounter) (*Peer, net.Conn) {
	return budgetMessagePeer(t, counter, nil)
}

func budgetMessagePeer(t *testing.T, counter *wire.RequestCounter, budget *wire.PayloadBudget) (*Peer, net.Conn) {
	t.Helper()
	local, remote := net.Pipe()
	p := newPeerBase(&Config{ChainParams: &chaincfg.MainNetParams, RequestCounter: counter, PayloadBudget: budget}, false)
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

// expectCounterMessage reads one message sent by the Peer from the remote end
// and asserts its command. The decoded message is returned for payload checks.
func expectCounterMessage(t *testing.T, remote net.Conn, command string) wire.Message {
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

func TestCounterQueueSplitsRequestsAndPassesControl(t *testing.T) {
	counter := wire.NewRequestCounter(uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion)))
	p, remote := counterMessagePeer(t, counter)
	// Receive simulated responses so completed requests release their counts
	// and allow the next queued request to be sent.
	go p.inHandler()
	t.Cleanup(func() { p.Disconnect(); <-p.inQuit })
	done := make(chan struct{}, 1)
	request := requestTransactions(2)
	p.QueueMessage(request, done)
	first := expectCounterMessage(t, remote, wire.CmdGetData).(*wire.MsgGetData)
	if len(first.InvList) != 1 || first.InvList[0].Hash != request.InvList[0].Hash {
		t.Fatal("getdata batch was not split at available capacity")
	}
	// A full data-request window must still allow control messages through.
	p.QueueMessage(wire.NewMsgPing(1), nil)
	expectCounterMessage(t, remote, wire.CmdPing)
	select {
	case <-done:
		t.Fatal("batch completion was signaled before its last fragment")
	default:
	}
	// Simulate the remote replying to the first transaction request.
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx.TxMemo = []byte{0}
	if err := wire.WriteMessage(remote, tx, wire.ProtocolVersion, wire.MainNet); err != nil {
		t.Fatal(err)
	}
	second := expectCounterMessage(t, remote, wire.CmdGetData).(*wire.MsgGetData)
	if len(second.InvList) != 1 || second.InvList[0].Hash != request.InvList[1].Hash {
		t.Fatal("remaining inventory was lost or reordered")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("last fragment did not signal batch completion")
	}
	p.Disconnect()
	if count, size := counter.Usage(); count != 0 || size != 0 {
		t.Fatalf("disconnect leaked counts: %d, %d", count, size)
	}
}

func TestSharedCounterWakesPeerAfterDisconnect(t *testing.T) {
	counter := wire.NewRequestCounter(uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion)))
	a, remoteA := counterMessagePeer(t, counter)
	b, remoteB := counterMessagePeer(t, counter)
	// Both peers share capacity for one response. A occupies it; B must wait.
	a.QueueMessage(requestTransactions(1), nil)
	expectCounterMessage(t, remoteA, wire.CmdGetData)
	b.QueueMessage(requestTransactions(1), nil)
	b.QueueMessage(wire.NewMsgPing(1), nil)
	expectCounterMessage(t, remoteB, wire.CmdPing)
	// Disconnect A to release shared capacity and wake B's queued request.
	a.Disconnect()
	expectCounterMessage(t, remoteB, wire.CmdGetData)
	b.Disconnect()
	if count, size := counter.Usage(); count != 0 || size != 0 {
		t.Fatalf("cross-connection wakeup leaked counts: %d, %d", count, size)
	}
}

func TestWriteFailureReturnsResponseCredits(t *testing.T) {
	counter := wire.NewRequestCounter(uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion)))
	p, remote := counterMessagePeer(t, counter)
	// Close the simulated remote endpoint so the Peer's request write fails.
	remote.Close()
	p.QueueMessage(requestTransactions(1), nil)
	select {
	case <-p.quit:
	case <-time.After(2 * time.Second):
		t.Fatal("write failure did not disconnect the peer")
	}
	if count, size := counter.Usage(); count != 0 || size != 0 {
		t.Fatalf("write failure leaked counts: %d, %d", count, size)
	}
}

func TestDisconnectCancelsQueuedSupplementalRequests(t *testing.T) {
	counter := wire.NewRequestCounter(512 * 1024 * 1024)
	p, remote := counterMessagePeer(t, counter)
	done := make(chan struct{}, 1)
	// The default quota admits only 15 blocktx responses (32 MiB + 32 B
	// each). The final request is queued even though the connection is live.
	for i := 0; i < 16; i++ {
		var sent chan struct{}
		if i == 15 {
			sent = done
		}
		p.QueueMessage(wire.NewMsgGetBlockTx(chainhash.Hash{1}, chainhash.Hash{byte(i)}), sent)
	}
	for i := 0; i < 15; i++ {
		expectCounterMessage(t, remote, wire.CmdGetBlockTx)
	}
	p.QueueMessage(wire.NewMsgPing(1), nil)
	expectCounterMessage(t, remote, wire.CmdPing)
	select {
	case <-done:
		t.Fatal("quota-blocked request was sent")
	default:
	}
	// Reconstruction expiry uses Disconnect to cancel this queue without
	// adding a second cancellation protocol or allowing stale later sends.
	p.Disconnect()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect did not drain the unsent request")
	}
	if count, size := counter.Usage(); count != 0 || size != 0 {
		t.Fatalf("supplemental requests retained credits: %d, %d", count, size)
	}
}

func TestDirectTransactionRelayReachesListener(t *testing.T) {
	counter := wire.NewRequestCounter(uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion)))
	p, remote := counterMessagePeer(t, counter)
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
	if count, size := counter.Usage(); count != 0 || size != 0 {
		t.Fatalf("relay read retained a temporary charge: %d, %d", count, size)
	}
}

func TestRelayCapacityExhaustionClosesWithoutReject(t *testing.T) {
	counter := wire.NewRequestCounter(uint64((&wire.MsgTxAbe{}).MaxPayloadLength(wire.ProtocolVersion)))
	holder := wire.NewMessageRequests(counter)
	holder.Add(requestTransactions(1))
	defer holder.Close()
	p, remote := counterMessagePeer(t, counter)
	go p.inHandler()
	t.Cleanup(func() { p.Disconnect(); <-p.inQuit })
	// Write only the header. The peer must close rather than allocate/read the
	// body or wait indefinitely to send a rejection for local congestion.
	var b bytes.Buffer
	wire.WriteMessage(&b, wire.NewMsgTxAbe(wire.TxVersion_Height_0), wire.ProtocolVersion, wire.MainNet)
	if _, err := remote.Write(b.Bytes()[:wire.MessageHeaderSize]); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.inQuit:
	case <-time.After(2 * time.Second):
		t.Fatal("quota exhaustion tried to send a protocol rejection")
	}
	if count, _ := counter.Usage(); count != 1 {
		t.Fatal("disconnect changed the other peer's reservation")
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

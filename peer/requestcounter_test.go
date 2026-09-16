package peer

import (
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
	t.Helper()
	local, remote := net.Pipe()
	p := newPeerBase(&Config{ChainParams: &chaincfg.MainNetParams, RequestCounter: counter}, false)
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
		hash := chainhash.Hash{byte(i)}
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
	p.QueueMessage(requestTransactions(2), done)
	first := expectCounterMessage(t, remote, wire.CmdGetData).(*wire.MsgGetData)
	if len(first.InvList) != 1 || first.InvList[0].Hash != (chainhash.Hash{0}) {
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
	if err := wire.WriteMessage(remote, wire.NewMsgTxAbe(wire.TxVersion_Height_0), wire.ProtocolVersion, wire.MainNet); err != nil {
		t.Fatal(err)
	}
	second := expectCounterMessage(t, remote, wire.CmdGetData).(*wire.MsgGetData)
	if len(second.InvList) != 1 || second.InvList[0].Hash != (chainhash.Hash{1}) {
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

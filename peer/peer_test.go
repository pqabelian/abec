package peer

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/wire"
)

type testConn struct{ io.Reader }

func (c *testConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c *testConn) Close() error                     { return nil }
func (c *testConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *testConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *testConn) SetDeadline(time.Time) error      { return nil }
func (c *testConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testConn) SetWriteDeadline(time.Time) error { return nil }

func testMessagePeer(t *testing.T, input []byte) *Peer {
	t.Helper()
	p := newPeerBase(&Config{ChainParams: &chaincfg.MainNetParams}, false)
	p.conn = &testConn{bytes.NewReader(input)}
	atomic.StoreInt32(&p.connected, 1)
	p.stallControl = make(chan stallControlMsg, 4096)
	p.sendDoneQueue = make(chan struct{}, 4096)
	close(p.queueQuit)
	go p.outHandler()
	t.Cleanup(func() { p.Disconnect(); <-p.outQuit })
	return p
}

func TestHeadersResponseAccepted(t *testing.T) {
	var b bytes.Buffer
	if err := wire.WriteMessage(&b, wire.NewMsgHeaders(), wire.ProtocolVersion, wire.MainNet); err != nil {
		t.Fatal(err)
	}
	p := testMessagePeer(t, b.Bytes())
	done := make(chan struct{}, 1)
	p.sendQueue <- outMsg{msg: wire.NewMsgGetHeaders(), encoding: wire.BaseEncoding, doneChan: done}
	<-done
	if _, _, err := p.readMessage(wire.BaseEncoding); err != nil {
		t.Fatalf("valid headers response to a sent getheaders was rejected: %v", err)
	}
}

func TestConcurrentRequestsAndResponses(t *testing.T) {
	const n = 300
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	var b bytes.Buffer
	if err := wire.WriteMessage(&b, tx, wire.ProtocolVersion, wire.MainNet); err != nil {
		t.Fatal(err)
	}
	p := testMessagePeer(t, bytes.Repeat(b.Bytes(), n))
	// Outstanding pipelined requests make every response below solicited.
	gd := wire.NewMsgGetData()
	hash := tx.TxHash()
	gd.AddInvVect(wire.NewInvVect(wire.InvTypeWitnessTx, &hash))
	for i := 0; i < n; i++ {
		p.pendingRequest.Add(gd)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			p.sendQueue <- outMsg{msg: gd, encoding: wire.BaseEncoding}
		}
	}()
	for i := 0; i < n; i++ {
		if _, _, err := p.readMessage(wire.BaseEncoding); err != nil {
			t.Error(err)
			break
		}
	}
	wg.Wait()
}

package peer

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"

	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

func TestUseGetBlockTxVersion(t *testing.T) {
	for _, tc := range []struct {
		agent string
		want  bool
	}{
		{"", false},
		{"/abec:3.0.0/", false},
		{"/abec:3.0.1-rc.1/", false},
		{"/abec:3.0.1/", false},
		{"/abec:3.0.1(test peer)/", false},
		{"/abec:3.0.1+build/", false},
		{"/abecwire:0.0/abec:3.0.1/", false},
		{"/abec:3.0.2/", false},
		{"/abec:3.0.10/", false},
		{"/abec:3.1.0-rc.1/", false},
		{"/abec:3.1.0/", false},
		{"/abec:3.1.0(test peer)/", false},
		{"/abec:3.1.0+build/", false},
		{"/abecwire:0.0/abec:3.1.0/", false},
		{"/abec:3.2.0/", true},
		{"/abec:3.2.0(test peer)/", true},
		{"/abecwire:0.0/abec:3.2.1/", true},
		{"/abec:invalid/", false},
	} {
		t.Run(tc.agent, func(t *testing.T) {
			p := NewInboundPeer(&Config{})
			p.userAgent = tc.agent
			if got := p.UseGetBlockTx(); got != tc.want {
				t.Fatalf("UseGetBlockTx() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNeedSetResultStopsAtHeader(t *testing.T) {
	for _, params := range []*chaincfg.Params{&chaincfg.MainNetParams, &chaincfg.RegressionNetParams} {
		t.Run(params.Name, func(t *testing.T) {
			p, remote := connectedMessagePeer(t)
			p.cfg.ChainParams = params
			p.addr = "127.0.0.1:12345"
			var handled atomic.Bool
			p.cfg.Listeners.OnNeedSetResult = func(*Peer, *wire.MsgNeedSetResult, []byte) { handled.Store(true) }
			go p.inHandler()
			t.Cleanup(func() { p.Disconnect(); <-p.inQuit })
			var frame bytes.Buffer
			if err := wire.WriteMessage(&frame, wire.NewMsgNeedSetResult(chainhash.Hash{}, nil), wire.ProtocolVersion, params.Net); err != nil {
				t.Fatal(err)
			}
			// Supply only the header and never read from the remote endpoint.
			// Reading the body or waiting to write a reject would both block.
			if _, err := remote.Write(frame.Bytes()[:wire.MessageHeaderSize]); err != nil {
				t.Fatal(err)
			}
			select {
			case <-p.inQuit:
			case <-time.After(time.Second):
				t.Fatal("legacy response waited for a payload or reject write")
			}
			if p.Connected() || handled.Load() || atomic.LoadUint64(&p.bytesReceived) != wire.MessageHeaderSize {
				t.Fatal("legacy response was processed past its header")
			}
		})
	}
}

func TestLegacyNeedSetCanBeServedButNeverRequested(t *testing.T) {
	for _, agent := range []string{"/abec:3.1.0/", "/abec:3.2.0/"} {
		t.Run(agent, func(t *testing.T) {
			p, remote := connectedMessagePeer(t)
			p.userAgent = agent
			p.cfg.Listeners.OnNeedSet = func(p *Peer, request *wire.MsgNeedSet, _ []byte) {
				p.QueueMessage(wire.NewMsgNeedSetResult(request.BlockHash, nil), nil)
			}
			go p.inHandler()
			t.Cleanup(func() { p.Disconnect(); <-p.inQuit })
			request := wire.NewMsgNeedSet(chainhash.Hash{1}, nil)
			done := make(chan struct{}, 1)
			p.QueueMessage(request, done)
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("discarded needset stranded its sender")
			}
			// Flush a control message to prove no needset preceded it on the wire.
			p.QueueMessage(wire.NewMsgPing(1), nil)
			expectPeerMessage(t, remote, wire.CmdPing)
			if err := wire.WriteMessage(remote, request, wire.ProtocolVersion, wire.MainNet); err != nil {
				t.Fatal(err)
			}
			response := expectPeerMessage(t, remote, wire.CmdNeedSetResult).(*wire.MsgNeedSetResult)
			if response.BlockHash != request.BlockHash || !p.Connected() || p.pendingRequest.Expired(time.Now()) {
				t.Fatal("legacy service response changed connection or pending requests")
			}
		})
	}
}

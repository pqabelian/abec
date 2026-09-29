package syncmgr

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/pqabelian/abec/abeutil"
	"github.com/pqabelian/abec/chainhash"
	peerpkg "github.com/pqabelian/abec/peer"
	"github.com/pqabelian/abec/wire"
)

// Give net.Pipe the TCP address required by the production inbound handshake.
type reconstructionConn struct{ net.Conn }

func (c reconstructionConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}
}

func reconstructionPeer(t *testing.T, sm *SyncManager, version string) (*peerpkg.Peer, net.Conn, <-chan struct{}) {
	t.Helper()
	local, remote := net.Pipe()
	processed := make(chan struct{}, 1)
	p := peerpkg.NewInboundPeer(&peerpkg.Config{
		Chain: sm.chain, ChainParams: sm.chainParams,
		UserAgentName: "abec", UserAgentVersion: "3.2.0",
		Listeners: peerpkg.MessageListeners{
			OnInv: func(p *peerpkg.Peer, msg *wire.MsgInv) {
				<-sm.QueueInv(msg, p)
			},
			OnPrunedBlock: func(p *peerpkg.Peer, msg *wire.MsgPrunedBlock, _ []byte) {
				<-sm.QueuePrunedBlock(abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(msg, nil), p, nil)
			},
			OnBlockTx: func(p *peerpkg.Peer, msg *wire.MsgBlockTx, _ []byte) {
				<-sm.QueueBlockTx(msg, p)
				processed <- struct{}{}
			},
		},
	})
	t.Cleanup(func() { p.Disconnect(); remote.Close() })
	if err := remote.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	p.AssociateConnection(reconstructionConn{local})
	address := wire.NewNetAddressIPPort(net.IPv4(127, 0, 0, 1), 12345, 0)
	msg := wire.NewMsgVersion(address, address, 1, 0)
	if err := msg.AddUserAgent("abec", version); err != nil {
		t.Fatal(err)
	}
	msg.Services = wire.SFNodeWitness
	if err := wire.WriteMessage(remote, msg, wire.ProtocolVersion, sm.chainParams.Net); err != nil {
		t.Fatal(err)
	}
	readReconstructionMessage(t, sm, remote, wire.CmdVersion)
	readReconstructionMessage(t, sm, remote, wire.CmdVerAck)
	if err := wire.WriteMessage(remote, wire.NewMsgVerAck(), wire.ProtocolVersion, sm.chainParams.Net); err != nil {
		t.Fatal(err)
	}
	// Select this peer without starting an unrelated initial chain download.
	sm.syncPeer = p
	sm.handleNewPeerMsg(p)
	return p, remote, processed
}

func readReconstructionMessage(t *testing.T, sm *SyncManager, remote net.Conn, command string) wire.Message {
	t.Helper()
	msg, _, err := wire.ReadMessage(remote, wire.ProtocolVersion, sm.chainParams.Net)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Command() != command {
		t.Fatalf("received %s, want %s", msg.Command(), command)
	}
	return msg
}

func expectBlockRequest(t *testing.T, sm *SyncManager, remote net.Conn, hash chainhash.Hash, kind wire.InvType) {
	t.Helper()
	msg := readReconstructionMessage(t, sm, remote, wire.CmdGetData).(*wire.MsgGetData)
	if len(msg.InvList) != 1 {
		t.Fatalf("getdata has %d entries, want 1", len(msg.InvList))
	}
	if iv := msg.InvList[0]; iv.Hash != hash || iv.Type != kind {
		t.Fatalf("getdata = %s for %s, want %s for %s", iv.Type, iv.Hash, kind, hash)
	}
}

func TestPrunedBlockDownloadPolicy(t *testing.T) {
	for _, tc := range []struct {
		version string
		kind    wire.InvType
	}{
		{"3.0.0", wire.InvTypeWitnessBlock},
		{"3.0.1-rc.1", wire.InvTypeWitnessBlock},
		{"unknown", wire.InvTypeWitnessBlock},
		{"3.0.1", wire.InvTypeWitnessBlock},
		{"3.0.2", wire.InvTypeWitnessBlock},
		{"3.1.0-rc.1", wire.InvTypeWitnessBlock},
		{"3.1.0", wire.InvTypeWitnessBlock},
		{"3.2.0", wire.InvTypePrunedBlock},
		{"3.2.1", wire.InvTypePrunedBlock},
	} {
		t.Run(tc.version, func(t *testing.T) {
			sm, _ := testSyncManager(t)
			tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
			tx.TxWitness = []byte{1}
			pruned := testPrunedBlock(t, sm, tx)
			p, remote, processed := reconstructionPeer(t, sm, tc.version)
			sm.Start()
			hash := pruned.BlockHash()
			inv := wire.NewMsgInv()
			inv.AddInvVect(wire.NewInvVect(wire.InvTypePrunedBlock, &hash))
			if err := wire.WriteMessage(remote, inv, wire.ProtocolVersion, sm.chainParams.Net); err != nil {
				t.Fatal(err)
			}
			expectBlockRequest(t, sm, remote, hash, tc.kind)
			if tc.kind == wire.InvTypeWitnessBlock {
				// A legacy peer cannot substitute a pruned block for the full request.
				var frame bytes.Buffer
				if _, err := wire.WriteMessageWithEncodingN(&frame, pruned, wire.ProtocolVersion, sm.chainParams.Net, wire.WitnessEncoding); err != nil {
					t.Fatal(err)
				}
				if _, err := remote.Write(frame.Bytes()[:wire.MessageHeaderSize]); err != nil {
					t.Fatal(err)
				}
				select {
				case <-p.Done():
				case <-time.After(time.Second):
					t.Fatal("accepted an unrequested legacy pruned block")
				}
				sm.Stop()
				if sm.pendingPrunedBlock != nil {
					t.Fatal("legacy peer started reconstruction")
				}
				return
			}
			if _, err := wire.WriteMessageWithEncodingN(remote, pruned, wire.ProtocolVersion, sm.chainParams.Net, wire.WitnessEncoding); err != nil {
				t.Fatal(err)
			}
			request := readReconstructionMessage(t, sm, remote, wire.CmdGetBlockTx).(*wire.MsgGetBlockTx)
			if request.BlockHash != hash || request.TxHash != tx.TxHash() {
				t.Fatal("incorrect single-transaction supplement request")
			}
			if _, err := wire.WriteMessageWithEncodingN(remote, wire.NewMsgBlockTx(hash, tx), wire.ProtocolVersion, sm.chainParams.Net, wire.WitnessEncoding); err != nil {
				t.Fatal(err)
			}
			select {
			case <-processed:
			case <-time.After(time.Second):
				t.Fatal("blocktx did not complete reconstruction")
			}
			sm.Stop()
			// The mock tx body fails full validation, but reconstruction must finish.
			if sm.pendingPrunedBlock != nil || len(sm.peerStates[p].requestedBlocks) != 0 {
				t.Fatal("completed reconstruction retained pending state")
			}
		})
	}
}

func TestPrunedBlockWithoutMissingTransactions(t *testing.T) {
	sm, _ := testSyncManager(t)
	pruned := testPrunedBlock(t, sm)
	p, remote, _ := reconstructionPeer(t, sm, "3.2.0")
	sm.Start()
	hash := pruned.BlockHash()
	inv := wire.NewMsgInv()
	inv.AddInvVect(wire.NewInvVect(wire.InvTypePrunedBlock, &hash))
	if err := wire.WriteMessage(remote, inv, wire.ProtocolVersion, sm.chainParams.Net); err != nil {
		t.Fatal(err)
	}
	expectBlockRequest(t, sm, remote, hash, wire.InvTypePrunedBlock)
	if _, err := wire.WriteMessageWithEncodingN(remote, pruned, wire.ProtocolVersion, sm.chainParams.Net, wire.WitnessEncoding); err != nil {
		t.Fatal(err)
	}
	// The coinbase-only block needs no supplements. Its dummy witness fails
	// full validation, so rejection must arrive without any getblocktx first.
	readReconstructionMessage(t, sm, remote, wire.CmdReject)
	sm.Stop()
	if sm.pendingPrunedBlock != nil || len(sm.peerStates[p].requestedBlocks) != 0 {
		t.Fatal("block with no missing transactions retained reconstruction state")
	}
}

func TestBusyReconstructionRequestsFullBlocksAcrossPeers(t *testing.T) {
	sm, _ := testSyncManager(t)
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx.TxWitness = []byte{1}
	pruned := testPrunedBlock(t, sm, tx)
	p, remote, _ := reconstructionPeer(t, sm, "3.2.0")
	hash := pruned.BlockHash()
	sm.requestedBlocks[hash], sm.peerStates[p].requestedBlocks[hash] = struct{}{}, struct{}{}
	sm.handlePrunedBlockMsgAbe(&prunedBlockMsg{block: abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(pruned, nil), peer: p})
	readReconstructionMessage(t, sm, remote, wire.CmdGetBlockTx)
	owner := sm.pendingPrunedBlock
	other, otherRemote, _ := reconstructionPeer(t, sm, "3.2.1")
	for i, endpoint := range []struct {
		peer   *peerpkg.Peer
		remote net.Conn
	}{{p, remote}, {other, otherRemote}} {
		next := *pruned
		next.Header.Timestamp = next.Header.Timestamp.Add(time.Duration(i+1) * time.Second)
		hash := next.BlockHash()
		sm.requestedBlocks[hash], sm.peerStates[endpoint.peer].requestedBlocks[hash] = struct{}{}, struct{}{}
		done := make(chan struct{}, 1)
		sm.handlePrunedBlockMsgAbe(&prunedBlockMsg{block: abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(&next, nil), peer: endpoint.peer, reply: done})
		expectBlockRequest(t, sm, endpoint.remote, hash, wire.InvTypeWitnessBlock)
		if sm.pendingPrunedBlock != owner || len(owner.missing) != 1 {
			t.Fatal("another block replaced the node-wide reconstruction")
		}
		select {
		case <-done:
		default:
			t.Fatal("fallback retained the pruned message")
		}
		if _, ok := sm.peerStates[endpoint.peer].requestedBlocks[hash]; !ok {
			t.Fatal("fallback lost the full-block request")
		}
	}
	// Announcements should request full blocks immediately while the slot is busy.
	for i, kind := range []wire.InvType{wire.InvTypeWitnessBlock, wire.InvTypePrunedBlock} {
		inv := wire.NewMsgInv()
		nextHash := chainhash.Hash{byte(i + 10)}
		inv.AddInvVect(wire.NewInvVect(wire.InvTypePrunedBlock, &nextHash))
		sm.handleInvMsg(&invMsg{inv: inv, peer: other})
		expectBlockRequest(t, sm, otherRemote, nextHash, kind)
		sm.finishPrunedBlockRequest(p, hash)
	}
}

package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/abesuite/abec/abelog"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/database"
	_ "github.com/abesuite/abec/database/ffldb"
	"github.com/abesuite/abec/peer"
	"github.com/abesuite/abec/wire"
)

func quietP2PTestLogs(t *testing.T) {
	t.Helper()
	// The application backend normally requires daemon log-rotator startup.
	for _, logger := range subsystemLoggers {
		level := logger.Level()
		logger.SetLevel(abelog.LevelOff)
		t.Cleanup(func() { logger.SetLevel(level) })
	}
}

func TestDataServiceStopsBeforeDatabaseAccess(t *testing.T) {
	quietP2PTestLogs(t)
	previousConfig := cfg
	cfg = &config{DisableBanning: true}
	t.Cleanup(func() { cfg = previousConfig })
	for _, stopped := range []string{"peer", "server"} {
		for _, command := range []string{wire.CmdNeedSet, wire.CmdGetBlockTx, wire.CmdGetData} {
			t.Run(stopped+"/"+command, func(t *testing.T) {
				p := peer.NewInboundPeer(&peer.Config{})
				defer p.Disconnect()
				// A database/chain access would panic: admission must be checked first.
				sp := &serverPeer{Peer: p, server: &server{quit: make(chan struct{})}, quit: make(chan struct{})}
				switch stopped {
				case "peer":
					p.Disconnect() // Wrapper cleanup and sp.quit remain pending.
				case "server":
					close(sp.server.quit)
				}
				switch command {
				case wire.CmdNeedSet:
					sp.OnNeedSet(p, wire.NewMsgNeedSet(chainhash.Hash{}, nil), nil)
				case wire.CmdGetBlockTx:
					sp.OnGetBlockTx(p, wire.NewMsgGetBlockTx(chainhash.Hash{}, chainhash.Hash{}), nil)
				case wire.CmdGetData:
					msg := wire.NewMsgGetData()
					msg.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, &chainhash.Hash{}))
					sp.OnGetData(p, msg)
				}
			})
		}
	}
}

func TestDataServiceFetchFailureAndDiscardedSend(t *testing.T) {
	quietP2PTestLogs(t)
	previousConfig := cfg
	cfg = &config{DisableBanning: true}
	t.Cleanup(func() { cfg = previousConfig })
	dir := t.TempDir()
	db, err := database.Create("ffldb", filepath.Join(dir, "blocks"), wire.MainNet, wire.FullNode, filepath.Join(dir, "temporary.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	chain, err := blockchain.New(&blockchain.Config{DB: db, ChainParams: &chaincfg.MainNetParams, NodeType: wire.FullNode, TimeSource: blockchain.NewMedianTime()})
	if err != nil {
		t.Fatal(err)
	}
	s := &server{chain: chain, db: db}
	p := peer.NewInboundPeer(&peer.Config{CommunicationCache: &s.communicationCache})
	defer p.Disconnect()
	sp := &serverPeer{Peer: p, server: s}
	sp.OnNeedSet(p, wire.NewMsgNeedSet(chainhash.Hash{99}, nil), nil)
	genesis := chaincfg.MainNetParams.GenesisBlock
	if err := sp.server.pushNeedSetResultMsg(sp, genesis.BlockHash(), nil, wire.WitnessEncoding); err != nil {
		t.Fatalf("valid needset did not reach the send path: %v", err)
	}
	if err := sp.server.pushBlockTxMsg(sp, genesis.BlockHash(), genesis.Transactions[0].TxHash(), wire.WitnessEncoding); err != nil {
		t.Fatalf("valid blocktx did not reach the send path: %v", err)
	}
	sp.OnNeedSet(p, wire.NewMsgNeedSet(genesis.BlockHash(), nil), nil)
	sp.OnGetBlockTx(p, wire.NewMsgGetBlockTx(genesis.BlockHash(), genesis.Transactions[0].TxHash()), nil)
	genesisHash := genesis.BlockHash()
	sp.continueHash = &genesisHash
	done := make(chan struct{}, 1)
	if err := s.pushPrunedBlockMsg(sp, &genesisHash, done, wire.WitnessEncoding); err != nil {
		t.Fatalf("valid pruned response did not reach the send path: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("pruned continuation stranded its send-completion notification")
	}
	if sp.continueHash != nil {
		t.Fatal("pruned response left the continuation hash pending")
	}
	for _, inventoryType := range []wire.InvType{wire.InvTypeBlock, wire.InvTypeWitnessBlock} {
		msg := wire.NewMsgGetData()
		msg.AddInvVect(wire.NewInvVect(inventoryType, &chainhash.Hash{99}))
		genesisHash := genesis.BlockHash()
		msg.AddInvVect(wire.NewInvVect(inventoryType, &genesisHash))
		sp.OnGetData(p, msg)
	}
	s.communicationCache.Range(func(key, value interface{}) bool {
		t.Errorf("discarded response retained a cache entry: %v", key)
		return true
	})
}

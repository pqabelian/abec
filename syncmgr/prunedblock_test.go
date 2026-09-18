package syncmgr

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/blockchain/consensus"
	"github.com/abesuite/abec/blockchain/consensus/ethashpow"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/wire"
)

// Use a real parent, commitment and easy regtest PoW for reconstruction tests.
// Transaction bodies can still be invalid: full validation happens afterwards.
func testPrunedBlock(t *testing.T, sm *SyncManager, txs ...*wire.MsgTxAbe) *wire.MsgPrunedBlock {
	t.Helper()
	if sm.chain == nil {
		sm.chainParams = &chaincfg.RegressionNetParams
		dir := t.TempDir()
		db, err := database.Create("ffldb", filepath.Join(dir, "blocks"), sm.chainParams.Net, wire.FullNode, filepath.Join(dir, "temporary.log"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sm.Stop(); db.Close() })
		sm.chain, err = blockchain.New(&blockchain.Config{
			DB: db, ChainParams: sm.chainParams, NodeType: wire.FullNode, TimeSource: blockchain.NewMedianTime(),
		})
		if err != nil {
			t.Fatal(err)
		}
		sm.powConsensus = consensus.NewPowConsensus(ethashpow.EthashConfig{})
	}
	genesis := sm.chainParams.GenesisBlock
	coinbase := *genesis.Transactions[0]
	input, err := wire.NewStandardCoinbaseTxIn(1, coinbase.Version)
	if err != nil {
		t.Fatal(err)
	}
	coinbase.TxIns, coinbase.TxWitness = []*wire.TxInAbe{input}, []byte{1}
	msg := &wire.MsgPrunedBlock{Header: genesis.Header, CoinbaseTx: &coinbase}
	msg.Header.PrevBlock = genesis.BlockHash()
	msg.Header.Timestamp = msg.Header.Timestamp.Add(time.Second)
	msg.Header.Height = 1
	commitPrunedBlock(t, sm, msg, txs...)
	return msg
}

func commitPrunedBlock(t *testing.T, sm *SyncManager, msg *wire.MsgPrunedBlock, txs ...*wire.MsgTxAbe) {
	t.Helper()
	transactions := make([]*abeutil.TxAbe, 0, len(txs)+1)
	for _, tx := range append([]*wire.MsgTxAbe{msg.CoinbaseTx}, txs...) {
		wrapped, err := abeutil.NewTxAbe(tx, nil)
		if err != nil {
			t.Fatal(err)
		}
		transactions = append(transactions, wrapped)
	}
	msg.TransactionHashes, msg.WitnessHashs = nil, nil
	for _, tx := range txs {
		msg.AddTransactionHash(tx)
	}
	merkles := blockchain.BuildMerkleTreeStoreAbe(transactions, false)
	msg.Header.MerkleRoot = *merkles[len(merkles)-1]
	target := blockchain.CompactToBig(msg.Header.Bits)
	for i := 0; i < 1000; i++ {
		if sm.powConsensus.VerifySeal(&msg.Header, target, nil) == nil {
			return
		}
		msg.Header.Nonce++
	}
	t.Fatal("could not solve easy regtest header")
}

func TestPrunedBlockRejectsIneligibleSupplementalDownload(t *testing.T) {
	for _, unknownParent := range []bool{false, true} {
		sm, p := testSyncManager(t)
		tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
		tx.TxWitness = []byte{1}
		msg := testPrunedBlock(t, sm, tx)
		if unknownParent {
			msg.Header.PrevBlock = chainhash.Hash{99}
		} else {
			// Preserve the real PoW header, but replace the committed tx list.
			msg.TransactionHashes[0][0] ^= 1
		}
		block := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(msg, nil)
		hash := *block.Hash()
		state := sm.peerStates[p]
		state.requestedBlocks[hash], sm.requestedBlocks[hash] = struct{}{}, struct{}{}
		done := make(chan struct{}, 1)
		sm.handlePrunedBlockMsgAbe(&prunedBlockMsg{block: block, peer: p, reply: done})
		if sm.pendingPrunedBlock != nil {
			t.Fatal("ineligible pruned block started supplemental reconstruction")
		}
		select {
		case <-done:
		default:
			t.Fatal("rejected reconstruction did not release its caller")
		}
		_, requested := state.requestedBlocks[hash]
		if requested != unknownParent {
			t.Fatal("unknown parent must retain its full-block request; invalid commitment must discard it")
		}
		sm.Stop()
	}
}

func TestInvalidCoinbaseDoesNotStartSupplementalDownload(t *testing.T) {
	sm, p := testSyncManager(t)
	tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
	tx.TxWitness = []byte{1}
	msg := testPrunedBlock(t, sm, tx)
	msg.CoinbaseTx.TxFee = abeutil.MaxNeutrino + 1
	commitPrunedBlock(t, sm, msg, tx) // Correct commitment and real regtest PoW.
	block := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(msg, nil)
	if _, err := sm.preparePrunedBlock(&prunedBlockMsg{block: block, peer: p}); err == nil {
		t.Fatal("already-visible invalid coinbase started supplemental reconstruction")
	}
}

func TestSupplementalWitnessMismatchStopsReconstruction(t *testing.T) {
	for _, singleTx := range []bool{false, true} {
		sm, p := testSyncManager(t)
		txs := make([]*wire.MsgTxAbe, maxPendingBlockTxRequests+1)
		for i := range txs {
			txs[i] = wire.NewMsgTxAbe(wire.TxVersion_Height_0)
			txs[i].TxMemo, txs[i].TxWitness = []byte{byte(i)}, []byte{1}
		}
		msg := testPrunedBlock(t, sm, txs...)
		block := abeutil.NewPrunedBlockFromPrunedBlockAndBytesAbe(msg, nil)
		hash := *block.Hash()
		state := sm.peerStates[p]
		state.requestedBlocks[hash], sm.requestedBlocks[hash] = struct{}{}, struct{}{}
		sm.handlePrunedBlockMsgAbe(&prunedBlockMsg{block: block, peer: p})
		pending := sm.pendingPrunedBlock
		if pending == nil {
			t.Fatal("valid commitment did not start reconstruction")
		}
		pending.useGetBlockTx = singleTx
		bad := *txs[0]
		bad.TxWitness = []byte{99} // Same tx identity, different committed witness.
		if singleTx {
			pending.inFlight = maxPendingBlockTxRequests
			pending.unrequested = msg.TransactionHashes[maxPendingBlockTxRequests:]
			sm.handleBlockTxMsg(&blockTxMsg{result: wire.NewMsgBlockTx(hash, &bad), peer: p})
		} else {
			txs[0] = &bad
			sm.handleNeedSetResultMsg(&needSetResultMsg{result: wire.NewMsgNeedSetResult(hash, txs), peer: p})
		}
		if sm.pendingPrunedBlock != nil || len(sm.requestedBlocks) != 0 || pending.unrequested != nil {
			t.Fatal("wrong witness replenished requests or retained reconstruction")
		}
		select {
		case <-p.Done():
		default:
			t.Fatal("wrong witness reached full-block validation instead of immediate rejection")
		}
		sm.Stop()
	}
}

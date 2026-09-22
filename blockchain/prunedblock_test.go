package blockchain

import (
	"testing"
	"time"

	"github.com/pqabelian/abec/abeutil"
	"github.com/pqabelian/abec/blockchain/consensus"
	"github.com/pqabelian/abec/blockchain/consensus/ethashpow"
	"github.com/pqabelian/abec/blockchain/ruleerror"
	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/wire"
)

func prunedCommitmentFixture(t *testing.T, version int32, count int) *wire.MsgPrunedBlock {
	t.Helper()
	msg := &wire.MsgPrunedBlock{Header: chaincfg.RegressionNetParams.GenesisBlock.Header}
	msg.Header.Version = version
	transactions := make([]*abeutil.TxAbe, count)
	for i := range transactions {
		tx := wire.NewMsgTxAbe(wire.TxVersion_Height_0)
		if version >= wire.BlockVersionAconcagua {
			tx.Version = wire.TxVersion_Height_464000_Aconcagua
		}
		tx.TxMemo, tx.TxWitness = []byte{byte(i)}, []byte{byte(i + 1)}
		if i == 0 {
			if tx.Version == wire.TxVersion_Height_0 {
				tx.TxOuts = chaincfg.RegressionNetParams.GenesisBlock.Transactions[0].TxOuts
			}
			input, err := wire.NewStandardCoinbaseTxIn(1, tx.Version)
			if err != nil {
				t.Fatal(err)
			}
			tx.TxIns, msg.CoinbaseTx = []*wire.TxInAbe{input}, tx
		} else {
			msg.AddTransactionHash(tx)
		}
		var err error
		transactions[i], err = abeutil.NewTxAbe(tx, nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	if version >= wire.BlockVersionEthashPow {
		root, _ := BuildMerkleTreeStoreAbeEthash(transactions)
		msg.Header.MerkleRoot = *root
	} else {
		merkles := BuildMerkleTreeStoreAbe(transactions, false)
		msg.Header.MerkleRoot = *merkles[len(merkles)-1]
	}
	return msg
}

func TestPrunedMerkleCommitmentMatchesFullBlock(t *testing.T) {
	for _, version := range []int32{wire.BlockVersionInitial, wire.BlockVersionEthashPow, wire.BlockVersionDSA, wire.BlockVersionMLPAUT, wire.BlockVersionAconcagua} {
		for _, count := range []int{1, 2, 3, 5, 8} {
			msg := prunedCommitmentFixture(t, version, count)
			if err := checkPrunedBlockMerkleRoot(msg); err != nil {
				t.Fatalf("version %x, count %d: %v", version, count, err)
			}
			if count > 1 {
				msg.TransactionHashes[0][0] ^= 1
				if checkPrunedBlockMerkleRoot(msg) == nil {
					t.Fatal("a valid header authorized a fabricated transaction list")
				}
				msg.TransactionHashes[0][0] ^= 1
				msg.WitnessHashs[0][0] ^= 1
				if checkPrunedBlockMerkleRoot(msg) == nil {
					t.Fatal("a valid header authorized a fabricated witness list")
				}
			}
			msg.CoinbaseTx.TxMemo = []byte{99}
			if checkPrunedBlockMerkleRoot(msg) == nil {
				t.Fatal("a valid header authorized a different coinbase")
			}
		}
	}
}

func TestPrunedBlockEligibility(t *testing.T) {
	params := chaincfg.RegressionNetParams
	b := &BlockChain{chainParams: &params, timeSource: NewMedianTime(), blocksPerRetarget: 4000}
	b.index = newBlockIndex(nil, &params)
	parent, err := b.newBlockNode(&params.GenesisBlock.Header, nil)
	if err != nil {
		t.Fatal(err)
	}
	parent.status = statusValid
	b.index.AddNode(parent)
	msg := prunedCommitmentFixture(t, wire.BlockVersionInitial, 2)
	msg.Header.PrevBlock = parent.hash
	msg.Header.Timestamp = msg.Header.Timestamp.Add(time.Second)
	pow := consensus.NewPowConsensus(ethashpow.EthashConfig{})
	target := CompactToBig(msg.Header.Bits)
	for pow.VerifySeal(&msg.Header, target, nil) != nil {
		msg.Header.Nonce++
	}
	if err := b.CheckPrunedBlock(msg, pow); err != nil {
		t.Fatalf("valid header and commitment rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		change func(*wire.MsgPrunedBlock)
		code   ruleerror.ErrorCode
	}{
		{"unknown parent", func(m *wire.MsgPrunedBlock) { m.Header.PrevBlock = chainhash.Hash{99} }, ruleerror.ErrPreviousBlockUnknown},
		{"wrong difficulty", func(m *wire.MsgPrunedBlock) { m.Header.Bits-- }, ruleerror.ErrUnexpectedDifficulty},
		{"future timestamp", func(m *wire.MsgPrunedBlock) {
			m.Header.Timestamp = time.Now().Truncate(time.Second).Add((MaxTimeOffsetSeconds + 1) * time.Second)
		}, ruleerror.ErrTimeTooNew},
		{"untrusted epoch", func(m *wire.MsgPrunedBlock) { m.Header.Version = wire.BlockVersionEthashPow; m.Header.Height = 1 << 30 }, ruleerror.ErrMismatchedBlockHeightAndVersion},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := *msg
			test.change(&candidate)
			// A nil engine would panic if expensive PoW verification were reached.
			err := b.CheckPrunedBlock(&candidate, nil)
			if ruleErr, ok := err.(ruleerror.RuleError); !ok || ruleErr.ErrorCode != test.code {
				t.Fatalf("got %v, want rule error %v", err, test.code)
			}
		})
	}
	t.Run("wrong commitment", func(t *testing.T) {
		candidate := *msg
		candidate.Header.MerkleRoot[0] ^= 1
		// Merkle validation follows PoW. Re-mine the changed header so the
		// test reaches the commitment check with a real consensus engine.
		for pow.VerifySeal(&candidate.Header, target, nil) != nil {
			candidate.Header.Nonce++
		}
		err := b.CheckPrunedBlock(&candidate, pow)
		if ruleErr, ok := err.(ruleerror.RuleError); !ok || ruleErr.ErrorCode != ruleerror.ErrBadMerkleRoot {
			t.Fatalf("got %v, want rule error %v", err, ruleerror.ErrBadMerkleRoot)
		}
	})
	bad := *msg
	for pow.VerifySeal(&bad.Header, target, nil) == nil {
		bad.Header.Nonce++
	}
	if err := b.CheckPrunedBlock(&bad, pow); err == nil {
		t.Fatal("invalid proof of work started supplemental download")
	}
	// Preserve configured fake-PoW scopes using the validated coinbase height,
	// including legacy headers which do not carry a serialized height.
	b.fakePoWHeightScopes = []BlockHeightScope{{StartHeight: 1, EndHeight: 2}}
	bad.Header.Height = 999
	if err := b.CheckPrunedBlock(&bad, nil); err != nil {
		t.Fatalf("configured fake-PoW block rejected: %v", err)
	}
	params.Net = wire.MainNet
	if err := b.CheckPrunedBlock(&bad, pow); err == nil {
		t.Fatal("fake-PoW scopes disabled mainnet proof of work")
	}
}

func TestCoinbaseActivationPreservesTransferGracePeriod(t *testing.T) {
	params := chaincfg.RegressionNetParams
	b := &BlockChain{chainParams: &params}
	for _, fork := range []struct {
		activation, commit int32
		blockVersion       int32
		oldTx, newTx       uint32
	}{
		{params.BlockHeightMLPAUT, params.BlockHeightMLPAUTCOMMIT, wire.BlockVersionMLPAUT, wire.TxVersion_Height_0, wire.TxVersion_Height_MLPAUT_300000},
		{params.BlockHeightAconcagua, params.BlockHeightAconcaguaCommit, wire.BlockVersionAconcagua, wire.TxVersion_Height_MLPAUT_300000, wire.TxVersion_Height_464000_Aconcagua},
	} {
		for _, height := range []int32{fork.activation, fork.commit} {
			for _, coinbaseVersion := range []uint32{fork.oldTx, fork.newTx} {
				for _, transferVersion := range []uint32{fork.oldTx, fork.newTx} {
					input, err := wire.NewStandardCoinbaseTxIn(height, coinbaseVersion)
					if err != nil {
						t.Fatal(err)
					}
					coinbase, transfer := wire.NewMsgTxAbe(coinbaseVersion), wire.NewMsgTxAbe(transferVersion)
					coinbase.TxIns, coinbase.TxWitness = []*wire.TxInAbe{input}, []byte{1}
					transfer.TxWitness = []byte{2}
					msg := &wire.MsgBlockAbe{
						Header:       wire.BlockHeader{Version: fork.blockVersion, Height: height},
						Transactions: []*wire.MsgTxAbe{coinbase, transfer},
						WitnessHashs: []*chainhash.Hash{coinbase.TxWitnessHash(), transfer.TxWitnessHash()},
					}
					block, err := abeutil.NewBlockAbe(msg)
					if err != nil {
						t.Fatal(err)
					}
					block.SetHeight(height)
					err = b.checkBlockContextAbe(block, &blockNode{height: height - 1}, BFFastAdd)
					wantValid := coinbaseVersion == fork.newTx && (height < fork.commit || transferVersion == fork.newTx)
					if (err == nil) != wantValid {
						t.Fatalf("height %d, coinbase %d, transfer %d: valid=%v, err=%v", height, coinbaseVersion, transferVersion, wantValid, err)
					}
				}
			}
		}
	}
}

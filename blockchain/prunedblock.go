package blockchain

import (
	"fmt"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain/consensus"
	"github.com/abesuite/abec/blockchain/ruleerror"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

// CheckPrunedBlock verifies eligibility for supplemental downloads. It does not
// replace full block validation after reconstruction. An unknown parent returns
// ErrPreviousBlockUnknown so callers can use the ordinary full-block orphan path.
// This function is safe for concurrent access.
func (b *BlockChain) CheckPrunedBlock(block *wire.MsgPrunedBlock, pow *consensus.PowConsensus) error {
	if block.CoinbaseTx == nil || !block.CoinbaseTx.HasTxWitness() {
		return fmt.Errorf("pruned block coinbase has no witness")
	}
	if len(block.TransactionHashes) != len(block.WitnessHashs) {
		return fmt.Errorf("pruned block transaction and witness hash counts differ")
	}

	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	header := &block.Header
	prev := b.index.LookupNode(&header.PrevBlock)
	if prev == nil {
		return ruleerror.NewRuleError(ruleerror.ErrPreviousBlockUnknown, "pruned block parent is unknown")
	}
	if b.index.NodeStatus(prev).KnownInvalid() {
		return ruleerror.NewRuleError(ruleerror.ErrInvalidAncestorBlock, "pruned block parent is invalid")
	}
	// Reject invalid targets and timestamps without performing PoW yet.
	if err := checkBlockHeaderSanity(header, pow, b.chainParams.PowLimit, b.timeSource, BFNoPoWCheck); err != nil {
		return err
	}

	// Check height, version and expected difficulty before PoW verification,
	// which may otherwise create an Ethash cache for an untrusted epoch.
	if err := b.checkBlockHeaderContextAbe(header, prev, BFNone); err != nil {
		return err
	}
	coinbase, err := abeutil.NewTxAbe(block.CoinbaseTx, nil)
	if err != nil {
		return err
	}
	if err := checkSerializedHeightAbe(coinbase, prev.height+1); err != nil {
		return err
	}

	flags := BFNone
	if b.chainParams.Net != wire.MainNet {
		// The coinbase height now agrees with the parent. Preserve the same
		// configured fake-PoW scopes used by the ordinary block path.
		for _, scope := range b.FakePoWHeightScopes() {
			if scope.StartHeight <= prev.height+1 && prev.height+1 < scope.EndHeight {
				flags |= BFNoPoWCheck
				break
			}
		}
	}
	if err := checkProofOfWork(header, pow, b.chainParams.PowLimit, flags); err != nil {
		return err
	}

	// Mirror checkBlockContextAbe's coinbase version rules for admission.
	// Full-block validation retains its original check order and errors.
	height, version := prev.height+1, coinbase.MsgTx().Version
	if height >= b.chainParams.BlockHeightAconcagua {
		if version < wire.TxVersion_Height_464000_Aconcagua {
			return fmt.Errorf("coinbase transaction version %d is invalid at block height %d", version, height)
		}
	} else if version >= wire.TxVersion_Height_464000_Aconcagua {
		return fmt.Errorf("coinbase transaction version %d is invalid at block height %d", version, height)
	}
	if height >= b.chainParams.BlockHeightMLPAUT {
		if version < wire.TxVersion_Height_MLPAUT_300000 {
			return fmt.Errorf("coinbase transaction version %d is invalid at block height %d", version, height)
		}
	} else if version >= wire.TxVersion_Height_MLPAUT_300000 {
		return fmt.Errorf("coinbase transaction version %d is invalid at block height %d", version, height)
	}

	if err := CheckTransactionSanityAbe(coinbase); err != nil {
		return err
	}
	if err := checkPrunedBlockMerkleRoot(block); err != nil {
		return err
	}

	return nil
}

func checkPrunedBlockMerkleRoot(block *wire.MsgPrunedBlock) error {
	hashPair := HashMerkleBranches
	if block.Header.Version >= wire.BlockVersionEthashPow {
		hashPair = HashMerkleBranchesEthash
	}
	// Leaves commit to both transaction and witness hashes, using the same
	// hash function as branches in each consensus era.
	leaves := make([]*chainhash.Hash, len(block.TransactionHashes)+1)
	coinbaseHash := block.CoinbaseTx.TxHash()
	leaves[0] = hashPair(&coinbaseHash, block.CoinbaseTx.TxWitnessHash())
	for i := range block.TransactionHashes {
		leaves[i+1] = hashPair(&block.TransactionHashes[i], &block.WitnessHashs[i])
	}
	for len(leaves) > 1 {
		for i := 0; i < len(leaves); i += 2 {
			right := min(i+1, len(leaves)-1)
			leaves[i/2] = hashPair(leaves[i], leaves[right])
		}
		leaves = leaves[:(len(leaves)+1)/2]
	}
	if !block.Header.MerkleRoot.IsEqual(leaves[0]) {
		return ruleerror.NewRuleError(ruleerror.ErrBadMerkleRoot, "pruned block merkle root is invalid")
	}
	return nil
}

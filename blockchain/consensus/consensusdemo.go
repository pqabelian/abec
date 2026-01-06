// Copyright (c) 2021-2025 The Abelian Foundation. All rights reserved.
// This file is part of Abelian.
//
// This source code is licensed under the MIT License found in the LICENSE file
// in the root directory of this source tree.
//
//
// Abelian Foundation 2021-2025
//
//

package consensus

import (
	"github.com/abesuite/abec/blockchain/consensus/ethashpow"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"math/big"
)

// EthashPowVerifySealFast is a demo function to support the demo of ethashPow mining.
// It performs a quick verification on whether (nonceExt, mixDigest) forms a seal of contextHash with respect to target.
//
// This algorithm is used to check the validity of nonceExt at a low cost, to prevent DOS attack.
func EthashPowVerifySealFast(headerContentHash chainhash.Hash, nonceExt uint64, mixDigest chainhash.Hash, target *big.Int) bool {
	return ethashpow.VerifySealFast(headerContentHash, nonceExt, mixDigest, target)
}

// EthashPowTrySeal is a demo function to support the demo of ethashPow mining.
// It tris nonce to test whether the nonce generates a valid sealHash which lies in the scope specified by target,
// i.e., satisfying the consensus rules defined by VerifySeal().
// If the input nonce is valid, the block header will be updated, i.e., the MixDigest and NonceExt are set.
// To enable multiple calls on TrySeal() to use the same epoch and contentHash (to avoid the unnecessary computation of epoch and contentHash),
// this function takes epoch and contentHash as input, which should be computed by the caller on the input "header *wire.BlockHeader".
// That is, it is the responsibility of the caller to provide the epoch, contentHash and target corresponding to the input blockHeader,
// and the header *wire.BlockHeader is actually responsible to take the MixDigest and NonceExt out (if they are valid).
// To mine, TrySeal() will be called highly frequently.
// TrySeal() just provides a reference implementation for mining, i.e., finding valid EthashPoW solutions.
// Note that, the consensus rules are defined by VerifySeal(), and any nonce, whatever how it is found, is fine,
// as long as it satisfies the rules defined by VerifySeal().
func (powConsensus *PowConsensus) EthashPowTrySeal(epoch int, contentHash chainhash.Hash, nonceExt uint64, target *big.Int, header *wire.BlockHeader) bool {
	return powConsensus.ethashPow.TrySeal(epoch, contentHash, nonceExt, target, header)
}

// EthashPowPrepareDatasetForUpgrade is a demo function to support the demo of ethashPow mining.
func (powConsensus *PowConsensus) EthashPowPrepareDatasetForUpgrade(currentHeight int32) {
	//	As dataset generation is slow, say about 10 minutes, we need to prepare the dataset in advance.
	//	Such a call will generate the first dataset and the second dataset (as the future one).
	//	Each will take 10 minutes (even in the setting without mining).
	//	To be safe, we call this procedure 200 minutes in advance.
	if !powConsensus.ethashPow.FakePow() && currentHeight == powConsensus.ethashPow.EthashPowStartHeight()-100 {
		powConsensus.ethashPow.PrepareDatasetForUpgrade()
	}
}

// EthashPowEpoch is a demo function to support the demo of ethashPow mining.
func (powConsensus *PowConsensus) EthashPowEpoch(blockHeight int32) int {
	return powConsensus.ethashPow.Epoch(blockHeight)
}

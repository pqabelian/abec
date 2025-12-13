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
	"fmt"
	"github.com/abesuite/abec/blockchain/consensus/ethashpow"
	"github.com/abesuite/abec/blockchain/consensus/nakamotopowaconcagua"
	"github.com/abesuite/abec/blockchain/consensus/nakamotopowinit"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"math/big"
)

type PowConsensus struct {
	nakamotoPowAconcagua *nakamotopowaconcagua.NakamotoPowAconcagua
	ethashPow            *ethashpow.EthashPow
	nakamotoPowInit      *nakamotopowinit.NakamotoPowInit
}

// NewPowConsensus creates a PowConsensus, using the passed ethashpow.EthashConfig.
func NewPowConsensus(ethashConfig ethashpow.EthashConfig) *PowConsensus {
	powConsensus := &PowConsensus{}

	// nakamotoPowAconcagua
	powConsensus.nakamotoPowAconcagua = nakamotopowaconcagua.NewNakamotoPowAconcagua()

	// ethashPow
	powConsensus.ethashPow = ethashpow.NewEthashPow(ethashConfig)

	// nakamotoPowInit
	powConsensus.nakamotoPowInit = nakamotopowinit.NewNakamotoPowInit()

	return powConsensus
}

// VerifySeal verifies whether the passed wire.BlockHeader is valid with respect to the passed target.
//
// targetSecond may be used only when header.Version >= wire.BlockVersionAconcagua.
// review done 2025.12.12
func (powConsensus *PowConsensus) VerifySeal(header *wire.BlockHeader, target *big.Int, targetSecond *big.Int) error {
	if header == nil {
		return fmt.Errorf("PowConsensus.VerifySeal: the input header is nil")
	}

	if header.Version >= wire.BlockVersionAconcagua {

		switch header.ConsensusApplied {

		case wire.ConsensusNakamotoPow:
			if powConsensus.nakamotoPowAconcagua == nil {
				return fmt.Errorf("PowConsensus.VerifySeal: nakamotoPowAconcagua is nil")
			}
			return powConsensus.nakamotoPowAconcagua.VerifySeal(header, target)

		case wire.ConsensusEthashPow:
			if powConsensus.ethashPow == nil {
				return fmt.Errorf("PowConsensus.VerifySeal: powConsensus.ethashPow is nil")
			}
			// Note that Aconcagua-fork uses the same ethashPow as the EthashPow-fork.
			return powConsensus.ethashPow.VerifySeal(header, targetSecond)

		default:
			// todo: confirm whether the rule error value matters
			return fmt.Errorf("PowConsensus.VerifySeal: header (height=%d, hash = %s) has an unsupported ConsensusApplied %d",
				header.Height, header.BlockHash().String(), header.ConsensusApplied)
		}
	}

	if header.Version >= wire.BlockVersionEthashPow {

		if powConsensus.ethashPow == nil {
			return fmt.Errorf("PowConsensus.VerifySeal: powConsensus.ethashPow is nil")
		}
		return powConsensus.ethashPow.VerifySeal(header, target)

	}

	// header.Version < wire.BlockVersionEthashPow

	if powConsensus.nakamotoPowInit == nil {
		return fmt.Errorf("PowConsensus.VerifySeal: nakamotoPowInit is nil")
	}
	return powConsensus.nakamotoPowInit.VerifySeal(header, target)

}

// HeaderContentHash returns the hash of the passed BlockHeader's HeaderContent.
//
//   - EthashPow uses (HeaderContentHash, NonceExt) to mine/find the valid (MixDigest,SealHash),
//     and can use (HeaderContentHash, NonceExt, MixDigest) to compute SealHash fast (without expensive computation)
//     to have a quick verification.
//   - NakamotoPowAconcagua does not use this function.
//     To be self-completed, NakamotoPowAconcagua also provides this function.
//   - NakamotoPowInit does not use this function.
//     To be self-completed, NakamotoPowInit also provides this function.
//
// See (bh *BlockHeader) HeaderContent() and ethashpow.SealHashFast().
func HeaderContentHash(header *wire.BlockHeader) (*chainhash.Hash, error) {
	if header == nil {
		return nil, fmt.Errorf("HeaderContentHash: the input header is nil")
	}

	if header.Version >= wire.BlockVersionAconcagua {

		switch header.ConsensusApplied {

		case wire.ConsensusNakamotoPow:
			// for ConsensusNakamotoPow, HeaderContentHash is used to build the SealHashPreImage.
			return nakamotopowaconcagua.HeaderContentHash(header)

		case wire.ConsensusEthashPow:
			// Note that Aconcagua-fork uses the same ethashPow as the EthashPow-fork.
			return ethashpow.HeaderContentHash(header)

		default:
			// todo: confirm whether the rule error value matters
			return nil,
				fmt.Errorf("HeaderContentHash: header (height=%d, hash = %s) has an unsupported ConsensusApplied %d",
					header.Height, header.BlockHash().String(), header.ConsensusApplied)
		}
	}

	if header.Version >= wire.BlockVersionEthashPow {
		return ethashpow.HeaderContentHash(header)
	}

	// for header.Version < wire.BlockVersionEthashPow, this function is meaningless.
	return nakamotopowinit.HeaderContentHashDummy(header)
}

// SealHashFast returns the sealHash of the input block header, by simply computing the SealHash,
// without performing the expensive (verification) computations.
//
// This algorithm is used only where sealHash is needed independently, for example, for display.
func SealHashFast(header *wire.BlockHeader) chainhash.Hash {
	if header == nil {
		return chainhash.InvalidHash
	}

	if header.Version >= wire.BlockVersionAconcagua {
		switch header.ConsensusApplied {
		case wire.ConsensusNakamotoPow:
			return nakamotopowaconcagua.SealHashFast(header)

		case wire.ConsensusEthashPow:
			// Note that Aconcagua-fork uses the same ethashPow as the EthashPow-fork.
			return ethashpow.SealHashFast(header)

		default:
			return chainhash.InvalidHash
		}
	}

	if header.Version >= wire.BlockVersionEthashPow {
		return ethashpow.SealHashFast(header)
	}

	return nakamotopowinit.SealHashFast(header)

}

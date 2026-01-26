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

package ethashpow

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"time"

	"github.com/pqabelian/abec/blockchain/consensus/common"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/wire"
	"golang.org/x/crypto/sha3"
)

// Various error messages to mark blocks invalid. These should be private to
// prevent engine specific errors from being referenced in the remainder of the
// codebase, inherently breaking if the engine is swapped out. Please put common
// error types into the consensus package.
var (
	errInvalidMixDigest = errors.New("invalid mix digest")
	errInvalidPoW       = errors.New("invalid proof-of-work")
)

// VerifySeal checks whether a block(header) satisfies the Ethash-PoW difficulty requirements,
// either using the usual ethash cache for it, or alternatively using a full DAG to make it faster.
// VerifySeal() define the consensus rules.
// As the target rule may depend on the blockchain, EthashPow leaves the difficulty computation to blockchain module.
// review done 2025.12.12
func (ethashPow *EthashPow) VerifySeal(header *wire.BlockHeader, target *big.Int) error {

	if header.Version < wire.BlockVersionEthashPow {
		return fmt.Errorf("EthashPow VerifySeal: wrong call on this funciton, "+
			"since header.Version (%d) < wire.BlockVersionEthashPow", header.Version)
	}

	//	ethash.config.VerifyByFullDAG allows to configure a mining machine to use fullDAG to have faster verification.
	fulldag := ethashPow.config.VerifyByFullDAG

	// If we're running a fake PoW, accept any seal as valid
	if ethashPow.config.PowMode == ModeFake || ethashPow.config.PowMode == ModeFullFake {
		time.Sleep(ethashPow.fakeDelay)
		if ethashPow.fakeFail == header.Height {
			return errInvalidPoW
		}
		return nil
	}

	// Note that since AbelEthash-Pow tekase effect, blockHeader contains Height.
	epoch := int((header.Height - ethashPow.config.BlockHeightStart) / ethashPow.config.EpochLength)

	// Recompute the digest and PoW values
	var (
		digest   []byte
		sealHash chainhash.Hash
	)

	headerContentHash, err := HeaderContentHash(header)
	if err != nil {
		return err
	}

	// If fast-but-heavy PoW verification was requested, use an ethash dataset
	if fulldag {
		datasetInst := ethashPow.dataset(epoch, true)
		if datasetInst.generated() {
			digest, sealHash = hashimotoFull(datasetInst.dataset, *headerContentHash, header.NonceExt)

			// Datasets are unmapped in a finalizer. Ensure that the dataset stays alive
			// until after the call to hashimotoFull so it's not unmapped while being used.
			runtime.KeepAlive(datasetInst)
		} else {
			// dataset not yet generated, don't hang, use a cache instead
			fulldag = false
		}
	}
	// If slow-but-light PoW verification was requested (or DAG is not yet ready), use an ethash cache
	if !fulldag {
		cacheInst := ethashPow.cache(epoch)

		size := datasetSize(epoch)
		if ethashPow.config.PowMode == ModeTest {
			size = 32 * 1024
		}
		digest, sealHash = hashimotoLight(size, cacheInst.cache, *headerContentHash, header.NonceExt)

		// Caches are unmapped in a finalizer. Ensure that the cache stays alive
		// until after the call to hashimotoLight so it's not unmapped while being used.
		runtime.KeepAlive(cacheInst)
	}

	// Verify the calculated values against the ones provided in the header
	if !bytes.Equal(header.MixDigest[:], digest) {
		return errInvalidMixDigest
	}

	//	todo: (optimization) if necessary, directly hashToBig here, rather call a function
	if common.HashToBig(sealHash).Cmp(target) > 0 {
		return errInvalidPoW
	}

	////	Optimization: directly hashToBig here, rather call the function hashToBig()
	////	The mining part codes, e.g. TrySeal(), should match the codes here.
	//for i := 0; i < chainhash.HashSize/2; i++ {
	//	sealHash[i], sealHash[chainhash.HashSize-1-i] = sealHash[chainhash.HashSize-1-i], sealHash[i]
	//}
	//if new(big.Int).SetBytes(sealHash[:]).Cmp(target) > 0 {
	//	return errInvalidPoW
	//}

	return nil
}

// HeaderContentHash returns the hash of the passed BlockHeader's HeaderContent, computed by SHA3-256.
//
// EthashPow uses (HeaderContentHash, NonceExt) to mine/find the valid (MixDigest,SealHash), and
// can use (HeaderContentHash, NonceExt, MixDigest) to compute SealHash fast (without expensive computation) to have a quick verification.
//
// See (bh *BlockHeader) HeaderContent() and VerifySealFast().
// review done 2025.12.12
func HeaderContentHash(header *wire.BlockHeader) (*chainhash.Hash, error) {
	headerContent, err := header.HeaderContent()
	if err != nil {
		return nil, err
	}

	headerContentHash := chainhash.ChainHash(headerContent)
	return &headerContentHash, nil
}

// VerifySealFast performs a quick verification on whether (nonceExt, mixDigest) forms a seal of contentHash with respect to target,
// without checking whether mixDigest is consistent with (headerContentHash, nonceExt), which are expensive on computation and storage.
//
// This algorithm is used to check the validity of nonceExt at a low cost, to prevent DOS attack.
func VerifySealFast(headerContentHash chainhash.Hash, nonceExt uint64, mixDigest chainhash.Hash, target *big.Int) bool {
	// Combine contentHash + nonce into a 64 byte seed
	seedTmp := make([]byte, chainhash.HashSize+8)
	copy(seedTmp, headerContentHash[:])
	binary.LittleEndian.PutUint64(seedTmp[chainhash.HashSize:], nonceExt)

	// we use the standard SHA3-512, rather than LegacyKeccak512
	// seed = crypto.Keccak512(seed)
	//seed := make([]byte, 64)
	seed := sha3.Sum512(seedTmp)
	//copy(seed, hashTmp[:])

	sealHash := chainhash.ChainHash(append(seed[:], mixDigest[:]...))

	//	This part codes must match with that in VerifySeal().
	if common.HashToBig(sealHash).Cmp(target) <= 0 {
		return true
	}

	return false

}

// SealHashFast returns the sealHash of the input block header.
//
// The algorithm codes are consistent with the codes in hashimoto(),
// but only compute the sealHash using contentHash, NonceExt and MixDigest,
// without checking whether MixDigest is consistent with (contentHash, NonceExt).
// Note that the consistence is actually a part of the block-validity checks.
//
// This algorithm is used only where sealHash is needed independently, for example, for display.
func SealHashFast(header *wire.BlockHeader) chainhash.Hash {
	if header == nil {
		return chainhash.InvalidHash
	}

	// Combine contentHash + nonce into a 64 byte seed
	headerContentHash, err := HeaderContentHash(header)
	if err != nil {
		return chainhash.InvalidHash
	}

	seedTmp := make([]byte, chainhash.HashSize+8)
	copy(seedTmp, headerContentHash[:])
	binary.LittleEndian.PutUint64(seedTmp[chainhash.HashSize:], header.NonceExt)

	// we use the standard SHA3-512, rather than LegacyKeccak512
	// seed = crypto.Keccak512(seed)
	//seed := make([]byte, 64)
	seed := sha3.Sum512(seedTmp)
	//copy(seed, hashTmp[:])

	return chainhash.ChainHash(append(seed[:], header.MixDigest[:]...))
}

package ethashpow

import (
	"github.com/abesuite/abec/blockchain/consensus/common"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"math/big"
	"runtime"
)

// The functions below are used to support the demo of ethashPow mining.

// Epoch packages the computation of epoch.
// To be efficient, when calling this function inside ethash package,
// we directly use the computation rather than call this function.
func (ethashPow *EthashPow) Epoch(blockHeight int32) int {
	return int((blockHeight - ethashPow.config.BlockHeightStart) / ethashPow.config.EpochLength)
}

// TrySeal tris nonce to test whether the nonce generates a valid sealHash which lies in the scope specified by target,
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
func (ethashPow *EthashPow) TrySeal(epoch int, contentHash chainhash.Hash, nonceExt uint64, target *big.Int, header *wire.BlockHeader) bool {

	var digest []byte
	var sealHash chainhash.Hash

	datasetInst := ethashPow.dataset(epoch, true)
	if datasetInst.generated() {
		digest, sealHash = hashimotoFull(datasetInst.dataset, contentHash, nonceExt)

		// Datasets are unmapped in a finalizer. Ensure that the dataset stays alive
		// until after the call to hashimotoFull so it's not unmapped while being used.
		runtime.KeepAlive(datasetInst)

	} else {
		cacheInst := ethashPow.cache(epoch)

		size := datasetSize(epoch)
		if ethashPow.config.PowMode == ModeTest {
			size = 32 * 1024
		}
		digest, sealHash = hashimotoLight(size, cacheInst.cache, contentHash, nonceExt)

		// Caches are unmapped in a finalizer. Ensure that the cache stays alive
		// until after the call to hashimotoLight so it's not unmapped while being used.
		runtime.KeepAlive(cacheInst)
	}

	if common.HashToBig(sealHash).Cmp(target) <= 0 {

		header.NonceExt = nonceExt

		header.MixDigest = chainhash.Hash{} // to make sure header.MixDigest != nil
		copy(header.MixDigest[:], digest)

		return true
	}

	return false
}

// HashPerTrySeal denotes the number of hashes per call of TrySeal() function.
// There are two hashes in one TrySeal (actually in hashimoto()), one for naive hash, and one on input the mixDigest computed from DAG.
// While the later one takes much more time than the former one, we only count the later one for hash rate.
// Or, in other words, the hast times means the number of tried nonce.
const HashPerTrySeal = 1 //2

// PrepareDatasetForUpgrade is used only for preparing the initial dataset when upgrading.
func (ethashPow *EthashPow) PrepareDatasetForUpgrade() {
	ethashPow.dataset(0, true)
}

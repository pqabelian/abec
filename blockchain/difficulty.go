package blockchain

import (
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"math/big"
	"time"
)

// dsaSmoothFactors defines the smooth factor for DSA by hardcode,
// say that, it supports only this smooth factor array, i.e., the difficulty of coming slot will be affected/computed
// from the immediate 20 slots (of blocks), where the number of blocks in each slot is decided by TargetTimespanDSA and TargetTimePerBlockDSA.
// Added by Alice, 2024.05.11, for DSA
// todo(DSA): review
//var dsaSmoothFactors = [20]float64{
//	0.0025, 0.0075,
//	0.0125, 0.0175,
//	0.0225, 0.0275,
//	0.0325, 0.0375,
//	0.0425, 0.0475,
//	0.0525, 0.0575,
//	0.0625, 0.0675,
//	0.0725, 0.0775,
//	0.0825, 0.0875,
//	0.0925, 0.0975,
//}

// dsaSmoothFactorsInt gives the smooth factors in integer.
// The final result will be divided by 10000.
var dsaSmoothFactorsInt = [20]int64{
	25, 75,
	125, 175,
	225, 275,
	325, 375,
	425, 475,
	525, 575,
	625, 675,
	725, 775,
	825, 875,
	925, 975,
}

// bigTenThousand will be used to compute smooth factor from dsaSmoothFactorsInt.
var bigTenThousand = big.NewInt(10000)

var (
	// bigOne is 1 represented as a big.Int.  It is defined here to avoid
	// the overhead of creating it multiple times.
	bigOne = big.NewInt(1)

	// oneLsh256 is 1 shifted left 256 bits.  It is defined here to avoid
	// the overhead of creating it multiple times.
	oneLsh256 = new(big.Int).Lsh(bigOne, 256)
)

// HashToBig converts a chainhash.Hash into a big.Int that can be used to
// perform math comparisons.
func HashToBig(hash *chainhash.Hash) *big.Int {
	// A Hash is in little-endian, but the big package wants the bytes in
	// big-endian, so reverse them.
	buf := *hash
	blen := len(buf)
	for i := 0; i < blen/2; i++ {
		buf[i], buf[blen-1-i] = buf[blen-1-i], buf[i]
	}

	return new(big.Int).SetBytes(buf[:])
}

// CompactToBig converts a compact representation of a whole number N to an
// unsigned 32-bit number.  The representation is similar to IEEE754 floating
// point numbers.
//
// Like IEEE754 floating point, there are three basic components: the sign,
// the exponent, and the mantissa.  They are broken out as follows:
//
//   - the most significant 8 bits represent the unsigned base 256 exponent
//
//   - bit 23 (the 24th bit) represents the sign bit
//
//   - the least significant 23 bits represent the mantissa
//
//     -------------------------------------------------
//     |   Exponent     |    Sign    |    Mantissa     |
//     -------------------------------------------------
//     | 8 bits [31-24] | 1 bit [23] | 23 bits [22-00] |
//     -------------------------------------------------
//
// The formula to calculate N is:
//
//	N = (-1^sign) * mantissa * 256^(exponent-3)
//
// This compact form is only used in bitcoin to encode unsigned 256-bit numbers
// which represent difficulty targets, thus there really is not a need for a
// sign bit, but it is implemented here to stay consistent with bitcoind.
func CompactToBig(compact uint32) *big.Int {
	// Extract the mantissa, sign bit, and exponent.
	mantissa := compact & 0x007fffff
	isNegative := compact&0x00800000 != 0
	exponent := uint(compact >> 24)

	// Since the base for the exponent is 256, the exponent can be treated
	// as the number of bytes to represent the full 256-bit number.  So,
	// treat the exponent as the number of bytes and shift the mantissa
	// right or left accordingly.  This is equivalent to:
	// N = mantissa * 256^(exponent-3)
	var bn *big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		bn = big.NewInt(int64(mantissa))
	} else {
		bn = big.NewInt(int64(mantissa))
		bn.Lsh(bn, 8*(exponent-3))
	}

	// Make it negative if the sign bit is set.
	if isNegative {
		bn = bn.Neg(bn)
	}

	return bn
}

// BigToCompact converts a whole number N to a compact representation using
// an unsigned 32-bit number.  The compact representation only provides 23 bits
// of precision, so values larger than (2^23 - 1) only encode the most
// significant digits of the number.  See CompactToBig for details.
func BigToCompact(n *big.Int) uint32 {
	// No need to do any work if it's zero.
	if n.Sign() == 0 {
		return 0
	}

	// Since the base for the exponent is 256, the exponent can be treated
	// as the number of bytes.  So, shift the number right or left
	// accordingly.  This is equivalent to:
	// mantissa = mantissa / 256^(exponent-3)
	var mantissa uint32
	exponent := uint(len(n.Bytes()))
	if exponent <= 3 {
		mantissa = uint32(n.Bits()[0])
		mantissa <<= 8 * (3 - exponent)
	} else {
		// Use a copy to avoid modifying the caller's original number.
		tn := new(big.Int).Set(n)
		mantissa = uint32(tn.Rsh(tn, 8*(exponent-3)).Bits()[0])
	}

	// When the mantissa already has the sign bit set, the number is too
	// large to fit into the available 23-bits, so divide the number by 256
	// and increment the exponent accordingly.
	if mantissa&0x00800000 != 0 {
		mantissa >>= 8
		exponent++
	}

	// Pack the exponent, sign bit, and mantissa into an unsigned 32-bit
	// int and return it.
	compact := uint32(exponent<<24) | mantissa
	if n.Sign() < 0 {
		compact |= 0x00800000
	}
	return compact
}

// CalcWork calculates a work value from difficulty bits.  Bitcoin increases
// the difficulty for generating a block by decreasing the value which the
// generated hash must be less than.  This difficulty target is stored in each
// block header using a compact representation as described in the documentation
// for CompactToBig.  The main chain is selected by choosing the chain that has
// the most proof of work (highest difficulty).  Since a lower target difficulty
// value equates to higher actual difficulty, the work value which will be
// accumulated must be the inverse of the difficulty.  Also, in order to avoid
// potential division by zero and really small floating point numbers, the
// result adds 1 to the denominator and multiplies the numerator by 2^256.
func CalcWork(bits uint32) *big.Int {
	// Return a work value of zero if the passed difficulty bits represent
	// a negative number. Note this should not happen in practice with valid
	// blocks, but an invalid block could trigger it.
	difficultyNum := CompactToBig(bits)
	if difficultyNum.Sign() <= 0 {
		return big.NewInt(0)
	}

	// (1 << 256) / (difficultyNum + 1)
	denominator := new(big.Int).Add(difficultyNum, bigOne)
	return new(big.Int).Div(oneLsh256, denominator)
}

// Added by Alice, 2024.05.11, for DSA
// todo(DSA): review
func calcTargetFromExpectedWorkSumPerBlock(expectedWorkSumPerBlock *big.Int) *big.Int {
	denominator := big.NewInt(1)
	if expectedWorkSumPerBlock != nil && expectedWorkSumPerBlock.Sign() > 0 {
		denominator = expectedWorkSumPerBlock
	}

	// (1 << 256) / (expectedWorkSum)
	// This is assuming that Hash-with-256-output is used for the PoW algorithm.
	return new(big.Int).Div(oneLsh256, denominator)
}

// calcEasiestDifficulty calculates the easiest possible difficulty that a block
// can have given starting difficulty bits and a duration.  It is mainly used to
// verify that claimed proof of work by a block is sane as compared to a
// known good checkpoint.
func (b *BlockChain) calcEasiestDifficulty(bits uint32, duration time.Duration) uint32 {
	// Convert types used in the calculations below.
	durationVal := int64(duration / time.Second)
	adjustmentFactor := big.NewInt(b.chainParams.RetargetAdjustmentFactor)

	// The test network rules allow minimum difficulty blocks after more
	// than twice the desired amount of time needed to generate a block has
	// elapsed.
	if b.chainParams.ReduceMinDifficulty {
		reductionTime := int64(b.chainParams.MinDiffReductionTime /
			time.Second)
		if durationVal > reductionTime {
			return b.chainParams.PowLimitBits
		}
	}

	// Since easier difficulty equates to higher numbers, the easiest
	// difficulty for a given duration is the largest value possible given
	// the number of retargets for the duration and starting difficulty
	// multiplied by the max adjustment factor.
	newTarget := CompactToBig(bits)
	for durationVal > 0 && newTarget.Cmp(b.chainParams.PowLimit) < 0 {
		newTarget.Mul(newTarget, adjustmentFactor)
		durationVal -= b.maxRetargetTimespan
	}

	// Limit new value to the proof of work limit.
	if newTarget.Cmp(b.chainParams.PowLimit) > 0 {
		newTarget.Set(b.chainParams.PowLimit)
	}

	return BigToCompact(newTarget)
}

// findPrevTestNetDifficulty returns the difficulty of the previous block which
// did not have the special testnet minimum difficulty rule applied.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) findPrevTestNetDifficulty(startNode *blockNode) uint32 {
	// Search backwards through the chain for the last block without
	// the special rule applied.
	iterNode := startNode
	for iterNode != nil && iterNode.height%b.blocksPerRetarget != 0 &&
		iterNode.bits == b.chainParams.PowLimitBits {

		iterNode = iterNode.parent
	}

	// Return the found difficulty or the minimum difficulty if no
	// appropriate block was found.
	lastBits := b.chainParams.PowLimitBits
	if iterNode != nil {
		lastBits = iterNode.bits
	}
	return lastBits
}

// findPrevTestNetDifficultyDSA returns the difficulty of the previous block which
// did not have the special testnet minimum difficulty rule applied.
// This function MUST be called with the chain state lock held (for writes).
// Added by Alice, 2024.05.11, for DSA
// todo(DSA): review
func (b *BlockChain) findPrevTestNetDifficultyDSA(startNode *blockNode) uint32 {
	// Search backwards through the chain for the last block without
	// the special rule applied.
	iterNode := startNode
	for iterNode != nil && iterNode.height%b.blocksPerRetargetDSA != 0 &&
		iterNode.bits == b.chainParams.PowLimitBits {

		iterNode = iterNode.parent
	}

	// Return the found difficulty or the minimum difficulty if no
	// appropriate block was found.
	lastBits := b.chainParams.PowLimitBits
	if iterNode != nil {
		lastBits = iterNode.bits
	}
	return lastBits
}

// calcNextRequiredDifficulty calculates the required difficulty for the block
// after the passed previous block node based on the difficulty retarget rules.
// This function differs from the exported CalcNextRequiredDifficulty in that
// the exported version uses the current best chain as the previous block node
// while this function accepts any block node.
func (b *BlockChain) calcNextRequiredDifficulty(lastNode *blockNode, newBlockTime time.Time) (uint32, error) {
	// Genesis block.
	if lastNode == nil {
		return b.chainParams.PowLimitBits, nil
	}

	// Added by Alice, 2024.05.11, for DSA
	// todo(DSA): review
	if lastNode.height+1 >= b.chainParams.BlockHeightDSA {
		//	DSA takes effect from BlockHeightMLPAUT

		// Return the previous block's difficulty requirements if this block
		// is not at a difficulty retarget interval.
		if (lastNode.height+1)%b.blocksPerRetargetDSA != 0 {
			// For networks that support it, allow special reduction of the
			// required difficulty once too much time has elapsed without
			// mining a block.
			if b.chainParams.ReduceMinDifficulty {
				// Return minimum difficulty when more than the desired
				// amount of time has elapsed without mining a block.
				reductionTime := int64(b.chainParams.MinDiffReductionTime /
					time.Second)
				allowMinTime := lastNode.timestamp + reductionTime
				if newBlockTime.Unix() > allowMinTime {
					return b.chainParams.PowLimitBits, nil
				}

				// The block was mined within the desired timeframe, so
				// return the difficulty for the last block which did
				// not have the special minimum difficulty rule applied.
				return b.findPrevTestNetDifficultyDSA(lastNode), nil
			}

			// For the main network (or any unrecognized networks), simply
			// return the previous block's difficulty requirements.
			return lastNode.bits, nil
		}

		// the classic difficulty adjustment mechanism:
		// currentDifficulty * (adjustedTimespan / targetTimespan),
		// where adjustedTimespan (normally) is the time spent to generate last blocksPerRetarget blocks, say actualTimespan.
		// and targetTimespan is the target time that the system expects to generate the coming/next blocksPerRetarget blocks.
		// The behind principles: the system assumes the computation power, say HashRate in the coming epoch will be the same as the last epoch,
		// then, using such a HashRate and the (expected) targetTimespan, the system sets the difficulty for the coming epoch.
		// The HashRate of the last epoch is:  (2^{256} / oldTarget) * blocksPerRetarget / actualTimespan,
		// The HashRate of the coming epoch is:  (2^{256} / newTarget) * blocksPerRetarget / targetTimespan.
		// The HashRate of the last epoch is:  epochWorkSum_old / actualTimespan,
		// The HashRate of the coming epoch is:  epochWorkSum_new / targetTimespan.
		// Note that epochWorkSum_old = blocksPerRetarget * blockWorkSum_old, and blockWorkSum_old = (1 << 256) / (target_old + 1)
		//       and epochWorkSum_new = blocksPerRetarget * blockWorkSum_new, and blockWorkSum_new = (1 << 256) / (target_new + 1)
		// Thus, we have (target_old + 1) * actualTimespan = (target_new+1) * targetTimespan，
		// and then target_new + 1 = (target_old + 1 ) * (actualTimespan / targetTimespan), which means approximately
		// target_new = target_old * (actualTimespan / targetTimespan)

		// For Difficulty Smooth Adjustment:
		// The system assumes the HashRate in the coming slot will be the (weighted) average of the HashRate of the previous 20 slots.
		// alpha_0 HR_0 + ... + alpha_19 HR_19 = (1 << 256) / (target_new + 1) * blocksPerRetargetDSA / targetTimespanDSA, where
		// HR_i = slotWorkSum_i / actualTimespan_i
		// Then, target_new = (1 << 256) / (avgHR * targetTimespanPerBlockDSA).

		// Difficulty Smooth Adjustment
		log.Infof("Difficulty retarget at block height %d", lastNode.height+1)

		avgHR := big.NewInt(0)
		latestHR := big.NewInt(1)
		latestTimeSpan := int64(1)

		slotWorkSum := big.NewInt(0)
		slotTimeSpan := big.NewInt(1)
		hashRate := big.NewInt(1)

		factorInt := big.NewInt(1)
		avgItem := big.NewInt(1)

		slotEndNode := lastNode
		for i := len(dsaSmoothFactorsInt) - 1; i >= 0; i-- {
			if slotEndNode == nil {
				return 0, AssertError(fmt.Sprintf("%d-th slotEndNode is nil", i))
			}

			slotStartNode := slotEndNode.RelativeAncestor(b.blocksPerRetargetDSA - 1)
			if slotStartNode == nil {
				return 0, AssertError(fmt.Sprintf("unable to obtain %d-th slotStartNode (at heigt %d)", i, slotEndNode.height-b.blocksPerRetargetDSA+1))
			}

			if slotEndNode.workSum.Cmp(slotStartNode.workSum) <= 0 {
				errStr := fmt.Sprintf("slotEndNode (at heigt %d, hash %s) has workSum %d, while slotStartNode (at heigt %d, hash %s) has workSum %d",
					slotEndNode.height, slotEndNode.hash, slotEndNode.workSum, slotStartNode.height, slotStartNode.hash, slotStartNode.workSum)
				return 0, AssertError(errStr)
			}

			timeStampWarn := false
			if slotEndNode.timestamp <= slotStartNode.timestamp {
				// This should not happen.
				// In case attacker launch attacks on this point and to make the system as robust as possible, we use a default smallest time and warn.
				timeStampWarn = true

				warnStr := fmt.Sprintf("slotEndNode (at heigt %d, hash %s) has timestamp %d, while slotStartNode (at heigt %d, hash %s) has timestamp %d",
					slotEndNode.height, slotEndNode.hash, slotEndNode.timestamp, slotStartNode.height, slotStartNode.hash, slotStartNode.timestamp)
				log.Warn(warnStr)
				log.Warn(warnStr)
				log.Warn(warnStr)
				// As this is actually a serious warning, it warns three times.
			}

			if timeStampWarn {
				slotTimeSpan.SetInt64(b.minRetargetTimespanDSA)
				// Note that when warning happens, it means the network hash rate is much larger than the difficulty evaluates,
				// for example, with the main net, at least 8 times of the expected (since, for main net 200 blocks were generated in 2 hours).
				// The above time setting may underestimate the hash rate for this slot.
				log.Infof("Timestamp warning happens. The slot time is set to minRetargetTimespan (%064x)", time.Duration(b.minRetargetTimespan)*time.Second)
			} else {
				slotTimeSpan.SetInt64(slotEndNode.timestamp - slotStartNode.timestamp) // in seconds
			}

			slotWorkSum = slotWorkSum.Sub(slotEndNode.workSum, slotStartNode.workSum)
			hashRate = hashRate.Div(slotWorkSum, slotTimeSpan)

			// logging for each slot
			log.Infof("Slot %d : start height: %d, end height %d, difficulty %08x (%064x), timespan %064x, workSum %d, hashRate %d",
				i, slotStartNode.height, slotEndNode.height, slotEndNode.bits, CompactToBig(slotEndNode.bits), time.Duration(slotTimeSpan.Int64())*time.Second, slotWorkSum, hashRate)

			if i == len(dsaSmoothFactorsInt)-1 {
				latestHR = hashRate
				latestTimeSpan = slotTimeSpan.Int64()
			}

			factorInt.SetInt64(dsaSmoothFactorsInt[i])
			avgItem = avgItem.Mul(hashRate, factorInt) // Note that this will not cause overflow
			avgHR = avgHR.Add(avgHR, avgItem)

			slotEndNode = slotStartNode.parent
		}

		avgHR = avgHR.Div(avgHR, bigTenThousand)

		retargetAdjustmentFactor := big.NewInt(b.chainParams.RetargetAdjustmentFactor)
		maxAllowedHR := new(big.Int).Mul(latestHR, retargetAdjustmentFactor)
		minAllowedHR := new(big.Int).Div(latestHR, retargetAdjustmentFactor)
		targetHR := avgHR
		if avgHR.Cmp(maxAllowedHR) == 1 {
			targetHR = maxAllowedHR
		} else if avgHR.Cmp(minAllowedHR) == -1 {
			targetHR = minAllowedHR
		}

		targetTimePerBlock := int64(b.chainParams.TargetTimePerBlockDSA / time.Second)
		targetWorkSumPerBlock := new(big.Int).Mul(targetHR, big.NewInt(targetTimePerBlock))
		newTarget := calcTargetFromExpectedWorkSumPerBlock(targetWorkSumPerBlock)

		// Limit new value to the proof of work limit.
		if newTarget.Cmp(b.chainParams.PowLimit) > 0 {
			newTarget.Set(b.chainParams.PowLimit)
		}

		// Log new target difficulty and return it.  The new target logging is
		// intentionally converting the bits back to a number instead of using
		// newTarget since conversion to the compact representation loses
		// precision.
		newTargetBits := BigToCompact(newTarget)

		log.Infof("Summary for Difficulty retarget at block height %d", lastNode.height+1)
		log.Infof("Old target %08x (%064x)", lastNode.bits, CompactToBig(lastNode.bits))
		log.Infof("New target %08x (%064x)", newTargetBits, CompactToBig(newTargetBits))
		log.Infof("Latest timespan %v, Latest Hash Rate %064x, Average Hash Rate %064x, Target Hash Rate %064x, Target timespan %v",
			time.Duration(latestTimeSpan)*time.Second,
			latestHR,
			avgHR,
			targetHR,
			b.chainParams.TargetTimespanDSA)

		return newTargetBits, nil
	}

	// Return the previous block's difficulty requirements if this block
	// is not at a difficulty retarget interval.
	if (lastNode.height+1)%b.blocksPerRetarget != 0 {
		// For networks that support it, allow special reduction of the
		// required difficulty once too much time has elapsed without
		// mining a block.
		if b.chainParams.ReduceMinDifficulty {
			// Return minimum difficulty when more than the desired
			// amount of time has elapsed without mining a block.
			reductionTime := int64(b.chainParams.MinDiffReductionTime /
				time.Second)
			allowMinTime := lastNode.timestamp + reductionTime
			if newBlockTime.Unix() > allowMinTime {
				return b.chainParams.PowLimitBits, nil
			}

			// The block was mined within the desired timeframe, so
			// return the difficulty for the last block which did
			// not have the special minimum difficulty rule applied.
			return b.findPrevTestNetDifficulty(lastNode), nil
		}

		// For the main network (or any unrecognized networks), simply
		// return the previous block's difficulty requirements.
		return lastNode.bits, nil
	}

	// Get the block node at the previous retarget (targetTimespan days
	// worth of blocks).
	firstNode := lastNode.RelativeAncestor(b.blocksPerRetarget - 1)
	if firstNode == nil {
		return 0, AssertError("unable to obtain previous retarget block")
	}

	// Limit the amount of adjustment that can occur to the previous
	// difficulty.
	actualTimespan := lastNode.timestamp - firstNode.timestamp
	adjustedTimespan := actualTimespan
	if actualTimespan < b.minRetargetTimespan {
		adjustedTimespan = b.minRetargetTimespan
	} else if actualTimespan > b.maxRetargetTimespan {
		adjustedTimespan = b.maxRetargetTimespan
	}

	// Calculate new target difficulty as:
	//  currentDifficulty * (adjustedTimespan / targetTimespan)
	// The result uses integer division which means it will be slightly
	// rounded down.  Bitcoind also uses integer division to calculate this
	// result.
	oldTarget := CompactToBig(lastNode.bits)
	newTarget := new(big.Int).Mul(oldTarget, big.NewInt(adjustedTimespan))
	targetTimeSpan := int64(b.chainParams.TargetTimespan / time.Second)
	newTarget.Div(newTarget, big.NewInt(targetTimeSpan))

	// Limit new value to the proof of work limit.
	if newTarget.Cmp(b.chainParams.PowLimit) > 0 {
		newTarget.Set(b.chainParams.PowLimit)
	}

	// Log new target difficulty and return it.  The new target logging is
	// intentionally converting the bits back to a number instead of using
	// newTarget since conversion to the compact representation loses
	// precision.
	newTargetBits := BigToCompact(newTarget)
	log.Infof("Difficulty retarget at block height %d", lastNode.height+1)
	log.Infof("Old target %08x (%064x)", lastNode.bits, oldTarget)
	log.Infof("New target %08x (%064x)", newTargetBits, CompactToBig(newTargetBits))
	log.Infof("Actual timespan %v, adjusted timespan %v, target timespan %v",
		time.Duration(actualTimespan)*time.Second,
		time.Duration(adjustedTimespan)*time.Second,
		b.chainParams.TargetTimespan)

	return newTargetBits, nil
}

// CalcNextRequiredDifficulty calculates the required difficulty for the block
// after the end of the current best chain based on the difficulty retarget
// rules.
//
// This function is safe for concurrent access.
func (b *BlockChain) CalcNextRequiredDifficulty(timestamp time.Time) (uint32, error) {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	difficulty, err := b.calcNextRequiredDifficulty(b.bestChain.Tip(), timestamp)
	return difficulty, err
}

package blockchain

import (
	"fmt"
	"math/big"
	"time"

	"github.com/abesuite/abec/wire"
)

type DifficultyVector struct {
	Bits           uint32
	BitsSecond     uint32
	PowScaleSecond uint32
}

func NewDifficultyVector(bits, bitsSecond, powScaleSecond uint32) *DifficultyVector {
	return &DifficultyVector{
		Bits:           bits,
		BitsSecond:     bitsSecond,
		PowScaleSecond: powScaleSecond,
	}
}

// CalcNextRequiredDifficultyVector calculates the required difficulty vector for the block
// after the end of the current best chain based on the difficulty retarget rules.
//
// This function is safe for concurrent access.
func (b *BlockChain) CalcNextRequiredDifficultyVector(timestamp time.Time) (*DifficultyVector, error) {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	bitsVector, err := b.calcNextRequiredDifficultyVector(b.bestChain.Tip(), timestamp)
	return bitsVector, err
}

// calcNextRequiredDifficultyVector calculates the required difficulty vector for the block
// after the passed previous block node based on the difficulty retarget rules.
// This function differs from the exported CalcNextRequiredDifficultyVector in that
// the exported version uses the current best chain as the previous block node
// while this function accepts any block node.
// todo: confirm return pointer?
func (b *BlockChain) calcNextRequiredDifficultyVector(lastNode *blockNode, newBlockTime time.Time) (*DifficultyVector, error) {
	var difficultyVector *DifficultyVector

	// Genesis block.
	if lastNode == nil {
		difficultyVector = NewDifficultyVector(b.chainParams.PowLimitBits, wire.BitsSecondDummy, wire.PowScaleSecondDummy)
		return difficultyVector, nil
	}

	if lastNode.height+1 >= b.chainParams.BlockHeightAconcagua {
		// Use DSA algorithm to compute the DifficultyVector for DualPoWConsensus,
		// which takes effect from Aconcagua upgrade
		return b.calcNextRequiredDifficultyVectorAconcagua(lastNode, newBlockTime)
	}

	if lastNode.height+1 >= b.chainParams.BlockHeightDSA {
		//	DSA takes effect from BlockHeightDSA
		bits, err := b.calcNextRequiredDifficultyDSA(lastNode, newBlockTime)
		if err != nil {
			return nil, err
		}

		difficultyVector = NewDifficultyVector(bits, wire.BitsSecondDummy, wire.PowScaleSecondDummy)
		return difficultyVector, nil
	}

	//	lastNode.height+1 < b.chainParams.BlockHeightDSA
	bits, err := b.calcNextRequiredDifficultyInit(lastNode, newBlockTime)
	if err != nil {
		return nil, err
	}

	difficultyVector = NewDifficultyVector(bits, wire.BitsSecondDummy, wire.PowScaleSecondDummy)
	return difficultyVector, nil

}

// calcNextRequiredDifficultyVectorDSA calculates the required difficulty vector for the block
// after the passed previous block node based on the difficulty retarget rules.
//
// This function is a subroutine for calcNextRequiredDifficultyVector,
// for the case of lastNode.height+1 >= b.chainParams.BlockHeightAconcagua,
// where DSA algorithms are applied and hybrid consensus protocol are applied.
func (b *BlockChain) calcNextRequiredDifficultyVectorAconcagua(lastNode *blockNode, newBlockTime time.Time) (*DifficultyVector, error) {
	var difficultyVector *DifficultyVector

	// Genesis block.
	if lastNode == nil {
		difficultyVector = NewDifficultyVector(b.chainParams.PowLimitBits, wire.BitsSecondDummy, wire.PowScaleSecondDummy)
		return difficultyVector, nil
	}

	if lastNode.height+1 < b.chainParams.BlockHeightAconcagua {
		errStr := fmt.Sprintf("wrong call on calcNextRequiredDifficultyVectorAconcagua: "+
			"lastNode.height+1 (%d) < b.chainParams.BlockHeightAconcagua (%d)",
			lastNode.height+1, b.chainParams.BlockHeightAconcagua)
		return nil, AssertError(errStr)
	}

	// lastNode.height+1 >= b.chainParams.BlockHeightAconcagua

	// bypass adjust difficulty when hit configured Fake PoW scope
	if b.FakePoWHeightScopes() != nil {
		for _, scope := range b.FakePoWHeightScopes() {
			nextHeight := lastNode.height + 1
			if scope.StartHeight <= nextHeight && nextHeight < scope.EndHeight {
				if lastNode.height+1 == b.chainParams.BlockHeightAconcagua {
					difficultyVector = NewDifficultyVector(lastNode.bits, lastNode.bits, b.getPowScaleSecond(nextHeight))
				} else {
					difficultyVector = NewDifficultyVector(lastNode.bits, lastNode.bitsSecond, b.getPowScaleSecond(nextHeight))
				}
				return difficultyVector, nil
			}
		}
	}

	// Return the previous block's difficulty requirements if this block is not at a difficulty retarget interval.
	if (lastNode.height+1)%b.blocksPerRetargetDSA != 0 {
		// For networks that support it, allow special reduction of the
		// required difficulty once too much time has elapsed without mining a block.
		if b.chainParams.ReduceMinDifficulty {
			// Return minimum difficulty when more than the desired
			// amount of time has elapsed without mining a block.
			reductionTime := int64(b.chainParams.MinDiffReductionTime / time.Second)
			allowMinTime := lastNode.timestamp + reductionTime
			if newBlockTime.Unix() > allowMinTime {
				return NewDifficultyVector(b.chainParams.PowLimitBits, b.chainParams.PowLimitBits,
					b.getPowScaleSecond(lastNode.height+1)), nil
			}

			// The block was mined within the desired timeframe, so
			// return the difficulty for the last block which did
			// not have the special minimum difficulty rule applied.
			return b.findPrevTestNetDifficultyVectorAconcagua(lastNode), nil
		}

		// For the main network (or any unrecognized networks), simply
		// return the previous block's difficulty requirements.
		return NewDifficultyVector(lastNode.bits, lastNode.bitsSecond, b.getPowScaleSecond(lastNode.height+1)), nil
	}

	// (lastNode.height+1)%b.blocksPerRetargetDSA == 0

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

	var (
		// the following loop will generate these value

		avgHR           = big.NewInt(0) // set initial value to be 0, since it will sum
		latestSlotAvgHR = big.NewInt(0)

		avgHRSecond           = big.NewInt(0) // set initial value to be 0, since it will sum
		latestSlotAvgHRSecond = big.NewInt(0)

		latestSlotTimeSpan = int64(1)
	)

	factorInt := big.NewInt(0)

	slotTimeSpan := big.NewInt(1)

	slotWorkSum := big.NewInt(0)
	slotHashRate := big.NewInt(0) // for each slot
	avgItem := big.NewInt(0)

	slotWorkSumSecond := big.NewInt(0)
	slotHashRateSecond := big.NewInt(0) // for each slot
	avgItemSecond := big.NewInt(0)

	slotEndNode := lastNode
	for i := len(dsaSmoothFactorsInt) - 1; i >= 0; i-- {
		if slotEndNode == nil {
			return nil, AssertError(fmt.Sprintf("%d-th slotEndNode is nil", i))
		}

		slotStartNode := slotEndNode.RelativeAncestor(b.blocksPerRetargetDSA - 1)
		if slotStartNode == nil {
			return nil, AssertError(fmt.Sprintf("unable to obtain %d-th slotStartNode (at heigt %d)",
				i, slotEndNode.height-b.blocksPerRetargetDSA+1))
		}

		if slotEndNode.workSum.Cmp(slotStartNode.workSum) < 0 {
			errStr := fmt.Sprintf("slotEndNode (at heigt %d, hash %s) has workSum %d, while slotStartNode (at heigt %d, hash %s) has workSum %d",
				slotEndNode.height, slotEndNode.hash, slotEndNode.workSum, slotStartNode.height, slotStartNode.hash, slotStartNode.workSum)
			return nil, AssertError(errStr)
		}

		if slotEndNode.workSumSecond.Cmp(slotStartNode.workSumSecond) < 0 {
			errStr := fmt.Sprintf("slotEndNode (at heigt %d, hash %s) has workSumSecond %d, while slotStartNode (at heigt %d, hash %s) has workSumSecond %d",
				slotEndNode.height, slotEndNode.hash, slotEndNode.workSumSecond, slotStartNode.height, slotStartNode.hash, slotStartNode.workSumSecond)
			return nil, AssertError(errStr)
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
			log.Infof("Timestamp warning happens. The slot time is set to minRetargetTimespan (%v)",
				time.Duration(b.minRetargetTimespanDSA)*time.Second)
		} else {
			slotTimeSpan.SetInt64(slotEndNode.timestamp - slotStartNode.timestamp) // in seconds
		}

		slotWorkSum = slotWorkSum.Sub(slotEndNode.workSum, slotStartNode.workSum)
		slotHashRate = slotHashRate.Div(slotWorkSum, slotTimeSpan)

		slotWorkSumSecond = slotWorkSumSecond.Sub(slotEndNode.workSumSecond, slotStartNode.workSumSecond)
		slotHashRateSecond = slotHashRateSecond.Div(slotWorkSumSecond, slotTimeSpan)

		// logging for each slot
		log.Infof("Slot %d : start height: %d, end height %d,"+
			"difficulty %08x (%064x), difficulty second %08x (%064x), timespan %064x, "+
			"workSum %d, hashRate %d, workSumSecond %d, hashRateSecond %d ",
			i, slotStartNode.height, slotEndNode.height,
			slotEndNode.bits, CompactToBig(slotEndNode.bits), slotEndNode.bitsSecond, CompactToBig(slotEndNode.bitsSecond),
			time.Duration(slotTimeSpan.Int64())*time.Second,
			slotWorkSum, slotHashRate, slotWorkSumSecond, slotHashRateSecond)

		if i == len(dsaSmoothFactorsInt)-1 {
			latestSlotTimeSpan = slotTimeSpan.Int64()

			tmpBytes := make([]byte, len(slotHashRate.Bytes()))
			copy(tmpBytes, slotHashRate.Bytes())
			latestSlotAvgHR.SetBytes(tmpBytes)

			tmpBytesSecond := make([]byte, len(slotHashRateSecond.Bytes()))
			copy(tmpBytesSecond, slotHashRateSecond.Bytes())
			latestSlotAvgHRSecond.SetBytes(tmpBytesSecond)
		}

		factorInt.SetInt64(dsaSmoothFactorsInt[i])

		avgItem = avgItem.Mul(slotHashRate, factorInt) // Note that this will not cause overflow
		avgHR = avgHR.Add(avgHR, avgItem)
		avgItemSecond = avgItemSecond.Mul(slotHashRateSecond, factorInt) // Note that this will not cause overflow
		avgHRSecond = avgHRSecond.Add(avgHRSecond, avgItemSecond)

		slotEndNode = slotStartNode.parent
	}

	avgHR = avgHR.Div(avgHR, bigTenThousand)
	avgHRSecond = avgHRSecond.Div(avgHRSecond, bigTenThousand)

	retargetAdjustmentFactor := big.NewInt(b.chainParams.RetargetAdjustmentFactor)

	maxAllowedHR := new(big.Int).Mul(latestSlotAvgHR, retargetAdjustmentFactor)
	minAllowedHR := new(big.Int).Div(latestSlotAvgHR, retargetAdjustmentFactor)
	targetHR := avgHR
	if avgHR.Cmp(maxAllowedHR) > 0 {
		targetHR = maxAllowedHR

		log.Infof("Difficulty adjustment at height %d : avgHR(%v) is too large, adjust to maxAllowed value (%v)",
			lastNode.height+1, avgHR, maxAllowedHR)

	} else if avgHR.Cmp(minAllowedHR) < 0 {
		targetHR = minAllowedHR

		log.Infof("Difficulty adjustment at height %d : avgHR(%v) is too small, adjust to minAllowed value (%v)",
			lastNode.height+1, avgHR, minAllowedHR)
	}

	maxAllowedHRSecond := new(big.Int).Mul(latestSlotAvgHRSecond, retargetAdjustmentFactor)
	minAllowedHRSecond := new(big.Int).Div(latestSlotAvgHRSecond, retargetAdjustmentFactor)
	targetHRSecond := avgHRSecond
	if avgHRSecond.Cmp(maxAllowedHRSecond) > 0 {
		targetHRSecond = maxAllowedHRSecond

		log.Infof("Difficulty adjustment at height %d : avgHRSecond(%v) is too large, adjust to maxAllowed value (%v)",
			lastNode.height+1, avgHRSecond, maxAllowedHRSecond)

	} else if avgHRSecond.Cmp(minAllowedHRSecond) < 0 {
		targetHRSecond = minAllowedHRSecond

		log.Infof("Difficulty adjustment at height %d : avgHRSecond(%v) is too small, adjust to minAllowed value (%v)",
			lastNode.height+1, avgHRSecond, minAllowedHRSecond)

	}

	// As there are TWO PowConsensus,
	// the targetTimePerBlock for each consensus is double of the targetTimePerBlock for the system.
	// THIS IS VERY IMPORTANT!
	// THIS IS VERY IMPORTANT!
	// THIS IS VERY IMPORTANT!
	// targetTimePerBlock := int64(b.chainParams.TargetTimePerBlockDSA / time.Second)
	targetTimePerBlockAconcagua := int64(b.chainParams.TargetTimePerBlockDSA/time.Second) * 2
	// END OF IMPORTANT NOTICE

	targetWorkSumPerBlock := new(big.Int).Mul(targetHR, big.NewInt(targetTimePerBlockAconcagua))
	newTarget := calcTargetFromExpectedWorkPerBlock(targetWorkSumPerBlock)

	targetWorkSumPerBlockSecond := new(big.Int).Mul(targetHRSecond, big.NewInt(targetTimePerBlockAconcagua))
	newTargetSecond := calcTargetFromExpectedWorkPerBlock(targetWorkSumPerBlockSecond)

	// Limit new value to the proof of work limit.
	if newTarget.Cmp(b.chainParams.PowLimit) > 0 {
		newTarget.Set(b.chainParams.PowLimit)

		log.Infof("Difficulty adjustment at height %d : newTarget(%v) is too large, adjust to PowLimit (%v)",
			lastNode.height+1, newTarget, b.chainParams.PowLimit)
	}

	if newTargetSecond.Cmp(b.chainParams.PowLimit) > 0 {
		newTargetSecond.Set(b.chainParams.PowLimit)

		log.Infof("Difficulty adjustment at height %d : newTargetSecond(%v) is too large, adjust to PowLimit (%v)",
			lastNode.height+1, newTargetSecond, b.chainParams.PowLimit)

	}

	// Log new target difficulty and return it.  The new target logging is
	// intentionally converting the bits back to a number instead of using
	// newTarget since conversion to the compact representation loses
	// precision.
	newTargetBits := BigToCompact(newTarget)
	newTargetBitsSecond := BigToCompact(newTargetSecond)

	// handle the border case
	// THIS IS VERY IMPORTANT!
	// THIS IS VERY IMPORTANT!
	// THIS IS VERY IMPORTANT!
	if lastNode.height+1 == b.chainParams.BlockHeightAconcagua {
		// For the 0-th slot of Aconcagua fork, set BitsSecond to the same as Bits.
		// This is because there is no PoWConsensus-2 before lastNode.height+1.
		newTargetBitsSecond = newTargetBits

		log.Infof("Difficulty adjustment at height %d : newTargetBitsSecond is set the same as newTargetBits %08x (%064x)",
			lastNode.height+1, newTargetBits, CompactToBig(newTargetBits))

	} else {
		borderHeight := b.chainParams.BlockHeightAconcagua + int32(len(dsaSmoothFactorsInt)-1)*b.blocksPerRetargetDSA
		log.Infof("border height: %d", borderHeight)
		if lastNode.height+1 <= borderHeight {
			// for the [1, len(dsaSmoothFactorsInt)-1]-th slots of Aconcagua fork,
			// use the latestSlotAvgHRSecond as the avgHRSecond.
			// This is because at the border scope [BlockHeightAconcagua, BlockHeightAconcagua + 19*200],
			// the computation of avgHRSecond needs the slotHashRateSecond in scope [BlockHeightAconcagua-20*200, BlockHeightAconcagua],
			// which does not exist.
			// To balance the two PoWConsensus as soon as possible, for the border scope, it uses the latestSlotAvgHR (of last slot).
			targetHRSecondAdjust := latestSlotAvgHRSecond

			log.Infof("Difficulty adjustment at height %d : targetHRSecond is set the same as latestSlotAvgHRSecond (%v)",
				lastNode.height+1, latestSlotAvgHRSecond)

			targetWorkSumPerBlockSecondAdjust := new(big.Int).Mul(targetHRSecondAdjust, big.NewInt(targetTimePerBlockAconcagua))
			newTargetSecondAdjust := calcTargetFromExpectedWorkPerBlock(targetWorkSumPerBlockSecondAdjust)

			if newTargetSecondAdjust.Cmp(b.chainParams.PowLimit) > 0 {
				newTargetSecondAdjust.Set(b.chainParams.PowLimit)

				log.Infof("Difficulty adjustment at height %d : newTargetSecondAdjust(%v) is too large, adjust to PowLimit (%v)",
					lastNode.height+1, newTargetSecondAdjust, b.chainParams.PowLimit)
			}

			newTargetBitsSecond = BigToCompact(newTargetSecondAdjust)
		}
	}
	// END OF IMPORTANT NOTICE

	log.Infof("Summary for Difficulty retarget at block height %d", lastNode.height+1)
	log.Infof("Old target %08x (%064x)", lastNode.bits, CompactToBig(lastNode.bits))
	log.Infof("New target %08x (%064x)", newTargetBits, CompactToBig(newTargetBits))
	log.Infof("Old target Second %08x (%064x)", lastNode.bitsSecond, CompactToBig(lastNode.bitsSecond))
	log.Infof("New target Second %08x (%064x)", newTargetBitsSecond, CompactToBig(newTargetBitsSecond))
	log.Infof("Latest Slot timespan %v, Latest Slot's Hash Rate %v, Latest Slot's Hash Rate Second %v",
		time.Duration(latestSlotTimeSpan)*time.Second, latestSlotAvgHR, latestSlotAvgHRSecond)
	log.Infof("Target timespan %v, Average Hash Rate %d, Target Hash Rate %d, Average Hash Rate Second %d, Target Hash Rate Second %d,",
		b.chainParams.TargetTimespanDSA, avgHR, targetHR, avgHRSecond, targetHRSecond)

	return NewDifficultyVector(newTargetBits, newTargetBitsSecond, b.getPowScaleSecond(lastNode.height+1)), nil

}

// getPowScaleSecond returns the PowScaleSecond corresponding to the passed blockHeight.
func (b *BlockChain) getPowScaleSecond(blockHeight int32) uint32 {
	// The system needs to preconfigure a map here.
	// Based on test result on 2025.10, we set it to be 20.
	return 20
}

// findPrevTestNetDifficultyVectorAconcagua returns the difficulty vector of the previous block which
// did not have the special testnet minimum difficulty rule applied.
//
// This function MUST be called with the chain state lock held (for writes).
func (b *BlockChain) findPrevTestNetDifficultyVectorAconcagua(startNode *blockNode) *DifficultyVector {
	// Search backwards through the chain for the last block without the special rule applied.
	iterNode := startNode
	for iterNode != nil && iterNode.height%b.blocksPerRetargetDSA != 0 &&
		iterNode.bits == b.chainParams.PowLimitBits {

		iterNode = iterNode.parent
	}

	// Return the found difficulty or the minimum difficulty if no appropriate block was found.
	lastBits := b.chainParams.PowLimitBits
	lastBitsSecond := b.chainParams.PowLimitBits
	if iterNode != nil {
		lastBits = iterNode.bits
		lastBitsSecond = iterNode.bitsSecond
	}

	height := int32(1)
	if startNode != nil {
		height = startNode.height + 1
	}

	return NewDifficultyVector(lastBits, lastBitsSecond, b.getPowScaleSecond(height))

}

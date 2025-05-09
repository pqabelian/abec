package blockchain

import (
	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/wire"
	"math"
)

const (
	// vbLegacyBlockVersion is the highest legacy block version before the
	// version bits scheme became active.
	vbLegacyBlockVersion = 4

	// todo: (EthashPoW) revise the version mechanism
	//	todo: (block version upgrade mechainism (initial) design)
	//	The initial version is int32(0x10000000).
	//	We use the left 12 bits for hard-fork upgrade, and will use the remaining 20 bits for soft-fork update.
	//	Actually, block version is defined as int32, we will alwasy set the leftest bit to be 0,
	//	and only use the 11 bits for hard fork.
	//	Further, like a tree, the hard fork version will be
	//	0x20000000, 0x30000000, ..., 0x70000000,
	//	0x71000000, 0x72000000, ..., 0x7F000000,
	//	0x7F100000, 0x7F200000, ..., 0x7FF00000.
	//	Note that hard-forks will be not so many.
	//	If necessary, we may use versions such as 0x31000000, ... 0x3F000000.
	// All historical versions should be listed here.
	BlockVersionInitial = 0x10000000
	//	wire.BlockVersionEthashPow = 0x20000000

	// todo(DSA): review
	//	wire.BlockVersionDSA = 0x21000000

	// ToDo(MLP):
	//	wire.BlockVersionMLPAUT = 0x30000000

	//	todo: 202207 revise the version mechanism
	//	In the future,
	// vbTopBits defines the bits to set in the version to signal that the
	// version bits scheme is being used.
	vbTopBits = 0x10000000 //	 todo: modify according to the AIP mechanism.
	// ToDo(MLP): whether we need to modify those related to this part.

	// vbTopMask is the bitmask to use to determine whether or not the
	// version bits scheme is in use.
	vbTopMask = 0xe0000000 //	 todo: modify according to the AIP mechanism.

	// vbNumBits is the total number of bits available for use with the
	// version bits scheme.
	vbNumBits = 29 //	 todo: modify according to the AIP mechanism.

	// unknownVerNumToCheck is the number of previous blocks to consider
	// when checking for a threshold of unknown block versions for the
	// purposes of warning the user.
	unknownVerNumToCheck = 100

	// unknownVerWarnNum is the threshold of previous blocks that have an
	// unknown version to use for the purposes of warning the user.
	unknownVerWarnNum = unknownVerNumToCheck / 2
)

// bitConditionChecker provides a thresholdConditionChecker which can be used to
// test whether or not a specific bit is set when it's not supposed to be
// according to the expected version based on the known deployments and the
// current state of the chain.  This is useful for detecting and warning about
// unknown rule activations.
type bitConditionChecker struct {
	bit   uint32
	chain *BlockChain
}

// Ensure the bitConditionChecker type implements the thresholdConditionChecker
// interface.
var _ thresholdConditionChecker = bitConditionChecker{}

// BeginTime returns the unix timestamp for the median block time after which
// voting on a rule change starts (at the next window).
//
// Since this implementation checks for unknown rules, it returns 0 so the rule
// is always treated as active.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c bitConditionChecker) BeginTime() uint64 {
	return 0
}

// EndTime returns the unix timestamp for the median block time after which an
// attempted rule change fails if it has not already been locked in or
// activated.
//
// Since this implementation checks for unknown rules, it returns the maximum
// possible timestamp so the rule is always treated as active.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c bitConditionChecker) EndTime() uint64 {
	return math.MaxUint64
}

// RuleChangeActivationThreshold is the number of blocks for which the condition
// must be true in order to lock in a rule change.
//
// This implementation returns the value defined by the chain params the checker
// is associated with.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c bitConditionChecker) RuleChangeActivationThreshold() uint32 {
	return c.chain.chainParams.RuleChangeActivationThreshold
}

// MinerConfirmationWindow is the number of blocks in each threshold state
// retarget window.
//
// This implementation returns the value defined by the chain params the checker
// is associated with.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c bitConditionChecker) MinerConfirmationWindow() uint32 {
	return c.chain.chainParams.MinerConfirmationWindow
}

// Condition returns true when the specific bit associated with the checker is
// set and it's not supposed to be according to the expected version based on
// the known deployments and the current state of the chain.
//
// This function MUST be called with the chain state lock held (for writes).
//
// This is part of the thresholdConditionChecker interface implementation.
func (c bitConditionChecker) Condition(node *blockNode) (bool, error) {
	conditionMask := uint32(1) << c.bit
	version := uint32(node.version)
	if version&vbTopMask != vbTopBits {
		return false, nil
	}
	if version&conditionMask == 0 {
		return false, nil
	}

	expectedVersion, err := c.chain.calcNextBlockVersion(node.parent)
	if err != nil {
		return false, err
	}
	return uint32(expectedVersion)&conditionMask == 0, nil
}

// deploymentChecker provides a thresholdConditionChecker which can be used to
// test a specific deployment rule.  This is required for properly detecting
// and activating consensus rule changes.
type deploymentChecker struct {
	deployment *chaincfg.ConsensusDeployment
	chain      *BlockChain
}

// Ensure the deploymentChecker type implements the thresholdConditionChecker
// interface.
var _ thresholdConditionChecker = deploymentChecker{}

// BeginTime returns the unix timestamp for the median block time after which
// voting on a rule change starts (at the next window).
//
// This implementation returns the value defined by the specific deployment the
// checker is associated with.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c deploymentChecker) BeginTime() uint64 {
	return c.deployment.StartTime
}

// EndTime returns the unix timestamp for the median block time after which an
// attempted rule change fails if it has not already been locked in or
// activated.
//
// This implementation returns the value defined by the specific deployment the
// checker is associated with.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c deploymentChecker) EndTime() uint64 {
	return c.deployment.ExpireTime
}

// RuleChangeActivationThreshold is the number of blocks for which the condition
// must be true in order to lock in a rule change.
//
// This implementation returns the value defined by the chain params the checker
// is associated with.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c deploymentChecker) RuleChangeActivationThreshold() uint32 {
	return c.chain.chainParams.RuleChangeActivationThreshold
}

// MinerConfirmationWindow is the number of blocks in each threshold state
// retarget window.
//
// This implementation returns the value defined by the chain params the checker
// is associated with.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c deploymentChecker) MinerConfirmationWindow() uint32 {
	return c.chain.chainParams.MinerConfirmationWindow
}

// Condition returns true when the specific bit defined by the deployment
// associated with the checker is set.
//
// This is part of the thresholdConditionChecker interface implementation.
func (c deploymentChecker) Condition(node *blockNode) (bool, error) {
	conditionMask := uint32(1) << c.deployment.BitNumber
	version := uint32(node.version)
	return (version&vbTopMask == vbTopBits) && (version&conditionMask != 0),
		nil
}

// calcNextBlockVersion calculates the expected version of the block after the
// passed previous block node based on the state of started and locked in
// rule change deployments.
//
// This function differs from the exported CalcNextBlockVersion in that the
// exported version uses the current best chain as the previous block node
// while this function accepts any block node.
//
// This function MUST be called with the chain state lock held (for writes).
// todo: (EthashPoW) need to set the BlockVersionEthashPow
func (b *BlockChain) calcNextBlockVersion(prevNode *blockNode) (int32, error) {
	// Set the appropriate bits for each actively defined rule deployment
	// that is either in the process of being voted on, or locked in for the
	// activation at the next threshold window change.

	// ToDo(MLP):

	//if prevNode != nil && prevNode.height+1 >= b.chainParams.BlockHeightEthashPoW {
	//	//	todo: this rule should be public known.
	//	//	shall we directly defined wire.BlockVersionEthashPow as int32? to avoid type-transfer.
	//	return int32(wire.BlockVersionEthashPow), nil
	//}

	if prevNode != nil {
		if prevNode.height+1 >= b.chainParams.BlockHeightMLPAUT {
			return int32(wire.BlockVersionMLPAUT), nil
		}

		// Added by Alice, 2024.05.11, for DSA
		// todo(DSA): review
		if prevNode.height+1 >= b.chainParams.BlockHeightDSA {
			return int32(wire.BlockVersionDSA), nil
		}

		if prevNode.height+1 >= b.chainParams.BlockHeightEthashPoW {
			return int32(wire.BlockVersionEthashPow), nil
		}
	}

	return int32(BlockVersionInitial), nil

	// todo: modify according to the AIP mechanism.
	//expectedVersion := uint32(vbTopBits)
	//for id := 0; id < len(b.chainParams.Deployments); id++ {
	//	deployment := &b.chainParams.Deployments[id]
	//	cache := &b.deploymentCaches[id]
	//	checker := deploymentChecker{deployment: deployment, chain: b}
	//	state, err := b.thresholdState(prevNode, checker, cache)
	//	if err != nil {
	//		return 0, err
	//	}
	//	if state == ThresholdStarted || state == ThresholdLockedIn {
	//		expectedVersion |= uint32(1) << deployment.BitNumber
	//	}
	//}
	//return int32(expectedVersion), nil
}

// CalcNextBlockVersion calculates the expected version of the block after the
// end of the current best chain based on the state of started and locked in
// rule change deployments.
//
// This function is safe for concurrent access.
func (b *BlockChain) CalcNextBlockVersion() (int32, error) {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	version, err := b.calcNextBlockVersion(b.bestChain.Tip())
	return version, err
}

// warnUnknownRuleActivations displays a warning when any unknown new rules are
// either about to activate or have been activated.  This will only happen once
// when new rules have been activated and every block for those about to be
// activated.
//
// This function MUST be called with the chain state lock held (for writes)
func (b *BlockChain) warnUnknownRuleActivations(node *blockNode) error {
	// Warn if any unknown new rules are either about to activate or have
	// already been activated.
	for bit := uint32(0); bit < vbNumBits; bit++ {
		checker := bitConditionChecker{bit: bit, chain: b}
		cache := &b.warningCaches[bit]
		state, err := b.thresholdState(node.parent, checker, cache)
		if err != nil {
			return err
		}

		switch state {
		case ThresholdActive:
			if !b.unknownRulesWarned {
				log.Warnf("Unknown new rules activated (bit %d)",
					bit)
				b.unknownRulesWarned = true
			}

		case ThresholdLockedIn:
			window := int32(checker.MinerConfirmationWindow())
			activationHeight := window - (node.height % window)
			log.Warnf("Unknown new rules are about to activate in "+
				"%d blocks (bit %d)", activationHeight, bit)
		}
	}

	return nil
}

// warnUnknownVersions logs a warning if a high enough percentage of the last
// blocks have unexpected versions.
//
// This function MUST be called with the chain state lock held (for writes)
// TODO
func (b *BlockChain) warnUnknownVersions(node *blockNode) error {
	// Nothing to do if already warned.
	if b.unknownVersionsWarned {
		return nil
	}

	// Warn if enough previous blocks have unexpected versions.
	numUpgraded := uint32(0)
	for i := uint32(0); i < unknownVerNumToCheck && node != nil; i++ {
		expectedVersion, err := b.calcNextBlockVersion(node.parent)
		if err != nil {
			return err
		}
		if expectedVersion > vbLegacyBlockVersion &&
			(node.version & ^expectedVersion) != 0 {

			numUpgraded++
		}

		node = node.parent
	}
	if numUpgraded > unknownVerWarnNum {
		log.Warn("Unknown block versions are being mined, so new " +
			"rules might be in effect.  Are you running the " +
			"latest version of the software?")
		b.unknownVersionsWarned = true
	}

	return nil
}

package blockchain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chaincfg"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/consensus/ethash"
	"github.com/abesuite/abec/txscript"
	"github.com/abesuite/abec/wire"
	"math"
	"math/big"
	"time"
)

const (
	// MaxTimeOffsetSeconds is the maximum number of seconds a block time
	// is allowed to be ahead of the current time.  This is currently 2
	// hours.
	MaxTimeOffsetSeconds = 2 * 60 * 60

	// MinCoinbaseScriptLen is the minimum length a coinbase script can be.
	MinCoinbaseScriptLen = 2

	// MaxCoinbaseScriptLen is the maximum length a coinbase script can be.
	MaxCoinbaseScriptLen = 100

	// medianTimeBlocks is the number of previous blocks which should be
	// used to calculate the median time used to validate block timestamps.
	medianTimeBlocks = 11

	// serializedHeightVersion is the block version which changed block
	// coinbases to start with the serialized block height.
	serializedHeightVersion = 1

	// baseSubsidy is the starting subsidy amount for mined blocks.  This
	// value is halved every SubsidyHalvingInterval blocks.
	//baseSubsidy = 512 * abeutil.NeutrinoPerAbe       //TODO(osy):this value should be 400 to uniform
	//baseSubsidy = 400 * abeutil.NeutrinoPerAbe      //TODO(abe): for testing 1,2,5,10, we adjust the subsidy from 400 to 512
	baseSubsidy = 256 * abeutil.NeutrinoPerAbe
)

var (
	// zeroHash is the zero value for a chainhash.Hash and is defined as
	// a package level variable to avoid the need to create a new instance
	// every time a check is needed.
	zeroHash chainhash.Hash

	// block91842Hash is one of the two nodes which violate the rules
	// set forth in BIP0030.  It is defined as a package level variable to
	// avoid the need to create a new instance every time a check is needed.
	block91842Hash = newHashFromStr("00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")

	// block91880Hash is one of the two nodes which violate the rules
	// set forth in BIP0030.  It is defined as a package level variable to
	// avoid the need to create a new instance every time a check is needed.
	block91880Hash = newHashFromStr("00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")
)

// isNullOutpoint determines whether or not a previous transaction output point
// is set.
func isNullOutpoint(outpoint *wire.OutPoint) bool {
	if outpoint.Index == math.MaxUint32 && outpoint.Hash == zeroHash {
		return true
	}
	return false
}

// ShouldHaveSerializedBlockHeight determines if a block should have a
// serialized block height embedded within the scriptSig of its
// coinbase transaction. Judgement is based on the block version in the block
// header. Blocks with version 2 and above satisfy this criteria. See BIP0034
// for further information.
func ShouldHaveSerializedBlockHeight(header *wire.BlockHeader) bool {
	// todo: (ethmining) This is a bug? we have header.Version = 1 now?
	// answer: any time we have height in coinbase transaction
	// but we version encode mechanism is different:
	// 0x100_00000 -> left 12 bit is hard-fork and right  20 is soft-fork
	// it means that we should extract the hard-fork part and convert it
	return true
}

// IsCoinBaseTx determines whether or not a transaction is a coinbase.  A coinbase
// is a special transaction created by miners that has no inputs.  This is
// represented in the block chain by a transaction with a single input that has
// a previous output transaction index set to the maximum value along with a
// zero hash.
//
// This function only differs from IsCoinBase in that it works with a raw wire
// transaction as opposed to a higher level util transaction.
func IsCoinBaseTx(msgTx *wire.MsgTx) bool {
	// A coin base must only have one transaction input.
	if len(msgTx.TxIn) != 1 {
		return false
	}

	// The previous output of a coin base must have a max value index and
	// a zero hash.
	prevOut := &msgTx.TxIn[0].PreviousOutPoint
	if prevOut.Index != math.MaxUint32 || prevOut.Hash != zeroHash {
		return false
	}

	return true
}

// IsCoinBase determines whether or not a transaction is a coinbase.  A coinbase
// is a special transaction created by miners that has no inputs.  This is
// represented in the block chain by a transaction with a single input that has
// a previous output transaction index set to the maximum value along with a
// zero hash.
//
// This function only differs from IsCoinBaseTx in that it works with a higher
// level util transaction as opposed to a raw wire transaction.
func IsCoinBase(tx *abeutil.Tx) bool {
	return IsCoinBaseTx(tx.MsgTx())
}

func IsCoinBaseAbe(tx *abeutil.TxAbe) (bool, error) {
	return tx.MsgTx().IsCoinBase()
}

// SequenceLockActive determines if a transaction's sequence locks have been
// met, meaning that all the inputs of a given transaction have reached a
// height or time sufficient for their relative lock-time maturity.
func SequenceLockActive(sequenceLock *SequenceLock, blockHeight int32,
	medianTimePast time.Time) bool {

	// If either the seconds, or height relative-lock time has not yet
	// reached, then the transaction is not yet mature according to its
	// sequence locks.
	if sequenceLock.Seconds >= medianTimePast.Unix() ||
		sequenceLock.BlockHeight >= blockHeight {
		return false
	}

	return true
}

// IsFinalizedTransaction determines whether or not a transaction is finalized.
func IsFinalizedTransaction(tx *abeutil.Tx, blockHeight int32, blockTime time.Time) bool {
	msgTx := tx.MsgTx()

	// Lock time of zero means the transaction is finalized.
	lockTime := msgTx.LockTime
	if lockTime == 0 {
		return true
	}

	// The lock time field of a transaction is either a block height at
	// which the transaction is finalized or a timestamp depending on if the
	// value is before the txscript.LockTimeThreshold.  When it is under the
	// threshold it is a block height.
	blockTimeOrHeight := int64(0)
	if lockTime < txscript.LockTimeThreshold {
		blockTimeOrHeight = int64(blockHeight)
	} else {
		blockTimeOrHeight = blockTime.Unix()
	}
	if int64(lockTime) < blockTimeOrHeight {
		return true
	}

	// At this point, the transaction's lock time hasn't occurred yet, but
	// the transaction might still be finalized if the sequence number
	// for all transaction inputs is maxed out.
	for _, txIn := range msgTx.TxIn {
		if txIn.Sequence != math.MaxUint32 {
			return false
		}
	}
	return true
}

// IsFinalizedTransaction determines whether or not a transaction is finalized.
func IsFinalizedTransactionAbe(tx *abeutil.TxAbe, blockHeight int32, blockTime time.Time) bool {
	//	msgTx := tx.MsgTx()

	// ABE does not support locktime at this moment, 2020.04
	/*	// Lock time of zero means the transaction is finalized.
		lockTime := msgTx.LockTime
		if lockTime == 0 {
			return true
		}*/

	/*	// The lock time field of a transaction is either a block height at
		// which the transaction is finalized or a timestamp depending on if the
		// value is before the txscript.LockTimeThreshold.  When it is under the
		// threshold it is a block height.
		blockTimeOrHeight := int64(0)
		if lockTime < txscript.LockTimeThreshold {
			blockTimeOrHeight = int64(blockHeight)
		} else {
			blockTimeOrHeight = blockTime.Unix()
		}
		if int64(lockTime) < blockTimeOrHeight {
			return true
		}*/

	/*	// At this point, the transaction's lock time hasn't occurred yet, but
		// the transaction might still be finalized if the sequence number
		// for all transaction inputs is maxed out.
		for _, txIn := range msgTx.TxIn {
			if txIn.Sequence != math.MaxUint32 {
				return false
			}
		}*/

	return true
}

// isBIP0030Node returns whether or not the passed node represents one of the
// two blocks that violate the BIP0030 rule which prevents transactions from
// overwriting old ones.
func isBIP0030Node(node *blockNode) bool {
	if node.height == 91842 && node.hash.IsEqual(block91842Hash) {
		return true
	}

	if node.height == 91880 && node.hash.IsEqual(block91880Hash) {
		return true
	}

	return false
}

// CalcBlockSubsidy returns the subsidy amount a block at the provided height
// should have. This is mainly used for determining how much the coinbase for
// newly generated blocks awards as well as validating the coinbase for blocks
// has the expected value.
//
// The subsidy is halved every SubsidyReductionInterval blocks.  Mathematically
// this is: baseSubsidy / 2^(height/SubsidyReductionInterval)
//
// At the target block generation rate for the main network, this is
// approximately every 4 years.
func CalcBlockSubsidy(height int32, chainParams *chaincfg.Params) uint64 {
	if chainParams.SubsidyReductionInterval == 0 {
		return baseSubsidy
	}

	// Equivalent to: baseSubsidy / 2^(height/subsidyHalvingInterval)
	era := uint(height / chainParams.SubsidyReductionInterval)
	if era < 10 {
		return baseSubsidy >> uint(height/chainParams.SubsidyReductionInterval)
	} else {
		return 0
	}
}

// CheckTransactionSanity performs some preliminary checks on a transaction to
// ensure it is sane.  These checks are context free.
func CheckTransactionSanity(tx *abeutil.Tx) error {
	// A transaction must have at least one input.
	msgTx := tx.MsgTx()
	if len(msgTx.TxIn) == 0 {
		return ruleError(ErrNoTxInputs, "transaction has no inputs")
	}

	// A transaction must have at least one output.
	if len(msgTx.TxOut) == 0 {
		return ruleError(ErrNoTxOutputs, "transaction has no outputs")
	}

	// A transaction must not exceed the maximum allowed block payload when
	// serialized.
	serializedTxSize := tx.MsgTx().SerializeSizeStripped()
	if serializedTxSize > MaxBlockBaseSize {
		str := fmt.Sprintf("serialized transaction is too big - got "+
			"%d, max %d", serializedTxSize, MaxBlockBaseSize)
		return ruleError(ErrTxTooBig, str)
	}

	// Ensure the transaction amounts are in range.  Each transaction
	// output must not be negative or more than the max allowed per
	// transaction.  Also, the total of all outputs must abide by the same
	// restrictions.  All amounts in a transaction are in a unit value known
	// as a satoshi.  One bitcoin is a quantity of satoshi as defined by the
	// SatoshiPerBitcoin constant.
	var totalSatoshi int64
	for _, txOut := range msgTx.TxOut {
		satoshi := txOut.Value
		if satoshi < 0 {
			str := fmt.Sprintf("transaction output has negative "+
				"value of %v", satoshi)
			return ruleError(ErrBadTxOutValue, str)
		}
		if satoshi > abeutil.MaxSatoshi {
			str := fmt.Sprintf("transaction output value of %v is "+
				"higher than max allowed value of %v", satoshi,
				abeutil.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}

		// Two's complement int64 overflow guarantees that any overflow
		// is detected and reported.  This is impossible for Bitcoin, but
		// perhaps possible if an alt increases the total money supply.
		totalSatoshi += satoshi
		if totalSatoshi < 0 {
			str := fmt.Sprintf("total value of all transaction "+
				"outputs exceeds max allowed value of %v",
				abeutil.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}
		if totalSatoshi > abeutil.MaxSatoshi {
			str := fmt.Sprintf("total value of all transaction "+
				"outputs is %v which is higher than max "+
				"allowed value of %v", totalSatoshi,
				abeutil.MaxSatoshi)
			return ruleError(ErrBadTxOutValue, str)
		}
	}

	// Check for duplicate transaction inputs.
	existingTxOut := make(map[wire.OutPoint]struct{})
	for _, txIn := range msgTx.TxIn {
		if _, exists := existingTxOut[txIn.PreviousOutPoint]; exists {
			return ruleError(ErrDuplicateTxInputs, "transaction "+
				"contains duplicate inputs")
		}
		existingTxOut[txIn.PreviousOutPoint] = struct{}{}
	}

	// Coinbase script length must be between min and max length.
	if IsCoinBase(tx) {
		slen := len(msgTx.TxIn[0].SignatureScript)
		if slen < MinCoinbaseScriptLen || slen > MaxCoinbaseScriptLen {
			str := fmt.Sprintf("coinbase transaction script length "+
				"of %d is out of range (min: %d, max: %d)",
				slen, MinCoinbaseScriptLen, MaxCoinbaseScriptLen)
			return ruleError(ErrBadCoinbaseScriptLen, str)
		}
	} else {
		// Previous transaction outputs referenced by the inputs to this
		// transaction must not be null.
		for _, txIn := range msgTx.TxIn {
			if isNullOutpoint(&txIn.PreviousOutPoint) {
				return ruleError(ErrBadTxInput, "transaction "+
					"input refers to previous output that "+
					"is null")
			}
		}
	}

	return nil
}

// CheckTransactionSanityAbe performs some preliminary checks on a transaction to
// ensure it is sane.  These checks are context free.
//  1. There is at least one input and one output
//  2. The number of input and output should not exceed the maximum
//  3. Fee should not smaller than zero and bigger than MaxNeutrino
//  4. The size (without witness) should not exceed MaxBlockBaseSize
//  5. If is coinbase tx
//  1. Input's block number and ring size should obey the ring version
//     If is transfer tx
//  1. Each input's serial number should not be zero
//  2. Each input's ring version should be the same
//  3. Each input's block number and ring size should obey the ring version
//  4. No duplicate inputs (same ring and same serial number)
func CheckTransactionSanityAbe(tx *abeutil.TxAbe) error {
	// A transaction must have at least one input.
	msgTx := tx.MsgTx()
	if len(msgTx.TxIns) == 0 {
		return ruleError(ErrNoTxInputs, "transaction has no inputs")
	}

	// A transaction must have at least one output.
	//	here only does not check the situation of TxoDetails
	if len(msgTx.TxOuts) == 0 {
		return ruleError(ErrNoTxOutputs, "transaction has no outputs")
	}

	// At his moment, ABE limits the numbers of inputs and outputs, so does not consider the payload size
	txInputMaxNum, err := abecryptoparam.GetTxInputMaxNum(msgTx.Version)
	if err != nil {
		return err
	}
	if len(msgTx.TxIns) > txInputMaxNum {
		str := fmt.Sprintf("the number of inputs exceeds the allowd max number %d", txInputMaxNum)
		return ruleError(ErrTooManyTxInputs, str)
	}
	txOutputMaxNum, err := abecryptoparam.GetTxOutputMaxNum(msgTx.Version)
	if err != nil {
		return err
	}
	if len(msgTx.TxOuts) > txOutputMaxNum {
		str := fmt.Sprintf("the number of txo exceeds the allowd max number %d", txOutputMaxNum)
		return ruleError(ErrTooManyTxOutputs, str)
	}

	if msgTx.TxFee < 0 {
		str := fmt.Sprintf("transaction output has negative value of %v", msgTx.TxFee)
		return ruleError(ErrBadTxFeeValue, str)
	}
	if msgTx.TxFee > abeutil.MaxNeutrino {
		str := fmt.Sprintf("transaction fee of %v is higher than max allowed value of %v", msgTx.TxFee, abeutil.MaxSatoshi)
		return ruleError(ErrBadTxFeeValue, str)
	}

	// A transaction must not exceed the maximum allowed block payload when serialized.
	serializedTxSize := tx.MsgTx().SerializeSize()
	if serializedTxSize > MaxBlockBaseSize {
		str := fmt.Sprintf("serialized transaction is too big - got "+
			"%d, max %d", serializedTxSize, MaxBlockBaseSize)
		return ruleError(ErrTxTooBig, str)
	}

	isCb, err := IsCoinBaseAbe(tx)
	if err != nil {
		return err
	}
	if isCb {
		previousOutPointRing := msgTx.TxIns[0].PreviousOutPointRing
		/*		if previousOutPointRing == nil {
				return ruleError(ErrBadTxInput, "Coinbase Transaction refers to an OutPointRing that is null")
			}*/
		//	For coinbase transaction, the previousOutPointRing is hardcoded by design,
		//	where the ringVersion is set the same as the coinbase transaction.
		blockNumPerRingGroup, err := wire.GetBlockNumPerRingGroupByRingVersion(previousOutPointRing.Version)
		if err != nil {
			return err
		}
		txoRingSize, err := wire.GetTxoRingSizeByRingVersion(previousOutPointRing.Version)
		if err != nil {
			return err
		}

		blkHashNum := len(previousOutPointRing.BlockHashs)
		if blkHashNum != int(blockNumPerRingGroup) {
			str := fmt.Sprintf("Coinbase Transaction refers to an OutPointRing with block-hash-number "+
				"%d, should be %d", blkHashNum, blockNumPerRingGroup)
			return ruleError(ErrBadTxInput, str)
		}

		ringSize := len(previousOutPointRing.OutPoints)
		if ringSize > int(txoRingSize) {
			str := fmt.Sprintf("Coinbase Transaction refers to an OutPointRing with ring-size too big: "+
				"%d, max %d", ringSize, txoRingSize)
			return ruleError(ErrBadTxInput, str)
		}

		return nil
	}

	// A transfer transaction can consume only the rings with the same version, i.e., the Txos with the same version,
	// the Txos genreated by the same crypto-scheme.
	inputRingVersion := msgTx.TxIns[0].PreviousOutPointRing.Version
	blockNumPerRingGroup, err := wire.GetBlockNumPerRingGroupByRingVersion(inputRingVersion)
	txoRingSize, err := wire.GetTxoRingSizeByRingVersion(inputRingVersion)

	// Check for duplicate transaction inputs.
	consumedOutPoints := make(map[chainhash.Hash]map[string]struct{})
	for i, txIn := range msgTx.TxIns {
		nullSn, err := abecryptoparam.GetNullSerialNumber(txIn.PreviousOutPointRing.Version)
		if err != nil {
			return err
		}
		if bytes.Compare(txIn.SerialNumber, nullSn) == 0 {
			return ruleError(ErrBadTxInput, "transaction input refers to a serial number that is null")
		}

		if txIn.PreviousOutPointRing.Version != inputRingVersion {
			str := fmt.Sprintf("transaction's %d -th input refers to an OutPointRing with ring version "+
				"%d, different from 0-th input ring's version %d", i, txIn.PreviousOutPointRing.Version, inputRingVersion)
			return ruleError(ErrBadTxInput, str)
		}

		blkHashNum := len(txIn.PreviousOutPointRing.BlockHashs)
		if blkHashNum != int(blockNumPerRingGroup) {
			str := fmt.Sprintf("transaction's %d -th input refers to an OutPointRing with block-hash-number "+
				"%d, should be %d", i, blkHashNum, blockNumPerRingGroup)
			return ruleError(ErrBadTxInput, str)
		}

		ringSize := len(txIn.PreviousOutPointRing.OutPoints)
		if ringSize > int(txoRingSize) {
			str := fmt.Sprintf("transaction's %d -th input refers to an OutPointRing with ring-size too big: "+
				"%d, max %d", i, ringSize, txoRingSize)
			return ruleError(ErrBadTxInput, str)
		}

		ringHash := txIn.PreviousOutPointRing.Hash()
		if _, ringExists := consumedOutPoints[ringHash]; !ringExists {
			consumedOutPoints[ringHash] = make(map[string]struct{})
		}
		if _, snExists := consumedOutPoints[ringHash][string(txIn.SerialNumber)]; snExists {
			return ruleError(ErrDuplicateTxInputs, "transaction "+
				"contains duplicate inputs")
		}

		consumedOutPoints[ringHash][string(txIn.SerialNumber)] = struct{}{}
	}

	return nil
}

// checkProofOfWork ensures the block header bits which indicate the target
// difficulty is in min/max range and that the block hash is less than the
// target difficulty as claimed.
//
// The flags modify the behavior of this function as follows:
//   - BFNoPoWCheck: The check to ensure the block hash is less than the target
//     difficulty is not performed.
//     //	todo: (EthashPoW)
func checkProofOfWork(header *wire.BlockHeader, ethash *ethash.Ethash, powLimit *big.Int, flags BehaviorFlags) error {
	// The target difficulty must be larger than zero.
	target := CompactToBig(header.Bits)
	if target.Sign() <= 0 {
		str := fmt.Sprintf("block target difficulty of %064x is too low",
			target)
		return ruleError(ErrUnexpectedDifficulty, str)
	}

	// The target difficulty must be less than the maximum allowed.
	if target.Cmp(powLimit) > 0 {
		str := fmt.Sprintf("block target difficulty of %064x is "+
			"higher than max of %064x", target, powLimit)
		return ruleError(ErrUnexpectedDifficulty, str)
	}

	// The block hash must be less than the claimed target unless the flag
	// to avoid proof of work checks is set.
	if flags&BFNoPoWCheck != BFNoPoWCheck {
		// The block hash must be less than the claimed target.
		// todo: (EthashPoW)
		// It is necessary to use header.Version, rather than the Height as the branch condition.
		if header.Version == int32(wire.BlockVersionEthashPow) {
			err := ethash.VerifySeal(header, target)
			if err != nil {
				return err
			}
		} else {
			hash := header.BlockHash()
			hashNum := HashToBig(&hash)
			if hashNum.Cmp(target) > 0 {
				str := fmt.Sprintf("block hash of %064x is higher than "+
					"expected max of %064x", hashNum, target)
				return ruleError(ErrHighHash, str)
			}
		}
	}

	return nil
}

// CheckProofOfWork ensures the block header bits which indicate the target
// difficulty is in min/max range and that the block hash is less than the
// target difficulty as claimed.
func CheckProofOfWork(block *abeutil.Block, powLimit *big.Int) error {
	return checkProofOfWork(&block.MsgBlock().Header, nil, powLimit, BFNone)
}

// CountSigOps returns the number of signature operations for all transaction
// input and output scripts in the provided transaction.  This uses the
// quicker, but imprecise, signature operation counting mechanism from
// txscript.
func CountSigOps(tx *abeutil.Tx) int {
	msgTx := tx.MsgTx()

	// Accumulate the number of signature operations in all transaction
	// inputs.
	totalSigOps := 0
	for _, txIn := range msgTx.TxIn {
		numSigOps := txscript.GetSigOpCount(txIn.SignatureScript)
		totalSigOps += numSigOps
	}

	// Accumulate the number of signature operations in all transaction
	// outputs.
	for _, txOut := range msgTx.TxOut {
		numSigOps := txscript.GetSigOpCount(txOut.PkScript)
		totalSigOps += numSigOps
	}

	return totalSigOps
}

// CountP2SHSigOps returns the number of signature operations for all input
// transactions which are of the pay-to-script-hash type.  This uses the
// precise, signature operation counting mechanism from the script engine which
// requires access to the input transaction scripts.
func CountP2SHSigOps(tx *abeutil.Tx, isCoinBaseTx bool, utxoView *UtxoViewpoint) (int, error) {
	// Coinbase transactions have no interesting inputs.
	if isCoinBaseTx {
		return 0, nil
	}

	// Accumulate the number of signature operations in all transaction
	// inputs.
	msgTx := tx.MsgTx()
	totalSigOps := 0
	for txInIndex, txIn := range msgTx.TxIn {
		// Ensure the referenced input transaction is available.
		utxo := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if utxo == nil || utxo.IsSpent() {
			str := fmt.Sprintf("output %v referenced from "+
				"transaction %s:%d either does not exist or "+
				"has already been spent", txIn.PreviousOutPoint,
				tx.Hash(), txInIndex)
			return 0, ruleError(ErrMissingTxOut, str)
		}

		// We're only interested in pay-to-script-hash types, so skip
		// this input if it's not one.
		pkScript := utxo.PkScript()
		if !txscript.IsPayToScriptHash(pkScript) {
			continue
		}

		// Count the precise number of signature operations in the
		// referenced public key script.
		sigScript := txIn.SignatureScript
		numSigOps := txscript.GetPreciseSigOpCount(sigScript, pkScript,
			true)

		// We could potentially overflow the accumulator so check for
		// overflow.
		lastSigOps := totalSigOps
		totalSigOps += numSigOps
		if totalSigOps < lastSigOps {
			str := fmt.Sprintf("the public key script from output "+
				"%v contains too many signature operations - "+
				"overflow", txIn.PreviousOutPoint)
			return 0, ruleError(ErrTooManySigOps, str)
		}
	}

	return totalSigOps, nil
}

// checkBlockHeaderSanity performs some preliminary checks on a block header to
// ensure it is sane before continuing with processing.  These checks are
// context free.
//  1. Check proof of work
//  2. Check the precision of timestamp
//  3. Ensure the timestamp is not too far in the future
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to checkProofOfWork.
//
//	todo: (EthashPoW)
func checkBlockHeaderSanity(header *wire.BlockHeader, ethash *ethash.Ethash, powLimit *big.Int, timeSource MedianTimeSource, flags BehaviorFlags) error {
	// Ensure the proof of work bits in the block header is in min/max range
	// and the block hash is less than the target value described by the
	// bits.
	//	todo: (EthashPoW)
	err := checkProofOfWork(header, ethash, powLimit, flags)
	if err != nil {
		return err
	}

	// A block timestamp must not have a greater precision than one second.
	// This check is necessary because Go time.Time values support
	// nanosecond precision whereas the consensus rules only apply to
	// seconds and it's much nicer to deal with standard Go time values
	// instead of converting to seconds everywhere.
	if !header.Timestamp.Equal(time.Unix(header.Timestamp.Unix(), 0)) {
		str := fmt.Sprintf("block timestamp of %v has a higher "+
			"precision than one second", header.Timestamp)
		return ruleError(ErrInvalidTime, str)
	}

	// Ensure the block time is not too far in the future.
	maxTimestamp := timeSource.AdjustedTime().Add(time.Second *
		MaxTimeOffsetSeconds)
	if header.Timestamp.After(maxTimestamp) {
		str := fmt.Sprintf("block timestamp of %v is too far in the "+
			"future", header.Timestamp)
		return ruleError(ErrTimeTooNew, str)
	}

	return nil
}

// checkBlockSanity performs some preliminary checks on a block to ensure it is
// sane before continuing with block processing.  These checks are context free.
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to checkBlockHeaderSanity.
//
//	todo(ABE):
func checkBlockSanityBTCD(block *abeutil.Block, powLimit *big.Int, timeSource MedianTimeSource, flags BehaviorFlags) error {
	msgBlock := block.MsgBlock()
	header := &msgBlock.Header
	err := checkBlockHeaderSanity(header, nil, powLimit, timeSource, flags)
	if err != nil {
		return err
	}

	// A block must have at least one transaction.
	numTx := len(msgBlock.Transactions)
	if numTx == 0 {
		return ruleError(ErrNoTransactions, "block does not contain "+
			"any transactions")
	}

	// A block must not have more transactions than the max block payload or
	// else it is certainly over the weight limit.
	//	todo(ABE): This seems to be a bug
	if numTx > MaxBlockBaseSize {
		str := fmt.Sprintf("block contains too many transactions - "+
			"got %d, max %d", numTx, MaxBlockBaseSize)
		return ruleError(ErrBlockTooBig, str)
	}

	// A block must not exceed the maximum allowed block payload when
	// serialized.
	serializedSize := msgBlock.SerializeSizeStripped()
	if serializedSize > MaxBlockBaseSize {
		str := fmt.Sprintf("serialized block is too big - got %d, "+
			"max %d", serializedSize, MaxBlockBaseSize)
		return ruleError(ErrBlockTooBig, str)
	}

	// The first transaction in a block must be a coinbase.
	transactions := block.Transactions()
	if !IsCoinBase(transactions[0]) {
		return ruleError(ErrFirstTxNotCoinbase, "first transaction in "+
			"block is not a coinbase")
	}

	// A block must not have more than one coinbase.
	for i, tx := range transactions[1:] {
		if IsCoinBase(tx) {
			str := fmt.Sprintf("block contains second coinbase at "+
				"index %d", i+1)
			return ruleError(ErrMultipleCoinbases, str)
		}
	}

	// Do some preliminary checks on each transaction to ensure they are
	// sane before continuing.
	for _, tx := range transactions {
		err := CheckTransactionSanity(tx)
		if err != nil {
			return err
		}
	}

	// Build merkle tree and ensure the calculated merkle root matches the
	// entry in the block header.  This also has the effect of caching all
	// of the transaction hashes in the block to speed up future hash
	// checks.  Bitcoind builds the tree here and checks the merkle root
	// after the following checks, but there is no reason not to check the
	// merkle root matches here.
	merkles := BuildMerkleTreeStore(block.Transactions(), false)
	calculatedMerkleRoot := merkles[len(merkles)-1]
	if !header.MerkleRoot.IsEqual(calculatedMerkleRoot) {
		str := fmt.Sprintf("block merkle root is invalid - block "+
			"header indicates %v, but calculated value is %v",
			header.MerkleRoot, calculatedMerkleRoot)
		return ruleError(ErrBadMerkleRoot, str)
	}

	// Check for duplicate transactions.  This check will be fairly quick
	// since the transaction hashes are already cached due to building the
	// merkle tree above.
	existingTxHashes := make(map[chainhash.Hash]struct{})
	for _, tx := range transactions {
		hash := tx.Hash()
		if _, exists := existingTxHashes[*hash]; exists {
			str := fmt.Sprintf("block contains duplicate "+
				"transaction %v", hash)
			return ruleError(ErrDuplicateTx, str)
		}
		existingTxHashes[*hash] = struct{}{}
	}

	// The number of signature operations must be less than the maximum
	// allowed per block.
	totalSigOps := 0
	for _, tx := range transactions {
		// We could potentially overflow the accumulator so check for
		// overflow.
		lastSigOps := totalSigOps
		totalSigOps += (CountSigOps(tx) * WitnessScaleFactor)
		if totalSigOps < lastSigOps || totalSigOps > MaxBlockSigOpsCost {
			str := fmt.Sprintf("block contains too many signature "+
				"operations - got %v, max %v", totalSigOps,
				MaxBlockSigOpsCost)
			return ruleError(ErrTooManySigOps, str)
		}
	}

	return nil
}

// checkBlockSanityAbe performs some preliminary checks on a block to ensure it is
// sane before continuing with block processing.  These checks are context free.
//  1. Check sanity of block header (checkBlockHeaderSanity)
//  2. There is at least one transaction in the block
//  3. The block size (without witness) is smaller than MaxBlockBaseSize
//  4. The first transaction is coinbase and there is only one coinbase in the block
//  5. Preliminary check on each transaction (CheckTransactionSanityAbe)
//  6. The merkle root is correctly computed with the given transactions
//  7. No duplicate transactions (same tx hash)
//
// The flags do not modify the behavior of this function directly, however they
// are needed to pass along to checkBlockHeaderSanity.
//
//	todo: (EthashPoW)
func checkBlockSanityAbe(block *abeutil.BlockAbe, ethash *ethash.Ethash, powLimit *big.Int, timeSource MedianTimeSource, flags BehaviorFlags) error {
	msgBlock := block.MsgBlock()
	header := &msgBlock.Header
	//	todo: (EthashPoW)
	err := checkBlockHeaderSanity(header, ethash, powLimit, timeSource, flags)
	if err != nil {
		return err
	}

	// A block must have at least one transaction.
	numTx := len(msgBlock.Transactions)
	if numTx == 0 {
		return ruleError(ErrNoTransactions, "block does not contain "+
			"any transactions")
	}

	// A block must not have more transactions than the max block payload or
	// else it is certainly over the weight limit.
	if numTx > MaxBlockBaseSize {
		str := fmt.Sprintf("block contains too many transactions - "+
			"got %d, max %d", numTx, MaxBlockBaseSize)
		return ruleError(ErrBlockTooBig, str)
	}

	// A block must not exceed the maximum allowed block payload when
	// serialized.
	serializedSize := msgBlock.SerializeSizeStripped()
	if serializedSize > MaxBlockBaseSize {
		str := fmt.Sprintf("serialized block is too big - got %d, "+
			"max %d", serializedSize, MaxBlockBaseSize)
		return ruleError(ErrBlockTooBig, str)
	}

	// The first transaction in a block must be a coinbase.
	transactions := block.Transactions()
	isCb, err := transactions[0].IsCoinBase()
	if err != nil {
		return err
	}
	if !isCb {
		return ruleError(ErrFirstTxNotCoinbase, "first transaction in "+
			"block is not a coinbase")
	}

	// A block must not have more than one coinbase.
	for i, tx := range transactions[1:] {
		isCb, err := tx.IsCoinBase()
		if err != nil {
			return err
		}

		if isCb {
			str := fmt.Sprintf("block contains second coinbase at "+
				"index %d", i+1)
			return ruleError(ErrMultipleCoinbases, str)
		}
	}

	// Do some preliminary checks on each transaction to ensure they are
	// sane before continuing.
	for _, tx := range transactions {
		err := CheckTransactionSanityAbe(tx)
		if err != nil {
			return err
		}
	}

	// Build merkle tree and ensure the calculated merkle root matches the
	// entry in the block header.  This also has the effect of caching all
	// of the transaction hashes in the block to speed up future hash
	// checks.  Bitcoind builds the tree here and checks the merkle root
	// after the following checks, but there is no reason not to check the
	// merkle root matches here.
	// todo: (EthashPoW) use the optimized BuildMerkleTreeStoreAbeEthash()
	log.Debugf("Verify the transaction merkle tree for block %s", block.Hash())
	if header.Version == int32(wire.BlockVersionEthashPow) {
		calculatedMerkleRoot, _ := BuildMerkleTreeStoreAbeEthash(block.Transactions())
		if !header.MerkleRoot.IsEqual(calculatedMerkleRoot) {
			str := fmt.Sprintf("block merkle root is invalid - block "+
				"header indicates %v, but calculated value is %v",
				header.MerkleRoot, calculatedMerkleRoot)
			return ruleError(ErrBadMerkleRoot, str)
		}
	} else {
		merkles := BuildMerkleTreeStoreAbe(block.Transactions(), false)
		calculatedMerkleRoot := merkles[len(merkles)-1]
		if !header.MerkleRoot.IsEqual(calculatedMerkleRoot) {
			str := fmt.Sprintf("block merkle root is invalid - block "+
				"header indicates %v, but calculated value is %v",
				header.MerkleRoot, calculatedMerkleRoot)
			return ruleError(ErrBadMerkleRoot, str)
		}
	}

	// Check for duplicate transactions.  This check will be fairly quick
	// since the transaction hashes are already cached due to building the
	// merkle tree above.
	existingTxHashes := make(map[chainhash.Hash]struct{})
	for _, tx := range transactions {
		hash := tx.Hash()
		if _, exists := existingTxHashes[*hash]; exists {
			str := fmt.Sprintf("block contains duplicate "+
				"transaction %v", hash)
			return ruleError(ErrDuplicateTx, str)
		}
		existingTxHashes[*hash] = struct{}{}
	}

	return nil
}

// todo: (EthashPoW) 202207
func CheckBlockSanity(block *abeutil.BlockAbe, ethash *ethash.Ethash, powLimit *big.Int, timeSource MedianTimeSource) error {
	return checkBlockSanityAbe(block, ethash, powLimit, timeSource, BFNone)
}

// ExtractCoinbaseHeight attempts to extract the height of the block from the
// scriptSig of a coinbase transaction.  Coinbase heights are only present in
// blocks of version 2 or later.  This was added as part of BIP0034.
func ExtractCoinbaseHeight(coinbaseTx *abeutil.Tx) (int32, error) {
	sigScript := coinbaseTx.MsgTx().TxIn[0].SignatureScript
	if len(sigScript) < 1 {
		str := "the coinbase signature script for blocks of " +
			"version %d or greater must start with the " +
			"length of the serialized block height"
		str = fmt.Sprintf(str, serializedHeightVersion)
		return 0, ruleError(ErrMissingCoinbaseHeight, str)
	}

	// Detect the case when the block height is a small integer encoded with
	// as single byte.
	opcode := int(sigScript[0])
	if opcode == txscript.OP_0 {
		return 0, nil
	}
	if opcode >= txscript.OP_1 && opcode <= txscript.OP_16 {
		return int32(opcode - (txscript.OP_1 - 1)), nil
	}

	// Otherwise, the opcode is the length of the following bytes which
	// encode in the block height.
	serializedLen := int(sigScript[0])
	if len(sigScript[1:]) < serializedLen {
		str := "the coinbase signature script for blocks of " +
			"version %d or greater must start with the " +
			"serialized block height"
		str = fmt.Sprintf(str, serializedLen)
		return 0, ruleError(ErrMissingCoinbaseHeight, str)
	}

	serializedHeightBytes := make([]byte, 8)
	copy(serializedHeightBytes, sigScript[1:serializedLen+1])
	serializedHeight := binary.LittleEndian.Uint64(serializedHeightBytes)

	return int32(serializedHeight), nil
}

// todo(ABE):
func ExtractCoinbaseHeightAbe(coinbaseTx *abeutil.TxAbe) (int32, error) {
	if coinbaseTx == nil {
		str := "Cannot extract blockHeight from a coinbase transaction that is null"
		return 0, ruleError(ErrMissingCoinbaseHeight, str)
	}

	isCb, err := coinbaseTx.IsCoinBase()
	if err != nil {
		return 0, err
	}
	if !isCb {
		str := "Cannot extract blockHeight from a transaction that is not coinbase"
		return 0, ruleError(ErrMissingCoinbaseHeight, str)
	}

	if len(coinbaseTx.MsgTx().TxIns[0].PreviousOutPointRing.BlockHashs) < 1 {
		str := "Cannot extract blockHeight from a coinbase transaction that deos not match the protocol: There are not BlockHashs in PreviousOutPointRing"
		return 0, ruleError(ErrMissingCoinbaseHeight, str)
	}

	return wire.ExtractCoinbaseHeight(coinbaseTx.MsgTx()), nil
}

// checkSerializedHeight checks if the signature script in the passed
// transaction starts with the serialized block height of wantHeight.
func checkSerializedHeight(coinbaseTx *abeutil.Tx, wantHeight int32) error {
	serializedHeight, err := ExtractCoinbaseHeight(coinbaseTx)
	if err != nil {
		return err
	}

	if serializedHeight != wantHeight {
		str := fmt.Sprintf("the coinbase signature script serialized "+
			"block height is %d when %d was expected",
			serializedHeight, wantHeight)
		return ruleError(ErrBadCoinbaseHeight, str)
	}
	return nil
}

func checkSerializedHeightAbe(coinbaseTx *abeutil.TxAbe, wantHeight int32) error {
	serializedHeight, err := ExtractCoinbaseHeightAbe(coinbaseTx)
	if err != nil {
		return err
	}

	if serializedHeight != wantHeight {
		str := fmt.Sprintf("the coinbase signature script serialized "+
			"block height is %d when %d was expected",
			serializedHeight, wantHeight)
		return ruleError(ErrBadCoinbaseHeight, str)
	}
	return nil
}

// checkBlockHeaderContextAbe performs several validation checks on the block header
// which depend on its position within the block chain.
//
// The flags modify the behavior of this function as follows:
//   - BFFastAdd: All checks except those involving comparing the header against
//     the checkpoints are not performed.
//
// This function MUST be called with the chain state lock held (for writes).
//  1. Check the difficulty is correctly computed (if not fast add)
//  2. Check the timestamp is after the median time of last several blocks (if not fast add)
//  3. If this height is checkpoint, check if the block hash matches the checkpoint
//  4. Ensure the height of block is after the latest checkpoint
func (b *BlockChain) checkBlockHeaderContextAbe(header *wire.BlockHeader, prevNode *blockNode, flags BehaviorFlags) error {
	fastAdd := flags&BFFastAdd == BFFastAdd
	if !fastAdd {
		// Ensure the difficulty specified in the block header matches
		// the calculated difficulty based on the previous block and
		// difficulty retarget rules.
		expectedDifficulty, err := b.calcNextRequiredDifficulty(prevNode,
			header.Timestamp)
		if err != nil {
			return err
		}
		blockDifficulty := header.Bits
		if blockDifficulty != expectedDifficulty {
			str := "block difficulty of %d is not the expected value of %d"
			str = fmt.Sprintf(str, blockDifficulty, expectedDifficulty)
			return ruleError(ErrUnexpectedDifficulty, str)
		}

		// Ensure the timestamp for the block header is after the
		// median time of the last several blocks (medianTimeBlocks).
		medianTime := prevNode.CalcPastMedianTime()
		if !header.Timestamp.After(medianTime) {
			str := "block timestamp of %v is not after expected %v"
			str = fmt.Sprintf(str, header.Timestamp, medianTime)
			return ruleError(ErrTimeTooOld, str)
		}
	}

	// The height of this block is one more than the referenced previous
	// block.
	blockHeight := prevNode.height + 1
	// todo:(EthashPoW)
	//	This is VERY necessary.
	//	Now, the blockHeight of block/node is set, we can check the whether the header.Height and header.Version are set correctly.
	//	This will prevent an updated Abelian node from accepting an old-version block.
	if blockHeight >= b.chainParams.BlockHeightEthashPoW {
		if header.Height != blockHeight {
			str := fmt.Sprintf("block has height %d while its prevNode has height %d", header.Height, prevNode.height)
			return ruleError(ErrMismatchedBlockHeightWithPrevNode, str)
		}
		//	todo: when more versions appear, we need to refactor here.
		if header.Version != int32(wire.BlockVersionEthashPow) {
			str := fmt.Sprintf("block has height %d, it should have version %d for EthashPoW, rather than the old version %d", header.Height, int32(wire.BlockVersionEthashPow), header.Version)
			return ruleError(ErrMismatchedBlockHeightAndVersion, str)
		}
	}

	// Ensure chain matches up to predetermined checkpoints.
	blockHash := header.BlockHash()
	if !b.verifyCheckpoint(blockHeight, &blockHash) {
		str := fmt.Sprintf("block at height %d does not match "+
			"checkpoint hash", blockHeight)
		return ruleError(ErrBadCheckpoint, str)
	}

	// Find the previous checkpoint and prevent blocks which fork the main
	// chain before it.  This prevents storage of new, otherwise valid,
	// blocks which build off of old blocks that are likely at a much easier
	// difficulty and therefore could be used to waste cache and disk space.
	checkpointNode, err := b.findPreviousCheckpoint()
	if err != nil {
		return err
	}
	if checkpointNode != nil && blockHeight < checkpointNode.height {
		str := fmt.Sprintf("block at height %d forks the main chain "+
			"before the previous checkpoint at height %d",
			blockHeight, checkpointNode.height)
		return ruleError(ErrForkTooOld, str)
	}

	return nil
}

// checkBlockContextAbe peforms several validation checks on the block which depend
// on its position within the block chain.
//
// The flags modify the behavior of this function as follows:
//   - BFFastAdd: The transaction are not checked to see if they are finalized
//
// The flags are also passed to checkBlockHeaderContext.  See its documentation
// for how the flags modify its behavior.
//
// This function MUST be called with the chain state lock held (for writes).
//  1. Check the block header context (checkBlockHeaderContextAbe)
//  2. Check if the block height is written into the coinbase transaction (if not fast add)
func (b *BlockChain) checkBlockContextAbe(block *abeutil.BlockAbe, prevNode *blockNode, flags BehaviorFlags) error {
	// Perform all block header related validation checks.
	header := &block.MsgBlock().Header
	err := b.checkBlockHeaderContextAbe(header, prevNode, flags)
	if err != nil {
		return err
	}

	fastAdd := flags&BFFastAdd == BFFastAdd
	if !fastAdd {

		// The height of this block is one more than the referenced
		// previous block.
		blockHeight := prevNode.height + 1

		coinbaseTx := block.Transactions()[0]
		err = checkSerializedHeightAbe(coinbaseTx, blockHeight)
		if err != nil {
			return err
		}
		err = checkStandardCoinbaseTxIn(coinbaseTx.MsgTx(), block.Hash(), blockHeight, wire.TxVersion)
		if err != nil {
			return err
		}
		// If segwit is active, then we'll need to fully validate the
		// new witness commitment for adherence to the rules.
		//	todo(ABE): if witness commitment is implemented, here needs check?
		/*		if segwitState == ThresholdActive {
				// Validate the witness commitment (if any) within the
				// block.  This involves asserting that if the coinbase
				// contains the special commitment output, then this
				// merkle root matches a computed merkle root of all
				// the wtxid's of the transactions within the block. In
				// addition, various other checks against the
				// coinbase's witness stack.
				if err := ValidateWitnessCommitment(block); err != nil {
					return err
				}

				// Once the witness commitment, witness nonce, and sig
				// op cost have been validated, we can finally assert
				// that the block's weight doesn't exceed the current
				// consensus parameter.
				blockWeight := GetBlockWeight(block)
				if blockWeight > MaxBlockWeight {
					str := fmt.Sprintf("block's weight metric is "+
						"too high - got %v, max %v",
						blockWeight, MaxBlockWeight)
					return ruleError(ErrBlockWeightTooHigh, str)
				}
			}*/
	}

	return nil
}
func checkStandardCoinbaseTxIn(coinbaseTx *wire.MsgTxAbe, blockHash *chainhash.Hash, blockHeight int32, txVersion uint32) error {
	// one input
	if len(coinbaseTx.TxIns) != 1 {
		str := fmt.Sprintf("the coinbase transaction in block %s has %d input", blockHash, len(coinbaseTx.TxIns))
		return ruleError(ErrTooManyTxInputs, str)
	}
	// null serial number
	nullSn, err := abecryptoparam.GetNullSerialNumber(txVersion)
	if err != nil {
		return err
	}
	if !bytes.Equal(coinbaseTx.TxIns[0].SerialNumber, nullSn) {
		str := fmt.Sprintf("the serial number in coinbase transaction in block %s is not zero", blockHash)
		return ruleError(ErrBadTxInput, str)
	}
	// version, block hash in Ring
	if coinbaseTx.TxIns[0].PreviousOutPointRing.Version != txVersion {
		str := fmt.Sprintf("the version should be in coinbase transaction in block %s", blockHash)
		return ruleError(ErrBadTxInput, str)
	}
	if len(coinbaseTx.TxIns[0].PreviousOutPointRing.BlockHashs) != 0 {
		if binary.BigEndian.Uint32(coinbaseTx.TxIns[0].PreviousOutPointRing.BlockHashs[0][:4]) != uint32(blockHeight) {
			str := fmt.Sprintf("the height should be in coinbase transaction in block %s", blockHash)
			return ruleError(ErrBadTxInput, str)
		}
	}
	// one outpoint and empty data
	if len(coinbaseTx.TxIns[0].PreviousOutPointRing.OutPoints) != 1 {
		str := fmt.Sprintf("the consumed outpoint in coinbase transaction in block %s is %d", blockHash, len(coinbaseTx.TxIns[0].PreviousOutPointRing.OutPoints))
		return ruleError(ErrBadTxInput, str)
	}
	if !coinbaseTx.TxIns[0].PreviousOutPointRing.OutPoints[0].TxHash.IsEqual(&chainhash.ZeroHash) {
		str := fmt.Sprintf("the consumed outpoint in coinbase transaction in block %s shoudle be empty", blockHash)
		return ruleError(ErrBadTxInput, str)
	}
	if coinbaseTx.TxIns[0].PreviousOutPointRing.OutPoints[0].Index != 0 {
		str := fmt.Sprintf("the consumed outpoint in coinbase transaction in block %s shoudle be empty", blockHash)
		return ruleError(ErrBadTxInput, str)
	}

	return nil

}

// checkBIP0030 ensures blocks do not contain duplicate transactions which
// 'overwrite' older transactions that are not fully spent.  This prevents an
// attack where a coinbase and all of its dependent transactions could be
// duplicated to effectively revert the overwritten transactions to a single
// confirmation thereby making them vulnerable to a double spend.
//
// For more details, see
// https://github.com/bitcoin/bips/blob/master/bip-0030.mediawiki and
// http://r6.ca/blog/20120206T005236Z.html.
//
// This function MUST be called with the chain state lock held (for reads).
func (b *BlockChain) checkBIP0030(node *blockNode, block *abeutil.Block, view *UtxoViewpoint) error {
	// Fetch utxos for all of the transaction ouputs in this block.
	// Typically, there will not be any utxos for any of the outputs.
	fetchSet := make(map[wire.OutPoint]struct{})
	for _, tx := range block.Transactions() {
		prevOut := wire.OutPoint{Hash: *tx.Hash()}
		for txOutIdx := range tx.MsgTx().TxOut {
			prevOut.Index = uint32(txOutIdx)
			fetchSet[prevOut] = struct{}{}
		}
	}
	err := view.fetchUtxos(b.db, fetchSet)
	if err != nil {
		return err
	}

	// Duplicate transactions are only allowed if the previous transaction
	// is fully spent.
	for outpoint := range fetchSet {
		utxo := view.LookupEntry(outpoint)
		if utxo != nil && !utxo.IsSpent() {
			str := fmt.Sprintf("tried to overwrite transaction %v "+
				"at block height %d that is not fully spent",
				outpoint.Hash, utxo.BlockHeight())
			return ruleError(ErrOverwriteTx, str)
		}
	}

	return nil
}

// todo(Abe): remove
func (b *BlockChain) checkBIP0030Abe(node *blockNode, block *abeutil.BlockAbe, view *UtxoRingViewpoint) error {
	// Fetch utxos for all of the transaction ouputs in this block.
	// Typically, there will not be any utxos for any of the outputs.
	/*	fetchSet := make(map[wire.OutPoint]struct{})
		for _, tx := range block.Transactions() {
			prevOut := wire.OutPoint{Hash: *tx.Hash()}
			for txOutIdx := range tx.MsgTx().TxOut {
				prevOut.Index = uint32(txOutIdx)
				fetchSet[prevOut] = struct{}{}
			}
		}
		err := view.fetchUtxos(b.db, fetchSet)
		if err != nil {
			return err
		}

		// Duplicate transactions are only allowed if the previous transaction
		// is fully spent.
		for outpoint := range fetchSet {
			utxo := view.LookupEntry(outpoint)
			if utxo != nil && !utxo.IsSpent() {
				str := fmt.Sprintf("tried to overwrite transaction %v "+
					"at block height %d that is not fully spent",
					outpoint.Hash, utxo.BlockHeight())
				return ruleError(ErrOverwriteTx, str)
			}
		}*/

	return nil
}

// CheckTransactionInputs performs a series of checks on the inputs to a
// transaction to ensure they are valid.  An example of some of the checks
// include verifying all inputs exist, ensuring the coinbase seasoning
// requirements are met, detecting double spends, validating all values and fees
// are in the legal range and the total output amount doesn't exceed the input
// amount, and verifying the signatures to prove the spender was the owner of
// the bitcoins and therefore allowed to spend them.  As it checks the inputs,
// it also calculates the total fees for the transaction and returns that value.
//
// NOTE: The transaction MUST have already been sanity checked with the
// CheckTransactionSanity function prior to calling this function.
func CheckTransactionInputs(tx *abeutil.Tx, txHeight int32, utxoView *UtxoViewpoint, chainParams *chaincfg.Params) (int64, error) {
	// Coinbase transactions have no inputs.
	if IsCoinBase(tx) {
		return 0, nil
	}

	txHash := tx.Hash()
	var totalSatoshiIn int64
	for txInIndex, txIn := range tx.MsgTx().TxIn {
		// Ensure the referenced input transaction is available.
		utxo := utxoView.LookupEntry(txIn.PreviousOutPoint)
		if utxo == nil || utxo.IsSpent() {
			str := fmt.Sprintf("output %v referenced from "+
				"transaction %s:%d either does not exist or "+
				"has already been spent", txIn.PreviousOutPoint,
				tx.Hash(), txInIndex)
			return 0, ruleError(ErrMissingTxOut, str)
		}

		// Ensure the transaction is not spending coins which have not
		// yet reached the required coinbase maturity.
		if utxo.IsCoinBase() {
			originHeight := utxo.BlockHeight()
			blocksSincePrev := txHeight - originHeight
			coinbaseMaturity := int32(chainParams.CoinbaseMaturity)
			if blocksSincePrev < coinbaseMaturity {
				str := fmt.Sprintf("tried to spend coinbase "+
					"transaction output %v from height %v "+
					"at height %v before required maturity "+
					"of %v blocks", txIn.PreviousOutPoint,
					originHeight, txHeight,
					coinbaseMaturity)
				return 0, ruleError(ErrImmatureSpend, str)
			}
		}

		// Ensure the transaction amounts are in range.  Each of the
		// output values of the input transactions must not be negative
		// or more than the max allowed per transaction.  All amounts in
		// a transaction are in a unit value known as a satoshi.  One
		// bitcoin is a quantity of satoshi as defined by the
		// SatoshiPerBitcoin constant.
		originTxSatoshi := utxo.Amount()
		if originTxSatoshi < 0 {
			str := fmt.Sprintf("transaction output has negative "+
				"value of %v", abeutil.Amount(originTxSatoshi))
			return 0, ruleError(ErrBadTxOutValue, str)
		}
		if originTxSatoshi > abeutil.MaxSatoshi {
			str := fmt.Sprintf("transaction output value of %v is "+
				"higher than max allowed value of %v",
				abeutil.Amount(originTxSatoshi),
				abeutil.MaxSatoshi)
			return 0, ruleError(ErrBadTxOutValue, str)
		}

		// The total of all outputs must not be more than the max
		// allowed per transaction.  Also, we could potentially overflow
		// the accumulator so check for overflow.
		lastSatoshiIn := totalSatoshiIn
		totalSatoshiIn += originTxSatoshi
		if totalSatoshiIn < lastSatoshiIn ||
			totalSatoshiIn > abeutil.MaxSatoshi {
			str := fmt.Sprintf("total value of all transaction "+
				"inputs is %v which is higher than max "+
				"allowed value of %v", totalSatoshiIn,
				abeutil.MaxSatoshi)
			return 0, ruleError(ErrBadTxOutValue, str)
		}
	}

	// Calculate the total output amount for this transaction.  It is safe
	// to ignore overflow and out of range errors here because those error
	// conditions would have already been caught by checkTransactionSanity.
	var totalSatoshiOut int64
	for _, txOut := range tx.MsgTx().TxOut {
		totalSatoshiOut += txOut.Value
	}

	// Ensure the transaction does not spend more than its inputs.
	if totalSatoshiIn < totalSatoshiOut {
		str := fmt.Sprintf("total value of all transaction inputs for "+
			"transaction %v is %v which is less than the amount "+
			"spent of %v", txHash, totalSatoshiIn, totalSatoshiOut)
		return 0, ruleError(ErrSpendTooHigh, str)
	}

	// NOTE: bitcoind checks if the transaction fees are < 0 here, but that
	// is an impossible condition because of the check above that ensures
	// the inputs are >= the outputs.
	txFeeInSatoshi := totalSatoshiIn - totalSatoshiOut
	return txFeeInSatoshi, nil
}

// CheckTransactionInputsAbe performs a series of checks on the inputs to a
// transaction to ensure they are valid.
//  1. If the transaction is coinbase, just return
//  2. For each input, check if has been spent or not (txo ring exists and no existing serial number is the same)
//  3. For each input, check if it is mature if it consumes coinbase transaction
//     Abe todo
func CheckTransactionInputsAbe(tx *abeutil.TxAbe, txHeight int32, utxoRingView *UtxoRingViewpoint, chainParams *chaincfg.Params) error {
	// Coinbase transactions have no inputs.
	isCb, err := IsCoinBaseAbe(tx)
	if err != nil {
		return err
	}
	if isCb {
		return nil
	}

	for txInIndex, txIn := range tx.MsgTx().TxIns {
		// Ensure the referenced input transaction is available.
		utxoRing := utxoRingView.LookupEntry(txIn.PreviousOutPointRing.Hash())
		if utxoRing == nil || utxoRing.IsSpent(txIn.SerialNumber) {
			str := fmt.Sprintf("TXO Ring %s referenced from "+
				"transaction %s:%d either does not exist or "+
				"has already been spent", txIn.String(),
				tx.Hash(), txInIndex)
			return ruleError(ErrMissingTxOut, str)
			// Abe to do: update the ErrMissingTxOut to ErrMissingTxOutRing
		}

		// Ensure the transaction is not spending coins which have not
		// yet reached the required coinbase maturity.
		if utxoRing.IsCoinBase() {
			originHeight := utxoRing.RingBlockHeight()
			blocksSincePrev := txHeight - originHeight
			coinbaseMaturity := int32(chainParams.CoinbaseMaturity)
			if blocksSincePrev < coinbaseMaturity {
				str := fmt.Sprintf("tried to spend coinbase "+
					"transaction output %s from height %v "+
					"at height %v before required maturity "+
					"of %v blocks", txIn.String(),
					originHeight, txHeight,
					coinbaseMaturity)
				return ruleError(ErrImmatureSpend, str)
			}
		}
	}

	return nil
}

// checkConnectBlockAbe performs several checks to confirm connecting the passed
// block to the chain represented by the passed view does not violate any rules.
// In addition, the passed view is updated to spend all of the referenced
// outputs and add all of the new utxos created by block.  Thus, the view will
// represent the state of the chain as if the block were actually connected and
// consequently the best hash for the view is also updated to passed block.
//
// An example of some of the checks performed are ensuring connecting the block
// would not cause any duplicate transaction hashes for old transactions that
// aren't already fully spent, double spends, exceeding the maximum allowed
// signature operations per block, invalid values in relation to the expected
// block subsidy, or fail transaction script validation.
//
// The CheckConnectBlockTemplate function makes use of this function to perform
// the bulk of its work.  The only difference is this function accepts a node
// which may or may not require reorganization to connect it to the main chain
// whereas CheckConnectBlockTemplate creates a new node which specifically
// connects to the end of the current main chain and then calls this function
// with that node.
//
// This function MUST be called with the chain state lock held (for writes).
//
//		Abe todo
//	  1. Ensure the ring view is for the node being checked (the previous block is the best hash of ring view)
//	  2. Fetch all the utxo rings (consumed by inputs in the blocks) needed from the database and store them into ring view
//	  3. Check all transaction inputs (mature and not spent) CheckTransactionInputsAbe
//	  4. Add all transaction inputs into utxo rings (including serial number and consumed block hash)
//	  5. Ensure the block fee in coinbase is not larger than block reward plus tx fee
//	  6. Validate the witness of each transaction (if after the checkpoint)
//	  7. Set new best height for utxo ring view
func (b *BlockChain) checkConnectBlockAbe(node *blockNode, block *abeutil.BlockAbe, view *UtxoRingViewpoint, stxos *[]*SpentTxOutAbe) error {
	// If the side chain blocks end up in the database, a call to
	// CheckBlockSanity should be done here in case a previous version
	// allowed a block that is no longer valid.  However, since the
	// implementation only currently uses memory for the side chain blocks,
	// it isn't currently necessary.

	// The coinbase for the Genesis block is not spendable, so just return
	// an error now.
	//	In ABE, he coinbase for the Genesis block is spendable.
	/*	if node.hash.IsEqual(b.chainParams.GenesisHash) {
		str := "the coinbase for the genesis block is not spendable"
		return ruleError(ErrMissingTxOut, str)
	}*/

	// Ensure the view is for the node being checked.
	parentHash := &block.MsgBlock().Header.PrevBlock
	if !view.BestHash().IsEqual(parentHash) {
		return AssertError(fmt.Sprintf("inconsistent view when "+
			"checking block connection: best hash is %v instead "+
			"of expected %v", view.BestHash(), parentHash))
	}

	// BIP0030 added a rule to prevent blocks which contain duplicate
	// transactions that 'overwrite' older transactions which are not fully
	// spent.  See the documentation for checkBIP0030 for more details.
	//
	// There are two blocks in the chain which violate this rule, so the
	// check must be skipped for those blocks.  The isBIP0030Node function
	// is used to determine if this block is one of the two blocks that must
	// be skipped.
	//
	// In addition, as of BIP0034, duplicate coinbases are no longer
	// possible due to its requirement for including the block height in the
	// coinbase and thus it is no longer possible to create transactions
	// that 'overwrite' older ones.  Therefore, only enforce the rule if
	// BIP0034 is not yet active.  This is a useful optimization because the
	// BIP0030 check is expensive since it involves a ton of cache misses in
	// the utxoset.
	/*	if !isBIP0030Node(node) && (node.height < b.chainParams.BIP0034Height) {
		err := b.checkBIP0030(node, block, view)
		if err != nil {
			return err
		}
	}*/
	/*	err := b.checkBIP0030Abe(node, block, view)
		if err != nil {
			return err
		}*/

	// Load all of the utxo rings referenced by the inputs for all transactions
	// in the block don't already exist in the utxo ring view from the database.
	//
	// These utxo ring entries are needed for verification of things.
	err := view.fetchInputUtxoRings(b.db, block)
	if err != nil {
		return err
	}

	// Abe to do: Abe does not support p2sh at this moment
	/*	// BIP0016 describes a pay-to-script-hash type that is considered a
		// "standard" type.  The rules for this BIP only apply to transactions
		// after the timestamp defined by txscript.Bip16Activation.  See
		// https://en.bitcoin.it/wiki/BIP_0016 for more details.
		enforceBIP0016 := node.timestamp >= txscript.Bip16Activation.Unix()*/

	// Abe to do: set enforceSegWit as true
	/*	// Query for the Version Bits state for the segwit soft-fork
		// deployment. If segwit is active, we'll switch over to enforcing all
		// the new rules.
		segwitState, err := b.deploymentState(node.parent, chaincfg.DeploymentSegwit)
		if err != nil {
			return err
		}
		enforceSegWit := segwitState == ThresholdActive*/

	// The number of signature operations must be less than the maximum
	// allowed per block.  Note that the preliminary sanity checks on a
	// block also include a check similar to this one, but this check
	// expands the count to include a precise count of pay-to-script-hash
	// signature operations in each of the input transaction public key
	// scripts.
	transactions := block.Transactions()
	/*	totalSigOpCost := 0
		for i, tx := range transactions {
			// Since the first (and only the first) transaction has
			// already been verified to be a coinbase transaction,
			// use i == 0 as an optimization for the flag to
			// countP2SHSigOps for whether or not the transaction is
			// a coinbase transaction rather than having to do a
			// full coinbase check again.
			sigOpCost, err := GetSigOpCost(tx, i == 0, view, enforceBIP0016,
				enforceSegWit)
			if err != nil {
				return err
			}

			// Check for overflow or going over the limits.  We have to do
			// this on every loop iteration to avoid overflow.
			lastSigOpCost := totalSigOpCost
			totalSigOpCost += sigOpCost
			if totalSigOpCost < lastSigOpCost || totalSigOpCost > MaxBlockSigOpsCost {
				str := fmt.Sprintf("block contains too many "+
					"signature operations - got %v, max %v",
					totalSigOpCost, MaxBlockSigOpsCost)
				return ruleError(ErrTooManySigOps, str)
			}
		}*/

	// Perform several checks on the inputs for each transaction.  Also
	// accumulate the total fees.  This could technically be combined with
	// the loop above instead of running another loop over the transactions,
	// but by separating it we can avoid running the more expensive (though
	// still relatively cheap as compared to running the scripts) checks
	// against all the inputs when the signature operations are out of
	// bounds.
	var totalFees uint64
	for _, tx := range transactions[1:] {
		err := CheckTransactionInputsAbe(tx, node.height, view,
			b.chainParams)
		if err != nil {
			return err
		}

		// Sum the total fees and ensure we don't overflow the
		// accumulator.
		lastTotalFees := totalFees
		totalFees += tx.MsgTx().TxFee
		if totalFees < lastTotalFees {
			return ruleError(ErrBadFees, "total fees for block "+
				"overflows accumulator")
		}

		// Add all of the outputs for this transaction which are not
		// provably unspendable as available utxos.  Also, the passed
		// spent txos slice is updated to contain an entry for each
		// spent txout in the order each transaction spends them.
		err = view.connectTransaction(tx, &node.hash, stxos)
		if err != nil {
			return err
		}
	}

	// The total output values of the coinbase transaction must not exceed
	// the expected subsidy value plus total transaction fees gained from
	// mining the block.  It is safe to ignore overflow and out of range
	// errors here because those error conditions would have already been
	// caught by checkTransactionSanity.
	/*	var totalNeutrinoOut uint64
		for _, txOut := range transactions[0].MsgTx().TxOuts { // the coinbase transaction may have more than one outputs
			totalNeutrinoOut += txOut.ValueScript
		}*/
	totalNeutrinoOut := transactions[0].MsgTx().TxFee // for coinbase transaction, TxFee is used to represent the Value_in

	expectedNeutrinoOut := CalcBlockSubsidy(node.height, b.chainParams) + totalFees
	if totalNeutrinoOut > expectedNeutrinoOut {
		str := fmt.Sprintf("coinbase transaction for block pays %v "+
			"which is more than expected value of %v",
			totalNeutrinoOut, expectedNeutrinoOut)
		return ruleError(ErrBadCoinbaseValue, str)
	}

	// Don't run scripts if this node is before the latest known good
	// checkpoint since the validity is verified via the checkpoints (all
	// transactions are included in the merkle root hash and any changes
	// will therefore be detected by the next checkpoint).  This is a huge
	// optimization because running the scripts is the most time consuming
	// portion of block handling.
	checkpoint := b.LatestCheckpoint()
	witnessCheck := true
	// full node would check all data
	// semi full node/normal node would check witness after latest checkpoint
	if b.nodeType != wire.FullNode && checkpoint != nil && node.height <= checkpoint.Height {
		witnessCheck = false
	}

	// Blocks created after the BIP0016 activation time need to have the
	// pay-to-script-hash checks enabled.
	//var scriptFlags txscript.ScriptFlags
	/*	if enforceBIP0016 {
		scriptFlags |= txscript.ScriptBip16
	}*/

	// Enforce DER signatures for block versions 3+ once the historical
	// activation threshold has been reached.  This is part of BIP0066.
	/*	blockHeader := &block.MsgBlock().Header
		if blockHeader.Version >= 3 && node.height >= b.chainParams.BIP0066Height {
			scriptFlags |= txscript.ScriptVerifyDERSignatures
		}*/

	// Enforce CHECKLOCKTIMEVERIFY for block versions 4+ once the historical
	// activation threshold has been reached.  This is part of BIP0065.
	/*	if blockHeader.Version >= 4 && node.height >= b.chainParams.BIP0065Height {
			scriptFlags |= txscript.ScriptVerifyCheckLockTimeVerify
		}
	*/
	// Enforce CHECKSEQUENCEVERIFY during all block validation checks once
	// the soft-fork deployment is fully active.
	/*	csvState, err := b.deploymentState(node.parent, chaincfg.DeploymentCSV)
		if err != nil {
			return err
		}
		if csvState == ThresholdActive {
			// If the CSV soft-fork is now active, then modify the
			// scriptFlags to ensure that the CSV op code is properly
			// validated during the script checks bleow.
			scriptFlags |= txscript.ScriptVerifyCheckSequenceVerify

			// We obtain the MTP of the *previous* block in order to
			// determine if transactions in the current block are final.
			medianTime := node.parent.CalcPastMedianTime()

			// Additionally, if the CSV soft-fork package is now active,
			// then we also enforce the relative sequence number based
			// lock-times within the inputs of all transactions in this
			// candidate block.
			for _, tx := range block.Transactions() {
				// A transaction can only be included within a block
				// once the sequence locks of *all* its inputs are
				// active.
				sequenceLock, err := b.calcSequenceLock(node, tx, view,
					false)
				if err != nil {
					return err
				}
				if !SequenceLockActive(sequenceLock, node.height,
					medianTime) {
					str := fmt.Sprintf("block contains " +
						"transaction whose input sequence " +
						"locks are not met")
					return ruleError(ErrUnfinalizedTx, str)
				}
			}
		}*/

	// Enforce the segwit soft-fork package once the soft-fork has shifted
	// into the "active" version bits state.
	/*	if enforceSegWit {
		scriptFlags |= txscript.ScriptVerifyWitness
		scriptFlags |= txscript.ScriptStrictMultiSig
	}*/

	// Now that the inexpensive checks are done and have passed, verify the
	// transactions are actually allowed to spend the coins by running the
	// expensive ECDSA signature check scripts.  Doing this last helps
	// prevent CPU exhaustion attacks.
	if witnessCheck {
		log.Debugf("Check the witness for block %s in height %d", block.Hash(), block.Height())
		err := checkBlockScriptsAbe(block, view, b.witnessCache)
		if err != nil {
			return err
		}
	}

	// Update the best hash for view to include this block since all of its
	// transactions have been connected.
	view.SetBestHash(&node.hash)

	return nil
}

// CheckConnectBlockTemplateAbe fully validates that connecting the passed block to
// the main chain does not violate any consensus rules, aside from the proof of
// work requirement. The block must connect to the current tip of the main chain.
//
// This function is safe for concurrent access.
//
//	todo (ABE):
func (b *BlockChain) CheckConnectBlockTemplateAbe(block *abeutil.BlockAbe) error {
	b.chainLock.Lock()
	defer b.chainLock.Unlock()

	// Skip the proof of work check as this is just a block template.
	flags := BFNoPoWCheck

	// This only checks whether the block can be connected to the tip of the
	// current chain.
	tip := b.bestChain.Tip()
	header := block.MsgBlock().Header
	if tip.hash != header.PrevBlock {
		str := fmt.Sprintf("previous block must be the current chain tip %v, "+
			"instead got %v", tip.hash, header.PrevBlock)
		return ruleError(ErrPrevBlockNotBest, str)
	}

	//	todo: (EthashPoW)
	if header.Height != tip.height+1 {
		str := fmt.Sprintf("the height of block (template) must be 1 greater than that of the current chain tip %v (%d), "+
			"instead got %d", tip.hash, tip.height, header.Height)
		return ruleError(ErrMismatchedBlockHeightWithPrevNode, str)
	}

	//	todo: (EthashPoW)
	//	for flags = BFNoPoWCheck, PoW will not be checked, we set ethash = nil
	err := checkBlockSanityAbe(block, nil, b.chainParams.PowLimit, b.timeSource, flags)
	if err != nil {
		return err
	}

	err = b.checkBlockContextAbe(block, tip, flags)
	if err != nil {
		return err
	}

	// Leave the spent txouts entry nil in the state since the information
	// is not needed and thus extra work can be avoided.
	view := NewUtxoRingViewpoint()
	view.SetBestHash(&tip.hash)
	//	todo: (EthashPoW)
	newNode, err := b.newBlockNode(&header, tip)
	if err != nil {
		return err
	}

	return b.checkConnectBlockAbe(newNode, block, view, nil)
}

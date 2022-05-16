package blockchain

import (
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abeutil"
	"runtime"
	"time"
)

// txValidateItem holds a transaction to validate.
type txValidateItem struct {
	txInIndex int
	tx        *abeutil.TxAbe
}

// txValidator provides a type which asynchronously validates transaction.
// It provides several channels for communication and a processing
// function that is intended to be in run multiple goroutines.
type txValidator struct {
	validateChan chan *txValidateItem
	quitChan     chan struct{}
	resultChan   chan error
	utxoRingView *UtxoRingViewpoint
}

// sendResult sends the result of a script pair validation on the internal
// result channel while respecting the quit channel.  This allows orderly
// shutdown when the validation process is aborted early due to a validation
// error in one of the other goroutines.
func (v *txValidator) sendResult(result error) {
	select {
	case v.resultChan <- result:
	case <-v.quitChan:
	}
}

// validateHandler consumes items to validate from the internal validate channel
// and returns the result of the validation on the internal result channel. It
// must be run as a goroutine.
func (v *txValidator) validateHandler() {
out:
	for {
		select {
		case txVI := <-v.validateChan:
			err := ValidateTransactionScriptsAbe(txVI.tx, v.utxoRingView)
			v.sendResult(err)

		case <-v.quitChan:
			break out
		}
	}
}

// Validate validates the scripts for all of the passed transactions using
// multiple goroutines.
func (v *txValidator) Validate(items []*txValidateItem) error {
	if len(items) == 0 {
		return nil
	}

	// Limit the number of goroutines to do script validation based on the
	// number of processor cores.  This helps ensure the system stays
	// reasonably responsive under heavy load.
	maxGoRoutines := runtime.NumCPU() * 3
	if maxGoRoutines <= 0 {
		maxGoRoutines = 1
	}
	if maxGoRoutines > len(items) {
		maxGoRoutines = len(items)
	}

	// Start up validation handlers that are used to asynchronously
	// validate each transaction.
	for i := 0; i < maxGoRoutines; i++ {
		go v.validateHandler()
	}

	// Validate each of the transaction. The quit channel is closed when any
	// errors occur so all processing goroutines exit regardless of which
	// transaction had the validation error.
	numTx := len(items)
	currentItem := 0
	processedItems := 0
	for processedItems < numTx {
		// Only send items while there are still items that need to
		// be processed. The select statement will never select a nil
		// channel.
		var validateChan chan *txValidateItem
		var item *txValidateItem
		if currentItem < numTx {
			validateChan = v.validateChan
			item = items[currentItem]
		}

		select {
		case validateChan <- item:
			currentItem++

		case err := <-v.resultChan:
			processedItems++
			if err != nil {
				close(v.quitChan)
				return err
			}
		}
	}

	close(v.quitChan)
	return nil
}

// newTxValidator returns a new instance of txValidator to be used for
// validating transaction scripts asynchronously.
func newTxValidator(utxoRingView *UtxoRingViewpoint) *txValidator {
	return &txValidator{
		validateChan: make(chan *txValidateItem),
		quitChan:     make(chan struct{}),
		resultChan:   make(chan error),
		utxoRingView: utxoRingView,
	}
}

//	new validate function under pqringct
// to be discussed
func ValidateTransactionScriptsAbe(tx *abeutil.TxAbe, utxoRingView *UtxoRingViewpoint) error {

	txInLen := len(tx.MsgTx().TxIns)
	abeTxInDetail := make([]*abecrypto.AbeTxInDetail, txInLen)
	for i := 0; i < txInLen; i++ {
		utxoRing := utxoRingView.LookupEntry(tx.MsgTx().TxIns[i].PreviousOutPointRing.Hash())
		if utxoRing == nil {
			str := fmt.Sprintf("unable to find unspent "+
				"out point ring %v referenced from "+
				"transaction %s:%d",
				tx.MsgTx().TxIns[i].PreviousOutPointRing, tx.Hash(),
				i)
			return ruleError(ErrMissingTxOut, str)
		}

		serializedTxoList := utxoRing.TxOuts()

		ringHash := utxoRing.outPointRing.Hash()
		abeTxInDetail[i] = abecrypto.NewAbeTxInDetail(ringHash, serializedTxoList, tx.MsgTx().TxIns[i].SerialNumber)
	}

	isValid, err := abecrypto.TransferTxVerify(tx.MsgTx(), abeTxInDetail)
	if !isValid || err != nil {
		str := fmt.Sprintf("transaction %s verify failed", tx.Hash())
		return ruleError(ErrScriptValidation, str)
	}

	return nil
}

// checkBlockScriptsAbe validates the witness of each transaction in blocks
func checkBlockScriptsAbe(block *abeutil.BlockAbe, utxoRingView *UtxoRingViewpoint) error {

	//	Collect all transactions and required information for validation.
	allTxs := block.Transactions()
	numTx := len(allTxs)
	txValItems := make([]*txValidateItem, 0, numTx)

	for i := 0; i < numTx; i++ {
		// Skip coinbase transaction.
		isCb, err := allTxs[i].IsCoinBase()
		if err != nil {
			return err
		}
		if isCb {
			continue
		}

		txVI := &txValidateItem{
			txInIndex: allTxs[i].Index(),
			tx:        allTxs[i],
		}
		txValItems = append(txValItems, txVI)
	}

	start := time.Now()

	validator := newTxValidator(utxoRingView)
	if err := validator.Validate(txValItems); err != nil {
		return err
	}

	elapsed := time.Since(start)
	log.Debugf("block inputs %v took %v to verify", block.Hash(), elapsed)

	// Validate successfully.
	return nil
}

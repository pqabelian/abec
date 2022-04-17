package blockchain

import (
	"bytes"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/txscript"
	"github.com/abesuite/abec/wire"
	"math"
	"runtime"
	"time"
)

// btcd
// txValidateItem holds a transaction along with which input to validate.
type txValidateItem struct {
	txInIndex int
	txIn      *wire.TxIn
	tx        *abeutil.Tx
	sigHashes *txscript.TxSigHashes
}

// abe
// txValidateItemInput holds a transaction along with which input to validate.
// validate common input script
type txValidateItemInput struct {
	txInIndex int
	txIn      *wire.TxInAbe
	tx        *abeutil.TxAbe
}

// abe
// txValidateItemOutput holds a transaction along with which output to validate.
// validate common output script
type txValidateItemOutput struct {
	txOutIndex int
	txOut      *wire.TxOutAbe
	tx         *abeutil.TxAbe
}

// txValidator provides a type which asynchronously validates transaction
// inputs.  It provides several channels for communication and a processing
// function that is intended to be in run multiple goroutines.
type txValidator struct {
	validateChan chan *txValidateItem
	quitChan     chan struct{}
	resultChan   chan error
	utxoView     *UtxoViewpoint
	flags        txscript.ScriptFlags
	sigCache     *txscript.SigCache
	hashCache    *txscript.HashCache
}

// txValidatorInput provides a type which asynchronously validates transaction
// inputs.  It provides several channels for communication and a processing
// function that is intended to be in run multiple goroutines.
type txValidatorInput struct {
	validateChan chan *txValidateItemInput
	quitChan     chan struct{}
	resultChan   chan error
	utxoRingView *UtxoRingViewpoint
}

// txValidatorOutput provides a type which asynchronously validates transaction
// outputs.  It provides several channels for communication and a processing
// function that is intended to be in run multiple goroutines.
type txValidatorOutput struct {
	validateChan chan *txValidateItemOutput
	quitChan     chan struct{}
	resultChan   chan error
	utxoRingView *UtxoRingViewpoint
}

// txValidatorBalance provides a type which asynchronously validates transaction
// balance. It provides several channels for communication and a processing
// function that is intended to be in run multiple goroutines.
type txValidatorBalance struct {
	validateChan chan *abeutil.TxAbe
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

// sendResult sends the result of a script pair validation on the internal
// result channel while respecting the quit channel.  This allows orderly
// shutdown when the validation process is aborted early due to a validation
// error in one of the other goroutines.
func (v *txValidatorInput) sendResult(result error) {
	select {
	case v.resultChan <- result:
	case <-v.quitChan:
	}
}

// sendResult sends the result of a script pair validation on the internal
// result channel while respecting the quit channel.  This allows orderly
// shutdown when the validation process is aborted early due to a validation
// error in one of the other goroutines.
func (v *txValidatorOutput) sendResult(result error) {
	select {
	case v.resultChan <- result:
	case <-v.quitChan:
	}
}

// sendResult sends the result of a script pair validation on the internal
// result channel while respecting the quit channel.  This allows orderly
// shutdown when the validation process is aborted early due to a validation
// error in one of the other goroutines.
func (v *txValidatorBalance) sendResult(result error) {
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
			// Ensure the referenced input utxo is available.
			txIn := txVI.txIn
			utxo := v.utxoView.LookupEntry(txIn.PreviousOutPoint)
			if utxo == nil {
				str := fmt.Sprintf("unable to find unspent "+
					"output %v referenced from "+
					"transaction %s:%d",
					txIn.PreviousOutPoint, txVI.tx.Hash(),
					txVI.txInIndex)
				err := ruleError(ErrMissingTxOut, str)
				v.sendResult(err)
				break out
			}

			// Create a new script engine for the script pair.
			sigScript := txIn.SignatureScript
			witness := txIn.Witness
			pkScript := utxo.PkScript()
			inputAmount := utxo.Amount()
			vm, err := txscript.NewEngine(pkScript, txVI.tx.MsgTx(),
				txVI.txInIndex, v.flags, v.sigCache, txVI.sigHashes,
				inputAmount)
			if err != nil {
				str := fmt.Sprintf("failed to parse input "+
					"%s:%d which references output %v - "+
					"%v (input witness %x, input script "+
					"bytes %x, prev output script bytes %x)",
					txVI.tx.Hash(), txVI.txInIndex,
					txIn.PreviousOutPoint, err, witness,
					sigScript, pkScript)
				err := ruleError(ErrScriptMalformed, str)
				v.sendResult(err)
				break out
			}

			// Execute the script pair.
			if err := vm.Execute(); err != nil {
				str := fmt.Sprintf("failed to validate input "+
					"%s:%d which references output %v - "+
					"%v (input witness %x, input script "+
					"bytes %x, prev output script bytes %x)",
					txVI.tx.Hash(), txVI.txInIndex,
					txIn.PreviousOutPoint, err, witness,
					sigScript, pkScript)
				err := ruleError(ErrScriptValidation, str)
				v.sendResult(err)
				break out
			}

			// Validation succeeded.
			v.sendResult(nil)

		case <-v.quitChan:
			break out
		}
	}
}

// validateHandler consumes items to validate from the internal validate channel
// and returns the result of the validation on the internal result channel. It
// must be run as a goroutine.
func (v *txValidatorInput) validateHandler() {
out:
	for {
		select {
		case txVI := <-v.validateChan:
			// Ensure the referenced input utxoRing is available.
			txIn := txVI.txIn
			utxoRing := v.utxoRingView.LookupEntry(txIn.PreviousOutPointRing.Hash())
			if utxoRing == nil {
				str := fmt.Sprintf("unable to find unspent "+
					"out point ring %v referenced from "+
					"transaction %s:%d",
					txIn.PreviousOutPointRing, txVI.tx.Hash(),
					txVI.txInIndex)
				err := ruleError(ErrMissingTxOut, str)
				v.sendResult(err)
				break out
			}

			// Create a new engine for validation.
			txConsumed := utxoRing.TxOuts()
			vm, err := txscript.NewEngineAbe(txVI.tx.Hash(), txVI.tx.MsgTx(), txVI.txInIndex, -1, txConsumed, txscript.ItemInput)
			if err != nil {
				str := fmt.Sprintf("failed to parse input "+
					"%s:%d which references output %v - "+
					"%v)",
					txVI.tx.Hash(), txVI.txInIndex,
					txIn.PreviousOutPointRing, err)
				err := ruleError(ErrScriptMalformed, str)
				v.sendResult(err)
				break out
			}

			// Start engine.
			if err := vm.Execute(); err != nil {
				str := fmt.Sprintf("failed to validate input "+
					"%s:%d which references output %v - "+
					"%v)",
					txVI.tx.Hash(), txVI.txInIndex,
					txIn.PreviousOutPointRing, err)
				err := ruleError(ErrScriptValidation, str)
				v.sendResult(err)
				break out
			}

			// Validation succeeded.
			v.sendResult(nil)

		case <-v.quitChan:
			break out
		}
	}
}

// todo(ABE)
// validateHandler consumes items to validate from the internal validate channel
// and returns the result of the validation on the internal result channel. It
// must be run as a goroutine.
func (v *txValidatorOutput) validateHandler() {
out:
	for {
		select {
		case <-v.validateChan:
			v.sendResult(nil)

		case <-v.quitChan:
			break out
		}
	}
}

// todo(ABE)
// validateHandler consumes items to validate from the internal validate channel
// and returns the result of the validation on the internal result channel. It
// must be run as a goroutine.
func (v *txValidatorBalance) validateHandler() {
out:
	for {
		select {
		case <-v.validateChan:
			v.sendResult(nil)

		case <-v.quitChan:
			break out
		}
	}
}

// Validate validates the scripts for all of the passed transaction inputs using
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
	// validate each transaction input.
	for i := 0; i < maxGoRoutines; i++ {
		go v.validateHandler()
	}

	// Validate each of the inputs.  The quit channel is closed when any
	// errors occur so all processing goroutines exit regardless of which
	// input had the validation error.
	numInputs := len(items)
	currentItem := 0
	processedItems := 0
	for processedItems < numInputs {
		// Only send items while there are still items that need to
		// be processed.  The select statement will never select a nil
		// channel.
		var validateChan chan *txValidateItem
		var item *txValidateItem
		if currentItem < numInputs {
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

// Validate validates the scripts for all of the passed transaction inputs using
// multiple goroutines.
func (v *txValidatorInput) Validate(items []*txValidateItemInput) error {
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
	// validate each transaction input.
	for i := 0; i < maxGoRoutines; i++ {
		// TODO(abe): do use the lock and sync, maybe there are some wrong logic if possible?
		go v.validateHandler()
	}

	// Validate each of the inputs.  The quit channel is closed when any
	// errors occur so all processing goroutines exit regardless of which
	// input had the validation error.
	numInputs := len(items)
	currentItem := 0
	processedItems := 0
	for processedItems < numInputs {
		// Only send items while there are still items that need to
		// be processed.  The select statement will never select a nil
		// channel.
		var validateChan chan *txValidateItemInput
		var item *txValidateItemInput
		if currentItem < numInputs {
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

// Validate validates the scripts for all of the passed transaction outputs using
// multiple goroutines.
func (v *txValidatorOutput) Validate(items []*txValidateItemOutput) error {
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
	// validate each transaction input.
	for i := 0; i < maxGoRoutines; i++ {
		go v.validateHandler()
	}

	// Validate each of the outputs.  The quit channel is closed when any
	// errors occur so all processing goroutines exit regardless of which
	// output had the validation error.
	numOutputs := len(items)
	currentItem := 0
	processedItems := 0
	for processedItems < numOutputs {
		// Only send items while there are still items that need to
		// be processed.  The select statement will never select a nil
		// channel.
		var validateChan chan *txValidateItemOutput
		var item *txValidateItemOutput
		if currentItem < numOutputs {
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

// Validate validates the scripts for all of the passed transaction balance using
// multiple goroutines.
func (v *txValidatorBalance) Validate(items []*abeutil.TxAbe) error {
	if len(items) == 0 {
		return nil
	}

	// Limit the number of goroutines to do script validation based on the
	// number of processor cores.  This helps ensure the system stays
	// reasonably responsive under heavy load.
	// TODO(abe): this parameter is too large?
	maxGoRoutines := runtime.NumCPU() * 3
	if maxGoRoutines <= 0 {
		maxGoRoutines = 1
	}
	if maxGoRoutines > len(items) {
		maxGoRoutines = len(items)
	}

	// Start up validation handlers that are used to asynchronously
	// validate each transaction input.
	for i := 0; i < maxGoRoutines; i++ {
		go v.validateHandler()
	}

	// Validate each of the transaction balance. The quit channel is closed when any
	// errors occur so all processing goroutines exit regardless of which
	// transaction had the validation error.
	numTx := len(items)
	currentItem := 0
	processedItems := 0
	for processedItems < numTx {
		// Only send items while there are still items that need to
		// be processed.  The select statement will never select a nil
		// channel.
		var validateChan chan *abeutil.TxAbe
		var item *abeutil.TxAbe
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
func newTxValidator(utxoView *UtxoViewpoint, flags txscript.ScriptFlags,
	sigCache *txscript.SigCache, hashCache *txscript.HashCache) *txValidator {
	return &txValidator{
		validateChan: make(chan *txValidateItem),
		quitChan:     make(chan struct{}),
		resultChan:   make(chan error),
		utxoView:     utxoView,
		sigCache:     sigCache,
		hashCache:    hashCache,
		flags:        flags,
	}
}

// newTxValidatorInput returns a new instance of txValidatorInput to
// be used for validating transaction inputs asynchronously.
func newTxValidatorInput(utxoRingView *UtxoRingViewpoint) *txValidatorInput {
	return &txValidatorInput{
		validateChan: make(chan *txValidateItemInput),
		quitChan:     make(chan struct{}),
		resultChan:   make(chan error),
		utxoRingView: utxoRingView,
	}
}

// newTxValidatorOutput returns a new instance of txValidatorOutput to
// be used for validating transaction outputs asynchronously.
func newTxValidatorOutput(utxoRingView *UtxoRingViewpoint) *txValidatorOutput {
	return &txValidatorOutput{
		validateChan: make(chan *txValidateItemOutput),
		quitChan:     make(chan struct{}),
		resultChan:   make(chan error),
		utxoRingView: utxoRingView,
	}
}

// newTxValidatorBalance returns a new instance of txValidatorBalance to
// be used for validating transaction input and output balance asynchronously.
func newTxValidatorBalance(utxoRingView *UtxoRingViewpoint) *txValidatorBalance {
	return &txValidatorBalance{
		validateChan: make(chan *abeutil.TxAbe),
		quitChan:     make(chan struct{}),
		resultChan:   make(chan error),
		utxoRingView: utxoRingView,
	}
}

// ValidateTransactionScripts validates the scripts for the passed transaction
// using multiple goroutines.
func ValidateTransactionScripts(tx *abeutil.Tx, utxoView *UtxoViewpoint,
	flags txscript.ScriptFlags, sigCache *txscript.SigCache,
	hashCache *txscript.HashCache) error {

	// First determine if segwit is active according to the scriptFlags. If
	// it isn't then we don't need to interact with the HashCache.
	segwitActive := flags&txscript.ScriptVerifyWitness == txscript.ScriptVerifyWitness

	// If the hashcache doesn't yet has the sighash midstate for this
	// transaction, then we'll compute them now so we can re-use them
	// amongst all worker validation goroutines.
	if segwitActive && tx.MsgTx().HasWitness() &&
		!hashCache.ContainsHashes(tx.Hash()) {
		hashCache.AddSigHashes(tx.MsgTx())
	}

	var cachedHashes *txscript.TxSigHashes
	if segwitActive && tx.MsgTx().HasWitness() {
		// The same pointer to the transaction's sighash midstate will
		// be re-used amongst all validation goroutines. By
		// pre-computing the sighash here instead of during validation,
		// we ensure the sighashes
		// are only computed once.
		cachedHashes, _ = hashCache.GetSigHashes(tx.Hash())
	}

	// Collect all of the transaction inputs and required information for
	// validation.
	txIns := tx.MsgTx().TxIn
	txValItems := make([]*txValidateItem, 0, len(txIns))
	for txInIdx, txIn := range txIns {
		// Skip coinbases.
		if txIn.PreviousOutPoint.Index == math.MaxUint32 {
			continue
		}

		txVI := &txValidateItem{
			txInIndex: txInIdx,
			txIn:      txIn,
			tx:        tx,
			sigHashes: cachedHashes,
		}
		txValItems = append(txValItems, txVI)
	}

	// Validate all of the inputs.
	validator := newTxValidator(utxoView, flags, sigCache, hashCache)
	return validator.Validate(txValItems)
}

//	the validation function can be removed because the main validation process has been moved to pqringct
func ValidateTransactionScriptsAbe2(tx *abeutil.TxAbe, utxoRingView *UtxoRingViewpoint) error {

	//  todo
	//	TxBalance
	//	The balance between the inputs and outputs should be verified.
	//	For SALRS, the can be done by simple computation with public values;
	//	But for full version, this is done by some witness based on cryptography.
	txValItemsBalance := make([]*abeutil.TxAbe, 0, 1)
	txValItemsBalance = append(txValItemsBalance, tx)
	validatorBalance := newTxValidatorBalance(utxoRingView)
	if err := validatorBalance.Validate(txValItemsBalance); err != nil {
		return err
	}

	//	TxIns
	//	Collect all of the transaction inputs and required information for validation.
	//	For each input, the authorization and authentication should be verified.
	txIns := tx.MsgTx().TxIns
	nullSN, err := abecryptoparam.GetNullSerialNumber(tx.MsgTx().Version)
	if err != nil {
		return err
	}
	txValItemsInput := make([]*txValidateItemInput, 0, len(txIns))
	for txInIdx, txIn := range txIns {
		// Skip coinbases. Redundant here.
		if bytes.Equal(txIn.SerialNumber, nullSN) {
			continue
		}

		txVI := &txValidateItemInput{
			txInIndex: txInIdx,
			txIn:      txIn,
			tx:        tx,
		}
		txValItemsInput = append(txValItemsInput, txVI)
	}

	// Validate all of the inputs.
	validatorInput := newTxValidatorInput(utxoRingView)
	if err := validatorInput.Validate(txValItemsInput); err != nil {
		return err
	}

	//  todo
	//	TxOuts
	//	Collect all of the transaction outputs and required information for validation.
	//	For full version, each TXO's hidden value should be verified, e.g. the range proof
	txOuts := tx.MsgTx().TxOuts
	txValItemsOutput := make([]*txValidateItemOutput, 0, len(txOuts))
	for txOutIdx, txOut := range txOuts {
		txVI := &txValidateItemOutput{
			txOutIndex: txOutIdx,
			txOut:      txOut,
			tx:         tx,
		}
		txValItemsOutput = append(txValItemsOutput, txVI)
	}

	// Validate all of the outputs.
	validatorOutput := newTxValidatorOutput(utxoRingView)
	if err := validatorOutput.Validate(txValItemsOutput); err != nil {
		return err
	}

	// Validate successfully.
	return nil
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
		// TODO(20220320): compute the ringHash and choose the sidx
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

// checkBlockScripts executes and validates the inputs, outputs and balance
// for all transactions in the passed block using multiple goroutines.
func checkBlockScripts(block *abeutil.Block, utxoView *UtxoViewpoint,
	scriptFlags txscript.ScriptFlags, sigCache *txscript.SigCache,
	hashCache *txscript.HashCache) error {

	// First determine if segwit is active according to the scriptFlags. If
	// it isn't then we don't need to interact with the HashCache.
	segwitActive := scriptFlags&txscript.ScriptVerifyWitness == txscript.ScriptVerifyWitness

	// Collect all of the transaction inputs and required information for
	// validation for all transactions in the block into a single slice.
	numInputs := 0
	for _, tx := range block.Transactions() {
		numInputs += len(tx.MsgTx().TxIn)
	}
	txValItems := make([]*txValidateItem, 0, numInputs)
	for _, tx := range block.Transactions() {
		hash := tx.Hash()

		// If the HashCache is present, and it doesn't yet contain the
		// partial sighashes for this transaction, then we add the
		// sighashes for the transaction. This allows us to take
		// advantage of the potential speed savings due to the new
		// digest algorithm (BIP0143).
		if segwitActive && tx.HasWitness() && hashCache != nil &&
			!hashCache.ContainsHashes(hash) {

			hashCache.AddSigHashes(tx.MsgTx())
		}

		var cachedHashes *txscript.TxSigHashes
		if segwitActive && tx.HasWitness() {
			if hashCache != nil {
				cachedHashes, _ = hashCache.GetSigHashes(hash)
			} else {
				cachedHashes = txscript.NewTxSigHashes(tx.MsgTx())
			}
		}

		for txInIdx, txIn := range tx.MsgTx().TxIn {
			// Skip coinbases.
			if txIn.PreviousOutPoint.Index == math.MaxUint32 {
				continue
			}

			txVI := &txValidateItem{
				txInIndex: txInIdx,
				txIn:      txIn,
				tx:        tx,
				sigHashes: cachedHashes,
			}
			txValItems = append(txValItems, txVI)
		}
	}

	// Validate all of the inputs.
	validator := newTxValidator(utxoView, scriptFlags, sigCache, hashCache)
	start := time.Now()
	if err := validator.Validate(txValItems); err != nil {
		return err
	}
	elapsed := time.Since(start)

	log.Tracef("block %v took %v to verify", block.Hash(), elapsed)

	// If the HashCache is present, once we have validated the block, we no
	// longer need the cached hashes for these transactions, so we purge
	// them from the cache.
	if segwitActive && hashCache != nil {
		for _, tx := range block.Transactions() {
			if tx.MsgTx().HasWitness() {
				hashCache.PurgeSigHashes(tx.Hash())
			}
		}
	}

	return nil
}

// checkBlockScriptsAbe executes and validates the inputs, outputs and balance
// for all transactions in the passed block using multiple goroutines.
func checkBlockScriptsAbe(block *abeutil.BlockAbe, utxoRingView *UtxoRingViewpoint) error {
	//  todo
	//	TxBalance
	//	The balance between the inputs and outputs of all transactions should be verified.
	//	For SALRS, the can be done by simple computation with public values;
	//	But for full version, this is done by some witness based on cryptography.
	txValItemsBalance := block.Transactions()
	validatorBalance := newTxValidatorBalance(utxoRingView)

	start := time.Now()
	if err := validatorBalance.Validate(txValItemsBalance); err != nil {
		return err
	}
	elapsed := time.Since(start)
	log.Tracef("block balance %v took %v to verify", block.Hash(), elapsed)

	//	TxIns
	//	Collect all transaction's inputs and required information for validation.
	//	For each input, the authorization and authentication should be verified.
	numInputs := 0
	for _, tx := range block.Transactions() {
		numInputs += len(tx.MsgTx().TxIns)
	}
	txValItemsInput := make([]*txValidateItemInput, 0, numInputs)

	for _, tx := range block.Transactions() {
		for txInIdx, txIn := range tx.MsgTx().TxIns {
			// Skip coinbases. Redundant here.
			nullSerialNumber, err := abecryptoparam.GetNullSerialNumber(tx.MsgTx().Version)
			if err != nil {
				return err
			}
			if bytes.Equal(txIn.SerialNumber, nullSerialNumber) {
				continue
			}

			txVI := &txValidateItemInput{
				txInIndex: txInIdx,
				txIn:      txIn,
				tx:        tx,
			}
			txValItemsInput = append(txValItemsInput, txVI)
		}
	}

	// Validate all of the inputs.
	validatorInput := newTxValidatorInput(utxoRingView)

	start = time.Now()
	if err := validatorInput.Validate(txValItemsInput); err != nil {
		return err
	}
	elapsed = time.Since(start)
	log.Tracef("block inputs %v took %v to verify", block.Hash(), elapsed)

	//  todo
	//	TxOuts
	//	Collect all transaction's outputs and required information for validation.
	//	For full version, each TXO's hidden value should be verified, e.g. the range proof
	numOutputs := 0
	for _, tx := range block.Transactions() {
		numOutputs += len(tx.MsgTx().TxOuts)
	}
	txValItemsOutput := make([]*txValidateItemOutput, 0, numOutputs)

	for _, tx := range block.Transactions() {
		for txOutIdx, txOut := range tx.MsgTx().TxOuts {

			txVI := &txValidateItemOutput{
				txOutIndex: txOutIdx,
				txOut:      txOut,
				tx:         tx,
			}
			txValItemsOutput = append(txValItemsOutput, txVI)
		}
	}

	// Validate all of the outputs.
	validatorOutput := newTxValidatorOutput(utxoRingView)

	start = time.Now()
	if err := validatorOutput.Validate(txValItemsOutput); err != nil {
		return err
	}
	elapsed = time.Since(start)
	log.Tracef("block outputs %v took %v to verify", block.Hash(), elapsed)

	// Validate successfully.
	return nil
}

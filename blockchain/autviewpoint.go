package blockchain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/aut"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/database"
)

// autFlags is a bitmask defining additional information and state for a
// aut transaction output in an aut view.
type autFlags uint8

const (
	// atfRootCoin indicates that a txout was contained in a registration tx or transfer/mint tx.
	atfRootCoin autFlags = 1 << iota

	// tfSpent indicates that a txout is spent.
	atfSpent

	// atfModified indicates that a txout has been modified since it was
	// loaded.
	atfModified
)

// data structure
// AUTSCRIPT | AUT Version | VarSize | AUT TX TYPE |
// 													 AUT NAME | issuers | PLANNED  | threshold ..
// 													  n | value | ... | value | memo
// 													            issuers |  PLANNED  | threshold ..
// 													  issuers | threshold
//

// Register (txhash,index) -> (aut_name,root_coin)
// Mint (txhash,index)  -> AUT Coin (AUT NAME)
// Transfer Abelian TXO  -> AUT Coin (AUT NAME)
//

// AUTEntry houses details about an AUT Transaction output in a AUT
// view such as whether or not it was contained in a AUT Registration Transaction, the height of
// the block that contains the tx, whether or not it is spent, its public key
// script, and how much it pays.
type Entry struct {
	info   *aut.Info
	tokens map[aut.OutPoint]*AUTEntry
}

func (e Entry) Add(outpiont aut.OutPoint, entry *AUTEntry) {
	e.tokens[outpiont] = entry
}

type AUTEntry struct {
	name []byte
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.
	amount      uint64
	blockHeight int32 // Height of block containing tx.

	// packedFlags contains additional info about output such as whether it
	// is a coinbase, whether it is spent, and whether it has been modified
	// since it was loaded.  This approach is used in order to reduce memory
	// usage since there will be a lot of these in memory.
	packedFlags autFlags
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (entry *AUTEntry) isModified() bool {
	return entry.packedFlags&atfModified == atfModified
}

// IsRootCoin returns whether or not the output was contained in a coinbase
// transaction.
func (entry *AUTEntry) IsRootCoin() bool {
	return entry.packedFlags&atfRootCoin == atfRootCoin
}

// IsSpent returns whether or not the output has been spent based upon the
// current state of the unspent transaction output view it was obtained from.
func (entry *AUTEntry) IsSpent() bool {
	return entry.packedFlags&atfSpent == atfSpent
}

// BlockHeight returns the height of the block containing the output.
func (entry *AUTEntry) BlockHeight() int32 {
	return entry.blockHeight
}

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
func (entry *AUTEntry) Spend() {
	// Nothing to do if the output is already spent.
	if entry.IsSpent() {
		return
	}

	// Mark the output as spent and modified.
	entry.packedFlags |= atfSpent | atfModified
}

// Amount returns the amount of the output.
func (entry *AUTEntry) Amount() uint64 {
	return entry.amount
}

// Clone returns a shallow copy of the utxo entry.
func (entry *AUTEntry) Clone() *AUTEntry {
	if entry == nil {
		return nil
	}

	return &AUTEntry{
		amount:      entry.amount,
		blockHeight: entry.blockHeight,
		packedFlags: entry.packedFlags,
	}
}

// NewAUTEntry returns a new AUTEntry built from the arguments.
func NewAUTEntry(
	name []byte, amount uint64, blockHeight int32, isRootCoin bool) *AUTEntry {
	var flag autFlags
	if isRootCoin {
		flag |= atfRootCoin
	}

	return &AUTEntry{
		amount:      amount,
		blockHeight: blockHeight,
		packedFlags: flag,
	}
}

// AUTViewpoint represents a view into the set of unspent transaction outputs
// from a specific point of view in the chain.  For example, it could be for
// the end of the main chain, some point in the history of the main chain, or
// down a side chain.
//
// The unspent outputs are needed by other transactions for things such as
// script validation and double spend prevention.
type AUTViewpoint struct {
	entries  map[string]*Entry
	bestHash chainhash.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
func (view *AUTViewpoint) BestHash() *chainhash.Hash {
	return &view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
func (view *AUTViewpoint) SetBestHash(hash *chainhash.Hash) {
	view.bestHash = *hash
}

// LookupEntry returns information about a given transaction output according to
// the current state of the view.  It will return nil if the passed output does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
func (view *AUTViewpoint) LookupEntry(autNameKey string, outpoint aut.OutPoint) *AUTEntry {
	if view.entries == nil {
		return nil
	}
	entry, ok := view.entries[autNameKey]
	if !ok {
		return nil
	}
	return entry.tokens[outpoint]
}

func (view *AUTViewpoint) LookupInfo(autNameKey string) *aut.Info {
	if view.entries == nil {
		return nil
	}
	entry, ok := view.entries[autNameKey]
	if !ok {
		return nil
	}
	return entry.info
}

// addTxOut adds the specified output to the view if it is not provably
// unspendable.  When the view already has an entry for the output, it will be
// marked unspent.  All fields will be updated for existing entries since it's
// possible it has changed during a reorg.
func (view *AUTViewpoint) addAUTToken(autNameKey string, outpoint aut.OutPoint, amount uint64, blockHeight int32) {
	// if the tx is not existing in the utxoentry, create a new one. otherwise update the height of view
	// Update existing entries.  All fields are updated because it's
	// possible (although extremely unlikely) that the existing entry is
	// being replaced by a different transaction with the same hash.  This
	// is allowed so long as the previous transaction is fully spent.
	_, ok := view.entries[autNameKey]
	if !ok {
		log.Errorf("unreachable, invalid addAUTToken is called")
		return
	}
	autEntry := new(AUTEntry)
	view.entries[autNameKey].tokens[outpoint] = autEntry
	autEntry.amount = amount
	autEntry.blockHeight = blockHeight
	autEntry.packedFlags = atfModified
}

// connectTransaction updates the view by adding all new utxos created by the
// passed transaction and marking all utxos that the transactions spend as
// spent.  In addition, when the 'stxos' argument is not nil, it will be updated
// to append an entry for each spent txout.  An error will be returned if the
// view does not contain the required utxos.
func (view *AUTViewpoint) connectTransaction(tx *abeutil.TxAbe, blockHeight int32, sauts *[]SpentAUT) error {
	// Extract memo from tx memo
	// TODO Extract(tx.MsgTx().TxMemo)
	txHash := tx.Hash()
	autTx, ok := tx.AUTTransaction()
	if !ok {
		return nil
	}
	if autTx == nil {
		return aut.ErrInValidAUTTx
	}

	autNameKey := hex.EncodeToString(autTx.AUTName())
	if autTx.Type() != aut.Registration && view.entries[autNameKey] == nil {
		return errors.New("non-existing AUT")
	}
	switch autTransaction := autTx.(type) {
	case *aut.RegistrationTx:
		// 1. Register AUT
		// TODO check whether the name repeat
		tokens := map[aut.OutPoint]*AUTEntry{}
		rootCoinSet := map[aut.OutPoint]struct{}{}
		for i := 0; i < len(autTransaction.TxOuts); i++ {
			tokens[autTransaction.TxOuts[i]] = NewAUTEntry(autTransaction.Name, 0, blockHeight, true)
			rootCoinSet[autTransaction.TxOuts[i]] = struct{}{}
		}
		// 2. Record the AUT Root Coin
		view.entries[autNameKey] = &Entry{
			info: &aut.Info{
				Name:               autTransaction.Name,
				Memo:               autTransaction.Memo,
				UpdateThreshold:    autTransaction.IssuerUpdateThreshold,
				IssueThreshold:     autTransaction.IssueTokensThreshold,
				PlannedTotalAmount: autTransaction.PlannedTotalAmount,
				ExpireHeight:       autTransaction.ExpireHeight,
				Issuers:            autTransaction.Issuers,
				UnitName:           autTransaction.UnitName,
				MinUnitName:        autTransaction.MinUnitName,
				UnitScale:          autTransaction.UnitScale,
				MintedAmount:       0,
				RootCoinSet:        rootCoinSet,
			},
			tokens: tokens,
		}
		if sauts != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = UpdateAUTInfo{
				Before: nil,
				After:  view.entries[autNameKey].info,
				Height: blockHeight,
			}
			*sauts = append(*sauts, stxo)
		}

	case *aut.MintTx:
		var currentSauts = (SpentAUTTokens)(make([]SpentAUTToken, 0, len(autTransaction.TxIns)))
		// 1. Consume existed AUT Root Coin
		for i := 0; i < len(autTransaction.TxIns); i++ {
			if _, ok = view.entries[autNameKey].info.RootCoinSet[autTransaction.TxIns[i]]; !ok {
				err := errors.New("spend non-existing root coin")
				log.Debugf("transaction %s is spend invalid AUT root coin: %s", txHash, err)
				return err
			}
			if sauts != nil {
				// Populate the stxo details using the utxo entry.
				var stxo = SpentAUTToken{
					Amount:     0,
					Height:     blockHeight,
					IsRootCoin: true,
				}
				currentSauts = append(currentSauts, stxo)
			}
			delete(view.entries[autNameKey].tokens, autTransaction.TxIns[i])
			delete(view.entries[autNameKey].info.RootCoinSet, autTransaction.TxIns[i])
		}
		if sauts != nil {
			// Populate the stxo details using the utxo entry.
			*sauts = append(*sauts, &currentSauts)
		}
		// 2. Record new AUT Coin and value
		for i := 0; i < autTransaction.NumOuts(); i++ {
			// TODO check the value and summed value
			if autTransaction.TxoAUTValues[i] < view.entries[autNameKey].info.PlannedTotalAmount &&
				view.entries[autNameKey].info.MintedAmount+autTransaction.TxoAUTValues[i] < view.entries[autNameKey].info.MintedAmount ||
				view.entries[autNameKey].info.MintedAmount+autTransaction.TxoAUTValues[i] > view.entries[autNameKey].info.PlannedTotalAmount {
				// try to evil
				return errors.New("try to evil")
			}
			view.entries[autNameKey].info.MintedAmount = view.entries[autNameKey].info.MintedAmount + autTransaction.TxoAUTValues[i]
			view.entries[autNameKey].tokens[autTransaction.TxOuts[i]] = &AUTEntry{
				name:        autTransaction.Name,
				amount:      autTransaction.TxoAUTValues[i],
				blockHeight: blockHeight,
				packedFlags: atfModified,
			}
		}
	case *aut.ReRegistrationTx:
		// 1. Update AUT
		// TODO check the amount diff!!!
		if autTransaction.PlannedTotalAmount < view.entries[autNameKey].info.PlannedTotalAmount &&
			autTransaction.PlannedTotalAmount < view.entries[autNameKey].info.MintedAmount {
			return errors.New("try to evil")
		}
		originInfo := view.entries[autNameKey].info.Clone()
		// 2. Disable all AUT Root Coin
		view.entries[autNameKey].info.RootCoinSet = map[aut.OutPoint]struct{}{}
		for _, out := range autTx.Outs() {
			if _, ok := view.entries[autNameKey].info.RootCoinSet[out]; ok {
				return errors.New("unreachable code")
			}
			view.entries[autNameKey].info.RootCoinSet[out] = struct{}{}
		}
		// update Info
		view.entries[autNameKey].info.Memo = autTransaction.Memo
		view.entries[autNameKey].info.UpdateThreshold = autTransaction.IssuerUpdateThreshold
		view.entries[autNameKey].info.IssueThreshold = autTransaction.IssueTokensThreshold
		view.entries[autNameKey].info.PlannedTotalAmount = autTransaction.PlannedTotalAmount
		view.entries[autNameKey].info.ExpireHeight = autTransaction.ExpireHeight
		view.entries[autNameKey].info.Issuers = autTransaction.Issuers

		if sauts != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = UpdateAUTInfo{
				Before: originInfo,
				After:  view.entries[autNameKey].info,
				Height: blockHeight,
			}
			*sauts = append(*sauts, stxo)
		}

	case *aut.TransferTx:
		// TODO check the amount balance!!!
		var currentSauts = (SpentAUTTokens)(make([]SpentAUTToken, 0, len(autTransaction.TxIns)))
		// 1. Consume existed AUT Coin
		for i := 0; i < len(autTransaction.TxIns); i++ {
			if _, ok = view.entries[autNameKey].info.RootCoinSet[autTransaction.TxIns[i]]; !ok {
				err := errors.New("spend non-existing root coin")
				log.Debugf("transaction %s is spend invalid AUT root coin: %s", txHash, err)
				return err
			}
			if sauts != nil {
				// Populate the stxo details using the utxo entry.
				var stxo = SpentAUTToken{
					Amount:     0,
					Height:     blockHeight,
					IsRootCoin: true,
				}
				currentSauts = append(currentSauts, stxo)
			}
			delete(view.entries[autNameKey].tokens, autTransaction.TxIns[i])
		}
		if sauts != nil {
			// Populate the stxo details using the utxo entry.
			*sauts = append(*sauts, &currentSauts)
		}
		// 2. Record new AUT coin
		for i, outpoint := range autTransaction.TxOuts {
			// TODO check the value and summed value
			if autTransaction.TxoAUTValues[i] < view.entries[autNameKey].info.PlannedTotalAmount &&
				view.entries[autNameKey].info.MintedAmount+autTransaction.TxoAUTValues[i] < view.entries[autNameKey].info.MintedAmount {
				// try to evil
				return errors.New("try to evil")
			}
			view.entries[autNameKey].info.MintedAmount = view.entries[autNameKey].info.MintedAmount + autTransaction.TxoAUTValues[i]
			view.entries[autNameKey].tokens[outpoint] = &AUTEntry{
				name:        autTransaction.Name,
				amount:      autTransaction.TxoAUTValues[i],
				blockHeight: blockHeight,
				packedFlags: atfModified,
			}
		}

	case *aut.BurnTx:
		// TODO check the amount balance!!!
		var currentSauts = (SpentAUTTokens)(make([]SpentAUTToken, 0, len(autTransaction.TxIns)))
		// 1. Consume existed AUT Coin
		for i := 0; i < len(autTransaction.TxIns); i++ {
			if _, ok = view.entries[autNameKey].info.RootCoinSet[autTransaction.TxIns[i]]; !ok {
				err := errors.New("spend non-existing root coin")
				log.Debugf("transaction %s is spend invalid AUT root coin: %s", txHash, err)
				return err
			}
			if sauts != nil {
				// Populate the stxo details using the utxo entry.
				var stxo = SpentAUTToken{
					Amount:     0,
					Height:     blockHeight,
					IsRootCoin: true,
				}
				currentSauts = append(currentSauts, stxo)
			}
			delete(view.entries[autNameKey].tokens, autTransaction.TxIns[i])
		}
		if sauts != nil {
			// Populate the stxo details using the utxo entry.
			*sauts = append(*sauts, &currentSauts)
		}
	default:
		log.Debugf("unsupported type of AUT transaction %s", txHash)
		return errors.New("hit unexpected case")
	}
	return nil
}

// connectTransactions updates the view by adding all new utxos created by all
// of the transactions in the passed block, marking all utxos the transactions
// spend as spent, and setting the best hash for the view to the passed block.
// In addition, when the 'stxos' argument is not nil, it will be updated to
// append an entry for each spent txout.
func (view *AUTViewpoint) connectTransactions(block *abeutil.BlockAbe, stxos *[]SpentAUT) error {
	for _, tx := range block.Transactions() {
		err := view.connectTransaction(tx, block.Height(), stxos)
		if err != nil {
			return err
		}
	}

	// Update the best hash for view to include this block since all of its
	// transactions have been connected.
	view.SetBestHash(block.Hash())
	return nil
}

// disconnectTransactions updates the view by removing all of the transactions
// created by the passed block, restoring all utxos the transactions spent by
// using the provided spent txo information, and setting the best hash for the
// view to the block before the passed block.
func (view *AUTViewpoint) disconnectTransactions(db database.DB, block *abeutil.BlockAbe, sauts []SpentAUT) error {
	// Sanity check the correct number of sauts are provided.
	//if len(sauts) != countSpentOutputsAUT(block) {
	//	return AssertError("disconnectTransactions called with bad " +
	//		"spent transaction out information")
	//}

	// Loop backwards through all transactions so everything is unspent in
	// reverse order.  This is necessary since transactions later in a block
	// can spend from previous ones.
	stxoIdx := len(sauts) - 1
	transactions := block.Transactions()
	for txIdx := len(transactions) - 1; txIdx > -1; txIdx-- {
		tx, ok := transactions[txIdx].AUTTransaction()
		if !ok {
			continue
		}
		if tx == nil {
			log.Errorf("a invalid transaction enter chain block!!! PLS report")
		}

		// All entries will need to potentially be marked as a coinbase.
		var packedFlags autFlags

		if tx.Type() == aut.Registration || tx.Type() == aut.ReRegistration {
			packedFlags |= atfRootCoin
		}
		autNameKey := hex.EncodeToString(tx.AUTName())

		// Mark all of the spendable outputs originally created by the
		// transaction as spent.  It is instructive to note that while
		// the outputs aren't actually being spent here, rather they no
		// longer exist, since a pruned utxo set is used, there is no
		// practical difference between a utxo that does not exist and
		// one that has been spent.
		//
		// When the utxo does not already exist in the view, add an
		// entry for it and then mark it spent.  This is done because
		// the code relies on its existence in the view in order to
		// signal modifications have happened.
		for idx, outpoint := range tx.Outs() {
			autInfo := view.entries[autNameKey]
			if autInfo == nil {
				panic("Err")
			}
			autInfo.tokens[outpoint] = &AUTEntry{
				amount:      tx.Values(uint8(idx)),
				blockHeight: block.Height(),
				packedFlags: packedFlags,
			}

			autInfo.tokens[outpoint].Spend()
		}

		// Loop backwards through all of the transaction inputs (except
		// for the coinbase which has no inputs) and unspend the
		// referenced txos.  This is necessary to match the order of the
		// spent txout entries.

		stxo := sauts[stxoIdx]
		switch tokens := stxo.(type) {
		case *SpentAUTTokens:
			txIns := tx.Ins()
			for i := 0; i < len(*tokens); i++ {
				// Ensure the spent txout index is decremented to stay
				// in sync with the transaction input.
				// When there is not already an entry for the referenced
				// output in the view, it means it was previously spent,
				// so create a new utxo entry in order to resurrect it.
				originOut := txIns[i]
				entry := view.entries[autNameKey].tokens[originOut]
				if entry == nil {
					entry = new(AUTEntry)
					view.entries[autNameKey].tokens[originOut] = entry
				}

				// Restore the utxo using the stxo data from the spend
				// journal and mark it as modified.
				entry.amount = (*tokens)[i].Amount
				entry.blockHeight = (*tokens)[i].Height
				entry.packedFlags = atfModified
				if (*tokens)[i].IsRootCoin {
					entry.packedFlags |= atfRootCoin
				}
			}
		case *UpdateAUTInfo:
			panic("implement me")
		default:

		}

	}

	// Update the best hash for view to the previous block since all of the
	// transactions for the current block have been disconnected.
	view.SetBestHash(&block.MsgBlock().Header.PrevBlock)
	return nil
}

// Entries returns the underlying map that stores of all the utxo entries.
func (view *AUTViewpoint) Entries() map[string]*Entry {
	return view.entries
}

func (view *AUTViewpoint) AUTEntries(autNameKey string) map[aut.OutPoint]*AUTEntry {
	return view.entries[autNameKey].tokens
}

func (view *AUTViewpoint) AUTInfo(autNameKey string) *aut.Info {
	return view.entries[autNameKey].info
}

func (view *AUTViewpoint) SetEntries(entries map[string]*Entry) {
	view.entries = entries
}

// commit prunes all entries marked modified that are now fully spent and marks
// all entries as unmodified.
func (view *AUTViewpoint) commit() {
	for _, autEntry := range view.entries {
		for outpoint, entry := range autEntry.tokens {
			if entry == nil || (entry.isModified() && entry.IsSpent()) {
				delete(autEntry.tokens, outpoint)
				continue
			}

			entry.packedFlags ^= atfModified
		}

	}
}

// fetchUtxosMain fetches unspent transaction output data about the provided
// set of outpoints from the point of view of the end of the main chain at the
// time of the call.
//
// Upon completion of this function, the view will contain an entry for each
// requested outpoint.  Spent outputs, or those which otherwise don't exist,
// will result in a nil entry in the view.
func (view *AUTViewpoint) fetchAUTMain(db database.DB, outpoints map[aut.OutPoint]struct{}, autNameKey []byte) error {
	// Nothing to do if there are no requested outputs.
	if len(outpoints) == 0 && len(autNameKey) == 0 {
		return nil
	}

	// Load the requested set of unspent transaction outputs from the point
	// of view of the end of the main chain.
	//
	// NOTE: Missing entries are not considered an error here and instead
	// will result in nil entries in the view.  This is intentionally done
	// so other code can use the presence of an entry in the store as a way
	// to unnecessarily avoid attempting to reload it from the database.
	return db.View(func(dbTx database.Tx) error {
		info, err := dbFetchAUTInfo(dbTx, autNameKey)
		if err != nil {
			return err
		}

		tokens := make(map[aut.OutPoint]*AUTEntry, len(outpoints))
		for outpoint := range outpoints {
			entry, err := dbFetchAUTEntry(dbTx, outpoint)
			if err != nil {
				return err
			}

			if !bytes.Equal(entry.name, info.Name) {
				return errors.New("unmatched AUT name and info")
			}

			tokens[outpoint] = entry
		}
		view.entries[hex.EncodeToString(autNameKey)] = &Entry{
			info:   info,
			tokens: tokens,
		}

		return nil
	})
}

// fetchInputUtxos loads the unspent transaction outputs for the inputs
// referenced by the transactions in the given block into the view from the
// database as needed.  In particular, referenced entries that are earlier in
// the block are added to the view and entries that are already in the view are
// not modified.
func (view *AUTViewpoint) fetchInputAUTUtxos(db database.DB, block *abeutil.BlockAbe) error {
	// Loop through all of the transaction inputs (except for the coinbase
	// which has no inputs) collecting them into sets of what is needed and
	// what is already known (in-flight).
	neededSet := make(map[aut.OutPoint]struct{}) // it is not in the same block
	for _, tx := range block.Transactions() {
		isCB, err := tx.IsCoinBase()
		if err != nil {
			return err
		}
		if isCB {
			continue
		}
		autTx, ok := tx.AUTTransaction()
		if !ok {
			continue
		}
		if autTx == nil {
			return aut.ErrInValidAUTTx
		}
		autNameKey := hex.EncodeToString(autTx.AUTName())
		for _, txIn := range autTx.Ins() {
			autEntry := view.LookupEntry(autNameKey, txIn)
			if autEntry == nil {
				neededSet[txIn] = struct{}{}
			}
		}
		err = view.fetchAUTMain(db, neededSet, autTx.AUTName())
		if err != nil {
			return err
		}
	}

	// Request the input utxos from the database.
	return nil
}

// NewUtxoViewpoint returns a new empty unspent transaction output view.
func NewAUTViewpoint() *AUTViewpoint {
	return &AUTViewpoint{
		entries: make(map[string]*Entry),
	}
}

// FetchUtxoView loads unspent transaction outputs for the inputs referenced by
// the passed transaction from the point of view of the end of the main chain.
// It also attempts to fetch the utxos for the outputs of the transaction itself
// so the returned view can be examined for duplicate transactions.
//
// This function is safe for concurrent access however the returned view is NOT.
func (b *BlockChain) FetchAUTView(originTx *abeutil.TxAbe) (*AUTViewpoint, error) {
	// Create a set of needed outputs based on those referenced by the
	// inputs of the passed transaction and the outputs of the transaction
	// itself.

	autTx, ok := originTx.AUTTransaction()
	if !ok {
		return nil, nil
	}
	if autTx == nil {
		return nil, aut.ErrInValidAUTTx
	}
	view := NewAUTViewpoint()
	neededSet := make(map[aut.OutPoint]struct{})
	switch autTx.Type() {
	case aut.Registration:
		return view, nil
	case aut.Mint:
		// fetch info
	case aut.ReRegistration:
		// fetch info
	case aut.Transfer:
		fallthrough
	case aut.Burn:
		// fetch input
		for _, outpoint := range autTx.Ins() {
			neededSet[outpoint] = struct{}{}
		}
	default:
		log.Errorf("unreachable")
		return nil, errors.New("unreachable")
	}

	// no output need to be fetched
	// 	for _, outpoint := range autTx.Outs() {
	//		neededSet[outpoint] = struct{}{}
	//	}

	// Request the utxos from the point of view of the end of the main
	// chain.
	b.chainLock.RLock()
	err := view.fetchAUTMain(b.db, neededSet, autTx.AUTName())
	b.chainLock.RUnlock()
	return view, err
}

// FetchUtxoEntry loads and returns the requested unspent transaction output
// from the point of view of the end of the main chain.
//
// NOTE: Requesting an output for which there is no data will NOT return an
// error.  Instead both the entry and the error will be nil.  This is done to
// allow pruning of spent transaction outputs.  In practice this means the
// caller must check if the returned entry is nil before invoking methods on it.
//
// This function is safe for concurrent access however the returned entry (if
// any) is NOT.
func (b *BlockChain) FetchAUTEntry(outpoint aut.OutPoint) (*AUTEntry, error) {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	var entry *AUTEntry
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		entry, err = dbFetchAUTEntry(dbTx, outpoint)
		return err
	})
	if err != nil {
		return nil, err
	}

	return entry, nil
}

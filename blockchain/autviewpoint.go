package blockchain

import (
	"encoding/hex"
	"errors"
	"fmt"
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
type AUTEntry struct {
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.
	name        []byte
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
		name:        entry.name,
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
		name:        name,
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
	entries  map[aut.OutPoint]*AUTEntry
	infos    map[string]*aut.Info
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
func (view *AUTViewpoint) LookupEntry(outpoint aut.OutPoint) *AUTEntry {
	return view.entries[outpoint]
}

func (view *AUTViewpoint) LookupInfo(autNameKey string) *aut.Info {
	return view.infos[autNameKey]
}

// addTxOut adds the specified output to the view if it is not provably
// unspendable.  When the view already has an entry for the output, it will be
// marked unspent.  All fields will be updated for existing entries since it's
// possible it has changed during a reorg.
func (view *AUTViewpoint) addAUTCoin(outpoint aut.OutPoint, amount uint64, blockHeight int32) {
	// if the tx is not existing in the utxoentry, create a new one. otherwise update the height of view
	// Update existing entries.  All fields are updated because it's
	// possible (although extremely unlikely) that the existing entry is
	// being replaced by a different transaction with the same hash.  This
	// is allowed so long as the previous transaction is fully spent.
	entry := view.LookupEntry(outpoint)
	if entry == nil {
		entry = new(AUTEntry)
		view.entries[outpoint] = entry
	}

	entry.amount = amount
	entry.blockHeight = blockHeight
	entry.packedFlags = atfModified
}

// connectTransaction updates the view by adding all new utxos created by the
// passed transaction and marking all utxos that the transactions spend as
// spent.  In addition, when the 'stxos' argument is not nil, it will be updated
// to append an entry for each spent txout.  An error will be returned if the
// view does not contain the required utxos.
func (view *AUTViewpoint) connectTransaction(tx *abeutil.TxAbe, blockHeight int32, sauts *[]SpentAUT /* TODO do we need this?*/) error {
	// Extract memo from tx memo
	// TODO Extract(tx.MsgTx().TxMemo)
	txHash := tx.Hash()
	autTx, err := aut.DeserializeFromTx(tx.MsgTx())
	if err != nil {
		log.Debugf("transaction %s is not a valid AUT transaction: %s", txHash, err)
		return err
	}
	// TODO Extract AUT Name, transaction type from tx.Memo
	autName := autTx.AUTName()
	if len(autName) == 0 {
		log.Debugf("transaction %s is not a valid AUT transaction: %s", txHash, err)
		return err
	}
	autNameKey := hex.EncodeToString(autName)
	//check the amount in transaction
	for i := 0; i < autTx.NumOuts(); i++ {
		// TODO extract value from tx.MsgTx().TxOuts[token.Index].TxoScript
		value := 0
		if value != 1 {
			return errors.New("wrong value")
		}
	}
	if autTx.Type() != aut.Registration && view.infos[autNameKey] == nil {
		return errors.New("non-existing AUT")
	}
	switch autTransaction := autTx.(type) {
	case *aut.RegistrationTx:
		// 1. Register AUT
		// TODO check whether the name repeat
		view.infos[autNameKey] = &aut.Info{
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
		}
		// 2. Record the AUT Root Coin
		for _, token := range autTransaction.TxOuts {
			view.infos[autNameKey].RootCoinSet[token] = struct{}{}
		}

	case *aut.MintTx:
		// 1. Consume existed AUT Root Coin
		for i := 0; i < len(autTransaction.TxIns); i++ {
			if _, ok := view.infos[autNameKey].RootCoinSet[autTransaction.TxIns[i]]; !ok {
				err = errors.New("spend non-existing root coin")
				log.Debugf("transaction %s is spend invalid AUT root coin: %s", txHash, err)
				return err
			}
			if sauts != nil {
				// Populate the stxo details using the utxo entry.
				var stxo = SpentAUT{
					Amount:     0,
					Height:     0,
					IsRootCoin: true,
				}
				*sauts = append(*sauts, stxo)
			}
			delete(view.infos[autNameKey].RootCoinSet, autTransaction.TxIns[i])
		}
		// 2. Record new AUT Coin and value
		for i := 0; i < autTransaction.NumOuts(); i++ {
			// TODO check the value and summed value
			if autTransaction.TxoAUTValues[i] < view.infos[autNameKey].PlannedTotalAmount &&
				view.infos[autNameKey].MintedAmount+autTransaction.TxoAUTValues[i] < view.infos[autNameKey].MintedAmount ||
				view.infos[autNameKey].MintedAmount+autTransaction.TxoAUTValues[i] > view.infos[autNameKey].PlannedTotalAmount {
				// try to evil
				return errors.New("try to evil")
			}
			view.infos[autNameKey].MintedAmount = view.infos[autNameKey].MintedAmount + autTransaction.TxoAUTValues[i]
			view.addAUTCoin(autTransaction.TxOuts[i], autTransaction.TxoAUTValues[i], blockHeight)
		}
	case *aut.ReRegistrationTx:
		// 1. Update AUT
		// TODO check the amount diff!!!
		if autTransaction.PlannedTotalAmount < view.infos[autNameKey].PlannedTotalAmount && autTransaction.PlannedTotalAmount < view.infos[autNameKey].MintedAmount {
			return errors.New("try to evil")
		}
		// 2. Disable all AUT Root Coin
		for range autTx.Ins() {
			if sauts != nil {
				// Populate the stxo details using the utxo entry.
				var stxo = SpentAUT{
					Amount:     0,
					Height:     0,
					IsRootCoin: true,
				}
				*sauts = append(*sauts, stxo)
			}
		}
		view.infos[autNameKey].RootCoinSet = map[aut.OutPoint]struct{}{}
		for _, out := range autTx.Outs() {
			if _, ok := view.infos[autNameKey].RootCoinSet[out]; ok {
				return errors.New("unreachable code")
			}
			view.infos[autNameKey].RootCoinSet[out] = struct{}{}
		}

	case *aut.TransferTx:
		// TODO check the amount balance!!!

		// 1. Consume existed AUT Coin
		for i := 0; i < len(autTransaction.TxIns); i++ {
			entry, ok := view.entries[autTransaction.TxIns[i]]
			if !ok {
				return AssertError(fmt.Sprintf("AUT view missing input %v",
					autTransaction.TxIns[i]))
			}
			if sauts != nil {
				// Populate the stxo details using the utxo entry.
				var stxo = SpentAUT{
					Amount:     entry.Amount(),
					Height:     entry.BlockHeight(),
					IsRootCoin: entry.IsRootCoin(),
				}
				*sauts = append(*sauts, stxo)
			}
		}
		// 2. Record new AUT coin
		for i, out := range autTx.Outs() {
			// TODO check the value and summed value
			if autTransaction.TxoAUTValues[i] < view.infos[autNameKey].PlannedTotalAmount &&
				view.infos[autNameKey].MintedAmount+autTransaction.TxoAUTValues[i] < view.infos[autNameKey].MintedAmount {
				// try to evil
				return errors.New("try to evil")
			}
			view.infos[autNameKey].MintedAmount = view.infos[autNameKey].MintedAmount + autTransaction.TxoAUTValues[i]
			view.addAUTCoin(out, autTransaction.TxoAUTValues[i], blockHeight)
		}

	case *aut.BurnTx:
		// 1. Consume existed AUT Coin
		for i := 0; i < len(autTransaction.TxIns); i++ {
			entry, ok := view.entries[autTransaction.TxIns[i]]
			if !ok {
				return AssertError(fmt.Sprintf("AUT view missing input %v",
					autTransaction.TxIns[i]))
			}
			if sauts != nil {
				// Populate the stxo details using the utxo entry.
				var stxo = SpentAUT{
					Amount:     entry.Amount(),
					Height:     entry.BlockHeight(),
					IsRootCoin: entry.IsRootCoin(),
				}
				*sauts = append(*sauts, stxo)
			}
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
	if len(sauts) != countSpentOutputsAUT(block) {
		return AssertError("disconnectTransactions called with bad " +
			"spent transaction out information")
	}

	// Loop backwards through all transactions so everything is unspent in
	// reverse order.  This is necessary since transactions later in a block
	// can spend from previous ones.
	stxoIdx := len(sauts) - 1
	transactions := block.AUTTransactions()
	for txIdx := len(transactions) - 1; txIdx > -1; txIdx-- {
		tx := transactions[txIdx]

		// All entries will need to potentially be marked as a coinbase.
		var packedFlags autFlags

		if tx.Type() == aut.Registration {
			packedFlags |= atfRootCoin
		}

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
			entry := view.entries[outpoint]
			if entry == nil {
				entry = &AUTEntry{
					amount:      tx.Values(uint8(idx)),
					blockHeight: block.Height(),
					packedFlags: packedFlags,
				}

				view.entries[outpoint] = entry
			}

			entry.Spend()
		}

		// Loop backwards through all of the transaction inputs (except
		// for the coinbase which has no inputs) and unspend the
		// referenced txos.  This is necessary to match the order of the
		// spent txout entries.

		txIns := tx.Ins()
		for txInIdx := tx.NumIns() - 1; txInIdx > -1; txInIdx-- {
			// Ensure the spent txout index is decremented to stay
			// in sync with the transaction input.
			stxo := sauts[stxoIdx]
			stxoIdx--

			// When there is not already an entry for the referenced
			// output in the view, it means it was previously spent,
			// so create a new utxo entry in order to resurrect it.
			originOut := txIns[txInIdx]
			entry := view.entries[originOut]
			if entry == nil {
				entry = new(AUTEntry)
				view.entries[originOut] = entry
			}

			// Restore the utxo using the stxo data from the spend
			// journal and mark it as modified.
			entry.amount = stxo.Amount
			entry.blockHeight = stxo.Height
			entry.packedFlags = atfModified
			if stxo.IsRootCoin {
				entry.packedFlags |= atfRootCoin
			}
		}
	}

	// Update the best hash for view to the previous block since all of the
	// transactions for the current block have been disconnected.
	view.SetBestHash(&block.MsgBlock().Header.PrevBlock)
	return nil
}

// RemoveEntry removes the given transaction output from the current state of
// the view.  It will have no effect if the passed output does not exist in the
// view.
func (view *AUTViewpoint) RemoveEntry(outpoint aut.OutPoint) {
	delete(view.entries, outpoint)
}

// Entries returns the underlying map that stores of all the utxo entries.
func (view *AUTViewpoint) Entries() map[aut.OutPoint]*AUTEntry {
	return view.entries
}
func (view *AUTViewpoint) Infos() map[string]*aut.Info {
	return view.infos
}
func (view *AUTViewpoint) SetEntries(entries map[aut.OutPoint]*AUTEntry) {
	view.entries = entries

}
func (view *AUTViewpoint) SetInfos(infos map[string]*aut.Info) {
	view.infos = infos
}

// commit prunes all entries marked modified that are now fully spent and marks
// all entries as unmodified.
func (view *AUTViewpoint) commit() {
	for outpoint, entry := range view.entries {
		if entry == nil || (entry.isModified() && entry.IsSpent()) {
			delete(view.entries, outpoint)
			continue
		}

		entry.packedFlags ^= atfModified
	}
}

// fetchUtxosMain fetches unspent transaction output data about the provided
// set of outpoints from the point of view of the end of the main chain at the
// time of the call.
//
// Upon completion of this function, the view will contain an entry for each
// requested outpoint.  Spent outputs, or those which otherwise don't exist,
// will result in a nil entry in the view.
func (view *AUTViewpoint) fetchAUTMain(db database.DB, outpoints map[aut.OutPoint]struct{}, autNameKeys [][]byte) error {
	// Nothing to do if there are no requested outputs.
	if len(outpoints) == 0 {
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
		for outpoint := range outpoints {
			entry, err := dbFetchAUTEntry(dbTx, outpoint)
			if err != nil {
				return err
			}

			view.entries[outpoint] = entry
		}

		for _, key := range autNameKeys {
			info, err := dbFetchAUTInfo(dbTx, key)
			if err != nil {
				return err
			}

			view.infos[hex.EncodeToString(key)] = info
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
	neededSet := make(map[aut.OutPoint]struct{})             // it is not in the same block
	autNames := make([][]byte, 0, len(block.Transactions())) // it is not in the same block
	for _, tx := range block.Transactions() {
		autTx, err := aut.DeserializeFromTx(tx.MsgTx())
		if err != nil {
			continue
		}
		for _, txIn := range autTx.Ins() {
			if _, ok := view.entries[txIn]; !ok {
				neededSet[txIn] = struct{}{}
			}
		}
	}

	// Request the input utxos from the database.
	return view.fetchAUTMain(db, neededSet, autNames)
}

// NewUtxoViewpoint returns a new empty unspent transaction output view.
func NewAUTViewpoint() *AUTViewpoint {
	return &AUTViewpoint{
		entries: make(map[aut.OutPoint]*AUTEntry),
		infos:   make(map[string]*aut.Info),
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
	autTx, err := aut.DeserializeFromTx(originTx.MsgTx())
	if err != nil {
		return nil, err
	}
	neededSet := make(map[aut.OutPoint]struct{})
	for _, outpoint := range autTx.Ins() {
		neededSet[outpoint] = struct{}{}
	}

	// no output need to be fetched
	// 	for _, outpoint := range autTx.Outs() {
	//		neededSet[outpoint] = struct{}{}
	//	}

	// Request the utxos from the point of view of the end of the main
	// chain.
	view := NewAUTViewpoint()
	b.chainLock.RLock()
	err = view.fetchAUTMain(b.db, neededSet, [][]byte{autTx.AUTName()})
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

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

// AUTCoin houses details about an AUT Transaction output in a AUT
// view such as whether or not it was contained in a AUT Registration Transaction, the height of
// the block that contains the tx, whether or not it is spent, its public key
// script, and how much it pays.
// todo: AutEntry?
type AUTEntry struct {
	info  *aut.Info
	coins map[aut.OutPoint]*AUTCoin
}

func NewAUTEntry(info *aut.Info, coins map[aut.OutPoint]*AUTCoin) *AUTEntry {
	return &AUTEntry{info: info, coins: coins}
}

// todo: AddCion
func (e *AUTEntry) Add(outpiont aut.OutPoint, entry *AUTCoin) {
	e.coins[outpiont] = entry
}

func (e *AUTEntry) Info() *aut.Info {
	return e.info
}
func (e *AUTEntry) AUTCoins() map[aut.OutPoint]*AUTCoin {
	return e.coins
}

func (e *AUTEntry) LookupCoin(point aut.OutPoint) *AUTCoin {
	return e.coins[point]
}

type AUTCoin struct {
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
func (entry *AUTCoin) isModified() bool {
	return entry.packedFlags&atfModified == atfModified
}

// IsRootCoin returns whether or not the output was contained in a coinbase
// transaction.
func (entry *AUTCoin) IsRootCoin() bool {
	return entry.packedFlags&atfRootCoin == atfRootCoin
}

// IsSpent returns whether or not the output has been spent based upon the
// current state of the unspent transaction output view it was obtained from.
func (entry *AUTCoin) IsSpent() bool {
	return entry.packedFlags&atfSpent == atfSpent
}

// BlockHeight returns the height of the block containing the output.
func (entry *AUTCoin) BlockHeight() int32 {
	return entry.blockHeight
}

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
func (entry *AUTCoin) Spend() {
	// Nothing to do if the output is already spent.
	if entry.IsSpent() {
		return
	}

	// Mark the output as spent and modified.
	entry.packedFlags |= atfSpent | atfModified
}

// Amount returns the amount of the output.
func (entry *AUTCoin) Amount() uint64 {
	return entry.amount
}

// Clone returns a shallow copy of the utxo entry.
func (entry *AUTCoin) Clone() *AUTCoin {
	if entry == nil {
		return nil
	}

	return &AUTCoin{
		amount:      entry.amount,
		blockHeight: entry.blockHeight,
		packedFlags: entry.packedFlags,
	}
}

// todo: function name
// NewAUTCoin returns a new AUTCoin built from the arguments.
func NewAUTCoin(
	name []byte, amount uint64, blockHeight int32, isRootCoin bool) *AUTCoin {
	var flag autFlags = atfModified
	if isRootCoin {
		flag |= atfRootCoin
	}

	return &AUTCoin{
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
//
//	todo: using AutName as key to store AutEntries.
type AUTViewpoint struct {
	entries  map[string]*AUTEntry
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
// todo: function name LookupAutCoin
func (view *AUTViewpoint) LookupEntry(autNameKey string, outpoint aut.OutPoint) *AUTCoin {
	if view.entries == nil {
		return nil
	}
	entry, ok := view.entries[autNameKey]
	if !ok {
		return nil
	}
	return entry.coins[outpoint]
}

// todo: function name LookupAutDesc
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
	autEntry := new(AUTCoin)
	view.entries[autNameKey].coins[outpoint] = autEntry
	autEntry.amount = amount
	autEntry.blockHeight = blockHeight
	autEntry.packedFlags = atfModified
}

// connectTransaction updates the view by adding all new utxos created by the
// passed transaction and marking all utxos that the transactions spend as
// spent.  In addition, when the 'stxos' argument is not nil, it will be updated
// to append an entry for each spent txout.  An error will be returned if the
// view does not contain the required utxos.
// TODO Check consistence with mining.spendTransactionAbe
func (view *AUTViewpoint) connectTransaction(tx *abeutil.TxAbe, blockHeight int32, sauts *[]SpentAUT) error {
	autTx, isAUTTx := tx.AUTTransaction()
	if !isAUTTx {
		return nil
	}
	if autTx == nil {
		return aut.ErrInValidAUTTx
	}

	autNameKey := hex.EncodeToString(autTx.AUTName())
	entry, exist := view.entries[autNameKey]
	if autTx.Type() == aut.Registration {
		if exist {
			return errors.New("an non-registration AUT transaction try to register a existing AUT name ")
		}
	} else {
		if !exist {
			return errors.New("an non-registration AUT transaction try to operate on a non-existing aut")
		}
	}
	switch autTransaction := autTx.(type) {
	case *aut.RegistrationTx:
		rootCoinSet := map[aut.OutPoint]struct{}{}
		for i := 0; i < len(autTransaction.TxOuts); i++ {
			rootCoinSet[autTransaction.TxOuts[i]] = struct{}{}
		}
		// register the AUT entry
		entry = NewAUTEntry(
			&aut.Info{
				AutName:            autTransaction.AutName,
				AutMemo:            autTransaction.AutMemo,
				UpdateThreshold:    autTransaction.IssuerUpdateThreshold,
				IssueThreshold:     autTransaction.IssueTokensThreshold,
				PlannedTotalAmount: autTransaction.PlannedTotalAmount,
				ExpireHeight:       autTransaction.ExpireHeight,
				IssuerTokens:       autTransaction.IssuerTokens,
				UnitName:           autTransaction.UnitName,
				MinUnitName:        autTransaction.MinUnitName,
				UnitScale:          autTransaction.UnitScale,
				MintedAmount:       0,
				RootCoinSet:        rootCoinSet,
			},
			nil,
		)
		view.entries[autNameKey] = entry

		// TODO AUT actually do need to use saut to record
		if sauts != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = &UpdateAUTInfo{
				Before: nil,
				After:  entry.info,
				Height: blockHeight,
			}
			*sauts = append(*sauts, stxo)
		}

	case *aut.MintTx:
		info := entry.Info()
		var currentSauts = (SpentAUTTokens)(make([]SpentAUTToken, 0, len(autTransaction.TxIns)))
		for i := 0; i < len(autTransaction.TxIns); i++ {
			if _, ok := info.RootCoinSet[autTransaction.TxIns[i]]; !ok {
				return errors.New("an AUT transaction with non-existing/spent root coin")
			}
			delete(info.RootCoinSet, autTransaction.TxIns[i])
			if sauts != nil {
				// Populate the stxo details using the utxo entry.
				var stxo = SpentAUTToken{
					Amount:     0,
					Height:     blockHeight,
					IsRootCoin: true,
				}
				currentSauts = append(currentSauts, stxo)
			}
		}
		// TODO AUT actually do need to use saut to record
		if sauts != nil {
			// Populate the stxo details using the utxo entry.
			*sauts = append(*sauts, &currentSauts)
		}

		// value overflow? exceed?
		wouldMintedAmount := uint64(0)
		for i := 0; i < len(autTransaction.TxoAUTValues); i++ {
			if wouldMintedAmount+autTransaction.TxoAUTValues[i] < wouldMintedAmount || // overflow
				wouldMintedAmount+autTransaction.TxoAUTValues[i] < autTransaction.TxoAUTValues[i] || // overflow
				wouldMintedAmount+autTransaction.TxoAUTValues[i] > info.PlannedTotalAmount {
				return errors.New("an AUT mint transaction try to mint amount exceed planned")
			}
			wouldMintedAmount += autTransaction.TxoAUTValues[i]
			entry.Add(autTransaction.TxOuts[i], NewAUTCoin(autTransaction.Name, autTransaction.TxoAUTValues[i], blockHeight, false))
		}
		if info.MintedAmount+wouldMintedAmount < info.MintedAmount {
			return errors.New("an AUT mint transaction try to mint amount exceed planned")
		}
		info.MintedAmount += wouldMintedAmount

	case *aut.ReRegistrationTx:
		// input exist? double spent?
		info := entry.info
		originInfo := view.entries[autNameKey].info.Clone()
		for i := 0; i < len(autTransaction.TxIns); i++ {
			if _, ok := info.RootCoinSet[autTransaction.TxIns[i]]; !ok {
				return errors.New("an AUT transaction with non-existing/spent root coin")
			}
			delete(info.RootCoinSet, autTransaction.TxIns[i])
		}

		// update aut info
		info.AutMemo = autTransaction.Memo
		info.UpdateThreshold = autTransaction.IssuerUpdateThreshold
		info.IssueThreshold = autTransaction.IssueTokensThreshold
		info.PlannedTotalAmount = autTransaction.PlannedTotalAmount
		info.ExpireHeight = autTransaction.ExpireHeight
		info.IssuerTokens = autTransaction.IssuerTokens
		info.UnitScale = autTransaction.UnitScale
		// remove previous root coins
		info.RootCoinSet = make(map[aut.OutPoint]struct{}, len(autTransaction.TxOuts))
		for i := 0; i < len(autTransaction.TxOuts); i++ {
			info.RootCoinSet[autTransaction.TxOuts[i]] = struct{}{}
		}
		view.entries[autNameKey].info = info

		if sauts != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = &UpdateAUTInfo{
				Before:           originInfo,
				After:            view.entries[autNameKey].info,
				Height:           blockHeight,
				IsReRegistration: true,
			}
			*sauts = append(*sauts, stxo)
		}

	case *aut.TransferTx:
		// check the sanity of transfer transaction
		// balance between inputs and outputs
		info := entry.Info()
		var currentSauts = (SpentAUTTokens)(make([]SpentAUTToken, 0, len(autTransaction.TxIns)))
		totalInputValue := uint64(0)
		for i := 0; i < len(autTransaction.TxIns); i++ {
			token := entry.LookupCoin(autTransaction.TxIns[i])
			if token == nil {
				return errors.New("an AUT transfer transaction try to spend non-existing/burn token")
			}
			if token.IsSpent() {
				return errors.New("an AUT transfer transaction try to spend spent token")
			}
			token.Spend()
			if sauts != nil {
				// Populate the stxo details using the utxo entry.
				var stxo = SpentAUTToken{
					Amount:     token.Amount(),
					Height:     blockHeight,
					IsRootCoin: false,
				}
				currentSauts = append(currentSauts, stxo)
			}
		}
		if sauts != nil {
			// Populate the stxo details using the utxo entry.
			*sauts = append(*sauts, &currentSauts)
		}

		totalOutValue := uint64(0)
		for i := 0; i < len(autTransaction.TxoAUTValues); i++ {
			if totalOutValue+autTransaction.TxoAUTValues[i] < totalOutValue || // overflow
				totalOutValue+autTransaction.TxoAUTValues[i] < autTransaction.TxoAUTValues[i] || // overflow
				totalOutValue+autTransaction.TxoAUTValues[i] > info.MintedAmount ||
				totalOutValue+autTransaction.TxoAUTValues[i] > info.PlannedTotalAmount {
				return errors.New("an AUT transfer transaction try to overflow amount")
			}
			entry.Add(autTransaction.TxOuts[i], NewAUTCoin(autTransaction.Name, autTransaction.TxoAUTValues[i], 0, false))
		}
		if totalInputValue != totalOutValue {
			return errors.New("an AUT transfer transaction try to break-balance amount")
		}

	case *aut.BurnTx:
		var currentSauts = (SpentAUTTokens)(make([]SpentAUTToken, 0, len(autTransaction.TxIns)))
		burnedValues := uint64(0)
		for i := 0; i < len(autTransaction.TxIns); i++ {
			token := entry.LookupCoin(autTransaction.TxIns[i])
			if token == nil {
				return errors.New("an AUT transfer transaction try to spend non-existing/burn token")
			}
			if token.IsSpent() {
				return errors.New("an AUT transfer transaction try to spend spent token")
			}
			if burnedValues+token.Amount() <= burnedValues {
				return errors.New("an AUT transfer transaction try to spend overflow token")
			}
			token.Spend()
			if sauts != nil {
				// Populate the stxo details using the utxo entry.
				var stxo = SpentAUTToken{
					Amount: token.Amount(),
					Height: blockHeight,
				}
				currentSauts = append(currentSauts, stxo)
			}
			burnedValues += token.Amount()
		}
		if sauts != nil {
			// Populate the stxo details using the utxo entry.
			*sauts = append(*sauts, &currentSauts)
		}

	default:
		return errors.New("unreachable")
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
func (view *AUTViewpoint) disconnectTransactions(db database.DB, block *abeutil.BlockAbe,
	sauts []SpentAUT, infoToDel map[string]struct{}) error {
	// Sanity check the correct number of sauts are provided.
	//if len(sauts) != countSpentOutputsAUT(block) {
	//	return AssertError("disconnectTransactions called with bad " +
	//		"spent transaction out information")
	//}

	// Loop backwards through all autTransactions so everything is unspent in
	// reverse order.  This is necessary since autTransactions later in a block
	// can spend from previous ones.
	stxoIdx := len(sauts) - 1
	autTransactions := block.AUTTransactions()
	for txIdx := len(autTransactions) - 1; txIdx > -1; txIdx-- {
		autNameKey := hex.EncodeToString(autTransactions[txIdx].AUTName())
		entry := view.entries[autNameKey]
		switch autTransaction := autTransactions[txIdx].(type) {
		case *aut.RegistrationTx:
			infoToDel[autNameKey] = struct{}{}
			stxoIdx -= 1
		case *aut.MintTx:
			// Restore inputs
			for _, in := range autTransaction.TxIns {
				entry.info.RootCoinSet[in] = struct{}{}
			}
			// Remove outputs
			totalMintedAmount := uint64(0)
			for i := 0; i < len(autTransaction.TxoAUTValues); i++ {
				if totalMintedAmount+autTransaction.TxoAUTValues[i] < totalMintedAmount || // overflow
					totalMintedAmount+autTransaction.TxoAUTValues[i] < autTransaction.TxoAUTValues[i] || // overflow
					totalMintedAmount+autTransaction.TxoAUTValues[i] > entry.info.PlannedTotalAmount {
					return errors.New("an AUT mint transaction try to mint amount exceed planned")
				}
				totalMintedAmount += autTransaction.TxoAUTValues[i]
				entry.coins[autTransaction.TxOuts[i]].Spend()
			}
			entry.info.MintedAmount -= totalMintedAmount
			stxoIdx -= 1

		case *aut.ReRegistrationTx:
			updatedAUTInfo := sauts[stxoIdx].(*UpdateAUTInfo)
			entry.info = updatedAUTInfo.Before
			stxoIdx -= 1
		case *aut.TransferTx:
			consumedAutCoins := sauts[stxoIdx].(*SpentAUTTokens)
			for i, coin := range *consumedAutCoins {
				entry.coins[autTransaction.TxIns[i]] = NewAUTCoin(autTransactions[txIdx].AUTName(), coin.Amount, coin.Height, false)
			}
			for i := 0; i < len(autTransaction.TxOuts); i++ {
				entry.coins[autTransaction.TxOuts[i]].Spend()
			}
			stxoIdx -= 1

		case *aut.BurnTx:
			consumedAutCoins := sauts[stxoIdx].(*SpentAUTTokens)
			burnedAmount := uint64(0)
			for i, coin := range *consumedAutCoins {
				entry.coins[autTransaction.TxIns[i]] = NewAUTCoin(autTransactions[txIdx].AUTName(), coin.Amount, coin.Height, false)
				burnedAmount += coin.Amount
			}
			entry.info.MintedAmount += burnedAmount
			stxoIdx -= 1
		default:
			panic("unreachable")
		}
	}

	// Update the best hash for view to the previous block since all of the
	// autTransactions for the current block have been disconnected.
	view.SetBestHash(&block.MsgBlock().Header.PrevBlock)
	return nil
}

// Entries returns the underlying map that stores of all the utxo entries.
func (view *AUTViewpoint) Entries() map[string]*AUTEntry {
	return view.entries
}

func (view *AUTViewpoint) AUTEntries(autNameKey string) *AUTEntry {
	return view.entries[autNameKey]
}

func (view *AUTViewpoint) SetEntries(entries map[string]*AUTEntry) {
	view.entries = entries
}
func (view *AUTViewpoint) SetEntry(autName []byte, entry *AUTEntry) {
	view.entries[hex.EncodeToString(autName)] = entry
}

// commit prunes all entries marked modified that are now fully spent and marks
// all entries as unmodified.
func (view *AUTViewpoint) commit() {
	for _, autEntry := range view.entries {
		for outpoint, entry := range autEntry.coins {
			if entry == nil || (entry.isModified() && entry.IsSpent()) {
				delete(autEntry.coins, outpoint)
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
func (view *AUTViewpoint) fetchAUTMain(db database.DB, outpoints map[aut.OutPoint]struct{}, autName []byte) error {
	// Nothing to do if there are no requested outputs.
	if len(outpoints) == 0 && len(autName) == 0 {
		return nil
	}

	// Load the requested set of unspent transaction outputs from the point
	// of view of the end of the main chain.
	//
	// NOTE: Missing entries are not considered an error here and instead
	// will result in nil entries in the view.  This is intentionally done
	// so other code can use the presence of an entry in the store as a way
	// to unnecessarily avoid attempting to reload it from the database.
	autNameKey := hex.EncodeToString(autName)
	return db.View(func(dbTx database.Tx) error {
		if _, ok := view.entries[autNameKey]; !ok {
			// fetch aut info with root coin
			info, err := dbFetchAUTInfo(dbTx, autName)
			if err != nil {
				return err
			}
			view.entries[autNameKey] = &AUTEntry{
				info: info,
			}
		}

		if view.entries[autNameKey].coins == nil {
			view.entries[autNameKey].coins = make(map[aut.OutPoint]*AUTCoin, len(outpoints))
		}
		// fetch aut coin
		for outpoint := range outpoints {
			entry, err := dbFetchAUTEntry(dbTx, outpoint)
			if err != nil {
				return err
			}

			if !bytes.Equal(entry.name, autName) {
				return errors.New("unmatched AUT name and info")
			}

			view.entries[autNameKey].coins[outpoint] = entry
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
	for _, tx := range block.Transactions()[1:] {
		// Loop through all of the transaction inputs (except for the coinbase
		// which has no inputs) collecting them into sets of what is needed and
		// what is already known (in-flight).
		neededSet := make(map[aut.OutPoint]struct{}) // it is not in the same block
		autTx, isAUTTx := tx.AUTTransaction()
		if !isAUTTx {
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
		err := view.fetchAUTMain(db, neededSet, autTx.AUTName())
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
		entries: make(map[string]*AUTEntry),
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

	autTx, isAUTTx := originTx.AUTTransaction()
	if !isAUTTx {
		return nil, nil
	}
	if autTx == nil {
		return nil, aut.ErrInValidAUTTx
	}
	view := NewAUTViewpoint()
	neededSet := make(map[aut.OutPoint]struct{})
	switch autTx.Type() {
	case aut.Registration:
		// try fetch the AUT with same name
		// aut root coin store with AUT
	case aut.Mint:
		// aut root coin store with AUT
	case aut.ReRegistration:
		// aut root coin store with AUT
	case aut.Transfer:
		fallthrough
	case aut.Burn:
		// fetch input which would be spent
		for _, outpoint := range autTx.Ins() {
			neededSet[outpoint] = struct{}{}
		}
	default:
		log.Errorf("unreachable code")
		return nil, errors.New("unknown aut transaction type")
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
func (b *BlockChain) FetchAUTEntry(outpoint aut.OutPoint) (*AUTCoin, error) {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	var entry *AUTCoin
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

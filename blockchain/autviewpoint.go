package blockchain

import (
	"encoding/hex"
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
// 													 AUT IDENTIFIER | AUT Symbol | issuers | PLANNED  | threshold ..
// 													  n | value | ... | value | memo
// 													            issuers |  PLANNED  | threshold ..
// 													  issuers | threshold
//

// Register (txhash,index) -> (aut_identifier,root_coin)
// Mint (txhash,index)  -> AUT Coin (AUT IDENTIFIER)
// Transfer Abelian TXO  -> AUT Coin (AUT IDENTIFIER)
//

// AUTCoin houses details about an AUT Transaction output in a AUT
// view such as whether or not it was contained in a AUT Registration Transaction, the height of
// the block that contains the tx, whether or not it is spent, its public key
// script, and how much it pays.
// todo: AutEntry?
type AUTEntry struct {
	metadata *aut.MetaInfo
	coins    map[aut.OutPoint]*AUTCoin
}

func NewAUTEntry(metadata *aut.MetaInfo, coins map[aut.OutPoint]*AUTCoin) *AUTEntry {
	return &AUTEntry{metadata: metadata, coins: coins}
}

// todo: AddCion
func (e *AUTEntry) Add(outpiont aut.OutPoint, entry *AUTCoin) {
	if e.coins == nil {
		e.coins = make(map[aut.OutPoint]*AUTCoin)
	}
	e.coins[outpiont] = entry
}

func (e *AUTEntry) Metadata() *aut.MetaInfo {
	return e.metadata
}
func (e *AUTEntry) AUTCoins() map[aut.OutPoint]*AUTCoin {
	return e.coins
}

func (e *AUTEntry) LookupCoin(point aut.OutPoint) *AUTCoin {
	return e.coins[point]
}

type AUTCoin struct {
	identifier []byte
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
	identifier []byte, amount uint64, blockHeight int32, isRootCoin bool) *AUTCoin {
	var flag autFlags = atfModified
	if isRootCoin {
		flag |= atfRootCoin
	}

	return &AUTCoin{
		identifier:  identifier,
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
//	todo: using AutIdentifier as key to store AutEntries.
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

// LookupAutCoin returns information about a given transaction output according to
// the current state of the view.  It will return nil if the passed output does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
// todo: function name LookupAutCoin
func (view *AUTViewpoint) LookupAUTCoin(autIdentifierKey string, outpoint aut.OutPoint) *AUTCoin {
	if view.entries == nil {
		return nil
	}
	entry, ok := view.entries[autIdentifierKey]
	if !ok {
		return nil
	}
	return entry.coins[outpoint]
}

// todo: function name LookupAutDesc
func (view *AUTViewpoint) LookupAUTMetaInfo(autIdentifierKey string) *aut.MetaInfo {
	if view.entries == nil {
		return nil
	}
	entry, ok := view.entries[autIdentifierKey]
	if !ok {
		return nil
	}
	return entry.metadata
}

// addTxOut adds the specified output to the view if it is not provably
// unspendable.  When the view already has an entry for the output, it will be
// marked unspent.  All fields will be updated for existing entries since it's
// possible it has changed during a reorg.
func (view *AUTViewpoint) addAUTToken(autIdentifierKey string, outpoint aut.OutPoint, amount uint64, blockHeight int32) {
	// if the tx is not existing in the utxoentry, create a new one. otherwise update the height of view
	// Update existing entries.  All fields are updated because it's
	// possible (although extremely unlikely) that the existing entry is
	// being replaced by a different transaction with the same hash.  This
	// is allowed so long as the previous transaction is fully spent.
	_, ok := view.entries[autIdentifierKey]
	if !ok {
		log.Errorf("unreachable, invalid addAUTToken is called")
		return
	}
	autEntry := new(AUTCoin)
	view.entries[autIdentifierKey].coins[outpoint] = autEntry
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
	autTx, err := tx.AUTTransaction()
	if err != nil {
		return err
	}
	if autTx == nil {
		return nil
	}

	autIdentifierKey := hex.EncodeToString(autTx.AUTIdentifier())
	entry, exist := view.entries[autIdentifierKey]
	if autTx.Type() == aut.Registration {
		if exist && entry != nil && entry.metadata != nil {
			return fmt.Errorf("an registration AUT transaction %s try to register AUT entry with an existing AUT identified by %s", tx.Hash(), string(autTx.AUTIdentifier()))
		}
	} else {
		if !exist || entry == nil || entry.metadata == nil {
			return fmt.Errorf("an non-registration AUT transaction %s try to operate on non-existing AUT entry identified by %s", tx.Hash(), string(autTx.AUTIdentifier()))
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
			&aut.MetaInfo{
				AutIdentifier:      autTransaction.AutIdentifier,
				AutSymbol:          autTransaction.AutSymbol,
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
		view.entries[autIdentifierKey] = entry

		// TODO AUT actually do need to use saut to record
		if sauts != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = &UpdateAUTInfo{
				Before: nil,
				After:  entry.metadata,
				Height: blockHeight,
			}
			*sauts = append(*sauts, stxo)
		}

		log.Infof(`Register AUT with identifier %s with following configuration:
Symbol: %v,
UpdateThreshold: %v,
IssueThreshold: %v,
PlannedTotalAmount: %v,
ExpireHeight: %v,
IssuerTokens: %v,
UnitName: %v,
MinUnitName: %v,
UnitScale: %v,	
`, string(autTransaction.AutIdentifier), string(autTransaction.AutSymbol), autTransaction.IssuerUpdateThreshold, autTransaction.IssueTokensThreshold,
			autTransaction.PlannedTotalAmount, autTransaction.ExpireHeight, autTransaction.IssuerTokens,
			string(autTransaction.UnitName), string(autTransaction.MinUnitName), autTransaction.UnitScale)

	case *aut.MintTx:
		info := entry.Metadata()
		var currentSauts = (SpentAUTTokens)(make([]SpentAUTToken, 0, len(autTransaction.TxIns)))
		for i := 0; i < len(autTransaction.TxIns); i++ {
			if _, ok := info.RootCoinSet[autTransaction.TxIns[i]]; !ok {
				return fmt.Errorf("an mint AUT transaction %s try to mint AUT with "+
					"non-existing/spent root coin (%s,%d) for AUT identified by %s",
					tx.Hash(), autTransaction.TxIns[i].TxHash, autTransaction.TxIns[i].Index,
					string(autTx.AUTIdentifier()))
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
				return fmt.Errorf("an mint AUT transaction %s try to mint AUT exceed planned amount %d for AUT identified by %s", tx.Hash(), info.PlannedTotalAmount, string(autTx.AUTIdentifier()))
			}
			wouldMintedAmount += autTransaction.TxoAUTValues[i]
			entry.Add(autTransaction.TxOuts[i], NewAUTCoin(autTransaction.AutIdentifier, autTransaction.TxoAUTValues[i], blockHeight, false))
		}
		if info.MintedAmount+wouldMintedAmount < info.MintedAmount {
			return fmt.Errorf("an mint AUT transaction %s try to mint AUT exceed planned amount %d for AUT identified by %s", tx.Hash(), info.PlannedTotalAmount, string(autTx.AUTIdentifier()))
		}

		log.Infof(`Mint %d AUT coins for identifier %s (minted amount %d /planned total amount %d) with %d issuer tokens`,
			wouldMintedAmount, string(autTransaction.AutIdentifier),
			info.MintedAmount, info.PlannedTotalAmount, len(autTransaction.TxIns))

		info.MintedAmount += wouldMintedAmount
	case *aut.ReRegistrationTx:
		// input exist? double spent?
		metadata := entry.metadata
		originInfo := view.entries[autIdentifierKey].metadata.Clone()
		for i := 0; i < len(autTransaction.TxIns); i++ {
			if _, ok := metadata.RootCoinSet[autTransaction.TxIns[i]]; !ok {
				return fmt.Errorf("an re-registration AUT transaction %s try to mint AUT "+
					"with non-existing/spent root coin (%s,%d) for AUT identified by %s",
					tx.Hash(), autTransaction.TxIns[i].TxHash, autTransaction.TxIns[i].Index,
					string(autTx.AUTIdentifier()))
			}
			delete(metadata.RootCoinSet, autTransaction.TxIns[i])
		}

		// update aut metadata
		metadata.AutMemo = autTransaction.Memo
		metadata.UpdateThreshold = autTransaction.IssuerUpdateThreshold
		metadata.IssueThreshold = autTransaction.IssueTokensThreshold
		metadata.PlannedTotalAmount = autTransaction.PlannedTotalAmount
		metadata.ExpireHeight = autTransaction.ExpireHeight
		metadata.IssuerTokens = autTransaction.IssuerTokens
		metadata.UnitScale = autTransaction.UnitScale
		// remove previous root coins
		metadata.RootCoinSet = make(map[aut.OutPoint]struct{}, len(autTransaction.TxOuts))
		for i := 0; i < len(autTransaction.TxOuts); i++ {
			metadata.RootCoinSet[autTransaction.TxOuts[i]] = struct{}{}
		}
		view.entries[autIdentifierKey].metadata = metadata

		if sauts != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = &UpdateAUTInfo{
				Before:           originInfo,
				After:            view.entries[autIdentifierKey].metadata,
				Height:           blockHeight,
				IsReRegistration: true,
			}
			*sauts = append(*sauts, stxo)
		}
		log.Infof(`Re-register AUT with identifier %s with following configuration:
Symbol: %s -> %s,
UpdateThreshold: %v -> %v,
IssueThreshold: %v -> %v,
PlannedTotalAmount: %v -> %v,
ExpireHeight: %v -> %v,
IssuerTokens: %v -> %v,
UnitScale: %v -> %v`, string(autTransaction.AutIdentifier),
			string(originInfo.AutSymbol), string(autTransaction.AutSymbol),
			originInfo.UpdateThreshold, autTransaction.IssuerUpdateThreshold,
			originInfo.IssueThreshold, autTransaction.IssueTokensThreshold,
			originInfo.PlannedTotalAmount, autTransaction.PlannedTotalAmount,
			originInfo.ExpireHeight, autTransaction.ExpireHeight,
			originInfo.IssuerTokens, autTransaction.IssuerTokens,
			originInfo.UnitScale, autTransaction.UnitScale,
			//len(originInfo.RootCoinSet), autTransaction.OutAutRootCoinNum,
		)

	case *aut.TransferTx:
		// check the sanity of transfer transaction
		// balance between inputs and outputs
		info := entry.Metadata()
		var currentSauts = (SpentAUTTokens)(make([]SpentAUTToken, 0, len(autTransaction.TxIns)))
		totalInputValue := uint64(0)
		for i := 0; i < len(autTransaction.TxIns); i++ {
			token := entry.LookupCoin(autTransaction.TxIns[i])
			if token == nil {
				return fmt.Errorf("an transfer AUT transaction %s try to spend "+
					"non-existing/burn token (%s,%d) for AUT identified by %s",
					tx.Hash(), autTransaction.TxIns[i].TxHash, autTransaction.TxIns[i].Index,
					string(autTx.AUTIdentifier()))
			}
			if token.IsSpent() {
				return fmt.Errorf("an transfer AUT transaction %s try to spend "+
					"spent token (%s,%d) for AUT identified by %s",
					tx.Hash(), autTransaction.TxIns[i].TxHash, autTransaction.TxIns[i].Index,
					string(autTx.AUTIdentifier()))
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
			totalInputValue += token.Amount()
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
				return fmt.Errorf("an transfer AUT transaction %s try to overflow "+
					"planned amount %d for AUT identified by %s",
					tx.Hash(), info.PlannedTotalAmount, string(autTx.AUTIdentifier()))
			}
			totalOutValue += autTransaction.TxoAUTValues[i]
			entry.Add(autTransaction.TxOuts[i], NewAUTCoin(autTransaction.AutIdentifier, autTransaction.TxoAUTValues[i], blockHeight, false))
		}
		if totalInputValue != totalOutValue {
			return fmt.Errorf("an transfer AUT transaction %s try to unbalance "+
				"input %d and output %d for AUT identified by %s",
				tx.Hash(), totalInputValue, totalOutValue, string(autTx.AUTIdentifier()))
		}

		log.Infof(`Transfer for identifier %s (minted amount %d /planned total amount %d) %d AUT coins`, string(autTransaction.AutIdentifier),
			info.MintedAmount, info.PlannedTotalAmount, totalOutValue)

	case *aut.BurnTx:
		info := entry.Metadata()
		var currentSauts = (SpentAUTTokens)(make([]SpentAUTToken, 0, len(autTransaction.TxIns)))
		burnedValues := uint64(0)
		for i := 0; i < len(autTransaction.TxIns); i++ {
			token := entry.LookupCoin(autTransaction.TxIns[i])
			if token == nil {
				return fmt.Errorf("an burn AUT transaction %s try to spend"+
					" non-existing/burn token (%s,%d) for AUT identified by %s",
					tx.Hash(), autTransaction.TxIns[i].TxHash, autTransaction.TxIns[i].Index,
					string(autTx.AUTIdentifier()))
			}
			if token.IsSpent() {
				return fmt.Errorf("an burn AUT transaction %s try to spend"+
					" spent token (%s,%d) for AUT identified by %s",
					tx.Hash(), autTransaction.TxIns[i].TxHash, autTransaction.TxIns[i].Index,
					string(autTx.AUTIdentifier()))
			}
			if burnedValues+token.Amount() <= burnedValues {
				return fmt.Errorf("an burn AUT transaction %s try to overflow"+
					" for AUT identified by %s",
					tx.Hash(), string(autTx.AUTIdentifier()))
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
		log.Infof(`Burn for identifier %s (minted amount %d /planned total amount %d) %d AUT coins`, string(autTransaction.AutIdentifier),
			info.MintedAmount, info.PlannedTotalAmount, burnedValues)

	default:
		return fmt.Errorf("aut transaction %s with unknown type %d", tx.Hash(), autTx.Type())
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
		err := view.connectTransaction(tx, block.MsgBlock().Header.Height, stxos)
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
		autTransaction := autTransactions[txIdx]
		autIdentifier := autTransaction.AUTIdentifier()
		autIdentifierKey := hex.EncodeToString(autIdentifier)

		if view.entries[autIdentifierKey] == nil {
			err := view.fetchAUTMain(db, nil, autIdentifier, autTransaction.Type())
			if err != nil {
				return err
			}
		}
		outpoints := map[aut.OutPoint]struct{}{}
		autTxType := autTransaction.Type()
		if autTxType == aut.Registration { // consume nothing

		} else if autTxType == aut.Mint { // consume root coin, and generated coins
			for _, point := range autTransaction.TxOutputs() {
				outpoints[point] = struct{}{}
			}
		} else if autTxType == aut.ReRegistration { // consume root coin, and generate root coin

		} else if autTxType == aut.Transfer { // consume coin, and generate coin
			for _, point := range autTransaction.TxOutputs() {
				outpoints[point] = struct{}{}
			}
			for _, point := range autTransaction.TxInputs() {
				outpoints[point] = struct{}{}
			}
		} else if autTxType == aut.Burn { // consume coin
			for _, point := range autTransaction.TxInputs() {
				outpoints[point] = struct{}{}
			}
		} else {
			return fmt.Errorf("found an aut transaction with unknown type %d when "+
				"disconnecting transactions in block %s", autTransaction.Type(), block.Hash())
		}
		if len(outpoints) != 0 {
			err := view.fetchAUTMain(db, outpoints, autIdentifier, autTransaction.Type())
			if err != nil {
				return err
			}
		}
		entry := view.entries[autIdentifierKey]

		switch autTx := autTransaction.(type) {
		case *aut.RegistrationTx:
			infoToDel[autIdentifierKey] = struct{}{}
			stxoIdx -= 1
		case *aut.MintTx:
			// Restore inputs
			for _, in := range autTx.TxIns {
				entry.metadata.RootCoinSet[in] = struct{}{}
			}
			// Remove outputs
			totalMintedAmount := uint64(0)
			for i := 0; i < len(autTx.TxoAUTValues); i++ {
				totalMintedAmount += autTx.TxoAUTValues[i]
				entry.coins[autTx.TxOuts[i]].Spend()
			}
			entry.metadata.MintedAmount -= totalMintedAmount
			stxoIdx -= 1

		case *aut.ReRegistrationTx:
			updatedAUTInfo := sauts[stxoIdx].(*UpdateAUTInfo)
			entry.metadata = updatedAUTInfo.Before
			stxoIdx -= 1
		case *aut.TransferTx:
			consumedAutCoins := sauts[stxoIdx].(*SpentAUTTokens)
			for i, coin := range *consumedAutCoins {
				entry.coins[autTx.TxIns[i]] = NewAUTCoin(autTx.AUTIdentifier(), coin.Amount, coin.Height, false)
			}
			for i := 0; i < len(autTx.TxOuts); i++ {
				entry.coins[autTx.TxOuts[i]].Spend()
			}
			stxoIdx -= 1

		case *aut.BurnTx:
			consumedAutCoins := sauts[stxoIdx].(*SpentAUTTokens)
			burnedAmount := uint64(0)
			for i, coin := range *consumedAutCoins {
				entry.coins[autTx.TxIns[i]] = NewAUTCoin(autTx.AUTIdentifier(), coin.Amount, coin.Height, false)
				burnedAmount += coin.Amount
			}
			entry.metadata.MintedAmount += burnedAmount
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

func (view *AUTViewpoint) AUTEntries(autIdentifierKey string) *AUTEntry {
	return view.entries[autIdentifierKey]
}

func (view *AUTViewpoint) SetEntries(entries map[string]*AUTEntry) {
	view.entries = entries
}
func (view *AUTViewpoint) SetEntry(autIdentifierKey []byte, entry *AUTEntry) {
	view.entries[hex.EncodeToString(autIdentifierKey)] = entry
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
func (view *AUTViewpoint) fetchAUTMain(db database.DB, outpoints map[aut.OutPoint]struct{}, autIdentifier []byte, autTxType aut.TransactionType) error {
	if len(autIdentifier) != aut.IdentifierLength {
		return fmt.Errorf("invalid aut identifier:%v", autIdentifier)
	}

	// Load the requested set of unspent transaction outputs from the point
	// of view of the end of the main chain.
	//
	// NOTE: Missing entries are not considered an error here and instead
	// will result in nil entries in the view.  This is intentionally done
	// so other code can use the presence of an entry in the store as a way
	// to unnecessarily avoid attempting to reload it from the database.
	autIdentifierKey := hex.EncodeToString(autIdentifier)
	return db.View(func(dbTx database.Tx) error {
		if _, ok := view.entries[autIdentifierKey]; !ok {
			// fetch aut info with root coin
			metadata, err := dbFetchAUTMetaInfo(dbTx, autIdentifier)
			if err != nil {
				return err
			}
			// try to fetch the aut with specified identifier
			if autTxType != aut.Registration && metadata == nil {
				return fmt.Errorf("non-registration aut transaction with type %d should not operate on "+
					"unknown AUT identified %s", autTxType, autIdentifier)
			}
			if metadata != nil {
				view.entries[autIdentifierKey] = &AUTEntry{
					metadata: metadata,
				}
			}
		}

		if autTxType == aut.Registration {
			if len(outpoints) != 0 {
				return fmt.Errorf("registration aut transaction should not fetch token, but it try fetch %d tokens for AUT identified %s ",
					len(outpoints), autIdentifier)
			}
			if entry, ok := view.entries[autIdentifierKey]; ok || entry != nil {
				return fmt.Errorf("registration aut transaction try to register AUT  identified by %s which already exists",
					autIdentifier)
			}
			view.entries[autIdentifierKey] = &AUTEntry{
				metadata: nil,
			}
			return nil
		}

		// fetch aut coin
		if autTxType == aut.Mint || autTxType == aut.ReRegistration {
			for outpoint := range outpoints {
				if _, ok := view.entries[autIdentifierKey].metadata.RootCoinSet[outpoint]; !ok {
					return fmt.Errorf("mint/reregistration aut transaction try to operate on AUT identified by %s "+
						"with non-exist/spent root coin (%s,%d)", autIdentifier, outpoint.TxHash, outpoint.Index)
				}
			}
		} else {
			if view.entries[autIdentifierKey].coins == nil {
				view.entries[autIdentifierKey].coins = make(map[aut.OutPoint]*AUTCoin, len(outpoints))
			}
			for outpoint := range outpoints {
				entry, err := dbFetchAUTEntry(dbTx, outpoint)
				if err != nil {
					return err
				}

				view.entries[autIdentifierKey].coins[outpoint] = entry
			}
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
		autTx, err := tx.AUTTransaction()
		if err != nil {
			//	if a tx.AUTTransaction() returns error, such a transaction should not be accepted by mempool or a block.
			return err
		}
		if autTx != nil {
			autIdentifierKey := hex.EncodeToString(autTx.AUTIdentifier())
			for _, txIn := range autTx.TxInputs() {
				autCoin := view.LookupAUTCoin(autIdentifierKey, txIn)
				if autCoin == nil {
					neededSet[txIn] = struct{}{}
				}
			}
			err = view.fetchAUTMain(db, neededSet, autTx.AUTIdentifier(), autTx.Type())
			if err != nil {
				return err
			}
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

// FetchAUTView loads unspent transaction outputs for the inputs referenced by
// the passed transaction from the point of view of the end of the main chain.
// It also attempts to fetch the utxos for the outputs of the transaction itself
// so the returned view can be examined for duplicate transactions.
//
// This function is safe for concurrent access however the returned view is NOT.
// refactored by Alice 2024.03.01
func (b *BlockChain) FetchAUTView(hostTx *abeutil.TxAbe) (*AUTViewpoint, error) {
	// Create a set of needed outputs based on those referenced by the
	// inputs of the passed transaction and the outputs of the transaction
	// itself.

	autTx, err := hostTx.AUTTransaction()
	if err != nil {
		return nil, err
	}
	if autTx == nil {
		return nil, nil
	}

	view := NewAUTViewpoint()
	neededSet := make(map[aut.OutPoint]struct{})
	switch autTx.Type() {
	case aut.Registration:
		// try fetch the AUT with same identifier
		// aut root coin store with AUT
	case aut.Mint:
		// aut root coin store with AUT
	case aut.ReRegistration:
		// aut root coin store with AUT
	case aut.Transfer:
		fallthrough
	case aut.Burn:
		// fetch input which would be spent
		for _, outpoint := range autTx.TxInputs() {
			neededSet[outpoint] = struct{}{}
		}
	default:
		return nil, fmt.Errorf("aut transaction %s with unknown type %d", hostTx.Hash(), autTx.Type())
	}

	// no output need to be fetched
	// 	for _, outpoint := range autTx.Outs() {
	//		neededSet[outpoint] = struct{}{}
	//	}

	// Request the utxos from the point of view of the end of the main
	// chain.
	b.chainLock.RLock()
	err = view.fetchAUTMain(b.db, neededSet, autTx.AUTIdentifier(), autTx.Type())
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

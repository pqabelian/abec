package blockchain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/ctaut"
	"github.com/abesuite/abec/database"
)

// autFlags is a bitmask defining additional information and state for a
// aut transaction output in an aut view.
type ctAutFlags uint8

const (
	// TODO(CTAUT) Remove this flag
	// cafSpent indicates that a txout is spent.
	cafSpent ctAutFlags = 1 << iota

	// atfModified indicates that a txout has been modified since it was
	// loaded.
	cafModified
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
type CTAUTInstance struct {
	metadata *ctaut.Metadata
	coins    map[ctaut.OutPoint]*CTAUTCoin
}

func NewCTAUTInstance(metadata *ctaut.Metadata, coins map[ctaut.OutPoint]*CTAUTCoin) *CTAUTInstance {
	a := 2
	switch a {
	case 1, 2:
	}
	return &CTAUTInstance{metadata: metadata, coins: coins}
}

// todo: AddCion
func (instance *CTAUTInstance) Add(outpiont ctaut.OutPoint, coin *CTAUTCoin) {
	if instance.coins == nil {
		instance.coins = make(map[ctaut.OutPoint]*CTAUTCoin)
	}
	instance.coins[outpiont] = coin
}

func (instance *CTAUTInstance) Metadata() *ctaut.Metadata {
	return instance.metadata
}
func (instance *CTAUTInstance) AUTCoins() map[ctaut.OutPoint]*CTAUTCoin {
	return instance.coins
}

func (instance *CTAUTInstance) SpendCoin(point ctaut.OutPoint) (*CTAUTCoin, error) {
	token, exist := instance.coins[point]
	if !exist || token == nil {
		return nil, errors.New("non-exist aut coin")
	}
	if token.IsSpent() {
		return nil, errors.New("spent aut coin")
	}

	token.Spend()

	return token, nil
}

type CTAUTCoin struct {
	identifier []byte
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.
	script      []byte
	blockHeight int32 // Height of block containing tx.

	// packedFlags contains additional info about output such as whether it
	// is a coinbase, whether it is spent, and whether it has been modified
	// since it was loaded.  This approach is used in order to reduce memory
	// usage since there will be a lot of these in memory.
	packedFlags ctAutFlags
}

// isModified returns whether or not the output has been modified since it was
// loaded.
func (coin *CTAUTCoin) isModified() bool {
	return coin.packedFlags&cafModified == cafModified
}

// IsSpent returns whether or not the output has been spent based upon the
// current state of the unspent transaction output view it was obtained from.
func (coin *CTAUTCoin) IsSpent() bool {
	return coin.packedFlags&cafSpent == cafSpent
}

// BlockHeight returns the height of the block containing the output.
func (coin *CTAUTCoin) BlockHeight() int32 {
	return coin.blockHeight
}

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
func (coin *CTAUTCoin) Spend() {
	// Nothing to do if the output is already spent.
	if coin.IsSpent() {
		return
	}

	// Mark the output as spent and modified.
	coin.packedFlags |= cafSpent | cafModified
}

// Clone returns a shallow copy of the utxo entry.
func (coin *CTAUTCoin) Clone() *CTAUTCoin {
	if coin == nil {
		return nil
	}

	script := make([]byte, len(coin.script))
	copy(script, coin.script)
	return &CTAUTCoin{
		identifier:  coin.identifier,
		script:      script,
		blockHeight: coin.blockHeight,
		packedFlags: coin.packedFlags,
	}
}

// todo: function name
// NewAUTCoin returns a new AUTCoin built from the arguments.
func NewCTAUTCoin(identifier []byte, script []byte, blockHeight int32) *CTAUTCoin {

	return &CTAUTCoin{
		identifier:  identifier,
		script:      script,
		blockHeight: blockHeight,
		packedFlags: cafModified,
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
type CTAUTViewpoint struct {
	instances map[string]*CTAUTInstance
	bestHash  chainhash.Hash
}

func CTAUTIdentifierKey(identifier []byte) string {
	return hex.EncodeToString(identifier)
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
func (view *CTAUTViewpoint) BestHash() *chainhash.Hash {
	return &view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
func (view *CTAUTViewpoint) SetBestHash(hash *chainhash.Hash) {
	view.bestHash = *hash
}

func (view *CTAUTViewpoint) Instances() map[string]*CTAUTInstance {
	return view.instances
}

func (view *CTAUTViewpoint) SetInstances(instances map[string]*CTAUTInstance) {
	view.instances = instances
}

// LookupAutCoin returns information about a given transaction output according to
// the current state of the view.  It will return nil if the passed output does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
// todo: function name LookupAutCoin
func (view *CTAUTViewpoint) LookupCTAUTCoin(identifier []byte, outpoint ctaut.OutPoint) *CTAUTCoin {
	if view.instances == nil {
		return nil
	}
	instance, ok := view.instances[CTAUTIdentifierKey(identifier)]
	if !ok {
		return nil
	}
	return instance.coins[outpoint]
}

// todo: function name LookupAutDesc
func (view *CTAUTViewpoint) LookupCTAUTMetaInfo(identifier []byte) *ctaut.Metadata {
	if view.instances == nil {
		return nil
	}
	instance, ok := view.instances[CTAUTIdentifierKey(identifier)]
	if !ok {
		return nil
	}
	return instance.metadata
}

// addTxOut adds the specified output to the view if it is not provably
// unspendable.  When the view already has an entry for the output, it will be
// marked unspent.  All fields will be updated for existing entries since it's
// possible it has changed during a reorg.
func (view *CTAUTViewpoint) addCTAUTCoin(identifier []byte, outpoint ctaut.OutPoint, script []byte, blockHeight int32) {
	// if the tx is not existing in the utxoentry, create a new one. otherwise update the height of view
	// Update existing entries.  All fields are updated because it's
	// possible (although extremely unlikely) that the existing entry is
	// being replaced by a different transaction with the same hash.  This
	// is allowed so long as the previous transaction is fully spent.
	instance, ok := view.instances[CTAUTIdentifierKey(identifier)]
	if !ok {
		log.Errorf("unreachable, invalid addAUTToken is called")
		return
	}
	instance.coins[outpoint] = NewCTAUTCoin(identifier, script, blockHeight)
}

func (view *CTAUTViewpoint) connectRegistrationTransaction(autTransaction *ctaut.RegistrationTx, txHash chainhash.Hash,
	blockHeight int32, sctauts *[]SpentCTAUT) error {
	identifierKey := CTAUTIdentifierKey(autTransaction.AUTIdentifier())
	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if exist && instance != nil && instance.metadata != nil {
		return fmt.Errorf("an registration AUT transaction %s try to register AUT entry with an existing AUT identified by %s",
			txHash, identifierKey)
	}

	rootCoinSet := map[ctaut.OutPoint]struct{}{}
	for i := 0; i < len(autTransaction.TxOuts); i++ {
		rootCoinSet[autTransaction.TxOuts[i].OutPoint] = struct{}{}
	}
	// register the AUT entry
	instance = NewCTAUTInstance(
		&ctaut.Metadata{
			CTAutIdentifier:       autTransaction.CTAutIdentifier,
			CTAutSymbol:           autTransaction.CTAutSymbol,
			UnitName:              autTransaction.UnitName,
			MinUnitName:           autTransaction.MinUnitName,
			UnitScale:             autTransaction.UnitScale,
			AutMemo:               autTransaction.AutMemo,
			PlannedTotalAmount:    autTransaction.PlannedTotalAmount,
			IssuerTokens:          autTransaction.IssuerTokens,
			IssueTokensThreshold:  autTransaction.IssueTokensThreshold,
			IssuerUpdateThreshold: autTransaction.IssuerUpdateThreshold,
			ExpireHeight:          autTransaction.ExpireHeight,

			MintedAmount: 0,
			RootCoinSet:  rootCoinSet,
		},
		nil,
	)
	view.instances[identifierKey] = instance

	// TODO(CTAUT): It seems that CTAUT  do need to use saut to record
	if sctauts != nil {
		// Populate the stxo details using the utxo entry.
		var stxo = &UpdatedCTAUTInfo{
			Before: nil,
			After:  instance.metadata,
			Height: blockHeight,
		}
		*sctauts = append(*sctauts, stxo)
	}

	log.Debugf(`In transaction %s, AUT with identifier %s with following configuration is registered: Symbol: %v,
	IssuerUpdateThreshold: %v, IssueTokensThreshold: %v, PlannedTotalAmount: %v,
	ExpireHeight: %v, UnitName: %v, MinUnitName: %v, UnitScale: %v`,
		txHash,
		identifierKey, hex.EncodeToString(autTransaction.CTAutSymbol),
		autTransaction.IssuerUpdateThreshold, autTransaction.IssueTokensThreshold, autTransaction.PlannedTotalAmount,
		autTransaction.ExpireHeight,
		hex.EncodeToString(autTransaction.UnitName), hex.EncodeToString(autTransaction.MinUnitName), autTransaction.UnitScale)
	log.Debugf("Totoal %d issuers", len(autTransaction.IssuerTokens))
	for i := 0; i < len(autTransaction.IssuerTokens); i++ {
		log.Debugf("\t %d-th: %s", i, hex.EncodeToString(autTransaction.IssuerTokens[i]))
	}

	return nil
}
func (view *CTAUTViewpoint) connectMintTransaction(autTransaction *ctaut.MintTx, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentCTAUT) error {
	identifierKey := CTAUTIdentifierKey(autTransaction.AUTIdentifier())
	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return fmt.Errorf("an non-registration AUT transaction %s try to operate on non-existing AUT entry identified by %s",
			txHash, identifierKey)
	}

	info := view.instances[identifierKey].Metadata()
	txIns := autTransaction.TxInputs()
	currentSctauts := make([]SpentCTAUTToken, 0, len(txIns))
	for i := 0; i < len(txIns); i++ {
		if _, ok := info.RootCoinSet[txIns[i].OutPoint]; !ok {
			return fmt.Errorf(`an mint AUT transaction %s try to mint AUT with 
				"non-existing/spent root coin (%s,%d) for AUT identified by %s`,
				txHash, txIns[i].TxHash, txIns[i].Index,
				identifierKey)
		}
		delete(info.RootCoinSet, txIns[i].OutPoint)

		// TODO(CTAUT): It seems that CTAUT  do need to use saut to record
		if sctauts != nil {
			var stxo = SpentCTAUTToken{
				Script: nil,
				Height: blockHeight,
			}
			currentSctauts = append(currentSctauts, stxo)
		}

	}
	// TODO AUT actually do need to use saut to record
	if sctauts != nil {
		sctaut := SpentCTAUTTokens(currentSctauts)
		*sctauts = append(*sctauts, &sctaut)
	}

	// Rules
	// 1. check balance proof, has done when extracting script from the transaction
	// 2. check minted is exceed
	wouldMintedAmount := autTransaction.Vin
	if info.MintedAmount+wouldMintedAmount < info.MintedAmount {
		return fmt.Errorf("an mint AUT transaction %s try to mint AUT exceed planned amount %d for AUT identified by %s",
			txHash, info.PlannedTotalAmount, identifierKey)
	}
	info.MintedAmount += wouldMintedAmount

	log.Debugf(`Mint %d AUT coins for identifier %s (minted amount %d /planned total amount %d) with %d issuer tokens`,
		wouldMintedAmount, identifierKey,
		info.MintedAmount, info.PlannedTotalAmount, len(txIns))
	return nil
}
func (view *CTAUTViewpoint) connectReRegistrationTransaction(autTransaction *ctaut.ReRegistrationTx, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentCTAUT) error {
	identifierKey := CTAUTIdentifierKey(autTransaction.AUTIdentifier())
	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return fmt.Errorf("an non-registration AUT transaction %s try to operate on non-existing AUT entry identified by %s",
			txHash, identifierKey)
	}

	// input exist? double spent?
	metadata := instance.metadata
	previousMetadata := metadata.Clone()

	txIns := autTransaction.TxInputs()
	for i := 0; i < len(txIns); i++ {
		if _, ok := metadata.RootCoinSet[txIns[i].OutPoint]; !ok {
			return fmt.Errorf("an re-registration AUT transaction %s try to mint AUT "+
				"with non-existing/spent root coin (%s,%d) for AUT identified by %s",
				txHash, txIns[i].TxHash, txIns[i].Index, identifierKey)
		}
		delete(metadata.RootCoinSet, txIns[i].OutPoint)
	}

	metadata.CTAutSymbol = autTransaction.CTAutSymbol
	metadata.UnitScale = autTransaction.UnitScale

	metadata.AutMemo = autTransaction.AutMemo
	// assert
	if metadata.MintedAmount > autTransaction.PlannedTotalAmount {
		return errors.New("re-registration transaction try to make planned amount less than minted amount")
	}
	metadata.PlannedTotalAmount = autTransaction.PlannedTotalAmount

	metadata.IssuerTokens = autTransaction.IssuerTokens
	metadata.IssuerUpdateThreshold = autTransaction.IssuerUpdateThreshold
	metadata.IssueTokensThreshold = autTransaction.IssueTokensThreshold
	metadata.ExpireHeight = autTransaction.ExpireHeight

	// remove previous root coins
	txOuts := autTransaction.TxOutputs()
	metadata.RootCoinSet = make(map[ctaut.OutPoint]struct{}, len(txOuts))
	for i := 0; i < len(txOuts); i++ {
		metadata.RootCoinSet[txOuts[i].OutPoint] = struct{}{}
	}

	// update aut metadata
	view.instances[identifierKey].metadata = metadata

	if sctauts != nil {
		// Populate the stxo details using the utxo entry.
		var stxo = &UpdatedCTAUTInfo{
			Before:           previousMetadata,
			After:            metadata.Clone(),
			Height:           blockHeight,
			IsReRegistration: true,
		}
		*sctauts = append(*sctauts, stxo)
	}
	log.Debugf(`Re-register AUT with identifier %s with following configuration: Symbol: %s -> %s,
IssuerUpdateThreshold: %v -> %v, IssueTokensThreshold: %v -> %v,
PlannedTotalAmount: %v -> %v, ExpireHeight: %v -> %v,
UnitScale: %v -> %v`, identifierKey,
		hex.EncodeToString(previousMetadata.CTAutSymbol), hex.EncodeToString(metadata.CTAutSymbol),
		previousMetadata.IssuerUpdateThreshold, metadata.IssuerUpdateThreshold,
		previousMetadata.IssueTokensThreshold, metadata.IssueTokensThreshold,
		previousMetadata.PlannedTotalAmount, metadata.PlannedTotalAmount,
		previousMetadata.ExpireHeight, metadata.ExpireHeight,
		previousMetadata.UnitScale, metadata.UnitScale,
	)
	log.Debugf("Previous IssuerTokens: len = %d", len(previousMetadata.IssuerTokens))
	for i := 0; i < len(previousMetadata.IssuerTokens); i++ {
		log.Debugf("[%d] %s", i, hex.EncodeToString(previousMetadata.IssuerTokens[i]))
	}

	log.Debugf("Current IssuerTokens: len = %d", len(metadata.IssuerTokens))
	for i := 0; i < len(metadata.IssuerTokens); i++ {
		log.Debugf("[%d] %s", i, hex.EncodeToString(metadata.IssuerTokens[i]))
	}
	log.Debugf("Abolished RootCoin: len = %d", len(previousMetadata.RootCoinSet))
	for point := range previousMetadata.RootCoinSet {
		log.Debugf("%s", point)
	}
	log.Debugf("Enabled RootCoin: len = %d", len(metadata.RootCoinSet))
	for _, point := range metadata.RootCoinSet {
		log.Debugf("%s", point)
	}
	return nil
}
func (view *CTAUTViewpoint) connectTransferTransaction(autTransaction *ctaut.TransferTx, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentCTAUT) error {
	identifierKey := CTAUTIdentifierKey(autTransaction.AUTIdentifier())
	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return fmt.Errorf("an non-registration AUT transaction %s try to operate on non-existing AUT entry identified by %s",
			txHash, identifierKey)
	}

	txIns := autTransaction.TxInputs()
	var currentSctauts = make([]SpentCTAUTToken, 0, len(txIns))
	for i := 0; i < len(txIns); i++ {
		token, err := instance.SpendCoin(txIns[i].OutPoint)
		if err != nil {
			return fmt.Errorf("an transfer AUT transaction %s try to spend "+
				"non-existing/burn token (%s,%d) for AUT identified by %s but fail due to %s",
				txHash, txIns[i].TxHash, txIns[i].Index,
				identifierKey, err)
		}

		if sctauts != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = SpentCTAUTToken{
				Script: token.script,
				Height: blockHeight,
			}
			currentSctauts = append(currentSctauts, stxo)
		}
	}
	if sctauts != nil {
		// Populate the stxo details using the utxo entry.
		sctaut := SpentCTAUTTokens(currentSctauts)
		*sctauts = append(*sctauts, &sctaut)
	}

	txOuts := autTransaction.TxOutputs()
	for i := 0; i < len(txOuts); i++ {
		coin := NewCTAUTCoin(autTransaction.AUTIdentifier(), txOuts[i].ValueScript, blockHeight)
		view.instances[identifierKey].Add(txOuts[i].OutPoint, coin)
	}

	return nil
}
func (view *CTAUTViewpoint) connectBurnTransaction(autTransaction *ctaut.BurnTx, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentCTAUT) error {
	identifierKey := CTAUTIdentifierKey(autTransaction.AUTIdentifier())
	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return fmt.Errorf("an non-registration AUT transaction %s try to operate on non-existing AUT entry identified by %s",
			txHash, identifierKey)
	}

	txIns := autTransaction.TxInputs()
	var currentSctauts = make([]SpentCTAUTToken, 0, len(txIns))
	for i := 0; i < len(txIns); i++ {
		token, err := instance.SpendCoin(txIns[i].OutPoint)
		if err != nil {
			return fmt.Errorf("an transfer AUT transaction %s try to spend "+
				"non-existing/burn token (%s,%d) for AUT identified by %s but fail due to %s",
				txHash, txIns[i].TxHash, txIns[i].Index,
				identifierKey, err)
		}

		if sctauts != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = SpentCTAUTToken{
				Script: token.script,
				Height: blockHeight,
			}
			currentSctauts = append(currentSctauts, stxo)
		}
	}
	if sctauts != nil {
		// Populate the stxo details using the utxo entry.
		sctaut := SpentCTAUTTokens(currentSctauts)
		*sctauts = append(*sctauts, &sctaut)
	}

	// Rule: the first output would be viewed as destroyed/burned
	txOuts := autTransaction.TxOutputs()

	log.Debugf("outpoint %s for AUT instance %s is burned", txOuts[0].OutPoint, identifierKey)
	for i := 1; i < len(txOuts); i++ {
		coin := NewCTAUTCoin(autTransaction.AUTIdentifier(), txOuts[i].ValueScript, blockHeight)
		view.instances[identifierKey].Add(txOuts[i].OutPoint, coin)
	}

	return nil
}

// connectTransaction updates the view by adding all new utxos created by the
// passed transaction and marking all utxos that the transactions spend as
// spent.  In addition, when the 'stxos' argument is not nil, it will be updated
// to append an entry for each spent txout.  An error will be returned if the
// view does not contain the required utxos.
// TODO Check consistence with mining.spendTransactionAbe
func (view *CTAUTViewpoint) connectTransaction(tx *abeutil.TxAbe, blockHeight int32, sctauts *[]SpentCTAUT) error {
	autTx, err := tx.CTAUTTransaction()
	if err != nil {
		return err
	}
	if autTx == nil {
		return nil
	}
	txHash := tx.Hash()

	switch autTransaction := autTx.(type) {
	case *ctaut.RegistrationTx:
		err = view.connectRegistrationTransaction(autTransaction, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}
	case *ctaut.MintTx:
		err = view.connectMintTransaction(autTransaction, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}
	case *ctaut.ReRegistrationTx:
		err = view.connectReRegistrationTransaction(autTransaction, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}

	case *ctaut.TransferTx:
		err = view.connectTransferTransaction(autTransaction, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}

	case *ctaut.BurnTx:
		err = view.connectBurnTransaction(autTransaction, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}

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
func (view *CTAUTViewpoint) connectTransactions(block *abeutil.BlockAbe, sctauts *[]SpentCTAUT) error {
	for _, tx := range block.Transactions() {
		err := view.connectTransaction(tx, block.MsgBlock().Header.Height, sctauts)
		if err != nil {
			return err
		}
	}

	// Update the best hash for view to include this block since all of its
	// transactions have been connected.
	view.SetBestHash(block.Hash())
	return nil
}
func (view *CTAUTViewpoint) disconnectRegistrationTransaction(db database.DB, autTransaction *ctaut.RegistrationTx,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	identifier := autTransaction.AUTIdentifier()
	identifierKey := CTAUTIdentifierKey(identifier)

	err := view.fetchCTAUTMain(db, nil, identifier)
	if err != nil {
		return nil, err
	}

	unregisteredCTAUT := map[string]struct{}{}

	instance, exist := view.instances[identifierKey]
	if !exist || instance == nil || instance.metadata == nil {
		return nil, fmt.Errorf("fail to find the registered AUT instance identified by %s",
			identifierKey)
	}
	unregisteredCTAUT[identifierKey] = struct{}{}

	return unregisteredCTAUT, nil
}

func (view *CTAUTViewpoint) disconnectMintTransaction(db database.DB, autTransaction *ctaut.MintTx,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	identifier := autTransaction.AUTIdentifier()
	identifierKey := CTAUTIdentifierKey(identifier)

	// fetch outpoint from database if not exist with instance in batch
	outpoints := map[ctaut.OutPoint]struct{}{}
	coins := autTransaction.TxOutputs()
	for _, coin := range coins {
		outpoints[coin.OutPoint] = struct{}{}
	}
	err := view.fetchCTAUTMain(db, outpoints, identifier)
	if err != nil {
		return nil, err
	}

	instance, exist := view.instances[identifierKey]
	if !exist || instance == nil || instance.metadata == nil {
		return nil, fmt.Errorf("fail to find the registered AUT instance identified by %s",
			identifierKey)
	}

	// abolish generate CTAUT coins
	for _, coin := range coins {
		if _, exist := instance.coins[coin.OutPoint]; !exist {
			return nil, fmt.Errorf("unknown coins %s for AUT instance %s", coin.OutPoint, identifierKey)
		}
		instance.coins[coin.OutPoint].Spend()
	}

	// restore consumed CTAUT root coins
	for _, rootCoin := range autTransaction.TxIns {
		copiedAUTPoint := ctaut.OutPoint{}
		copy(copiedAUTPoint.TxHash[:], rootCoin.TxHash[:])
		copiedAUTPoint.Index = rootCoin.Index

		instance.metadata.RootCoinSet[copiedAUTPoint] = struct{}{}
		log.Debugf("try to resume consumed root coin (%s,%d) for AUT identified by %s",
			rootCoin.TxHash.String(), rootCoin.Index, identifierKey)
	}

	return nil, nil
}
func (view *CTAUTViewpoint) disconnectReRegistrationTransaction(db database.DB, autTransaction *ctaut.ReRegistrationTx,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	identifier := autTransaction.AUTIdentifier()
	identifierKey := CTAUTIdentifierKey(identifier)

	err := view.fetchCTAUTMain(db, nil, identifier)
	if err != nil {
		return nil, err
	}

	instance, exist := view.instances[identifierKey]
	if !exist || instance == nil || instance.metadata == nil {
		return nil, fmt.Errorf("fail to find the registered AUT instance identified by %s",
			identifierKey)
	}

	updatedAUTInfo, ok := sctaut.(*UpdatedCTAUTInfo)
	if !ok {
		return nil, fmt.Errorf("invalid updated information")
	}

	instance.metadata = updatedAUTInfo.Before.Clone()
	return nil, nil
}

func (view *CTAUTViewpoint) disconnectTransferTransaction(db database.DB, autTransaction *ctaut.TransferTx,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	identifier := autTransaction.AUTIdentifier()
	identifierKey := CTAUTIdentifierKey(identifier)

	// fetch outpoint from database if not exist with instance in batch
	outpoints := map[ctaut.OutPoint]struct{}{}
	for _, coin := range autTransaction.TxOutputs() {
		outpoints[coin.OutPoint] = struct{}{}
	}
	for _, coin := range autTransaction.TxInputs() {
		outpoints[coin.OutPoint] = struct{}{}
	}
	err := view.fetchCTAUTMain(db, outpoints, identifier)
	if err != nil {
		return nil, err
	}

	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return nil, fmt.Errorf("fail to find the registered AUT instance identified by %s",
			identifierKey)
	}

	for _, coin := range autTransaction.TxOutputs() {
		if _, exist := instance.coins[coin.OutPoint]; !exist {
			return nil, fmt.Errorf("unknown coins %s for AUT instance %s", coin.OutPoint, identifierKey)
		}
		instance.coins[coin.OutPoint].Spend()
	}

	txIns := autTransaction.TxInputs()
	consumedAutTokens, ok := sctaut.(*SpentCTAUTTokens)
	if !ok {
		return nil, fmt.Errorf("invalid updated information")
	}
	// assert
	if len(txIns) != len(*consumedAutTokens) {
		return nil, fmt.Errorf("mismatched spend journal")
	}
	// TODO(CTAUT) consider order?
	for i := len(*consumedAutTokens) - 1; i >= 0; i-- {
		// TODO it seems there is no way to get script other than here
		token := (*consumedAutTokens)[i]
		coin := txIns[i]
		if _, ok := instance.coins[coin.OutPoint]; ok {
			return nil, fmt.Errorf("duplicate coins %s for AUT instance %s", coin.OutPoint, identifierKey)
		}
		instance.coins[coin.OutPoint] = NewCTAUTCoin(identifier, token.Script, blockHeight)
	}

	return nil, nil
}
func (view *CTAUTViewpoint) disconnectBurnTransaction(db database.DB, autTransaction *ctaut.BurnTx,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	identifier := autTransaction.AUTIdentifier()
	identifierKey := CTAUTIdentifierKey(identifier)

	// fetch outpoint from database if not exist with instance in batch
	outpoints := map[ctaut.OutPoint]struct{}{}
	for _, coin := range autTransaction.TxOutputs() {
		outpoints[coin.OutPoint] = struct{}{}
	}
	for _, coin := range autTransaction.TxInputs() {
		outpoints[coin.OutPoint] = struct{}{}
	}
	err := view.fetchCTAUTMain(db, outpoints, identifier)
	if err != nil {
		return nil, err
	}

	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return nil, fmt.Errorf("fail to find the registered AUT instance identified by %s",
			identifierKey)
	}

	txOuts := autTransaction.TxOutputs()
	for i := len(txOuts); i > 0; i++ {
		coin := txOuts[i]
		if _, exist := instance.coins[coin.OutPoint]; !exist {
			return nil, fmt.Errorf("unknown coins %s for AUT instance %s", coin.OutPoint, identifierKey)
		}
		instance.coins[coin.OutPoint].Spend()
	}
	if _, exist := instance.coins[txOuts[0].OutPoint]; exist {
		return nil, fmt.Errorf("should not exist coin %s for AUT instance %s", txOuts[0].OutPoint, identifierKey)
	}

	txIns := autTransaction.TxInputs()
	consumedAutTokens, ok := sctaut.(*SpentCTAUTTokens)
	if !ok {
		return nil, fmt.Errorf("invalid updated information")
	}
	// assert
	if len(txIns) != len(*consumedAutTokens) {
		return nil, fmt.Errorf("mismatched spend journal")
	}
	// TODO(CTAUT) consider order?
	for i := len(*consumedAutTokens) - 1; i >= 0; i-- {
		// TODO it seems there is no way to get script other than here
		token := (*consumedAutTokens)[i]
		coin := txIns[i]
		if _, ok := instance.coins[coin.OutPoint]; ok {
			return nil, fmt.Errorf("duplicate coins %s for AUT instance %s", coin.OutPoint, identifierKey)
		}
		instance.coins[coin.OutPoint] = NewCTAUTCoin(identifier, token.Script, blockHeight)
	}

	return nil, nil
}

// disconnectTransactions updates the view by removing all of the transactions
// created by the passed block, restoring all utxos the transactions spent by
// using the provided spent txo information, and setting the best hash for the
// view to the block before the passed block.
//
// NOTE: saut must not be modified anyway!!!
func (view *CTAUTViewpoint) disconnectTransactions(db database.DB, block *abeutil.BlockAbe,
	sauts []SpentCTAUT) (map[string]struct{}, error) {

	// Sanity check the correct number of sauts are provided.
	if len(sauts) != countSpentOutputsCTAUT(block) {
		return nil, AssertError("disconnectTransactions called with bad " +
			"spent transaction out information")
	}

	// Loop backwards through all autTransactions so everything is unspent in
	// reverse order.  This is necessary since autTransactions later in a block
	// can spend from previous ones.
	stxoIdx := len(sauts) - 1
	ctAUTTxs := block.CTAUTTransactions()
	unregisteredCTAUTs := map[string]struct{}{}
	for txIdx := len(ctAUTTxs) - 1; txIdx >= 0; txIdx-- {
		ctAUTTx := ctAUTTxs[txIdx]

		switch autTransaction := ctAUTTx.(type) {
		case *ctaut.RegistrationTx:
			registeredAUTs, err := view.disconnectRegistrationTransaction(db, autTransaction, block.Height(), sauts[stxoIdx])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}
			for identifier := range registeredAUTs {
				unregisteredCTAUTs[identifier] = struct{}{}
			}

		case *ctaut.MintTx:
			_, err := view.disconnectMintTransaction(db, autTransaction, block.Height(), sauts[stxoIdx])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}

		case *ctaut.ReRegistrationTx:
			_, err := view.disconnectReRegistrationTransaction(db, autTransaction, block.Height(), sauts[stxoIdx])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}

		case *ctaut.TransferTx:
			_, err := view.disconnectTransferTransaction(db, autTransaction, block.Height(), sauts[stxoIdx])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}

		case *ctaut.BurnTx:
			_, err := view.disconnectBurnTransaction(db, autTransaction, block.Height(), sauts[stxoIdx])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}
		default:
			return nil, AssertError("disconnectTransactions called with unknown AUT transaction type")
		}

		stxoIdx -= 1
	}

	// Update the best hash for view to the previous block since all of the
	// autTransactions for the current block have been disconnected.
	view.SetBestHash(&block.MsgBlock().Header.PrevBlock)
	return unregisteredCTAUTs, nil
}

// commit prunes all entries marked modified that are now fully spent and marks
// all entries as unmodified.
func (view *CTAUTViewpoint) commit() {
	for _, instance := range view.instances {
		for outpoint, coin := range instance.coins {
			if coin == nil || (coin.isModified() && coin.IsSpent()) {
				delete(instance.coins, outpoint)
				continue
			}

			coin.packedFlags ^= cafModified
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
func (view *CTAUTViewpoint) fetchCTAUTMain(db database.DB, outpoints map[ctaut.OutPoint]struct{}, identifier []byte) error {
	if len(identifier) != ctaut.IdentifierLength {
		return fmt.Errorf("invalid aut identifier:%v", identifier)
	}

	// Load the requested set of unspent aut transaction outputs from the point
	// of view of the end of the main chain.
	//
	// NOTE: Missing entries are not considered an error here and instead
	// will result in nil entries in the view.  This is intentionally done
	// so other code can use the presence of an entry in the store as a way
	// to unnecessarily avoid attempting to reload it from the database.
	autIdentifierKey := CTAUTIdentifierKey(identifier)
	return db.View(func(dbTx database.Tx) error {
		// firstly, fetch the meta information for specified identifier
		if _, ok := view.instances[autIdentifierKey]; !ok {
			// fetch aut info with root coin
			metadata, err := dbFetchCTAUTMetadata(dbTx, identifier)
			if err != nil {
				return err
			}
			if metadata != nil {
				view.instances[autIdentifierKey] = &CTAUTInstance{
					metadata: metadata,
				}
			}
		}

		if view.instances[autIdentifierKey].coins == nil {
			view.instances[autIdentifierKey].coins = make(map[ctaut.OutPoint]*CTAUTCoin, len(outpoints))
		}
		for outpoint := range outpoints {
			// when the view has corresponding outpoints, do not
			// fetch from database, it means that outpoint has fetched
			if view.instances[autIdentifierKey].coins[outpoint] != nil {
				continue
			}

			coin, err := dbFetchCTAUTCoin(dbTx, outpoint)
			if err != nil {
				return err
			}
			// assert
			if !bytes.Equal(coin.identifier, identifier) {
				return fmt.Errorf("invalid fetch for point (%s, %d) for CTAUT instance %s",
					outpoint.TxHash, outpoint.Index, autIdentifierKey)
			}
			view.instances[autIdentifierKey].coins[outpoint] = coin
		}

		return nil
	})
}

// fetchInputUtxos loads the unspent transaction outputs for the inputs
// referenced by the transactions in the given block into the view from the
// database as needed.  In particular, referenced entries that are earlier in
// the block are added to the view and entries that are already in the view are
// not modified.
func (view *CTAUTViewpoint) fetchInputCTAUTUtxos(db database.DB, block *abeutil.BlockAbe, hostView *UtxoRingViewpoint) error {
	blockHeight := block.Height()
	for _, tx := range block.Transactions()[1:] {
		// Loop through all of the transaction inputs (except for the coinbase
		// which has no inputs) collecting them into sets of what is needed and
		// what is already known (in-flight).
		neededSet := make(map[ctaut.OutPoint]struct{}) // it is not in the same block
		autTx, err := tx.CTAUTTransaction()
		if err != nil {
			//	if a tx.AUTTransaction() returns error, such a transaction should not be accepted by mempool or a block.
			return err
		}
		if autTx != nil {
			numInCoins := autTx.NumTxInputs()

			txHash := tx.Hash()
			hostedTxIns := tx.MsgTx().TxIns
			startIndex := 0

			for ; startIndex < len(hostedTxIns); startIndex++ {
				// sanity-check
				ringHash := hostedTxIns[startIndex].PreviousOutPointRing.Hash()
				utxoRing := hostView.LookupEntry(ringHash)
				if utxoRing == nil {
					return fmt.Errorf("transaction %s try to mint at height %d but "+
						"the consumed UTXO at Ring %s not exist", txHash, blockHeight, ringHash)
				}
				if len(utxoRing.txOuts) == 0 {
					return fmt.Errorf("transaction %s try to mint at height %d but "+
						"the consumed UTXO at Ring %s has ring size %d, expected %d",
						txHash, blockHeight, ringHash, len(utxoRing.txOuts), 1)
				}
				privacyLevel, err := abecryptox.GetTxoPrivacyLevel(utxoRing.txOuts[0])
				if err != nil {
					return err
				}
				if privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre ||
					privacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
					continue
				}

				if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
					return fmt.Errorf("expect privacy level %d but got %d",
						abecryptoxkey.PrivacyLevelPSEUDONYMCT, privacyLevel)
				}
				break
			}
			if startIndex+numInCoins > len(hostedTxIns) {
				return fmt.Errorf("claim %d (root) coins but only remain %d outputs",
					numInCoins, len(hostedTxIns)-startIndex)
			}

			autTxIns := make([]*ctaut.CTAUTToken, numInCoins)
			for i := 0; i < len(autTxIns); i++ {
				hostIndex := startIndex + i

				// sanity-check
				ringHash := hostedTxIns[startIndex].PreviousOutPointRing.Hash()
				utxoRing := hostView.LookupEntry(ringHash)
				if utxoRing == nil {
					return fmt.Errorf("transaction %s try to mint at height %d but "+
						"the consumed UTXO at Ring %s not exist", txHash, blockHeight, ringHash)
				}
				if len(utxoRing.txOuts) == 0 || len(utxoRing.outPointRing.OutPoints) == 0 {
					return fmt.Errorf("transaction %s try to mint at height %d but "+
						"the consumed UTXO at Ring %s has ring size %d, expected %d",
						txHash, blockHeight, ringHash, len(utxoRing.txOuts), 1)
				}
				privacyLevel, err := abecryptox.GetTxoPrivacyLevel(utxoRing.txOuts[0])
				if err != nil {
					return err
				}
				if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
					return fmt.Errorf("expect privacy level %d but got %d",
						abecryptoxkey.PrivacyLevelPSEUDONYMCT, privacyLevel)
				}

				outpoint := ctaut.OutPoint{
					TxHash: utxoRing.outPointRing.OutPoints[0].TxHash,
					Index:  utxoRing.outPointRing.OutPoints[0].Index,
				}

				coinAddress, err := ctaut.CheckTxoSanity(outpoint.TxHash, int(outpoint.Index), utxoRing.txOuts[hostIndex])
				if err != nil {
					return fmt.Errorf("transaction %s try to mint at height %d but "+
						"the consumed UTXO at Ring %s is not a valid output",
						txHash, blockHeight, hostedTxIns[i].PreviousOutPointRing.Hash())
				}

				// TODO(CTAUT)
				autTxIns[i] = &ctaut.CTAUTToken{
					OutPoint:    outpoint,
					ValueScript: nil, // nil for root coin
					CoinAddress: coinAddress,
				}
			}
			err = autTx.SetTxInputs(autTxIns)
			if err != nil {
				return fmt.Errorf("fail to set aut tx inputs %s", err)
			}

			for _, txIn := range autTxIns {
				autCoin := view.LookupCTAUTCoin(autTx.AUTIdentifier(), txIn.OutPoint)
				if autCoin == nil {
					neededSet[txIn.OutPoint] = struct{}{}
				}
			}
			err = view.fetchCTAUTMain(db, neededSet, autTx.AUTIdentifier())
			if err != nil {
				return err
			}
		}
	}

	// Request the input utxos from the database.
	return nil
}

func (view *CTAUTViewpoint) SpendTransaction(autTx ctaut.Transaction, txHash *chainhash.Hash, blockHeight int32) error {
	var err error
	switch autTransaction := autTx.(type) {
	case *ctaut.RegistrationTx:
		err = view.connectRegistrationTransaction(autTransaction, *txHash, blockHeight, nil)
		if err != nil {
			return err
		}
	case *ctaut.MintTx:
		err = view.connectMintTransaction(autTransaction, *txHash, blockHeight, nil)
		if err != nil {
			return err
		}
	case *ctaut.ReRegistrationTx:
		err = view.connectReRegistrationTransaction(autTransaction, *txHash, blockHeight, nil)
		if err != nil {
			return err
		}

	case *ctaut.TransferTx:
		err = view.connectTransferTransaction(autTransaction, *txHash, blockHeight, nil)
		if err != nil {
			return err
		}

	case *ctaut.BurnTx:
		err = view.connectBurnTransaction(autTransaction, *txHash, blockHeight, nil)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("aut transaction %s with unknown type %d", *txHash, autTx.Type())
	}
	return nil
}

// NewUtxoViewpoint returns a new empty unspent transaction output view.
func NewCTAUTViewpoint() *CTAUTViewpoint {
	return &CTAUTViewpoint{
		instances: make(map[string]*CTAUTInstance),
	}
}

// FetchAUTView loads unspent transaction outputs for the inputs referenced by
// the passed transaction from the point of view of the end of the main chain.
// It also attempts to fetch the utxos for the outputs of the transaction itself
// so the returned view can be examined for duplicate transactions.
//
// This function is safe for concurrent access however the returned view is NOT.
// refactored by Alice 2024.03.01
func (b *BlockChain) FetchCTAUTView(ctAutTx ctaut.Transaction) (*CTAUTViewpoint, error) {
	// Create a set of needed outputs based on those referenced by the
	// inputs of the passed transaction and the outputs of the transaction
	// itself.
	view := NewCTAUTViewpoint()

	if ctAutTx == nil {
		return view, nil
	}

	neededSet := make(map[ctaut.OutPoint]struct{})

	switch autTransaction := ctAutTx.(type) {
	case *ctaut.RegistrationTx:
		// nothing
		// all root coin would be fetched with instance
	case *ctaut.MintTx:
		// nothing
		// all root coin would be fetched with instance
	case *ctaut.ReRegistrationTx:
		// nothing
		// all root coin would be fetched with instance
	case *ctaut.TransferTx:
		for i := 0; i < len(autTransaction.TxIns); i++ {
			neededSet[autTransaction.TxIns[i].OutPoint] = struct{}{}
		}
	case *ctaut.BurnTx:
		for i := 0; i < len(autTransaction.TxIns); i++ {
			neededSet[autTransaction.TxIns[i].OutPoint] = struct{}{}
		}
	default:
		return nil, fmt.Errorf("unknown transaction type for CTAUT")
	}

	var err error
	// Request the coins from the point of view of the end of the main chain.
	func() {
		b.chainLock.RLock()
		defer b.chainLock.RUnlock()

		err = view.fetchCTAUTMain(b.db, neededSet, ctAutTx.AUTIdentifier())
	}()

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
func (b *BlockChain) FetchCTAUTCoin(outpoint ctaut.OutPoint) (*CTAUTCoin, error) {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	var coin *CTAUTCoin
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		coin, err = dbFetchCTAUTCoin(dbTx, outpoint)
		return err
	})
	if err != nil {
		return nil, err
	}

	return coin, nil
}

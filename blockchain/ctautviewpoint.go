package blockchain

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	ctautapi "github.com/abesuite/abec/ctaut/api"

	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/ctaut"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/wire"
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

// AUTCoin houses details about an AUT CTAUTScript output in a AUT
// view such as whether or not it was contained in a AUT Registration CTAUTScript, the height of
// the block that contains the tx, whether or not it is spent, its public key
// script, and how much it pays.
// todo: AutEntry?
type CTAUTInstance struct {
	metadata *ctautapi.AutMetadata
	coins    map[ctautapi.HostOutPoint]*CTAUTCoin
}

func NewCTAUTInstance(metadata *ctautapi.AutMetadata, coins map[ctautapi.HostOutPoint]*CTAUTCoin) *CTAUTInstance {
	return &CTAUTInstance{metadata: metadata, coins: coins}
}

// todo: AddCion
func (instance *CTAUTInstance) Add(outpiont ctaut.HostOutPoint, coin *CTAUTCoin) {
	if instance.coins == nil {
		instance.coins = make(map[ctaut.HostOutPoint]*CTAUTCoin)
	}
	instance.coins[outpiont] = coin
}

func (instance *CTAUTInstance) Metadata() *ctautapi.AutMetadata {
	return instance.metadata
}
func (instance *CTAUTInstance) AUTCoins() map[ctautapi.HostOutPoint]*CTAUTCoin {
	return instance.coins
}

func (instance *CTAUTInstance) SpendCoin(point ctautapi.HostOutPoint) (*CTAUTCoin, error) {
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
	identifier ctaut.AutId
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.
	version     uint32 // TODO
	script      []byte
	blockHeight int32 // Height of block containing tx.

	// packedFlags contains additional info about output such as whether it
	// is a coinbase, whether it is spent, and whether it has been modified
	// since it was loaded.  This approach is used in order to reduce memory
	// usage since there will be a lot of these in memory.
	packedFlags ctAutFlags
}

func (coin *CTAUTCoin) Script() []byte {
	return coin.script
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
func NewCTAUTCoin(version uint32, identifier ctaut.AutId, script []byte, blockHeight int32) *CTAUTCoin {

	return &CTAUTCoin{
		version:     version,
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
func (view *CTAUTViewpoint) LookupCTAUTCoin(identifier ctaut.AutId, outpoint ctaut.HostOutPoint) *CTAUTCoin {
	if view.instances == nil {
		return nil
	}
	instance, ok := view.instances[identifier.String()]
	if !ok {
		return nil
	}
	return instance.coins[outpoint]
}

// todo: function name LookupAutDesc
func (view *CTAUTViewpoint) LookupCTAUTMetaInfo(identifier ctautapi.AutId) *ctautapi.AutMetadata {
	if view.instances == nil {
		return nil
	}
	instance, ok := view.instances[identifier.String()]
	if !ok {
		return nil
	}
	return instance.metadata
}

// addTxOut adds the specified output to the view if it is not provably
// unspendable.  When the view already has an entry for the output, it will be
// marked unspent.  All fields will be updated for existing entries since it's
// possible it has changed during a reorg.
func (view *CTAUTViewpoint) addCTAUTCoin(version uint32, identifier ctaut.AutId, outpoint ctaut.HostOutPoint, script []byte, blockHeight int32) {
	// if the tx is not existing in the utxoentry, create a new one. otherwise update the height of view
	// Update existing entries.  All fields are updated because it's
	// possible (although extremely unlikely) that the existing entry is
	// being replaced by a different transaction with the same hash.  This
	// is allowed so long as the previous transaction is fully spent.
	instance, ok := view.instances[identifier.String()]
	if !ok {
		log.Errorf("unreachable, invalid addAUTToken is called")
		return
	}
	instance.coins[outpoint] = NewCTAUTCoin(version, identifier, script, blockHeight)
}

// todo: remove txHash chainhash.Hash
func (view *CTAUTViewpoint) connectRegistrationScript(script *ctautapi.ExtAutScript, txHash chainhash.Hash,
	blockHeight int32, sctauts *[]SpentCTAUT) error {
	if script.Type() != ctaut.AutScriptTypeRegistration {
		return fmt.Errorf("expected registration script, but got %d", script.Type())
	}

	identifier := script.AutIdentifier()
	identifierKey := identifier.String()
	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if exist && instance != nil && instance.metadata != nil {
		return fmt.Errorf("an registration AUT transaction %s try to register AUT entry with an existing AUT identified by %s",
			txHash, identifierKey)
	}
	// register the AUT entry
	metadata, err := script.CreateAutMetadata()
	if err != nil {
		return err
	}
	instance = NewCTAUTInstance(metadata, nil)
	view.instances[identifierKey] = instance

	if sctauts != nil {
		// Populate the stxo details using the utxo entry.
		var stxo = &UpdatedCTAUTInfo{
			Before:           nil,
			After:            instance.metadata,
			Height:           blockHeight,
			IsReRegistration: false,
		}
		*sctauts = append(*sctauts, stxo)
	}

	log.Debugf("In transaction %s, CT-AUT with identifier %s with following configuration is registered:", txHash, identifierKey)
	log.Debugf("\t Version: %d", metadata.Version)
	log.Debugf("\t Name: %v:", hex.EncodeToString(metadata.AutName))
	log.Debugf("\t Symbol: %v", hex.EncodeToString(metadata.AutSymbol))
	log.Debugf("\t BaseUnitName: %v", hex.EncodeToString(metadata.BaseUnitName))
	log.Debugf("\t SubUnitName: %v", hex.EncodeToString(metadata.SubUnitName))
	log.Debugf("\t UnitScale: %v", metadata.UnitScale)
	log.Debugf("\t Memo: %v", metadata.AutMemo)
	log.Debugf("\t PlannedTotalSupply: %v", metadata.PlannedTotalSupply)
	log.Debugf("\t ReregistrationExpireHeight: %v", metadata.ReregistrationExpireHeight)
	log.Debugf("\t ReregistrationThreshold: %v", metadata.ReregistrationThreshold)
	log.Debugf("\t MintThreshold: %v", metadata.MintThreshold)
	log.Debugf("\t Totoal %d issuers", len(metadata.Issuers))
	for i := 0; i < len(metadata.Issuers); i++ {
		log.Debugf("\t\t [%d] %s", i, metadata.Issuers[i].String())
	}
	log.Debugf("\t Enabled RootCoin: len = %d", len(metadata.ActiveRootTokenSet))
	for point := range metadata.ActiveRootTokenSet {
		log.Debugf("\t\t %s", point)
	}
	log.Debugf("\t Updated Version: len = %d", len(metadata.UpdateScriptVersions))
	for i := 0; i < len(metadata.UpdateScriptVersions); i++ {
		log.Debugf("\t\t %d", metadata.UpdateScriptVersions[i])
	}
	return nil
}

// todo: remove txHash chainhash.Hash
func (view *CTAUTViewpoint) connectReRegistrationScript(script *ctautapi.ExtAutScript, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentCTAUT) error {
	if script.Type() != ctaut.AutScriptTypeReRegistration {
		return fmt.Errorf("expected re-registration script, but got %d", script.Type())
	}

	identifier := script.AutIdentifier()
	identifierKey := identifier.String()
	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return fmt.Errorf("an non-registration AUT transaction %s try to operate on non-existing AUT entry identified by %s",
			txHash, identifierKey)
	}

	// input exist? double spent?
	metadata := instance.metadata
	previousMetadata := metadata.Clone()

	err := script.UpdateAutMetadata(metadata)
	if err != nil {
		return err
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
	log.Debugf("Re-register AUT with identifier %s with following configuration:", identifierKey)
	log.Debugf("\t Version: %d", metadata.Version)
	log.Debugf("\t Memo: %v -> %v", previousMetadata.AutMemo, metadata.AutMemo)
	log.Debugf("\t PlannedTotalSupply: %v -> %v", previousMetadata.PlannedTotalSupply, metadata.PlannedTotalSupply)
	log.Debugf("\t ReregistrationExpireHeight: %v -> %v", previousMetadata.ReregistrationExpireHeight, metadata.ReregistrationExpireHeight)
	log.Debugf("\t ReregistrationThreshold: %v -> %v", previousMetadata.ReregistrationThreshold, metadata.ReregistrationThreshold)
	log.Debugf("\t MintThreshold: %v -> %v", previousMetadata.MintThreshold, metadata.MintThreshold)
	log.Debugf("\t UnitScale: %v -> %v", previousMetadata.UnitScale, metadata.UnitScale)
	log.Debugf("\t Previous Issuers: len = %d", len(previousMetadata.Issuers))
	for i := 0; i < len(previousMetadata.Issuers); i++ {
		log.Debugf("\t\t [%d] %s", i, previousMetadata.Issuers[i].String())
	}
	log.Debugf("\t Current IssuerTokens: len = %d", len(metadata.Issuers))
	for i := 0; i < len(metadata.Issuers); i++ {
		log.Debugf("\t\t [%d] %s", i, metadata.Issuers[i].String())
	}
	log.Debugf("\t Abolished RootCoin: len = %d", len(previousMetadata.ActiveRootTokenSet))
	for point := range previousMetadata.ActiveRootTokenSet {
		log.Debugf("%s", point)
	}
	log.Debugf("\t Enabled RootCoin: len = %d", len(metadata.ActiveRootTokenSet))
	for point := range metadata.ActiveRootTokenSet {
		log.Debugf("%s", point)
	}
	log.Debugf("\t Updated Version: len = %d", len(metadata.UpdateScriptVersions))
	for i := 0; i < len(metadata.UpdateScriptVersions); i++ {
		log.Debugf("\t\t %d", metadata.UpdateScriptVersions[i])
	}
	return nil
}

// todo: remove txHash chainhash.Hash
func (view *CTAUTViewpoint) connectMintScript(script *ctautapi.ExtAutScript, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentCTAUT) error {
	if script.Type() != ctaut.AutScriptTypeMint {
		return fmt.Errorf("expected mint script, but got %d")
	}
	mintScript, ok := script.AutScript.(*ctaut.MintScript)
	if !ok {
		return fmt.Errorf("invalid script type for mint transaction")
	}

	identifier := script.AutIdentifier()
	identifierKey := identifier.String()
	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return fmt.Errorf("an non-registration AUT transaction %s try to operate on non-existing AUT entry identified by %s",
			txHash, identifierKey)
	}

	info := view.instances[identifierKey].Metadata()
	consumedTokens, err := script.ConsumedTokens()
	if err != nil {
		return err
	}
	currentSctauts := make([]SpentCTAUTToken, 0, len(consumedTokens))
	for i := 0; i < len(consumedTokens); i++ {
		if _, ok := info.ActiveRootTokenSet[consumedTokens[i].HostOutPoint.String()]; !ok {
			return fmt.Errorf(`an mint AUT transaction %s try to mint AUT with 
				"non-existing/spent root coin (%s,%d) for AUT identified by %s`,
				txHash, consumedTokens[i].HostOutPoint.TxHash, consumedTokens[i].HostOutPoint.Index,
				identifierKey)
		}
		delete(info.ActiveRootTokenSet, consumedTokens[i].HostOutPoint.String())

		if sctauts != nil {
			var stxo = SpentCTAUTToken{
				Version: consumedTokens[i].Version,
				Script:  nil,
				Height:  blockHeight,
			}
			currentSctauts = append(currentSctauts, stxo)
		}

	}
	// TODO AUT actually do need to use saut to record
	if sctauts != nil {
		sctaut := SpentCTAUTTokens(currentSctauts)
		*sctauts = append(*sctauts, &sctaut)
	}

	// Double check
	// 1. check whether minted amount is exceed planned
	wouldMintedAmount := mintScript.Vin()
	if info.MintedAmount+wouldMintedAmount < info.MintedAmount {
		return fmt.Errorf("an mint AUT transaction %s try to mint AUT exceed planned amount %d for AUT identified by %s",
			txHash, info.PlannedTotalSupply, identifierKey)
	}
	info.MintedAmount += wouldMintedAmount

	// 2. add generated token
	generatedTokens := script.GeneratedTokens()
	for _, token := range generatedTokens {
		view.instances[identifierKey].Add(
			token.HostOutPoint,
			NewCTAUTCoin(token.Version, identifier, token.ValueScript, blockHeight),
		)
	}

	log.Debugf(`Mint %d AUT coins for identifier %s (minted amount %d /planned total amount %d) with %d issuer tokens`,
		wouldMintedAmount, identifierKey,
		info.MintedAmount, info.PlannedTotalSupply,
		len(consumedTokens))
	return nil
}

// todo: remove txHash chainhash.Hash
func (view *CTAUTViewpoint) connectTransferScript(script *ctautapi.ExtAutScript, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentCTAUT) error {
	if script.Type() != ctaut.AutScriptTypeTransfer {
		return fmt.Errorf("expected transfer script, but got %d", script.Type())
	}

	identifier := script.AutIdentifier()
	identifierKey := identifier.String()
	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return fmt.Errorf("an non-registration AUT transaction %s try to operate on non-existing AUT entry identified by %s",
			txHash, identifierKey)
	}

	consumedTokens, err := script.ConsumedTokens()
	if err != nil {
		return err
	}
	var currentSctauts = make([]SpentCTAUTToken, 0, len(consumedTokens))
	for i := 0; i < len(consumedTokens); i++ {
		token, err := instance.SpendCoin(consumedTokens[i].HostOutPoint)
		if err != nil {
			return fmt.Errorf("an transfer AUT transaction %s try to spend "+
				"non-existing/burn token (%s,%d) for AUT identified by %s but fail due to %s",
				txHash, consumedTokens[i].HostOutPoint.TxHash, consumedTokens[i].HostOutPoint.Index,
				identifierKey, err)
		}

		if sctauts != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = SpentCTAUTToken{
				Version: token.version,
				Script:  token.script,
				Height:  blockHeight,
			}
			currentSctauts = append(currentSctauts, stxo)
		}
	}
	if sctauts != nil {
		// Populate the stxo details using the utxo entry.
		sctaut := SpentCTAUTTokens(currentSctauts)
		*sctauts = append(*sctauts, &sctaut)
	}

	generatedTokens := script.GeneratedTokens()
	for i := 0; i < len(generatedTokens); i++ {
		coin := NewCTAUTCoin(generatedTokens[i].Version, identifier, generatedTokens[i].ValueScript, blockHeight)
		view.instances[identifierKey].Add(generatedTokens[i].HostOutPoint, coin)
	}

	return nil
}

// todo: remove txHash chainhash.Hash
func (view *CTAUTViewpoint) connectBurnScript(script *ctautapi.ExtAutScript, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentCTAUT) error {
	if script.Type() != ctaut.AutScriptTypeBurn {
		return fmt.Errorf("expected burn script, but got %d", script.Type())
	}

	identifier := script.AutIdentifier()
	identifierKey := identifier.String()
	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return fmt.Errorf("an non-registration AUT transaction %s try to operate on non-existing AUT entry identified by %s",
			txHash, identifierKey)
	}

	consumedTokens, err := script.ConsumedTokens()
	if err != nil {
		return err
	}
	var currentSctauts = make([]SpentCTAUTToken, 0, len(consumedTokens))
	for i := 0; i < len(consumedTokens); i++ {
		token, err := instance.SpendCoin(consumedTokens[i].HostOutPoint)
		if err != nil {
			return fmt.Errorf("an transfer AUT transaction %s try to spend "+
				"non-existing/burn token (%s,%d) for AUT identified by %s but fail due to %s",
				txHash, consumedTokens[i].HostOutPoint.TxHash, consumedTokens[i].HostOutPoint.Index,
				identifierKey, err)
		}

		if sctauts != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = SpentCTAUTToken{
				Version: token.version,
				Script:  token.script,
				Height:  blockHeight,
			}
			currentSctauts = append(currentSctauts, stxo)
		}
	}
	if sctauts != nil {
		// Populate the stxo details using the utxo entry.
		sctaut := SpentCTAUTTokens(currentSctauts)
		*sctauts = append(*sctauts, &sctaut)
	}

	generatedToken := script.GeneratedTokens()

	// Rule: the last output would be viewed as destroyed/burned
	for i := 0; i < len(generatedToken)-1; i++ {
		coin := NewCTAUTCoin(generatedToken[i].Version, identifier, generatedToken[i].ValueScript, blockHeight)
		view.instances[identifierKey].Add(generatedToken[i].HostOutPoint, coin)
	}
	burnedToken := generatedToken[len(generatedToken)-1]
	// update the burned amount
	autTxo := &ctautwire.AutTxo{}
	err = autTxo.Deserialize(burnedToken.ValueScript)
	if err != nil {
		return err
	}
	burnedValue, err := abecryptox.ExtractAutTxoValue(autTxo, nil, nil)
	if err != nil {
		return err
	}

	if view.instances[identifierKey].metadata.BurnedAmount+burnedValue < view.instances[identifierKey].metadata.BurnedAmount {
		return fmt.Errorf("a CT-AUT burn script in transaction %s try to burn token overflow the burned amount %d for AUT identified by %s",
			txHash, view.instances[identifierKey].metadata.BurnedAmount, identifierKey)
	}
	if view.instances[identifierKey].metadata.BurnedAmount+burnedValue > view.instances[identifierKey].metadata.MintedAmount {
		return fmt.Errorf("a CT-AUT burn script in transaction %s try to burn token exceed the minted amount %d for AUT identified by %s",
			txHash, view.instances[identifierKey].metadata.MintedAmount, identifierKey)
	}
	view.instances[identifierKey].metadata.BurnedAmount += burnedValue

	log.Debugf("outpoint %s for AUT instance %s is burned, token value %d", burnedToken.HostOutPoint, identifierKey, burnedValue)

	return nil
}

// connectTransaction updates the view by adding all new utxos created by the
// passed transaction and marking all utxos that the transactions spend as
// spent.  In addition, when the 'stxos' argument is not nil, it will be updated
// to append an entry for each spent txout.  An error will be returned if the
// view does not contain the required utxos.
// TODO Check consistence with mining.spendTransactionAbe
func (view *CTAUTViewpoint) connectTransaction(tx *abeutil.TxAbe, blockHeight int32, sctauts *[]SpentCTAUT) error {
	script, err := tx.ExtAutScript()
	if err != nil {
		return err
	}
	if script == nil {
		return nil
	}
	txHash := tx.Hash()

	switch script.AutScript.(type) {
	case *ctaut.RegistrationScript:
		err = view.connectRegistrationScript(script, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}
	case *ctaut.ReRegistrationScript:
		err = view.connectReRegistrationScript(script, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}
	case *ctaut.MintScript:
		err = view.connectMintScript(script, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}

	case *ctaut.TransferScript:
		err = view.connectTransferScript(script, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}

	case *ctaut.BurnScript:
		err = view.connectBurnScript(script, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("aut transaction %s with unknown type %d", tx.Hash(), script.Type())
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
func (view *CTAUTViewpoint) disconnectRegistrationTransaction(db database.DB, script *ctautapi.ExtAutScript,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	if script.Type() != ctaut.AutScriptTypeRegistration {
		return nil, fmt.Errorf("expected registration script, but got %d", script.Type())
	}

	identifier := script.AutIdentifier()
	identifierKey := identifier.String()

	err := view.fetchCTAUTMain(db, nil, identifier)
	if err != nil {
		return nil, err
	}

	unregisteredCTAUT := map[string]struct{}{}

	// ensure the instance does exist
	instance, exist := view.instances[identifierKey]
	if !exist || instance == nil || instance.metadata == nil {
		return nil, fmt.Errorf("fail to find the registered AUT instance identified by %s",
			identifierKey)
	}

	// for updated information
	updatedAUTInfo, ok := sctaut.(*UpdatedCTAUTInfo)
	if !ok {
		return nil, fmt.Errorf("invalid updated information")
	}
	// assert
	if updatedAUTInfo.IsReRegistration {
		return nil, fmt.Errorf("invalid updated information: not for registration")
	}
	if updatedAUTInfo.Height != blockHeight {
		return nil, fmt.Errorf("invalid updated information: mismatch block height")
	}

	unregisteredCTAUT[identifierKey] = struct{}{}

	return unregisteredCTAUT, nil
}

func (view *CTAUTViewpoint) disconnectReRegistrationTransaction(db database.DB, script *ctautapi.ExtAutScript,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	if script.Type() != ctaut.AutScriptTypeReRegistration {
		return nil, fmt.Errorf("expected re-registration script, but got %d", script.Type())
	}

	identifier := script.AutIdentifier()
	identifierKey := identifier.String()

	err := view.fetchCTAUTMain(db, nil, identifier)
	if err != nil {
		return nil, err
	}

	// ensure the instance does exist
	instance, exist := view.instances[identifierKey]
	if !exist || instance == nil || instance.metadata == nil {
		return nil, fmt.Errorf("fail to find the registered AUT instance identified by %s",
			identifierKey)
	}

	updatedAUTInfo, ok := sctaut.(*UpdatedCTAUTInfo)
	if !ok {
		return nil, fmt.Errorf("invalid updated information")
	}
	// assert
	if !updatedAUTInfo.IsReRegistration {
		return nil, fmt.Errorf("invalid updated information")
	}
	if updatedAUTInfo.Height != blockHeight {
		return nil, fmt.Errorf("invalid updated information")
	}

	// rollback with spend journal directly
	instance.metadata = updatedAUTInfo.Before.Clone()
	return nil, nil
}

func (view *CTAUTViewpoint) disconnectMintTransaction(db database.DB, script *ctautapi.ExtAutScript,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	if script.Type() != ctaut.AutScriptTypeMint {
		return nil, fmt.Errorf("expected mint script, but got %d", script.Type())
	}

	identifier := script.AutIdentifier()
	identifierKey := identifier.String()

	// fetch outpoint from database if not exist with instance in batch
	outpoints := map[ctautapi.HostOutPoint]struct{}{}
	generatedTokens := script.GeneratedTokens()
	for _, token := range generatedTokens {
		outpoints[token.HostOutPoint] = struct{}{}
	}
	err := view.fetchCTAUTMain(db, outpoints, identifier)
	if err != nil {
		return nil, err
	}

	// ensure the instance does exist
	instance, exist := view.instances[identifierKey]
	if !exist || instance == nil || instance.metadata == nil {
		return nil, fmt.Errorf("fail to find the registered AUT instance identified by %s",
			identifierKey)
	}

	// abolish generate CTAUT coins
	for _, token := range generatedTokens {
		if _, exist := instance.coins[token.HostOutPoint]; !exist {
			return nil, fmt.Errorf("unknown coins %s for AUT instance %s", token.HostOutPoint, identifierKey)
		}
		instance.coins[token.HostOutPoint].Spend()
	}

	// restore consumed CTAUT root coins
	consumedTokens, err := script.ConsumedTokens()
	if err != nil {
		return nil, err
	}
	for _, rootToken := range consumedTokens {
		copiedAUTPoint := &ctautapi.HostOutPoint{}
		copy(copiedAUTPoint.TxHash[:], rootToken.HostOutPoint.TxHash[:])
		copiedAUTPoint.Index = rootToken.HostOutPoint.Index

		instance.metadata.ActiveRootTokenSet[copiedAUTPoint.String()] = copiedAUTPoint
		log.Debugf("try to resume consumed root coin (%s,%d) for AUT identified by %s",
			rootToken.HostOutPoint.TxHash.String(), rootToken.HostOutPoint.Index, identifierKey)
	}

	return nil, nil
}
func (view *CTAUTViewpoint) disconnectTransferTransaction(db database.DB, script *ctautapi.ExtAutScript,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	if script.Type() != ctaut.AutScriptTypeTransfer {
		return nil, fmt.Errorf("expected transfer script, but got %d", script.Type())
	}

	identifier := script.AutIdentifier()
	identifierKey := identifier.String()

	// fetch generate outpoint from database if not exist with instance in batch
	outpoints := map[ctautapi.HostOutPoint]struct{}{}
	generatedTokens := script.GeneratedTokens()
	for _, token := range generatedTokens {
		outpoints[token.HostOutPoint] = struct{}{}
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

	for _, token := range generatedTokens {
		if _, exist := instance.coins[token.HostOutPoint]; !exist {
			return nil, fmt.Errorf("unknown tokens %s for AUT instance %s", token.HostOutPoint, identifierKey)
		}
		instance.coins[token.HostOutPoint].Spend()
	}

	consumedAutTokens, ok := sctaut.(*SpentCTAUTTokens)
	if !ok {
		return nil, fmt.Errorf("invalid updated information")
	}
	consumedTokens, err := script.ConsumedTokens()
	if err != nil {
		return nil, err
	}
	// assert
	if len(consumedTokens) != len(*consumedAutTokens) {
		return nil, fmt.Errorf("mismatched spend journal")
	}
	// TODO(CTAUT) consider order?
	for i := len(*consumedAutTokens) - 1; i >= 0; i-- {
		// TODO it seems there is no way to get script other than here
		token := (*consumedAutTokens)[i]
		coin := consumedTokens[i]
		if _, ok := instance.coins[coin.HostOutPoint]; ok {
			return nil, fmt.Errorf("duplicate coins %s for AUT instance %s", coin.HostOutPoint.String(), identifierKey)
		}
		instance.coins[coin.HostOutPoint] = NewCTAUTCoin(token.Version, identifier, token.Script, blockHeight)
	}

	return nil, nil
}
func (view *CTAUTViewpoint) disconnectBurnTransaction(db database.DB, script *ctautapi.ExtAutScript,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	if script.Type() != ctaut.AutScriptTypeBurn {
		return nil, fmt.Errorf("expected burn script, but got %d", script.Type())
	}

	identifier := script.AutIdentifier()
	identifierKey := identifier.String()

	// fetch outpoint from database if not exist with instance in batch
	outpoints := map[ctautapi.HostOutPoint]struct{}{}
	generatedTokens := script.GeneratedTokens()
	// Note that the last generated token would be burned, and thus not exist in database
	for i := 0; i < len(generatedTokens)-1; i++ {
		token := generatedTokens[i]
		outpoints[token.HostOutPoint] = struct{}{}
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

	// the last generated token would be burned
	for i := len(generatedTokens) - 2; i >= 0; i-- {
		coin := generatedTokens[i]
		if _, exist := instance.coins[coin.HostOutPoint]; !exist {
			return nil, fmt.Errorf("unknown coins %s for AUT instance %s", coin.HostOutPoint, identifierKey)
		}
		instance.coins[coin.HostOutPoint].Spend()
	}
	burnedToken := generatedTokens[len(generatedTokens)-1]
	if _, exist := instance.coins[burnedToken.HostOutPoint]; exist {
		return nil, fmt.Errorf("should not exist coin %s for AUT instance %s", burnedToken.HostOutPoint, identifierKey)
	}
	// update the burned amount
	autTxo := &ctautwire.AutTxo{}
	err = autTxo.Deserialize(burnedToken.ValueScript)
	if err != nil {
		return nil, err
	}
	burnedValue, err := abecryptox.ExtractAutTxoValue(autTxo, nil, nil)
	if err != nil {
		return nil, err
	}
	instance.metadata.BurnedAmount -= burnedValue

	consumedAutTokens, ok := sctaut.(*SpentCTAUTTokens)
	if !ok {
		return nil, fmt.Errorf("invalid updated information")
	}
	claimedConsumedTokens, err := script.ConsumedTokens()
	if err != nil {
		return nil, err
	}
	// assert
	if len(claimedConsumedTokens) != len(*consumedAutTokens) {
		return nil, fmt.Errorf("mismatched spend journal")
	}
	// TODO(CTAUT) consider order?
	for i := len(*consumedAutTokens) - 1; i >= 0; i-- {
		// TODO it seems there is no way to get script other than here
		token := (*consumedAutTokens)[i]
		claimedToken := claimedConsumedTokens[i]
		if _, ok := instance.coins[claimedToken.HostOutPoint]; ok {
			return nil, fmt.Errorf("duplicate coins %s for AUT instance %s", claimedToken.HostOutPoint.String(), identifierKey)
		}
		instance.coins[claimedToken.HostOutPoint] = NewCTAUTCoin(token.Version, identifier, token.Script, blockHeight)
	}

	return nil, nil
}

// disconnectCTAUTScripts updates the view by removing all of the transactions
// created by the passed block, restoring all utxos the transactions spent by
// using the provided spent txo information, and setting the best hash for the
// view to the block before the passed block.
//
// NOTE: saut must not be modified anyway!!!
func (view *CTAUTViewpoint) disconnectCTAUTScripts(db database.DB, block *abeutil.BlockAbe,
	sauts []SpentCTAUT, hostView *UtxoRingViewpoint,
) (map[string]struct{}, error) {

	// Sanity check the correct number of sauts are provided.
	if len(sauts) != countSpentOutputsCTAUT(block) {
		return nil, AssertError("disconnectCTAUTScripts called with bad " +
			"spent transaction out information")
	}

	blockHeight := block.Height()
	// Loop backwards through all ctAutScripts so everything is unspent in
	// reverse order.  This is necessary since ctAutScripts later in a block
	// can spend from previous ones.
	ctAutScripts := block.ExtAutScripts()
	unregisteredCTAUTs := map[string]struct{}{}
	for index := len(ctAutScripts) - 1; index >= 0; index-- {
		ctAutScript := ctAutScripts[index]

		err := ctAutScript.AssembleInputAutTokensStep1(func(ringHash chainhash.Hash) (*wire.TxoRing, error) {
			ringEntry := hostView.LookupEntry(ringHash)
			if ringEntry == nil {
				return nil, errors.New("no such ring found")
			}
			return ringEntry.TxoRing(), nil
		})
		if err != nil {
			return nil, err
		}
		switch ctAutScript.AutScript.(type) {
		case *ctaut.RegistrationScript:
			unregisteredInstances, err := view.disconnectRegistrationTransaction(db, ctAutScript, blockHeight, sauts[index])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}
			for identifier := range unregisteredInstances {
				unregisteredCTAUTs[identifier] = struct{}{}
			}
		case *ctaut.ReRegistrationScript:
			_, err := view.disconnectReRegistrationTransaction(db, ctAutScript, blockHeight, sauts[index])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}
		case *ctaut.MintScript:
			_, err := view.disconnectMintTransaction(db, ctAutScript, blockHeight, sauts[index])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}

		case *ctaut.TransferScript:
			_, err := view.disconnectTransferTransaction(db, ctAutScript, blockHeight, sauts[index])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}

		case *ctaut.BurnScript:
			_, err := view.disconnectBurnTransaction(db, ctAutScript, blockHeight, sauts[index])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}
		default:
			return nil, AssertError("disconnectTransactions called with unknown AUT transaction type")
		}
	}

	// Update the best hash for view to the previous block since all of the
	// ctAutScripts for the current block have been disconnected.
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
func (view *CTAUTViewpoint) fetchCTAUTMain(db database.DB, outpoints map[ctautapi.HostOutPoint]struct{}, identifier ctautapi.AutId) error {
	//if len(identifier) != ctaut.AutIdentifierLength {
	//	return fmt.Errorf("invalid aut identifier:%v", identifier)
	//}

	// Load the requested set of unspent aut transaction outputs from the point
	// of view of the end of the main chain.
	//
	// NOTE: Missing entries are not considered an error here and instead
	// will result in nil entries in the view.  This is intentionally done
	// so other code can use the presence of an entry in the store as a way
	// to unnecessarily avoid attempting to reload it from the database.
	autIdentifierKey := identifier.String()
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

		if view.instances[autIdentifierKey] != nil {
			if view.instances[autIdentifierKey].coins == nil {
				view.instances[autIdentifierKey].coins = make(map[ctautapi.HostOutPoint]*CTAUTCoin, len(outpoints))
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
				if coin == nil {
					return fmt.Errorf("invalid fetch for point (%s, %d) for CTAUT instance %s",
						outpoint.TxHash, outpoint.Index, autIdentifierKey)
				}
				if !bytes.Equal(coin.identifier[:], identifier[:]) {
					return fmt.Errorf("invalid fetch for point (%s, %d) for CTAUT instance %s",
						outpoint.TxHash, outpoint.Index, autIdentifierKey)
				}
				view.instances[autIdentifierKey].coins[outpoint] = coin
			}
		}
		return nil
	})
}

// fetchConsumedCTAUTTokens loads the unspent transaction outputs for the inputs
// referenced by the transactions in the given block into the view from the
// database as needed.  In particular, referenced entries that are earlier in
// the block are added to the view and entries that are already in the view are
// not modified.
func (view *CTAUTViewpoint) fetchConsumedCTAUTTokens(db database.DB, block *abeutil.BlockAbe, hostView *UtxoRingViewpoint) error {
	for _, tx := range block.Transactions()[1:] {
		// Loop through all of the transaction inputs (except for the coinbase
		// which has no inputs) collecting them into sets of what is needed and
		// what is already known (in-flight).
		neededSet := make(map[ctautapi.HostOutPoint]struct{}) // it is not in the same block
		ctAutScript, err := tx.ExtAutScript()
		if err != nil {
			//	if a tx.AUTTransaction() returns error, such a transaction should not be accepted by mempool or a block.
			return err
		}
		if ctAutScript != nil {
			err = ctAutScript.AssembleInputAutTokensStep1(func(ringHash chainhash.Hash) (*wire.TxoRing, error) {
				ringEntry := hostView.LookupEntry(ringHash)
				if ringEntry == nil {
					return nil, errors.New("no such ring found")
				}

				return ringEntry.TxoRing(), nil
			})
			if err != nil {
				return err
			}

			identifier := ctAutScript.AutIdentifier()
			consumedTokens, err := ctAutScript.ConsumedTokens()
			if err != nil {
				return err
			}
			if ctAutScript.Type() == ctaut.AutScriptTypeTransfer || ctAutScript.Type() == ctaut.AutScriptTypeBurn {
				for _, consumedToken := range consumedTokens {
					token := view.LookupCTAUTCoin(identifier, consumedToken.HostOutPoint)
					if token == nil {
						neededSet[consumedToken.HostOutPoint] = struct{}{}
					}
				}
			}

			// Request the input utxos from the database.
			err = view.fetchCTAUTMain(db, neededSet, identifier)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// todo: remove txHash *chainhash.Hash?
func (view *CTAUTViewpoint) SpendCTAutScript(script *ctautapi.ExtAutScript, txHash *chainhash.Hash, blockHeight int32) error {
	var err error
	switch script.AutScript.(type) {
	case *ctaut.RegistrationScript:
		err = view.connectRegistrationScript(script, *txHash, blockHeight, nil)
		if err != nil {
			return err
		}
	case *ctaut.ReRegistrationScript:
		err = view.connectReRegistrationScript(script, *txHash, blockHeight, nil)
		if err != nil {
			return err
		}
	case *ctaut.MintScript:
		err = view.connectMintScript(script, *txHash, blockHeight, nil)
		if err != nil {
			return err
		}
	case *ctaut.TransferScript:
		err = view.connectTransferScript(script, *txHash, blockHeight, nil)
		if err != nil {
			return err
		}
	case *ctaut.BurnScript:
		err = view.connectBurnScript(script, *txHash, blockHeight, nil)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("aut transaction %s with unknown type %d", *txHash, script.Type())
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
func (b *BlockChain) FetchCTAUTView(script *ctautapi.ExtAutScript) (*CTAUTViewpoint, error) {
	// Create a set of needed outputs based on those referenced by the
	// inputs of the passed transaction and the outputs of the transaction
	// itself.
	view := NewCTAUTViewpoint()

	if script == nil {
		return view, nil
	}

	neededSet := make(map[ctaut.HostOutPoint]struct{})

	switch script.AutScript.(type) {
	case *ctaut.RegistrationScript:
		// nothing
		// all root coin would be fetched with instance
	case *ctaut.MintScript:
		// nothing
		// all root coin would be fetched with instance
	case *ctaut.ReRegistrationScript:
		// nothing
		// all root coin would be fetched with instance
	case *ctaut.TransferScript:
		consumedTokens, err := script.ConsumedTokens()
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(consumedTokens); i++ {
			neededSet[consumedTokens[i].HostOutPoint] = struct{}{}
		}
	case *ctaut.BurnScript:
		consumedTokens, err := script.ConsumedTokens()
		if err != nil {
			return nil, err
		}
		for i := 0; i < len(consumedTokens); i++ {
			neededSet[consumedTokens[i].HostOutPoint] = struct{}{}
		}
	default:
		return nil, fmt.Errorf("unknown transaction type for CTAUT")
	}

	var err error
	// Request the coins from the point of view of the end of the main chain.
	func() {
		b.chainLock.RLock()
		defer b.chainLock.RUnlock()

		identifier := script.AutIdentifier()
		err = view.fetchCTAUTMain(b.db, neededSet, identifier)
	}()
	if err != nil {
		return nil, err
	}

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
func (b *BlockChain) FetchCTAUTCoin(outpoint ctaut.HostOutPoint) (*CTAUTCoin, error) {
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

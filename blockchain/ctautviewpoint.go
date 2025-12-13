package blockchain

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chainhash"
	ctautapi "github.com/abesuite/abec/ctaut/api"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
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

// CTAUTInstance houses details about an AUT CTAUTScript output in a AUT
// view such as whether or not it was contained in a AUT Registration CTAUTScript, the height of
// the block that contains the tx, whether or not it is spent, its public key
// script, and how much it pays.
// todo: AutEntry?
// review done 2015.12.11
type CTAUTInstance struct {
	metadata *ctautapi.AutMetadata
	coins    map[ctautapi.HostOutPoint]*CTAUTCoin
}

// NewCTAUTInstance
// review done 2015.12.11
func NewCTAUTInstance(metadata *ctautapi.AutMetadata, coins map[ctautapi.HostOutPoint]*CTAUTCoin) *CTAUTInstance {
	return &CTAUTInstance{metadata: metadata, coins: coins}
}

// PutCoin
// review done 2015.12.13
func (instance *CTAUTInstance) PutCoin(outpiont ctautapi.HostOutPoint, coin *CTAUTCoin) {
	if instance.coins == nil {
		instance.coins = make(map[ctautapi.HostOutPoint]*CTAUTCoin)
	}
	instance.coins[outpiont] = coin
}

// Metadata
// review done 2015.12.11
func (instance *CTAUTInstance) Metadata() *ctautapi.AutMetadata {
	return instance.metadata
}

// AUTCoins
// review done 2015.12.11
func (instance *CTAUTInstance) AUTCoins() map[ctautapi.HostOutPoint]*CTAUTCoin {
	return instance.coins
}

// SpendCoin
// review done 2015.12.12 todo:
func (instance *CTAUTInstance) SpendCoin(point ctautapi.HostOutPoint) (*CTAUTCoin, error) {
	token, exist := instance.coins[point]
	if !exist || token == nil {
		return nil, fmt.Errorf("attempting to spend a non-exist aut coin")
	}
	if token.IsSpent() {
		return nil, fmt.Errorf("attempting spend a spent aut coin")
	}

	token.Spend()

	return token, nil
}

// CTAUTCoin
// review done 2025.12.11
type CTAUTCoin struct {
	identifier ctautapi.AutId
	// NOTE: Additions, deletions, or modifications to the order of the
	// definitions in this struct should not be changed without considering
	// how it affects alignment on 64-bit platforms.  The current order is
	// specifically crafted to result in minimal padding.  There will be a
	// lot of these in memory, so a few extra bytes of padding adds up.
	version     uint32 // TODO
	valueScript []byte // serializedAutTxo is put into this field
	blockHeight int32  // Height of block containing tx.

	// packedFlags contains additional info about output such as whether it
	// is a coinbase, whether it is spent, and whether it has been modified
	// since it was loaded.  This approach is used in order to reduce memory
	// usage since there will be a lot of these in memory.
	packedFlags ctAutFlags
}

// Version
// review done 2025.12.11
func (coin *CTAUTCoin) Version() uint32 {
	return coin.version
}

// ValueScript
// review done 2025.12.11
func (coin *CTAUTCoin) ValueScript() []byte {
	return coin.valueScript
}

// isModified returns whether or not the output has been modified since it was
// loaded.
// review done 2025.12.11
func (coin *CTAUTCoin) isModified() bool {
	return coin.packedFlags&cafModified == cafModified
}

// IsSpent returns whether or not the output has been spent based upon the
// current state of the unspent transaction output view it was obtained from.
// review done 2025.12.11
func (coin *CTAUTCoin) IsSpent() bool {
	return coin.packedFlags&cafSpent == cafSpent
}

// BlockHeight returns the height of the block containing the output.
// review done 2025.12.11
func (coin *CTAUTCoin) BlockHeight() int32 {
	return coin.blockHeight
}

// Spend marks the output as spent.  Spending an output that is already spent
// has no effect.
// todo: review
func (coin *CTAUTCoin) Spend() {
	// Nothing to do if the output is already spent.
	if coin.IsSpent() {
		return
	}

	// Mark the output as spent and modified.
	coin.packedFlags |= cafSpent | cafModified
}

// Clone returns a shallow copy of the utxo entry.
// review done 2025.12.11
func (coin *CTAUTCoin) Clone() *CTAUTCoin {
	if coin == nil {
		return nil
	}

	valueScript := make([]byte, len(coin.valueScript))
	copy(valueScript, coin.valueScript)
	return &CTAUTCoin{
		identifier:  coin.identifier,
		valueScript: valueScript,
		blockHeight: coin.blockHeight,
		packedFlags: coin.packedFlags,
	}
}

// todo: function name

// NewCTAUTCoin returns a new CTAUTCoin built from the arguments.
// todo: review
func NewCTAUTCoin(version uint32, identifier ctautapi.AutId, valueScript []byte, blockHeight int32) *CTAUTCoin {

	return &CTAUTCoin{
		version:     version,
		identifier:  identifier,
		valueScript: valueScript,
		blockHeight: blockHeight,
		packedFlags: cafModified,
	}
}

// CTAUTViewpoint represents a view into the set of unspent transaction outputs
// from a specific point of view in the chain.  For example, it could be for
// the end of the main chain, some point in the history of the main chain, or
// down a side chain.
//
// The unspent outputs are needed by other transactions for things such as
// script validation and double spend prevention.
//
//	todo: using AutIdentifier as key to store AutEntries.
//
// review done 2025.12.11, todo: add Add and Lookup AutInstance methods.
type CTAUTViewpoint struct {
	instances map[string]*CTAUTInstance
	bestHash  chainhash.Hash
}

// BestHash returns the hash of the best block in the chain the view currently
// respresents.
// review done 2025.12.11
func (view *CTAUTViewpoint) BestHash() *chainhash.Hash {
	return &view.bestHash
}

// SetBestHash sets the hash of the best block in the chain the view currently
// respresents.
// review done 2025.12.11
func (view *CTAUTViewpoint) SetBestHash(hash *chainhash.Hash) {
	view.bestHash = *hash
}

// Instances
// review done 2025.12.11
func (view *CTAUTViewpoint) Instances() map[string]*CTAUTInstance {
	return view.instances
}

// SetInstances
// review done 2025.12.11
func (view *CTAUTViewpoint) SetInstances(instances map[string]*CTAUTInstance) {
	view.instances = instances
}

func (view *CTAUTViewpoint) PutInstance(instance *CTAUTInstance) error {
	if instance == nil {
		return fmt.Errorf("attempting to put a nil instance")
	}
	if instance.metadata == nil {
		return fmt.Errorf("attempting to put an instance with nil metadata")
	}

	if view.instances == nil {
		view.instances = make(map[string]*CTAUTInstance)
	}

	identifierKey := instance.metadata.AutIdentifier.String()
	view.instances[identifierKey] = instance

	return nil
}

// LookupCTAUTCoin returns information about a given transaction output according to
// the current state of the view.  It will return nil if the passed output does
// not exist in the view or is otherwise not available such as when it has been
// disconnected during a reorg.
// todo: function name LookupAutCoin
// review done 2025.12.11
func (view *CTAUTViewpoint) LookupCTAUTCoin(identifier ctautapi.AutId, outpoint ctautapi.HostOutPoint) *CTAUTCoin {
	if view.instances == nil {
		return nil
	}
	instance, ok := view.instances[identifier.String()]
	if !ok {
		return nil
	}
	if instance == nil {
		return nil
	}

	return instance.coins[outpoint]
}

// LookupCTAUTMetaInfo
// review done 2025.12.11
// todo: function name LookupAutDesc
func (view *CTAUTViewpoint) LookupCTAUTMetaInfo(identifier ctautapi.AutId) *ctautapi.AutMetadata {
	if view.instances == nil {
		return nil
	}
	instance, ok := view.instances[identifier.String()]
	if !ok {
		return nil
	}
	if instance == nil {
		return nil
	}

	return instance.metadata
}
func (view *CTAUTViewpoint) SpendRootToken(identifier ctautapi.AutId, outpoint ctautapi.HostOutPoint) error {
	if view.instances == nil {
		return fmt.Errorf("no instance for identifier %v", identifier.String())
	}

	instance, ok := view.instances[identifier.String()]
	if !ok {
		return fmt.Errorf("no instance for identifier %v", identifier.String())
	}
	if instance == nil || instance.metadata == nil {
		return fmt.Errorf("no instance for identifier %v", identifier.String())
	}

	metadata := instance.metadata
	opStr := outpoint.String()
	if _, ok := metadata.ActiveRootTokenSet[opStr]; !ok {
		return fmt.Errorf("no root token %s for identifier %v", opStr, identifier.String())
	}
	delete(metadata.ActiveRootTokenSet, opStr)

	return nil
}

func (view *CTAUTViewpoint) SpendCTAUTCoin(identifier ctautapi.AutId, outpoint ctautapi.HostOutPoint) error {
	if view.instances == nil {
		return fmt.Errorf("no instance for identifier %v", identifier.String())
	}

	instance, ok := view.instances[identifier.String()]
	if !ok {
		return fmt.Errorf("no instance for identifier %v", identifier.String())
	}
	if instance == nil {
		return fmt.Errorf("no instance for identifier %v", identifier.String())
	}

	_, err := instance.SpendCoin(outpoint)
	if err != nil {
		return err
	}

	return nil
}

// addCTAUTCoin adds the specified output to the view if it is not provably
// unspendable.  When the view already has an entry for the output, it will be
// marked unspent.  All fields will be updated for existing entries since it's
// possible it has changed during a reorg.
func (view *CTAUTViewpoint) addCTAUTCoin(version uint32, identifier ctautapi.AutId, outpoint ctautapi.HostOutPoint, valueScript []byte, blockHeight int32) error {
	// if the tx is not existing in the utxoentry, create a new one. otherwise update the height of view
	// Update existing entries.  All fields are updated because it's
	// possible (although extremely unlikely) that the existing entry is
	// being replaced by a different transaction with the same hash.  This
	// is allowed so long as the previous transaction is fully spent.
	instance, ok := view.instances[identifier.String()]
	if !ok {
		return fmt.Errorf("unreachable, invalid addAUTToken is called")
	}
	if instance.coins == nil {
		instance.coins = make(map[ctautapi.HostOutPoint]*CTAUTCoin)
	}
	instance.coins[outpoint] = NewCTAUTCoin(version, identifier, valueScript, blockHeight)
	return nil
}

// todo: review the following codes

// todo: remove txHash chainhash.Hash
func (view *CTAUTViewpoint) connectRegistrationScript(script *ctautapi.ExtAutScript, txHash chainhash.Hash,
	blockHeight int32, sctauts *[]SpentCTAUT) error {
	if script.Type() != ctautapi.AutScriptTypeRegistration {
		return fmt.Errorf("expected registration script, but got %d", script.Type())
	}

	identifier := script.AutIdentifier()
	autMetadata := view.LookupCTAUTMetaInfo(identifier)
	if autMetadata != nil {
		return fmt.Errorf("an registration AUT transaction %s try to register AUT entry with an existing AUT identified by %s",
			txHash, identifier.String())
	}
	newAutMetadata, err := script.CreateAutMetadata()
	if err != nil {
		return err
	}
	newInstance := NewCTAUTInstance(newAutMetadata, nil)
	if err = view.PutInstance(newInstance); err != nil {
		return err
	}

	if sctauts != nil {
		// Populate the stxo details using the utxo entry.
		var stxo = &UpdatedCTAUTInfo{
			Before:           nil,
			After:            newAutMetadata,
			Height:           blockHeight,
			IsReRegistration: false,
		}
		*sctauts = append(*sctauts, stxo)
	}

	log.Debugf("In transaction %s, CT-AUT with identifier %s with following configuration is registered:", txHash, identifier.String())
	log.Debugf("\t Version: %d", newAutMetadata.Version)
	log.Debugf("\t Name: %v:", hex.EncodeToString(newAutMetadata.AutName))
	log.Debugf("\t Symbol: %v", hex.EncodeToString(newAutMetadata.AutSymbol))
	log.Debugf("\t BaseUnitName: %v", hex.EncodeToString(newAutMetadata.BaseUnitName))
	log.Debugf("\t SubUnitName: %v", hex.EncodeToString(newAutMetadata.SubUnitName))
	log.Debugf("\t UnitScale: %v", newAutMetadata.UnitScale)
	log.Debugf("\t Memo: %v", newAutMetadata.AutMemo)
	log.Debugf("\t PlannedTotalSupply: %v", newAutMetadata.PlannedTotalSupply)
	log.Debugf("\t ReregistrationExpireHeight: %v", newAutMetadata.ReregistrationExpireHeight)
	log.Debugf("\t ReregistrationThreshold: %v", newAutMetadata.ReregistrationThreshold)
	log.Debugf("\t MintThreshold: %v", newAutMetadata.MintThreshold)
	log.Debugf("\t PrivacyType: %v", newAutMetadata.PrivacyType)
	log.Debugf("\t Totoal %d issuers", len(newAutMetadata.Issuers))
	for i := 0; i < len(newAutMetadata.Issuers); i++ {
		log.Debugf("\t\t [%d] %s", i, newAutMetadata.Issuers[i].String())
	}
	log.Debugf("\t Enabled RootCoin: len = %d", len(newAutMetadata.ActiveRootTokenSet))
	for point := range newAutMetadata.ActiveRootTokenSet {
		log.Debugf("\t\t %s", point)
	}
	log.Debugf("\t Updated Version: len = %d", len(newAutMetadata.UpdateScriptVersions))
	for i := 0; i < len(newAutMetadata.UpdateScriptVersions); i++ {
		log.Debugf("\t\t %d", newAutMetadata.UpdateScriptVersions[i])
	}
	return nil
}

// todo: remove txHash chainhash.Hash
// todo: review 2025.12.12; note that no input no output
func (view *CTAUTViewpoint) connectReRegistrationScript(script *ctautapi.ExtAutScript, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentCTAUT) error {
	if script.Type() != ctautapi.AutScriptTypeReRegistration {
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

	// todo: 2025.12.12 use a new variable for updatedMetadata
	metadata, err := script.UpdateAutMetadata(metadata)
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
	log.Debugf("\t PrivacyType: %v -> %v", previousMetadata.PrivacyType, metadata.PrivacyType)
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
// todo: review 2025.12.12
func (view *CTAUTViewpoint) connectMintScript(extAutScript *ctautapi.ExtAutScript, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentCTAUT) error {
	if extAutScript.Type() != ctautapi.AutScriptTypeMint {
		return fmt.Errorf("expected mint script, but got %d", extAutScript.Type())
	}
	mintScript, ok := extAutScript.AutScript.(*ctautapi.MintScript)
	if !ok {
		return fmt.Errorf("invalid script type for mint transaction")
	}

	identifier := extAutScript.AutIdentifier()
	identifierKey := identifier.String()
	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return fmt.Errorf("an non-registration AUT transaction %s try to operate on non-existing AUT entry identified by %s",
			txHash, identifierKey)
	}

	info := view.instances[identifierKey].Metadata()

	currentSctauts := make([]SpentCTAUTToken, 0, mintScript.NumConsumedTokens())
	consumedHostOutpoints := extAutScript.ConsumedHostOutpoints()
	for i := 0; i < len(consumedHostOutpoints); i++ {
		hostOutpoint := consumedHostOutpoints[i]
		if _, ok := info.ActiveRootTokenSet[hostOutpoint.String()]; !ok {
			return fmt.Errorf(`an mint AUT transaction %s try to mint AUT with 
				"non-existing/spent root coin (%s,%d) for AUT identified by %s`,
				txHash, hostOutpoint.TxHash, hostOutpoint.Index,
				identifierKey)
		}
		delete(info.ActiveRootTokenSet, hostOutpoint.String())

		if sctauts != nil {
			var stxo = SpentCTAUTToken{
				Version:     mintScript.Version(),
				ValueScript: nil,
				Height:      blockHeight,
			}
			currentSctauts = append(currentSctauts, stxo)
		}

	}
	// TODO AUT actually do need to use saut to record
	// todo: 2025.12.12 why first currentSctauts then sctauts; sctauts is a strange structure
	if sctauts != nil {
		sctaut := SpentCTAUTTokens(currentSctauts)
		*sctauts = append(*sctauts, &sctaut)
	}

	// Double check
	// 1. check whether minted amount is exceed planned
	// todo: 2025.12.12 use PlannedTotalSupply
	wouldMintedAmount := mintScript.Vin()
	if info.MintedAmount+wouldMintedAmount < info.MintedAmount {
		return fmt.Errorf("an mint AUT transaction %s try to mint AUT exceed planned amount %d for AUT identified by %s",
			txHash, info.PlannedTotalSupply, identifierKey)
	}
	info.MintedAmount += wouldMintedAmount

	// 2. add generated token
	// todo: 2025.12.12 is making a reuseable function for differnet callers? for Spend, does not need to generate outputTokens
	// todo: not that his may cause/allow the spending of pending AutTxo.
	// todo: the available autTokens should be first decided by corresponding TxIn of the host-Tx, then double-checked by AutTokens.
	// so, they should be always melt together.
	generatedTokens := extAutScript.GeneratedTokens()
	for _, token := range generatedTokens {
		view.instances[identifierKey].PutCoin(
			token.HostOutPoint,
			NewCTAUTCoin(token.Version, identifier, token.ValueScript, blockHeight),
		)
	}

	log.Debugf(`Mint %d AUT coins for identifier %s (minted amount %d /planned total amount %d) with %d root tokens`,
		wouldMintedAmount, identifierKey,
		info.MintedAmount, info.PlannedTotalSupply,
		len(consumedHostOutpoints))
	return nil
}

// todo: review 2025.12.12
// todo: remove txHash chainhash.Hash
func (view *CTAUTViewpoint) connectTransferScript(extAutScript *ctautapi.ExtAutScript, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentCTAUT) error {
	if extAutScript.Type() != ctautapi.AutScriptTypeTransfer {
		return fmt.Errorf("expected transfer script, but got %d", extAutScript.Type())
	}

	identifier := extAutScript.AutIdentifier()
	identifierKey := identifier.String()
	instance, exist := view.instances[identifierKey]
	// todo: view adds a LookupAutInstance method.
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return fmt.Errorf("an non-registration AUT transaction %s try to operate on non-existing AUT entry identified by %s",
			txHash, identifierKey)
	}

	consumedHostOutpoints := extAutScript.ConsumedHostOutpoints()
	currentSctauts := make([]SpentCTAUTToken, 0, len(consumedHostOutpoints))
	for i := 0; i < len(consumedHostOutpoints); i++ {
		hostOutpoint := consumedHostOutpoints[i]

		token, err := instance.SpendCoin(*hostOutpoint)
		if err != nil {
			return fmt.Errorf("an transfer AUT transaction %s try to spend "+
				"non-existing/burn token (%s,%d) for AUT identified by %s but fail due to %s",
				txHash, hostOutpoint.TxHash, hostOutpoint.Index,
				identifierKey, err)
		}

		if sctauts != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = SpentCTAUTToken{
				Version:     token.version,
				ValueScript: token.valueScript,
				Height:      blockHeight,
			}
			currentSctauts = append(currentSctauts, stxo)
		}
	}
	if sctauts != nil {
		// Populate the stxo details using the utxo entry.
		sctaut := SpentCTAUTTokens(currentSctauts)
		*sctauts = append(*sctauts, &sctaut)
	}

	// todo: for connect, this part is useful.
	generatedTokens := extAutScript.GeneratedTokens()
	for i := 0; i < len(generatedTokens); i++ {
		coin := NewCTAUTCoin(generatedTokens[i].Version, identifier, generatedTokens[i].ValueScript, blockHeight)
		view.instances[identifierKey].PutCoin(generatedTokens[i].HostOutPoint, coin)
	}

	return nil
}

// todo: review 2025.12.12
// todo: remove txHash chainhash.Hash
func (view *CTAUTViewpoint) connectBurnScript(extAutScript *ctautapi.ExtAutScript, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentCTAUT) error {
	if extAutScript.Type() != ctautapi.AutScriptTypeBurn {
		return fmt.Errorf("expected burn script, but got %d", extAutScript.Type())
	}

	identifier := extAutScript.AutIdentifier()
	identifierKey := identifier.String()
	instance, exist := view.instances[identifierKey]
	// TODO(CTAUT) assert rule need match the initialization
	if !exist || instance == nil || instance.metadata == nil {
		return fmt.Errorf("an non-registration AUT transaction %s try to operate on non-existing AUT entry identified by %s",
			txHash, identifierKey)
	}

	consumedHostOutpoints := extAutScript.ConsumedHostOutpoints()
	currentSctauts := make([]SpentCTAUTToken, 0, len(consumedHostOutpoints))
	for i := 0; i < len(consumedHostOutpoints); i++ {
		hostOutpoint := consumedHostOutpoints[i]

		token, err := instance.SpendCoin(*hostOutpoint)
		if err != nil {
			return fmt.Errorf("an transfer AUT transaction %s try to spend "+
				"non-existing/burn token (%s,%d) for AUT identified by %s but fail due to %s",
				txHash, hostOutpoint.TxHash, hostOutpoint.Index,
				identifierKey, err)
		}

		if sctauts != nil {
			// Populate the stxo details using the utxo entry.
			var stxo = SpentCTAUTToken{
				Version:     token.version,
				ValueScript: token.valueScript,
				Height:      blockHeight,
			}
			currentSctauts = append(currentSctauts, stxo)
		}
	}
	if sctauts != nil {
		// Populate the stxo details using the utxo entry.
		sctaut := SpentCTAUTTokens(currentSctauts)
		*sctauts = append(*sctauts, &sctaut)
	}

	generatedToken := extAutScript.GeneratedTokens()

	// Rule: the last output would be viewed as destroyed/burned
	for i := 0; i < len(generatedToken)-1; i++ {
		coin := NewCTAUTCoin(generatedToken[i].Version, identifier, generatedToken[i].ValueScript, blockHeight)
		view.instances[identifierKey].PutCoin(generatedToken[i].HostOutPoint, coin)
	}
	burnedToken := generatedToken[len(generatedToken)-1]
	// update the burned amount
	autTxo := &ctautwire.AutTxo{}
	err := autTxo.Deserialize(burnedToken.ValueScript)
	if err != nil {
		return err
	}
	burnedValue, err := abecryptox.ExtractAutTxoValue(autTxo, nil, nil)
	if err != nil {
		return err
	}

	// todo: use more naive computation
	if view.instances[identifierKey].metadata.BurnedAmount+burnedValue < view.instances[identifierKey].metadata.BurnedAmount {
		return fmt.Errorf("a CT-AUT burn script in transaction %s try to burn token overflow the burned amount %d for AUT identified by %s",
			txHash, view.instances[identifierKey].metadata.BurnedAmount, identifierKey)
	}
	if view.instances[identifierKey].metadata.BurnedAmount+burnedValue > view.instances[identifierKey].metadata.MintedAmount {
		return fmt.Errorf("a CT-AUT burn script in transaction %s try to burn token exceed the minted amount %d for AUT identified by %s",
			txHash, view.instances[identifierKey].metadata.MintedAmount, identifierKey)
	}
	view.instances[identifierKey].metadata.BurnedAmount += burnedValue

	log.Debugf("outpoint %s for AUT instance %s is burned, token value %d", burnedToken.HostOutPoint.String(), identifierKey, burnedValue)

	return nil
}

// connectTransaction updates the view by adding all new utxos created by the
// passed transaction and marking all utxos that the transactions spend as
// spent.  In addition, when the 'stxos' argument is not nil, it will be updated
// to append an entry for each spent txout.  An error will be returned if the
// view does not contain the required utxos.
// TODO Check consistence with mining.spendTransactionAbe
func (view *CTAUTViewpoint) connectTransaction(tx *abeutil.TxAbe, blockHeight int32, sctauts *[]SpentCTAUT) error {
	extAutScript := tx.ExtAutScript()
	if extAutScript == nil {
		return nil
	}

	txHash := tx.Hash()

	switch extAutScript.AutScript.(type) {
	case *ctautapi.RegistrationScript:
		err := view.connectRegistrationScript(extAutScript, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}
	case *ctautapi.ReRegistrationScript:
		err := view.connectReRegistrationScript(extAutScript, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}
	case *ctautapi.MintScript:
		err := view.connectMintScript(extAutScript, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}

	case *ctautapi.TransferScript:
		err := view.connectTransferScript(extAutScript, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}

	case *ctautapi.BurnScript:
		err := view.connectBurnScript(extAutScript, *txHash, blockHeight, sctauts)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("aut transaction %s with unknown type %d", tx.Hash(), extAutScript.Type())
	}

	return nil
}

// connectTransactions updates the view by adding all new utxos created by all
// of the transactions in the passed block, marking all utxos the transactions
// spend as spent, and setting the best hash for the view to the passed block.
// In addition, when the 'stxos' argument is not nil, it will be updated to
// append an entry for each spent txout.
// todo: 2025.12.13 put into hostview.connectTransactions, or remove, since the connectTransaction is put into hostview.connectTransaction
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
	if script.Type() != ctautapi.AutScriptTypeRegistration {
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
	if script.Type() != ctautapi.AutScriptTypeReRegistration {
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

func (view *CTAUTViewpoint) disconnectMintTransaction(db database.DB, extAutScript *ctautapi.ExtAutScript,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	if extAutScript.Type() != ctautapi.AutScriptTypeMint {
		return nil, fmt.Errorf("expected mint script, but got %d", extAutScript.Type())
	}

	identifier := extAutScript.AutIdentifier()
	identifierKey := identifier.String()

	// fetch outpoint from database if not exist with instance in batch
	outpoints := map[ctautapi.HostOutPoint]struct{}{}
	generatedTokens := extAutScript.GeneratedTokens()
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
	consumedHostOutpoints := extAutScript.ConsumedHostOutpoints()
	for i := 0; i < len(consumedHostOutpoints); i++ {
		hostOutpoint := consumedHostOutpoints[i]

		copiedAUTPoint := &ctautapi.HostOutPoint{}
		copy(copiedAUTPoint.TxHash[:], hostOutpoint.TxHash[:])
		copiedAUTPoint.Index = hostOutpoint.Index

		instance.metadata.ActiveRootTokenSet[copiedAUTPoint.String()] = copiedAUTPoint
		log.Debugf("try to resume consumed root coin (%s,%d) for AUT identified by %s",
			hostOutpoint.TxHash.String(), hostOutpoint.Index, identifierKey)
	}

	return nil, nil
}
func (view *CTAUTViewpoint) disconnectTransferTransaction(db database.DB, extAutScript *ctautapi.ExtAutScript,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	if extAutScript.Type() != ctautapi.AutScriptTypeTransfer {
		return nil, fmt.Errorf("expected transfer script, but got %d", extAutScript.Type())
	}

	identifier := extAutScript.AutIdentifier()
	identifierKey := identifier.String()

	// fetch generate outpoint from database if not exist with instance in batch
	outpoints := map[ctautapi.HostOutPoint]struct{}{}
	generatedTokens := extAutScript.GeneratedTokens()
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
	consumedHostOutpoints := extAutScript.ConsumedHostOutpoints()
	// assert
	if len(consumedHostOutpoints) != len(*consumedAutTokens) {
		return nil, fmt.Errorf("mismatched spend journal")
	}
	// TODO(CTAUT) consider order?
	for i := len(*consumedAutTokens) - 1; i >= 0; i-- {
		// TODO it seems there is no way to get script other than here
		token := (*consumedAutTokens)[i]
		hostOutpoint := consumedHostOutpoints[i]
		if _, ok := instance.coins[*hostOutpoint]; ok {
			return nil, fmt.Errorf("duplicate coins %s for AUT instance %s", hostOutpoint.String(), identifierKey)
		}
		instance.coins[*hostOutpoint] = NewCTAUTCoin(token.Version, identifier, token.ValueScript, blockHeight)
	}

	return nil, nil
}
func (view *CTAUTViewpoint) disconnectBurnTransaction(db database.DB, extAutScript *ctautapi.ExtAutScript,
	blockHeight int32, sctaut SpentCTAUT) (map[string]struct{}, error) {
	if extAutScript.Type() != ctautapi.AutScriptTypeBurn {
		return nil, fmt.Errorf("expected burn script, but got %d", extAutScript.Type())
	}

	identifier := extAutScript.AutIdentifier()
	identifierKey := identifier.String()

	// fetch outpoint from database if not exist with instance in batch
	outpoints := map[ctautapi.HostOutPoint]struct{}{}
	generatedTokens := extAutScript.GeneratedTokens()
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
			return nil, fmt.Errorf("unknown coins %s for AUT instance %s", coin.HostOutPoint.String(), identifierKey)
		}
		instance.coins[coin.HostOutPoint].Spend()
	}
	burnedToken := generatedTokens[len(generatedTokens)-1]
	if _, exist := instance.coins[burnedToken.HostOutPoint]; exist {
		return nil, fmt.Errorf("should not exist coin %s for AUT instance %s", burnedToken.HostOutPoint.String(), identifierKey)
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
	consumedHostOutpoints := extAutScript.ConsumedHostOutpoints()
	// assert
	if len(consumedHostOutpoints) != len(*consumedAutTokens) {
		return nil, fmt.Errorf("mismatched spend journal")
	}
	// TODO(CTAUT) consider order?
	for i := len(*consumedAutTokens) - 1; i >= 0; i-- {
		// TODO it seems there is no way to get script other than here
		token := (*consumedAutTokens)[i]
		hostOutpoint := consumedHostOutpoints[i]
		if _, ok := instance.coins[*hostOutpoint]; ok {
			return nil, fmt.Errorf("duplicate coins %s for AUT instance %s", hostOutpoint.String(), identifierKey)
		}
		instance.coins[*hostOutpoint] = NewCTAUTCoin(token.Version, identifier, token.ValueScript, blockHeight)
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

		switch ctAutScript.AutScript.(type) {
		case *ctautapi.RegistrationScript:
			unregisteredInstances, err := view.disconnectRegistrationTransaction(db, ctAutScript, blockHeight, sauts[index])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}
			for identifier := range unregisteredInstances {
				unregisteredCTAUTs[identifier] = struct{}{}
			}
		case *ctautapi.ReRegistrationScript:
			_, err := view.disconnectReRegistrationTransaction(db, ctAutScript, blockHeight, sauts[index])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}
		case *ctautapi.MintScript:
			_, err := view.disconnectMintTransaction(db, ctAutScript, blockHeight, sauts[index])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}

		case *ctautapi.TransferScript:
			_, err := view.disconnectTransferTransaction(db, ctAutScript, blockHeight, sauts[index])
			if err != nil {
				return nil, AssertError(fmt.Sprintf("disconnectTransactions called with bad "+
					"spent transaction out information: %s", err))
			}

		case *ctautapi.BurnScript:
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
//
// This function fetches autCoins of AutInstance with identifier, as well as the AutInstance's metadata.
// review done 2025.12.12
// todo: rename to a more accurate one
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
					// todo: initialize coins 2025.12.11; should use New function for CTAUTInstance
				}
			}
		} else {
			// 2025.12.13 Note that view is a memory object, it is assumed that it is more fresh than the database.
			// So, if view contains the AutInstance, it does not load it from database.
		}

		if view.instances[autIdentifierKey] != nil {
			if view.instances[autIdentifierKey].coins == nil {
				view.instances[autIdentifierKey].coins = make(map[ctautapi.HostOutPoint]*CTAUTCoin, len(outpoints))
			}
			for outpoint := range outpoints {
				// when the view has corresponding outpoints, do not
				// fetch from database, it means that outpoint has fetched
				if view.instances[autIdentifierKey].coins[outpoint] != nil {
					// memory is more fresh than database
					continue
				}

				coin, err := dbFetchCTAUTCoin(dbTx, outpoint)
				if err != nil {
					return err
				}
				// assert
				if coin == nil {
					return fmt.Errorf("invalid fetch for point (%s, %d) for AUT instance %s",
						outpoint.TxHash, outpoint.Index, autIdentifierKey)
				}
				if !bytes.Equal(coin.identifier[:], identifier[:]) {
					return fmt.Errorf("invalid fetch for point (%s, %d) for AUT instance %s",
						outpoint.TxHash, outpoint.Index, autIdentifierKey)
				}
				view.instances[autIdentifierKey].coins[outpoint] = coin
			}
		}
		return nil
	})
}

func (view *CTAUTViewpoint) fetchCTAUTMetadata(db database.DB, identifier ctautapi.AutId) (*CTAUTInstance, error) {
	autIdentifierKey := identifier.String()

	instance, ok := view.instances[autIdentifierKey]
	if ok {
		return instance, nil
	}

	err := db.View(func(dbTx database.Tx) error {
		// firstly, fetch the meta information for specified identifier
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
		return nil
	})
	if err != nil {
		return nil, err
	}

	// if no such instance, return error
	if view.instances[autIdentifierKey] == nil {
		return nil, fmt.Errorf("no such CTAUT instance found")
	}

	return view.instances[autIdentifierKey], nil
}
func (view *CTAUTViewpoint) fetchCTAUTToken(db database.DB, identifier ctautapi.AutId, outpoint ctautapi.HostOutPoint) (*CTAUTCoin, error) {
	autIdentifierKey := identifier.String()

	instance, err := view.fetchCTAUTMetadata(db, identifier)
	if err != nil {
		return nil, fmt.Errorf("fail to get CTAUT instance")
	}
	if instance == nil {
		return nil, fmt.Errorf("no such CTAUT instance found")
	}

	// check whether the coin fetched before
	coin := instance.coins[outpoint]
	if coin != nil {
		return coin, nil
	}

	// otherwise, fetch from database
	if instance.coins == nil {
		instance.coins = map[ctautapi.HostOutPoint]*CTAUTCoin{}
	}
	err = db.View(func(dbTx database.Tx) error {
		coin, err = dbFetchCTAUTCoin(dbTx, outpoint)
		if err != nil {
			return err
		}

		if coin != nil {
			view.instances[autIdentifierKey].coins[outpoint] = coin
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// check again
	coin = view.instances[autIdentifierKey].coins[outpoint]
	if coin != nil {
		return coin, nil
	}
	// if still nil, return error
	if coin == nil {
		return nil, fmt.Errorf("no such CTAUT coin found")
	}
	return coin, nil
}

// fetchConsumedCTAUTTokens loads the unspent transaction outputs for the inputs
// referenced by the transactions in the given block into the view from the
// database as needed.  In particular, referenced entries that are earlier in
// the block are added to the view and entries that are already in the view are
// not modified.
// review done 2025.12.12
func (view *CTAUTViewpoint) fetchConsumedCTAUTTokens(db database.DB, block *abeutil.BlockAbe, hostView *UtxoRingViewpoint) error {
	for i, ctAutScript := range block.ExtAutScripts() {
		// Loop through all of the transaction inputs (except for the coinbase
		// which has no inputs) collecting them into sets of what is needed and
		// what is already known (in-flight).
		if ctAutScript == nil {
			return fmt.Errorf("the block.ExtAutScripts()[%d]  is nil", i)
		}

		consumedHostOutpoints := ctAutScript.ConsumedHostOutpoints()
		neededSet := make(map[ctautapi.HostOutPoint]struct{}, len(consumedHostOutpoints))
		// todo: should not use the following if, so that AutMetadata that AutScriptTypeReregister and AutScriptTypeMint are also fetched
		if ctAutScript.Type() == ctautapi.AutScriptTypeTransfer || ctAutScript.Type() == ctautapi.AutScriptTypeBurn {
			for i := 0; i < len(consumedHostOutpoints); i++ {
				neededSet[*consumedHostOutpoints[i]] = struct{}{}
			}
		}
		err := view.fetchCTAUTMain(db, neededSet, ctAutScript.AutIdentifier())
		if err != nil {
			return err
		}
	}

	return nil
}

func (view *CTAUTViewpoint) AddMetadata(metadata *ctautapi.AutMetadata) error {
	identifierKey := metadata.AutIdentifier.String()
	if view.instances[identifierKey] != nil {
		return fmt.Errorf("duplicate AUT instance %s", identifierKey)
	}

	view.instances[metadata.AutIdentifier.String()] = &CTAUTInstance{
		metadata: metadata,
	}
	return nil
}

func (view *CTAUTViewpoint) AddToken(outpoint ctautapi.HostOutPoint, token *CTAUTCoin) error {
	identifierKey := token.identifier.String()
	if view.instances[identifierKey] == nil {
		return fmt.Errorf("no such identifier %s", identifierKey)
	}
	if view.instances[identifierKey].coins == nil {
		view.instances[identifierKey].coins = make(map[ctautapi.HostOutPoint]*CTAUTCoin)
	}
	if view.instances[identifierKey].coins[outpoint] != nil {
		return fmt.Errorf("duplicate token %s", outpoint.String())
	}
	view.instances[identifierKey].coins[outpoint] = token
	return nil
}

// NewUtxoViewpoint returns a new empty unspent transaction output view.
func NewCTAUTViewpoint() *CTAUTViewpoint {
	return &CTAUTViewpoint{
		instances: make(map[string]*CTAUTInstance),
	}
}

// FetchCTAUTView loads unspent transaction outputs for the inputs referenced by
// the passed transaction from the point of view of the end of the main chain.
// It also attempts to fetch the utxos for the outputs of the transaction itself
// so the returned view can be examined for duplicate transactions.
//
// This function is safe for concurrent access however the returned view is NOT.
// refactored by Alice 2024.03.01
// aut review done 2025.12.12 todo: discuss and confirm
func (b *BlockChain) FetchCTAUTView(script *ctautapi.ExtAutScript) (*CTAUTViewpoint, error) {
	// Create a set of needed outputs based on those referenced by the
	// inputs of the passed transaction and the outputs of the transaction
	// itself.
	view := NewCTAUTViewpoint()

	if script == nil {
		return view, nil
	}

	neededSet := make(map[ctautapi.HostOutPoint]struct{})

	switch script.AutScript.(type) {
	case *ctautapi.RegistrationScript:
		// nothing
		// all root coin would be fetched with instance
		// AutRootTokens exist in a special manner,
		// say, they do not have corresponding "real coins" stored in blockchain data,
		// and only virtually exist in AutMetadata.
	case *ctautapi.ReRegistrationScript:
		// nothing
		// all root coin would be fetched with instance
	case *ctautapi.MintScript:
		// nothing
		// all root coin would be fetched with instance
	case *ctautapi.TransferScript:
		consumedHostOutpoints := script.ConsumedHostOutpoints()
		for i := 0; i < len(consumedHostOutpoints); i++ {
			neededSet[*consumedHostOutpoints[i]] = struct{}{}
		}
	case *ctautapi.BurnScript:
		consumedHostOutpoints := script.ConsumedHostOutpoints()
		for i := 0; i < len(consumedHostOutpoints); i++ {
			neededSet[*consumedHostOutpoints[i]] = struct{}{}
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

func (b *BlockChain) FetchCTAUTMetadata(identifier ctautapi.AutId) (*ctautapi.AutMetadata, error) {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	return b.fetchCTAUTMetadata(identifier)
}

func (b *BlockChain) fetchCTAUTMetadata(identifier ctautapi.AutId) (*ctautapi.AutMetadata, error) {
	var metadata *ctautapi.AutMetadata
	err := b.db.View(func(dbTx database.Tx) error {
		// firstly, fetch the meta information for specified identifier
		// fetch aut info with root coin
		var err error
		metadata, err = dbFetchCTAUTMetadata(dbTx, identifier)
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return metadata, nil
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
func (b *BlockChain) fetchCTAUTToken(identifier ctautapi.AutId, outpoint ctautapi.HostOutPoint) (*CTAUTCoin, error) {
	var coin *CTAUTCoin
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		coin, err = dbFetchCTAUTCoin(dbTx, outpoint)
		return err
	})
	if err != nil {
		return nil, err
	}

	if coin == nil {
		return nil, fmt.Errorf("no such CTAUT coin found")
	}
	if !bytes.Equal(coin.identifier[:], identifier[:]) {
		return nil, fmt.Errorf("no such CTAUT coin found")
	}

	return coin, nil
}

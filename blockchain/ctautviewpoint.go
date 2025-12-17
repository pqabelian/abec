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
// todo: refactor view.PutCoin(autIdentifier, outPoint, CTAUTCoin) 2025.12.16
func (instance *CTAUTInstance) PutCoin(outpiont ctautapi.HostOutPoint, coin *CTAUTCoin) {
	if instance.coins == nil {
		instance.coins = make(map[ctautapi.HostOutPoint]*CTAUTCoin)
	}
	instance.coins[outpiont] = coin
}

// SetAutMetadata
// review done 2015.12.16
func (instance *CTAUTInstance) SetAutMetadata(autMetadata *ctautapi.AutMetadata) {
	if instance == nil {
		return
	}

	instance.metadata = autMetadata
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
// review done 2015.12.16
// The spentCoin's status-change is already in instance.coins,
// and the returned CTAUTCoin is just for the ease of the caller to directly obtain the coin.
// It is expected that the caller should not modify the returned CTAUTCoin.
func (instance *CTAUTInstance) SpendCoin(point ctautapi.HostOutPoint) (*CTAUTCoin, error) {
	if instance == nil {
		return nil, fmt.Errorf("the receiver instance for SpendCoin is nil")
	}

	if instance.coins == nil {
		return nil, fmt.Errorf("the instance has no coins")
	}

	token, exist := instance.coins[point]
	if !exist || token == nil {
		return nil, fmt.Errorf("attempting to spend a non-exist aut coin on outpoint %s", point.String())
	}

	if token.IsSpent() {
		return nil, fmt.Errorf("attempting spend a spent aut coin on outpoint %s", point.String())
	}

	token.Spend()

	return token, nil
}

// CTAUTCoin
// review done 2025.12.11
// todo: 2025.12.17 add hostOutPoint field in CTAUTCoin: not add at 2025.12;
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
// aut review done 2025.12.16
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
// aut review done 2025.12.16
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

// PutInstance
// aut review done 2025.12.16
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
	if view == nil {
		return nil
	}

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
	if view == nil {
		return nil
	}

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

// SpendRootToken
// au review done 2025.12.15
func (view *CTAUTViewpoint) SpendRootToken(identifier ctautapi.AutId, outpoint ctautapi.HostOutPoint) error {
	if view == nil {
		return fmt.Errorf("the receiver view is nil")
	}
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

// AddMintAmount adds the input mintAmount to the mintedAmount.
// review done 2025.12.16
func (view *CTAUTViewpoint) AddMintAmount(identifier ctautapi.AutId, mintAmount uint64) error {
	if view == nil {
		return fmt.Errorf("the receiver view is nil")
	}

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

	if metadata.MintedAmount > metadata.PlannedTotalSupply {
		// just an assertion
		return fmt.Errorf("autInstance (%v) has MintedAmount (%d) while its PlannedTotalSupply is %d ",
			identifier, metadata.MintedAmount, metadata.PlannedTotalSupply)
	}
	maxAllowed := metadata.PlannedTotalSupply - metadata.MintedAmount // uint64, >=0

	if mintAmount > maxAllowed {
		return fmt.Errorf("autInstance (%v) has MintedAmount (%d) and PlannedTotalSupply (%d), "+
			"fail to attempt add mintAmount (%d)",
			identifier, metadata.MintedAmount, metadata.PlannedTotalSupply, mintAmount)
	}

	metadata.MintedAmount = metadata.MintedAmount + mintAmount

	return nil
}

// AddBurnAmount adds the input mintAmount to the mintedAmount.
// aut review done 2025.12.16
func (view *CTAUTViewpoint) AddBurnAmount(identifier ctautapi.AutId, burnAmount uint64) error {
	if view == nil {
		return fmt.Errorf("the receiver view is nil")
	}

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

	// Note that the metadata.BurnedAmount is limited by the TransferRule,
	// so that it actually never violates the following check.
	// Don't worry the case : a pending tx increases the MintedAmount and fail to mined in block, some txs burned more than the allowed value.
	if metadata.BurnedAmount > metadata.MintedAmount {
		return fmt.Errorf("instnace (%v) has BurnedAmount (%d) while its MintedAmount is %d",
			identifier, metadata.BurnedAmount, metadata.MintedAmount)
	}
	maxAllowed := metadata.MintedAmount - metadata.BurnedAmount // uint64, >=0
	if burnAmount > maxAllowed {
		return fmt.Errorf("instnace (%v) has BurnedAmount (%d) and MintedAmount (%d), fail to attempt add burnAmount (%d)",
			identifier, metadata.BurnedAmount, metadata.MintedAmount, burnAmount)
	}

	metadata.BurnedAmount = metadata.BurnedAmount + burnAmount

	return nil
}

// SpendCTAUTCoin
// aut review done, 2025.12.16
func (view *CTAUTViewpoint) SpendCTAUTCoin(identifier ctautapi.AutId, outpoint ctautapi.HostOutPoint) error {
	if view == nil {
		return fmt.Errorf("the receiver view is nil")
	}

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

// todo: remove txHash chainhash.Hash
// aut review done 2025.12.16
func (view *CTAUTViewpoint) connectRegistrationScript(extAutScript *ctautapi.ExtAutScript, txHash chainhash.Hash,
	blockHeight int32, sctauts *[]SpentAut) error {

	if view == nil {
		return fmt.Errorf("connectRegistrationScript: the receiver view is nil")
	}

	if extAutScript == nil {
		return fmt.Errorf("connectRegistrationScript: extAutScript is nil")
	}

	if extAutScript.Type() != ctautapi.AutScriptTypeRegistration {
		return fmt.Errorf("expected registration script, but got %d", extAutScript.Type())
	}

	identifier := extAutScript.AutIdentifier()
	autMetadata := view.LookupCTAUTMetaInfo(identifier)
	if autMetadata != nil {
		return fmt.Errorf("an AutRegistrationScript in transaction %s attempts to register a new AutInstance "+
			"with an existing identifier %s",
			txHash.String(), identifier.String())
	}

	newAutMetadata, err := extAutScript.CreateAutMetadata(blockHeight)
	if err != nil {
		return err
	}
	newInstance := NewCTAUTInstance(newAutMetadata, nil)
	if err = view.PutInstance(newInstance); err != nil {
		return err
	}

	if sctauts != nil {
		// Populate the stxo details.
		// Note that for New AutInetance, the SpentAutInstance should have GeneratedHeight=SpentHeight.
		saut := NewSpentAutInstance(blockHeight, blockHeight,
			false, nil, newAutMetadata.Clone())
		*sctauts = append(*sctauts, saut)
	}

	log.Debugf("In transaction %s, CT-AUT with identifier %s with following configuration is registered:", txHash, identifier.String())
	log.Debugf("\t Version: %d", newAutMetadata.Version)
	log.Debugf("\t UpdatedHeight: %d", newAutMetadata.UpdatedHeight)
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
	log.Debugf("\t Updated Hieght: len = %d", len(newAutMetadata.UpdateHistoryHeights))
	for i := 0; i < len(newAutMetadata.UpdateHistoryHeights); i++ {
		log.Debugf("\t\t %d", newAutMetadata.UpdateHistoryHeights[i])
	}
	return nil
}

// connectReRegistrationScript
// todo: remove txHash chainhash.Hash
// review 2025.12.12 done
func (view *CTAUTViewpoint) connectReRegistrationScript(extAutScript *ctautapi.ExtAutScript, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentAut) error {
	if view == nil {
		return fmt.Errorf("connectReRegistrationScript: the receiver view is nil")
	}

	if extAutScript == nil {
		return fmt.Errorf("connectReRegistrationScript: extAutScript is nil")
	}

	if extAutScript.Type() != ctautapi.AutScriptTypeReRegistration {
		return fmt.Errorf("expected re-registration script, but got %d", extAutScript.Type())
	}

	identifier := extAutScript.AutIdentifier()
	identifierKey := identifier.String()
	autInstance, exist := view.instances[identifierKey]
	if !exist || autInstance == nil || autInstance.metadata == nil {
		return fmt.Errorf("an AutReRegistracitonScript in transaction (%s) attempts to operate on an AutInstance(%s) "+
			"but it is not found in database", txHash.String(), identifier.String())
	}

	oldMetadata := autInstance.metadata

	newMetadata, err := extAutScript.UpdateAutMetadata(oldMetadata.Clone(), blockHeight)
	if err != nil {
		return err
	}
	// Note that, by the above 2 lines codes, newMetadata's ActiveRootTokens are those specified by AutReRegistrationScript.

	if sctauts != nil {
		// Populate the saut.
		saut := NewSpentAutInstance(blockHeight, oldMetadata.UpdatedHeight,
			true, oldMetadata.Clone(), newMetadata.Clone())
		*sctauts = append(*sctauts, saut)
	}

	// update aut metadata
	// todo: view add method for updateMetadata
	// Note that following 2 lines perform the update of view caused by the AutReRegistrationScript.
	// explicitly put it back
	autInstance.metadata = newMetadata
	view.instances[identifierKey] = autInstance

	log.Debugf("Re-register AUT with identifier %s with following configuration:", identifierKey)
	log.Debugf("\t Version: %d --> %d", oldMetadata.Version, newMetadata.Version)
	log.Debugf("\t UpdatedHeight: %d --> %d", oldMetadata.UpdatedHeight, newMetadata.UpdatedHeight)
	log.Debugf("\t Memo: %v -> %v", oldMetadata.AutMemo, newMetadata.AutMemo)
	log.Debugf("\t PlannedTotalSupply: %v -> %v", oldMetadata.PlannedTotalSupply, newMetadata.PlannedTotalSupply)
	log.Debugf("\t ReregistrationExpireHeight: %v -> %v", oldMetadata.ReregistrationExpireHeight, newMetadata.ReregistrationExpireHeight)
	log.Debugf("\t ReregistrationThreshold: %v -> %v", oldMetadata.ReregistrationThreshold, newMetadata.ReregistrationThreshold)
	log.Debugf("\t MintThreshold: %v -> %v", oldMetadata.MintThreshold, newMetadata.MintThreshold)
	log.Debugf("\t UnitScale: %v -> %v", oldMetadata.UnitScale, newMetadata.UnitScale)
	log.Debugf("\t PrivacyType: %v -> %v", oldMetadata.PrivacyType, newMetadata.PrivacyType)
	log.Debugf("\t Previous Issuers: len = %d", len(oldMetadata.Issuers))
	for i := 0; i < len(oldMetadata.Issuers); i++ {
		log.Debugf("\t\t [%d] %s", i, oldMetadata.Issuers[i].String())
	}
	log.Debugf("\t Current IssuerTokens: len = %d", len(newMetadata.Issuers))
	for i := 0; i < len(newMetadata.Issuers); i++ {
		log.Debugf("\t\t [%d] %s", i, newMetadata.Issuers[i].String())
	}
	log.Debugf("\t Abolished RootCoin: len = %d", len(oldMetadata.ActiveRootTokenSet))
	for point := range oldMetadata.ActiveRootTokenSet {
		log.Debugf("%s", point)
	}
	log.Debugf("\t Enabled RootCoin: len = %d", len(newMetadata.ActiveRootTokenSet))
	for point := range newMetadata.ActiveRootTokenSet {
		log.Debugf("%s", point)
	}
	log.Debugf("\t Updated Version: len = %d", len(newMetadata.UpdateScriptVersions))
	for i := 0; i < len(newMetadata.UpdateScriptVersions); i++ {
		log.Debugf("\t\t %d", newMetadata.UpdateScriptVersions[i])
	}
	log.Debugf("\t Updated Heights: len = %d", len(newMetadata.UpdateHistoryHeights))
	for i := 0; i < len(newMetadata.UpdateHistoryHeights); i++ {
		log.Debugf("\t\t %d", newMetadata.UpdateHistoryHeights[i])
	}

	return nil
}

// connectMintScript
// todo: remove txHash chainhash.Hash
// review 2025.12.16 done
func (view *CTAUTViewpoint) connectMintScript(extAutScript *ctautapi.ExtAutScript, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentAut) error {
	if view == nil {
		return fmt.Errorf("connectMintScript: the receiver view is nil")
	}

	if extAutScript == nil {
		return fmt.Errorf("connectMintScript: extAutScript is nil")
	}

	if extAutScript.Type() != ctautapi.AutScriptTypeMint {
		return fmt.Errorf("expected mint script, but got %d", extAutScript.Type())
	}
	mintScript, ok := extAutScript.AutScript.(*ctautapi.MintScript)
	if !ok {
		return fmt.Errorf("invalid script type for mint transaction")
	}

	identifier := extAutScript.AutIdentifier()
	identifierKey := identifier.String()
	autInstance, exist := view.instances[identifierKey]
	if !exist || autInstance == nil || autInstance.metadata == nil {
		return fmt.Errorf("an AutMintScript in transaction (%s) attempts to operate on an AutInstance(%s) "+
			"but it is not found in database", txHash.String(), identifier.String())
	}
	oldMetadata := autInstance.metadata
	rootTokenVersion := oldMetadata.UpdateScriptVersions[len(oldMetadata.UpdateScriptVersions)-1]

	newMetadata := oldMetadata.Clone()

	txSpentAutTokens := make([]*SpentAutToken, 0, mintScript.NumConsumedTokens())
	consumedHostOutpoints := extAutScript.ConsumedHostOutpoints()
	for i := 0; i < len(consumedHostOutpoints); i++ {
		hostOutpoint := consumedHostOutpoints[i]
		hostOpStr := hostOutpoint.String()
		if _, ok := newMetadata.ActiveRootTokenSet[hostOpStr]; !ok {
			return fmt.Errorf("an AutMintScript in transaction (%s) attempts to mint tokens for AutInstance(%s) with "+
				"non-existing/spent root coin (%s)",
				txHash.String(), identifier.String(), hostOutpoint.String())
		}
		delete(newMetadata.ActiveRootTokenSet, hostOpStr)

		// todo: the sctatus for mint is different from that for reregistration? how to rollback? use UpdatedCTAUTInfo?
		if sctauts != nil {
			spentAutToken := NewSpentAutToken(oldMetadata.UpdatedHeight, rootTokenVersion,
				*hostOutpoint, true, nil)
			txSpentAutTokens = append(txSpentAutTokens, spentAutToken)
		}

	}
	// TODO AUT actually do need to use saut to record
	if sctauts != nil {
		spentAutTokenList := NewSpentAutTokenList(blockHeight, txSpentAutTokens)
		*sctauts = append(*sctauts, spentAutTokenList)
	}

	// Double check
	// 1. check whether minted amount is exceed planned
	if newMetadata.MintedAmount > newMetadata.PlannedTotalSupply {
		return fmt.Errorf("the AutInstance (%s) has MintedAmount (%d), while its PlannedTotalSupply is %d",
			identifier.String(), newMetadata.MintedAmount, newMetadata.PlannedTotalSupply)
	}
	maxAllowedToMint := newMetadata.PlannedTotalSupply - newMetadata.MintedAmount // uint64, >=0
	if mintScript.Vin() > maxAllowedToMint {
		return fmt.Errorf("the AutInstance (%s) has MintedAmount (%d) and PlannedTotalSupply (%d), "+
			"fail to mint new %d",
			identifier.String(), newMetadata.MintedAmount, newMetadata.PlannedTotalSupply, mintScript.Vin())
	}

	newMetadata.MintedAmount = newMetadata.MintedAmount + mintScript.Vin()

	// 2. add generated token
	// Not that this will not cause the spending of pending AutTxo, due to the host-mechanism.
	generatedTokens := extAutScript.GeneratedTokens()
	for i, newToken := range generatedTokens {
		if newToken == nil {
			return fmt.Errorf("an AutMintScript in AutInstance (%s) has carries nil at its GeneratedTokens[%d]",
				identifier.String(), i)
		}

		newCoin := NewCTAUTCoin(newToken.Version, identifier, newToken.ValueScript, blockHeight)
		autInstance.PutCoin(newToken.HostOutPoint, newCoin)
	}

	// explicitly put it back
	autInstance.metadata = newMetadata
	view.instances[identifierKey] = autInstance

	log.Debugf("Mint %d Aut coins for AutInstance %s (previous minted amount %d, planned total amount %d) with %d root tokens",
		mintScript.Vin(), identifier.String(),
		oldMetadata.MintedAmount, oldMetadata.PlannedTotalSupply,
		len(consumedHostOutpoints))

	return nil
}

// connectTransferScript
// review 2025.12.12 done
// todo: remove txHash chainhash.Hash
func (view *CTAUTViewpoint) connectTransferScript(extAutScript *ctautapi.ExtAutScript, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentAut) error {
	if view == nil {
		return fmt.Errorf("connectTransferScript: the receiver view is nil")
	}

	if extAutScript == nil {
		return fmt.Errorf("connectTransferScript: extAutScript is nil")
	}

	if extAutScript.Type() != ctautapi.AutScriptTypeTransfer {
		return fmt.Errorf("expected transfer script, but got %d", extAutScript.Type())
	}

	identifier := extAutScript.AutIdentifier()
	identifierKey := identifier.String()
	autInstance, exist := view.instances[identifierKey]
	// todo: view adds a LookupAutInstance method.
	if !exist || autInstance == nil || autInstance.metadata == nil {
		return fmt.Errorf("an AutTransferScript in transaction (%s) attempts to operate on an AutInstance(%s) "+
			"but it is not found in database", txHash.String(), identifier.String())
	}

	consumedHostOutpoints := extAutScript.ConsumedHostOutpoints()
	txSpentAutTokens := make([]*SpentAutToken, 0, len(consumedHostOutpoints))
	for i := 0; i < len(consumedHostOutpoints); i++ {
		hostOutpoint := consumedHostOutpoints[i]

		consumedToken, err := autInstance.SpendCoin(*hostOutpoint)
		if err != nil {
			return fmt.Errorf("an AutTransferScript in transaction (%s) attempts to spend "+
				"aut token on OutPoint %s for AutInstance (%s), but fail due to %v",
				txHash.String(), hostOutpoint.String(), identifierKey, err)
		}

		if sctauts != nil {
			// Populate the sAutToken
			spentAutToken := NewSpentAutToken(consumedToken.blockHeight, consumedToken.version,
				*hostOutpoint, false, consumedToken.valueScript)
			txSpentAutTokens = append(txSpentAutTokens, spentAutToken)
		}
	}
	if sctauts != nil {
		// Populate the stxo details using the utxo entry.
		spentAutTokenList := NewSpentAutTokenList(blockHeight, txSpentAutTokens)
		*sctauts = append(*sctauts, spentAutTokenList)
	}

	generatedTokens := extAutScript.GeneratedTokens()
	for i, outputToken := range generatedTokens {
		if outputToken == nil {
			return fmt.Errorf("an AutTransferScript in transaction (%s) carries nil at its GeneratedTokens[%d]",
				txHash.String(), i)
		}
		coin := NewCTAUTCoin(outputToken.Version, identifier, outputToken.ValueScript, blockHeight)
		autInstance.PutCoin(outputToken.HostOutPoint, coin)
	}

	// explicitly put it back
	view.instances[identifierKey] = autInstance

	return nil
}

// review 2025.12.12 done
// todo: remove txHash chainhash.Hash
func (view *CTAUTViewpoint) connectBurnScript(extAutScript *ctautapi.ExtAutScript, txHash chainhash.Hash, blockHeight int32, sctauts *[]SpentAut) error {
	if view == nil {
		return fmt.Errorf("connectBurnScript: the receiver view is nil")
	}

	if extAutScript == nil {
		return fmt.Errorf("connectBurnScript: extAutScript is nil")
	}

	if extAutScript.Type() != ctautapi.AutScriptTypeBurn {
		return fmt.Errorf("expected burn script, but got %d", extAutScript.Type())
	}

	identifier := extAutScript.AutIdentifier()
	identifierKey := identifier.String()
	autInstance, exist := view.instances[identifierKey]
	if !exist || autInstance == nil || autInstance.metadata == nil {
		return fmt.Errorf("an AutBurnScript in transaction (%s) attempts to operate on an AutInstance(%s) "+
			"but it is not found in database", txHash.String(), identifier.String())
	}
	newMetadata := autInstance.metadata.Clone()

	consumedHostOutpoints := extAutScript.ConsumedHostOutpoints()
	txSpentAutTokens := make([]*SpentAutToken, 0, len(consumedHostOutpoints))
	for i := 0; i < len(consumedHostOutpoints); i++ {
		hostOutpoint := consumedHostOutpoints[i]

		consumedToken, err := autInstance.SpendCoin(*hostOutpoint)
		if err != nil {
			return fmt.Errorf("an AutBurnScript in transaction (%s) attempts to spend "+
				"aut token on OutPoint %s for AutInstance (%s), but fail due to %v",
				txHash.String(), hostOutpoint.String(), identifierKey, err)
		}

		if sctauts != nil {
			// Populate the spentAutToken.
			spentAutToken := NewSpentAutToken(consumedToken.blockHeight, consumedToken.version,
				*hostOutpoint, false, consumedToken.valueScript)
			txSpentAutTokens = append(txSpentAutTokens, spentAutToken)
		}
	}
	if sctauts != nil {
		// Populate the stxo details using the utxo entry.
		spentAutTokenList := NewSpentAutTokenList(blockHeight, txSpentAutTokens)
		*sctauts = append(*sctauts, spentAutTokenList)
	}

	// Output Tokens
	generatedToken := extAutScript.GeneratedTokens()
	if len(generatedToken) == 0 {
		return fmt.Errorf("an AutBurnScript in transaction (%s) carries nil/empty GeneratedTokens",
			txHash.String())
	}

	// Rule: the last output would be viewed as destroyed/burned
	for i := 0; i < len(generatedToken)-1; i++ {
		outputToken := generatedToken[i]
		if outputToken == nil {
			return fmt.Errorf("an AutBurnScript in transaction (%s) carries nil at its GeneratedTokens[%d]",
				txHash.String(), i)
		}

		coin := NewCTAUTCoin(outputToken.Version, identifier, outputToken.ValueScript, blockHeight)
		autInstance.PutCoin(outputToken.HostOutPoint, coin)
	}

	// update AutMetadata.BurnedAmount
	burnedToken := generatedToken[len(generatedToken)-1]
	if burnedToken == nil {
		return fmt.Errorf("an AutBurnScript in transaction (%s) carries nil at its last position [%d], which should be a burned token",
			txHash.String(), len(generatedToken)-1)
	}

	autTxo := &ctautwire.AutTxo{}
	err := autTxo.Deserialize(burnedToken.ValueScript)
	if err != nil {
		return err
	}
	burnValue, err := abecryptox.ExtractAutTxoValue(autTxo, nil, nil)
	if err != nil {
		return err
	}

	// Note that this check is just for logic-completeness and will not be violated,
	// since the AutBurnScript is just a special AutTransferScript and is limited by the Transfer-Rules.
	if newMetadata.BurnedAmount > newMetadata.MintedAmount {
		return fmt.Errorf("the AutInstance (%s) has BurnedAmount (%d), while its MintedAmount is %d",
			identifier.String(), newMetadata.BurnedAmount, newMetadata.MintedAmount)
	}
	maxAllowedToBurn := newMetadata.MintedAmount - newMetadata.BurnedAmount // uint64, >=0
	if burnValue > maxAllowedToBurn {
		return fmt.Errorf("the AutInstance (%s) has BurnedAmount (%d) and MintedAmount (%d), "+
			"fail to burn new %d",
			identifier.String(), newMetadata.BurnedAmount, newMetadata.MintedAmount, burnValue)
	}
	newMetadata.BurnedAmount = newMetadata.BurnedAmount + burnValue

	// explicitly put it back
	autInstance.metadata = newMetadata
	view.instances[identifierKey] = autInstance

	log.Debugf("outpoint %s for AUT instance %s is burned, token value %d", burnedToken.HostOutPoint.String(), identifierKey, burnValue)

	return nil
}

// connectTransaction updates the view by adding all new utxos created by the
// passed transaction and marking all utxos that the transactions spend as
// spent.  In addition, when the 'stxos' argument is not nil, it will be updated
// to append an entry for each spent txout.  An error will be returned if the
// view does not contain the required utxos.
// TODO Check consistence with mining.spendTransactionAbe
// aut review done 2025.12.16
func (view *CTAUTViewpoint) connectTransactionAutScript(tx *abeutil.TxAbe, blockHeight int32, sctauts *[]SpentAut) error {
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

// todo: review the following codes
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
		// TODO assert?
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
		// TODO assert?
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
// aut review done, 2025.12.17; make data in memory to be consistent with that in database.
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
// review done 2025.12.16
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
				if coin != nil {
					if !bytes.Equal(coin.identifier[:], identifier[:]) {
						return fmt.Errorf("invalid fetch for point (%s, %d) for AUT instance %s",
							outpoint.TxHash, outpoint.Index, autIdentifierKey)
					}
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
	for t, ctAutScript := range block.ExtAutScripts() {
		// Loop through all of the transaction inputs (except for the coinbase
		// which has no inputs) collecting them into sets of what is needed and
		// what is already known (in-flight).
		if ctAutScript == nil {
			return fmt.Errorf("the block.ExtAutScripts()[%d]  is nil", t)
		}

		consumedHostOutpoints := ctAutScript.ConsumedHostOutpoints()
		neededSet := make(map[ctautapi.HostOutPoint]struct{}, len(consumedHostOutpoints))
		// Note that AutMetadata that AutScriptTypeReregister, AutScriptTypeReReregister, and AutScriptTypeMint are also fetched,
		// and neededSet is only for autCoins.
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

	view.instances[identifierKey] = &CTAUTInstance{
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

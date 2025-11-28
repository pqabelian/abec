package extscript

import (
	"bytes"
	"fmt"
	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/ctaut/rules"
	"github.com/abesuite/abec/ctaut/script"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/wire"
)

// ExtAutScript is used to collect the input Tokens and generate output Tokens by the AutScript,
// based on the information of host-Tx and AutScript.
type ExtAutScript struct {
	script.AutScript

	// Note that for following 2 fields:
	// - if the value is nil, it means that the tokens is not set
	// - if the value is empty slice, it means that the tokens is set but has no token
	inputHandled   bool //	indicate whether consumedTokens has been handled
	consumedTokens []*AutToken

	outputHandled   bool //	indicate whether generatedTokens has been handled
	generatedTokens []*AutToken
}

func NewExtAutScript(autScript script.AutScript) *ExtAutScript {
	extAutScript := &ExtAutScript{
		AutScript: autScript,
	}

	extAutScript.consumedTokens = nil
	extAutScript.inputHandled = false

	extAutScript.generatedTokens = nil
	extAutScript.outputHandled = false

	return extAutScript
}

// AssembleOutputAutTokens would get the specified host output from the host transaction
func (extAutScript *ExtAutScript) AssembleOutputAutTokens(txMsg *wire.MsgTxAbe) error {
	txOuts := txMsg.TxOuts
	txHash := txMsg.TxHash()

	numAutTokens := extAutScript.NumGeneratedTokens()
	startIdx := 0
	for ; startIdx < len(txOuts); startIdx++ {
		txOut := txOuts[startIdx]
		privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
		if err != nil {
			return err
		}
		if privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre ||
			privacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
			continue
		}

		if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			// the error is assuming that this function is called with pre-condition that there must be AutTokens.
			// i.e. numHiddenAutTokens > 0, this should be claimed explicitly.
			return fmt.Errorf("expect privacy level %d but got %d",
				abecryptoxkey.PrivacyLevelPSEUDONYMCT, privacyLevel)
		}
		// The Host-Txos for Aut are at the start positions of Pseudonym-privacy Txos.
		break
	}

	if startIdx+numAutTokens > len(txOuts) {
		return fmt.Errorf("claim %d outputs for CTAUT but only remain %d outputs in host transaction",
			numAutTokens, len(txOuts)-startIdx)
	}

	generatedTokens := make([]*AutToken, numAutTokens)
	for i := 0; i < numAutTokens; i++ {
		index := uint8(startIdx + i)
		txOut := txOuts[index]

		coinAddress, err := rules.RuleCheckOnHostTxo(txHash, index, txOut)
		if err != nil {
			return err
		}

		generatedTokens[i] = &AutToken{
			Version: extAutScript.Version(),
			HostOutPoint: script.HostOutPoint{
				TxHash: txHash,
				Index:  index,
			},
			ValueScript: nil, // nil for AutRootToken, fill out for AutToken later
			CoinAddress: coinAddress,
		}
	}

	switch ctAUTScript := extAutScript.AutScript.(type) {
	case *script.RegistrationScript:
		// no value script need to assign
	case *script.ReRegistrationScript:
		// no value script need to assign
	case *script.MintScript:
		for i := 0; i < numAutTokens; i++ {
			serializedAutTxo := ctAUTScript.SerializedAutTxos()[i]
			autTxo := &ctautwire.AutTxo{}
			err := autTxo.Deserialize(serializedAutTxo)
			if err != nil {
				return err
			}

			err = rules.RuleCheckOnAutTxoVersionType(generatedTokens[i].Version, autTxo)
			if err != nil {
				return err
			}

			// Implement Rule: set ValueScript to be serializedAutTxo
			generatedTokens[i].ValueScript = serializedAutTxo
		}
	case *script.TransferScript:
		for i := 0; i < numAutTokens; i++ {
			serializedAutTxo := ctAUTScript.SerializedAutTxos()[i]
			autTxo := &ctautwire.AutTxo{}
			err := autTxo.Deserialize(serializedAutTxo)
			if err != nil {
				return err
			}

			err = rules.RuleCheckOnAutTxoVersionType(generatedTokens[i].Version, autTxo)
			if err != nil {
				return err
			}

			generatedTokens[i].ValueScript = serializedAutTxo
		}

	case *script.BurnScript:
		for i := 0; i < numAutTokens; i++ {
			serializedAutTxo := ctAUTScript.SerializedAutTxos()[i]
			autTxo := &ctautwire.AutTxo{}
			err := autTxo.Deserialize(serializedAutTxo)
			if err != nil {
				return err
			}

			err = rules.RuleCheckOnAutTxoVersionType(generatedTokens[i].Version, autTxo)
			if err != nil {
				return err
			}

			generatedTokens[i].ValueScript = serializedAutTxo
		}

	default:
		return fmt.Errorf("unexpected aut script type %d", extAutScript.Type())
	}

	extAutScript.generatedTokens = generatedTokens
	extAutScript.outputHandled = true

	return nil
}

func (extAutScript *ExtAutScript) GeneratedTokens() ([]*AutToken, error) {
	if !extAutScript.outputHandled {
		return nil, fmt.Errorf("generated tokens not set")
	}

	return extAutScript.generatedTokens, nil
}

func (extAutScript *ExtAutScript) SetConsumedTokens(consumedTokens []*AutToken) error {

	if len(consumedTokens) != extAutScript.NumConsumedTokens() {
		return fmt.Errorf("mismatched number of consumed tokens")
	}

	// todo: need lock?
	extAutScript.consumedTokens = consumedTokens
	extAutScript.inputHandled = true

	return nil
}

func (extAutScript *ExtAutScript) ConsumedTokens() ([]*AutToken, error) {
	if !extAutScript.inputHandled {
		return nil, fmt.Errorf("consumed tokens not set")
	}

	return extAutScript.consumedTokens, nil
}

// CreateAutMetadata create a new AutMetadata from the RegistrationScript.
func (extAutScript *ExtAutScript) CreateAutMetadata(txHash chainhash.Hash) (*script.AutMetadata, error) {

	if extAutScript.Type() != script.AutScriptTypeRegistration {
		return nil, fmt.Errorf("wrong call on CreateMetadata: should be called only by registration script")
	}

	registerScript, ok := extAutScript.AutScript.(*script.RegistrationScript)
	if !ok {
		return nil, fmt.Errorf("wrong call on CreateMetadata: should be called only by registration script")
	}

	if err := registerScript.SanityCheck(); err != nil {
		return nil, fmt.Errorf("registerScript sanity check failed: %v", err)
	}

	if !extAutScript.outputHandled {
		return nil, fmt.Errorf("wrong call on CreateMetadata: generated tokens are not set yet")
	}

	rootTokenSet := map[string]*script.HostOutPoint{}
	for i := 0; i < len(extAutScript.generatedTokens); i++ {
		opStr := extAutScript.generatedTokens[i].HostOutPoint.String()
		rootTokenSet[opStr] = &extAutScript.generatedTokens[i].HostOutPoint
	}

	autIdentifier := chainhash.Hash{}
	copy(autIdentifier[:], txHash[:])

	newAutMetadata := &script.AutMetadata{
		Version:                    ctautwire.AutMetadataVersionInitValue,
		AutIdentifier:              autIdentifier,
		AutName:                    registerScript.AutName(),
		AutSymbol:                  registerScript.AutSymbol(),
		BaseUnitName:               registerScript.BaseUnitName(),
		SubUnitName:                registerScript.SubUnitName(),
		UnitScale:                  registerScript.UnitScale(),
		AutMemo:                    registerScript.AutMemo(),
		PlannedTotalSupply:         registerScript.PlannedTotalSupply(),
		Issuers:                    registerScript.Issuers(),
		ReregistrationExpireHeight: registerScript.ReregistrationExpireHeight(),

		ReregistrationThreshold: registerScript.ReregisterThreshold(),
		MintThreshold:           registerScript.MintThreshold(),

		MintedAmount:         0,
		BurnedAmount:         0,
		ActiveRootTokenSet:   rootTokenSet,
		UpdateScriptVersions: []uint32{registerScript.Version()},
	}
	return newAutMetadata, nil
}

// UpdateAutMetadata updates an AutMetadata using the ReRegistrationScript.
// todo: use var rather than pointer, and return a new AutMetadata?
func (extAutScript *ExtAutScript) UpdateAutMetadata(autMetadata *script.AutMetadata) error {
	// assert
	if extAutScript.Type() != script.AutScriptTypeReRegistration {
		return fmt.Errorf("wrong call on UpdateAutMetadata: should be called only by re-registration script")
	}

	reregisterScript, ok := extAutScript.AutScript.(*script.ReRegistrationScript)
	if !ok {
		return fmt.Errorf("wrong call on UpdateAutMetadata: should be called only by re-registration script")
	}

	if err := reregisterScript.SanityCheck(); err != nil {
		return fmt.Errorf("reregisterScript sanity check failed: %v", err)
	}

	identifier := extAutScript.AutIdentifier()
	if !bytes.Equal(identifier[:], autMetadata.AutIdentifier[:]) {
		return fmt.Errorf("the AutIdentifier of the re-registration script (%s) and that of the autMetadata (%s) "+
			"does not match", identifier.String(), autMetadata.AutIdentifier.String())
	}

	// todo: does not check inputHandled/outputHandled?
	consumedTokens := extAutScript.consumedTokens
	for i := 0; i < len(consumedTokens); i++ {
		opStr := consumedTokens[i].HostOutPoint.String()
		if _, ok := autMetadata.ActiveRootTokenSet[opStr]; !ok {
			return fmt.Errorf("an re-registration script attempts to update AutMetadata "+
				"with non-existing/spent root token (%s,%d) for AutInstance identified by %s",
				consumedTokens[i].HostOutPoint.TxHash, consumedTokens[i].HostOutPoint.Index,
				autMetadata.AutIdentifier)
		}
		// todo: if abort, the autMetadata is changed? should use a local var, and finally set when succeed
		delete(autMetadata.ActiveRootTokenSet, opStr)
	}

	// follow defined rules in AutScriptVersion
	autMetadata.Version += 1

	autMetadata.AutMemo = reregisterScript.AutMemo()

	if reregisterScript.PlannedTotalSupply() < autMetadata.MintedAmount {
		return fmt.Errorf("re-registration script attempts to make planned supply (%d) less than minted amount (%d)",
			reregisterScript.PlannedTotalSupply(), autMetadata.MintedAmount)
	}
	autMetadata.PlannedTotalSupply = reregisterScript.PlannedTotalSupply()

	autMetadata.Issuers = reregisterScript.Issuers()
	autMetadata.ReregistrationExpireHeight = reregisterScript.ReregistrationExpireHeight()

	autMetadata.ReregistrationThreshold = reregisterScript.ReregisterThreshold()
	autMetadata.MintThreshold = reregisterScript.MintThreshold()

	// remove previous root tokens
	autMetadata.ActiveRootTokenSet = make(map[string]*script.HostOutPoint, len(extAutScript.generatedTokens))
	for i := 0; i < len(extAutScript.generatedTokens); i++ {
		opStr := extAutScript.generatedTokens[i].HostOutPoint.String()
		autMetadata.ActiveRootTokenSet[opStr] = &extAutScript.generatedTokens[i].HostOutPoint
	}

	// check
	updateScriptVersionMax := autMetadata.UpdateScriptVersions[len(autMetadata.UpdateScriptVersions)-1]
	if reregisterScript.Version() < updateScriptVersionMax {
		return fmt.Errorf("the version of re-register script %d should be not smaller than the largest version (%d) in UpdateScriptVersions",
			reregisterScript.Version(), updateScriptVersionMax,
		)
	}
	autMetadata.UpdateScriptVersions = append(autMetadata.UpdateScriptVersions, reregisterScript.Version())

	return nil
}

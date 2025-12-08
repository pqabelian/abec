package extscript

import (
	"bytes"
	"fmt"

	"github.com/abesuite/abec/ctaut/dao"

	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/ctaut/rules"
	"github.com/abesuite/abec/ctaut/script"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/wire"
)

//type ExtAutScriptInputAssembleStatus uint8
//
//const (
//	ExtAutScriptInputAssembleStatus_Init  ExtAutScriptInputAssembleStatus = 0
//	ExtAutScriptInputAssembleStatus_Step1 ExtAutScriptInputAssembleStatus = 1
//	ExtAutScriptInputAssembleStatus_Step2 ExtAutScriptInputAssembleStatus = 2
//)

type HostOutPoint = dao.HostOutPoint
type AutId = dao.AutId
type AutIssuer = dao.AutIssuer
type AutToken = dao.AutToken

// ExtAutScript is used to collect the input Tokens and generate output Tokens by the AutScript,
// based on the information of host-Tx and AutScript.
type ExtAutScript struct {
	script.AutScript

	msgTx *wire.MsgTxAbe

	generatedTokens []*AutToken

	// Note that for following 2 fields:
	// - if the value is nil, it means that the tokens is not set
	// - if the value is empty slice, it means that the tokens is set but has no token
	//inputHandleStatus ExtAutScriptInputAssembleStatus //	indicate whether consumedTokens has been handled
	//handledConsumedTokens bool
	//consumedTokens        []*AutToken

	consumedHostOutpoints []*HostOutPoint
}

func (extAutScript *ExtAutScript) AutIdentifier() AutId {
	if extAutScript.AutScript.Type() == script.AutScriptTypeRegistration {
		return extAutScript.msgTx.TxHash()
	}

	return extAutScript.AutScript.AutIdentifier()
}

// NewExtAutScriptAndAssembleOutputTokens news an ExtAutScript,
// where ExtAutScript is initialized using the input autScript and msgTx,
// and GenerateTokens are assembled.
// Note that the ConsumedTokens are still set here.
func NewExtAutScriptAndAssembleOutputTokens(autScript script.AutScript, msgTx *wire.MsgTxAbe) (*ExtAutScript, error) {
	extAutScript := &ExtAutScript{
		AutScript: autScript,
		msgTx:     msgTx,
	}

	//extAutScript.handledConsumedTokens = false
	//extAutScript.consumedTokens = nil
	//extAutScript.inputHandleStatus = ExtAutScriptInputAssembleStatus_Init

	err := extAutScript.assembleInputHostOutpoint()
	if err != nil {
		return nil, err
	}

	err = extAutScript.assembleOutputAutTokens()
	if err != nil {
		return nil, err
	}

	return extAutScript, nil
}

// AssembleInputHostOutpoint would get the specified host outpoint for input from the host transaction
func (extAutScript *ExtAutScript) assembleInputHostOutpoint() error {
	extAutScript.consumedHostOutpoints = nil

	hostedTxIns := extAutScript.msgTx.TxIns

	startIndex := int(extAutScript.InStartIndex())
	numInCoins := extAutScript.NumConsumedTokens()
	if startIndex+numInCoins > len(hostedTxIns) {
		return fmt.Errorf("claim %d (root) coins but only remain %d outputs",
			numInCoins, len(hostedTxIns)-startIndex)
	}

	consumedHostOutpoints := make([]*script.HostOutPoint, numInCoins)
	for i := 0; i < numInCoins; i++ {
		hostIndex := uint8(startIndex + i)
		txIn := hostedTxIns[hostIndex]

		if len(txIn.PreviousOutPointRing.OutPoints) != 1 {
			return fmt.Errorf("incorrect input for Aut with wrong ring size %d", len(txIn.PreviousOutPointRing.OutPoints))
		}

		consumedHostOutpoints[i] = &script.HostOutPoint{
			TxHash: txIn.PreviousOutPointRing.OutPoints[0].TxHash,
			Index:  txIn.PreviousOutPointRing.OutPoints[0].Index,
		}
	}

	extAutScript.consumedHostOutpoints = consumedHostOutpoints

	return nil

}

// AssembleOutputAutTokens would get the specified host output from the host transaction
func (extAutScript *ExtAutScript) assembleOutputAutTokens() error {
	extAutScript.generatedTokens = nil

	txOuts := extAutScript.msgTx.TxOuts
	txHash := extAutScript.msgTx.TxHash()

	startIdx := int(extAutScript.OutStartIndex())
	numAutTokens := extAutScript.NumGeneratedTokens()
	if startIdx+numAutTokens > len(txOuts) {
		return fmt.Errorf("claim %d outputs for CTAUT but only remain %d outputs in host transaction",
			numAutTokens, len(txOuts)-startIdx)
	}

	generatedTokens := make([]*AutToken, numAutTokens)
	for i := 0; i < numAutTokens; i++ {
		index := uint8(startIdx + i)
		txOut := txOuts[index]

		hostOutPoint :=
			HostOutPoint{
				TxHash: txHash,
				Index:  index,
			}

		coinAddress, err := rules.RuleCheckOnHostTxo(&hostOutPoint, txOut)
		if err != nil {
			return err
		}

		generatedTokens[i] = &AutToken{
			Version:      extAutScript.Version(),
			HostOutPoint: hostOutPoint,
			CoinAddress:  coinAddress,
			ValueScript:  nil, // nil for AutRootToken, fill out for AutToken later

		}
	}

	switch autScriptInst := extAutScript.AutScript.(type) {
	case *script.RegistrationScript:
		// no value script need to assign
		if err := rules.RuleCheckOnIssuerHostClaim(autScriptInst.Issuers(), generatedTokens); err != nil {
			return err
		}
		break

	case *script.ReRegistrationScript:
		// no value script need to assign
		if err := rules.RuleCheckOnIssuerHostClaim(autScriptInst.Issuers(), generatedTokens); err != nil {
			return err
		}
		break

	case *script.MintScript:
		for i := 0; i < numAutTokens; i++ {
			serializedAutTxo := autScriptInst.SerializedAutTxos()[i]
			autTxo := &ctautwire.AutTxo{}
			err := autTxo.Deserialize(serializedAutTxo)
			if err != nil {
				return err
			}

			err = rules.RuleCheckOnAutTxoVersionType(generatedTokens[i].Version, autTxo)
			if err != nil {
				return err
			}

			autTxoType, err := abecryptox.GetAutTxoType(autTxo)
			if err != nil {
				return err
			}
			if i < int(autScriptInst.OutHiddenAutTokenNum()) {
				if autTxoType != abecryptox.AutTxoTypeHidden {
					return fmt.Errorf("aut txo type is not hidden")
				}
			} else {
				if autTxoType != abecryptox.AutTxoTypePublic {
					return fmt.Errorf("aut txo type is not public")
				}
			}

			// Implement Rule: set ValueScript to be serializedAutTxo
			generatedTokens[i].ValueScript = serializedAutTxo
		}
		break

	case *script.TransferScript:
		for i := 0; i < numAutTokens; i++ {
			serializedAutTxo := autScriptInst.SerializedAutTxos()[i]
			autTxo := &ctautwire.AutTxo{}
			err := autTxo.Deserialize(serializedAutTxo)
			if err != nil {
				return err
			}

			err = rules.RuleCheckOnAutTxoVersionType(generatedTokens[i].Version, autTxo)
			if err != nil {
				return err
			}

			autTxoType, err := abecryptox.GetAutTxoType(autTxo)
			if err != nil {
				return err
			}
			if i < int(autScriptInst.OutHiddenAutTokenNum()) {
				if autTxoType != abecryptox.AutTxoTypeHidden {
					return fmt.Errorf("aut txo type is not hidden")
				}
			} else {
				if autTxoType != abecryptox.AutTxoTypePublic {
					return fmt.Errorf("aut txo type is not public")
				}
			}

			generatedTokens[i].ValueScript = serializedAutTxo
		}
		break

	case *script.BurnScript:
		for i := 0; i < numAutTokens; i++ {
			serializedAutTxo := autScriptInst.SerializedAutTxos()[i]
			autTxo := &ctautwire.AutTxo{}
			err := autTxo.Deserialize(serializedAutTxo)
			if err != nil {
				return err
			}

			err = rules.RuleCheckOnAutTxoVersionType(generatedTokens[i].Version, autTxo)
			if err != nil {
				return err
			}

			autTxoType, err := abecryptox.GetAutTxoType(autTxo)
			if err != nil {
				return err
			}
			if i < int(autScriptInst.OutHiddenAutTokenNum()) {
				if autTxoType != abecryptox.AutTxoTypeHidden {
					return fmt.Errorf("aut txo type is not hidden")
				}
			} else {
				if autTxoType != abecryptox.AutTxoTypePublic {
					return fmt.Errorf("aut txo type is not public")
				}
			}

			generatedTokens[i].ValueScript = serializedAutTxo
		}
		break

	default:
		return fmt.Errorf("unexpected aut script type %d", extAutScript.Type())
	}

	extAutScript.generatedTokens = generatedTokens

	return nil
}

// AssembleInputAutTokensStep1 assemble the input Tokens for ExtutScript (Step1), making use of the lookupHostOutputTxoRing,
// which returns a TxoRing corresponding to TxIn.RingHash, from somewhere.
//
// RULE on the TxIn for Host-Tx:
// The TxIn should be ordered by
// (a) PrivacyLevelRINGCTPre/PrivacyLevelRINGCT
// (b) PrivacyLevelPSEUDONYMCT
// (c) PrivacyLevelPSEUDONYM
// and the AutTokens hosts on the first "consumedTokenNum" PrivacyLevelPSEUDONYMCT TxIns.
func (extAutScript *ExtAutScript) AssembleInputAutTokensStep1(
	lookupHostOutputTxoRing func(ringHash chainhash.Hash) (*wire.TxoRing, error),
	lookupAutToken func(identifier AutId, outpoint HostOutPoint) (uint32, []byte, error),
) error {

	if extAutScript.Type() == script.AutScriptTypeRegistration {
		//extAutScript.handledConsumedTokens = true
		//extAutScript.consumedTokens = nil
		return nil
	}
	//extAutScript.inputHandleStatus = ExtAutScriptInputAssembleStatus_Step1 // nonsense
	//extAutScript.consumedTokens = nil
	//
	//return nil
	//}

	// getTxoRingForHost lookups the txoRing for ringHash, and perform sanity-checks to guarantee that
	// the size of resulting txoRing is not 0.
	getTxoRingForHost := func(ringHash chainhash.Hash) (txoRing *wire.TxoRing, rstErr error) {
		txoRing, err := lookupHostOutputTxoRing(ringHash)
		if err != nil {
			return nil, err
		}

		if txoRing == nil {
			return nil, fmt.Errorf("the TxoRing obtained by ringHash (%s) is nil ", ringHash.String())
		}
		if txoRing.OutPointRing == nil {
			return nil, fmt.Errorf("the TxoRing.OutPointRing obtained by ringHash (%s) is nil ", ringHash.String())
		}

		ringId := txoRing.OutPointRing.RingId()
		if !ringId.IsEqual(&ringHash) {
			return nil, fmt.Errorf("the TxoRing.OutPointRing obtained by ringHash (%s) has ringId (%s)", ringHash.String(), ringId.String())
		}

		if len(txoRing.OutPointRing.OutPoints) != len(txoRing.TxOuts) {
			return nil, fmt.Errorf("the TxoRing obtained by ringHash (%s) has  "+
				"len(txoRing.OutPointRing.OutPoints) = %d || len(txoRing.TxOuts) = %d ",
				ringHash.String(), len(txoRing.OutPointRing.OutPoints), len(txoRing.TxOuts))
		}

		if len(txoRing.OutPointRing.OutPoints) == 0 {
			return nil, fmt.Errorf("the TxoRing obtained by ringHash (%s) has  "+
				"len(txoRing.OutPointRing.OutPoints) = 0 ",
				ringHash.String())
		}

		return txoRing, nil
	}

	txHash := extAutScript.msgTx.TxHash()

	hostedTxIns := extAutScript.msgTx.TxIns

	startIndex := 0
	for ; startIndex < len(hostedTxIns); startIndex++ {
		ringHash := hostedTxIns[startIndex].PreviousOutPointRing.Hash()

		txoRing, err := getTxoRingForHost(ringHash)
		if err != nil {
			return err
		}

		privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txoRing.TxOuts[0])
		if err != nil {
			return err
		}

		// skip fully-privacy area
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

	numInCoins := extAutScript.NumConsumedTokens()
	if startIndex+numInCoins > len(hostedTxIns) {
		return fmt.Errorf("claim %d (root) coins but only remain %d outputs",
			numInCoins, len(hostedTxIns)-startIndex)
	}

	scriptVersion := extAutScript.Version()
	identifier := extAutScript.AutIdentifier()
	consumedTokens := make([]*AutToken, numInCoins)
	for i := 0; i < len(consumedTokens); i++ {
		hostTxInIndex := startIndex + i
		hostTxIn := hostedTxIns[hostTxInIndex]

		// sanity-check
		ringHash := hostTxIn.PreviousOutPointRing.Hash()

		txoRing, err := getTxoRingForHost(ringHash)
		if err != nil {
			return err
		}

		privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txoRing.TxOuts[0])
		if err != nil {
			return err
		}
		if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			return fmt.Errorf("expect privacy level %d but got %d",
				abecryptoxkey.PrivacyLevelPSEUDONYMCT, privacyLevel)
		}

		if len(txoRing.TxOuts) != 1 {
			return fmt.Errorf("the TxoRing obtained by ringHash (%s) has  "+
				"privacyLevel == abecryptoxkey.PrivacyLevelPSEUDONYMCT but "+
				"len(txoRing.TxOuts) = %d ", ringHash.String(), len(txoRing.TxOuts))
		}

		// fill out with the first item in ring
		hostOutPoint := txoRing.OutPointRing.OutPoints[0]
		coinAddress, err := rules.RuleCheckOnHostTxo(hostOutPoint, txoRing.TxOuts[0])
		if err != nil {
			return fmt.Errorf("transaction %s try to consume UTXO at Ring %s is not a valid output", txHash,
				hostTxIn.PreviousOutPointRing.Hash())
		}

		tokenVersion := uint32(0)
		var valueScript []byte
		switch extAutScript.Type() {
		case script.AutScriptTypeRegistration:
			return fmt.Errorf("registration script should not consume any token")
		case script.AutScriptTypeReRegistration, script.AutScriptTypeMint:
			// no version and value script is need by script with those type
			// they would consume the root token
			break
		case script.AutScriptTypeTransfer, script.AutScriptTypeBurn:
			// they would consume the token
			tokenVersion, valueScript, err = lookupAutToken(identifier, *hostOutPoint)
			if err != nil {
				return err
			}
			err = abecryptox.AutRuleCheckOnTxInputVersion(tokenVersion, scriptVersion)
			if err != nil {
				return fmt.Errorf("script with version %d failed to consume the token with version %d",
					scriptVersion, tokenVersion)
			}
		default:
			return fmt.Errorf("unsupported aut script type %d", extAutScript.Type())
		}

		consumedTokens[i] = &AutToken{
			Version:      tokenVersion,
			HostOutPoint: *hostOutPoint,
			CoinAddress:  coinAddress,
			ValueScript:  valueScript,
		}
	}

	//extAutScript.inputHandleStatus = ExtAutScriptInputAssembleStatus_Step1

	//extAutScript.handledConsumedTokens = true
	//extAutScript.consumedTokens = consumedTokens

	return nil
}
func (extAutScript *ExtAutScript) ConsumedHostOutpoints() []*script.HostOutPoint {
	return extAutScript.consumedHostOutpoints
}

func (extAutScript *ExtAutScript) GeneratedTokens() []*AutToken {
	return extAutScript.generatedTokens
}

// todo: remove, use assemble function
func (extAutScript *ExtAutScript) SetConsumedTokens(consumedTokens []*AutToken) error {

	if len(consumedTokens) != extAutScript.NumConsumedTokens() {
		return fmt.Errorf("mismatched number of consumed tokens")
	}

	//extAutScript.consumedTokens = consumedTokens
	//extAutScript.handledConsumedTokens = true

	return nil
}

// todo:
//func (extAutScript *ExtAutScript) ConsumedTokens() ([]*AutToken, error) {
//if extAutScript.inputHandleStatus != ExtAutScriptInputAssembleStatus_Step2 {
//	return nil, fmt.Errorf("consumed tokens not set")
//}

//if !extAutScript.handledConsumedTokens {
//	return nil, fmt.Errorf("consumed tokens not set")
//}
//return extAutScript.consumedTokens, nil
//}

// CreateAutMetadata create a new AutMetadata from the RegistrationScript.
func (extAutScript *ExtAutScript) CreateAutMetadata() (*script.AutMetadata, error) {

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

	rootTokenSet := map[string]*HostOutPoint{}
	for i := 0; i < len(extAutScript.generatedTokens); i++ {
		hostOutPoint := extAutScript.generatedTokens[i].HostOutPoint
		opStr := hostOutPoint.String()
		rootTokenSet[opStr] = &hostOutPoint
	}

	newAutMetadata := &script.AutMetadata{
		Version:                    ctautwire.AutMetadataVersionInitValue,
		AutIdentifier:              extAutScript.msgTx.TxHash(),
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
func (extAutScript *ExtAutScript) UpdateAutMetadata(autMetadata *script.AutMetadata) (*script.AutMetadata, error) {
	// assert
	if extAutScript.Type() != script.AutScriptTypeReRegistration {
		return nil, fmt.Errorf("wrong call on UpdateAutMetadata: should be called only by re-registration script")
	}

	reregisterScript, ok := extAutScript.AutScript.(*script.ReRegistrationScript)
	if !ok {
		return nil, fmt.Errorf("wrong call on UpdateAutMetadata: should be called only by re-registration script")
	}

	if err := reregisterScript.SanityCheck(); err != nil {
		return nil, fmt.Errorf("reregisterScript sanity check failed: %v", err)
	}

	identifier := extAutScript.AutIdentifier()
	if !bytes.Equal(identifier[:], autMetadata.AutIdentifier[:]) {
		return nil, fmt.Errorf("the AutIdentifier of the re-registration script (%s) and that of the autMetadata (%s) "+
			"does not match", identifier.String(), autMetadata.AutIdentifier.String())
	}

	//if extAutScript.inputHandleStatus != ExtAutScriptInputAssembleStatus_Step2 {
	//	return fmt.Errorf("the re-registration script did not finish the assembly of the input token ")
	//}
	//if !extAutScript.handledConsumedTokens {
	//	return nil, fmt.Errorf("the re-registration script did not finish the assembly of the input token ")
	//}

	updatedAutMetadata := autMetadata.Clone()

	//consumedTokens := extAutScript.consumedTokens
	consumedHostOutpoints := extAutScript.consumedHostOutpoints
	for i := 0; i < len(consumedHostOutpoints); i++ {
		hostOutpoint := consumedHostOutpoints[i]
		opStr := hostOutpoint.String()
		if _, ok := updatedAutMetadata.ActiveRootTokenSet[opStr]; !ok {
			return nil, fmt.Errorf("an re-registration script attempts to update AutMetadata "+
				"with non-existing/spent root token (%s,%d) for AutInstance identified by %s",
				hostOutpoint.TxHash, hostOutpoint.Index, updatedAutMetadata.AutIdentifier)
		}
		delete(updatedAutMetadata.ActiveRootTokenSet, opStr)
	}

	// follow defined rules in AutScriptVersion
	updatedAutMetadata.Version += 1

	updatedAutMetadata.AutMemo = reregisterScript.AutMemo()

	if reregisterScript.PlannedTotalSupply() < updatedAutMetadata.MintedAmount {
		return nil, fmt.Errorf("re-registration script attempts to make planned supply (%d) less than minted amount (%d)",
			reregisterScript.PlannedTotalSupply(), updatedAutMetadata.MintedAmount)
	}
	updatedAutMetadata.PlannedTotalSupply = reregisterScript.PlannedTotalSupply()

	// issuers
	updatedAutMetadata.Issuers = make([]*AutIssuer, len(reregisterScript.Issuers()))
	for i := 0; i < len(reregisterScript.Issuers()); i++ {
		updatedAutMetadata.Issuers[i] = reregisterScript.Issuers()[i].Clone()
	}

	updatedAutMetadata.ReregistrationExpireHeight = reregisterScript.ReregistrationExpireHeight()

	updatedAutMetadata.ReregistrationThreshold = reregisterScript.ReregisterThreshold()
	updatedAutMetadata.MintThreshold = reregisterScript.MintThreshold()

	// set the new AutRootTokens
	updatedAutMetadata.ActiveRootTokenSet = make(map[string]*HostOutPoint, len(extAutScript.generatedTokens))
	for i := 0; i < len(extAutScript.generatedTokens); i++ {
		hostOutPoint := extAutScript.generatedTokens[i].HostOutPoint
		opStr := hostOutPoint.String()
		updatedAutMetadata.ActiveRootTokenSet[opStr] = &hostOutPoint
	}

	// check
	updateScriptVersionMax := updatedAutMetadata.UpdateScriptVersions[len(autMetadata.UpdateScriptVersions)-1]
	if reregisterScript.Version() < updateScriptVersionMax {
		return nil, fmt.Errorf("the version of re-register script %d should be not smaller than the largest version (%d) in UpdateScriptVersions",
			reregisterScript.Version(), updateScriptVersionMax,
		)
	}
	updatedAutMetadata.UpdateScriptVersions = append(updatedAutMetadata.UpdateScriptVersions, reregisterScript.Version())

	return updatedAutMetadata, nil
}

package abecryptox

import (
	"fmt"

	"github.com/pqabelian/abec/abecryptox/abecryptoxkey"
	"github.com/pqabelian/abec/abecryptox/abecryptoxparam"
	"github.com/pqabelian/abec/abecryptox/abecryptoxparamctx"
	autwire "github.com/pqabelian/abec/ctaut/wire"
	"github.com/pqabelian/pqringctx/pqringctxapi"
)

// AutTxoType is defined for the types of AutTxo, which is actually pqringctxapi.CtxTxoType,
// since it will also be passed to underlying crypto-scheme.
// cto review done 2025.12.21
type AutTxoType = pqringctxapi.CtxTxoType

const (
	AutTxoTypeHidden = pqringctxapi.CtxTxoTypeHidden
	AutTxoTypePublic = pqringctxapi.CtxTxoTypePublic
)

// // abecryptox -> abepqringctx -> pqringctx

// pqringctxAutCoinbaseTxGen generates a new AutCoinbaseTx,
// for the input (txVersion uint32, vin uint64, autTxOutputDescs []*AutTxOutputDesc).
// ctx review done 2025.12.21
func pqringctxAutCoinbaseTxGen(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	autScriptVersion uint32, vin uint64, autTxOutputDescs []*AutTxOutputDesc) (*autwire.AutCoinbaseTx, error) {
	// just redundant double check
	cryptoSchemeFromAutScriptVersion, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autScriptVersion)
	if err != nil {
		return nil, err
	}
	if cryptoSchemeFromAutScriptVersion != cryptoScheme {
		return nil, fmt.Errorf("pqringctxAutCoinbaseTxGen: the input cryptoScheme is different from that implied by txVersion")
	}

	//	parse AutTxOutputDesc to pqringctx.CtxTxOutputDesc
	ctxTxOutputDesc := make([]*pqringctxapi.CtxTxOutputDesc, len(autTxOutputDescs))
	for j := 0; j < len(autTxOutputDescs); j++ {

		// The rules of (txoVersion, autTxoType) need to be checked, since the ring-rules need this.
		err = pqringctxAutRuleCheckOnAutTxoVersionType(pp, autScriptVersion, autTxOutputDescs[j].AutTxoType())
		if err != nil {
			return nil, fmt.Errorf("pqringctxAutCoinbaseTxGen: (txVersion, autTxOutputDescs[%d].AutTxoType()) (%d, %d) "+
				"fail to pass the AutRuleCheckOnTxoVersionType: %v",
				autScriptVersion, j, autTxOutputDescs[j].AutTxoType(), err)
		}

		ctxTxOutputDesc[j] = pqringctxapi.NewCtxTxOutputDesc(autTxOutputDescs[j].AutTxoType(), autTxOutputDescs[j].coinValuePublicKey, autTxOutputDescs[j].value)
	}

	// call the pqringctx.CtxCoinbaseTxGen
	ctxCoinbaseTx, err := pqringctxapi.CtxCoinbaseTxGen(pp, vin, ctxTxOutputDesc)
	if err != nil {
		return nil, err
	}

	// parse the pqringctx.CtxCoinbaseTxGen to wire.AutCoinbaseTx
	ctxTxos := pqringctxapi.GetCtxCoinbaseTxTxos(ctxCoinbaseTx)
	autTxos := make([]*autwire.AutTxo, len(ctxTxos))
	for i := 0; i < len(ctxTxos); i++ {
		serializedCtxTxo, err := pqringctxapi.SerializeCtxTxo(pp, ctxTxos[i])
		if err != nil {
			return nil, err
		}
		autTxos[i] = &autwire.AutTxo{
			Version:   autScriptVersion,
			TxoScript: serializedCtxTxo,
		}
	}

	// witness must be associated with Tx, so it does not need to contain cryptoScheme or TxVersion.
	ctxCbTxWitness := pqringctxapi.GetCtxCoinbaseTxTxWitness(ctxCoinbaseTx)
	autTxWitness, err := pqringctxapi.SerializeCtxTxWitnessCbTx(pp, ctxCbTxWitness)
	if err != nil {
		return nil, err
	}

	autCoinbaseTx := &autwire.AutCoinbaseTx{
		Version:   autScriptVersion,
		Vin:       vin,
		TxOuts:    autTxos,
		TxWitness: autTxWitness,
	}

	return autCoinbaseTx, nil
}

// pqringctxAutCoinbaseTxVerify verify the input autCoinbaseTx *wire.AutCoinbaseTx.
// The caller needs to guarantee the well-form of the input autCoinbaseTx *wire.AutCoinbaseTx, such as the TxOuts.
// This function only checks the balance proof, by calling the crypto-scheme.
// ctx review done 2025.12.21
func pqringctxAutCoinbaseTxVerify(pp *pqringctxapi.PublicParameter, autCoinbaseTx *autwire.AutCoinbaseTx) error {
	if autCoinbaseTx == nil {
		return fmt.Errorf("pqringctxAutCoinbaseTxVerify: the input autCoinbaseTx is nil")
	}
	if len(autCoinbaseTx.TxOuts) <= 0 {
		return fmt.Errorf("pqringctxAutCoinbaseTxVerify: autCoinbaseTx.TxOuts is nil/empty")
	}

	var err error

	vin := autCoinbaseTx.Vin

	ctxTxos := make([]pqringctxapi.CtxTxo, len(autCoinbaseTx.TxOuts))
	for j := 0; j < len(autCoinbaseTx.TxOuts); j++ {

		autTxo := autCoinbaseTx.TxOuts[j]

		if autTxo.Version != autCoinbaseTx.Version {
			return fmt.Errorf("pqringctxAutCoinbaseTxVerify: autCoinbaseTx.TxOuts[%d].Version (%d) != autCoinbaseTx.Version (%d)",
				j, autTxo.Version, autCoinbaseTx.Version)
		}

		// todo: 2025.12.22 future refactor the architecture for Aut.
		autTxoType, err := pqringctxGetAutTxoType(pp, autTxo)
		if err != nil {
			return err
		}

		// The rules of (txoVersion, autTxoType) need to be checked, since the ring-rules need this.
		err = pqringctxAutRuleCheckOnAutTxoVersionType(pp, autTxo.Version, autTxoType)
		if err != nil {
			return fmt.Errorf("pqringctxAutCoinbaseTxVerify: autCoinbaseTx.TxOuts[%d]'s (Version, autTxoType) (%d, %d) "+
				"fail to pass the AutRuleCheckOnTxoVersionType: %v",
				j, autTxo.Version, autTxoType, err)
		}

		ctxTxos[j], err = pqringctxapi.DeserializeCtxTxo(pp, autTxo.TxoScript)
		if err != nil {
			return err
		}
	}

	ctxTxWitness, err := pqringctxapi.DeserializeCtxTxWitnessCbTx(pp, autCoinbaseTx.TxWitness)
	if err != nil {
		return err
	}

	ctxCoinbaseTx := pqringctxapi.NewCtxCoinbaseTx(vin, ctxTxos, ctxTxWitness)

	err = pqringctxapi.CtxCoinbaseTxVerify(pp, ctxCoinbaseTx)
	if err != nil {
		return err
	}

	return nil
}

// pqringctxAutTransferTxGen generates a new AutTransferTx,
// for the input (txVersion uint32, autTxInputDescs []*AutTxInputDesc, autTxOutputDescs []*AutTxOutputDesc).
// The parameter cryptoScheme here is obtained by the caller from TxVersion, which causes this function is called.
// Now it is redundant at this moment and works for ony double-check.
// ctx review done 2025.12.22
func pqringctxAutTransferTxGen(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	autScriptVersion uint32, autTxInputDescs []*AutTxInputDesc, autTxOutputDescs []*AutTxOutputDesc) (*autwire.AutTransferTx, error) {

	// just redundant double check
	cryptoSchemeFromAutScriptVersion, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autScriptVersion)
	if err != nil {
		return nil, err
	}
	if cryptoSchemeFromAutScriptVersion != cryptoScheme {
		return nil, fmt.Errorf("pqringctxAutTransferTxGen: the input cryptoScheme is different from that implied by autScriptVersion")
	}

	inputNum := len(autTxInputDescs)
	outputNum := len(autTxOutputDescs)

	if inputNum == 0 || outputNum == 0 {
		return nil, fmt.Errorf("pqringctxAutTransferTxGen: neither the input autTxInputDescs or autTxOutputDescs could be empty")
	}

	// ctxTxInputDescs
	ctxTxInputDescs := make([]*pqringctxapi.CtxTxInputDesc, inputNum)
	for i := 0; i < inputNum; i++ {

		err = pqringctxAutRuleCheckOnTxInputVersion(pp, autScriptVersion, autTxInputDescs[i].autTxo.Version)
		if err != nil {
			return nil, fmt.Errorf("pqringctxAutTransferTxGen: the autScriptVersion is %d, "+
				"but autTxInputDescs[%d].autTxo.Version is %d, which is out of the allowed ones",
				autScriptVersion, i, autTxInputDescs[i].autTxo.Version)
		}

		// ctxTxo
		ctxTxo, err := pqringctxapi.DeserializeCtxTxo(pp, autTxInputDescs[i].autTxo.TxoScript)
		if err != nil {
			return nil, err
		}

		//	coinValuePublicKey, coinValueSecretKey
		if ctxTxo.CtxTxoType() == pqringctxapi.CtxTxoTypeHidden {
			if len(autTxInputDescs[i].coinValuePublicKey) == 0 {
				// only fore CtxTxoTypePublic, the coinValuePublicKey could be nil.
				return nil, fmt.Errorf("pqringctxAutTransferTxGen: the autTxInputDescs[%d].autTxo is CtxTxoTypeHidden, but the coinValuePublicKey is nil", i)
			}

			if len(autTxInputDescs[i].coinValueSecretKey) == 0 {
				// only fore CtxTxoTypePublic, the coinValueSecretKey could be nil.
				return nil, fmt.Errorf("pqringctxAutTransferTxGen: the autTxInputDescs[%d].autTxo is CtxTxoTypeHidden, but the coinValueSecretKey is nil", i)
			}
		}

		ctxTxInputDescs[i] = pqringctxapi.NewCtxTxInputDesc(ctxTxo, autTxInputDescs[i].coinValuePublicKey, autTxInputDescs[i].coinValueSecretKey, autTxInputDescs[i].value)
	}

	//	ctxTxOutputDescs
	ctxTxOutputDescs := make([]*pqringctxapi.CtxTxOutputDesc, outputNum)
	for j := 0; j < outputNum; j++ {
		if autTxOutputDescs[j].autTxoType == AutTxoTypeHidden {
			if len(autTxOutputDescs[j].coinValuePublicKey) == 0 {
				// only fore AutTxoTypeHidden, the coinValuePublicKey could be nil.
				return nil, fmt.Errorf("pqringctxAutTransferTxGen: the autTxOutputDescs[%d].autTxoType is AutTxoTypeHidden, but the coinValuePublicKey is nil", j)
			}
		}

		// The rules of (txoVersion, autTxoType) need to be checked, since the ring-rules need this.
		err = pqringctxAutRuleCheckOnAutTxoVersionType(pp, autScriptVersion, autTxOutputDescs[j].AutTxoType())
		if err != nil {
			return nil, fmt.Errorf("pqringctxAutTransferTxGen: (autScriptVersion, autTxOutputDescs[%d].AutTxoType()) (%d, %d) "+
				"fail to pass the AutRuleCheckOnTxoVersionType: %v",
				autScriptVersion, j, autTxOutputDescs[j].AutTxoType(), err)
		}

		ctxTxOutputDescs[j] = pqringctxapi.NewCtxTxOutputDesc(autTxOutputDescs[j].autTxoType, autTxOutputDescs[j].coinValuePublicKey, autTxOutputDescs[j].value)
	}

	//	call the crypto scheme
	ctxTransferTx, err := pqringctxapi.CtxTransferTxGen(pp, ctxTxInputDescs, ctxTxOutputDescs)
	if err != nil {
		return nil, err
	}

	//	Set the txInputs
	//	As the underlying crypto-scheme will not change this part, it can be set directly using the autTxInputDescs
	autTxIns := make([]*autwire.AutTxo, inputNum)
	for i := 0; i < inputNum; i++ {
		autTxIns[i] = autTxInputDescs[i].autTxo
	}

	// Set the TxOuts
	ctxTxos := pqringctxapi.GetCtxTransferTxTxos(ctxTransferTx)
	autTxos := make([]*autwire.AutTxo, len(ctxTxos))
	for j := 0; j < len(ctxTxos); j++ {
		serializedCtxTxo, err := pqringctxapi.SerializeCtxTxo(pp, ctxTxos[j])
		if err != nil {
			return nil, err
		}

		// RULE: AutTxo has its version inherited from the AutScript.
		autTxos[j] = &autwire.AutTxo{
			Version:   autScriptVersion,
			TxoScript: serializedCtxTxo,
		}
	}

	// witness must be associated with Tx, so it does not need to contain cryptoScheme or TxVersion.
	ctxTrTxWitness := pqringctxapi.GetCtxTransferTxTxWitness(ctxTransferTx)
	autTxWitness, err := pqringctxapi.SerializeCtxTxWitnessTrTx(pp, ctxTrTxWitness)
	if err != nil {
		return nil, err
	}

	// RULE: AutTransferTx has its version inherited from the AutScript.
	autTransferTx := &autwire.AutTransferTx{
		Version:   autScriptVersion,
		TxIns:     autTxIns,
		TxOuts:    autTxos,
		TxWitness: autTxWitness,
	}

	return autTransferTx, nil
}

// pqringctxAutTransferTxVerify verify the input autTransferTx *wire.AutTransferTx.
// The caller needs to guarantee the well-form of the input autTransferTx *wire.AutTransferTx, such as the TxOuts.
// This function only checks the balance proof, by calling the crypto-scheme.
// ctx review done 2025.12.22 todo
func pqringctxAutTransferTxVerify(pp *pqringctxapi.PublicParameter, autTransferTx *autwire.AutTransferTx) error {
	if autTransferTx == nil {
		return fmt.Errorf("pqringctxAutTransferTxVerify: the input transferTx is empty")
	}

	inputNum := len(autTransferTx.TxIns)
	outputNum := len(autTransferTx.TxOuts)
	if inputNum <= 0 {
		return fmt.Errorf("pqringctxAutTransferTxVerify: the inputNum is 0")
	}
	if outputNum <= 0 {
		return fmt.Errorf("pqringctxAutTransferTxVerify: the outputNum is 0")
	}

	var err error
	//	txInputs
	ctxTxInputs := make([]pqringctxapi.CtxTxo, inputNum)
	for i := 0; i < inputNum; i++ {
		err = pqringctxAutRuleCheckOnTxInputVersion(pp, autTransferTx.Version, autTransferTx.TxIns[i].Version)
		if err != nil {
			return fmt.Errorf("pqringctxAutTransferTxVerify: autTransferTx.Version is %d, "+
				"but autTransferTx.TxIns[%d].Version is %d, which is out of the allowed ones",
				autTransferTx.Version, i, autTransferTx.TxIns[i].Version)
		}

		// Note that (AutTxo.Version, AutTxo.Type)-match is checked when the AutTxo was generated. Here does not check that.

		ctxTxInputs[i], err = pqringctxapi.DeserializeCtxTxo(pp, autTransferTx.TxIns[i].TxoScript)
		if err != nil {
			return err
		}
	}

	//	txos
	ctxTxos := make([]pqringctxapi.CtxTxo, outputNum)
	for j := 0; j < outputNum; j++ {
		autTxo := autTransferTx.TxOuts[j]

		// Rule check!
		if autTxo.Version != autTransferTx.Version {
			return fmt.Errorf("pqringctxTransferTxVerify: transferTx.TxOuts[%d].Version (%d) != transferTx.Version (%d)",
				j, autTxo.Version, autTransferTx.Version)
			//	The output Txos of a transaction should have the same version as the transaction.
		}

		// autTxoType, err := GetAutTxoType(autTxo)
		autTxoType, err := pqringctxGetAutTxoType(pp, autTxo)
		if err != nil {
			return err
		}

		// The rules of (txoVersion, autTxoType) need to be checked, since the ring-rules need this.
		err = pqringctxAutRuleCheckOnAutTxoVersionType(pp, autTxo.Version, autTxoType)
		if err != nil {
			return fmt.Errorf("pqringctxTransferTxVerify: autTransferTx.TxOuts[%d]'s (Version, autTxoType) (%d, %d) "+
				"fail to pass the AutRuleCheckOnTxoVersionType: %v",
				j, autTxo.Version, autTxoType, err)
		}

		ctxTxos[j], err = pqringctxapi.DeserializeCtxTxo(pp, autTxo.TxoScript)
		if err != nil {
			return err
		}
	}

	//	TxWitness
	ctxTxWitness, err := pqringctxapi.DeserializeCtxTxWitnessTrTx(pp, autTransferTx.TxWitness)
	if err != nil {
		return err
	}

	ctxTransferTx := pqringctxapi.NewCtxTransferTx(ctxTxInputs, ctxTxos, ctxTxWitness)

	// call the crypto scheme's verify algorithm
	err = pqringctxapi.CtxTransferTxVerify(pp, ctxTransferTx)
	if err != nil {
		return err
	}

	return nil
}

// helper functions	begin
//	helper functions	end

//	APIs for Txos	begin

// pqringctxGetAutTxoType returns the AutTxoType of the input *wire.AutTxo.
// ctx review done 2025.12.21
func pqringctxGetAutTxoType(pp *pqringctxapi.PublicParameter, autTxo *autwire.AutTxo) (AutTxoType, error) {
	ctxTxo, err := pqringctxapi.DeserializeCtxTxo(pp, autTxo.TxoScript)
	if err != nil {
		return pqringctxapi.CtxTxoTypeHidden, err
	}

	return ctxTxo.CtxTxoType(), nil
}

// pqringctxGetAutTxoScriptSize returns the TxoScript size for the input CtxTxoType.
// ctx review done 2025.12.22
func pqringctxGetAutTxoScriptSize(pp *pqringctxapi.PublicParameter, autTxoType AutTxoType) (int, error) {
	// Note that AutTxoType is defined to be CtxTxoType.
	return pqringctxapi.GetCtxTxoSerializeSizeByCtxTxoType(pp, autTxoType)
}

// pqringctxExtractValueFromAutTxo extracts the value of the input AutTxo,
// using the input (coinValuePublicKey, coinValueSecretKey).
// ctx review done 2025.12.22
func pqringctxExtractValueFromAutTxo(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	autTxo *autwire.AutTxo, cryptoValuePublicKey []byte, cryptoValueSecretKey []byte) (value uint64, err error) {
	cryptoSchemeByAutScriptVersion, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autTxo.Version)
	if err != nil {
		return 0, err
	}

	if cryptoSchemeByAutScriptVersion != cryptoScheme {
		return 0, fmt.Errorf("pqringctxExtractValueFromAutTxo: unmatched cryptoScheme for the input AutTxo")
	}

	var coinValuePublicKey []byte
	var coinValueSecretKey []byte
	if len(cryptoValueSecretKey) != 0 && len(cryptoValuePublicKey) != 0 {
		privacyLevelInCryptoValueSecretKey, coinValueSecretKeyTemp, err := abecryptoxkey.CryptoValueSecretKeyParse(cryptoValueSecretKey)
		if err != nil {
			return 0, err
		}
		privacyLevelInCryptoValuePublicKey, coinValuePublicKeyTemp, err := abecryptoxkey.CryptoValuePublicKeyParse(cryptoValuePublicKey)
		if err != nil {
			return 0, err
		}
		if privacyLevelInCryptoValueSecretKey != privacyLevelInCryptoValuePublicKey {
			return 0, fmt.Errorf("pqringctxExtractValueFromAutTxo: unmatched privacyLevel for the input cryptoValueSecretKey and cryptoValuePublicKey")
		}

		coinValuePublicKey = coinValuePublicKeyTemp
		coinValueSecretKey = coinValueSecretKeyTemp

	} else {
		coinValuePublicKey = nil
		coinValueSecretKey = nil
	}

	// NOTE: As the abepqringctx-layer obtained CtxTxo (associated in CtxTransferTx/CtxCoinbaseTx)
	// and serialized it to AutTxo.TxoScript,
	// here abepqringctx-layer calls crypto-scheme using CtxTxo.
	ctxTxo, err := pqringctxapi.DeserializeCtxTxo(pp, autTxo.TxoScript)
	if err != nil {
		return 0, err
	}

	return pqringctxapi.ExtractValueFromCtxTxo(pp, ctxTxo, coinValuePublicKey, coinValueSecretKey)
}

//	APIs for Txos	end

// APIs for TxWitnesses	begin

// pqringctxGetAutCoinbaseTxWitnessSizeByDesc returns the AutCoinbaseTxWitnessSize,
// which depends on the number of AutTxoHidden.
// ctx review done 2025.12.22
func pqringctxGetAutCoinbaseTxWitnessSizeByDesc(pp *pqringctxapi.PublicParameter, outNumForHidden uint8) (int, error) {
	return pqringctxapi.GetCtxTxWitnessCbTxSerializeSizeByDesc(pp, outNumForHidden)
}

// pqringctxGetAutTransferTxWitnessSizeByDesc returns the size of AutTransferTxWitness,
// which depends on the description information (inNumForHidden uint8, outNumForHidden uint8, vPublic int64),
// where vPublic = (sum of public value for out) - (sum of public value for in).
// ctx review done 2025.12.22
func pqringctxGetAutTransferTxWitnessSizeByDesc(pp *pqringctxapi.PublicParameter, inNumForHidden uint8, outNumForHidden uint8, vPublic int64) (int, error) {
	return pqringctxapi.GetCtxTxWitnessTrTxSerializeSizeByDesc(pp, inNumForHidden, outNumForHidden, vPublic)
}

//	APIs for TxWitnesses	end

// APIs for ruleChecks	begin

// pqringctxAutRuleCheckOnAutTxoVersionType checks the match between AutTxo's Version and AutTxoType.
//
// Note that AutTxo's version is inherited from AutScriptVersion.
//
// When new AutScriptVersion is added, rules need to be added here.
// cto review done 2025.12.21
func pqringctxAutRuleCheckOnAutTxoVersionType(pp *pqringctxapi.PublicParameter, autScriptVersion uint32, autType AutTxoType) error {
	switch autScriptVersion {
	case autwire.AutScriptVersion_1:
		if autType == AutTxoTypeHidden || autType == AutTxoTypePublic {
			// allowed cases
		} else {
			return fmt.Errorf("pqringctxAutRuleCheckOnAutTxoVersionType: autScriptVersion is %d, "+
				"but the autType (%d) is not AutTxoTypeHidden or AutTxoTypePublic",
				autScriptVersion, autType)
		}

	default:
		return fmt.Errorf("pqringctxAutRuleCheckOnAutTxoVersionType: autScriptVersion (%d) is not supported",
			autScriptVersion)
	}

	return nil
}

// pqringctxRuleCheckOnTxInputVersion checks the match between Tx's Version and TxInput's Version.
//
// When new TxVersion is added, rules need to be added here.
// ctx review done 2025.12.22
func pqringctxAutRuleCheckOnTxInputVersion(pp *pqringctxapi.PublicParameter, autScriptVersion uint32, autTxInputVersion uint32) error {

	switch autScriptVersion {
	case autwire.AutScriptVersion_1:
		if autTxInputVersion == autwire.AutScriptVersion_1 {
			// allowed cases
		} else {
			return fmt.Errorf("pqringctxAutRuleCheckOnTxInputVersion: (autScriptVersion, autTxInputVersion) (%d, %d), "+
				"is not allowed/supported",
				autScriptVersion, autTxInputVersion)
		}
	default:
		return fmt.Errorf("pqringctxAutRuleCheckOnTxInputVersion: autScriptVersion (%d) is not supported",
			autScriptVersion)
	}

	return nil
}

// APIs for ruleChecks	end

// ctx review done 2025.12.21

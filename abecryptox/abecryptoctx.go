package abecryptox

import (
	"fmt"

	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/abecryptox/abecryptoxparamctx"
	"github.com/abesuite/abec/ctaut/wire"
)

// APIs for Transactions	begin

// AutCoinbaseTxGen takes as input the transaction material and outputs a *wire.AutCoinbaseTx.
func AutCoinbaseTxGen(autScriptVersion uint32, vin uint64, autTxOutputDescs []*AutTxOutputDesc) (*wire.AutCoinbaseTx, error) {
	cryptoScheme, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autScriptVersion)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		cbTx, err := pqringctxAutCoinbaseTxGen(abecryptoxparam.PQRingCTXPP, cryptoScheme,
			autScriptVersion, vin, autTxOutputDescs)
		if err != nil {
			return nil, err
		}
		return cbTx, nil

	default:
		return nil, fmt.Errorf("AutCoinbaseTxGen: Unsupported crypto scheme")
	}

}

// AutCoinbaseTxVerify verifies whether the input autCoinbaseTx *wire.AutCoinbaseTx is valid.
func AutCoinbaseTxVerify(autCoinbaseTx *wire.AutCoinbaseTx) error {
	cryptoScheme, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autCoinbaseTx.Version)
	if err != nil {
		return err
	}

	switch cryptoScheme {

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxAutCoinbaseTxVerify(abecryptoxparam.PQRingCTXPP, autCoinbaseTx)

	default:
		return fmt.Errorf("AutCoinbaseTxVerify: crypto-scheme (%d) is not supported", cryptoScheme)
	}
}

// AutTransferTxGen takes as input the transaction material and outputs a *wire.AutTransferTx.
func AutTransferTxGen(autScriptVersion uint32, autTxInputDescs []*AutTxInputDesc, autTxOutputDescs []*AutTxOutputDesc) (*wire.AutTransferTx, error) {
	cryptoScheme, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autScriptVersion)
	if err != nil {
		return nil, err
	}
	//	Note that a transferTxMsgTemplate may be created by CreateTransferTxMsgTemplate in an early version, so that the transferTxMsgTemplate.Version is old version.

	switch cryptoScheme {

	case abecryptoxparam.CryptoSchemePQRingCTX:
		trTx, err := pqringctxAutTransferTxGen(abecryptoxparam.PQRingCTXPP, cryptoScheme, autScriptVersion, autTxInputDescs, autTxOutputDescs)
		if err != nil {
			return nil, err
		}
		return trTx, nil

	default:
		return nil, fmt.Errorf("AutTransferTxGen: Unsupported crypto scheme")
	}

}

// AutTransferTxVerify verifies the input AutTransferTx.
func AutTransferTxVerify(autTransferTx *wire.AutTransferTx) error {
	cryptoScheme, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autTransferTx.Version)
	if err != nil {
		return err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		err = pqringctxAutTransferTxVerify(abecryptoxparam.PQRingCTXPP, autTransferTx)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("AutTransferTxVerify: Unsupported crypto scheme")
	}

	return nil
}

//	APIs for Transactions	end

//	APIs for Txos	begin

// GetAutTxoType returns the AutTxoType of the input *wire.AutTxo.
func GetAutTxoType(autTxo *wire.AutTxo) (AutTxoType, error) {
	// TODO: add map aut script version to crypto scheme
	// or aut script version -> tx version -> crypto scheme?
	cryptoScheme, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autTxo.Version)
	if err != nil {
		return AutTxoTypeHidden, err
	}

	switch cryptoScheme {

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetAutTxoType(abecryptoxparam.PQRingCTXPP, autTxo)

	default:
		return AutTxoTypeHidden, fmt.Errorf("GetAutTxoType: the crypto scheme mapped from autTxo.Version is not supported")
	}
}

// GetAutTxoScriptSize returns the TxoScript size of AutTxo with the input AutTxoType.
// Note that the transactions are generated and verified by the underlying crypto-scheme,
// the TxoScript size for AutTxo actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
func GetAutTxoScriptSize(autScriptVersion uint32, autTxoType AutTxoType) (int, error) {
	cryptoScheme, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autScriptVersion)
	if err != nil {
		return 0, err
	}
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetAutTxoScriptSize(abecryptoxparam.PQRingCTXPP, autTxoType)
	default:
		return 0, fmt.Errorf("GetAutTxoScriptSize: Unsupported txVersion")
	}
}

// ExtractAutTxoValue extracts the value of the input AutTxo.
func ExtractAutTxoValue(autTxo *wire.AutTxo, cryptoValuePublicKey []byte, cryptoValueSecretKey []byte) (uint64, error) {
	cryptoScheme, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autTxo.Version)
	if err != nil {
		return 0, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxExtractValueFromAutTxo(abecryptoxparam.PQRingCTXPP, cryptoScheme, autTxo, cryptoValuePublicKey, cryptoValueSecretKey)

	default:
		return 0, fmt.Errorf("PseudonymTxoCoinParse: the cryptoScheme (%d) implied by abeTxo.Version is not supported", cryptoScheme)
	}

}

//	APIs for Txos	end

//	APIs for TxWitness	begin

// GetAutCoinbaseTxWitnessSizeByDesc returns the size of AutCoinbaseTxWitness,
// which depends on the TxVersion and the number of AutTxoHidden on the output side.
func GetAutCoinbaseTxWitnessSizeByDesc(autScriptVersion uint32, outNumForHidden uint8) (int, error) {
	cryptoScheme, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autScriptVersion)
	if err != nil {
		return 0, err
	}
	switch cryptoScheme {

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetAutCoinbaseTxWitnessSizeByDesc(abecryptoxparam.PQRingCTXPP, outNumForHidden)
	default:
		return 0, fmt.Errorf("GetAutCoinbaseTxWitnessSizeByDesc: Unsupported txVersion")
	}
}

// GetAutTransferTxWitnessSizeByDesc returns the size of AutTransferTxWitness,
// which depends on the TxVersion and description information (inNumForHidden uint8, outNumForHidden uint8, vPublic int64),
// where vPublic = (sum of public value for out) - (sum of public value for in).
func GetAutTransferTxWitnessSizeByDesc(autScriptVersion uint32,
	inNumForHidden uint8, outNumForHidden uint8, vPublic int64) (int, error) {
	cryptoScheme, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autScriptVersion)
	if err != nil {
		return 0, err
	}

	switch cryptoScheme {

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetAutTransferTxWitnessSizeByDesc(abecryptoxparam.PQRingCTXPP, inNumForHidden, outNumForHidden, vPublic)

	default:
		return 0, fmt.Errorf("GetAutTransferTxWitnessSizeByDesc: the input txVersion (%d) is not supported", autScriptVersion)
	}
}

//	APIs for TxWitness	end

// APIs for ruleChecks	begin

// AutRuleCheckOnTxoVersionType checks the match between HostTxo's Version and AutTxoType.
//
// When new TxVersion is added, rules need to be added here.
func AutRuleCheckOnTxoVersionType(hostTxoVersion uint32, autTxoType AutTxoType) error {
	cryptoScheme, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(hostTxoVersion)
	if err != nil {
		return err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxAutRuleCheckOnAutTxoVersionType(abecryptoxparam.PQRingCTXPP, hostTxoVersion, autTxoType)

	default:
		return fmt.Errorf("AutRuleCheckOnTxoVersionType: Unsupported hostTxoVersion (%d)", hostTxoVersion)
	}
}

// AutRuleCheckOnTxInputVersion checks the match between TxInput's Version and Tx's Version.
//
// When new TxVersion is added, rules need to be added here.
func AutRuleCheckOnTxInputVersion(txInputVersion uint32, autScriptVersion uint32) error {
	cryptoScheme, err := abecryptoxparamctx.GetCryptoSchemeByAutScriptVersion(autScriptVersion)
	if err != nil {
		return err
	}
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxAutRuleCheckOnTxInputVersion(abecryptoxparam.PQRingCTXPP, txInputVersion, autScriptVersion)

	default:
		return fmt.Errorf("AutRuleCheckOnTxInputVersion: Unsupported autScriptVersion (%d)", autScriptVersion)
	}
}

//	APIs for ruleChecks	end

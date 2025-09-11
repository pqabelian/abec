package abecryptox

import (
	"fmt"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/ctaut"
)

// APIs for Transactions	begin

// CoinbaseTxGen takes as input the transaction material and outputs a *wire.MsgTxAbe
// reviewed on 2023.12.07
// reviewed on 2023.12.21
func AutCoinbaseTxGen(txVersion uint32, vin uint64, autTxOutputDescs []*AutTxOutputDesc) (*ctaut.AutCoinbaseTx, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		cbTx, err := pqringctxAutCoinbaseTxGen(abecryptoxparam.PQRingCTXPP, txVersion, vin, autTxOutputDescs)
		if err != nil {
			return nil, err
		}
		return cbTx, nil
	default:
		return nil, fmt.Errorf("CoinbaseTxGen: Unsupported crypto scheme")
	}

}

// CoinbaseTxVerify verifies whether the input coinbaseTx *wire.MsgTxAbe is valid.
func AutCoinbaseTxVerify(autCoinbaseTx *ctaut.AutCoinbaseTx) error {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(autCoinbaseTx.Version)
	if err != nil {
		return err
	}

	switch cryptoScheme {

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxAutCoinbaseTxVerify(abecryptoxparam.PQRingCTXPP, autCoinbaseTx)

	default:
		return fmt.Errorf("CoinbaseTxVerify: crypto-scheme (%d) is not supported", cryptoScheme)
	}
}

// TransferTxGenByKeys generates a new MsgTxAbe by filling the TxIns[].serialNumber, TxOuts[], and the TxWitness of the input transferTxMsgTemplate.
// reviewed on 2023.12.21
func AutTransferTxGen(txVersion uint32, autTxInputDescs []*AutTxInputDesc, autTxOutputDescs []*AutTxOutputDesc) (*ctaut.AutTransferTx, error) {

	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return nil, err
	}
	//	Note that a transferTxMsgTemplate may be created by CreateTransferTxMsgTemplate in an early version, so that the transferTxMsgTemplate.Version is old version.

	switch cryptoScheme {

	case abecryptoxparam.CryptoSchemePQRingCTX:
		trTx, err := pqringctxAutTransferTxGen(abecryptoxparam.PQRingCTXPP, cryptoScheme, txVersion, autTxInputDescs, autTxOutputDescs)
		if err != nil {
			return nil, err
		}
		return trTx, nil
	default:
		return nil, fmt.Errorf("TransferTxGenByKeys: Unsupported crypto scheme")
	}

}

// TransferTxVerify verifies the input transferTx.
// todo: review
func AutTransferTxVerify(autTransferTx *ctaut.AutTransferTx) error {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(autTransferTx.Version)
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
		return fmt.Errorf("TransferTxVerify: Unsupported crypto scheme")
	}

	return nil
}

//	APIs for Transactions	end

//	APIs for Txos	begin

// GetTxoPrivacyLevel returns the PrivacyLevel of the input wire.TxOutAbe,
// which is determined by its version and its coinAddress.
// At present, there are only 3 Privacy Levels for Txo, say PrivacyLevelRINGCTPre, PrivacyLevelRINGCT, and PrivacyLevelPSEUDONYM,
// depending on the Txo's CoinAddressType,
// although there is an additional PrivacyLevel definition, say PrivacyLevelPSEUDONYMCT.
// In the future, if PrivacyLevelPSEUDONYMCT Txo is supported, Txo's data besides CoinAddressType will be further used to
// determine its PrivacyLevel.
// reviewed on 2024.01.04
func GetAutTxoType(autTxo *ctaut.AutTxo) (AutTxoType, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(autTxo.Version)
	if err != nil {
		return 0, err
	}

	switch cryptoScheme {

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetAutTxoType(abecryptoxparam.PQRingCTXPP, autTxo)
	default:
		return 0, fmt.Errorf("GetTxoPrivacyLevel: the crypto scheme mapped from abeTxo.Version is not supported")
	}
	return 0, nil
}

// GetTxoSerializeSizeApprox returns the approximate serialize size for a Txo,
// which is in a transaction with the version being the input TxVersion and for the cryptoAddressPayTo.
// Note that the transactions are generated and verified by the underlying crypto-scheme,
// the approximate serialize size for Txo actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
// reviewed on 2023.12.07
// reviewed on 2024.01.01
func GetAutTxoSerializeSize(txVersion uint32, autTxoType AutTxoType) (int, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetAutTxoSerializeSize(abecryptoxparam.PQRingCTXPP, autTxoType)
	default:
		return 0, fmt.Errorf("GetTxoSerializeSizeApprox: Unsupported txVersion")
	}
}

// TxoCoinReceiveByKeys
// todo: review
func ExtractAutTxoValue(autTxo *ctaut.AutTxo, coinaValuePublicKey []byte, cryptoValueSecretKey []byte) (uint64, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(autTxo.Version)
	if err != nil {
		return 0, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxExtractValueFromAutTxo(abecryptoxparam.PQRingCTXPP, cryptoScheme, autTxo, coinaValuePublicKey, cryptoValueSecretKey)

	default:
		return 0, fmt.Errorf("PseudonymTxoCoinParse: the cryptoScheme (%d) implied by abeTxo.Version is not supported", cryptoScheme)
	}

}

//	APIs for Txos	end

//	APIs for TxWitness	begin

// GetCbTxWitnessSerializeSizeApprox returns the approximate serialize size for CoinbaseTxWitness, which is decided by the TxVersion and the number of out Txo.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for CoinbaseTxWitness actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
// reviewed on 2023.12.07
// reviewed on 2024.01.01, by Alice
// refactored on 2024.01.24, by Alice, pqringctx-Layer takes cryptoAddress as input.
func GetAutCoinbaseTxWitnessSerializeSize(txVersion uint32, outNumForHidden uint8) (int, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}
	switch cryptoScheme {

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetAutCoinbaseTxWitnessSerializeSizeByDesc(abecryptoxparam.PQRingCTXPP, outNumForHidden)
	default:
		return 0, fmt.Errorf("GetCbTxWitnessSerializeSizeApprox: Unsupported txVersion")
	}
}

// GetTrTxWitnessSerializeSizeApprox returns the approximate serialize size for TransferTxWitness,
// which is decided by the TxVersion and description of the input and output.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for TransferTxWitness actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
// todo: vPublic = (sum of public value for out) - (sum of public value for in)
func GetAutTransferTxWitnessSerializeSize(txVersion uint32,
	inNumForHidden uint8, outNumForHidden uint8, vPublic int64) (int, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}

	switch cryptoScheme {

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetAutTransferTxWitnessSerializeSizeByDesc(abecryptoxparam.PQRingCTXPP, inNumForHidden, outNumForHidden, vPublic)

	default:
		return 0, fmt.Errorf("GetTrTxWitnessSerializeSizeApprox: the input txVersion (%d) is not supported", txVersion)
	}
}

//	APIs for TxWitness	end

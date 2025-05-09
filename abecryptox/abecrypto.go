package abecryptox

import (
	"fmt"
	"github.com/pqabelian/abec/abecrypto"
	"github.com/pqabelian/abec/abecrypto/abecryptoparam"
	"github.com/pqabelian/abec/abecryptox/abecryptoxkey"
	"github.com/pqabelian/abec/abecryptox/abecryptoxparam"
	"github.com/pqabelian/abec/wire"
)

// APIs for Transactions	begin

// CoinbaseTxGen takes as input the transaction material and outputs a *wire.MsgTxAbe
// reviewed on 2023.12.07
// reviewed on 2023.12.21
func CoinbaseTxGen(abeTxOutputDescs []*AbeTxOutputDesc, coinbaseTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(coinbaseTxMsgTemplate.Version)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		// This is to achieve back-compatibility with CryptoSchemePQRingCT.
		// Before the BlockHeightMLP, the caller may use the coinbaseTxMsgTemplate.Version that maps to CryptoSchemePQRingCT.
		pqringctAbeTxOutputDescs := make([]*abecrypto.AbeTxOutputDesc, len(abeTxOutputDescs))
		for i := 0; i < len(abeTxOutputDescs); i++ {
			pqringctAbeTxOutputDescs[i] = abecrypto.NewAbeTxOutDesc(abeTxOutputDescs[i].cryptoAddress, abeTxOutputDescs[i].value)
		}

		cbTx, err := abecrypto.CoinbaseTxGen(pqringctAbeTxOutputDescs, coinbaseTxMsgTemplate)
		if err != nil {
			return nil, err
		}
		return cbTx, nil

	case abecryptoxparam.CryptoSchemePQRingCTX:
		cbTx, err := pqringctxCoinbaseTxGen(abecryptoxparam.PQRingCTXPP, abeTxOutputDescs, coinbaseTxMsgTemplate)
		if err != nil {
			return nil, err
		}
		return cbTx, nil
	default:
		return nil, fmt.Errorf("CoinbaseTxGen: Unsupported crypto scheme")
	}

}

// CoinbaseTxVerify verifies whether the input coinbaseTx *wire.MsgTxAbe is valid.
// reviewed on 2023.12.21
// refactored on 2024.01.08, using err == nil or not to denote valid or invalid
// todo: review
func CoinbaseTxVerify(coinbaseTx *wire.MsgTxAbe) error {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(coinbaseTx.Version)
	if err != nil {
		return err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		return abecrypto.CoinbaseTxVerify(coinbaseTx)

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxCoinbaseTxVerify(abecryptoxparam.PQRingCTXPP, coinbaseTx)

	default:
		return fmt.Errorf("CoinbaseTxVerify: crypto-scheme (%d) is not supported", cryptoScheme)
	}
}

// CreateTransferTxMsgTemplateByRootSeeds creates a *wire.MsgTxAbe template, which will be used when calling TransferTxGen().
// reviewed on 2023.12.31
func CreateTransferTxMsgTemplateByRootSeeds(abeTxInputDescs []*AbeTxInputDescByRootSeeds, abeTxOutputDescs []*AbeTxOutputDesc, txFee uint64, txMemo []byte) (*wire.MsgTxAbe, error) {

	//	Version
	//	Note that new Tx must use the latest/current TxVersion.
	txMsgTemplate := wire.NewMsgTxAbe(wire.TxVersion)

	//	TxIns     []*TxInAbe
	for _, abeTxInputDesc := range abeTxInputDescs {
		txIn := wire.NewTxInAbe(nil, abeTxInputDesc.txoRing.OutPointRing)
		txMsgTemplate.AddTxIn(txIn)
	}

	//	 TxOuts    []*TxOutAbe: skip

	//	TxFee
	txMsgTemplate.TxFee = txFee

	//	TxMemo
	txMsgTemplate.TxMemo = txMemo

	//	TxWitness: skip

	return txMsgTemplate, nil
}

// CreateTransferTxMsgTemplateByRandSeeds creates a *wire.MsgTxAbe template, which will be used when calling TransferTxGen().
// reviewed on 2023.12.31
func CreateTransferTxMsgTemplateByRandSeeds(abeTxInputDescs []*AbeTxInputDescByRandSeeds, abeTxOutputDescs []*AbeTxOutputDesc, txFee uint64, txMemo []byte) (*wire.MsgTxAbe, error) {

	//	Version
	//	Note that new Tx must use the latest/current TxVersion.
	txMsgTemplate := wire.NewMsgTxAbe(wire.TxVersion)

	//	TxIns     []*TxInAbe
	for _, abeTxInputDesc := range abeTxInputDescs {
		txIn := wire.NewTxInAbe(nil, abeTxInputDesc.txoRing.OutPointRing)
		txMsgTemplate.AddTxIn(txIn)
	}

	//	 TxOuts    []*TxOutAbe: skip

	//	TxFee
	txMsgTemplate.TxFee = txFee

	//	TxMemo
	txMsgTemplate.TxMemo = txMemo

	//	TxWitness: skip

	return txMsgTemplate, nil
}

// CreateTransferTxMsgTemplateByKeys creates a *wire.MsgTxAbe template, which will be used when calling TransferTxGen().
// To be self-contained, we put it here, together with TransferTxGen().
// The fields of *wire.MsgTxAbe template will be handled as below:
// (1) Version: filled here
// (2) TxIns: partially filled here, say filled except the serialNumber
// (3) TxOuts: set empty here and will be filled by underlying crypto schemes
// (4) TxFee: filled here
// (5) TxMemo: filled here
// (6) TxWitness: set empty here and will be filled by underlying crypto schemes
// In summary, CreateTransferTxMsgTemplate() fills all fields except the serialNumber, TxOuts, and TxWitness.
// Note that these filled fields (except the Version) are independent of the underlying crypto scheme,
// and are specified by the issuer of a transaction.
// We separate the creation of this TransferTxMsgTemplate from TransferTxGen, because
// a caller may use other methods to create a TransferTxMsgTemplate.
// reviewed on 2023.12.21
// reviewed on 2023.12.31
func CreateTransferTxMsgTemplateByKeys(abeTxInputDescs []*AbeTxInputDescByKeys, abeTxOutputDescs []*AbeTxOutputDesc, txFee uint64, txMemo []byte) (*wire.MsgTxAbe, error) {

	//	Version
	//	Note that new Tx must use the latest/current TxVersion.
	txMsgTemplate := wire.NewMsgTxAbe(wire.TxVersion)

	//	TxIns     []*TxInAbe
	for _, abeTxInputDesc := range abeTxInputDescs {
		txIn := wire.NewTxInAbe(nil, abeTxInputDesc.txoRing.OutPointRing)
		txMsgTemplate.AddTxIn(txIn)
	}

	//	 TxOuts    []*TxOutAbe: skip

	//	TxFee
	txMsgTemplate.TxFee = txFee

	//	TxMemo
	txMsgTemplate.TxMemo = txMemo

	//	TxWitness: skip

	return txMsgTemplate, nil
}

// TransferTxGenByRootSeeds generates a wire.MsgTxAbe by using the (Root Seeds, CoinDetectorRootKey) to spend the coins.
// reviewed on 2023.12.31
func TransferTxGenByRootSeeds(abeTxInputDescs []*AbeTxInputDescByRootSeeds, abeTxOutputDescs []*AbeTxOutputDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {

	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(transferTxMsgTemplate.Version)
	if err != nil {
		return nil, err
	}

	//	Note that only CryptoSchemePQRingCTX supports TransferTxGenByRootSeeds.

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxTransferTxGenByRootSeeds(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)

	default:
		return nil, fmt.Errorf("TransferTxGenByRootSeeds: the crypto scheme obained by transferTxMsgTemplate.Version (%d) is not CryptoSchemePQRingCTX", cryptoScheme)
	}

}

func TransferTxGenByRandSeeds(abeTxInputDescs []*AbeTxInputDescByRandSeeds, abeTxOutputDescs []*AbeTxOutputDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {

	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(transferTxMsgTemplate.Version)
	if err != nil {
		return nil, err
	}

	//	Note that only CryptoSchemePQRingCTX supports TransferTxGenByRootSeeds.

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxTransferTxGenByRandSeeds(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)

	default:
		return nil, fmt.Errorf("TransferTxGenByRootSeeds: Unsupported crypto scheme")
	}

}

// TransferTxGenByKeys generates a new MsgTxAbe by filling the TxIns[].serialNumber, TxOuts[], and the TxWitness of the input transferTxMsgTemplate.
// reviewed on 2023.12.21
func TransferTxGenByKeys(abeTxInputDescs []*AbeTxInputDescByKeys, abeTxOutputDescs []*AbeTxOutputDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {

	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(transferTxMsgTemplate.Version)
	if err != nil {
		return nil, err
	}
	//	Note that a transferTxMsgTemplate may be created by CreateTransferTxMsgTemplate in an early version, so that the transferTxMsgTemplate.Version is old version.

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		// This is to achieve back-compatibility with CryptoSchemePQRingCT.
		// Before the BlockHeightMLP, the caller may use the transferTxMsgTemplate.Version that maps to CryptoSchemePQRingCT.
		// Actually, this should not happen, since the caller with abec/abecryptox should have used a new crypto-scheme.
		pqringctAbeTxInputDescs := make([]*abecrypto.AbeTxInputDesc, len(abeTxInputDescs))
		pqringctAbeTxOutputDescs := make([]*abecrypto.AbeTxOutputDesc, len(abeTxOutputDescs))
		for i := 0; i < len(abeTxInputDescs); i++ {
			abeTxInputDesc := abeTxInputDescs[i]
			ringId := abeTxInputDesc.txoRing.RingId()
			pqringctAbeTxInputDescs[i] = abecrypto.NewAbeTxInputDescWithFullRing(&ringId, abeTxInputDesc.txoRing, abeTxInputDesc.sidx,
				abeTxInputDesc.cryptoAddress, abeTxInputDesc.cryptoSpsk, abeTxInputDesc.cryptoSnsk, abeTxInputDesc.cryptoVsk,
				abeTxInputDesc.value)
		}
		for i := 0; i < len(abeTxOutputDescs); i++ {
			pqringctAbeTxOutputDescs[i] = abecrypto.NewAbeTxOutDesc(abeTxOutputDescs[i].cryptoAddress, abeTxOutputDescs[i].value)
		}

		trTx, err := abecrypto.TransferTxGen(pqringctAbeTxInputDescs, pqringctAbeTxOutputDescs, transferTxMsgTemplate)
		if err != nil {
			return nil, err
		}
		return trTx, nil

	case abecryptoxparam.CryptoSchemePQRingCTX:
		trTx, err := pqringctxTransferTxGenByKeys(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)
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
func TransferTxVerify(transferTx *wire.MsgTxAbe, abeTxInDetails []*AbeTxInDetail) error {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(transferTx.Version)
	if err != nil {
		return err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		pqringctAbeTxInDetails := make([]*abecrypto.AbeTxInDetail, len(abeTxInDetails))
		for i := 0; i < len(abeTxInDetails); i++ {
			abeTxInDetail := abeTxInDetails[i]
			pqringctAbeTxInDetails[i] = abecrypto.NewAbeTxInDetail(abeTxInDetail.ringId, abeTxInDetail.txoList, abeTxInDetail.serialNumber)
		}

		err = abecrypto.TransferTxVerify(transferTx, pqringctAbeTxInDetails)
		if err != nil {
			return err
		}

	case abecryptoxparam.CryptoSchemePQRingCTX:
		err = pqringctxTransferTxVerify(abecryptoxparam.PQRingCTXPP, transferTx, abeTxInDetails)
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
// reviewed on 2024.01.04
func GetTxoPrivacyLevel(abeTxo *wire.TxOutAbe) (abecryptoxkey.PrivacyLevel, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return 0, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		return abecryptoxkey.PrivacyLevelRINGCTPre, nil

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetTxoPrivacyLevel(abecryptoxparam.PQRingCTXPP, abeTxo)
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
func GetTxoSerializeSizeApprox(txVersion uint32, cryptoAddressPayTo []byte) (int, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		return abecryptoparam.GetTxoSerializeSizeApprox(txVersion)
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetTxoSerializeSize(abecryptoxparam.PQRingCTXPP, cryptoAddressPayTo)
	default:
		return 0, fmt.Errorf("GetTxoSerializeSizeApprox: Unsupported txVersion")
	}
}

// ExtractPublicRandFromTxo returns the PublicRand in the CoinAddress of the input wire.TxOutAbe.
// reviewed on 2023.12.31
// reviewed on 2024.01.24
func ExtractPublicRandFromTxo(abeTxo *wire.TxOutAbe) (publicRand []byte, err error) {
	if abeTxo == nil {
		return nil, fmt.Errorf("ExtractPublicRandFromTxo: the input abeTxo is nil")
	}

	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxExtractPublicRandFromTxo(abecryptoxparam.PQRingCTXPP, abeTxo)
	default:
		return nil, fmt.Errorf("ExtractPublicRandFromTxo: the crypto-scheme obtained from abeTxo.Version is not CryptoSchemePQRingCTX")
	}

	// return nil, err
}

// ExtractCoinAddressFromTxo returns the coinAddress of the input TxOutAbe.
// refactored on 2024.01.24 by Alice.
// todo: review
func ExtractCoinAddressFromTxo(abeTxo *wire.TxOutAbe) (coinAddress []byte, err error) {
	if abeTxo == nil {
		return nil, fmt.Errorf("ExtractCoinAddressFromTxo: the input abeTxo is nil")
	}

	cryptoSchemeByTxVersion, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return nil, err
	}

	switch cryptoSchemeByTxVersion {
	case abecryptoxparam.CryptoSchemePQRingCT:
		return abecrypto.ExtractCoinAddressFromTxoScript(abeTxo.TxoScript, abecryptoparam.CryptoSchemePQRingCT)

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxExtractCoinAddressFromTxo(abecryptoxparam.PQRingCTXPP, abeTxo)

	default:
		return nil, fmt.Errorf("ExtractCoinAddressFromTxo: unsupported TxOutAbe.version")
	}
}

// TxoCoinDetectByCoinDetectorRootKey checks whether an abeTxo belongs to the owner of coinDetectorRootKey.
// todo: review
func TxoCoinDetectByCoinDetectorRootKey(abeTxo *wire.TxOutAbe, coinDetectorRootKey []byte) (bool, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return false, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		// Only Txo with version corresponds to CryptoSchemePQRingCTX could be checked using DetectorKey.
		// Note that the Txo still could be one that does not support detect.
		return pqringctxTxoCoinDetectByCoinDetectorRootKey(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxo, coinDetectorRootKey)

	default:
		return false, fmt.Errorf("TxoCoinDetectByCoinDetectorRootKey: the cryptoScheme corresponding to abeTxo.Version is not CryptoSchemePQRingCTX")
	}
}

// TxoCoinDetectByCryptoDetectorKey checks whether an abeTxo belongs to the owner of cryptoDetectorKey.
// NOTE: From the view of users, detectorKey only has two layers, namely CoinDetectorRootKey and CryptoDetectorKey.
// This is different from the SpendKey.
// todo: review
func TxoCoinDetectByCryptoDetectorKey(abeTxo *wire.TxOutAbe, cryptoDetectorKey []byte) (bool, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return false, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		// Only Txo with version corresponds to CryptoSchemePQRingCTX could be checked using DetectorKey.
		// Note that the Txo still could be one that does not support detect.
		return pqringctxTxoCoinDetectByCryptoDetectorKey(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxo, cryptoDetectorKey)

	default:
		return false, fmt.Errorf("TxoCoinDetectorByDetectorKey: the cryptoScheme corresponding to abeTxo.Version is not CryptoSchemePQRingCTX")
	}
}

// TxoCoinReceiveByRootSeeds
// todo: review
func TxoCoinReceiveByRootSeeds(abeTxo *wire.TxOutAbe, coinValueKeyRootSeed []byte, coinDetectorRootKey []byte) (valid bool, value uint64, err error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return false, 0, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		// Only Txo with version corresponds to CryptoSchemePQRingCTX could be checked using DetectorKey.
		// Note that the Txo still could be one that does not support detect.
		return pqringctxTxoCoinReceiveByRootSeeds(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxo, coinValueKeyRootSeed, coinDetectorRootKey)

	default:
		return false, 0, fmt.Errorf("TxoCoinReceiveByRootSeeds: the cryptoScheme corresponding to abeTxo.Version is not CryptoSchemePQRingCTX")
	}
}

// TxoCoinReceiveByRandSeeds
// todo: review
func TxoCoinReceiveByRandSeeds(abeTxo *wire.TxOutAbe, coinValueKeyRandSeed []byte, coinDetectorKey []byte) (valid bool, value uint64, err error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return false, 0, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		// Only Txo with version corresponds to CryptoSchemePQRingCTX could be checked using DetectorKey.
		// Note that the Txo still could be one that does not support detect.
		return pqringctxTxoCoinReceiveByRandSeeds(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxo, coinValueKeyRandSeed, coinDetectorKey)

	default:
		return false, 0, fmt.Errorf("TxoCoinReceiveByRandSeeds: the cryptoScheme corresponding to abeTxo.Version is not CryptoSchemePQRingCTX")
	}
}

// TxoCoinReceiveByKeys
// todo: review
func TxoCoinReceiveByKeys(abeTxo *wire.TxOutAbe, cryptoAddress []byte, cryptoValueSecretKey []byte) (bool, uint64, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return false, 0, err
	}
	return pqringctxTxoCoinReceiveByKeys(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxo, cryptoAddress, cryptoValueSecretKey)
}

// PseudonymTxoCoinParse parses the input (Pseudonym-Privacy) TxoMLP to its (coinAddress, coinValue) pair, and
// return an err if it is not a Pseudonym-Privacy Txo.
// todo: review
func PseudonymTxoCoinParse(abeTxo *wire.TxOutAbe) (coinAddress []byte, coinValue uint64, err error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return nil, 0, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		return nil, 0, fmt.Errorf("PseudonymTxoCoinParse: Txo with version corresponding to cryptoScheme CryptoSchemePQRingCT could not be PseudonymTxoCoin")

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxPseudonymTxoCoinParse(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxo)

	default:
		return nil, 0, fmt.Errorf("PseudonymTxoCoinParse: the cryptoScheme (%d) implied by abeTxo.Version is not supported", cryptoScheme)
	}
}

// TxoCoinSerialNumberGenByRootSeed generates serialNumber for the input TxOutAbe, using the input cryptoSerialNumberSecretKey.
// NOTE: the input coinSerialNumberKeyRootSeed could be nil, for example, when the input TxOutAbe is on a Pseudonym-Privacy address.
// todo: review
func TxoCoinSerialNumberGenByRootSeed(abeTxo *wire.TxOutAbe, ringId wire.RingId, txoIndexInRing uint8, coinSerialNumberKeyRootSeed []byte) ([]byte, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		//	Note that the case could still be on an address with privacyLevel = PrivacyLevelRINGCTPre, and that will return an error.
		return pqringctxTxoCoinSerialNumberGenByRootSeed(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxo, ringId, txoIndexInRing, coinSerialNumberKeyRootSeed)

	default:
		return nil, fmt.Errorf("TxoCoinSerialNumberGenByRandSeed: the crypto-scheme (%d) corresponding to abeTxo.Version is not CryptoSchemePQRingCTX", cryptoScheme)
	}
}

// TxoCoinSerialNumberGenByRandSeed generates serialNumber for the input TxOutAbe, using the input coinSerialNumberKeyRandSeed.
// NOTE: the input coinSerialNumberKeyRandSeed could be nil, for example, when the input TxOutAbe is on a Pseudonym-Privacy address.
// todo: review
func TxoCoinSerialNumberGenByRandSeed(abeTxo *wire.TxOutAbe, ringId wire.RingId, txoIndexInRing uint8, coinSerialNumberKeyRandSeed []byte) ([]byte, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		//	Note that the case could still be on an address with privacyLevel = PrivacyLevelRINGCTPre, and that will return an error.
		return pqringctxTxoCoinSerialNumberGenByRandSeed(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxo, ringId, txoIndexInRing, coinSerialNumberKeyRandSeed)

	default:
		return nil, fmt.Errorf("TxoCoinSerialNumberGenByRandSeed: the crypto-scheme (%d) corresponding to abeTxo.Version is not CryptoSchemePQRingCTX", cryptoScheme)
	}
}

// TxoCoinSerialNumberGenByKey generates serialNumber for the input TxOutAbe, using the input cryptoSerialNumberSecretKey.
// NOTE: the input cryptoSerialNumberSecretKey could be nil, for example, when the input TxOutAbe is on a Pseudonym-Privacy address.
// todo: review
func TxoCoinSerialNumberGenByKey(abeTxo *wire.TxOutAbe, ringId wire.RingId, txoIndexInRing uint8, cryptoSerialNumberSecretKey []byte) ([]byte, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		return abecrypto.TxoCoinSerialNumberGen(abeTxo, ringId, txoIndexInRing, cryptoSerialNumberSecretKey)

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxTxoCoinSerialNumberGenByKey(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxo, ringId, txoIndexInRing, cryptoSerialNumberSecretKey)

	default:
		return nil, fmt.Errorf("TxoCoinSerialNumberGenByKey: the crypto-scheme (%d) corresponding to abeTxo.Version is not supported", cryptoScheme)
	}
}

// Abec uses the fixed-ring mechanism, and uses (ringHash, index) as the uniqe identifier of Txo in blockchain.
// serializedSksn is the serializedSksn generated by the CryptoAddressKeyGen() algorithm,
// and what the format is depends on the underlying crypto-scheme.
// todo: remove this.
//func TxoCoinSerialNumberGen(abeTxo *wire.TxOutAbe, ringHash chainhash.Hash, txoIndexInRing uint8, serializedSksn []byte) ([]byte, error) {
//	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
//	if err != nil {
//		return nil, err
//	}
//
//	switch cryptoScheme {
//	case abecryptoxparam.CryptoSchemePQRingCT:
//		return abecrypto.TxoCoinSerialNumberGen(abeTxo, ringHash, txoIndexInRing, serializedSksn)
//	case abecryptoxparam.CryptoSchemePQRingCTX:
//		return pqringctTxoCoinSerialNumberGen(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxo, ringHash, txoIndexInRing, serializedSksn)
//
//	default:
//		return nil, fmt.Errorf("TxoCoinSerialNumberGen: Unsupported crypto scheme")
//	}
//}

//	APIs for Txos	end

//	APIs for TxWitness	begin

// GetCbTxWitnessSerializeSizeApprox returns the approximate serialize size for CoinbaseTxWitness, which is decided by the TxVersion and the number of out Txo.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for CoinbaseTxWitness actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
// reviewed on 2023.12.07
// reviewed on 2024.01.01, by Alice
// refactored on 2024.01.24, by Alice, pqringctx-Layer takes cryptoAddress as input.
func GetCbTxWitnessSerializeSizeApprox(txVersion uint32, cryptoAddressListPayTo [][]byte) (int, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		return abecryptoparam.GetCbTxWitnessSerializeSizeApprox(txVersion, len(cryptoAddressListPayTo))

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetTxWitnessCbTxSerializeSizeByDesc(abecryptoxparam.PQRingCTXPP, cryptoAddressListPayTo)

	default:
		return 0, fmt.Errorf("GetCbTxWitnessSerializeSizeApprox: Unsupported txVersion")
	}
}

// GetTrTxWitnessSerializeSizeApprox returns the approximate serialize size for TransferTxWitness,
// which is decided by the TxVersion and description of the input and output.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for TransferTxWitness actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
// todo: review
func GetTrTxWitnessSerializeSizeApprox(txVersion uint32,
	inForRing uint8, inForSingleDistinct uint8, inRingSizes []uint8,
	outForRing uint8, vPublic int64) (int, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:

		inputRingSizes := make([]int, len(inRingSizes))
		for i := 0; i < len(inputRingSizes); i++ {
			inputRingSizes[i] = int(inRingSizes[i])
		}
		return abecryptoparam.GetTrTxWitnessSerializeSizeApprox(txVersion, txVersion, inputRingSizes, int(outForRing))

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetTxWitnessTrTxSerializeSizeByDesc(abecryptoxparam.PQRingCTXPP, inForRing, inForSingleDistinct, outForRing, inRingSizes, vPublic)

	default:
		return 0, fmt.Errorf("GetTrTxWitnessSerializeSizeApprox: the input txVersion (%d) is not supported", txVersion)
	}
}

//	APIs for TxWitness	end

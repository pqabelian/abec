package abecryptox

import (
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/wire"
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
func CoinbaseTxVerify(coinbaseTx *wire.MsgTxAbe) (bool, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(coinbaseTx.Version)
	if err != nil {
		return false, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		valid, err := abecrypto.CoinbaseTxVerify(coinbaseTx)
		if err != nil {
			return false, err
		}
		return valid, nil
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxCoinbaseTxVerify(abecryptoxparam.PQRingCTXPP, coinbaseTx)
	default:
		return false, fmt.Errorf("CoinbaseTxVerify: Unsupported crypto scheme")
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
		return pqringctxTransferTxGenByRootSeeds(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)

	default:
		return nil, fmt.Errorf("TransferTxGenByRootSeeds: Unsupported crypto scheme")
	}

}

// TransferTxGen generates a new MsgTxAbe by filling the TxIns[].serialNumber, TxOuts[], and the TxWitness of the input transferTxMsgTemplate.
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

// todo: review
func TransferTxVerify(transferTx *wire.MsgTxAbe, abeTxInDetails []*AbeTxInDetail) (bool, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(transferTx.Version)
	if err != nil {
		return false, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		pqringctAbeTxInDetails := make([]*abecrypto.AbeTxInDetail, len(abeTxInDetails))
		for i := 0; i < len(abeTxInDetails); i++ {
			abeTxInDetail := abeTxInDetails[i]
			pqringctAbeTxInDetails[i] = abecrypto.NewAbeTxInDetail(abeTxInDetail.ringId, abeTxInDetail.txoList, abeTxInDetail.serialNumber)
		}

		valid, err := abecrypto.TransferTxVerify(transferTx, pqringctAbeTxInDetails)
		if err != nil {
			return false, err
		}
		return valid, nil

	case abecryptoxparam.CryptoSchemePQRingCTX:
		valid, err := pqringctxTransferTxVerify(abecryptoxparam.PQRingCTXPP, transferTx, abeTxInDetails)
		if err != nil {
			return false, err
		}
		return valid, nil
	default:
		return false, fmt.Errorf("TransferTxVerify: Unsupported crypto scheme")
	}
}

//	APIs for Transactions	end

//	APIs for AddressKey-Encode-Format	begin
//	APIs for AddressKey-Encode-Format	end

//	APIs for Txos	begin

// GetTxoPrivacyLevel returns the PrivacyLevel of the input wire.TxOutAbe,
// which is determined by its version and its coinAddress.
// todo: review
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

// GetTxoSerializeSizeApprox returns the approximate serialize size for Txo, which is decided by the TxVersion.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for Txo actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
// reviewed on 2023.12.07
func GetTxoSerializeSizeApprox(txVersion uint32, cryptoAddress []byte) (int, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		return abecryptoparam.GetTxoSerializeSizeApprox(txVersion)
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetTxoSerializeSize(abecryptoxparam.PQRingCTXPP, cryptoAddress)
	default:
		return 0, fmt.Errorf("GetTxoSerializeSizeApprox: Unsupported txVersion")
	}
}

// ExtractPublicRandFromTxo returns the PublicRand in the CoinAddress of the input wire.TxOutAbe.
// reviewed on 2023.12.31
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

	return nil, err
}

//	APIs for Txos	end

//	APIs for TxWitness	begin

// GetCbTxWitnessSerializeSizeApprox returns the approximate serialize size for CoinbaseTxWitness, which is decided by the TxVersion and the number of out Txo.
// Note that the transactions are generated and versified by the underlying crypto-scheme,
// the approximate serialize size for CoinbaseTxWitness actually depends on the underlying crypto-scheme.
// That's why txVersion is required as the input for this function.
// reviewed on 2023.12.07
func GetCbTxWitnessSerializeSizeApprox(txVersion uint32, cryptoAddressListPayTo [][]byte) (int, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		return abecryptoparam.GetCbTxWitnessSerializeSizeApprox(txVersion, len(cryptoAddressListPayTo))
	case abecryptoxparam.CryptoSchemePQRingCTX:
		if len(cryptoAddressListPayTo) == 0 {
			return 0, fmt.Errorf("GetCbTxWitnessSerializeSizeApprox: the input cryptoAddressListPayTo is empty")
		}
		coinAddressListPayTo := make([][]byte, len(cryptoAddressListPayTo))
		for i := 0; i < len(cryptoAddressListPayTo); i++ {
			//	Note that the cryptoAddressListPayTo[i] may not be generated by pqringctx,
			//	we call ParseCryptoAddress() to cover all cases.
			_, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(cryptoAddressListPayTo[i])
			if err != nil {
				return 0, err
			}
			coinAddressListPayTo[i] = coinAddress
		}
		return pqringctxGetCbTxWitnessSerializeSize(abecryptoxparam.PQRingCTXPP, coinAddressListPayTo)
	default:
		return 0, fmt.Errorf("GetCbTxWitnessSerializeSizeApprox: Unsupported txVersion")
	}
}

//	APIs for TxWitness	end

package abecryptox

import (
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/wire"
)

// CryptoAddressKeyGen generates cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk from the param randSeed.
// The param randSeed is a randomness that will be used to in randomized algorithms to make the algorithms be deterministic to the caller.
// The caller should make sure that randSeed is random and have sufficient entropy.
// (1) For the case of privacyLevel == abecryptoxparam.PrivacyLevelRINGCT, randSeed should have size of TWO times of CryptoScheme's ParamSeedBytesLen (in bytes), one for address and one for value-privacy.
// (2) For the case of privacyLevel == abecryptoxparam.PrivacyLevelPSEUDONYM, randSeed should have size of CryptoScheme's ParamSeedBytesLen (in bytes), which is used to address.
// (Note that CryptoScheme's ParamSeedBytesLen could be obtained by GetCryptoSchemeParamSeedBytesLen().)
// Accordingly,
// for the case of privacyLevel == abecryptoxparam.PrivacyLevelPSEUDONYM, cryptoSnsk and cryptoVsk will be nil.
// reviewed on 2032.12.07
func CryptoAddressKeyGen(randSeed []byte, cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel abecryptoxparam.PrivacyLevel) (retCryptoAddress []byte, retCryptoSpsk []byte, retCryptoSnsk []byte, retCryptoVsk []byte, err error) {
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		// This is to achieve back-compatibility with CryptoSchemePQRingCT.
		// The caller, e.g., the wallet created with CryptoSchemePQRingCT will still call this function with cryptoScheme=CryptoSchemePQRingCT.
		return abecrypto.CryptoAddressKeyGen(randSeed, abecryptoparam.CryptoSchemePQRingCT)

	case abecryptoxparam.CryptoSchemePQRingCTX:
		cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, err := pqringctxCryptoAddressKeyGen(abecryptoxparam.PQRingCTXPP, randSeed, cryptoScheme, privacyLevel)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil

	default:
		return nil, nil, nil, nil, errors.New("CryptoAddressKeyGen: unsupported crypto-scheme")
	}
	//return nil, nil, nil, nil, nil
}

// APIs for Transactions	begin

// CoinbaseTxGen takes as input the transaction material and outputs a *wire.MsgTxAbe
// reviewed on 2023.12.07
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
// todo review
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

// CreateTransferTxMsgTemplate creates a *wire.MsgTxAbe template, which will be used when calling TransferTxGen().
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
//
//	a caller may use other methods to create a TransferTxMsgTemplate.
//
// todo: review
func CreateTransferTxMsgTemplate(abeTxInputDescs []*AbeTxInputDesc, abeTxOutputDescs []*AbeTxOutputDesc, txFee uint64, txMemo []byte) (*wire.MsgTxAbe, error) {

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

func TransferTxGen(abeTxInputDescs []*AbeTxInputDesc, abeTxOutputDescs []*AbeTxOutputDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {

	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(transferTxMsgTemplate.Version)
	if err != nil {
		return nil, err
	}
	//	Note that a transferTxMsgTemplate may be created by CreateTransferTxMsgTemplate in an early version, so that the transferTxMsgTemplate.Version is old version.

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		// This is to achieve back-compatibility with CryptoSchemePQRingCT.
		// Before the BlockHeightMLP, the caller may use the transferTxMsgTemplate.Version that maps to CryptoSchemePQRingCT.
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
		trTx, err := pqringctxTransferTxGen(abecryptoxparam.PQRingCTXPP, cryptoScheme, abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)
		if err != nil {
			return nil, err
		}
		return trTx, nil
	default:
		return nil, errors.New("TransferTxGen: Unsupported crypto scheme")
	}

}

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
			pqringctAbeTxInDetails[i] = abecrypto.NewAbeTxInDetail(abeTxInDetail.ringHash, abeTxInDetail.txoList, abeTxInDetail.serialNumber)
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
		return false, errors.New("TransferTxVerify: Unsupported crypto scheme")
	}
}

//	APIs for Transactions	end

//	APIs for AddressKey-Encode-Format	begin
//	APIs for AddressKey-Encode-Format	end

//	APIs for Txos	begin
//	APIs for Txos	end

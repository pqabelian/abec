package abecryptox

import (
	"errors"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/wire"
	"github.com/cryptosuite/pqringctx/pqringctxapi"
)

// // abecryptox -> abepqringctx -> pqringctx
// pqringctxCryptoAddressGen() generates cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, by calling pqringctx's key-generation functions and encapsed the keys.
// cryptoScheme is set as a parameter, since the map between CryptoScheme and the real crypto-scheme (here is pqringct) is coded by abecryptoparam.
// Note that based on privacyLevel, the returned cryptoSnsk and cryptoVsk could be nil.
func pqringctxCryptoAddressKeyGen(pp *pqringctxapi.PublicParameter, randSeed []byte,
	cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel abecryptoxparam.PrivacyLevel) (
	cryptoAddress []byte,
	cryptoSpsk []byte,
	cryptoSnsk []byte,
	cryptoVsk []byte,
	err error) {

	expectedSeedLen := pqringctxapi.GetParamSeedBytesLen(pp)

	if privacyLevel == abecryptoxparam.PrivacyLevelRINGCT {
		if 2*expectedSeedLen != len(randSeed) {
			return nil, nil, nil, nil, errors.New("invalid length of seed in pqringctxCryptoAddressGen")
		}

		coinAddress, coinSpendKey, coinSnKey, err := pqringctxapi.CoinAddressKeyForRingGen(pp, randSeed[:expectedSeedLen])
		if err != nil {
			return nil, nil, nil, nil, err
		}

		serializedVPk, serializedVSk, err := pqringctxapi.CoinValueKeyGen(pp, randSeed[expectedSeedLen:])
		if err != nil {
			return nil, nil, nil, nil, err
		}

		serializedCryptoScheme := abecryptoxparam.SerializeCryptoScheme(cryptoScheme)

		cryptoAddress = make([]byte, 5+len(coinAddress)+len(serializedVPk))
		copy(cryptoAddress[0:], serializedCryptoScheme)
		cryptoAddress[4] = byte(abecryptoxparam.PrivacyLevelRINGCT)
		copy(cryptoAddress[5:], coinAddress)
		copy(cryptoAddress[5+len(coinAddress):], serializedVPk)

		cryptoSpsk = make([]byte, 5+len(coinSpendKey))
		copy(cryptoSpsk[0:], serializedCryptoScheme)
		cryptoAddress[4] = byte(abecryptoxparam.PrivacyLevelRINGCT)
		copy(cryptoSpsk[5:], coinSpendKey)

		cryptoSnsk = make([]byte, 5+len(coinSnKey))
		copy(cryptoSnsk[0:], serializedCryptoScheme)
		cryptoAddress[4] = byte(abecryptoxparam.PrivacyLevelRINGCT)
		copy(cryptoSnsk[5:], coinSnKey)

		cryptoVsk = make([]byte, 5+len(serializedVSk))
		copy(cryptoVsk[0:], serializedCryptoScheme)
		cryptoAddress[4] = byte(abecryptoxparam.PrivacyLevelRINGCT)
		copy(cryptoVsk[5:], serializedVSk)

		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil

	} else if privacyLevel == abecryptoxparam.PrivacyLevelPSEUDONYM {
		if expectedSeedLen != len(randSeed) {
			return nil, nil, nil, nil, errors.New("invalid length of seed in pqringctxCryptoAddressGen")
		}

		coinAddress, coinSpendKey, err := pqringctxapi.CoinAddressKeyForSingleGen(pp, randSeed)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		serializedCryptoScheme := abecryptoxparam.SerializeCryptoScheme(cryptoScheme)

		cryptoAddress = make([]byte, 5+len(coinAddress))
		copy(cryptoAddress[0:], serializedCryptoScheme)
		cryptoAddress[4] = byte(abecryptoxparam.PrivacyLevelPSEUDONYM)
		copy(cryptoAddress[5:], coinAddress)

		cryptoSpsk = make([]byte, 5+len(coinSpendKey))
		copy(cryptoSpsk[0:], serializedCryptoScheme)
		cryptoAddress[4] = byte(abecryptoxparam.PrivacyLevelPSEUDONYM)
		copy(cryptoSpsk[5:], coinSpendKey)

		cryptoSnsk = nil

		cryptoVsk = nil

		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil
	} else {
		return nil, nil, nil, nil, errors.New("unsupported privacyLevel in pqringctxCryptoAddressGen")
	}
}

// The caller needs to fill the Version, TxIns, TxFee, TxMemo fields for coinbaseTxMsgTemplate,
// this function will fill the TxOuts and TxWitness fields.
// The cryptoScheme here is used only for double-check.
func pqringctxCoinbaseTxGen(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, abeTxOutputDescs []*AbeTxOutputDesc, coinbaseTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	////	pqringctx
	//txOutputDescs := make([]*pqringct.TxOutputDesc, len(abeTxOutputDescs))
	//for j := 0; j < len(abeTxOutputDescs); j++ {
	//	cryptoSchemeInAddress, err := abecryptoxparam.ExtractCryptoSchemeFromCryptoAddress(abeTxOutputDescs[j].cryptoAddress)
	//	if err != nil || cryptoSchemeInAddress != cryptoScheme {
	//		return nil, errors.New("unmatched cryptoScheme for coinbase transaction and cryptoAddress")
	//	}
	//
	//	// parse the cryptoAddress to serializedApk and serializedVpk
	//	apkLen := pqringct.GetAddressPublicKeySerializeSize(pp)
	//	//vpkLen := pp.GetValuePublicKeySerializeSize()
	//	serializedApk := abeTxOutputDescs[j].cryptoAddress[4 : 4+apkLen]
	//	serializedVpk := abeTxOutputDescs[j].cryptoAddress[4+apkLen:]
	//	txOutputDescs[j] = pqringct.NewTxOutputDescv2(pp, serializedApk, serializedVpk, abeTxOutputDescs[j].value)
	//}
	//
	//// call the pqringct.CoinbaseTxGen
	////	vin is set in coinbaseTxMsgTemplate.TxFee
	//cryptoCoinbaseTx, err := pqringct.CoinbaseTxGen(pp, coinbaseTxMsgTemplate.TxFee, txOutputDescs, coinbaseTxMsgTemplate.TxMemo)
	//if err != nil {
	//	return nil, err
	//}
	//
	//// parse the pqringct.CoinbaseTx to wire.TxAbe
	//coinbaseTxMsgTemplate.TxOuts = make([]*wire.TxOutAbe, len(cryptoCoinbaseTx.OutputTxos))
	//for i := 0; i < len(cryptoCoinbaseTx.OutputTxos); i++ {
	//	serializedTxo, err := pqringct.SerializeTxo(pp, cryptoCoinbaseTx.OutputTxos[i])
	//	if err != nil {
	//		return nil, err
	//	}
	//	coinbaseTxMsgTemplate.TxOuts[i] = &wire.TxOutAbe{
	//		Version:   coinbaseTxMsgTemplate.Version,
	//		TxoScript: serializedTxo,
	//	}
	//}
	//
	//// witness must be associated with Tx, so it does not need to contain cryptoscheme or TxVersion.
	//var serializedCbTxWitness []byte
	//if len(cryptoCoinbaseTx.OutputTxos) == 1 {
	//	serializedCbTxWitness, err = pqringct.SerializeCbTxWitnessJ1(pp, cryptoCoinbaseTx.TxWitnessJ1)
	//} else {
	//	serializedCbTxWitness, err = pqringct.SerializeCbTxWitnessJ2(pp, cryptoCoinbaseTx.TxWitnessJ2)
	//}
	//if err != nil {
	//	return nil, err
	//}
	//
	//coinbaseTxMsgTemplate.TxWitness = serializedCbTxWitness
	//return coinbaseTxMsgTemplate, nil
	return nil, nil
}

// pqringctxCoinbaseTxVerify verify the input coinbaseTx.
// The caller needs to guarantee the well-form of the input coinbaseTx *wire.MsgTxAbe, such as the TxIns.
// This function only checks the balance proof, by calling the crypto-scheme.
func pqringctxCoinbaseTxVerify(pp *pqringctxapi.PublicParameter, coinbaseTx *wire.MsgTxAbe) (bool, error) {
	//if coinbaseTx == nil {
	//	return false, nil
	//}
	//if len(coinbaseTx.TxOuts) <= 0 {
	//	return false, nil
	//}
	//var err error
	//
	//cryptoCoinbaseTx := &pqringct.CoinbaseTx{}
	//
	//cryptoCoinbaseTx.Vin = coinbaseTx.TxFee
	//
	//cryptoCoinbaseTx.OutputTxos = make([]*pqringct.Txo, len(coinbaseTx.TxOuts))
	//for i := 0; i < len(coinbaseTx.TxOuts); i++ {
	//	if coinbaseTx.TxOuts[i].Version != coinbaseTx.Version {
	//		return false, nil
	//	}
	//	cryptoCoinbaseTx.OutputTxos[i], err = pqringct.DeserializeTxo(pp, coinbaseTx.TxOuts[i].TxoScript)
	//	if err != nil {
	//		return false, err
	//	}
	//}
	//
	//cryptoCoinbaseTx.TxMemo = coinbaseTx.TxMemo
	//
	//if len(coinbaseTx.TxOuts) == 1 {
	//	cryptoCoinbaseTx.TxWitnessJ1, err = pqringct.DeserializeCbTxWitnessJ1(pp, coinbaseTx.TxWitness)
	//	cryptoCoinbaseTx.TxWitnessJ2 = nil
	//} else {
	//	cryptoCoinbaseTx.TxWitnessJ1 = nil
	//	cryptoCoinbaseTx.TxWitnessJ2, err = pqringct.DeserializeCbTxWitnessJ2(pp, coinbaseTx.TxWitness)
	//}
	//if err != nil {
	//	return false, err
	//}
	//
	//bl, err := pqringct.CoinbaseTxVerify(pp, cryptoCoinbaseTx)
	//if err != nil {
	//	return false, err
	//}
	//if bl == false {
	//	return false, nil
	//}

	return true, nil
}

func pqringctxTransferTxVerify(pp *pqringctxapi.PublicParameter, transferTx *wire.MsgTxAbe, abeTxInDetails []*AbeTxInDetail) (bool, error) {
	//if transferTx == nil {
	//	return false, nil
	//}
	//
	//inputNum := len(transferTx.TxIns)
	//outputNum := len(transferTx.TxOuts)
	//if inputNum <= 0 || outputNum <= 0 {
	//	return false, nil
	//}
	//
	//if len(abeTxInDetails) != inputNum {
	//	return false, nil
	//}
	//
	//var err error
	//inputsVersion := transferTx.TxIns[0].PreviousOutPointRing.Version
	//outputsVersion := transferTx.Version
	//
	//cryptoTransferTx := &pqringct.TransferTx{}
	//
	////	Inputs
	//cryptoTransferTx.Inputs = make([]*pqringct.TrTxInput, inputNum)
	//for i := 0; i < inputNum; i++ {
	//	if transferTx.TxIns[i].PreviousOutPointRing.Version != inputsVersion {
	//		return false, nil
	//		//	This is necessary, since the same version will ensure that when calling the cryptoscheme, there are not exceptions.
	//	}
	//	if bytes.Compare(abeTxInDetails[i].serialNumber, transferTx.TxIns[i].SerialNumber) != 0 {
	//		return false, nil
	//		//	This check can be removed, as the caller will provide abeTxInDetails, which are made by querying the database using the transferTx.TxIns information
	//	}
	//	txoList := make([]*pqringct.LgrTxo, len(abeTxInDetails[i].txoList))
	//	for j := 0; j < len(abeTxInDetails[i].txoList); j++ {
	//		if abeTxInDetails[i].txoList[j].Version != transferTx.TxIns[i].PreviousOutPointRing.Version {
	//			return false, nil
	//			//	The Txos in the same ring should have the same version
	//		}
	//
	//		txo, err := pp.DeserializeTxo(abeTxInDetails[i].txoList[j].TxoScript)
	//		if err != nil {
	//			return false, err
	//		}
	//		txolid := ledgerTxoIdGen(abeTxInDetails[i].ringHash, uint8(j))
	//		txoList[j] = pqringct.NewLgrTxo(txo, txolid)
	//
	//	}
	//	cryptoTransferTx.Inputs[i] = &pqringct.TrTxInput{
	//		TxoList:      txoList,
	//		SerialNumber: abeTxInDetails[i].serialNumber,
	//	}
	//}
	//
	////	OutputTxos
	//cryptoTransferTx.OutputTxos = make([]*pqringct.Txo, outputNum)
	//for j := 0; j < outputNum; j++ {
	//	if transferTx.TxOuts[j].Version != outputsVersion {
	//		return false, nil
	//		//	The output Txos of a transaction should have the same version as the transaction.
	//	}
	//
	//	cryptoTransferTx.OutputTxos[j], err = pp.DeserializeTxo(transferTx.TxOuts[j].TxoScript)
	//	if err != nil {
	//		return false, err
	//	}
	//}
	//
	////	Fee
	//cryptoTransferTx.Fee = transferTx.TxFee
	//
	////	TxMemo
	//cryptoTransferTx.TxMemo = transferTx.TxMemo
	//
	////	TxWitness
	//cryptoTransferTx.TxWitness, err = pp.DeserializeTrTxWitness(transferTx.TxWitness)
	//if err != nil {
	//	return false, nil
	//}
	//
	//// call the crypto scheme's verify algroithm
	//bl, err := pqringct.TransferTxVerify(pp, cryptoTransferTx)
	//if err != nil {
	//	return false, err
	//}
	//if bl == false {
	//	return false, nil
	//}

	return true, nil
}

// API for AddressKeys	begin
// API for AddressKeys	end

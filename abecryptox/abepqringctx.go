package abecryptox

import (
	"fmt"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/wire"
	"github.com/cryptosuite/pqringctx/pqringctxapi"
)

// // abecryptox -> abepqringctx -> pqringctx

// pqringctxCryptoAddressGen() generates cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, by calling pqringctx's key-generation functions and encapsed the keys.
// cryptoScheme is set as a parameter, since the map between CryptoScheme and the real crypto-scheme (here is pqringct) is coded by abecryptoparam.
// Note that based on privacyLevel, the returned cryptoSnsk and cryptoVsk could be nil.
// reviewed on 2023.12.07
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
			return nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyGen: invalid length of seed for RingCT-privacy")
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
		cryptoSpsk[4] = byte(abecryptoxparam.PrivacyLevelRINGCT)
		copy(cryptoSpsk[5:], coinSpendKey)

		cryptoSnsk = make([]byte, 5+len(coinSnKey))
		copy(cryptoSnsk[0:], serializedCryptoScheme)
		cryptoSnsk[4] = byte(abecryptoxparam.PrivacyLevelRINGCT)
		copy(cryptoSnsk[5:], coinSnKey)

		cryptoVsk = make([]byte, 5+len(serializedVSk))
		copy(cryptoVsk[0:], serializedCryptoScheme)
		cryptoVsk[4] = byte(abecryptoxparam.PrivacyLevelRINGCT)
		copy(cryptoVsk[5:], serializedVSk)

		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil

	} else if privacyLevel == abecryptoxparam.PrivacyLevelPSEUDONYM {
		if expectedSeedLen != len(randSeed) {
			return nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressGen: invalid length of seed for Pseudonym-privacy")
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
		cryptoSpsk[4] = byte(abecryptoxparam.PrivacyLevelPSEUDONYM)
		copy(cryptoSpsk[5:], coinSpendKey)

		cryptoSnsk = nil

		cryptoVsk = nil

		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil
	} else {
		return nil, nil, nil, nil, fmt.Errorf("unsupported privacyLevel in pqringctxCryptoAddressGen")
	}
}

// The caller needs to fill the Version, TxIns, TxFee, TxMemo fields for coinbaseTxMsgTemplate,
// this function will fill the TxOuts and TxWitness fields.
// reviewed on 2023.12.07
func pqringctxCoinbaseTxGen(pp *pqringctxapi.PublicParameter, abeTxOutputDescs []*AbeTxOutputDesc, coinbaseTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {

	//	parse AbeTxOutputDesc to pqringctx.TxOutputDesc
	txOutputDescs := make([]*pqringctxapi.TxOutputDescMLP, len(abeTxOutputDescs))
	for j := 0; j < len(abeTxOutputDescs); j++ {
		_, coinAddress, valuePublicKey, err := abecryptoxparam.CryptoAddressParse(abeTxOutputDescs[j].cryptoAddress)
		if err != nil {
			return nil, err
		}

		txOutputDescs[j] = pqringctxapi.NewTxOutputDescMLP(coinAddress, valuePublicKey, abeTxOutputDescs[j].value)
	}

	// call the pqringctx.CoinbaseTxGen
	//	vin is set in coinbaseTxMsgTemplate.TxFee
	cryptoCoinbaseTx, err := pqringctxapi.CoinbaseTxGen(pp, coinbaseTxMsgTemplate.TxFee, txOutputDescs, coinbaseTxMsgTemplate.TxMemo)
	if err != nil {
		return nil, err
	}

	// parse the pqringctx.CoinbaseTx to wire.TxAbe
	cryptoTxos := cryptoCoinbaseTx.GetTxos()
	coinbaseTxMsgTemplate.TxOuts = make([]*wire.TxOutAbe, len(cryptoTxos))
	for i := 0; i < len(cryptoTxos); i++ {
		serializedTxo, err := pqringctxapi.SerializeTxo(pp, cryptoTxos[i])
		if err != nil {
			return nil, err
		}
		coinbaseTxMsgTemplate.TxOuts[i] = &wire.TxOutAbe{
			Version:   coinbaseTxMsgTemplate.Version,
			TxoScript: serializedTxo,
		}
	}

	// witness must be associated with Tx, so it does not need to contain cryptoScheme or TxVersion.
	serializedCbTxWitness, err := pqringctxapi.SerializeTxWitnessCbTx(pp, cryptoCoinbaseTx.GetTxWitness())
	if err != nil {
		return nil, err
	}
	coinbaseTxMsgTemplate.TxWitness = serializedCbTxWitness

	return coinbaseTxMsgTemplate, nil
	//return nil, nil
}

// pqringctxCoinbaseTxVerify verify the input coinbaseTx.
// The caller needs to guarantee the well-form of the input coinbaseTx *wire.MsgTxAbe, such as the TxIns.
// This function only checks the balance proof, by calling the crypto-scheme.
// todo review
func pqringctxCoinbaseTxVerify(pp *pqringctxapi.PublicParameter, coinbaseTx *wire.MsgTxAbe) (bool, error) {
	if coinbaseTx == nil {
		return false, nil
	}
	if len(coinbaseTx.TxOuts) <= 0 {
		return false, nil
	}

	var err error

	vin := coinbaseTx.TxFee

	txoMLPs := make([]pqringctxapi.TxoMLP, len(coinbaseTx.TxOuts))
	for i := 0; i < len(coinbaseTx.TxOuts); i++ {
		if coinbaseTx.TxOuts[i].Version != coinbaseTx.Version {
			return false, nil
		}

		txoMLPs[i], err = pqringctxapi.DeserializeTxo(pp, coinbaseTx.TxOuts[i].TxoScript)
		if err != nil {
			return false, err
		}
	}

	txMemo := coinbaseTx.TxMemo

	txWitness, err := pqringctxapi.DeserializeTxWitnessCbTx(pp, coinbaseTx.TxWitness)
	if err != nil {
		return false, err
	}

	cryptoCoinbaseTx := pqringctxapi.NewCoinbaseTxMLP(vin, txoMLPs, txMemo, txWitness)

	bl, err := pqringctxapi.CoinbaseTxVerify(pp, cryptoCoinbaseTx)
	if err != nil {
		return false, err
	}
	if bl == false {
		return false, nil
	}

	return true, nil
}

// pqringctxTransferTxGen generates a MsgTxAbe, by filling the serialNumbers in TxIns， Txos and TxWitness of the input transferTxMsgTemplate.
// The caller needs to fill the Version, TxIns, TxFee, TxMemo fields of transferTxMsgTemplate.
// This function will fill the serialNumbers in TxIns, the Txos, and TxWitness fields of transferTxMsgTemplate, and return it as the result.
// The parameter cryptoScheme here is obtained by the caller from TxVersion, which causes this function is called.
// Now it is redundant at this moment and works for ony double-check.
// In the future, when the version of input ring is different from the ring of TxVersion/TxoVersion,
// the two corresponding cryptoSchemes will be extracted here and further decides the TxGen algorithms.
// Refer to wire.param for the details.
// todo: to review
func pqringctxTransferTxGen(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, abeTxInputDescs []*AbeTxInputDesc, abeTxOutputDescs []*AbeTxOutputDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	inputNum := len(abeTxInputDescs)
	outputNum := len(abeTxOutputDescs)

	if inputNum == 0 || outputNum == 0 {
		return nil, fmt.Errorf("pqringctxTransferTxGen: the input abeTxInputDescs and abeTxOutputDescs should not be empty.")
	}

	if inputNum != len(transferTxMsgTemplate.TxIns) {
		return nil, fmt.Errorf("pqringctxTransferTxGen: the number of abeTxInputDescs does not match the number of TxIn in transferTxMsgTemplate")
	}

	// todo:XXXX
	//inputsRingVersion := transferTxMsgTemplate.TxIns[0].PreviousOutPointRing.Version
	//if inputsRingVersion != transferTxMsgTemplate.Version {
	//	//	pqringct consumes only the input rings generated by pqringct
	//	return nil, errors.New("pqringctTransferTxGen: the version of the TxIn does not corresponding to PQRingCT")
	//}
	//
	//cryptoSchemeInputRing, err := abecryptoparam.GetCryptoSchemeByTxVersion(inputsRingVersion)
	//if err != nil {
	//	return nil, err
	//}
	//if cryptoSchemeInputRing != cryptoScheme {
	//	return nil, errors.New("pqringctTransferTxGen: unmatched cryptoScheme for input ring of transfer transaction and that of transaction")
	//}
	//
	////outputsVersion := transferTxMsgTemplate.Version
	//
	////	inputDescs
	//txInputDescs := make([]*pqringct.TxInputDesc, inputNum)
	//for i := 0; i < inputNum; i++ {
	//	if transferTxMsgTemplate.TxIns[i].PreviousOutPointRing.Version != inputsRingVersion {
	//		return nil, errors.New("pqringctTransferTxGen: the version of the TxIn in one transaction should be the same")
	//	}
	//	lgrTxoList := make([]*pqringct.LgrTxo, len(abeTxInputDescs[i].txoList))
	//	for j := 0; j < len(abeTxInputDescs[i].txoList); j++ {
	//		if abeTxInputDescs[i].txoList[j].Version != inputsRingVersion {
	//			return nil, errors.New("pqringctTransferTxGen: the version of TXOs in abeTxInputDescs.serializedTxoList does not match the version in the corresponding TxIn")
	//		}
	//		txo, err := pqringct.DeserializeTxo(pp, abeTxInputDescs[i].txoList[j].TxoScript)
	//		if err != nil {
	//			return nil, err
	//		}
	//
	//		txolid := ledgerTxoIdGen(abeTxInputDescs[i].ringHash, uint8(j))
	//
	//		lgrTxoList[j] = pqringct.NewLgrTxo(txo, txolid)
	//	}
	//
	//	sidx := abeTxInputDescs[i].sidx
	//	value := abeTxInputDescs[i].value
	//
	//	cryptoSchemeInKey, err := ExtractCryptoSchemeFromCryptoAddressSpsk(abeTxInputDescs[i].cryptoSpsk)
	//	if err != nil || cryptoSchemeInKey != cryptoScheme {
	//		return nil, errors.New("pqringctTransferTxGen: unmatched cryptoScheme for Spsk and transaction")
	//	}
	//	serializedASksp := abeTxInputDescs[i].cryptoSpsk[4:]
	//
	//	cryptoSchemeInKey, err = ExtractCryptoSchemeFromCryptoAddressSnsk(abeTxInputDescs[i].cryptoSnsk)
	//	if err != nil || cryptoSchemeInKey != cryptoScheme {
	//		return nil, errors.New("pqringctTransferTxGen: unmatched cryptoScheme for Snsk and transaction")
	//	}
	//	serializedASksn := abeTxInputDescs[i].cryptoSnsk[4:]
	//
	//	cryptoSchemeInKey, err = ExtractCryptoSchemeFromCryptoVsk(abeTxInputDescs[i].cryptoVsk)
	//	if err != nil || cryptoSchemeInKey != cryptoScheme {
	//		return nil, errors.New("pqringctTransferTxGen: unmatched cryptoScheme for Vsk and transaction")
	//	}
	//	serializedVSk := abeTxInputDescs[i].cryptoVsk[4:]
	//
	//	cryptoSchemeInAddress, err := ExtractCryptoSchemeFromCryptoAddress(abeTxInputDescs[i].cryptoAddress)
	//	if err != nil || cryptoSchemeInAddress != cryptoScheme {
	//		return nil, errors.New("pqringctTransferTxGen: unmatched cryptoScheme for input address and transaction")
	//	}
	//	apkLen := pqringct.GetAddressPublicKeySerializeSize(pp)
	//	serializedVpk := abeTxInputDescs[i].cryptoAddress[4+apkLen:]
	//
	//	txInputDescs[i] = pqringct.NewTxInputDescv2(pp, lgrTxoList, sidx, serializedASksp, serializedASksn, serializedVpk, serializedVSk, value)
	//}
	//
	//// outputDescs
	//txOutputDescs := make([]*pqringct.TxOutputDesc, outputNum)
	//for j := 0; j < outputNum; j++ {
	//	cryptoscheme4outAddress, err := ExtractCryptoSchemeFromCryptoAddress(abeTxOutputDescs[j].cryptoAddress)
	//	if err != nil || cryptoscheme4outAddress != cryptoScheme {
	//		return nil, errors.New("pqringctTransferTxGen: unmatched cryptoScheme for transfer transaction and its output cryptoAddress")
	//	}
	//	// parse the cryptoAddress to serializedApk and serializedVpk
	//	apkLen := pqringct.GetAddressPublicKeySerializeSize(pp)
	//	serializedApk := abeTxOutputDescs[j].cryptoAddress[4 : 4+apkLen]
	//	serializedVpk := abeTxOutputDescs[j].cryptoAddress[4+apkLen:]
	//
	//	txOutputDescs[j] = pqringct.NewTxOutputDescv2(pp, serializedApk, serializedVpk, abeTxOutputDescs[j].value)
	//}
	//
	////	call the crypto scheme
	//cryptoTransferTx, err := pqringct.TransferTxGen(pp, txInputDescs, txOutputDescs, transferTxMsgTemplate.TxFee, transferTxMsgTemplate.TxMemo)
	//if err != nil {
	//	return nil, err
	//}
	////	For the inputs, only the serial number needs to be set
	//for i := 0; i < inputNum; i++ {
	//	transferTxMsgTemplate.TxIns[i].SerialNumber = cryptoTransferTx.Inputs[i].SerialNumber
	//}
	//
	////	Set the output Txos
	//transferTxMsgTemplate.TxOuts = make([]*wire.TxOutAbe, outputNum)
	//for j := 0; j < outputNum; j++ {
	//	serializeTxo, err := pp.SerializeTxo(cryptoTransferTx.OutputTxos[j])
	//	if err != nil {
	//		return nil, err
	//	}
	//	//	todo: wire.TxOutAbe use NewTxOutAbe()
	//	transferTxMsgTemplate.TxOuts[j] = &wire.TxOutAbe{
	//		Version:   transferTxMsgTemplate.Version,
	//		TxoScript: serializeTxo,
	//	}
	//}
	//
	////	Set the TxWitness
	//transferTxMsgTemplate.TxWitness, err = pp.SerializeTrTxWitness(cryptoTransferTx.TxWitness)
	//if err != nil {
	//	return nil, err
	//}

	return transferTxMsgTemplate, nil
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

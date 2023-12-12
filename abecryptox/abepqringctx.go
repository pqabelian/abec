package abecryptox

import (
	"bytes"
	"fmt"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/cryptosuite/pqringctx/pqringctxapi"
)

// // abecryptox -> abepqringctx -> pqringctx

// The caller needs to fill the Version, TxIns, TxFee, TxMemo fields for coinbaseTxMsgTemplate,
// this function will fill the TxOuts and TxWitness fields.
// reviewed on 2023.12.07
func pqringctxCoinbaseTxGen(pp *pqringctxapi.PublicParameter, abeTxOutputDescs []*AbeTxOutputDesc, coinbaseTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {

	//	parse AbeTxOutputDesc to pqringctx.TxOutputDesc
	txOutputDescs := make([]*pqringctxapi.TxOutputDescMLP, len(abeTxOutputDescs))
	for j := 0; j < len(abeTxOutputDescs); j++ {
		_, coinAddress, coinValuePK, err := abecryptoxkey.CryptoAddressParse(abeTxOutputDescs[j].cryptoAddress)
		if err != nil {
			return nil, err
		}

		txOutputDescs[j] = pqringctxapi.NewTxOutputDescMLP(coinAddress, coinValuePK, abeTxOutputDescs[j].value)
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

// pqringctxTransferTxGen generates a MsgTxAbe,
// by filling TxIns[].serialNumber，Txos, and TxWitness of the input transferTxMsgTemplate.
// The caller needs to fill the Version, TxIns[].PreviousOutPointRing, TxFee, TxMemo fields of transferTxMsgTemplate.
// This function will fill the TxIns[].serialNumber，Txos, and TxWitness of the input transferTxMsgTemplate, and return it as the result.
// The parameter cryptoScheme here is obtained by the caller from TxVersion, which causes this function is called.
// Now it is redundant at this moment and works for ony double-check.
// In the future, when the version of input ring is different from the ring of TxVersion/TxoVersion,
// the two corresponding cryptoSchemes will be extracted here and further decides the TxGen algorithms.
// Refer to wire.param for the details.
// todo: to review
// todo: review CryptoValueSecretKeyParse
// todo: review pqringctxapi.TransferTxGen
// todo: review cryptoTransferTx.GetTxInputs()
// todo: review cryptoTransferTx.GetTxos()
// todo: review cryptoTransferTx.GetTxWitness()
// todo: review pqringctxapi.SerializeTxWitnessTrTx
func pqringctxTransferTxGen(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, abeTxInputDescs []*AbeTxInputDesc, abeTxOutputDescs []*AbeTxOutputDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	// just redundant double check
	cryptoSchemeFromTxVersion, err := abecryptoxparam.GetCryptoSchemeByTxVersion(transferTxMsgTemplate.Version)
	if err != nil {
		return nil, err
	}
	if cryptoSchemeFromTxVersion != cryptoScheme {
		return nil, fmt.Errorf("pqringctxTransferTxGen: the input cryptoScheme is different from that implied by transferTxMsgTemplate.Version")
	}

	inputNum := len(abeTxInputDescs)
	outputNum := len(abeTxOutputDescs)

	if inputNum == 0 || outputNum == 0 {
		return nil, fmt.Errorf("pqringctxTransferTxGen: neither the input abeTxInputDescs or abeTxOutputDescs could be empty")
	}

	if inputNum != len(transferTxMsgTemplate.TxIns) {
		return nil, fmt.Errorf("pqringctxTransferTxGen: the number of abeTxInputDescs does not match the number of TxIn in transferTxMsgTemplate")
	}

	// cryptoTxInputDescs
	cryptoTxInputDescs := make([]*pqringctxapi.TxInputDescMLP, inputNum)
	for i := 0; i < inputNum; i++ {
		txInRingVersion := transferTxMsgTemplate.TxIns[i].PreviousOutPointRing.Version
		if txInRingVersion != transferTxMsgTemplate.Version {
			//	the transferTxMsgTemplate is attempting to spend the coins generated by Txs with different versions.
			//	Here we need to hard code to accept only the expected cases.
			if txInRingVersion == wire.TxVersion_Height_0 &&
				transferTxMsgTemplate.Version == wire.TxVersion_Height_MLPAUT_236000 {
				// allowed case:
				// we allow to use a transaction with Version == wire.TxVersion_Height_MLPAUT_236000
				// to spend coins with Version == wire.TxVersion_Height_0.
			} else {
				return nil, fmt.Errorf("pqringctxTransferTxGen: the transferTxMsgTemplate is attempting to spend coins created by transactions with differnet versions, but the case is out of the allowed ones")
			}
		}

		// lgrTxoList
		lgrTxoList := make([]*pqringctxapi.LgrTxoMLP, len(abeTxInputDescs[i].txoRing.TxOuts))
		ringId := abeTxInputDescs[i].txoRing.RingId()
		for j := 0; j < len(abeTxInputDescs[i].txoRing.TxOuts); j++ {
			if abeTxInputDescs[i].txoRing.TxOuts[j].Version != txInRingVersion {
				return nil, fmt.Errorf("pqringctxTransferTxGen: abeTxInputDescs[%d].txoRing.TxOuts[%d].Version does not match transferTxMsgTemplate.TxIns[%d].PreviousOutPointRing.Version", i, j, i)
			}

			txoMLP, err := pqringctxapi.DeserializeTxo(pp, abeTxInputDescs[i].txoRing.TxOuts[j].TxoScript)
			if err != nil {
				return nil, err
			}

			txolid := pqringctxLedgerTxoIdGen(ringId, uint8(j))

			lgrTxoList[j] = pqringctxapi.NewLgrTxo(txoMLP, txolid)
		}

		//  sidx          uint8
		sidx := abeTxInputDescs[i].sidx

		//	keys
		var coinAddressInCoin []byte
		var coinAddressTypeInCoin pqringctxapi.CoinAddressType
		coinAddressInCoin, err = pqringctxapi.ExtractCoinAddressFromSerializedTxo(pp, abeTxInputDescs[i].txoRing.TxOuts[sidx].TxoScript)
		if err != nil {
			return nil, err
		}
		coinAddressTypeInCoin, err = pqringctxapi.ExtractCoinAddressTypeFromCoinAddress(pp, coinAddressInCoin)
		if err != nil {
			return nil, err
		}

		//	cryptoAddress check
		var coinAddressFromCryptoAddress []byte
		var privacyLevelInAddress abecryptoxkey.PrivacyLevel
		var coinValuePublicKey []byte = nil
		privacyLevelInAddress, coinAddressFromCryptoAddress, coinValuePublicKey, err = abecryptoxkey.CryptoAddressParse(abeTxInputDescs[i].cryptoAddress)
		if err != nil {
			return nil, err
		}
		if bytes.Compare(coinAddressFromCryptoAddress, coinAddressInCoin) != 0 {
			return nil, fmt.Errorf("pqringctxTransferTxGen: the coinAddress extracted from abeTxInputDescs[%d].cryptoAddress and that extracted from abeTxInputDescs[%d].txoRing.TxOuts[%].TxoScript are inconsistent", i, i, sidx)
		}

		//	coinSpendSecretKey []byte
		var coinSpendSecretKey []byte
		var privacyLevelInKey abecryptoxkey.PrivacyLevel
		var coinAddressTypeInKey pqringctxapi.CoinAddressType

		privacyLevelInKey, coinSpendSecretKey, err = abecryptoxkey.CryptoSpendSecretKeyParse(abeTxInputDescs[i].cryptoSpsk)
		if err != nil {
			return nil, err
		}
		if privacyLevelInKey != privacyLevelInAddress {
			return nil, fmt.Errorf("pqringctxTransferTxGen: the privacyLevel extracted from abeTxInputDescs[%d].cryptoSpsk and that extracted from abeTxInputDescs[%d].cryptoAddress are inconsistent", i, i)
		}
		coinAddressTypeInKey, err = pqringctxapi.ExtractCoinAddressTypeFromCoinSpendSecretKey(pp, coinSpendSecretKey)
		if err != nil {
			return nil, err
		}
		if coinAddressTypeInKey != coinAddressTypeInCoin {
			return nil, fmt.Errorf("pqringctxTransferTxGen: the coinAddressType in abeTxInputDescs[%d].cryptoSpsk does not match of the coin to spend", i)
		}

		//	coinSerialNumberSecretKey []byte
		var coinSerialNumberSecretKey []byte = nil
		if abeTxInputDescs[i].cryptoSnsk != nil {
			privacyLevelInKey, coinSerialNumberSecretKey, err = abecryptoxkey.CryptoSerialNumberSecretKeyParse(abeTxInputDescs[i].cryptoSnsk)
			if err != nil {
				return nil, err
			}
			if privacyLevelInKey != privacyLevelInAddress {
				return nil, fmt.Errorf("pqringctxTransferTxGen: the privacyLevel extracted from abeTxInputDescs[%d].cryptoSnsk and that extracted from abeTxInputDescs[%d].cryptoAddress are inconsistent", i, i)
			}

			coinAddressTypeInKey, err = pqringctxapi.ExtractCoinAddressTypeFromCoinSerialNumberSecretKey(pp, coinSerialNumberSecretKey)
			if err != nil {
				return nil, err
			}
			if coinAddressTypeInKey != coinAddressTypeInCoin {
				return nil, fmt.Errorf("pqringctxTransferTxGen: the coinAddressType in abeTxInputDescs[%d].cryptoSnsk does not match that of the coin to spend", i)
			}
		} else {
			if privacyLevelInAddress != abecryptoxkey.PrivacyLevelPSEUDONYM {
				// only when the privacyLevelInAddress is PrivacyLevelPSEUDONYM, the provided cryptoSnsk could be nil.
				return nil, fmt.Errorf("pqringctxTransferTxGen: the abeTxInputDescs[%d].[%d]-th Txo's privacy-level is not PrivacyLevelPSEUDONYM, but the cryptoSnsk is nil", i, sidx)
			}
		}

		//	coinValuePublicKey             []byte
		//	parsed from cryptoAddress as above
		if coinValuePublicKey == nil {
			if privacyLevelInAddress != abecryptoxkey.PrivacyLevelPSEUDONYM {
				// only when the privacyLevelInAddress is PrivacyLevelPSEUDONYM, the extracted coinValuePublicKey from the cryptoAddress could be nil.
				return nil, fmt.Errorf("pqringctxTransferTxGen: the abeTxInputDescs[%d].[%d]-th Txo's privacy-level is not PrivacyLevelPSEUDONYM, but the coinValuePublicKey is nil", i, sidx)
			}
		}

		//	coinValueSecretKey             []byte
		var coinValueSecretKey []byte = nil
		if abeTxInputDescs[i].cryptoVsk != nil {
			privacyLevelInKey, coinValueSecretKey, err = abecryptoxkey.CryptoValueSecretKeyParse(abeTxInputDescs[i].cryptoVsk)
			if err != nil {
				return nil, err
			}
			if privacyLevelInKey != privacyLevelInAddress {
				return nil, fmt.Errorf("pqringctxTransferTxGen: the privacyLevel extracted from abeTxInputDescs[%d].cryptoVsk and that extracted from abeTxInputDescs[%d].cryptoAddress are inconsistent", i, i)
			}
		} else {
			if privacyLevelInAddress != abecryptoxkey.PrivacyLevelPSEUDONYM {
				// only when the privacyLevelInAddress is PrivacyLevelPSEUDONYM, the provided cryptoVsk could be nil.
				return nil, fmt.Errorf("pqringctxTransferTxGen: the abeTxInputDescs[%d].[%d]-th Txo's privacy-level is not PrivacyLevelPSEUDONYM, but the cryptoVsk is nil", i, sidx)
			}
		}

		// value
		// explicitly given in abeTxInputDescs[i]
		value := abeTxInputDescs[i].value

		cryptoTxInputDescs[i] = pqringctxapi.NewTxInputDescMLP(lgrTxoList, sidx, coinSpendSecretKey, coinSerialNumberSecretKey, coinValuePublicKey, coinValueSecretKey, value)
	}

	//	cryptoTxOutputDescs
	cryptoTxOutputDescs := make([]*pqringctxapi.TxOutputDescMLP, outputNum)
	for j := 0; j < outputNum; j++ {
		_, coinAddress, coinValuePublicKey, err := abecryptoxkey.CryptoAddressParse(abeTxOutputDescs[j].cryptoAddress)
		if err != nil {
			return nil, err
		}

		cryptoTxOutputDescs[j] = pqringctxapi.NewTxOutputDescMLP(coinAddress, coinValuePublicKey, abeTxOutputDescs[j].value)
	}

	//	call the crypto scheme
	cryptoTransferTx, err := pqringctxapi.TransferTxGen(pp, cryptoTxInputDescs, cryptoTxOutputDescs, transferTxMsgTemplate.TxFee, transferTxMsgTemplate.TxMemo)
	if err != nil {
		return nil, err
	}

	//	Set the txInputs
	//	only the serial number needs to be set
	cryptoTxInputs := cryptoTransferTx.GetTxInputs()
	for i := 0; i < inputNum; i++ {
		transferTxMsgTemplate.TxIns[i].SerialNumber = cryptoTxInputs[i].GetSerialNumber()
	}

	cryptoTxos := cryptoTransferTx.GetTxos()
	transferTxMsgTemplate.TxOuts = make([]*wire.TxOutAbe, len(cryptoTxos))
	for i := 0; i < len(cryptoTxos); i++ {
		serializedTxo, err := pqringctxapi.SerializeTxo(pp, cryptoTxos[i])
		if err != nil {
			return nil, err
		}
		transferTxMsgTemplate.TxOuts[i] = &wire.TxOutAbe{
			Version:   transferTxMsgTemplate.Version,
			TxoScript: serializedTxo,
		}
	}

	// witness must be associated with Tx, so it does not need to contain cryptoScheme or TxVersion.
	transferTxMsgTemplate.TxWitness, err = pqringctxapi.SerializeTxWitnessTrTx(pp, cryptoTransferTx.GetTxWitness())
	if err != nil {
		return nil, err
	}

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

// helper functions	begin

// pqringctxLedgerTxoIdGen generates ledgerTxoId for Txo in a ring (meaning in a ledger).
// This keeps the same as that in pqringct.
// reviewed on 2023.12.08
func pqringctxLedgerTxoIdGen(ringId wire.RingId, index uint8) []byte {
	w := bytes.NewBuffer(make([]byte, 0, chainhash.HashSize+1))
	var err error
	// ringId
	_, err = w.Write(ringId[:])
	if err != nil {
		return nil
	}
	// index
	err = w.WriteByte(index)
	if err != nil {
		return nil
	}
	return chainhash.DoubleHashB(w.Bytes())
}

//	helper functions	end

//	APIs for Txos	begin

// pqringctxGetTxoSerializeSize returns the TxoSerializeSize for the input coinAddress.
// reviewed on 2023.12.07
func pqringctxGetTxoSerializeSize(pp *pqringctxapi.PublicParameter, coinAddress []byte) (int, error) {
	return pqringctxapi.GetTxoSerializeSize(pp, coinAddress)
}

//	APIs for Txos	end

// APIs for TxWitnesses	begin
func pqringctxGetCbTxWitnessSerializeSize(pp *pqringctxapi.PublicParameter, coinAddressListPayTo [][]byte) (int, error) {
	return pqringctxapi.GetCbTxWitnessSerializeSizeByDesc(pp, coinAddressListPayTo)
}

//	APIs for TxWitnesses	end

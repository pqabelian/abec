package abecryptox

import (
	"bytes"
	"fmt"
	"github.com/pqabelian/abec/abecryptox/abecryptoutils"
	"github.com/pqabelian/abec/abecryptox/abecryptoxkey"
	"github.com/pqabelian/abec/abecryptox/abecryptoxparam"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/wire"
	"github.com/pqabelian/pqringctx/pqringctxapi"
)

// // abecryptox -> abepqringctx -> pqringctx

// The caller needs to fill the Version, TxIns, TxFee, TxMemo fields for coinbaseTxMsgTemplate,
// this function will fill the TxOuts and TxWitness fields.
// reviewed on 2023.12.07
// reviewed on 2023.12.21
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
	cryptoTxos := pqringctxapi.GetCbTxTxos(cryptoCoinbaseTx)
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
	cbTxWitness := pqringctxapi.GetCbTxTxWitness(cryptoCoinbaseTx)
	serializedCbTxWitness, err := pqringctxapi.SerializeTxWitnessCbTx(pp, cbTxWitness)
	if err != nil {
		return nil, err
	}
	coinbaseTxMsgTemplate.TxWitness = serializedCbTxWitness

	return coinbaseTxMsgTemplate, nil
	//return nil, nil
}

// pqringctxCoinbaseTxVerify verify the input coinbaseTx *wire.MsgTxAbe.
// The caller needs to guarantee the well-form of the input coinbaseTx *wire.MsgTxAbe, such as the TxIns.
// This function only checks the balance proof, by calling the crypto-scheme.
// reviewed on 2023.12.21
// refactored on 2024.01.08, using err == nil or not to denote valid or invalid
// todo: review
func pqringctxCoinbaseTxVerify(pp *pqringctxapi.PublicParameter, coinbaseTx *wire.MsgTxAbe) error {
	if coinbaseTx == nil {
		return fmt.Errorf("pqringctxCoinbaseTxVerify: the input coinbaseTx is nil")
	}
	if len(coinbaseTx.TxOuts) <= 0 {
		return fmt.Errorf("pqringctxCoinbaseTxVerify: coinbaseTx.TxOuts is nil/empty")
	}

	var err error

	vin := coinbaseTx.TxFee

	txoMLPs := make([]pqringctxapi.TxoMLP, len(coinbaseTx.TxOuts))
	for i := 0; i < len(coinbaseTx.TxOuts); i++ {
		if coinbaseTx.TxOuts[i].Version != coinbaseTx.Version {
			return fmt.Errorf("pqringctxCoinbaseTxVerify: coinbaseTx.TxOuts[%d].Version (%d) != coinbaseTx.Version (%d)",
				i, coinbaseTx.TxOuts[i].Version, coinbaseTx.Version)
		}

		txoMLPs[i], err = pqringctxapi.DeserializeTxo(pp, coinbaseTx.TxOuts[i].TxoScript)
		if err != nil {
			return err
		}
	}

	txMemo := coinbaseTx.TxMemo

	txWitness, err := pqringctxapi.DeserializeTxWitnessCbTx(pp, coinbaseTx.TxWitness)
	if err != nil {
		return err
	}

	cryptoCoinbaseTx := pqringctxapi.NewCoinbaseTxMLP(vin, txoMLPs, txMemo, txWitness)

	err = pqringctxapi.CoinbaseTxVerify(pp, cryptoCoinbaseTx)
	if err != nil {
		return err
	}
	//if bl == false {
	//	return false, nil
	//}

	return nil
}

// pqringctxTransferTxGenByRootSeeds translates []*AbeTxInputDescByRootSeeds into []*AbeTxInputDescByKeys, then call pqringctxTransferTxGenByKeys.
// reviewed on 2023.12.31
func pqringctxTransferTxGenByRootSeeds(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	abeTxInputDescsByRootSeeds []*AbeTxInputDescByRootSeeds, abeTxOutputDescs []*AbeTxOutputDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	// just redundant double check
	cryptoSchemeFromTxVersion, err := abecryptoxparam.GetCryptoSchemeByTxVersion(transferTxMsgTemplate.Version)
	if err != nil {
		return nil, err
	}
	if cryptoSchemeFromTxVersion != cryptoScheme {
		return nil, fmt.Errorf("pqringctxTransferTxGenByRootSeeds: the input cryptoScheme is different from that implied by transferTxMsgTemplate.Version")
	}

	inputNum := len(abeTxInputDescsByRootSeeds)
	abeTxInputDescs := make([]*AbeTxInputDescByKeys, inputNum)
	for i := 0; i < inputNum; i++ {
		abeTxInputDescByRootSeedsItem := abeTxInputDescsByRootSeeds[i]

		if abeTxInputDescByRootSeedsItem.privacyLevel != abecryptoxkey.PrivacyLevelRINGCT && abeTxInputDescByRootSeedsItem.privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM {
			return nil, fmt.Errorf("pqringctxTransferTxGenByRootSeeds: the privacyLeve of the %d -th coin-to-spend is not PrivacyLevelRINGCT or PrivacyLevelPSEUDONYM", i)
		}

		if abeTxInputDescByRootSeedsItem.txoRing == nil || int(abeTxInputDescByRootSeedsItem.sidx) >= len(abeTxInputDescByRootSeedsItem.txoRing.TxOuts) {
			return nil, fmt.Errorf("pqringctxTransferTxGenByRootSeeds: the %d -th coin-to-spend is not correctly specified, the sidx (%d) exceeds the ring size", i, abeTxInputDescByRootSeedsItem.sidx)
		}

		publicRand, err := ExtractPublicRandFromTxo(abeTxInputDescByRootSeedsItem.txoRing.TxOuts[abeTxInputDescByRootSeedsItem.sidx])
		if err != nil {
			return nil, err
		}

		cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey, err :=
			abecryptoxkey.CryptoAddressKeyReGenByRootSeedsFromPublicRand(abeTxInputDescByRootSeedsItem.cryptoScheme, abeTxInputDescByRootSeedsItem.privacyLevel,
				abeTxInputDescByRootSeedsItem.coinSpendKeyRootSeed, abeTxInputDescByRootSeedsItem.coinSerialNumberKeyRootSeed, abeTxInputDescByRootSeedsItem.coinValueKeyRootSeed,
				abeTxInputDescByRootSeedsItem.coinDetectorRootKey, publicRand)
		if err != nil {
			return nil, err
		}

		abeTxInputDescs[i] = NewAbeTxInputDescByKeys(
			abeTxInputDescByRootSeedsItem.txoRing, abeTxInputDescByRootSeedsItem.sidx,
			cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey,
			abeTxInputDescByRootSeedsItem.value)
	}

	return pqringctxTransferTxGenByKeys(pp, cryptoScheme, abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)
}

// pqringctxTransferTxGenByRandSeeds translates []*AbeTxInputDescByRandSeeds into []*AbeTxInputDescByKeys, then call pqringctxTransferTxGenByKeys.
// reviewed on 2023.12.31
func pqringctxTransferTxGenByRandSeeds(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, abeTxInputDescsByRandSeeds []*AbeTxInputDescByRandSeeds, abeTxOutputDescs []*AbeTxOutputDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	// just redundant double check
	cryptoSchemeFromTxVersion, err := abecryptoxparam.GetCryptoSchemeByTxVersion(transferTxMsgTemplate.Version)
	if err != nil {
		return nil, err
	}
	if cryptoSchemeFromTxVersion != cryptoScheme {
		return nil, fmt.Errorf("pqringctxTransferTxGenByRandSeeds: the input cryptoScheme is different from that implied by transferTxMsgTemplate.Version")
	}

	inputNum := len(abeTxInputDescsByRandSeeds)
	abeTxInputDescs := make([]*AbeTxInputDescByKeys, inputNum)
	for i := 0; i < inputNum; i++ {
		abeTxInputDescByRandSeedsItem := abeTxInputDescsByRandSeeds[i]

		if abeTxInputDescByRandSeedsItem.privacyLevel != abecryptoxkey.PrivacyLevelRINGCT && abeTxInputDescByRandSeedsItem.privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM {
			return nil, fmt.Errorf("pqringctxTransferTxGenByRandSeeds: the privacyLeve of the %d -th coin-to-spend is not PrivacyLevelRINGCT or PrivacyLevelPSEUDONYM", i)
		}

		if abeTxInputDescByRandSeedsItem.txoRing == nil || int(abeTxInputDescByRandSeedsItem.sidx) >= len(abeTxInputDescByRandSeedsItem.txoRing.TxOuts) {
			return nil, fmt.Errorf("pqringctxTransferTxGenByRandSeeds: the %d -th coin-to-spend is not correctly specified, the sidx (%d) exceeds the ring size", i, abeTxInputDescByRandSeedsItem.sidx)
		}

		publicRand, err := ExtractPublicRandFromTxo(abeTxInputDescByRandSeedsItem.txoRing.TxOuts[abeTxInputDescByRandSeedsItem.sidx])
		if err != nil {
			return nil, err
		}

		cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey, err :=
			abecryptoxkey.CryptoAddressKeyGenByRandSeeds(abeTxInputDescByRandSeedsItem.cryptoScheme, abeTxInputDescByRandSeedsItem.privacyLevel,
				abeTxInputDescByRandSeedsItem.coinSpendKeyRandSeed, abeTxInputDescByRandSeedsItem.coinSerialNumberKeyRandSeed, abeTxInputDescByRandSeedsItem.coinValueKeyRandSeed,
				abeTxInputDescByRandSeedsItem.coinDetectorKey, publicRand)
		if err != nil {
			return nil, err
		}

		abeTxInputDescs[i] = NewAbeTxInputDescByKeys(
			abeTxInputDescByRandSeedsItem.txoRing, abeTxInputDescByRandSeedsItem.sidx,
			cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey,
			abeTxInputDescByRandSeedsItem.value)
	}

	return pqringctxTransferTxGenByKeys(pp, cryptoScheme, abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)
}

// pqringctxTransferTxGenByKeys generates a MsgTxAbe,
// by filling TxIns[].serialNumber，Txos, and TxWitness of the input transferTxMsgTemplate.
// The caller needs to fill the Version, TxIns[].PreviousOutPointRing, TxFee, TxMemo fields of transferTxMsgTemplate.
// This function will fill the TxIns[].serialNumber，Txos, and TxWitness of the input transferTxMsgTemplate, and return it as the result.
// The parameter cryptoScheme here is obtained by the caller from TxVersion, which causes this function is called.
// Now it is redundant at this moment and works for ony double-check.
// In the future, when the version of input ring is different from the ring of TxVersion/TxoVersion,
// the two corresponding cryptoSchemes will be extracted here and further decides the TxGen algorithms.
// Refer to wire.param for the details.
// reviewed on 2023.12.21
// todo: to review
// todo: review CryptoValueSecretKeyParse
func pqringctxTransferTxGenByKeys(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, abeTxInputDescs []*AbeTxInputDescByKeys, abeTxOutputDescs []*AbeTxOutputDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
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
				transferTxMsgTemplate.Version == wire.TxVersion_Height_MLPAUT_300000 {
				// allowed case:
				// we allow to use a transaction with Version == wire.TxVersion_Height_MLPAUT_300000
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

			lgrTxoId := pqringctxLedgerTxoIdGen(ringId, uint8(j))

			lgrTxoList[j] = pqringctxapi.NewLgrTxo(txoMLP, lgrTxoId)
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
			return nil, fmt.Errorf("pqringctxTransferTxGen: the coinAddress extracted from abeTxInputDescs[%d].cryptoAddress and that extracted from abeTxInputDescs[%d].txoRing.TxOuts[%d].TxoScript are inconsistent", i, i, sidx)
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

		//	coinDetectorKey []byte
		var coinDetectorKey []byte
		if privacyLevelInAddress != abecryptoxkey.PrivacyLevelRINGCTPre {
			privacyLevelInKey, coinDetectorKey, err = abecryptoxkey.CryptoDetectorKeyParse(abeTxInputDescs[i].cryptoDetectorKey)
			if err != nil {
				return nil, err
			}
			if privacyLevelInKey != privacyLevelInAddress {
				return nil, fmt.Errorf("pqringctxTransferTxGen: the privacyLevel extracted from abeTxInputDescs[%d].cryptoDetectorKey and that extracted from abeTxInputDescs[%d].cryptoAddress are inconsistent", i, i)
			}
		}

		// value
		// explicitly given in abeTxInputDescs[i]
		value := abeTxInputDescs[i].value

		cryptoTxInputDescs[i] = pqringctxapi.NewTxInputDescMLP(lgrTxoList, sidx, coinSpendSecretKey, coinSerialNumberSecretKey, coinValuePublicKey, coinValueSecretKey, coinDetectorKey, value)
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
	cryptoTxInputs := pqringctxapi.GetTrTxTxInputs(cryptoTransferTx)
	for i := 0; i < inputNum; i++ {
		transferTxMsgTemplate.TxIns[i].SerialNumber = pqringctxapi.GetTxInputSerialNumber(cryptoTxInputs[i])
	}

	cryptoTxos := pqringctxapi.GetTrTxTxos(cryptoTransferTx)
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
	trTxWitness := pqringctxapi.GetTrTxWitness(cryptoTransferTx)
	transferTxMsgTemplate.TxWitness, err = pqringctxapi.SerializeTxWitnessTrTx(pp, trTxWitness)
	if err != nil {
		return nil, err
	}

	return transferTxMsgTemplate, nil
}

// pqringctxTransferTxVerify verifies wire.MsgTxAbe.
// todo: review
func pqringctxTransferTxVerify(pp *pqringctxapi.PublicParameter, transferTx *wire.MsgTxAbe, abeTxInDetails []*AbeTxInDetail) error {
	if transferTx == nil {
		return fmt.Errorf("pqringctxTransferTxVerify: the input transferTx is empty")
	}

	inputNum := len(transferTx.TxIns)
	outputNum := len(transferTx.TxOuts)
	if inputNum <= 0 {
		return fmt.Errorf("pqringctxTransferTxVerify: the inputNum is 0")
	}
	if outputNum <= 0 {
		return fmt.Errorf("pqringctxTransferTxVerify: the outputNum is 0")
	}

	if len(abeTxInDetails) != inputNum {
		return fmt.Errorf("pqringctxTransferTxVerify: len(abeTxInDetails) (%d) != len(transferTx.TxIns) (%d)", len(abeTxInDetails), len(transferTx.TxIns))
	}

	var err error
	//	txInputs
	cryptoTxInputMLPs := make([]*pqringctxapi.TxInputMLP, inputNum)
	for i := 0; i < inputNum; i++ {
		if transferTx.TxIns[i].PreviousOutPointRing.Version != transferTx.Version {
			if transferTx.TxIns[i].PreviousOutPointRing.Version == wire.TxVersion_Height_0 &&
				transferTx.Version == wire.TxVersion_Height_MLPAUT_300000 {
				//	allowed
			} else {
				//	not in the allowed cases
				return fmt.Errorf("pqringctxTransferTxVerify: transferTx.TxIns[%d].PreviousOutPointRing.Version (%d) is out of design", i, transferTx.TxIns[i].PreviousOutPointRing.Version)
			}
		}

		//	to be self-contained, the serial number should be checked
		if bytes.Compare(transferTx.TxIns[i].SerialNumber, abeTxInDetails[i].serialNumber) != 0 {
			return fmt.Errorf("pqringctxTransferTxVerify: transferTx.TxIns[%d].SerialNumber (%v) and abeTxInDetails[%d].serialNumber (%v) are differnet",
				i, transferTx.TxIns[i].SerialNumber, i, abeTxInDetails[i].serialNumber)
		}

		//	to be self-contained, the ringId should be checked
		ringId := transferTx.TxIns[i].PreviousOutPointRing.RingId()
		if bytes.Compare(ringId[:], abeTxInDetails[i].ringId[:]) != 0 {
			return fmt.Errorf("pqringctxTransferTxVerify: transferTx.TxIns[%d].PreviousOutPointRing.RingId() (%v) and abeTxInDetails[%d].ringId (%v) are different",
				i, transferTx.TxIns[i].PreviousOutPointRing.RingId(), i, abeTxInDetails[i].ringId)
		}

		lgrTxoList := make([]*pqringctxapi.LgrTxoMLP, len(abeTxInDetails[i].txoList))
		for j := 0; j < len(abeTxInDetails[i].txoList); j++ {
			if abeTxInDetails[i].txoList[j].Version != transferTx.TxIns[i].PreviousOutPointRing.Version {
				return fmt.Errorf("pqringctxTransferTxVerify: abeTxInDetails[%d].txoList[%d].Version (%d) is different from transferTx.TxIns[%d].PreviousOutPointRing.Version (%d)",
					i, j, abeTxInDetails[i].txoList[j].Version, i, transferTx.TxIns[i].PreviousOutPointRing.Version)
				//	The Txos in the same ring should have the same version
			}

			txoMLP, err := pqringctxapi.DeserializeTxo(pp, abeTxInDetails[i].txoList[j].TxoScript) //	Note that pqringctx can deserialize the TxoScript generated by pqringct.
			if err != nil {
				return err
			}
			lgrTxoId := pqringctxLedgerTxoIdGen(ringId, uint8(j))
			lgrTxoList[j] = pqringctxapi.NewLgrTxo(txoMLP, lgrTxoId)
		}

		cryptoTxInputMLPs[i] = pqringctxapi.NewTxInputMLP(lgrTxoList, abeTxInDetails[i].serialNumber)
	}

	//	txos
	cryptoTxoMLPs := make([]pqringctxapi.TxoMLP, outputNum)
	for j := 0; j < outputNum; j++ {
		if transferTx.TxOuts[j].Version != transferTx.Version {
			return fmt.Errorf("pqringctxTransferTxVerify: transferTx.TxOuts[%d].Version (%d) != transferTx.Version (%d)",
				j, transferTx.TxOuts[j].Version, transferTx.Version)
			//	The output Txos of a transaction should have the same version as the transaction.
		}

		cryptoTxoMLPs[j], err = pqringctxapi.DeserializeTxo(pp, transferTx.TxOuts[j].TxoScript)
		if err != nil {
			return err
		}
	}

	//	fee
	//	txMemo

	//	TxWitness
	cryptoTxWitness, err := pqringctxapi.DeserializeTxWitnessTrTx(pp, transferTx.TxWitness)
	if err != nil {
		return err
	}

	cryptoTransferTx := pqringctxapi.NewTransferTxMLP(cryptoTxInputMLPs, cryptoTxoMLPs, transferTx.TxFee, transferTx.TxMemo, cryptoTxWitness)

	// call the crypto scheme's verify algorithm
	err = pqringctxapi.TransferTxVerify(pp, cryptoTransferTx)
	if err != nil {
		return err
	}

	return nil
}

// API for AddressKeys	begin
// API for AddressKeys	end

// helper functions	begin

// pqringctxLedgerTxoIdGen generates ledgerTxoId for Txo in a ring (meaning in a ledger).
// This must keep the same as that in pqringct.ledgerTxoIdGen.
// reviewed on 2023.12.08
// reviewed on 2023.12.21
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

// pqringctxGetTxoPrivacyLevel returns the PrivacyLevel of the input wire.TxOutAbe.
// reviewed on 2024.01.04
func pqringctxGetTxoPrivacyLevel(pp *pqringctxapi.PublicParameter, abeTxo *wire.TxOutAbe) (abecryptoxkey.PrivacyLevel, error) {
	cryptoTxoMLP, err := pqringctxapi.DeserializeTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return 0, err
	}

	return abecryptoxkey.GetPrivacyLevelFromCoinAddressType(cryptoTxoMLP.CoinAddressType())
}

// pqringctxGetTxoSerializeSize returns the TxoSerializeSize for the input coinAddress.
// reviewed on 2023.12.07
// refactored on 2024.01.24 by Alice: pqringctx-Layer takes as input cryptoAddress and parses it to coinAddress.
func pqringctxGetTxoSerializeSize(pp *pqringctxapi.PublicParameter, cryptoAddressPayTo []byte) (int, error) {
	//	Note that the cryptoAddressPayTo may not be generated by pqringctx,
	//	we call ParseCryptoAddress() to cover all cases.
	_, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(cryptoAddressPayTo)
	if err != nil {
		return 0, err
	}

	return pqringctxapi.GetTxoSerializeSize(pp, coinAddress)
}

// pqringctxExtractPublicRandFromTxo returns the PublicRand in the CoinAddress of the input wire.TxOutAbe.
// reviewed on 2023.12.31
func pqringctxExtractPublicRandFromTxo(pp *pqringctxapi.PublicParameter, abeTxo *wire.TxOutAbe) ([]byte, error) {
	coinAddress, err := pqringctxapi.ExtractCoinAddressFromSerializedTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return nil, err
	}
	return pqringctxapi.ExtractPublicRandFromCoinAddress(pp, coinAddress)
}

// pqringctxExtractCoinAddressFromTxo returns the CoinAddress of the input wire.TxOutAbe.
// reviewed on 2023.12.31
func pqringctxExtractCoinAddressFromTxo(pp *pqringctxapi.PublicParameter, abeTxo *wire.TxOutAbe) ([]byte, error) {
	return pqringctxapi.ExtractCoinAddressFromSerializedTxo(pp, abeTxo.TxoScript)
}

// pqringctxTxoCoinDetectByCoinDetectorRootKey use the input coinDetectorRootKey to check whether the input wire.TxOutAbe's coinAddress belongs to the owner of coinDetectorRootKey.
// todo: review
func pqringctxTxoCoinDetectByCoinDetectorRootKey(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, abeTxo *wire.TxOutAbe, coinDetectorRootKey []byte) (bool, error) {
	if abeTxo == nil {
		return false, fmt.Errorf("pqringctxTxoCoinDetectByCoinDetectorRootKey: the input abeTxo is nil")
	}

	coinAddress, err := pqringctxapi.ExtractCoinAddressFromSerializedTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return false, err
	}

	//	extract publicRand and generate coinDetectorKey
	//	NOTE: the codes here must be consistent with that in abecryptoxkey/abepqringctxkey.go
	publicRand, err := pqringctxapi.ExtractPublicRandFromCoinAddress(pp, coinAddress)
	if err != nil {
		return false, err
	}
	coinDetectorKey, err := abecryptoutils.KDF(coinDetectorRootKey, publicRand)
	if err != nil {
		return false, err
	}

	return pqringctxapi.DetectCoinAddress(pp, coinAddress, coinDetectorKey)
}

// pqringctxTxoCoinDetectByCryptoDetectorKey use the input cryptoDetectorKey to check whether the input wire.TxOutAbe's coinAddress belongs to the owner of cryptoDetectorKey.
// todo: review
func pqringctxTxoCoinDetectByCryptoDetectorKey(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, abeTxo *wire.TxOutAbe, cryptoDetectorKey []byte) (bool, error) {
	if abeTxo == nil {
		return false, fmt.Errorf("pqringctxTxoCoinDetectByCryptoDetectorKey: the input abeTxo is nil")
	}

	coinAddress, err := pqringctxapi.ExtractCoinAddressFromSerializedTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return false, err
	}

	_, coinDetectorKey, err := abecryptoxkey.CryptoDetectorKeyParse(cryptoDetectorKey)
	if err != nil {
		return false, err
	}

	return pqringctxapi.DetectCoinAddress(pp, coinAddress, coinDetectorKey)
}

// pqringctxTxoCoinReceiveByRootSeeds checks whether the input abeTxo *wire.TxOutAbe belongs to the owner of the input coinDetectorRootKey, and if true,
// it extracts the value of abeTxo using the input coinValueKeyRootSeed.
// Note that it is the responsibility of the caller or user to make sure the coinValueKeyRootSeed is for the input abeTxo.
// todo: review
func pqringctxTxoCoinReceiveByRootSeeds(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, abeTxo *wire.TxOutAbe,
	coinValueKeyRootSeed []byte, coinDetectorRootKey []byte) (valid bool, value uint64, err error) {

	cryptoSchemeInTxo, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return false, 0, err
	}
	if cryptoSchemeInTxo != cryptoScheme {
		return false, 0, fmt.Errorf("pqringctxTxoCoinReceiveByRootSeeds: unmatched cryptoScheme for the input Txo")
	}

	//	NOTE: As the abepqringctx-layer obtained TxoMLP (associated in crypto-TransferTx/CoinbaseTx) and serialized it to abeTxo.TxoScript,
	//	here abepqringctx-layer calls crypto-scheme using TxoMLP.
	txoMLP, err := pqringctxapi.DeserializeTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return false, 0, err
	}
	coinAddressInTxo, err := pqringctxapi.GetCoinAddressFromTxo(pp, txoMLP)
	if err != nil {
		return false, 0, err
	}

	//	extract publicRand for later coinAddressDetect and coinValueKeyGen
	//	NOTE: the codes here must be consistent with that in abecryptoxkey/abepqringctxkey.go
	publicRand, err := pqringctxapi.ExtractPublicRandFromCoinAddress(pp, coinAddressInTxo)
	if err != nil {
		return false, 0, err
	}

	//	generate coinDetectorKey and detect coinAddress
	//	NOTE: the codes here must be consistent with that in abecryptoxkey/abepqringctxkey.go
	coinDetectorKey, err := abecryptoutils.KDF(coinDetectorRootKey, publicRand)
	if err != nil {
		return false, 0, err
	}

	//	check whether the coinAddress of abeTxo belongs to the owner of coinDetectorKey.
	valid, err = pqringctxapi.DetectCoinAddress(pp, coinAddressInTxo, coinDetectorKey)
	if err != nil {
		return false, 0, err
	}
	if !valid {
		return false, 0, nil
	}

	var coinValuePublicKey, coinValueSecretKey []byte
	if len(coinValueKeyRootSeed) != 0 {
		//	generate (coinValuePublicKey, coinValueSecretKey)
		//	NOTE: the codes here must be consistent with that in abecryptoxkey/abepqringctxkey.go
		if len(coinValueKeyRootSeed) != abecryptoutils.PRFKeyBytesLen {
			return false, 0, fmt.Errorf("pqringctxTxoCoinReceiveByRootSeeds: invalid length of coinValueKeyRootSeed (%d)", len(coinValueKeyRootSeed))
		}

		coinValueKeyRandSeed, err := abecryptoutils.KDF(coinValueKeyRootSeed, publicRand)
		if err != nil {
			return false, 0, err
		}
		coinValuePublicKey, coinValueSecretKey, err = pqringctxapi.CoinValueKeyGen(pp, coinValueKeyRandSeed)
		if err != nil {
			return false, 0, err
		}
	} else {
		coinValuePublicKey = nil
		coinValueSecretKey = nil
	}

	return pqringctxapi.TxoCoinReceive(pp, txoMLP, coinAddressInTxo, coinValuePublicKey, coinValueSecretKey)
}

// pqringctxTxoCoinReceiveByRandSeeds checks whether the input abeTxo *wire.TxOutAbe belongs to the owner of the input coinDetectorKey, and if true,
// it extracts the value of abeTxo using the input coinValueKeyRandSeed.
// Note that it is the responsibility of the caller or user to make sure the coinValueKeyRandSeed is for the input abeTxo.
// todo: review
func pqringctxTxoCoinReceiveByRandSeeds(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, abeTxo *wire.TxOutAbe,
	coinValueKeyRandSeed []byte, coinDetectorKey []byte) (valid bool, value uint64, err error) {
	cryptoSchemeInTxo, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return false, 0, err
	}

	if cryptoSchemeInTxo != cryptoScheme {
		return false, 0, fmt.Errorf("pqringctxTxoCoinReceiveByRandSeeds: unmatched cryptoScheme for the input Txo")
	}

	//	NOTE: As the abepqringctx-layer obtained TxoMLP (associated in crypto-TransferTx/CoinbaseTx) and serialized it to abeTxo.TxoScript,
	//	here abepqringctx-layer calls crypto-scheme using TxoMLP.
	txoMLP, err := pqringctxapi.DeserializeTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return false, 0, err
	}
	coinAddressInTxo, err := pqringctxapi.GetCoinAddressFromTxo(pp, txoMLP)
	if err != nil {
		return false, 0, err
	}

	//	check whether the coinAddress of abeTxo belongs to the owner of coinDetectorKey.
	valid, err = pqringctxapi.DetectCoinAddress(pp, coinAddressInTxo, coinDetectorKey)
	if err != nil {
		return false, 0, err
	}
	if !valid {
		return false, 0, nil
	}

	var coinValuePublicKey, coinValueSecretKey []byte
	if len(coinValueKeyRandSeed) != 0 {
		//	generate (coinValuePublicKey, coinValueSecretKey)
		//	NOTE: the codes here must be consistent with that in abecryptoxkey/abepqringctxkey.go
		coinValuePublicKey, coinValueSecretKey, err = pqringctxapi.CoinValueKeyGen(pp, coinValueKeyRandSeed)
		if err != nil {
			return false, 0, err
		}
	} else {
		coinValuePublicKey = nil
		coinValueSecretKey = nil
	}

	return pqringctxapi.TxoCoinReceive(pp, txoMLP, coinAddressInTxo, coinValuePublicKey, coinValueSecretKey)
}

// pqringctxTxoCoinReceiveByKeys checks whether the input abeTxo *wire.TxOutAbe belongs to the owner of the input cryptoAddress, and if true,
// it extracts the value of abeTxo using the input cryptoValueSecretKey (if it indeed corresponds to the cryptoAddress).
// todo: review
func pqringctxTxoCoinReceiveByKeys(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, abeTxo *wire.TxOutAbe,
	cryptoAddress []byte, cryptoValueSecretKey []byte) (valid bool, value uint64, err error) {
	cryptoSchemeInTxo, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return false, 0, err
	}

	if cryptoSchemeInTxo != cryptoScheme {
		return false, 0, fmt.Errorf("pqringctxTxoCoinReceiveByKeys: unmatched cryptoScheme for the input Txo")
	}

	privacyLevelInCryptoAddress, coinAddress, coinValuePublicKey, err := abecryptoxkey.CryptoAddressParse(cryptoAddress)
	if err != nil {
		return false, 0, err
	}

	var coinValueSecretKey []byte
	if len(cryptoValueSecretKey) != 0 {
		// for Txo on Pseudonym-privacy Address, the cryptoValueSecretKey is nil
		privacyLevelInCryptoValueSecretKey, coinValueSecretKeyTemp, err := abecryptoxkey.CryptoValueSecretKeyParse(cryptoValueSecretKey)
		if err != nil {
			return false, 0, err
		}
		if privacyLevelInCryptoAddress != privacyLevelInCryptoValueSecretKey {
			return false, 0, fmt.Errorf("pqringctxTxoCoinReceiveByKeys: the privacyLevel in cryptoValueSecretKey does not match that in cryptoAddress")
		}
		coinValueSecretKey = coinValueSecretKeyTemp
	} else {
		coinValueSecretKey = nil
	}

	//	NOTE: As the abepqringctx-layer obtained TxoMLP (associated in crypto-TransferTx/CoinbaseTx) and serialized it to abeTxo.TxoScript,
	//	here abepqringctx-layer calls crypto-scheme using TxoMLP.
	txoMLP, err := pqringctxapi.DeserializeTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return false, 0, err
	}

	return pqringctxapi.TxoCoinReceive(pp, txoMLP, coinAddress, coinValuePublicKey, coinValueSecretKey)
}

// pqringctxPseudonymTxoCoinParse parses the input (Pseudonym-Privacy) TxoMLP to its (coinAddress, coinValue) pair, and
// return an err if it is not a Pseudonym-Privacy Txo.
// todo: review
func pqringctxPseudonymTxoCoinParse(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, abeTxo *wire.TxOutAbe) (
	coinAddress []byte, value uint64, err error) {

	cryptoSchemeInTxo, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return nil, 0, err
	}

	if cryptoSchemeInTxo != cryptoScheme {
		return nil, 0, fmt.Errorf("pqringctxTxoCoinReceiveByKeys: unmatched cryptoScheme for the input Txo")
	}

	//	NOTE: As the abepqringctx-layer obtained TxoMLP (associated in crypto-TransferTx/CoinbaseTx) and serialized it to abeTxo.TxoScript,
	//	here abepqringctx-layer calls crypto-scheme using TxoMLP.
	txoMLP, err := pqringctxapi.DeserializeTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return nil, 0, err
	}

	return pqringctxapi.PseudonymTxoCoinParse(pp, txoMLP)
}

// pqringctxTxoCoinSerialNumberGenByRootSeed generates serialNumber for the input LgrTxoMLP, using the input coinSerialNumberKeyRootSeed.
// NOTE: the input coinSerialNumberKeyRootSeed could be nil, for example, when the input TxOutAbe is on a Pseudonym-Privacy address.
// todo: review
func pqringctxTxoCoinSerialNumberGenByRootSeed(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	abeTxo *wire.TxOutAbe, ringId wire.RingId, txoIndexInRing uint8, coinSerialNumberKeyRootSeed []byte) ([]byte, error) {
	// ringId + index -> ID
	//	// (txo, txolid) + serialNumberSecretKey -> sn [pqringctx]
	cryptoSchemeInTxo, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return nil, err
	}

	if cryptoSchemeInTxo != cryptoScheme {
		return nil, fmt.Errorf("pqringctxTxoCoinSerialNumberGenByRootSeed: the cryptoScheme (%d) corresponding to abeTxo.Version does not match the input cryptoScheme (%d)", cryptoSchemeInTxo, cryptoScheme)
	}

	txoMLP, err := pqringctxapi.DeserializeTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return nil, err
	}
	coinAddressType := txoMLP.CoinAddressType()

	txolid := pqringctxLedgerTxoIdGen(ringId, txoIndexInRing)

	lgrTxo := pqringctxapi.NewLgrTxo(txoMLP, txolid)

	var coinSerialNumberSecretKey []byte
	// The cryptoSerialNumberSecretKey could be nil, for example, for Pseudonym-Privacy Txo.
	if len(coinSerialNumberKeyRootSeed) != 0 {
		if coinAddressType != pqringctxapi.CoinAddressTypePublicKeyForRing {
			//	NOTE: only CoinAddressTypePublicKeyForRing address has coinSerialNumberKeyRandSeed
			return nil, fmt.Errorf("pqringctxTxoCoinSerialNumberGenByRootSeed: coinSerialNumberKeyRandSeed is not nil/empty, but the txo's coinAddressType (%d) is not CoinAddressTypePublicKeyForRing", coinAddressType)
		}

		//	extract publicRand and generate coinSerialNumberSecretKey
		//	NOTE: the codes here must be consistent with that in abecryptoxkey/abepqringctxkey.go
		coinAddress, err := pqringctxapi.GetCoinAddressFromTxo(pp, txoMLP)
		if err != nil {
			return nil, err
		}
		publicRand, err := pqringctxapi.ExtractPublicRandFromCoinAddress(pp, coinAddress)
		if err != nil {
			return nil, err
		}

		if len(coinSerialNumberKeyRootSeed) != abecryptoutils.PRFKeyBytesLen {
			return nil, fmt.Errorf("pqringctxTxoCoinSerialNumberGenByRootSeed: invalid length of coinSerialNumberKeyRootSeed (%d)", len(coinSerialNumberKeyRootSeed))
		}
		coinSerialNumberKeyRandSeed, err := abecryptoutils.KDF(coinSerialNumberKeyRootSeed, publicRand)
		if err != nil {
			return nil, err
		}

		coinSerialNumberSecretKey, err = pqringctxapi.CoinAddressKeyForPKRingGenSerialNumberKeyPart(pp, coinSerialNumberKeyRandSeed)
		if err != nil {
			return nil, err
		}

	} else {
		if coinAddressType != pqringctxapi.CoinAddressTypePublicKeyHashForSingle {
			return nil, fmt.Errorf("pqringctxTxoCoinSerialNumberGenByRootSeed: coinSerialNumberKeyRandSeed is nil/empty, while the txo's coinAddressType (%d) is not CoinAddressTypePublicKeyHashForSingle", coinAddressType)
		}

		coinSerialNumberSecretKey = nil
	}

	//	lgrTxo rather than (txo,txolid) pair is used, since TransferTxGen is called on input Ledger-txos.
	sn, err := pqringctxapi.LedgerTxoSerialNumberGen(pp, lgrTxo, coinSerialNumberSecretKey)
	if err != nil {
		return nil, err
	}

	return sn, nil
}

// pqringctxTxoCoinSerialNumberGenByRandSeed generates serialNumber for the input LgrTxoMLP, using the input coinSerialNumberKeyRandSeed.
// NOTE: the input coinSerialNumberKeyRandSeed could be nil, for example, when the input TxOutAbe is on a Pseudonym-Privacy address.
// todo: review
func pqringctxTxoCoinSerialNumberGenByRandSeed(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	abeTxo *wire.TxOutAbe, ringId wire.RingId, txoIndexInRing uint8, coinSerialNumberKeyRandSeed []byte) ([]byte, error) {
	// ringId + index -> ID
	//	// (txo, txolid) + serialNumberSecretKey -> sn [pqringctx]
	cryptoSchemeInTxo, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return nil, err
	}

	if cryptoSchemeInTxo != cryptoScheme {
		return nil, fmt.Errorf("pqringctxTxoCoinSerialNumberGenByRandSeed: the cryptoScheme (%d) corresponding to abeTxo.Version does not match the input cryptoScheme (%d)", cryptoSchemeInTxo, cryptoScheme)
	}

	txoMLP, err := pqringctxapi.DeserializeTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return nil, err
	}
	coinAddressType := txoMLP.CoinAddressType()

	txolid := pqringctxLedgerTxoIdGen(ringId, txoIndexInRing)

	lgrTxo := pqringctxapi.NewLgrTxo(txoMLP, txolid)

	var coinSerialNumberSecretKey []byte
	// The cryptoSerialNumberSecretKey could be nil, for example, for Pseudonym-Privacy Txo.
	if len(coinSerialNumberKeyRandSeed) != 0 {
		if coinAddressType != pqringctxapi.CoinAddressTypePublicKeyForRing {
			//	NOTE: only CoinAddressTypePublicKeyForRing address has coinSerialNumberKeyRandSeed
			return nil, fmt.Errorf("pqringctxTxoCoinSerialNumberGenByRandSeed: coinSerialNumberKeyRandSeed is not nil/empty, but the txo's coinAddressType (%d) is not CoinAddressTypePublicKeyForRing", coinAddressType)
		}

		//	generate coinSerialNumberSecretKey
		//	NOTE: the codes here must be consistent with that in abecryptoxkey/abepqringctxkey.go
		coinSerialNumberSecretKey, err = pqringctxapi.CoinAddressKeyForPKRingGenSerialNumberKeyPart(pp, coinSerialNumberKeyRandSeed)
		if err != nil {
			return nil, err
		}

	} else {
		if coinAddressType != pqringctxapi.CoinAddressTypePublicKeyHashForSingle {
			return nil, fmt.Errorf("pqringctxTxoCoinSerialNumberGenByRandSeed: coinSerialNumberKeyRandSeed is nil/empty, while the txo's coinAddressType (%d) is not CoinAddressTypePublicKeyHashForSingle", coinAddressType)
		}

		coinSerialNumberSecretKey = nil
	}

	//	lgrTxo rather than (txo,txolid) pair is used, since TransferTxGen is called on input Ledger-txos.
	sn, err := pqringctxapi.LedgerTxoSerialNumberGen(pp, lgrTxo, coinSerialNumberSecretKey)
	if err != nil {
		return nil, err
	}

	return sn, nil
}

// pqringctxTxoCoinSerialNumberGenByKey generates serialNumber for the input LgrTxoMLP, using the input coinSerialNumberSecretKey.
// NOTE: the input cryptoSerialNumberSecretKey could be nil, for example, when the input TxOutAbe is on a Pseudonym-Privacy address.
// todo: review
func pqringctxTxoCoinSerialNumberGenByKey(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	abeTxo *wire.TxOutAbe, ringId wire.RingId, txoIndexInRing uint8, cryptoSerialNumberSecretKey []byte) ([]byte, error) {
	// ringId + index -> ID
	//	// (txo, txolid) + serialNumberSecretKey -> sn [pqringctx]
	cryptoSchemeInTxo, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return nil, err
	}

	if cryptoSchemeInTxo != cryptoScheme {
		return nil, fmt.Errorf("pqringctTxoCoinSerialNumberGenByKey: the cryptoScheme (%d) corresponding to abeTxo.Version does not match the input cryptoScheme (%d)", cryptoSchemeInTxo, cryptoScheme)
	}

	txoMLP, err := pqringctxapi.DeserializeTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return nil, err
	}
	coinAddressType := txoMLP.CoinAddressType()

	txolid := pqringctxLedgerTxoIdGen(ringId, txoIndexInRing)

	lgrTxo := pqringctxapi.NewLgrTxo(txoMLP, txolid)

	var coinSerialNumberSecretKey []byte
	// The cryptoSerialNumberSecretKey could be nil, for example, for Pseudonym-Privacy Txo.
	if len(cryptoSerialNumberSecretKey) != 0 {
		var privacyLevel abecryptoxkey.PrivacyLevel
		privacyLevel, coinSerialNumberSecretKey, err = abecryptoxkey.CryptoSerialNumberSecretKeyParse(cryptoSerialNumberSecretKey)
		if err != nil {
			return nil, err
		}

		if privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre {
			if coinAddressType != pqringctxapi.CoinAddressTypePublicKeyForRingPre {
				return nil, fmt.Errorf("pqringctTxoCoinSerialNumberGenByKey: cryptoSerialNumberSecretKey is not nil/empty and the extracted privacyLevel is PrivacyLevelRINGCTPre, but the txo's coinAddressType (%d) is not CoinAddressTypePublicKeyForRingPre", coinAddressType)
			}
		} else if privacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
			if coinAddressType != pqringctxapi.CoinAddressTypePublicKeyForRing {
				return nil, fmt.Errorf("pqringctTxoCoinSerialNumberGenByKey: cryptoSerialNumberSecretKey is not nil/empty and the extracted privacyLevel is PrivacyLevelRINGCT, but the txo's coinAddressType (%d) is not CoinAddressTypePublicKeyForRing", coinAddressType)
			}
		} else {
			return nil, fmt.Errorf("pqringctTxoCoinSerialNumberGenByKey: cryptoSerialNumberSecretKey is not nil/empty, but the extracted privacyLevel (%d) is not PrivacyLevelRINGCTPre or PrivacyLevelRINGCT", privacyLevel)
		}

	} else {
		if coinAddressType != pqringctxapi.CoinAddressTypePublicKeyHashForSingle {
			return nil, fmt.Errorf("pqringctTxoCoinSerialNumberGenByKey: cryptoSerialNumberSecretKey is nil/empty, but the txo's coinAddressType (%d) is not CoinAddressTypePublicKeyHashForSingle", coinAddressType)
		}

		coinSerialNumberSecretKey = nil
	}

	//	lgrTxo rather than (txo,txolid) pair is used, since TransferTxGen is called on input Ledger-txos.
	sn, err := pqringctxapi.LedgerTxoSerialNumberGen(pp, lgrTxo, coinSerialNumberSecretKey)
	if err != nil {
		return nil, err
	}

	return sn, nil
}

// todo: remove this.
//// For wallet
//func pqringctTxoCoinSerialNumberGen(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, abeTxo *wire.TxOutAbe, ringHash chainhash.Hash, txoIndexInRing uint8, cryptoSnsk []byte) ([]byte, error) {
//	// ringHash + index -> ID
//	//	// (txo, txolid) + Sksn -> sn [pqringct]
//	cryptoSchemeInTxo, err := abecryptoxparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
//	if err != nil {
//		return nil, err
//	}
//
//	if cryptoSchemeInTxo != cryptoScheme {
//		return nil, errors.New("pqringctTxoCoinSerialNumberGen: unmatched cryptoScheme for input Txo")
//	}
//
//	txo, err := pqringctxapi.DeserializeTxo(pp, abeTxo.TxoScript)
//	if err != nil {
//		return nil, err
//	}
//
//	if txo.CoinAddressType() == pqringctxapi.CoinAddressTypePublicKeyHashForSingle {
//		return pqringctxapi.GetNullSerialNumber(pp), nil
//	}
//
//	txolid := pqringctxLedgerTxoIdGen(ringHash, txoIndexInRing)
//
//	lgrTxo := pqringctxapi.NewLgrTxo(txo, txolid)
//
//	_, coinSerialNumberSecretKey, err := abecryptoxkey.CryptoSerialNumberSecretKeyParse(cryptoSnsk)
//	if err != nil {
//		return nil, errors.New("pqringctTxoCoinSerialNumberGen: unmatched cryptoScheme for Snsk")
//	}
//
//	sn, err := pqringctxapi.TxoCoinSerialNumberGen(pp, lgrTxo, coinSerialNumberSecretKey)
//	if err != nil {
//		return nil, err
//	}
//
//	return sn, nil
//}

//	APIs for Txos	end

// APIs for TxWitnesses	begin

// pqringctxGetTxWitnessCbTxSerializeSizeByDesc returns the TxWitnessCbTxSerializeSize for a CbTx,
// which takes the input cryptoAddressListPayTo[] as the cryptoAddressList for the output Txos.
// todo: review
func pqringctxGetTxWitnessCbTxSerializeSizeByDesc(pp *pqringctxapi.PublicParameter, cryptoAddressListPayTo [][]byte) (int, error) {
	if len(cryptoAddressListPayTo) == 0 {
		return 0, fmt.Errorf("pqringctxGetTxWitnessCbTxSerializeSizeByDesc: the input cryptoAddressListPayTo is empty")
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

	return pqringctxapi.GetTxWitnessCbTxSerializeSizeByDesc(pp, coinAddressListPayTo)
}

func pqringctxGetTxWitnessTrTxSerializeSizeByDesc(pp *pqringctxapi.PublicParameter, inForRing uint8, inForSingleDistinct uint8,
	outForRing uint8, inRingSizes []uint8, vPublic int64) (int, error) {
	return pqringctxapi.GetTxWitnessTrTxSerializeSizeByDesc(pp, inForRing, inForSingleDistinct, outForRing, inRingSizes, vPublic)
}

//	APIs for TxWitnesses	end

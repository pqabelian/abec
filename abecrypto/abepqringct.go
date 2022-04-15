package abecrypto

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/cryptosuite/pqringct"
)

//// abecrypto -> abepqringct -> pqringct
// pqringctCryptoAddressGen() generates cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, by calling pqringct's key-generation functions and encapsed the keys.
// cryptoScheme is set as a parameter, since the map between CryptoScheme and the real crypto-scheme (here is pqringct) is coded by abecryptoparam.
func pqringctCryptoAddressGen(pp *pqringct.PublicParameter, seed []byte,
	cryptoScheme abecryptoparam.CryptoScheme) (
	cryptoAddress []byte,
	cryptoSpsk []byte,
	cryptoSnsk []byte,
	cryptoVsk []byte,
	err error) {
	expectedSeedLen := pqringct.GetParamSeedBytesLen(pp)
	if 2*expectedSeedLen != len(seed) {
		return nil, nil, nil, nil, errors.New("invalid length of seed in pqringctCryptoAddressGen")
	}

	serializedAPk, serializedASksp, serializedASksn, err := pqringct.AddressKeyGen(pp, seed[:expectedSeedLen])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	serializedVPk, serializedVSk, err := pqringct.ValueKeyGen(pp, seed[expectedSeedLen:])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	serializedAddress := append(serializedAPk, serializedVPk...)

	cryptoAddress = make([]byte, 0, 4+len(serializedAddress))
	cryptoAddress = append(cryptoAddress, byte(cryptoScheme>>0))
	cryptoAddress = append(cryptoAddress, byte(cryptoScheme>>8))
	cryptoAddress = append(cryptoAddress, byte(cryptoScheme>>16))
	cryptoAddress = append(cryptoAddress, byte(cryptoScheme>>24))
	cryptoAddress = append(cryptoAddress, serializedAddress...)

	cryptoSpsk = make([]byte, 0, 4+len(serializedASksp))
	cryptoSpsk = append(cryptoSpsk, byte(cryptoScheme>>0))
	cryptoSpsk = append(cryptoSpsk, byte(cryptoScheme>>8))
	cryptoSpsk = append(cryptoSpsk, byte(cryptoScheme>>16))
	cryptoSpsk = append(cryptoSpsk, byte(cryptoScheme>>24))
	cryptoSpsk = append(cryptoSpsk, serializedASksp...)

	cryptoSnsk = make([]byte, 0, 4+len(serializedASksn))
	cryptoSnsk = append(cryptoSnsk, byte(cryptoScheme>>0))
	cryptoSnsk = append(cryptoSnsk, byte(cryptoScheme>>8))
	cryptoSnsk = append(cryptoSnsk, byte(cryptoScheme>>16))
	cryptoSnsk = append(cryptoSnsk, byte(cryptoScheme>>24))
	cryptoSnsk = append(cryptoSnsk, serializedASksn...)

	cryptoVsk = make([]byte, 0, 4+len(serializedVSk))
	cryptoVsk = append(cryptoVsk, byte(cryptoScheme>>0))
	cryptoVsk = append(cryptoVsk, byte(cryptoScheme>>8))
	cryptoVsk = append(cryptoVsk, byte(cryptoScheme>>16))
	cryptoVsk = append(cryptoVsk, byte(cryptoScheme>>24))
	cryptoVsk = append(cryptoVsk, serializedVSk...)

	return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil
}

// The caller needs to fill the Version, TxIns, TxFee fileds for coinbaseTxMsgTemplate,
// this function will fill the TxOuts and TxWitness fields.
// The cryptoScheme here is used only for double-check.
// The TxMemo filed could be modified as needed, as the TxWitness does not depend on the TxMemo.
//	todo: TxMemo should be authenticated by witness, otherwise, the miner can modify the TxMemo?
//	Or, in our design, TxMemo is not guaranteed to be claimed by the transfer transaction issuer.
func pqringctCoinbaseTxGen(pp *pqringct.PublicParameter, cryptoScheme abecryptoparam.CryptoScheme, abeTxOutputDescs []*AbeTxOutputDesc, coinbaseTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	//	pqringct
	txOutputDescs := make([]*pqringct.TxOutputDesc, len(abeTxOutputDescs))
	for j := 0; j < len(abeTxOutputDescs); j++ {
		cryptoscheme4address := abeTxOutputDescs[j].cryptoAddress[0]
		cryptoscheme4address |= abeTxOutputDescs[j].cryptoAddress[1]
		cryptoscheme4address |= abeTxOutputDescs[j].cryptoAddress[2]
		cryptoscheme4address |= abeTxOutputDescs[j].cryptoAddress[3]
		if abecryptoparam.CryptoScheme(cryptoscheme4address) != cryptoScheme {
			return nil, errors.New("unmatched cryptoScheme for coinbase transaction and cryptoAddress")
		}

		// parse the cryptoAddress to serializedApk and serializedVpk
		apkLen := pqringct.GetAddressPublicKeySerializeSize(pp)
		//vpkLen := pp.GetValuePublicKeySerializeSize()
		serializedApk := abeTxOutputDescs[j].cryptoAddress[4 : 4+apkLen]
		serializedVpk := abeTxOutputDescs[j].cryptoAddress[4+apkLen:]
		txOutputDescs[j] = pqringct.NewTxOutputDescv2(pp, serializedApk, serializedVpk, abeTxOutputDescs[j].value)
	}

	// call the pqringct.CoinbaseTxGen
	//	vin is set in coinbaseTxMsgTemplate.TxFee
	cryptoCoinbaseTx, err := pqringct.CoinbaseTxGen(pp, coinbaseTxMsgTemplate.TxFee, txOutputDescs, coinbaseTxMsgTemplate.TxMemo)
	if err != nil {
		return nil, err
	}

	// parse the pqringct.CoinbaseTx to wire.TxAbe
	coinbaseTxMsgTemplate.TxOuts = make([]*wire.TxOutAbe, len(cryptoCoinbaseTx.OutputTxos))
	for i := 0; i < len(cryptoCoinbaseTx.OutputTxos); i++ {
		serializedTxo, err := pqringct.SerializeTxo(pp, cryptoCoinbaseTx.OutputTxos[i])
		if err != nil {
			return nil, err
		}
		coinbaseTxMsgTemplate.TxOuts[i] = &wire.TxOutAbe{
			Version:   coinbaseTxMsgTemplate.Version,
			TxoScript: serializedTxo,
		}
	}

	// witness must be associated with Tx, so it does not need to contain cryptoscheme or TxVersion.
	var serializedCbTxWitness []byte
	if len(cryptoCoinbaseTx.OutputTxos) == 1 {
		serializedCbTxWitness, err = pqringct.SerializeCbTxWitnessJ1(pp, cryptoCoinbaseTx.TxWitnessJ1)
	} else {
		serializedCbTxWitness, err = pqringct.SerializeCbTxWitnessJ2(pp, cryptoCoinbaseTx.TxWitnessJ2)
	}
	if err != nil {
		return nil, err
	}

	coinbaseTxMsgTemplate.TxWitness = serializedCbTxWitness
	return coinbaseTxMsgTemplate, nil
}

// pqringctCoinbaseTxVerify verify the input coinbaseTx.
// The caller needs to guarantee the well-form of the input coinbaseTx *wire.MsgTxAbe, such as the TxIns.
// This function only checks the balance proof, by calling the crypto-scheme.
func pqringctCoinbaseTxVerify(pp *pqringct.PublicParameter, coinbaseTx *wire.MsgTxAbe) (bool, error) {
	if coinbaseTx == nil {
		return false, nil
	}
	if len(coinbaseTx.TxOuts) <= 0 {
		return false, nil
	}
	var err error

	cryptoCoinbaseTx := &pqringct.CoinbaseTx{}

	cryptoCoinbaseTx.Vin = coinbaseTx.TxFee

	cryptoCoinbaseTx.OutputTxos = make([]*pqringct.Txo, len(coinbaseTx.TxOuts))
	for i := 0; i < len(coinbaseTx.TxOuts); i++ {
		if coinbaseTx.TxOuts[i].Version != coinbaseTx.Version {
			return false, nil
		}
		cryptoCoinbaseTx.OutputTxos[i], err = pqringct.DeserializeTxo(pp, coinbaseTx.TxOuts[i].TxoScript)
		if err != nil {
			return false, err
		}
	}

	cryptoCoinbaseTx.TxMemo = coinbaseTx.TxMemo

	if len(coinbaseTx.TxOuts) == 1 {
		cryptoCoinbaseTx.TxWitnessJ1, err = pqringct.DeserializeCbTxWitnessJ1(pp, coinbaseTx.TxWitness)
		cryptoCoinbaseTx.TxWitnessJ2 = nil
	} else {
		cryptoCoinbaseTx.TxWitnessJ1 = nil
		cryptoCoinbaseTx.TxWitnessJ2, err = pqringct.DeserializeCbTxWitnessJ2(pp, coinbaseTx.TxWitness)
	}
	if err != nil {
		return false, err
	}

	bl, err := pqringct.CoinbaseTxVerify(pp, cryptoCoinbaseTx)
	if err != nil {
		return false, err
	}
	if bl == false {
		return false, nil
	}

	return true, nil
}

// The caller needs to fill the Version, TxIns, TxFee, TxMemo fields of transferTxMsgTemplate
// This function will fill the serialNumbers in TxIns, and the TxOuts and TxWitness fields of transferTxMsgTemplate, and return it as the result
// The parameter cryptoScheme here is redundant at this moment and works for ony double-check.
// In the future, when the version of input ring is different from the ring of TxVersion/TxoVersion, the two corresponding cryptoSchemes should be set as parameter here.
func pqringctTransferTxGen(pp *pqringct.PublicParameter, cryptoScheme abecryptoparam.CryptoScheme, abeTxInputDescs []*AbeTxInputDesc, abeTxOutputDescs []*AbeTxOutputDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	inputNum := len(abeTxInputDescs)
	outputNum := len(abeTxOutputDescs)

	if inputNum <= 0 || outputNum <= 0 {
		return nil, errors.New("pqringctTransferTxGen: the input number and the output number should be at least 1")
	}

	txInputMaxNum, err := abecryptoparam.GetTxInputMaxNum(transferTxMsgTemplate.Version)
	if err != nil {
		return nil, errors.New("pqringctTransferTxGen:" + err.Error())
	}
	maxInputNum := pqringct.GetTxInputMaxNum(abecryptoparam.PQRingCTPP)
	if inputNum > maxInputNum {
		return nil, fmt.Errorf("pqringctTransferTxGen: the input number %d exceeds the allowed max number %d", inputNum, txInputMaxNum)
	}

	txOutputMaxNum, err := abecryptoparam.GetTxOutputMaxNum(transferTxMsgTemplate.Version)
	if err != nil {
		return nil, errors.New("pqringctTransferTxGen:" + err.Error())
	}
	maxOutputNum := pqringct.GetTxOutputMaxNum(abecryptoparam.PQRingCTPP)
	if outputNum > maxOutputNum {
		return nil, fmt.Errorf("pqringctTransferTxGen: the output number %d exceeds the allowed max number %d", outputNum, txOutputMaxNum)
	}

	if inputNum != len(transferTxMsgTemplate.TxIns) {
		return nil, errors.New("the number of InputDesc does not match the number of TxIn in transferTxMsgTemplate")
	}

	inputsRingVersion := transferTxMsgTemplate.TxIns[0].PreviousOutPointRing.Version
	if inputsRingVersion != transferTxMsgTemplate.Version {
		//	pqringct consumes only the input rings generated by pqringct
		return nil, errors.New("pqringctTransferTxGen: the version of the TxIn does not corresponding to PQRingCT")
	}

	cryptoSchemeInputRing, err := abecryptoparam.GetCryptoSchemeByTxVersion(inputsRingVersion)
	if err != nil {
		return nil, err
	}
	if cryptoSchemeInputRing != cryptoScheme {
		return nil, errors.New("pqringctTransferTxGen: unmatched cryptoScheme for input ring of transfer transaction and that of transaction")
	}

	//outputsVersion := transferTxMsgTemplate.Version

	//	inputDescs
	txInputDescs := make([]*pqringct.TxInputDesc, inputNum)
	for i := 0; i < inputNum; i++ {
		if transferTxMsgTemplate.TxIns[i].PreviousOutPointRing.Version != inputsRingVersion {
			return nil, errors.New("pqringctTransferTxGen: the version of the TxIn in one transaction should be the same")
		}
		lgrTxoList := make([]*pqringct.LgrTxo, len(abeTxInputDescs[i].txoList))
		for j := 0; j < len(abeTxInputDescs[i].txoList); j++ {
			if abeTxInputDescs[i].txoList[j].Version != inputsRingVersion {
				return nil, errors.New("pqringctTransferTxGen: the version of TXOs in abeTxInputDescs.serializedTxoList does not match the version in the corresponding TxIn")
			}
			txo, err := pqringct.DeserializeTxo(pp, abeTxInputDescs[i].txoList[j].TxoScript)
			if err != nil {
				return nil, err
			}

			txolid := ledgerTxoIdGen(abeTxInputDescs[i].ringHash, uint8(j))

			lgrTxoList[j] = pqringct.NewLgrTxo(txo, txolid)
		}

		sidx := abeTxInputDescs[i].sidx
		value := abeTxInputDescs[i].value

		cryptoSchemeInKey := abeTxInputDescs[i].cryptoSpsk[0]
		cryptoSchemeInKey |= abeTxInputDescs[i].cryptoSpsk[1]
		cryptoSchemeInKey |= abeTxInputDescs[i].cryptoSpsk[2]
		cryptoSchemeInKey |= abeTxInputDescs[i].cryptoSpsk[3]
		if abecryptoparam.CryptoScheme(cryptoSchemeInKey) != cryptoScheme {
			return nil, errors.New("pqringctTransferTxGen: unmatched cryptoScheme for Spsk and transaction")
		}
		serializedASksp := abeTxInputDescs[i].cryptoSpsk[4:]

		cryptoSchemeInKey = abeTxInputDescs[i].cryptoSnsk[0]
		cryptoSchemeInKey |= abeTxInputDescs[i].cryptoSnsk[1]
		cryptoSchemeInKey |= abeTxInputDescs[i].cryptoSnsk[2]
		cryptoSchemeInKey |= abeTxInputDescs[i].cryptoSnsk[3]
		if abecryptoparam.CryptoScheme(cryptoSchemeInKey) != cryptoScheme {
			return nil, errors.New("pqringctTransferTxGen: unmatched cryptoScheme for Snsk and transaction")
		}
		serializedASksn := abeTxInputDescs[i].cryptoSnsk[4:]

		cryptoSchemeInKey = abeTxInputDescs[i].cryptoVsk[0]
		cryptoSchemeInKey |= abeTxInputDescs[i].cryptoVsk[1]
		cryptoSchemeInKey |= abeTxInputDescs[i].cryptoVsk[2]
		cryptoSchemeInKey |= abeTxInputDescs[i].cryptoVsk[3]
		if abecryptoparam.CryptoScheme(cryptoSchemeInKey) != cryptoScheme {
			return nil, errors.New("pqringctTransferTxGen: unmatched cryptoScheme for Vsk and transaction")
		}
		serializedVSk := abeTxInputDescs[i].cryptoVsk[4:]

		cryptoSchemeInAddress := abeTxInputDescs[i].cryptoAddress[0]
		cryptoSchemeInAddress |= abeTxInputDescs[i].cryptoAddress[1]
		cryptoSchemeInAddress |= abeTxInputDescs[i].cryptoAddress[2]
		cryptoSchemeInAddress |= abeTxInputDescs[i].cryptoAddress[3]
		if abecryptoparam.CryptoScheme(cryptoSchemeInAddress) != cryptoScheme {
			return nil, errors.New("pqringctTransferTxGen: unmatched cryptoScheme for input address and transaction")
		}
		apkLen := pqringct.GetAddressPublicKeySerializeSize(pp)
		serializedVpk := abeTxInputDescs[i].cryptoAddress[4+apkLen:]

		txInputDescs[i] = pqringct.NewTxInputDescv2(pp, lgrTxoList, sidx, serializedASksp, serializedASksn, serializedVpk, serializedVSk, value)
	}

	// outputDescs
	txOutputDescs := make([]*pqringct.TxOutputDesc, outputNum)
	for j := 0; j < outputNum; j++ {
		cryptoscheme4outAddress := abeTxOutputDescs[j].cryptoAddress[0]
		cryptoscheme4outAddress |= abeTxOutputDescs[j].cryptoAddress[1]
		cryptoscheme4outAddress |= abeTxOutputDescs[j].cryptoAddress[2]
		cryptoscheme4outAddress |= abeTxOutputDescs[j].cryptoAddress[3]
		if abecryptoparam.CryptoScheme(cryptoscheme4outAddress) != cryptoScheme {
			return nil, errors.New("pqringctTransferTxGen: unmatched cryptoScheme for transfer transaction and its output cryptoAddress")
		}
		// parse the cryptoAddress to serializedApk and serializedVpk
		apkLen := pqringct.GetAddressPublicKeySerializeSize(pp)
		serializedApk := abeTxOutputDescs[j].cryptoAddress[4 : 4+apkLen]
		serializedVpk := abeTxOutputDescs[j].cryptoAddress[4+apkLen:]

		txOutputDescs[j] = pqringct.NewTxOutputDescv2(pp, serializedApk, serializedVpk, abeTxOutputDescs[j].value)
	}

	//	call the crypto scheme
	cryptoTransferTx, err := pqringct.TransferTxGen(pp, txInputDescs, txOutputDescs, transferTxMsgTemplate.TxFee, transferTxMsgTemplate.TxMemo)
	if err != nil {
		return nil, err
	}
	//	For the inputs, only the serial number needs to be set
	for i := 0; i < inputNum; i++ {
		transferTxMsgTemplate.TxIns[i].SerialNumber = cryptoTransferTx.Inputs[i].SerialNumber
	}

	//	Set the output Txos
	transferTxMsgTemplate.TxOuts = make([]*wire.TxOutAbe, outputNum)
	for j := 0; j < outputNum; j++ {
		serializeTxo, err := pp.SerializeTxo(cryptoTransferTx.OutputTxos[j])
		if err != nil {
			return nil, err
		}
		//	todo: wire.TxOutAbe use NewTxOutAbe()
		transferTxMsgTemplate.TxOuts[j] = &wire.TxOutAbe{
			Version:   transferTxMsgTemplate.Version,
			TxoScript: serializeTxo,
		}
	}

	//	Set the TxWitness
	transferTxMsgTemplate.TxWitness, err = pp.SerializeTrTxWitness(cryptoTransferTx.TxWitness)
	if err != nil {
		return nil, err
	}

	return transferTxMsgTemplate, nil
}

func pqringctTransferTxVerify(pp *pqringct.PublicParameter, transferTx *wire.MsgTxAbe, abeTxInDetails []*AbeTxInDetail) (bool, error) {
	if transferTx == nil {
		return false, nil
	}

	inputNum := len(transferTx.TxIns)
	outputNum := len(transferTx.TxOuts)
	if inputNum <= 0 || outputNum <= 0 {
		return false, nil
	}

	if len(abeTxInDetails) != inputNum {
		return false, nil
	}

	var err error
	inputsVersion := transferTx.TxIns[0].PreviousOutPointRing.Version
	outputsVersion := transferTx.Version

	cryptoTransferTx := &pqringct.TransferTx{}

	//	Inputs
	cryptoTransferTx.Inputs = make([]*pqringct.TrTxInput, inputNum)
	for i := 0; i < inputNum; i++ {
		if transferTx.TxIns[i].PreviousOutPointRing.Version != inputsVersion {
			return false, nil
			//	This is necessary, since the same version will ensure that when calling the cryptoscheme, there are not exceptions.
		}
		if bytes.Compare(abeTxInDetails[i].serialNumber, transferTx.TxIns[i].SerialNumber) != 0 {
			return false, nil
			//	This check can be removed, as the caller will provide abeTxInDetails, which are made by querying the database using the transferTx.TxIns information
		}
		txoList := make([]*pqringct.LgrTxo, len(abeTxInDetails[i].txoList))
		for j := 0; j < len(abeTxInDetails[i].txoList); j++ {
			if abeTxInDetails[i].txoList[j].Version != transferTx.TxIns[i].PreviousOutPointRing.Version {
				return false, nil
				//	The Txos in the same ring should have the same version
			}

			txo, err := pp.DeserializeTxo(abeTxInDetails[i].txoList[j].TxoScript)
			if err != nil {
				return false, err
			}
			txolid := ledgerTxoIdGen(abeTxInDetails[i].ringHash, uint8(j))
			txoList[j] = pqringct.NewLgrTxo(txo, txolid)

		}
		cryptoTransferTx.Inputs[i] = &pqringct.TrTxInput{
			TxoList:      txoList,
			SerialNumber: abeTxInDetails[i].serialNumber,
		}
	}

	//	OutputTxos
	cryptoTransferTx.OutputTxos = make([]*pqringct.Txo, outputNum)
	for j := 0; j < outputNum; j++ {
		if transferTx.TxOuts[j].Version != outputsVersion {
			return false, nil
			//	The output Txos of a transaction should have the same version as the transaction.
		}

		cryptoTransferTx.OutputTxos[j], err = pp.DeserializeTxo(transferTx.TxOuts[j].TxoScript)
		if err != nil {
			return false, err
		}
	}

	//	Fee
	cryptoTransferTx.Fee = transferTx.TxFee

	//	TxMemo
	cryptoTransferTx.TxMemo = transferTx.TxMemo

	//	TxWitness
	cryptoTransferTx.TxWitness, err = pp.DeserializeTrTxWitness(transferTx.TxWitness)
	if err != nil {
		return false, nil
	}

	// call the crypto scheme's verify algroithm
	bl, err := pqringct.TransferTxVerify(pp, cryptoTransferTx)
	if err != nil {
		return false, err
	}
	if bl == false {
		return false, nil
	}

	return true, nil
}

func pqringctTxoCoinReceive(pp *pqringct.PublicParameter, cryptoScheme abecryptoparam.CryptoScheme, abeTxo *wire.TxOutAbe, cryptoAddress []byte, cryptoVsk []byte) (valid bool, v uint64, err error) {
	cryptoSchemeTxo, err := abecryptoparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return false, 0, err
	}

	if cryptoSchemeTxo != cryptoScheme {
		return false, 0, errors.New("pqringctTxoCoinReceive: unmatched cryptoScheme for input Txo")
	}

	txo, err := pqringct.DeserializeTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return false, 0, err
	}

	cryptoSchemeInAddress := cryptoAddress[0]
	cryptoSchemeInAddress |= cryptoAddress[1]
	cryptoSchemeInAddress |= cryptoAddress[2]
	cryptoSchemeInAddress |= cryptoAddress[3]
	if abecryptoparam.CryptoScheme(cryptoSchemeInAddress) != cryptoScheme {
		return false, 0, errors.New("pqringctTxoCoinReceive: unmatched cryptoScheme for input instanceAddress")
	}
	apkLen := pqringct.GetAddressPublicKeySerializeSize(pp)
	serializedApk := cryptoAddress[4 : 4+apkLen]
	serializedVpk := cryptoAddress[4+apkLen:]

	cryptoSchemeInVsk := cryptoVsk[0]
	cryptoSchemeInVsk |= cryptoVsk[1]
	cryptoSchemeInVsk |= cryptoVsk[2]
	cryptoSchemeInVsk |= cryptoVsk[3]
	if abecryptoparam.CryptoScheme(cryptoSchemeInVsk) != cryptoScheme {
		return false, 0, errors.New("pqringctTxoCoinReceive: unmatched cryptoScheme for Vsk")
	}
	serializedVsk := cryptoVsk[4:]

	return pqringct.TxoCoinReceive(pp, txo, serializedApk, serializedVpk, serializedVsk)
}

// For wallet
func pqringctTxoCoinSerialNumberGen(pp *pqringct.PublicParameter, cryptoScheme abecryptoparam.CryptoScheme, abeTxo *wire.TxOutAbe, ringHash chainhash.Hash, txoIndexInRing uint8, cryptoSnsk []byte) ([]byte, error) {
	// ringHash + index -> ID
	//	// (txo, txolid) + Sksn -> sn [pqringct]
	cryptoScheme4Txo, err := abecryptoparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return nil, err
	}

	if cryptoScheme4Txo != cryptoScheme {
		return nil, errors.New("pqringctTxoCoinSerialNumberGen: unmatched cryptoScheme for input Txo")
	}

	txo, err := pqringct.DeserializeTxo(pp, abeTxo.TxoScript)
	if err != nil {
		return nil, err
	}

	txolid := ledgerTxoIdGen(ringHash, txoIndexInRing)

	lgrTxo := pqringct.NewLgrTxo(txo, txolid)

	cryptoSchemeInSnsk := cryptoSnsk[0]
	cryptoSchemeInSnsk |= cryptoSnsk[1]
	cryptoSchemeInSnsk |= cryptoSnsk[2]
	cryptoSchemeInSnsk |= cryptoSnsk[3]
	if abecryptoparam.CryptoScheme(cryptoSchemeInSnsk) != cryptoScheme {
		return nil, errors.New("pqringctTxoCoinSerialNumberGen: unmatched cryptoScheme for Snsk")
	}
	serializedAsksn := cryptoSnsk[4:]

	//	lgrTxo rather than (txo,txolid) pair is used, since TransferTxGen is called on input Ledger-txos.
	sn, err := pqringct.LedgerTxoSerialNumberGen(pp, lgrTxo, serializedAsksn)
	if err != nil {
		return nil, err
	}

	return sn, nil

}

func pqringctExtractCoinAddressFromTxoScript(pp *pqringct.PublicParameter, txoscript []byte) ([]byte, error) {
	txo, err := pp.DeserializeTxo(txoscript)
	if err != nil {
		return nil, err
	}
	return pp.SerializeAddressPublicKey(txo.AddressPublicKey)
}

func ledgerTxoIdGen(ringHash chainhash.Hash, index uint8) []byte {
	w := bytes.NewBuffer(make([]byte, 0, chainhash.HashSize+1))
	var err error
	// ringHash
	_, err = w.Write(ringHash[:])
	if err != nil {
		return nil
	}
	// index
	err = w.WriteByte(index >> 0)
	if err != nil {
		return nil
	}
	return chainhash.DoubleHashB(w.Bytes())
}

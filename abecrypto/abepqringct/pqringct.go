package abepqringct

//
//import (
//	"bytes"
//	"encoding/binary"
//	"errors"
//	"fmt"
//	"github.com/abesuite/abec/abecrypto"
//	"github.com/abesuite/abec/abecrypto/abecryptoparam"
//	"github.com/abesuite/abec/wire"
//	"github.com/cryptosuite/pqringct"
//)
//
//type MasterPublicKeyIfc interface {
//	SerializeSize() uint32
//	Serialize() []byte
//	Deserialize([]byte) error
//}
//
//type MasterSecretViewKeyIfc interface {
//	SerializeSize() uint32
//	Serialize() []byte
//	Deserialize([]byte) error
//}
//
//type MasterSecretSignKeyIfc interface {
//	SerializeSize() uint32
//	Serialize() []byte
//	Deserialize([]byte) error
//}
//
//type AbeTxOutDesc struct {
//	serializedMasterPublicKey []byte
//	value                     uint64
//}
//
//func NewAbeTxOutDesc(serializedMpk []byte, value uint64) *AbeTxOutDesc {
//	return &AbeTxOutDesc{
//		serializedMpk,
//		value,
//	}
//}
//
//func (txOutDesc *AbeTxOutDesc) GetValue() uint64 {
//	return txOutDesc.value
//}
//
//type AbeTxInputDesc struct {
//	serializedTxoList             []*wire.TxOutAbe
//	sidx                          int
//	serializedMasterPublicKey     []byte
//	serializedMasterSecretViewKey []byte
//	serializedMasterSecretSignKey []byte
//	value                         uint64
//}
//
//func NewAbeTxInputDesc(serializedTxoList []*wire.TxOutAbe, sidx int, serializedMpk []byte, serializedMsvk []byte, serializedMssk []byte, value uint64) *AbeTxInputDesc {
//	return &AbeTxInputDesc{
//		serializedTxoList,
//		sidx,
//		serializedMpk,
//		serializedMsvk,
//		serializedMssk,
//		value,
//	}
//}
//
//type AbeTxInDetail struct {
//	serializedTxoList []*wire.TxOutAbe
//	serialNumber      []byte
//}
//
//func NewAbeTxInDetail(serializedTxoList []*wire.TxOutAbe, serialNumber []byte) *AbeTxInDetail {
//	return &AbeTxInDetail{
//		serializedTxoList,
//		serialNumber,
//	}
//}
//
///*
//The caller should know and specify the exact MasterKeyGen() for particular pqringct version.
//*/
////	todo_DONE: input and output seed
//func MasterKeyGen(inputSeed []byte, cryptoScheme abecrypto.CryptoScheme) (serializedSeed []byte, serializedMpk []byte, serializedMsvk []byte, serializedMssk []byte, err error) {
//	if len(inputSeed) != 0 {
//		if len(inputSeed) <= 4 {
//			err := errors.New("the leng of the inputSeed is smaller than 4")
//			return nil, nil, nil, nil, err
//		}
//		cryptoSchemeInSeed := binary.BigEndian.Uint32(inputSeed[:4])
//		if cryptoSchemeInSeed != uint32(cryptoScheme) {
//			err := errors.New("the CryptoScheme in the sedd does not match the input CryptoScheme")
//			return nil, nil, nil, nil, err
//		}
//	}
//
//	var mpk MasterPublicKeyIfc
//	var msvk MasterSecretViewKeyIfc
//	var mssk MasterSecretSignKeyIfc
//	var seed []byte
//
//	if cryptoScheme == abecrypto.CryptoSchemePQRINGCT {
//		if len(inputSeed) != 0 {
//			seed, mpk, msvk, mssk, err = abecryptoparam.CryptoPP.MasterKeyGen(inputSeed[4:])
//		} else {
//			seed, mpk, msvk, mssk, err = abecryptoparam.CryptoPP.MasterKeyGen(nil)
//		}
//		if err != nil {
//			return nil, nil, nil, nil, err
//		}
//	} else {
//		panic("Unsupported version appears! Implement here.")
//		// todo: if there is any more version to support, implement it here
//	}
//
//	retseedSer := inputSeed
//	if len(inputSeed) == 0 {
//		retseedSer = make([]byte, 4+len(seed))
//		binary.BigEndian.PutUint32(retseedSer, uint32(cryptoScheme))
//		copy(retseedSer[4:], seed)
//	}
//
//	retmpkSer := make([]byte, 4+mpk.SerializeSize())
//	binary.BigEndian.PutUint32(retmpkSer, uint32(cryptoScheme))
//	copy(retmpkSer[4:], mpk.Serialize())
//
//	retmsvkSer := make([]byte, 4+msvk.SerializeSize())
//	binary.BigEndian.PutUint32(retmsvkSer, uint32(cryptoScheme))
//	copy(retmsvkSer[4:], msvk.Serialize())
//
//	retmsskSer := make([]byte, 4+mssk.SerializeSize())
//	binary.BigEndian.PutUint32(retmsskSer, uint32(cryptoScheme))
//	copy(retmsskSer[4:], mssk.Serialize())
//
//	return retseedSer, retmpkSer, retmsvkSer, retmsskSer, nil
//}
//
///*
//The caller needs to fill the Version, TxIns, TxFee fileds for coinbaseTxMsgTemplate,
//this fucntion will fill the TxOuts and TxWitness fields.
//The TxMemo filed could be modified as needed, as the TxWitness does not depends on the TxMemo.
//*/
//func pqringctCoinbaseTxGen(abeTxOutDescs []*AbeTxOutDesc, coinbaseTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
//	cryptoScheme := abecrypto.GetCryptoScheme(coinbaseTxMsgTemplate.Version)
//
//	outputNum := len(abeTxOutDescs)
//	if outputNum > abecryptoparam.GetOutputMaxNum(coinbaseTxMsgTemplate.Version) {
//		return nil, fmt.Errorf("the output number %d exceeds the allowed max number %d", outputNum, abecryptoparam.GetInputMaxNum(coinbaseTxMsgTemplate.Version))
//	}
//
//	if cryptoScheme == abecrypto.CryptoSchemePQRINGCT {
//		//	pqringct
//		txOutputDescs := make([]*pqringct.TxOutputDesc, len(abeTxOutDescs))
//		for j := 0; j < len(abeTxOutDescs); j++ {
//			cryptoSchemeInDesc := binary.BigEndian.Uint32(abeTxOutDescs[j].serializedMasterPublicKey[:4])
//			if abecrypto.CryptoScheme(cryptoSchemeInDesc) != cryptoScheme {
//				return nil, errors.New("the cryptoScheme in TxOutDesc does not match that implied by the MsgTx.version")
//			}
//			mpk := &pqringct.MasterPublicKey{}
//			err := mpk.Deserialize(abeTxOutDescs[j].serializedMasterPublicKey[4:])
//			if err != nil {
//				return nil, err
//			}
//
//			txOutputDescs[j] = pqringct.NewTxOutputDesc(mpk, abeTxOutDescs[j].value)
//		}
//
//		cryptoCoinbaseTx, err := abecryptoparam.CryptoPP.pqringctCoinbaseTxGen(coinbaseTxMsgTemplate.TxFee, txOutputDescs)
//		if err != nil {
//			return nil, err
//		}
//
//		coinbaseTxMsgTemplate.TxOuts = make([]*wire.TxOutAbe, len(cryptoCoinbaseTx.OutputTxos))
//		for i := 0; i < len(cryptoCoinbaseTx.OutputTxos); i++ {
//			coinbaseTxMsgTemplate.TxOuts[i] = &wire.TxOutAbe{
//				coinbaseTxMsgTemplate.Version,
//				cryptoCoinbaseTx.OutputTxos[i].Serialize(),
//			}
//		}
//
//		coinbaseTxMsgTemplate.TxWitness = cryptoCoinbaseTx.TxWitness.Serialize()
//
//		return coinbaseTxMsgTemplate, nil
//	} else {
//		panic("Unsupported version appears! Implement here.")
//		// todo: if there is any more version to support, implement it here
//	}
//
//	return nil, nil
//}
//
///*
//The caller needs to guarantee the well-form of the input coinbaseTx *wire.MsgTxAbe, such as the TxIns.
//This function only checks the balance proof, by calling the crypto-scheme.
//*/
//func pqringctCoinbaseTxVerify(coinbaseTx *wire.MsgTxAbe) bool {
//	if coinbaseTx == nil {
//		return false
//	}
//
//	if len(coinbaseTx.TxOuts) <= 0 {
//		return false
//	}
//
//	cryptoScheme := abecrypto.GetCryptoScheme(coinbaseTx.Version)
//	if cryptoScheme == abecrypto.CryptoSchemePQRINGCT {
//		cryptoCoinbaseTx := &pqringct.CoinbaseTx{}
//
//		cryptoCoinbaseTx.Vin = coinbaseTx.TxFee
//
//		cryptoCoinbaseTx.TxWitness = &pqringct.CbTxWitness{}
//		reader := bytes.NewReader(coinbaseTx.TxWitness)
//		err := cryptoCoinbaseTx.TxWitness.Deserialize(reader)
//		if err != nil {
//			return false
//		}
//
//		cryptoCoinbaseTx.OutputTxos = make([]*pqringct.TXO, len(coinbaseTx.TxOuts))
//		for i := 0; i < len(coinbaseTx.TxOuts); i++ {
//			if coinbaseTx.TxOuts[i].Version != coinbaseTx.Version {
//				return false
//			}
//			txo := &pqringct.TXO{}
//			reader := bytes.NewReader(coinbaseTx.TxOuts[i].TxoScript)
//			err := txo.Deserialize(reader)
//			if err != nil {
//				return false
//			}
//
//			cryptoCoinbaseTx.OutputTxos[i] = txo
//		}
//
//		//	todo:
//		bl := abecryptoparam.CryptoPP.pqringctCoinbaseTxVerify(cryptoCoinbaseTx)
//		if bl == false {
//			return false
//		}
//	} else {
//		panic("Unsupported version appears! Implement here.")
//		// todo: if there is any more version to support, implement it here
//	}
//
//	return false
//}
//
///*
//The caller needs to fill the Version, TxIns, TxFee, TxMemo fields of transferTxMsgTemplate
//This function will fill the serialNumbers in TxIns, and the TxOuts and TxWitness fields of transferTxMsgTemplate, and return it as the result
//*/
//func pqringctTransferTxGen(abeTxInputDescs []*AbeTxInputDesc, abeTxOutputDescs []*AbeTxOutDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
//	inputNum := len(abeTxInputDescs)
//	outputNum := len(abeTxOutputDescs)
//
//	if inputNum <= 0 || outputNum <= 0 {
//		return nil, errors.New("the input number and the output number should be at least 1")
//	}
//
//	if inputNum > abecryptoparam.GetInputMaxNum(transferTxMsgTemplate.Version) {
//		return nil, fmt.Errorf("the input number %d exceeds the allowed max number %d", inputNum, abecryptoparam.GetInputMaxNum(transferTxMsgTemplate.Version))
//	}
//
//	if outputNum > abecryptoparam.GetOutputMaxNum(transferTxMsgTemplate.Version) {
//		return nil, fmt.Errorf("the output number %d exceeds the allowed max number %d", outputNum, abecryptoparam.GetOutputMaxNum(transferTxMsgTemplate.Version))
//	}
//
//	if inputNum != len(transferTxMsgTemplate.TxIns) {
//		return nil, errors.New("the number of InputDesc does not match the number of TxIn in transferTxMsgTemplate")
//	}
//
//	inputsVersion := transferTxMsgTemplate.TxIns[0].PreviousOutPointRing.Version
//	outputsVersion := transferTxMsgTemplate.Version
//
//	if abecrypto.GetCryptoScheme(inputsVersion) == abecrypto.CryptoSchemePQRINGCT && abecrypto.GetCryptoScheme(outputsVersion) == abecrypto.CryptoSchemePQRINGCT {
//		//	inputDescs
//		txInputDescs := make([]*pqringct.TxInputDesc, inputNum)
//		for i := 0; i < inputNum; i++ {
//			if transferTxMsgTemplate.TxIns[i].PreviousOutPointRing.Version != inputsVersion {
//				return nil, errors.New("the version of the TxIn in one transaction should be the same")
//			}
//
//			txoList := make([]*pqringct.TXO, len(abeTxInputDescs[i].serializedTxoList))
//			for j := 0; j < len(abeTxInputDescs[i].serializedTxoList); j++ {
//				if abeTxInputDescs[i].serializedTxoList[j].Version != inputsVersion {
//					return nil, errors.New("the version of TXOs in abeTxInputDescs.serializedTxoList does not match the version in the corresponding TxIn")
//				}
//
//				txo := &pqringct.TXO{}
//				reader := bytes.NewReader(abeTxInputDescs[i].serializedTxoList[j].TxoScript)
//				err := txo.Deserialize(reader)
//				if err != nil {
//					return nil, err
//				}
//				txoList[j] = txo
//			}
//
//			cryptoSchemeInInputDesc := binary.BigEndian.Uint32(abeTxInputDescs[i].serializedMasterPublicKey[:4])
//			if abecrypto.CryptoScheme(cryptoSchemeInInputDesc) != abecrypto.CryptoSchemePQRINGCT {
//				return nil, errors.New("the cryptoScheme of the MasterPublicKey in the TxInputDesc does not match that implied by the consumed TXO")
//			}
//			cryptoSchemeInInputDesc = binary.BigEndian.Uint32(abeTxInputDescs[i].serializedMasterSecretViewKey[:4])
//			if abecrypto.CryptoScheme(cryptoSchemeInInputDesc) != abecrypto.CryptoSchemePQRINGCT {
//				return nil, errors.New("the cryptoScheme of the MasterSecretViewKey in the TxInputDesc does not match that implied by the consumed TXO")
//			}
//			cryptoSchemeInInputDesc = binary.BigEndian.Uint32(abeTxInputDescs[i].serializedMasterSecretSignKey[:4])
//			if abecrypto.CryptoScheme(cryptoSchemeInInputDesc) != abecrypto.CryptoSchemePQRINGCT {
//				return nil, errors.New("the cryptoScheme of the MasterSecretSignKey in the TxInputDesc does not match that implied by the consumed TXO")
//			}
//
//			mpk := &pqringct.MasterPublicKey{}
//			err := mpk.Deserialize(abeTxInputDescs[i].serializedMasterPublicKey[4:])
//			if err != nil {
//				return nil, err
//			}
//
//			msvk := &pqringct.MasterSecretViewKey{}
//			err = msvk.Deserialize(abeTxInputDescs[i].serializedMasterSecretViewKey[4:])
//			if err != nil {
//				return nil, err
//			}
//
//			mssk := &pqringct.MasterSecretSignKey{}
//			err = mssk.Deserialize(abeTxInputDescs[i].serializedMasterSecretSignKey[4:])
//			if err != nil {
//				return nil, err
//			}
//
//			sidx := abeTxInputDescs[i].sidx
//			value := abeTxInputDescs[i].value
//
//			txInputDescs[i] = pqringct.NewTxInputDesc(txoList, sidx, mpk, msvk, mssk, value)
//		}
//
//		// outputDescs
//		txOutputDescs := make([]*pqringct.TxOutputDesc, outputNum)
//		for j := 0; j < outputNum; j++ {
//			cryptoSchemeInOutputDesc := binary.BigEndian.Uint32(abeTxOutputDescs[j].serializedMasterPublicKey[:4])
//			if abecrypto.CryptoScheme(cryptoSchemeInOutputDesc) != abecrypto.CryptoSchemePQRINGCT {
//				return nil, errors.New("the cryptoScheme in TxOutputDesc does not match that implied by the transferTxMsg.version")
//			}
//
//			mpk := &pqringct.MasterPublicKey{}
//			err := mpk.Deserialize(abeTxOutputDescs[j].serializedMasterPublicKey[4:])
//			if err != nil {
//				return nil, err
//			}
//
//			value := abeTxOutputDescs[j].value
//
//			txOutputDescs[j] = pqringct.NewTxOutputDesc(mpk, value)
//		}
//
//		txMemo := make([]byte, 4+len(transferTxMsgTemplate.TxMemo))
//		binary.BigEndian.PutUint32(txMemo, transferTxMsgTemplate.Version)
//		copy(txMemo[4:], transferTxMsgTemplate.TxMemo)
//
//		//	call the crypto scheme
//		cryptoTransferTx, err := abecryptoparam.CryptoPP.pqringctTransferTxGen(txInputDescs, txOutputDescs, transferTxMsgTemplate.TxFee, txMemo)
//		if err != nil {
//			return nil, err
//		}
//
//		//	For the inputs, only the serial number needs to be set
//		for i := 0; i < inputNum; i++ {
//			transferTxMsgTemplate.TxIns[i].SerialNumber = cryptoTransferTx.Inputs[i].SerialNumber
//		}
//
//		//	Set the output Txos
//		transferTxMsgTemplate.TxOuts = make([]*wire.TxOutAbe, outputNum)
//		for j := 0; j < outputNum; j++ {
//			transferTxMsgTemplate.TxOuts[j] = &wire.TxOutAbe{
//				transferTxMsgTemplate.Version,
//				cryptoTransferTx.OutputTxos[j].Serialize(),
//			}
//		}
//
//		//	Set the TxWitness
//		transferTxMsgTemplate.TxWitness = cryptoTransferTx.TxWitness.Serialize()
//
//		return transferTxMsgTemplate, nil
//	} else {
//		panic("Unsupported version appears! Implement here.")
//		// todo: if there is any more version to support, implement it here
//	}
//
//	return nil, nil
//}
//
//func pqringctTransferTxVerify(transferTx *wire.MsgTxAbe, abeTxInDetails []*AbeTxInDetail) bool {
//	if transferTx == nil {
//		return false
//	}
//
//	inputNum := len(transferTx.TxIns)
//	outputNum := len(transferTx.TxOuts)
//	if inputNum <= 0 || outputNum <= 0 {
//		return false
//	}
//
//	if len(abeTxInDetails) != inputNum {
//		return false
//	}
//
//	inputsVersion := transferTx.TxIns[0].PreviousOutPointRing.Version
//	outputsVersion := transferTx.Version
//
//	if abecrypto.GetCryptoScheme(inputsVersion) == abecrypto.CryptoSchemePQRINGCT && abecrypto.GetCryptoScheme(outputsVersion) == abecrypto.CryptoSchemePQRINGCT {
//		cryptoTransferTx := &pqringct.TransferTx{}
//
//		//	Inputs
//		cryptoTransferTx.Inputs = make([]*pqringct.TrTxInput, inputNum)
//		for i := 0; i < inputNum; i++ {
//			if transferTx.TxIns[i].PreviousOutPointRing.Version != inputsVersion {
//				return false
//				//	This is necessary, since the same version will ensure that when calling the cryptoscheme, there are not exceptions.
//			}
//			if bytes.Compare(abeTxInDetails[i].serialNumber, transferTx.TxIns[i].SerialNumber) != 0 {
//				return false
//				//	This check can be removed, as the caller will provide abeTxInDetails, which are made by querying the database using the transferTx.TxIns information
//			}
//
//			txoList := make([]*pqringct.TXO, len(abeTxInDetails[i].serializedTxoList))
//			for j := 0; j < len(abeTxInDetails[i].serializedTxoList); j++ {
//				if abeTxInDetails[i].serializedTxoList[j].Version != transferTx.TxIns[i].PreviousOutPointRing.Version {
//					return false
//					//	The TXOs in the same ring should have the same version
//				}
//				txoList[j] = &pqringct.TXO{}
//				reader := bytes.NewReader(abeTxInDetails[i].serializedTxoList[j].TxoScript)
//				err := txoList[j].Deserialize(reader)
//				if err != nil {
//					return false
//				}
//			}
//
//			cryptoTransferTx.Inputs[i] = &pqringct.TrTxInput{
//				txoList,
//				abeTxInDetails[i].serialNumber,
//			}
//		}
//
//		//	OutputTxos
//		cryptoTransferTx.OutputTxos = make([]*pqringct.TXO, outputNum)
//		for j := 0; j < outputNum; j++ {
//			if transferTx.TxOuts[j].Version != outputsVersion {
//				return false
//				//	The output TXOs of a transaction should have the same version as the transaction.
//			}
//
//			cryptoTransferTx.OutputTxos[j] = &pqringct.TXO{}
//			reader := bytes.NewReader(transferTx.TxOuts[j].TxoScript)
//			err := cryptoTransferTx.OutputTxos[j].Deserialize(reader)
//			if err != nil {
//				return false
//			}
//		}
//
//		//	Fee
//		cryptoTransferTx.Fee = transferTx.TxFee
//
//		//	TxMemo
//		cryptoTransferTx.TxMemo = make([]byte, 4+len(transferTx.TxMemo))
//		binary.BigEndian.PutUint32(cryptoTransferTx.TxMemo, transferTx.Version)
//		copy(cryptoTransferTx.TxMemo[4:], transferTx.TxMemo)
//
//		//	TxWitness
//		cryptoTransferTx.TxWitness = &pqringct.TrTxWitness{}
//		reader := bytes.NewReader(transferTx.TxWitness)
//		err := cryptoTransferTx.TxWitness.Deserialize(reader)
//		if err != nil {
//			return false
//		}
//
//		// call the crypto scheme's verify algroithm
//		bl := abecryptoparam.CryptoPP.pqringctTransferTxVerify(cryptoTransferTx)
//		if bl == false {
//			return false
//		} else {
//			return true
//		}
//
//	} else {
//		panic("Unsupported version appears! Implement here.")
//		// todo: if there is any more version to support, implement it here
//	}
//}
//
//// todo: (AliceBob 2021.06.20) abeTxo should be serilazedTxo?
//func TxoSerialNumberGen(abeTxo *wire.TxOutAbe, serialzedMpk []byte, serializedMsvk []byte, serializedMssk []byte) (sn []byte, reterr error) {
//	if abeTxo == nil {
//		return nil, errors.New("cannot generate serial number for nil Txo")
//	}
//
//	if len(serialzedMpk) <= 4 || len(serializedMsvk) <= 4 || len(serializedMssk) <= 4 {
//		return nil, errors.New("incorrect format of input keys")
//	}
//
//	cryptoSchemeInTxo := abecrypto.GetCryptoScheme(abeTxo.Version)
//	cryptoSchemeInKeys := binary.BigEndian.Uint32(serialzedMpk[:4])
//	if abecrypto.CryptoScheme(cryptoSchemeInKeys) != cryptoSchemeInTxo {
//		return nil, errors.New("the cryptoScheme of the Master Public Key does not match that of the TXO")
//	}
//	cryptoSchemeInKeys = binary.BigEndian.Uint32(serializedMsvk[:4])
//	if abecrypto.CryptoScheme(cryptoSchemeInKeys) != cryptoSchemeInTxo {
//		return nil, errors.New("the cryptoScheme of the Master Secret View Key does not match that of the TXO")
//	}
//	cryptoSchemeInKeys = binary.BigEndian.Uint32(serializedMssk[:4])
//	if abecrypto.CryptoScheme(cryptoSchemeInKeys) != cryptoSchemeInTxo {
//		return nil, errors.New("the cryptoScheme of the Master Secret Sign Key does not match that of the TXO")
//	}
//
//	if cryptoSchemeInTxo == abecrypto.CryptoSchemePQRINGCT {
//		mpk := &pqringct.MasterPublicKey{}
//		err := mpk.Deserialize(serialzedMpk[4:])
//		if err != nil {
//			return nil, err
//		}
//
//		msvk := &pqringct.MasterSecretViewKey{}
//		err = msvk.Deserialize(serializedMsvk[4:])
//		if err != nil {
//			return nil, err
//		}
//
//		mssk := &pqringct.MasterSecretSignKey{}
//		err = mssk.Deserialize(serializedMssk[4:])
//		if err != nil {
//			return nil, err
//		}
//
//		cryptoTxo := &pqringct.TXO{}
//		reader := bytes.NewReader(abeTxo.TxoScript)
//		err = cryptoTxo.Deserialize(reader)
//		if err != nil {
//			return nil, err
//		}
//
//		retsn, err := abecryptoparam.CryptoPP.TxoSerialNumberGen(cryptoTxo, mpk, msvk, mssk)
//		if err != nil {
//			return nil, err
//		}
//
//		return retsn, nil
//
//	} else {
//		panic("Unsupported version appears! Implement here.")
//		// todo: if there is any more version to support, implement it here
//	}
//
//	return nil, nil
//}
//
//// todo: (AliceBob 2021.06.20) abeTxo should be serilazedTxo?
//func pqringctTxoCoinReceive(abeTxo *wire.TxOutAbe, serialzedMpk []byte, serializedMsvk []byte) (valid bool, v uint64) {
//	if abeTxo == nil {
//		return false, 0
//	}
//
//	if len(serialzedMpk) <= 4 || len(serializedMsvk) <= 4 {
//		return false, 0
//	}
//
//	cryptoSchemeInTxo := abecrypto.GetCryptoScheme(abeTxo.Version)
//	cryptoSchemeInKeys := binary.BigEndian.Uint32(serialzedMpk[:4])
//	if abecrypto.CryptoScheme(cryptoSchemeInKeys) != cryptoSchemeInTxo {
//		return false, 0
//	}
//	cryptoSchemeInKeys = binary.BigEndian.Uint32(serializedMsvk[:4])
//	if abecrypto.CryptoScheme(cryptoSchemeInKeys) != cryptoSchemeInTxo {
//		return false, 0
//	}
//
//	if cryptoSchemeInTxo == abecrypto.CryptoSchemePQRINGCT {
//		mpk := &pqringct.MasterPublicKey{}
//		err := mpk.Deserialize(serialzedMpk[4:])
//		if err != nil {
//			return false, 0
//		}
//
//		msvk := &pqringct.MasterSecretViewKey{}
//		err = msvk.Deserialize(serializedMsvk[4:])
//		if err != nil {
//			return false, 0
//		}
//		cryptoTxo := &pqringct.TXO{}
//		reader := bytes.NewReader(abeTxo.TxoScript)
//		err = cryptoTxo.Deserialize(reader)
//		if err != nil {
//			return false, 0
//		}
//
//		return abecryptoparam.CryptoPP.pqringctTxoCoinReceive(cryptoTxo, mpk, msvk)
//	} else {
//		panic("Unsupported version appears! Implement here.")
//		// todo: if there is any more version to support, implement it here
//	}
//
//	return false, 0
//}

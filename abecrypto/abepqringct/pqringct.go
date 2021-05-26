package abepqringct

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/wire"
	"github.com/cryptosuite/pqringct"
)

var cryptoPP *pqringct.PublicParameter = pqringct.DefaultPP

//	todo:
func GetMasterPublicKeyLen(version uint32) uint32 {

	return 1
}

type MasterPublicKeyIfc interface {
	SerializeSize() uint32
	Serialize() []byte
	Deserialize([]byte) error
}

type MasterSecretViewKeyIfc interface {
	SerializeSize() uint32
	Serialize() []byte
	Deserialize([]byte) error
}

type MasterSecretSignKeyIfc interface {
	SerializeSize() uint32
	Serialize() []byte
	Deserialize([]byte) error
}

type AbeTxOutDesc struct {
	serializedMasterPublicKey []byte
	value                     uint64
}

func NewAbeTxOutDesc(serializedMpk []byte, value uint64) *AbeTxOutDesc {
	return &AbeTxOutDesc{
		serializedMpk,
		value,
	}
}

type AbeTxInputDesc struct {
	serializedTxoList             []*wire.TxOutAbe
	sidx                          int
	serializedMasterPublicKey     []byte
	serializedMasterSecretViewKey []byte
	serializedMasterSecretSignKey []byte
	value                         uint64
}

func NewAbeTxInputDesc(serializedTxoList []*wire.TxOutAbe, sidx int, serializedMpk []byte, serializedMsvk []byte, serializedMssk []byte, value uint64) *AbeTxInputDesc {
	return &AbeTxInputDesc{
		serializedTxoList,
		sidx,
		serializedMpk,
		serializedMsvk,
		serializedMssk,
		value,
	}
}

/*
The caller should know and specify the exact MasterKeyGen() for particular pqringct version.
*/
//	todo: input and output seed
func MasterKeyGen(inputSeed []byte, cryptoScheme abecrypto.CryptoScheme) (seed []byte, serializedMpk []byte, serializedMsvk []byte, serializedMssk []byte, err error) {
	if len(inputSeed) != 0 {
		cryptoSchemeInSeed := binary.BigEndian.Uint32(inputSeed[:4])
		if uint32(cryptoScheme) != cryptoSchemeInSeed {
			err := errors.New("the CryptoScheme does not match that in the inputSeed")
			return nil, nil, nil, nil, err
		}
	}

	var mpk MasterPublicKeyIfc
	var msvk MasterSecretViewKeyIfc
	var mssk MasterSecretSignKeyIfc

	if cryptoScheme == abecrypto.CryptoSchemePQRINGCT {
		mpk, msvk, mssk, err = cryptoPP.MasterKeyGen(inputSeed)
		if err != nil {
			return nil, nil, nil, nil, err
		}
	} else if false {
		panic("Unsupported version appears! Implement here.")
		// todo: if there is any more version to support, implement it here
	}

	//	todo: seed

	retmpkSer := make([]byte, 4+mpk.SerializeSize())
	binary.BigEndian.PutUint32(retmpkSer, uint32(cryptoScheme))
	copy(retmpkSer[4:], mpk.Serialize())

	retmsvkSer := make([]byte, 4+msvk.SerializeSize())
	binary.BigEndian.PutUint32(retmsvkSer, uint32(cryptoScheme))
	copy(retmsvkSer[4:], msvk.Serialize())

	retmsskSer := make([]byte, 4+mssk.SerializeSize())
	binary.BigEndian.PutUint32(retmsskSer, uint32(cryptoScheme))
	copy(retmsskSer[4:], mssk.Serialize())

	return nil, retmpkSer, retmsvkSer, retmsskSer, nil
}

/*
The caller needs to fill the Version, TxIns, TxFee fileds for coinbaseTxMsgTemplate,
this fucntion will fill the TxOuts and TxWitness fields.
The TxMemo filed could be modified as needed, as the TxWitness does not depends on the TxMemo.
*/
func CoinbaseTxGen(abeTxOutDescs []*AbeTxOutDesc, coinbaseTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	cryptoScheme := abecrypto.GetCryptoScheme(coinbaseTxMsgTemplate.Version)

	outputNum := len(abeTxOutDescs)
	if outputNum > GetOutputMaxNum(coinbaseTxMsgTemplate.Version) {
		return nil, fmt.Errorf("the output number %d exceeds the allowed max number %d", outputNum, GetInputMaxNum(coinbaseTxMsgTemplate.Version))
	}

	if cryptoScheme == abecrypto.CryptoSchemePQRINGCT {
		//	pqringct
		txOutputDescs := make([]*pqringct.TxOutputDesc, len(abeTxOutDescs))
		for j := 0; j < len(abeTxOutDescs); j++ {
			cryptoSchemeInDesc := binary.BigEndian.Uint32(abeTxOutDescs[j].serializedMasterPublicKey[:4])
			if abecrypto.CryptoScheme(cryptoSchemeInDesc) != cryptoScheme {
				return nil, errors.New("the cryptoScheme in TxOutDesc does not match that implied by the MsgTx.version")
			}
			mpk := &pqringct.MasterPublicKey{}
			err := mpk.Deserialize(abeTxOutDescs[j].serializedMasterPublicKey[4:])
			if err != nil {
				return nil, err
			}

			txOutputDescs[j] = pqringct.NewTxOutputDesc(mpk, abeTxOutDescs[j].value)
		}

		cryptoCoinbaseTx, err := cryptoPP.CoinbaseTxGen(coinbaseTxMsgTemplate.TxFee, txOutputDescs)
		if err != nil {
			return nil, err
		}

		coinbaseTxMsgTemplate.TxOuts = make([]*wire.TxOutAbe, len(cryptoCoinbaseTx.OutputTxos))
		for i := 0; i < len(cryptoCoinbaseTx.OutputTxos); i++ {
			coinbaseTxMsgTemplate.TxOuts[i] = &wire.TxOutAbe{
				coinbaseTxMsgTemplate.Version,
				cryptoCoinbaseTx.OutputTxos[i].Serialize(),
			}
		}

		coinbaseTxMsgTemplate.TxWitness = cryptoCoinbaseTx.TxWitness.Serialize()

		return coinbaseTxMsgTemplate, nil
	} else if false {
		panic("Unsupported version appears! Implement here.")
		// todo: if there is any more version to support, implement it here
	}

	return nil, nil
}

/*
The caller needs to guarantee the well-form of the input coinbaseTx *wire.MsgTxAbe, such as the TxIns.
This function only checks the balance proof, by calling the crypto-scheme.
*/
func CoinbaseTxVerify(coinbaseTx *wire.MsgTxAbe) bool {
	if coinbaseTx == nil {
		return false
	}

	if len(coinbaseTx.TxOuts) <= 0 {
		return false
	}

	cryptoScheme := abecrypto.GetCryptoScheme(coinbaseTx.Version)
	if cryptoScheme == abecrypto.CryptoSchemePQRINGCT {
		cryptoCoinbaseTx := &pqringct.CoinbaseTx{}

		cryptoCoinbaseTx.Vin = coinbaseTx.TxFee

		cryptoCoinbaseTx.TxWitness = &pqringct.CbTxWitness{}
		err := cryptoCoinbaseTx.TxWitness.Deserialize(coinbaseTx.TxWitness)
		if err != nil {
			return false
		}

		cryptoCoinbaseTx.OutputTxos = make([]*pqringct.TXO, len(coinbaseTx.TxOuts))
		for i := 0; i < len(coinbaseTx.TxOuts); i++ {
			if coinbaseTx.TxOuts[i].Version != coinbaseTx.Version {
				return false
			}
			txo := &pqringct.TXO{}
			err := txo.Deserialize(coinbaseTx.TxOuts[i].TxoScript)
			if err != nil {
				return false
			}

			cryptoCoinbaseTx.OutputTxos[i] = txo
		}

		bl, err := cryptoPP.CoinbaseTxVerify(cryptoCoinbaseTx)
		if err != nil || bl == false {
			return false
		}
	} else if false {
		panic("Unsupported version appears! Implement here.")
		// todo: if there is any more version to support, implement it here
	}

	return false
}

/*
The caller needs to fill the Version, TxIns, TxFee, TxMemo fields of transferTxMsgTemplate
This function will fill the serialNumbers in TxIns, and the TxOuts and TxWitness fields of transferTxMsgTemplate, and return it as the result
*/
func TransferTxGen(abeTxInputDescs []*AbeTxInputDesc, abeTxOutputDescs []*AbeTxOutDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	inputNum := len(abeTxInputDescs)
	outputNum := len(abeTxOutputDescs)

	if inputNum <= 0 || outputNum <= 0 {
		return nil, errors.New("the input number and the output number should be at least 1")
	}

	if inputNum > GetInputMaxNum(transferTxMsgTemplate.Version) {
		return nil, fmt.Errorf("the input number %d exceeds the allowed max number %d", inputNum, GetInputMaxNum(transferTxMsgTemplate.Version))
	}

	if outputNum > GetOutputMaxNum(transferTxMsgTemplate.Version) {
		return nil, fmt.Errorf("the output number %d exceeds the allowed max number %d", outputNum, GetOutputMaxNum(transferTxMsgTemplate.Version))
	}

	if inputNum != len(transferTxMsgTemplate.TxIns) {
		return nil, errors.New("the number of InputDesc does not match the number of TxIn in transferTxMsgTemplate")
	}

	//	TxInputDescs
	inputsVersion := transferTxMsgTemplate.TxIns[0].Version
	txInputDescs := make([]*pqringct.TxInputDesc, inputNum)
	for i := 0; i < inputNum; i++ {
		if transferTxMsgTemplate.TxIns[i].Version != inputsVersion {
			return nil, errors.New("the version of the TxIn in one transaction should be the same")
		}

		txoList := make([]*pqringct.TXO, len(abeTxInputDescs[i].serializedTxoList))
		for j := 0; j < len(abeTxInputDescs[i].serializedTxoList); j++ {
			if abeTxInputDescs[i].serializedTxoList[j].Version != inputsVersion {
				return nil, errors.New("the version of Txos in abeTxInputDescs.serializedTxoList does not match the version in the corresponding TxIn")
			}

			if inputsVersion >= 1 {
				//	Version decides the CryptoScheme
				txo := &pqringct.TXO{}
				err := txo.Deserialize(abeTxInputDescs[i].serializedTxoList[j].TxoScript)
				if err != nil {
					return nil, err
				}
				txoList[j] = txo
			} else if false {
				//	todo: if there is more versions, implement it here
			}
		}

		cryptoSchemeInInputDesc := binary.BigEndian.Uint32(abeTxInputDescs[i].serializedMasterPublicKey[:4])
		if abecrypto.CryptoScheme(cryptoSchemeInInputDesc) != abecrypto.GetCryptoScheme(inputsVersion) {
			return nil, errors.New("the cryptoScheme in the serializedMasterPublicKey in the TxInputDesc does not match that implied by the trsnsferTx.version")
		}
		cryptoSchemeInInputDesc = binary.BigEndian.Uint32(abeTxInputDescs[i].serializedMasterSecretViewKey[:4])
		if abecrypto.CryptoScheme(cryptoSchemeInInputDesc) != abecrypto.GetCryptoScheme(inputsVersion) {
			return nil, errors.New("the cryptoScheme in the serializedMasterSecretViewKey in the TxInputDesc does not match that implied by the trsnsferTx.version")
		}
		cryptoSchemeInInputDesc = binary.BigEndian.Uint32(abeTxInputDescs[i].serializedMasterSecretSignKey[:4])
		if abecrypto.CryptoScheme(cryptoSchemeInInputDesc) != abecrypto.GetCryptoScheme(inputsVersion) {
			return nil, errors.New("the cryptoScheme in the serializedMasterSecretSignKey in the TxInputDesc does not match that implied by the trsnsferTx.version")
		}

		if abecrypto.GetCryptoScheme(inputsVersion) == abecrypto.CryptoSchemePQRINGCT {
			mpk := &pqringct.MasterPublicKey{}
			err := mpk.Deserialize(abeTxInputDescs[i].serializedMasterPublicKey[4:])
			if err != nil {
				return nil, err
			}

			msvk := &pqringct.MasterSecretViewKey{}
			err = msvk.Deserialize(abeTxInputDescs[i].serializedMasterSecretViewKey[4:])
			if err != nil {
				return nil, err
			}

			mssk := &pqringct.MasterSecretSignKey{}
			err = mssk.Deserialize(abeTxInputDescs[i].serializedMasterSecretSignKey[4:])
			if err != nil {
				return nil, err
			}

			sidx := abeTxInputDescs[i].sidx
			value := abeTxInputDescs[i].value

			txInputDescs[i] = pqringct.NewTxInputDesc(txoList, sidx, mpk, msvk, mssk, value)

		} else if false {
			//	todo: if there is more versions, implement it here
		}
	}

	//	TxOutputDescs
	outputsVersion := transferTxMsgTemplate.Version
	txOutputDescs := make([]*pqringct.TxOutputDesc, outputNum)
	for j := 0; j < outputNum; j++ {
		cryptoSchemeInOutputDesc := binary.BigEndian.Uint32(abeTxOutputDescs[j].serializedMasterPublicKey[:4])
		if abecrypto.CryptoScheme(cryptoSchemeInOutputDesc) != abecrypto.GetCryptoScheme(outputsVersion) {
			return nil, errors.New("the cryptoScheme in TxOutputDesc does not match that implied by the transferTxMsg.version")
		}
		if abecrypto.GetCryptoScheme(inputsVersion) == abecrypto.CryptoSchemePQRINGCT {
			mpk := &pqringct.MasterPublicKey{}
			err := mpk.Deserialize(abeTxOutputDescs[j].serializedMasterPublicKey[4:])
			if err != nil {
				return nil, err
			}

			value := abeTxOutputDescs[j].value

			txOutputDescs[j] = pqringct.NewTxOutputDesc(mpk, value)
		} else if false {
			//	todo: if there is more versions, implement it here
		}
	}

	txMemo := make([]byte, 4+len(transferTxMsgTemplate.TxMemo))
	binary.BigEndian.PutUint32(txMemo, transferTxMsgTemplate.Version)
	copy(txMemo[4:], transferTxMsgTemplate.TxMemo)

	if abecrypto.GetCryptoScheme(transferTxMsgTemplate.Version) == abecrypto.CryptoSchemePQRINGCT {
		cryptoTransferTx, err := cryptoPP.TransferTxGen(txInputDescs, txOutputDescs, transferTxMsgTemplate.TxFee, txMemo)
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
			transferTxMsgTemplate.TxOuts[j] = &wire.TxOutAbe{
				transferTxMsgTemplate.Version,
				cryptoTransferTx.OutputTxos[j].Serialize(),
			}
		}

		//	Set the TxWitness
		transferTxMsgTemplate.TxWitness = cryptoTransferTx.TxWitness.Serialize()

		return transferTxMsgTemplate, nil
	} else if false {
		//	todo: if there is more versions, implement it here
	}

	return nil, nil
}

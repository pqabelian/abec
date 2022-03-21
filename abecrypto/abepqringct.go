package abecrypto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"github.com/cryptosuite/pqringct"
)

//// abecrypto -> abepqringct -> pqringct
//type AbeTxOutDescNew struct {
//	serializedApk []byte // receive
//	serializedVpk []byte // conceal
//	value         uint64 // truely
//}
//
//func NewAbeTxOutDescNew(serializedApk []byte, serializedVpk []byte, value uint64) *AbeTxOutDescNew {
//	return &AbeTxOutDescNew{
//		serializedApk,
//		serializedVpk,
//		value,
//	}
//}

//func (txOutDesc *AbeTxOutDescNew) GetValue() uint64 {
//	return txOutDesc.value
//}

//type AbeTxInputDescNew struct {
//	serializedTxoList []*wire.TxOutAbe
//	txoLdgIDList      [][]byte
//	sidx              int
//	serializedASK     []byte
//	serializedVPK     []byte
//	serializedVSK     []byte
//	value             uint64
//
//	ringHash chainhash.Hash
//}
//
//func NewAbeTxInputDescNew(serializedTxoList []*wire.TxOutAbe, txoLdgIDList [][]byte,
//	sidx int, serializedASK []byte, serializedVPK []byte,
//	serializedVSK []byte, value uint64, ringHash chainhash.Hash) *AbeTxInputDescNew {
//	return &AbeTxInputDescNew{
//		serializedTxoList,
//		txoLdgIDList,
//		sidx,
//		serializedASK,
//		serializedVPK,
//		serializedVSK,
//		value,
//		ringHash,
//	}
//}
//
//type AbeTxInDetailNew struct {
//	serializedTxoList []*wire.TxOutAbe
//	ringHash          chainhash.Hash
//	index             int
//	serialNumber      []byte
//}
//
//func NewAbeTxInDetailNew(serializedTxoList []*wire.TxOutAbe, ringHash chainhash.Hash, index int, serialNumber []byte) *AbeTxInDetailNew {
//	return &AbeTxInDetailNew{
//		serializedTxoList,
//		ringHash,
//		index,
//		serialNumber,
//	}
//}
func CryptoAddressGen(pp *pqringct.PublicParameter, seed []byte) (serializedAddress []byte, serializedVSk []byte, serializedASksp []byte, serializedASksn []byte, err error) {
	if 2*pp.ParamSeedBytesLen() != len(seed) {
		return nil, nil, nil, nil, errors.New("invalid length of seed")
	}
	var serializedAPk []byte
	serializedAPk, serializedASksp, serializedASksn, err = addressKeyGen(pp, seed)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	serializedAddress = append(serializedAddress, serializedAPk...)
	var serializedVPk []byte
	serializedVPk, serializedVSk, err = valueKeyGen(pp, seed)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	serializedAddress = append(serializedAddress, serializedVPk...)
	return serializedAddress, serializedVSk, serializedASksp, serializedASksn, nil
}

func valueKeyGen(pp *pqringct.PublicParameter, seed []byte) (serializedVPk []byte, serializedVSksn []byte, serializedVSksp []byte, err error) {
	if seed == nil || len(seed) != pp.ParamSeedBytesLen() {
		return nil, nil, nil, errors.New("invalid length of seed")
	}
	return pqringct.ValueKeyGen(pp, seed)
}

// AddressKeyGen generate the address key pair for pqringct
func addressKeyGen(pp *pqringct.PublicParameter, seed []byte) (serializedAPk []byte, serializedASk []byte, err error) {
	if seed == nil || len(seed) != pp.ParamSeedBytesLen() {
		return nil, nil, errors.New("invalid length of seed")
	}
	return pqringct.AddressKeyGen(pp, seed)
}

/*
The caller needs to fill the Version, TxIns, TxFee fileds for coinbaseTxMsgTemplate,
this fucntion will fill the TxOuts and TxWitness fields.
The TxMemo filed could be modified as needed, as the TxWitness does not depends on the TxMemo.
*/
func CoinbaseTxGen(pp *pqringct.PublicParameter, abeTxOutDescs []*AbeTxOutDesc, coinbaseTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	//	pqringct
	txOutputDescs := make([]*pqringct.TxOutputDescv2, len(abeTxOutDescs))
	for j := 0; j < len(abeTxOutDescs); j++ {
		// TODO(20220320): parse the address to serializedApk and serializedVpk
		pp.GetAddressPublicKeySerializeSize()
		pp.GetValuePublicKeySerializeSize()
		serializedApk, serializedVpk := abeTxOutDescs[j].address[:], abeTxOutDescs[j].address[:]
		txOutputDescs[j] = pqringct.NewTxOutputDescv2(serializedApk, serializedVpk, abeTxOutDescs[j].value)
	}
	// call the pqringct.CoinbaseTxGen
	cryptoCoinbaseTx, err := pqringct.CoinbaseTxGen(pp, coinbaseTxMsgTemplate.TxFee, txOutputDescs)
	if err != nil {
		return nil, err
	}
	// TODO(20220320): parse the pqringct.CoinbaseTx to wire.TxAbe
	coinbaseTxMsgTemplate.TxOuts = make([]*wire.TxOutAbe, len(cryptoCoinbaseTx.OutputTxos))
	for i := 0; i < len(cryptoCoinbaseTx.OutputTxos); i++ {
		w := bytes.NewBuffer(make([]byte, 0, 100000))
		err := cryptoCoinbaseTx.OutputTxos[i].Serialize0(w)
		if err != nil {
			return nil, err
		}
		coinbaseTxMsgTemplate.TxOuts[i] = &wire.TxOutAbe{
			coinbaseTxMsgTemplate.Version,
			w.Bytes(),
		}
	}
	w := bytes.NewBuffer(make([]byte, 0, 100000))
	err = cryptoCoinbaseTx.TxWitness.Serialize0(w)
	if err != nil {
		return nil, err
	}
	coinbaseTxMsgTemplate.TxWitness = w.Bytes()
	return coinbaseTxMsgTemplate, nil
}

/*
The caller needs to guarantee the well-form of the input coinbaseTx *wire.MsgTxAbe, such as the TxIns.
This function only checks the balance proof, by calling the crypto-scheme.
*/
func CoinbaseTxVerify(pp *pqringct.PublicParameter, coinbaseTx *wire.MsgTxAbe) bool {
	if coinbaseTx == nil {
		return false
	}
	if len(coinbaseTx.TxOuts) <= 0 {
		return false
	}
	cryptoCoinbaseTx := &pqringct.CoinbaseTxv2{}
	cryptoCoinbaseTx.Vin = coinbaseTx.TxFee
	cryptoCoinbaseTx.TxWitness = &pqringct.CbTxWitnessv2{}
	reader := bytes.NewReader(coinbaseTx.TxWitness)
	err := cryptoCoinbaseTx.TxWitness.Deserialize(reader)
	if err != nil {
		return false
	}
	cryptoCoinbaseTx.OutputTxos = make([]*pqringct.Txo, len(coinbaseTx.TxOuts))
	for i := 0; i < len(coinbaseTx.TxOuts); i++ {
		if coinbaseTx.TxOuts[i].Version != coinbaseTx.Version {
			return false
		}
		txo := &pqringct.Txo{}
		reader = bytes.NewReader(coinbaseTx.TxOuts[i].TxoScript)
		err = txo.Deserialize(reader)
		if err != nil {
			return false
		}
		cryptoCoinbaseTx.OutputTxos[i] = txo
	}
	bl := pqringct.CoinbaseTxVerify(pp, cryptoCoinbaseTx)
	if bl == false {
		return false
	}

	return false
}

/*
The caller needs to fill the Version, TxIns, TxFee, TxMemo fields of transferTxMsgTemplate
This function will fill the serialNumbers in TxIns, and the TxOuts and TxWitness fields of transferTxMsgTemplate, and return it as the result
*/
func TransferTxGen(pp *pqringct.PublicParameter, abeTxInputDescs []*AbeTxInputDesc, abeTxOutputDescs []*AbeTxOutDesc, transferTxMsgTemplate *wire.MsgTxAbe) (*wire.MsgTxAbe, error) {
	inputNum := len(abeTxInputDescs)
	outputNum := len(abeTxOutputDescs)

	if inputNum <= 0 || outputNum <= 0 {
		return nil, errors.New("the input number and the output number should be at least 1")
	}

	//if inputNum > pqringctparam.GetInputMaxNum(transferTxMsgTemplate.Version) {
	//	return nil, fmt.Errorf("the input number %d exceeds the allowed max number %d", inputNum, pqringctparam.GetInputMaxNum(transferTxMsgTemplate.Version))
	//}
	//
	//if outputNum > pqringctparam.GetOutputMaxNum(transferTxMsgTemplate.Version) {
	//	return nil, fmt.Errorf("the output number %d exceeds the allowed max number %d", outputNum, pqringctparam.GetOutputMaxNum(transferTxMsgTemplate.Version))
	//}

	if inputNum != len(transferTxMsgTemplate.TxIns) {
		return nil, errors.New("the number of InputDesc does not match the number of TxIn in transferTxMsgTemplate")
	}

	inputsVersion := transferTxMsgTemplate.TxIns[0].PreviousOutPointRing.Version
	//outputsVersion := transferTxMsgTemplate.Version

	//	inputDescs
	txInputDescs := make([]*pqringct.TxInputDescv2, inputNum)
	for i := 0; i < inputNum; i++ {
		if transferTxMsgTemplate.TxIns[i].PreviousOutPointRing.Version != inputsVersion {
			return nil, errors.New("the version of the TxIn in one transaction should be the same")
		}

		txoList := make([]*pqringct.LgrTxo, len(abeTxInputDescs[i].txoList))
		for j := 0; j < len(abeTxInputDescs[i].txoList); j++ {
			if abeTxInputDescs[i].txoList[j].Version != inputsVersion {
				return nil, errors.New("the version of TXOs in abeTxInputDescs.serializedTxoList does not match the version in the corresponding TxIn")
			}
			reader := bytes.NewReader(abeTxInputDescs[i].txoList[j].TxoScript)
			err := txoList[j].Txo.Deserialize(reader)
			if err != nil {
				return nil, err
			}
			txoList[j].Id = LedgerTxoIdGen(abeTxInputDescs[i].ringHash, abeTxInputDescs[i].sidx)
		}

		sidx := abeTxInputDescs[i].sidx
		// TODO(20220320): compute the value from txo[sidx] with vsk
		value := uint64(0)
		// TODO(20220320): parse the serializedSk to serialized serializedASk, serializedVSk, serialziedVPk
		serializedASk, serializedVSk, serializedVPk := abeTxInputDescs[i].serializedSk[:], abeTxInputDescs[i].serializedSk[:], abeTxInputDescs[i].serializedSk[:]
		txInputDescs[i] = pqringct.NewTxInputDescv2(txoList, sidx, serializedASk, serializedVPk, serializedVSk, value)
	}

	// outputDescs
	txOutputDescs := make([]*pqringct.TxOutputDescv2, outputNum)
	for j := 0; j < outputNum; j++ {
		// TODO(20220320): parse the address to serializedApk and serializedVpk
		serializedApk, serializedVpk := abeTxOutputDescs[j].address[:], abeTxOutputDescs[j].address[:]
		txOutputDescs[j] = pqringct.NewTxOutputDescv2(serializedApk, serializedVpk, abeTxOutputDescs[j].value)
	}

	txMemo := make([]byte, 4+len(transferTxMsgTemplate.TxMemo))
	binary.BigEndian.PutUint32(txMemo, transferTxMsgTemplate.Version)
	copy(txMemo[4:], transferTxMsgTemplate.TxMemo)

	//	call the crypto scheme
	cryptoTransferTx, err := pp.TransferTxGen(txInputDescs, txOutputDescs, transferTxMsgTemplate.TxFee, txMemo)
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
		w := bytes.NewBuffer(make([]byte, 0, 10000))
		err = cryptoTransferTx.OutputTxos[j].Serialize0(w)
		if err != nil {
			return nil, err
		}
		transferTxMsgTemplate.TxOuts[j] = &wire.TxOutAbe{
			transferTxMsgTemplate.Version,
			w.Bytes(),
		}
	}

	//	Set the TxWitness
	w := bytes.NewBuffer(make([]byte, 0, 10000))
	err = cryptoTransferTx.TxWitness.Serialize0(w)
	if err != nil {
		return nil, err
	}
	transferTxMsgTemplate.TxWitness = w.Bytes()

	return transferTxMsgTemplate, nil

}

func TransferTxVerify(pp *pqringct.PublicParameter, transferTx *wire.MsgTxAbe, abeTxInDetails []*AbeTxInDetail) bool {
	if transferTx == nil {
		return false
	}

	inputNum := len(transferTx.TxIns)
	outputNum := len(transferTx.TxOuts)
	if inputNum <= 0 || outputNum <= 0 {
		return false
	}

	if len(abeTxInDetails) != inputNum {
		return false
	}

	inputsVersion := transferTx.TxIns[0].PreviousOutPointRing.Version
	outputsVersion := transferTx.Version

	cryptoTransferTx := &pqringct.TransferTxv2{}

	//	Inputs
	cryptoTransferTx.Inputs = make([]*pqringct.TrTxInputv2, inputNum)
	for i := 0; i < inputNum; i++ {
		if transferTx.TxIns[i].PreviousOutPointRing.Version != inputsVersion {
			return false
			//	This is necessary, since the same version will ensure that when calling the cryptoscheme, there are not exceptions.
		}
		if bytes.Compare(abeTxInDetails[i].serialNumber, transferTx.TxIns[i].SerialNumber) != 0 {
			return false
			//	This check can be removed, as the caller will provide abeTxInDetails, which are made by querying the database using the transferTx.TxIns information
		}

		txoList := make([]*pqringct.LgrTxo, len(abeTxInDetails[i].txoList))
		for j := 0; j < len(abeTxInDetails[i].txoList); j++ {
			if abeTxInDetails[i].txoList[j].Version != transferTx.TxIns[i].PreviousOutPointRing.Version {
				return false
				//	The Txos in the same ring should have the same version
			}
			txoList[j] = &pqringct.LgrTxo{
				Txo: pqringct.Txo{},
				Id:  nil,
			}
			reader := bytes.NewReader(abeTxInDetails[i].txoList[j].TxoScript)
			err := txoList[j].Txo.Deserialize(reader)
			if err != nil {
				return false
			}
			// TODO(20220320): where is from "index"?
			index := 0
			txoList[j].Id = LedgerTxoIdGen(abeTxInDetails[i].ringHash, index)
		}
		cryptoTransferTx.Inputs[i] = &pqringct.TrTxInputv2{
			txoList,
			abeTxInDetails[i].serialNumber,
		}
	}

	//	OutputTxos
	cryptoTransferTx.OutputTxos = make([]*pqringct.Txo, outputNum)
	for j := 0; j < outputNum; j++ {
		if transferTx.TxOuts[j].Version != outputsVersion {
			return false
			//	The output Txos of a transaction should have the same version as the transaction.
		}

		cryptoTransferTx.OutputTxos[j] = &pqringct.Txo{}
		reader := bytes.NewReader(transferTx.TxOuts[j].TxoScript)
		err := cryptoTransferTx.OutputTxos[j].Deserialize(reader)
		if err != nil {
			return false
		}
	}

	//	Fee
	cryptoTransferTx.Fee = transferTx.TxFee

	//	TxMemo
	cryptoTransferTx.TxMemo = make([]byte, 4+len(transferTx.TxMemo))
	binary.BigEndian.PutUint32(cryptoTransferTx.TxMemo, transferTx.Version)
	copy(cryptoTransferTx.TxMemo[4:], transferTx.TxMemo)

	//	TxWitness
	cryptoTransferTx.TxWitness = &pqringct.TrTxWitnessv2{}
	reader := bytes.NewReader(transferTx.TxWitness)
	err := cryptoTransferTx.TxWitness.Deserialize(reader)
	if err != nil {
		return false
	}

	// call the crypto scheme's verify algroithm
	bl := pqringct.TransferTxVerify(pp, cryptoTransferTx)
	if bl == false {
		return false
	} else {
		return true
	}

}

// For wallet
func TxoSerialNumberGen(pp *pqringct.PublicParameter, txo *wire.TxOutAbe, ringHash chainhash.Hash, serializedSksn []byte) []byte {
	// ringHash + index -> ID
	//	// (ID+txo) + Sksn -> sn [pqringct]
	panic("TxoSerialNumberGen implement me")
	return nil
}
func TxoCoinReceive(pp *pqringct.PublicParameter, abeTxo *wire.TxOutAbe, address []byte, serializedSkvalue []byte) (valid bool, v uint64) {

	r := bytes.NewReader(abeTxo.TxoScript)
	txo, err := pp.ReadTxo(r)
	if err != nil {
		return false, 0
	}
	return pqringct.TxoCoinReceive(pp, txo, address, serializedSkvalue)
}
func (pp *AbeCryptoParam) GetTxoSerializeSize(version uint32) int {
	panic("GetTxoSerializeSize implement me")
	return -1
}
func (pp *AbeCryptoParam) GetCoinbaseTxWitnessLen(version uint32, num int) int {
	panic("GetCoinbaseTxWitnessLen implement me")
	return -1
}
func (pp *AbeCryptoParam) GetTxoSerialNumberLen(version uint32) int {
	panic("GetTxoSerialNumberLen implement me")
	return -1
}
func (pp *AbeCryptoParam) GetNullSerialNumber(version uint32) []byte {
	panic("GetNullSerialNumber implement me")
	return nil
}

func (pp *AbeCryptoParam) GetTxMemoMaxLen(version uint32) int {
	panic("GetNullSerialNumber implement me")
	return -1
}
func (pp *AbeCryptoParam) GetTxWitnessMaxLen(version uint32) int {
	panic("GetNullSerialNumber implement me")
	return -1
}
func (pp *AbeCryptoParam) GetTrTxWitnessSize(txVersion uint32, inputRingVersion uint32, inputRingSizes []int, outputTxoNum uint8) int {
	panic("GetNullSerialNumber implement me")
	return -1
}

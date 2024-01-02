package v1

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/blockchain"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"io"
)

// type OutPoint wire.OutPointAbe
//
//	As OutPointAbe use (TxHash, Index), here we use the more reasonable (TxId, Index)
//	In the future, we shall refactor OutPointAbe to (TxId, Index),
//	and here directly use "type OutPoint wire.OutPointAbe"
type OutPoint struct {
	TxId  *wire.TxId
	Index uint8

	outPointId *wire.OutPointId // cached OutPointId
}

func (outPoint *OutPoint) OutPointId() wire.OutPointId {
	if outPoint.outPointId == nil {
		// cache the outPointId

		opId := wire.OutPointId{}
		copy(opId[:], outPoint.TxId[:])
		opId[chainhash.HashSize] = outPoint.Index

		outPoint.outPointId = &opId
	}

	return *outPoint.outPointId
}

type TxRequestOutputDesc struct {
	cryptoAddress []byte // generated by CryptoAddressKeyGen
	value         uint64
}

type TxRequestInputDesc struct {
	ringId *wire.RingId // txoRing identifier
	//txoList []*wire.TxOutAbe
	txoRing *wire.TxoRing
	sidx    uint8 // spend which one
}

type TransferTxRequestDesc struct {
	TxRequestInputDescs  []*TxRequestInputDesc
	TxRequestOutputDescs []*TxRequestOutputDesc
	TxFee                uint64
	TxMemo               []byte
}

type CryptoKey struct {
	cryptoAddress []byte // address, generated by CryptoAddressKeyGen
	cryptoSpsk    []byte // spend secret key, generated by CryptoAddressKeyGen
	cryptoSnsk    []byte //  serial-number secret key, generated by CryptoAddressKeyGen
	cryptoVsk     []byte //  view secret key, generated by CryptoAddressKeyGen
}

// todo: user gets TxId by RPC? here we need to be consistent with RPC? say,
// being chainHash.Hash or string
type TxId wire.TxId

func (txId *TxId) String() string {
	wtxId := wire.TxId(*txId)
	return wtxId.String()
}

type TxoRingMember struct {
	ringId *wire.RingId // txoRing identifier
	//txoList []*wire.TxOutAbe
	txoRing *wire.TxoRing
	idx     uint8 // member index in ring
}

// NewOutPointFromTxIdStr assumes the input txIdStr was obtained by "(hash chainHash.Hash) String()" function
func NewOutPointFromTxIdStr(txIdStr string, index uint8) (*OutPoint, error) {
	txHash, err := chainhash.NewHashFromStr(txIdStr)
	if err != nil {
		return nil, err
	}

	txId := wire.TxId(*txHash)

	return &OutPoint{
		TxId:  &txId,
		Index: index,
	}, nil
}

func NewTxRequestOutputDesc(cryptoAddress []byte, value uint64) *TxRequestOutputDesc {
	return &TxRequestOutputDesc{
		cryptoAddress: cryptoAddress,
		value:         value,
	}
}

func NewCryptoKey(cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte, cryptoVsk []byte) *CryptoKey {
	return &CryptoKey{
		cryptoAddress: cryptoAddress,
		cryptoSpsk:    cryptoSpsk,
		cryptoSnsk:    cryptoSnsk,
		cryptoVsk:     cryptoVsk,
	}
}

func (txRequestInputDesc *TxRequestInputDesc) serializeSize() int {
	n := 0

	//	ringId
	n += chainhash.HashSize

	////	txoList
	//ringSize := len(txRequestInputDesc.txoList)
	//n += VarIntSerializeSize(uint64(ringSize))
	//for i := 0; i < ringSize; i++ {
	//	n += txRequestInputDesc.txoList[i].SerializeSize()
	//}

	//	txoRing
	n += txRequestInputDesc.txoRing.SerializeSize()

	// sidx
	n += 1

	return n
}

func writeTxRequestInputDesc(w io.Writer, txRequestInputDesc *TxRequestInputDesc) error {
	//	ringId
	_, err := w.Write(txRequestInputDesc.ringId[:])
	if err != nil {
		return err
	}

	////	txoList
	//err = WriteVarInt(w, uint64(len(txRequestInputDesc.txoList)))
	//if err != nil {
	//	return err
	//}
	//for _, txOut := range txRequestInputDesc.txoList {
	//	err = wire.WriteTxOutAbe(w, 0, txOut.Version, txOut)
	//	if err != nil {
	//		return err
	//	}
	//}

	//	txoRing
	err = txRequestInputDesc.txoRing.Serialize(w)
	if err != nil {
		return err
	}

	//	sidx
	err = binarySerializer.PutUint8(w, txRequestInputDesc.sidx)
	if err != nil {
		return err
	}

	return nil
}

func readTxRequestInputDesc(r io.Reader, txRequestInputDesc *TxRequestInputDesc) error {
	//	ringId
	ringId := wire.RingId{}
	_, err := io.ReadFull(r, ringId[:])
	if err != nil {
		return err
	}

	//// TxOuts
	//txoNum, err := ReadVarInt(r)
	//if err != nil {
	//	return err
	//}
	//txoList := make([]*wire.TxOutAbe, txoNum)
	//for i := uint64(0); i < txoNum; i++ {
	//	txOut := wire.TxOutAbe{}
	//	err = wire.ReadTxOutAbe(r, 0, 0, &txOut)
	//	if err != nil {
	//		return err
	//	}
	//	txoList[i] = &txOut
	//}

	//	txoRing
	txoRing := &wire.TxoRing{}
	err = txoRing.Deserialize(r)
	if err != nil {
		return err
	}

	// sidx
	sidx, err := binarySerializer.Uint8(r)
	if err != nil {
		return err
	}

	txRequestInputDesc.ringId = &ringId
	txRequestInputDesc.txoRing = txoRing
	txRequestInputDesc.sidx = sidx

	return nil
}

func (txRequestOutputDesc *TxRequestOutputDesc) serializeSize() int {
	n := 0
	//	cryptoAddress
	cryptoAddressLen := len(txRequestOutputDesc.cryptoAddress)
	n += VarIntSerializeSize(uint64(cryptoAddressLen)) + cryptoAddressLen

	//	value
	n += VarIntSerializeSize(txRequestOutputDesc.value)

	return n
}

func writeTxRequestOutputDesc(w io.Writer, txRequestOutputDesc *TxRequestOutputDesc) error {

	//	cryptoAddress
	err := WriteVarBytes(w, txRequestOutputDesc.cryptoAddress)
	if err != nil {
		return err
	}

	//	value
	err = WriteVarInt(w, txRequestOutputDesc.value)
	if err != nil {
		return err
	}

	return nil
}

func readTxRequestOutputDesc(r io.Reader, txRequestOutputDesc *TxRequestOutputDesc) error {

	//	cryptoAddress
	cryptoAddress, err := ReadVarBytes(r, abecrypto.GetCryptoAddressSerializeSizeMax(), "TxRequestOutputDesc.CryptoAddress")
	if err != nil {
		return err
	}

	//	value
	value, err := ReadVarInt(r)
	if err != nil {
		return err
	}

	txRequestOutputDesc.cryptoAddress = cryptoAddress
	txRequestOutputDesc.value = value

	return nil
}

func (txRequestDesc *TransferTxRequestDesc) serializeSize() int {
	n := 0

	//	TxRequestInputDescs
	inputNum := len(txRequestDesc.TxRequestInputDescs)
	n += VarIntSerializeSize(uint64(inputNum))
	for i := 0; i < inputNum; i++ {
		n += txRequestDesc.TxRequestInputDescs[i].serializeSize()
	}

	//  TxRequestOutputDescs
	outputNum := len(txRequestDesc.TxRequestOutputDescs)
	n += VarIntSerializeSize(uint64(outputNum))
	for i := 0; i < outputNum; i++ {
		n += txRequestDesc.TxRequestOutputDescs[i].serializeSize()
	}

	//	TxFee
	n += VarIntSerializeSize(txRequestDesc.TxFee)

	//	TxMemo
	memoLen := len(txRequestDesc.TxMemo)
	n += VarIntSerializeSize(uint64(memoLen)) + memoLen

	return n
}

func serializeTransferTxRequestDesc(txRequestDesc *TransferTxRequestDesc) ([]byte, error) {
	if txRequestDesc == nil {
		return nil, errors.New("serializeTransferTxRequestDesc: input txRequestDesc is nil")
	}

	w := bytes.NewBuffer(make([]byte, 0, txRequestDesc.serializeSize()))

	//	TxRequestInputDescs
	inputNum := len(txRequestDesc.TxRequestInputDescs)
	err := WriteVarInt(w, uint64(inputNum))
	if err != nil {
		return nil, err
	}
	for i := 0; i < inputNum; i++ {
		err = writeTxRequestInputDesc(w, txRequestDesc.TxRequestInputDescs[i])
		if err != nil {
			return nil, err
		}
	}

	//  TxRequestOutputDescs
	outputNum := len(txRequestDesc.TxRequestOutputDescs)
	err = WriteVarInt(w, uint64(outputNum))
	for i := 0; i < outputNum; i++ {
		err = writeTxRequestOutputDesc(w, txRequestDesc.TxRequestOutputDescs[i])
		if err != nil {
			return nil, err
		}
	}

	//	TxFee
	err = WriteVarInt(w, txRequestDesc.TxFee)
	if err != nil {
		return nil, err
	}

	//	TxMemo
	err = WriteVarBytes(w, txRequestDesc.TxMemo)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func deserializeTransferTxRequestDesc(serializedTxRequestDesc []byte) (*TransferTxRequestDesc, error) {
	var err error
	var count uint64

	r := bytes.NewReader(serializedTxRequestDesc)

	// Inputs     []*TxRequestInputDesc
	var Inputs []*TxRequestInputDesc
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		Inputs = make([]*TxRequestInputDesc, count)
		for i := uint64(0); i < count; i++ {
			txRequestInputDesc := TxRequestInputDesc{}
			err = readTxRequestInputDesc(r, &txRequestInputDesc)
			if err != nil {
				return nil, err
			}
			Inputs[i] = &txRequestInputDesc
		}
	} else {
		Inputs = nil
	}

	// Outputs []*TxRequestOutputDesc
	var Outputs []*TxRequestOutputDesc
	count, err = ReadVarInt(r)
	if err != nil {
		return nil, err
	}
	if count != 0 {
		Outputs = make([]*TxRequestOutputDesc, count)
		for i := uint64(0); i < count; i++ {
			Outputs[i] = &TxRequestOutputDesc{}
			err = readTxRequestOutputDesc(r, Outputs[i])
			if err != nil {
				return nil, err
			}
		}
	} else {
		Outputs = nil
	}

	// Fee        uint64
	TxFee, err := ReadVarInt(r)
	if err != nil {
		return nil, err
	}

	// TxMemo []byte
	TxMemo, err := ReadVarBytes(r, abecryptoparam.MaxAllowedTxMemoSize, "TransferTxRequestDesc.TxMemo")
	if err != nil {
		return nil, err
	}

	return &TransferTxRequestDesc{
		TxRequestInputDescs:  Inputs,
		TxRequestOutputDescs: Outputs,
		TxFee:                TxFee,
		TxMemo:               TxMemo,
	}, nil
}

func BuildTransferTxRequestDescFromTxoRings(
	outPointsToSpend []*OutPoint,
	serializedTxoRings [][]byte,
	txRequestOutputDescs []*TxRequestOutputDesc,
	txFee uint64,
	txMemo []byte,
) (serializedTxRequestDesc []byte, err error) {
	inputNum := len(outPointsToSpend)
	if inputNum == 0 {
		return nil, errors.New("BuildTransferTxRequestDesc: input outPointsToSpend is empty")
	}

	if len(serializedTxoRings) != inputNum {
		return nil, errors.New("BuildTransferTxRequestDesc: input outPointsToSpend's number is unmatched with txo ring")
	}

	outputNum := len(txRequestOutputDescs)
	if outputNum == 0 {
		return nil, errors.New("BuildTransferTxRequestDesc: input txRequestOutputDescs is empty")
	}

	// assembly input and check its sanctity
	txRequestInputDescs := make([]*TxRequestInputDesc, inputNum)
	seenTxInOutpoints := make(map[wire.OutPointId]*TxRequestInputDesc, inputNum)
	for i := 0; i < inputNum; i++ {
		txRequestInputDescs[i] = &TxRequestInputDesc{ringId: nil}
		// this nil will be used to check whether the corresponding TxoRing

		opId := outPointsToSpend[i].OutPointId()
		if _, ok := seenTxInOutpoints[opId]; ok {
			return nil, errors.New("BuildTransferTxRequestDesc: outPointsToSpend contains repeated OutPoint")
		}
		seenTxInOutpoints[opId] = txRequestInputDescs[i]
	}

	txoRings := make([]*wire.TxoRing, inputNum)
	for i := 0; i < len(serializedTxoRings); i++ {
		txoRings[i] = &wire.TxoRing{}
		err = txoRings[i].Deserialize(bytes.NewReader(serializedTxoRings[i]))
		if err != nil {
			return nil, err
		}
		ringId := txoRings[i].RingId()
		matched := false
		for opIndex, outPoint := range txoRings[i].OutPointRing.OutPoints {
			opId := outPoint.OutPointId()
			txRequestInputDesc, ok := seenTxInOutpoints[opId]
			if !ok {
				continue
			}
			matched = true
			//	the outPoint is one of the outPointsToSpend
			if txRequestInputDesc.ringId != nil {
				// It has been set previously
				return nil, errors.New("BuildTransferTxRequestDesc: there are repeated OutPoint (TxId, Index) in the rings")
			}

			seenTxInOutpoints[opId].ringId = &wire.RingId{}
			copy(seenTxInOutpoints[opId].ringId[:], ringId[:])
			seenTxInOutpoints[opId].txoRing = txoRings[i]
			seenTxInOutpoints[opId].sidx = uint8(opIndex) //	The Ring Rule will makes sure opIndex is in the scope of uint8
		}
		if !matched {
			return nil, errors.New("BuildTransferTxRequestDesc: there is unmatched OutPoint (TxId, Index) and txoRing")
		}
	}

	//	check whether all outPoint has been matched the corresponding TxoRing
	for i := 0; i < inputNum; i++ {
		if txRequestInputDescs[i].ringId == nil {
			return nil, errors.New("BuildTransferTxRequestDesc: at least one of the input OutPoing can not find the corresponding TxoRing")
		}
	}

	trTxRequestDesc := &TransferTxRequestDesc{
		TxRequestInputDescs:  txRequestInputDescs,
		TxRequestOutputDescs: txRequestOutputDescs,
		TxFee:                txFee,
		TxMemo:               txMemo,
	}

	serializedTxRequestDesc, err = serializeTransferTxRequestDesc(trTxRequestDesc)
	if err != nil {
		return nil, err
	}

	return serializedTxRequestDesc, nil

}

// BuildTransferTxRequestDescFromBlocks build from
// 1. some input specified by outPointToSpend, the relevant txo ring would be included in blocks specified by serializedBlocksForRingGroup
// 2. some output specified by txRequestOutputDescs,
// 3. transaction fee specified by txFee,
// 4. transaction memo specified by txMemo
func BuildTransferTxRequestDescFromBlocks(
	outPointsToSpend []*OutPoint,
	serializedBlocksForRingGroup [][]byte,
	txRequestOutputDescs []*TxRequestOutputDesc,
	txFee uint64,
	txMemo []byte,
) (serializedTxRequestDesc []byte, err error) {
	inputNum := len(outPointsToSpend)
	if inputNum == 0 {
		return nil, errors.New("BuildTransferTxRequestDesc: input outPointsToSpend is empty")
	}

	outputNum := len(txRequestOutputDescs)
	if outputNum == 0 {
		return nil, errors.New("BuildTransferTxRequestDesc: input txRequestOutputDescs is empty")
	}
	cryptoAddressMaxSize := abecrypto.GetCryptoAddressSerializeSizeMax()
	for i := 0; i < outputNum; i++ {
		if uint32(len(txRequestOutputDescs[i].cryptoAddress)) > cryptoAddressMaxSize {
			return nil, errors.New("BuildTransferTxRequestDesc: crypto address in txRequestOutputDescs is wrong size")
		}
	}

	blockNum := len(serializedBlocksForRingGroup)

	if blockNum == 0 {
		return nil, errors.New("BuildTransferTxRequestDesc: input serializedBlocksForRingGroup is empty")
	}

	blocks := make([]*abeutil.BlockAbe, blockNum)
	for i := 0; i < blockNum; i++ {
		// todo: to confirm
		//	For example, in the function, blockNoWitness is used.
		//	We need to clarify these functions.
		blocks[i], err = abeutil.NewBlockFromBytesAbe(serializedBlocksForRingGroup[i])
		if err != nil {
			return nil, err
		}

		//	assume the blocks are valid blocks in ledger, include:
		// (1) the Header contains its height. Based on this, we explicitly set the height of Block.
		height := blocks[i].MsgBlock().Header.Height
		if height == 0 {
			height, err = wire.ExtractCoinbaseHeight(blocks[i].MsgBlock().Transactions[0])
			if err != nil {
				return nil, err
			}
		}
		blocks[i].SetHeight(height)
	}

	blockIdx := 0
	for blockIdx < blockNum {
		// According to the first block the identity the version and txo ring size rule
		startBlockHeight := blocks[blockIdx].Height()
		blockNumPerRingGroup := wire.GetBlockNumPerRingGroupByBlockHeight(startBlockHeight)
		ringSize := wire.GetTxoRingSizeByBlockHeight(startBlockHeight)

		if startBlockHeight%int32(blockNumPerRingGroup) != 0 {
			return nil, errors.New("GenerateCoinSerialNumber: the blocks in input serializedBlocksForRingGroup cannot be divided into groups accurately")
		}

		if blockIdx+int(blockNumPerRingGroup)-1 >= blockNum {
			return nil, errors.New("GenerateCoinSerialNumber: the blocks in input serializedBlocksForRingGroup cannot be divided into groups completely")
		}

		for i := 0; i < int(blockNumPerRingGroup); i++ {
			height := blocks[blockIdx+i].Height()
			if height != startBlockHeight+int32(i) {
				return nil, errors.New("BuildTransferTxRequestDesc: the heights of input serializedBlocksForRingGroup are not successive")
			}

			if wire.GetBlockNumPerRingGroupByBlockHeight(height) != blockNumPerRingGroup {
				return nil, errors.New("BuildTransferTxRequestDesc: input serializedBlocksForRingGroup imply different blockNumPerRingGroup")
			}

			if wire.GetTxoRingSizeByBlockHeight(height) != ringSize {
				return nil, errors.New("BuildTransferTxRequestDesc: input serializedBlocksForRingGroup imply different RingSize")
			}
		}
		blockIdx += int(blockNumPerRingGroup)
	}

	txRequestInputDescs := make([]*TxRequestInputDesc, inputNum)

	outPointToTxRequestInputDescMap := make(map[wire.OutPointId]*TxRequestInputDesc, inputNum)
	for i := 0; i < inputNum; i++ {
		txRequestInputDescs[i] = &TxRequestInputDesc{ringId: nil}
		// this nil will be used to check whether the corresponding TxoRing

		opId := outPointsToSpend[i].OutPointId()
		if _, ok := outPointToTxRequestInputDescMap[opId]; ok {
			return nil, errors.New("BuildTransferTxRequestDesc: outPointsToSpend contains repeated OutPoint")
		} else {
			outPointToTxRequestInputDescMap[opId] = txRequestInputDescs[i]
			//	later txRequestInputDescs[i] will be fetched from the map, then be set and put back
		}
	}

	blockIdx = 0
	for blockIdx < blockNum {
		// According to the first block the identity the version and txo ring size rule
		startBlockHeight := blocks[blockIdx].Height()
		blockNumPerRingGroup := wire.GetBlockNumPerRingGroupByBlockHeight(startBlockHeight)
		ringSize := wire.GetTxoRingSizeByBlockHeight(startBlockHeight)

		txoRings, err := blockchain.BuildTxoRings(int(blockNumPerRingGroup), int(ringSize), blocks[blockIdx:blockIdx+int(blockNumPerRingGroup)])
		if err != nil {
			return nil, err
		}

		for ringId, txoRing := range txoRings {
			for opIndex, outPoint := range txoRing.OutPointRing.OutPoints {
				opId := outPoint.OutPointId()
				if txRequestInputDesc, ok := outPointToTxRequestInputDescMap[opId]; ok {
					//	the outPoint is one of the outPointsToSpend
					if txRequestInputDesc.ringId != nil {
						// It has been set previously
						return nil, fmt.Errorf("BuildTransferTxRequestDesc: there are repeated OutPoint (%s, %d) in the rings",
							txRequestInputDesc.txoRing.OutPointRing.OutPoints[txRequestInputDesc.sidx].TxHash,
							txRequestInputDesc.txoRing.OutPointRing.OutPoints[txRequestInputDesc.sidx].Index,
						)
					}

					outPointToTxRequestInputDescMap[opId].ringId = &wire.RingId{}
					copy(outPointToTxRequestInputDescMap[opId].ringId[:], ringId[:])
					outPointToTxRequestInputDescMap[opId].txoRing = txoRing
					outPointToTxRequestInputDescMap[opId].sidx = uint8(opIndex) //	The Ring Rule will makes sure opIndex is in the scope of uint8
				}
			}
		}

		blockIdx += int(blockNumPerRingGroup)
	}

	//	check whether all outPoint has found the corresponding TxoRing
	for i := 0; i < inputNum; i++ {
		if txRequestInputDescs[i].ringId == nil {
			return nil, fmt.Errorf("BuildTransferTxRequestDesc: at least one of the input OutPoing such as OutPoint[%d] = (%s,%d) can not find the corresponding TxoRing",
				i,
				chainhash.Hash(*outPointsToSpend[i].TxId).String(),
				outPointsToSpend[i].Index,
			)
		}
	}

	trTxRequestDesc := &TransferTxRequestDesc{
		TxRequestInputDescs:  txRequestInputDescs,
		TxRequestOutputDescs: txRequestOutputDescs,
		TxFee:                txFee,
		TxMemo:               txMemo,
	}

	serializedTxRequestDesc, err = serializeTransferTxRequestDesc(trTxRequestDesc)
	if err != nil {
		return nil, err
	}

	return serializedTxRequestDesc, nil
}

//	todo(MLP): todo
//
// CreateTransferTx would use the result called by BuildTransferTxRequestDescFromBlocks or BuildTransferTxRequestDescFromTxoRings as the unsigned transaction
// and the cryptoKeys should be matched in order for the input in unsigned transaction
func CreateTransferTx(serializedTransferTxRequestDesc []byte, cryptoKeys []*CryptoKey) (serializedTxFull []byte, txId *TxId, err error) {
	txRequestDesc, err := deserializeTransferTxRequestDesc(serializedTransferTxRequestDesc)
	if err != nil {
		return nil, nil, err
	}

	// abeTxInputDescs []*AbeTxInputDesc
	//	sanity checks
	inputNum := len(txRequestDesc.TxRequestInputDescs)
	if inputNum != len(cryptoKeys) {
		return nil, nil, errors.New("GenerateTransferTx: the number of input keys does not mathc the number of TransferTxRequestDesc's inputs")
	}

	abeTxInputDescs := make([]*abecrypto.AbeTxInputDesc, inputNum)
	for i := 0; i < inputNum; i++ {
		txRequestInputDesc := txRequestDesc.TxRequestInputDescs[i]
		cryptoKey := cryptoKeys[i]

		//	key validity check
		if valid, hints := abecrypto.VerifyCryptoAddressKey(cryptoKey.cryptoAddress, cryptoKey.cryptoSpsk, cryptoKey.cryptoSnsk, cryptoKey.cryptoVsk); !valid {
			return nil, nil, errors.New(hints)
		}

		copyedVskBytes := make([]byte, len(cryptoKey.cryptoVsk))
		copy(copyedVskBytes, cryptoKey.cryptoVsk)
		ok, value, err := abecrypto.TxoCoinReceive(txRequestInputDesc.txoRing.TxOuts[txRequestInputDesc.sidx], cryptoKey.cryptoAddress, copyedVskBytes)
		if err != nil {
			return nil, nil, err
		}
		if !ok {
			errStr := fmt.Sprintf("the %d -th cryptoKey cannot extract coin-value from the corresponding TxRequestInputDesc", i)
			return nil, nil, errors.New(errStr)
		}

		abeTxInputDescs[i] = abecrypto.NewAbeTxInputDescWithFullRing(
			txRequestInputDesc.ringId,
			txRequestInputDesc.txoRing,
			txRequestInputDesc.sidx,
			cryptoKey.cryptoAddress,
			cryptoKey.cryptoSpsk,
			cryptoKey.cryptoSnsk,
			cryptoKey.cryptoVsk,
			value, // amount in txo as input
		)
	}

	//	abeTxOutputDescs []*AbeTxOutputDesc
	outputNum := len(txRequestDesc.TxRequestOutputDescs)
	abeTxOutputDescs := make([]*abecrypto.AbeTxOutputDesc, outputNum)
	for i := 0; i < outputNum; i++ {
		txRequestOutputDesc := txRequestDesc.TxRequestOutputDescs[i]
		abeTxOutputDescs[i] = abecrypto.NewAbeTxOutDesc(txRequestOutputDesc.cryptoAddress, txRequestOutputDesc.value)
	}

	transferTxMsgTemplate, err := abecrypto.CreateTransferTxMsgTemplate(abeTxInputDescs, abeTxOutputDescs, txRequestDesc.TxFee, txRequestDesc.TxMemo)
	if err != nil {
		return nil, nil, err
	}

	transferTxMsg, err := abecrypto.TransferTxGen(abeTxInputDescs, abeTxOutputDescs, transferTxMsgTemplate)
	if err != nil {
		return nil, nil, err
	}

	buf := bytes.NewBuffer(make([]byte, 0, transferTxMsg.SerializeSizeFull()))
	err = transferTxMsg.SerializeFull(buf)
	if err != nil {
		return nil, nil, err
	}

	trTxId := TxId(transferTxMsg.TxId())

	return buf.Bytes(), &trTxId, nil
}

func GenerateCoinSerialNumber(
	outPoints []*OutPoint,
	serializedBlocksForRingGroup [][]byte,
	cryptoKeys []*CryptoKey) (serialNumbers [][]byte, err error) {

	coinNum := len(outPoints)
	if coinNum == 0 {
		return nil, errors.New("GenerateCoinSerialNumber: input outPoints is empty")
	}

	if coinNum != len(cryptoKeys) {
		return nil, errors.New("GenerateCoinSerialNumber: the number of input keys does not match the number of outPoints")
	}

	blockNum := len(serializedBlocksForRingGroup)

	if blockNum == 0 {
		return nil, errors.New("GenerateCoinSerialNumber: input serializedBlocksForRingGroup is empty")
	}

	blocks := make([]*abeutil.BlockAbe, blockNum)
	for i := 0; i < blockNum; i++ {
		// todo: to confirm
		//	For example, in the function, blockNoWitness is used.
		//	We need to clarify these functions.
		blocks[i], err = abeutil.NewBlockFromBytesAbe(serializedBlocksForRingGroup[i])
		if err != nil {
			return nil, err
		}

		//	assume the blocks are valid blocks in ledger, include:
		// (1) the Header contains its height. Based on this, we explicitly set the height of Block.
		blocks[i].SetHeight(blocks[i].MsgBlock().Header.Height)
	}

	// whether all block height is valid
	blockIdx := 0
	for blockIdx < blockNum {
		// According to the first block the identity the version and txo ring size rule
		startBlockHeight := blocks[blockIdx].Height()
		blockNumPerRingGroup := wire.GetBlockNumPerRingGroupByBlockHeight(startBlockHeight)
		ringSize := wire.GetTxoRingSizeByBlockHeight(startBlockHeight)

		if startBlockHeight%int32(blockNumPerRingGroup) != 0 {
			return nil, errors.New("GenerateCoinSerialNumber: the blocks in input serializedBlocksForRingGroup cannot be divided into groups accurately")
		}

		if blockIdx+int(blockNumPerRingGroup)-1 >= blockNum {
			return nil, errors.New("GenerateCoinSerialNumber: the blocks in input serializedBlocksForRingGroup cannot be divided into groups completely")
		}

		for i := 0; i < int(blockNumPerRingGroup); i++ {
			height := blocks[blockIdx+i].Height()
			if height != startBlockHeight+int32(i) {
				return nil, errors.New("GenerateCoinSerialNumber: the heights of input serializedBlocksForRingGroup are not successive")
			}

			if wire.GetBlockNumPerRingGroupByBlockHeight(height) != blockNumPerRingGroup {
				return nil, errors.New("GenerateCoinSerialNumber: input serializedBlocksForRingGroup imply different blockNumPerRingGroup")
			}

			if wire.GetTxoRingSizeByBlockHeight(height) != ringSize {
				return nil, errors.New("GenerateCoinSerialNumber: input serializedBlocksForRingGroup imply different RingSize")
			}
		}
		blockIdx += int(blockNumPerRingGroup)
	}

	txoRingMembers := make([]*TxoRingMember, coinNum)

	outPointToTxoRingMemberMap := make(map[wire.OutPointId]*TxoRingMember, coinNum)
	for i := 0; i < coinNum; i++ {
		txoRingMembers[i] = &TxoRingMember{ringId: nil}
		// this nil will be used to check whether the corresponding TxoRing

		opId := outPoints[i].OutPointId()
		if _, ok := outPointToTxoRingMemberMap[opId]; ok {
			return nil, errors.New("GenerateCoinSerialNumber: outPoints contains repeated OutPoint")
		} else {
			outPointToTxoRingMemberMap[opId] = txoRingMembers[i]
			//	later txoRingMembers[i] will be fetched from the map, then be set and put back
		}
	}

	blockIdx = 0
	for blockIdx < blockNum {
		// According to the first block the identity the version and txo ring size rule
		startBlockHeight := blocks[blockIdx].Height()
		blockNumPerRingGroup := wire.GetBlockNumPerRingGroupByBlockHeight(startBlockHeight)
		ringSize := wire.GetTxoRingSizeByBlockHeight(startBlockHeight)

		txoRings, err := blockchain.BuildTxoRings(int(blockNumPerRingGroup), int(ringSize), blocks[blockIdx:blockIdx+int(blockNumPerRingGroup)])
		if err != nil {
			return nil, err
		}

		for ringId, txoRing := range txoRings {
			for opIndex, outPoint := range txoRing.OutPointRing.OutPoints {
				opId := outPoint.OutPointId()
				if txoRingMember, ok := outPointToTxoRingMemberMap[opId]; ok {
					//	the outPoint is one of the outPointsToSpend
					if txoRingMember.ringId != nil {
						// It has been set previously
						return nil, fmt.Errorf("GenerateCoinSerialNumber: there are repeated OutPoint (%s, %d) in the rings",
							txoRingMember.txoRing.OutPointRing.OutPoints[txoRingMember.idx].TxHash,
							txoRingMember.txoRing.OutPointRing.OutPoints[txoRingMember.idx].Index,
						)
					}

					outPointToTxoRingMemberMap[opId].ringId = &wire.RingId{}
					copy(outPointToTxoRingMemberMap[opId].ringId[:], ringId[:])
					outPointToTxoRingMemberMap[opId].txoRing = txoRing
					outPointToTxoRingMemberMap[opId].idx = uint8(opIndex) //	The Ring Rule will make sure opIndex is in the scope of uint8
				}
			}
		}

		blockIdx += int(blockNumPerRingGroup)
	}

	//	check whether all outPoint has found the corresponding TxoRing
	for i := 0; i < coinNum; i++ {
		if txoRingMembers[i].ringId == nil {
			return nil, fmt.Errorf("GenerateCoinSerialNumber: at least one of the input OutPoing such as OutPoint[%d] = (%s,%d) can not find the corresponding TxoRing",
				i,
				chainhash.Hash(*outPoints[i].TxId).String(),
				outPoints[i].Index,
			)
		}
	}

	serialNumbers = make([][]byte, coinNum)
	for i := 0; i < coinNum; i++ {
		txOut := txoRingMembers[i].txoRing.TxOuts[txoRingMembers[i].idx]
		serialNumbers[i], err = abecrypto.TxoCoinSerialNumberGen(txOut,
			chainhash.Hash(*txoRingMembers[i].ringId),
			txoRingMembers[i].idx, cryptoKeys[i].cryptoSnsk)
		if err != nil {
			return nil, err
		}
	}

	return serialNumbers, nil
}

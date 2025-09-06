package wire

import (
	"fmt"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/chainhash"
	"io"
)

// writeOutPointAbe writes OutPointAbe to w io.Writer.
func (op *OutPointAbe) writeOutPointAbe(w io.Writer, pver uint32) error {
	if op == nil {
		return messageError("writeOutPointAbe", "the input *OutPointAbe is nil")
	}
	_, err := w.Write(op.TxHash[:])
	if err != nil {
		return err
	}

	return binarySerializer.PutUint8(w, op.Index)
}

// readOutPointAbe reads OutPointAbe from w r io.Reader.
// The caller is responsible for initialize the input *OutPointAbe.
func (op *OutPointAbe) readOutPointAbe(r io.Reader, pver uint32) error {
	if op == nil {
		return messageError("readOutPointAbe", "the input *OutPointAbe is nil")
	}

	_, err := io.ReadFull(r, op.TxHash[:])
	if err != nil {
		return err
	}

	op.Index, err = binarySerializer.Uint8(r)

	return err
}

// WriteOutPointRing writes OutPointRing to w io.Writer.
func (outPointRing *OutPointRing) WriteOutPointRing(w io.Writer, pver uint32) error {

	err := binarySerializer.PutUint32(w, littleEndian, outPointRing.Version)
	if err != nil {
		return err
	}

	err = binarySerializer.PutUint8(w, uint8(len(outPointRing.BlockHashs)))
	if err != nil {
		return err
	}
	for i := 0; i < len(outPointRing.BlockHashs); i++ {
		_, err := w.Write(outPointRing.BlockHashs[i][:])
		if err != nil {
			return err
		}
	}

	err = binarySerializer.PutUint8(w, uint8(len(outPointRing.OutPoints)))
	if err != nil {
		return err
	}
	for i := 0; i < len(outPointRing.OutPoints); i++ {
		err = outPointRing.OutPoints[i].writeOutPointAbe(w, pver)
		if err != nil {
			return err
		}
	}

	return nil
}

// ReadOutPointRing reads OutPointRing from r io.Reader.
// The caller is responsible for initializing *OutPointRing.
// todo: improve the allocation of space?
func (outPointRing *OutPointRing) ReadOutPointRing(r io.Reader, pver uint32) error {

	version, err := binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}
	outPointRing.Version = version

	blockNum, err := binarySerializer.Uint8(r)
	if err != nil {
		return err
	}
	expectedBlockNum, err := GetBlockNumPerRingGroupByRingVersion(outPointRing.Version)
	if err != nil {
		str := fmt.Sprintf("cannot get the block numberock number with version %d", outPointRing.Version)
		return messageError("readOutPointRing", str)
	}
	if blockNum != expectedBlockNum {
		str := fmt.Sprintf("the block number %d in ring does not match the version %d", blockNum, outPointRing.Version)
		return messageError("readOutPointRing", str)
	}
	outPointRing.BlockHashs = make([]*chainhash.Hash, blockNum)
	for i := 0; i < int(blockNum); i++ {
		tmp := chainhash.Hash{}
		_, err := io.ReadFull(r, tmp[:])
		if err != nil {
			return err
		}
		outPointRing.BlockHashs[i] = &tmp
	}

	//cnt, err = ReadVarInt(r, pver)
	ringSize, err := binarySerializer.Uint8(r)
	if err != nil {
		return err
	}
	maxRingSize, err := GetTxoRingSizeByRingVersion(outPointRing.Version)
	if err != nil {
		str := fmt.Sprintf("cannot get the ring size with version %d", outPointRing.Version)
		return messageError("readOutPointRing", str)
	}
	if ringSize > maxRingSize {
		str := fmt.Sprintf("the ring size (%d) exceeds the allowed max ring size %d with version %d", ringSize, maxRingSize, outPointRing.Version)
		return messageError("readOutPointRing", str)
	}
	outPointRing.OutPoints = make([]*OutPointAbe, ringSize)
	for i := 0; i < int(ringSize); i++ {
		outPointRing.OutPoints[i] = &OutPointAbe{}
		err = outPointRing.OutPoints[i].readOutPointAbe(r, pver)
		if err != nil {
			return err
		}
	}

	return nil
}

// writeTxIn writes TxIn to w io.Writer.
func (txIn *TxInAbe) writeTxInAbe(w io.Writer, pver uint32) error {

	err := WriteVarBytes(w, pver, txIn.SerialNumber)
	if err != nil {
		return err
	}

	return txIn.PreviousOutPointRing.WriteOutPointRing(w, pver)
}

// readTxIn reads the next sequence of bytes from r as a transaction input (TxIn).
func (txIn *TxInAbe) readTxInAbe(r io.Reader, pver uint32) error {

	serialNumber, err := ReadVarBytes(r, pver, abecryptoxparam.MaxAllowedSerialNumberSize, "SerialNumber")
	if err != nil {
		return err
	}
	txIn.SerialNumber = serialNumber

	return txIn.PreviousOutPointRing.ReadOutPointRing(r, pver)
}

// WriteTxOutAbe encodes TxOutAbe to to w.
func (txOut *TxOutAbe) WriteTxOutAbe(w io.Writer, pver uint32) error {

	err := binarySerializer.PutUint32(w, littleEndian, txOut.Version)
	if err != nil {
		return err
	}

	err = WriteVarBytes(w, pver, txOut.TxoScript)
	if err != nil {
		return err
	}

	return nil
}

// ReadTxOutAbe reads the next sequence of bytes from r as a Transaction Output.
func (txOut *TxOutAbe) ReadTxOutAbe(r io.Reader, pver uint32) error {

	version, err := binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}
	txOut.Version = version

	txoScript, err := ReadVarBytes(r, pver, abecryptoxparam.MaxAllowedTxoSize, "TxoScript")
	if err != nil {
		return err
	}
	txOut.TxoScript = txoScript

	return nil
}

// TxContentType is used to specify which part of transaction is considered in
// Write/Read, Serialization/Deserialization and Encode/Decode.
type TxContentType byte

const (
	TxContentTypeBase TxContentType = 0 // Tx Base Content := (Version, TxIns, TxOuts, Fee, TxMemo)
	TxContentTypeFull TxContentType = 1 // Tx Full Content := (Version, TxIns, TxOuts, Fee, TxMemo, TxWitness)
)

// WriteMsgTx writes MsgTxAbe to w.
// The parameter pver is used to provide flexible extension.
// The parameter txConType is used to determine whether the TxWitness is written.
// Note that the design is that, when txConType == txContentTypeFull,
// the TxWitness will always be written to w,
// even only "0" (for the length of bytes for TxWitness), implying the TxWitness is nil.
func (msg *MsgTxAbe) WriteMsgTx(w io.Writer, pver uint32, txConType TxContentType) error {
	//	Version
	err := binarySerializer.PutUint32(w, littleEndian, msg.Version)
	if err != nil {
		return err
	}

	//	TxIns
	err = WriteVarInt(w, pver, uint64(len(msg.TxIns)))
	if err != nil {
		return err
	}
	for _, txIn := range msg.TxIns {
		err = txIn.writeTxInAbe(w, pver)
		if err != nil {
			return err
		}
	}

	// TxOuts
	err = WriteVarInt(w, pver, uint64(len(msg.TxOuts)))
	for _, txOut := range msg.TxOuts {
		err = txOut.WriteTxOutAbe(w, pver)
		if err != nil {
			return err
		}
	}

	//	TxFee
	err = WriteVarInt(w, pver, msg.TxFee)
	if err != nil {
		return err
	}

	//	TxMemo
	err = WriteVarBytes(w, pver, msg.TxMemo)
	if err != nil {
		return err
	}

	if txConType == TxContentTypeFull {
		//	TxWitness
		// Note: even if msg.TxWitness, this works well, namely
		// there is a "0" for TxWitness, which will result in TxWitness being a []byte with length 0 when deserializing.
		err = WriteVarBytes(w, pver, msg.TxWitness)
		if err != nil {
			return err
		}
	}

	return nil
}

// ReadMsgTx read MsgTxAbe from r io.Reader.
// The parameter pver is used to provide flexible extension.
// The parameter txConType is used to determine whether read TxWitness.
// Note that the design is that, when txConType == txContentTypeFull,
// the parameter r io.Reader will always contain bytes for TxWitness, even they are only "0" implying the TxWitness is nil.
func (msg *MsgTxAbe) ReadMsgTx(r io.Reader, pver uint32, txConType TxContentType) error {

	//	Version
	version, err := binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}
	msg.Version = version

	//	TxIns
	txInNum, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	txInputMaxNum, err := abecryptoxparam.GetTxInputMaxNum(msg.Version)
	if err != nil {
		return err
	}
	if txInNum > uint64(txInputMaxNum) {
		str := fmt.Sprintf("The numner of inputs exceeds the allowd max number [txInNum %d, max %d]", txInNum,
			txInputMaxNum)
		return messageError("MsgTx.readMsgTx", str)
	}
	msg.TxIns = make([]*TxInAbe, txInNum)
	for i := uint64(0); i < txInNum; i++ {
		txIn := &TxInAbe{}
		err = txIn.readTxInAbe(r, pver)
		if err != nil {
			return err
		}
		msg.TxIns[i] = txIn
	}

	// TxOuts
	txoNum, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	txOutputMaxNum, err := abecryptoxparam.GetTxOutputMaxNum(msg.Version)
	if err != nil {
		return err
	}
	if txoNum > uint64(txOutputMaxNum) {
		str := fmt.Sprintf("The numner of inputs exceeds the allowd max number [txoNum %d, max %d]", txoNum,
			txOutputMaxNum)
		return messageError("MsgTx.readMsgTx", str)
	}
	msg.TxOuts = make([]*TxOutAbe, txoNum)
	for i := uint64(0); i < txoNum; i++ {
		txOut := &TxOutAbe{}
		err = txOut.ReadTxOutAbe(r, pver)
		if err != nil {
			return err
		}
		msg.TxOuts[i] = txOut
	}

	//	TxFee
	txFee, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}
	msg.TxFee = txFee

	//	TxMemo
	//	For better performance, we use constant to specify the maxAllowed size, rather than calling a function.
	// txMemo, err := ReadVarBytes(r, pver, uint32(abepqringctparam.GetTxMemoMaxLen(msg.Version)), "TxMemo")
	// todo: if necessary, use a function based on Version to support flexible upgrade.
	txMemo, err := ReadVarBytes(r, pver, abecryptoxparam.MaxAllowedTxMemoSize, "TxMemo")
	if err != nil {
		return err
	}
	msg.TxMemo = txMemo

	msg.TxWitness = nil // explicitly set the value
	// The design assumes that whatever, there is bytes for txWitness,
	// even they are only a "0" implying that the txWitness is empty.
	if txConType == TxContentTypeFull {
		txWitness, err := ReadVarBytes(r, pver, abecryptoxparam.MaxAllowedTxWitnessSize, "TxWitness")
		if err != nil {
			return err
		}
		msg.TxWitness = txWitness
	}

	return nil
}

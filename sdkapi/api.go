package sdkapi

import "github.com/abesuite/abec/wire"

type MsgBlock wire.MsgBlockAbe

func SerializeMsgBlock(msgBlock *MsgBlock) (serializedMsgBlock []byte, err error) {
	// TODO call by wire.MsgBlockAbe.Serialize
	// By Ocean
	panic("implement me")
}

func DeserializeMsgBlock(serializedMsgBlock []byte) (msgBlock *MsgBlock, err error) {
	// TODO call by wire.MsgBlockAbe.Deserialize
	// By Ocean
	panic("implement me")
}

func ParseTxoFromBlock(serialiedMsgBlock []byte) (serializedTxoLists [][]byte, err error) {
	// TODO extract the txo data from block
	// By Ocean
	panic("implement me")
}

type MsgTx wire.MsgTxAbe

func SerializeMsgTx(msgTx *MsgTx) (serializedMsgTx []byte, err error) {
	// TODO call by wire.MsgTxAbe.Serialize
	// By Ocean
	panic("implement me")
}

func DeserializeMsgTx(serializedMsgTx []byte) (msgTx *MsgTx, err error) {
	// TODO call by wire.MsgTxAbe.Deserialize
	// By Ocean
	panic("implement me")
}

func ParseTxoFromTx(serialiedMsgTx []byte) (serializedTxoLists [][]byte, err error) {
	// TODO extract the txo data from transaction
	// By Ocean
	panic("implement me")
}

func GenerateRawTransaction(inputDesc [][]byte, outputDesc [][]byte, txFee []byte, txMemo []byte) (serializedMsgTx []byte, err error) {
	// TODO check the number of input and output
	// TODO check the length of txMemo
	// TODO check the balance of inputs and output
	// By Ocean
	panic("implement me")
}

func SignRawTransaction(serializedRawTx []byte) (serializedMsgTx []byte, err error) {
	// TODO call by wire.MsgTxAbe.Deserialize
	// By Ocean
	panic("implement me")
}

package wire

import (
	"io"

	"github.com/abesuite/abec/chainhash"
)

type MsgGetBlockTx struct {
	BlockHash chainhash.Hash
	TxHash    chainhash.Hash
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgGetBlockTx) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	_, err := io.ReadFull(r, msg.BlockHash[:])
	if err != nil {
		return err
	}

	_, err = io.ReadFull(r, msg.TxHash[:])
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgGetBlockTx) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	_, err := w.Write(msg.BlockHash[:])
	if err != nil {
		return err
	}

	_, err = w.Write(msg.TxHash[:])
	if err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgGetBlockTx) Command() string {
	return CmdGetBlockTx
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgGetBlockTx) MaxPayloadLength(pver uint32) uint32 {
	// Num inventory vectors (varInt) + max allowed inventory vectors.
	return chainhash.HashSize * 2
}

func NewMsgGetBlockTx(blockHash chainhash.Hash, txHash chainhash.Hash) *MsgGetBlockTx {
	return &MsgGetBlockTx{
		BlockHash: blockHash,
		TxHash:    txHash,
	}
}

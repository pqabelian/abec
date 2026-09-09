package wire

import (
	"io"

	"github.com/abesuite/abec/chainhash"
)

type MsgBlockTx struct {
	BlockHash chainhash.Hash
	Tx        *MsgTxAbe
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgBlockTx) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	_, err := io.ReadFull(r, msg.BlockHash[:])
	if err != nil {
		return err
	}

	// Use TxVersion_Unknown temporary, this would be immediately set after Deserialize
	msg.Tx = NewMsgTxAbe(TxVersion_Unknown)
	err = msg.Tx.Deserialize(r)
	if err != nil {
		return err
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgBlockTx) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	_, err := w.Write(msg.BlockHash[:])
	if err != nil {
		return err
	}

	err = msg.Tx.BtcEncode(w, pver, enc)
	if err != nil {
		return err
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgBlockTx) Command() string {
	return CmdBlockTx
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgBlockTx) MaxPayloadLength(pver uint32) uint32 {
	return chainhash.HashSize + 32*1024*1024
}

func NewMsgBlockTx(blockHash chainhash.Hash, tx *MsgTxAbe) *MsgBlockTx {
	return &MsgBlockTx{
		BlockHash: blockHash,
		Tx:        tx,
	}
}

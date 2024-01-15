package wire

import (
	"fmt"
	"github.com/abesuite/abec/chainhash"
	"io"
)

type MsgNeedSetResult struct {
	BlockHash chainhash.Hash
	Txs       []*MsgTxAbe
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgNeedSetResult) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	_, err := io.ReadFull(r, msg.BlockHash[:])
	if err != nil {
		return err
	}

	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Limit to max inventory vectors per message.
	if count > maxTxPerBlock {
		str := fmt.Sprintf("too many invvect in message [%v]", count)
		return messageError("MsgInv.BtcDecode", str)
	}

	// Create a contiguous slice of inventory vectors to deserialize into in
	// order to reduce the number of allocations.
	msg.Txs = make([]*MsgTxAbe, count)
	for i := uint64(0); i < count; i++ {
		// Use TxVersion_Unknown temporary, this would be immediately set after Deserialize
		msg.Txs[i] = NewMsgTxAbe(TxVersion_Unknown)
		err = msg.Txs[i].Deserialize(r)
		if err != nil {
			return err
		}
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgNeedSetResult) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	_, err := w.Write(msg.BlockHash[:])
	if err != nil {
		return err
	}
	// Limit to max inventory vectors per message.
	count := len(msg.Txs)
	if count > maxTxPerBlock {
		str := fmt.Sprintf("too many invvect in message [%v]", count)
		return messageError("MsgInv.BtcEncode", str)
	}

	err = WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}

	for _, tx := range msg.Txs {
		err = tx.BtcEncode(w, pver, enc)
		if err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgNeedSetResult) Command() string {
	return CmdNeedSetResult
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgNeedSetResult) MaxPayloadLength(pver uint32) uint32 {
	// Num inventory vectors (varInt) + max allowed inventory vectors.
	return MaxMessagePayload
}

func NewMsgNeedSetResult(blockHash chainhash.Hash, Txs []*MsgTxAbe) *MsgNeedSetResult {
	return &MsgNeedSetResult{
		BlockHash: blockHash,
		Txs:       Txs,
	}
}

package wire

import (
	"fmt"
	"io"

	"github.com/abesuite/abec/chainhash"
)

type MsgNeedSet struct {
	BlockHash chainhash.Hash
	Hashes    []chainhash.Hash
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgNeedSet) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
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
	msg.Hashes = make([]chainhash.Hash, count)
	for i := uint64(0); i < count; i++ {
		_, err := io.ReadFull(r, msg.Hashes[i][:])
		if err != nil {
			return err
		}
	}

	return nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
func (msg *MsgNeedSet) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	_, err := w.Write(msg.BlockHash[:])
	if err != nil {
		return err
	}

	// Limit to max inventory vectors per message.
	count := len(msg.Hashes)
	if count > MaxInvPerMsg {
		str := fmt.Sprintf("too many invvect in message [%v]", count)
		return messageError("MsgInv.BtcEncode", str)
	}

	err = WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}

	for _, h := range msg.Hashes {
		_, err := w.Write(h[:])
		if err != nil {
			return err
		}
	}

	return nil
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgNeedSet) Command() string {
	return CmdNeedSet
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgNeedSet) MaxPayloadLength(pver uint32) uint32 {
	// Num inventory vectors (varInt) + max allowed inventory vectors.
	return MaxVarIntPayload + (MaxInvPerMsg * maxInvVectPayload)
}

func NewMsgNeedSet(blockhash chainhash.Hash, hashes []chainhash.Hash) *MsgNeedSet {
	return &MsgNeedSet{
		BlockHash: blockhash,
		Hashes:    hashes,
	}
}

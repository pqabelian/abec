package wire

import (
	"fmt"
	"io"

	"github.com/abesuite/abec/chainhash"
)

const blockTxNumLimit = 1

type MsgGetBlockTx struct {
	BlockHash chainhash.Hash
	TxHashes  []chainhash.Hash
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
func (msg *MsgGetBlockTx) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	_, err := io.ReadFull(r, msg.BlockHash[:])
	if err != nil {
		return err
	}

	count, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Limit to max inventory vectors per message.
	if count > blockTxNumLimit {
		str := fmt.Sprintf("too many txhash in message [%v]", count)
		return messageError("MsgGetBlockTx.BtcDecode", str)
	}

	// Create a contiguous slice of inventory vectors to deserialize into in
	// order to reduce the number of allocations.
	msg.TxHashes = make([]chainhash.Hash, count)
	for i := uint64(0); i < count; i++ {
		_, err := io.ReadFull(r, msg.TxHashes[i][:])
		if err != nil {
			return err
		}
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

	// Limit to max inventory vectors per message.
	count := len(msg.TxHashes)
	if count > MaxInvPerMsg {
		str := fmt.Sprintf("too many txhash in message [%v]", count)
		return messageError("MsgGetBlockTx.BtcEncode", str)
	}

	err = WriteVarInt(w, pver, uint64(count))
	if err != nil {
		return err
	}

	for _, h := range msg.TxHashes {
		_, err := w.Write(h[:])
		if err != nil {
			return err
		}
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
	return chainhash.HashSize + MaxVarIntPayload + (MaxInvPerMsg * maxInvVectPayload)
}

func NewMsgGetBlockTx(blockhash chainhash.Hash, hashes []chainhash.Hash) *MsgGetBlockTx {
	return &MsgGetBlockTx{
		BlockHash: blockhash,
		TxHashes:  hashes,
	}
}

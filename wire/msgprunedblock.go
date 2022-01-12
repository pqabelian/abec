package wire

import (
	"fmt"
	"io"

	"github.com/abesuite/abec/chainhash"
)

type MsgPrunedBlock struct {
	Header            BlockHeader
	TransactionHashes []chainhash.Hash
}

func (msg *MsgPrunedBlock) AddTransactionHash(tx *MsgTxAbe) error {
	msg.TransactionHashes = append(msg.TransactionHashes, tx.TxHash())
	return nil
}

func (msg *MsgPrunedBlock) ClearTransactions() {
	msg.TransactionHashes = make([]chainhash.Hash, 0, defaultTransactionAllocAbe)
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding blocks stored to disk, such as in a database, as
// opposed to decoding blocks from the wire.

func (msg *MsgPrunedBlock) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	err := readBlockHeader(r, pver, &msg.Header)
	if err != nil {
		return err
	}

	txCount, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	// Prevent more transactions than could possibly fit into a block.
	// It would be possible to cause memory exhaustion and panics without
	// a sane upper bound on this count.
	if txCount > maxTxPerBlockAbe {
		str := fmt.Sprintf("too many transactions to fit into a block "+
			"[count %d, max %d]", txCount, maxTxPerBlockAbe)
		return messageError("MsgBlock.BtcDecode", str)
	}

	msg.TransactionHashes = make([]chainhash.Hash, 0, txCount)
	for i := uint64(0); i < txCount; i++ {
		_, err = io.ReadFull(r, msg.TransactionHashes[i][:])
		if err != nil {
			return err
		}
	}

	return nil
}

// Deserialize decodes a block from r into the receiver using a format that is
// suitable for long-term storage such as a database while respecting the
// Version field in the block.  This function differs from BtcDecode in that
// BtcDecode decodes from the bitcoin wire protocol as it was sent across the
// network.  The wire encoding can technically differ depending on the protocol
// version and doesn't even really need to match the format of a stored block at
// all.  As of the time this comment was written, the encoded block is the same
// in both instances, but there is a distinct difference and separating the two
// allows the API to be flexible enough to deal with changes.
func (msg *MsgPrunedBlock) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	return msg.BtcDecode(r, 0, WitnessEncoding)
}

func (msg *MsgPrunedBlock) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := writeBlockHeader(w, pver, &msg.Header)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(len(msg.TransactionHashes)))
	if err != nil {
		return err
	}

	for _, h := range msg.TransactionHashes {
		_, err = w.Write(h[:])
		if err != nil {
			return err
		}
	}

	return nil
}
func (msg *MsgPrunedBlock) Serialize(w io.Writer) error {
	return msg.BtcEncode(w, 0, WitnessEncoding)
}

// SerializeSize returns the number of bytes it would take to serialize the
// block, factoring in any witness data within transaction.
func (msg *MsgPrunedBlock) SerializeSize() int {
	// Block header bytes + Serialized varint size for the number of
	// transactions.
	n := blockHeaderLen + VarIntSerializeSize(uint64(len(msg.TransactionHashes))) + len(msg.TransactionHashes)*32
	return n
}
func (msg *MsgPrunedBlock) Command() string {
	return CmdPrunedBlock
}

func (msg *MsgPrunedBlock) MaxPayloadLength(pver uint32) uint32 {
	// Block header at 80 bytes + transaction count + max transactions
	// which can vary up to the MaxBlockPayload (including the block header
	// and transaction count).
	return MaxBlockPayloadAbe
}

func (msg *MsgPrunedBlock) BlockHash() chainhash.Hash {
	return msg.Header.BlockHash()
}

// TxHashes returns a slice of hashes of all of transactions in this block.
func (msg *MsgBlockAbe) TxHashes() ([]chainhash.Hash, error) {
	hashList := make([]chainhash.Hash, 0, len(msg.Transactions))
	for _, tx := range msg.Transactions {
		hashList = append(hashList, tx.TxHash())
	}
	return hashList, nil
}

func NewMsgBlockPrunedFromMsgBlockAbe(block *MsgBlockAbe) (*MsgPrunedBlock, error) {
	res := &MsgPrunedBlock{
		Header:            block.Header,
		TransactionHashes: make([]chainhash.Hash, 0, defaultTransactionAlloc),
	}
	hashes, err := block.TxHashes()
	if err != nil {
		return nil, err
	}
	res.TransactionHashes = append(res.TransactionHashes, hashes...)
	return res, nil
}

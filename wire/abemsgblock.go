package wire

// defaultTransactionAlloc is the default size used for the backing array
// for transactions.  The transaction array will dynamically grow as needed, but
// this figure is intended to provide enough space for the number of
// transactions in the vast majority of blocks without needing to grow the
// backing array multiple times.
//const defaultTransactionAllocAbe = 2048

// MaxBlocksPerMsg is the maximum number of blocks allowed per message.
//const MaxBlocksPerMsgAbe = 500

// MaxBlockPayload is the maximum bytes a block message can be in bytes.
// After Segregated Witness, the max block payload has been raised to 8MB.
//const MaxBlockPayloadAbe = 8000000

// maxTxPerBlock is the maximum number of transactions that could
// possibly fit into a block.
//const maxTxPerBlockAbe = (MaxBlockPayloadAbe / TxPayloadMinSize) + 1

// TxLoc holds locator data for the offset and length of where a transaction is
// located within a MsgBlock data buffer.
/*type TxLocAbe struct {
	TxStart int
	TxLen   int
}*/

// MsgBlock implements the Message interface and represents an abe
// block message.  It is used to deliver block and transaction information in
// response to a getdata message (MsgGetData) for a given block hash.
/*type MsgBlockAbe struct {
	Header       BlockHeader
	Transactions []*MsgTxAbe
}*/

// AddTransaction adds a transaction to the message.
/*func (msg *MsgBlockAbe) AddTransaction(tx *MsgTxAbe) error {
	msg.Transactions = append(msg.Transactions, tx)
	return nil
}*/

// ClearTransactions removes all transactions from the message.
/*func (msg *MsgBlockAbe) ClearTransactions() {
	msg.Transactions = make([]*MsgTxAbe, 0, defaultTransactionAllocAbe)
}*/

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding blocks stored to disk, such as in a database, as
// opposed to decoding blocks from the wire.
/*func (msg *MsgBlockAbe) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
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

	msg.Transactions = make([]*MsgTxAbe, 0, txCount)
	for i := uint64(0); i < txCount; i++ {
		tx := MsgTxAbe{}
		err := tx.BtcDecode(r, pver, enc)
		if err != nil {
			return err
		}
		msg.Transactions = append(msg.Transactions, &tx)
	}

	return nil
}*/

// Deserialize decodes a block from r into the receiver using a format that is
// suitable for long-term storage such as a database while respecting the
// Version field in the block.  This function differs from BtcDecode in that
// BtcDecode decodes from the bitcoin wire protocol as it was sent across the
// network.  The wire encoding can technically differ depending on the protocol
// version and doesn't even really need to match the format of a stored block at
// all.  As of the time this comment was written, the encoded block is the same
// in both instances, but there is a distinct difference and separating the two
// allows the API to be flexible enough to deal with changes.
/*func (msg *MsgBlockAbe) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	err := msg.Header.Deserialize(r)
	if err != nil {
		return err
	}

	txCount, err := ReadVarInt(r, 0)
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

	msg.Transactions = make([]*MsgTxAbe, 0, txCount)
	for i := uint64(0); i < txCount; i++ {
		tx := MsgTxAbe{}
		err := tx.Deserialize(r)
		if err != nil {
			return err
		}
		msg.Transactions = append(msg.Transactions, &tx)
	}

	return nil

}*/

// DeserializeTxLoc decodes r in the same manner Deserialize does, but it takes
// a byte buffer instead of a generic reader and returns a slice containing the
// start and length of each transaction within the raw data that is being
// deserialized.
/*func (msg *MsgBlockAbe) DeserializeTxLocAbe(r *bytes.Buffer) ([]TxLocAbe, error) {
	fullLen := r.Len()

	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of existing wire protocol functions.
	err := msg.Header.Deserialize(r)
	if err != nil {
		return nil, err
	}

	txCount, err := ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}

	// Prevent more transactions than could possibly fit into a block.
	// It would be possible to cause memory exhaustion and panics without
	// a sane upper bound on this count.
	if txCount > maxTxPerBlockAbe {
		str := fmt.Sprintf("too many transactions to fit into a block "+
			"[count %d, max %d]", txCount, maxTxPerBlockAbe)
		return nil, messageError("MsgBlock.DeserializeTxLoc", str)
	}

	// Deserialize each transaction while keeping track of its location
	// within the byte stream.
	msg.Transactions = make([]*MsgTxAbe, 0, txCount)
	txLocs := make([]TxLocAbe, txCount)
	for i := uint64(0); i < txCount; i++ {
		txLocs[i].TxStart = fullLen - r.Len()
		tx := MsgTxAbe{}
		err := tx.Deserialize(r)
		if err != nil {
			return nil, err
		}
		msg.Transactions = append(msg.Transactions, &tx)
		txLocs[i].TxLen = (fullLen - r.Len()) - txLocs[i].TxStart
	}

	return txLocs, nil
}*/

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding blocks to be stored to disk, such as in a
// database, as opposed to encoding blocks for the wire.
// Abe to do: for ABEBlocks, the encode of tx should not encode the txo details and witness details
/*func (msg *MsgBlockAbe) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := writeBlockHeader(w, pver, &msg.Header)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(len(msg.Transactions)))
	if err != nil {
		return err
	}

	for _, tx := range msg.Transactions {
		err = tx.BtcEncode(w, pver, enc)
		if err != nil {
			return err
		}
	}

	return nil
}*/

// Serialize encodes the block to w using a format that suitable for long-term
// storage such as a database while respecting the Version field in the block.
// This function differs from BtcEncode in that BtcEncode encodes the block to
// the bitcoin wire protocol in order to be sent across the network.  The wire
// encoding can technically differ depending on the protocol version and doesn't
// even really need to match the format of a stored block at all.  As of the
// time this comment was written, the encoded block is the same in both
// instances, but there is a distinct difference and separating the two allows
// the API to be flexible enough to deal with changes.
/*func (msg *MsgBlockAbe) Serialize(w io.Writer) error {
	err := msg.Header.Serialize(w)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, 0, uint64(len(msg.Transactions)))
	if err != nil {
		return err
	}

	for _, tx := range msg.Transactions {
		err = tx.Serialize(w)
		if err != nil {
			return err
		}
	}

	return nil
}

// SerializeSize returns the number of bytes it would take to serialize the
// block, factoring in any witness data within transaction.
func (msg *MsgBlockAbe) SerializeSize() int {
	// Block header bytes + Serialized varint size for the number of
	// transactions.
	n := blockHeaderLen + VarIntSerializeSize(uint64(len(msg.Transactions)))

	for _, tx := range msg.Transactions {
		n += tx.SerializeSize() // to do, may remove the serializeType
	}

	return n
}*/

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
/*func (msg *MsgBlockAbe) Command() string {
	return CmdBlock
}*/

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
/*func (msg *MsgBlockAbe) MaxPayloadLength(pver uint32) uint32 {
	// Block header at 80 bytes + transaction count + max transactions
	// which can vary up to the MaxBlockPayload (including the block header
	// and transaction count).
	return MaxBlockPayloadAbe
}*/

// BlockHash computes the block identifier hash for this block.
/*func (msg *MsgBlockAbe) BlockHash() chainhash.Hash {
	return msg.Header.BlockHash()
}*/

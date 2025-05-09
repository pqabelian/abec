package wire

import (
	"bytes"
	"fmt"
	"github.com/pqabelian/abec/abecryptox/abecryptoxparam"
	"io"

	"github.com/pqabelian/abec/chainhash"
)

// defaultTransactionAlloc is the default size used for the backing array
// for transactions.  The transaction array will dynamically grow as needed, but
// this figure is intended to provide enough space for the number of
// transactions in the vast majority of blocks without needing to grow the
// backing array multiple times.
const defaultTransactionAlloc = 2048
const defaultTransactionAllocAbe = 2048

// MaxBlocksPerMsg is the maximum number of blocks allowed per message.
const MaxBlocksPerMsg = 500
const MaxBlocksPerMsgAbe = 500

// MaxBlockPayload is the maximum bytes a block message can be in bytes.
// After Segregated Witness, the max block payload has been raised to 4MB.
const MaxBlockPayload = 4000000

// MaxBlockPayloadAbe is the maximum bytes a block message can be in bytes.
// todo: The max block payload in abe is 8MB. However, it seems that there is bug in transaction
// serialization currently. Hence, the MaxBlockPayload is temporarily  set as 800MB.
//
// changed at fork for MLPAUT,use 256MB as max block message payload
// and corresponding, the max message size is adjusted to 320MB for redundancy
// the strategy is to use the default configuration first, if the network
// is not congested, gradually increase the default configuration until limited MaxBlockPayloadAbe
const MaxBlockPayloadAbe = 256 * 1024 * 1024

// maxTxPerBlock is the maximum number of transactions that could
// possibly fit into a block.
const maxTxPerBlock = (MaxBlockPayload / minTxPayload) + 1
const maxTxPerBlockAbe = (MaxBlockPayloadAbe / TxPayloadMinSize) + 1

// TxLoc holds locator data for the offset and length of where a transaction is
// located within a MsgBlock data buffer.
type TxLoc struct {
	TxStart int
	TxLen   int
}
type TxAbeLoc struct {
	TxStart      int
	TxLen        int
	WitnessStart int
	WitnessLen   int
}

// MsgBlock implements the Message interface and represents an abe
// block message.  It is used to deliver block and transaction information in
// response to a getdata message (MsgGetData) for a given block hash.
type MsgBlock struct {
	Header       BlockHeader
	Transactions []*MsgTx
}

// MsgBlockAbe implements the Message interface and represents an abe
// block message.  It is used to deliver block and transaction information in
// response to a getdata message (MsgGetData) for a given block hash.
type MsgBlockAbe struct {
	Header       BlockHeader
	Transactions []*MsgTxAbe
	WitnessHashs []*chainhash.Hash
}

// MsgSimplifiedBlock is used to submit simplified block (without transaction content)
// Transactions contains coinbase (the first one)
type MsgSimplifiedBlock struct {
	Header       BlockHeader
	Coinbase     *MsgTxAbe
	Transactions []chainhash.Hash
}

// AddTransaction adds a transaction to the message.
func (msg *MsgBlock) AddTransaction(tx *MsgTx) error {
	msg.Transactions = append(msg.Transactions, tx)
	return nil

}

func (msg *MsgBlockAbe) AddTransaction(tx *MsgTxAbe) error {
	msg.Transactions = append(msg.Transactions, tx)
	witHash := chainhash.DoubleHashH(tx.TxWitness)
	msg.WitnessHashs = append(msg.WitnessHashs, &witHash)
	return nil
}

// ClearTransactions removes all transactions from the message.
func (msg *MsgBlock) ClearTransactions() {
	msg.Transactions = make([]*MsgTx, 0, defaultTransactionAlloc)
}

func (msg *MsgBlockAbe) ClearTransactions() {
	msg.Transactions = make([]*MsgTxAbe, 0, defaultTransactionAllocAbe)
	msg.WitnessHashs = make([]*chainhash.Hash, 0, defaultTransactionAllocAbe)
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding blocks stored to disk, such as in a database, as
// opposed to decoding blocks from the wire.
func (msg *MsgBlock) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
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
	if txCount > maxTxPerBlock {
		str := fmt.Sprintf("too many transactions to fit into a block "+
			"[count %d, max %d]", txCount, maxTxPerBlock)
		return messageError("MsgBlock.BtcDecode", str)
	}

	msg.Transactions = make([]*MsgTx, 0, txCount)
	for i := uint64(0); i < txCount; i++ {
		tx := MsgTx{}
		err := tx.BtcDecode(r, pver, enc)
		if err != nil {
			return err
		}
		msg.Transactions = append(msg.Transactions, &tx)
	}

	return nil
}

func (msg *MsgBlockAbe) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
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
		err := tx.BtcDecode(r, pver, BaseEncoding)
		if err != nil {
			return err
		}
		msg.Transactions = append(msg.Transactions, &tx)
	}

	msg.WitnessHashs = make([]*chainhash.Hash, txCount)
	for i := uint64(0); i < txCount; i++ {
		tmp := chainhash.Hash{}
		_, err := io.ReadFull(r, tmp[:])
		if err != nil {
			return err
		}
		msg.WitnessHashs[i] = &tmp
	}
	existWitness := make([]byte, 1)
	_, err = r.Read(existWitness)
	if err != nil {
		return err
	}
	if enc == WitnessEncoding && existWitness[0] == 1 {
		var tmp []byte
		for _, tx := range msg.Transactions {
			tmp, err = ReadVarBytes(r, pver, abecryptoxparam.MaxAllowedTxWitnessSize, "tx.Witness")
			if err != nil {
				return err
			}
			tx.TxWitness = tmp
		}
	}
	return nil
}

func (msg *MsgSimplifiedBlock) AbeDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	err := readBlockHeader(r, pver, &msg.Header)
	if err != nil {
		return err
	}

	coinbaseExist, err := ReadVarInt(r, pver)
	if coinbaseExist == 1 {
		tx := MsgTxAbe{}
		err := tx.BtcDecode(r, pver, enc)
		if err != nil {
			return err
		}
		msg.Coinbase = &tx
	} else {
		msg.Coinbase = nil
	}

	txCount, err := ReadVarInt(r, pver)
	if err != nil {
		return err
	}

	msg.Transactions = make([]chainhash.Hash, txCount)
	for i := 0; i < int(txCount); i++ {
		_, err := io.ReadFull(r, msg.Transactions[i][:])
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
func (msg *MsgBlock) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	//
	// Passing an encoding type of WitnessEncoding to BtcEncode for the
	// MessageEncoding parameter indicates that the transactions within the
	// block are expected to be serialized according to the new
	// serialization structure defined in BIP0141.
	return msg.BtcDecode(r, 0, WitnessEncoding)
}

func (msg *MsgBlockAbe) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	return msg.BtcDecode(r, 0, WitnessEncoding)

	//
	//err := msg.Header.Deserialize(r)
	//if err != nil {
	//	return err
	//}
	//
	//txCount, err := ReadVarInt(r, 0)
	//if err != nil {
	//	return err
	//}
	//
	//// Prevent more transactions than could possibly fit into a block.
	//// It would be possible to cause memory exhaustion and panics without
	//// a sane upper bound on this count.
	//if txCount > maxTxPerBlockAbe {
	//	str := fmt.Sprintf("too many transactions to fit into a block "+
	//		"[count %d, max %d]", txCount, maxTxPerBlockAbe)
	//	return messageError("MsgBlock.BtcDecode", str)
	//}
	//
	//msg.Transactions = make([]*MsgTxAbe, 0, txCount)
	//for i := uint64(0); i < txCount; i++ {
	//	tx := MsgTxAbe{}
	//	err := tx.DeserializeFull(r)
	//	if err != nil {
	//		return err
	//	}
	//	msg.Transactions = append(msg.Transactions, &tx)
	//}
	//
	//return nil

}

func (msg *MsgSimplifiedBlock) Deserialize(r io.Reader) error {
	return msg.AbeDecode(r, 0, WitnessEncoding)
}
func (msg *MsgBlockAbe) DeserializeNoWitness(r io.Reader) error {
	return msg.BtcDecode(r, 0, BaseEncoding)
}

// DeserializeNoWitness decodes a block from r into the receiver similar to
// Deserialize, however DeserializeWitness strips all (if any) witness data
// from the transactions within the block before encoding them.
func (msg *MsgBlock) DeserializeNoWitness(r io.Reader) error {
	return msg.BtcDecode(r, 0, BaseEncoding)
}

// DeserializeTxLoc decodes r in the same manner Deserialize does, but it takes
// a byte buffer instead of a generic reader and returns a slice containing the
// start and length of each transaction within the raw data that is being
// deserialized.
func (msg *MsgBlock) DeserializeTxLoc(r *bytes.Buffer) ([]TxLoc, error) {
	fullLen := r.Len()

	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of existing wire protocol functions.
	err := readBlockHeader(r, 0, &msg.Header)
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
	if txCount > maxTxPerBlock {
		str := fmt.Sprintf("too many transactions to fit into a block "+
			"[count %d, max %d]", txCount, maxTxPerBlock)
		return nil, messageError("MsgBlock.DeserializeTxLoc", str)
	}

	// Deserialize each transaction while keeping track of its location
	// within the byte stream.
	msg.Transactions = make([]*MsgTx, 0, txCount)
	txLocs := make([]TxLoc, txCount)
	for i := uint64(0); i < txCount; i++ {
		txLocs[i].TxStart = fullLen - r.Len()
		tx := MsgTx{}
		err := tx.Deserialize(r)
		if err != nil {
			return nil, err
		}
		msg.Transactions = append(msg.Transactions, &tx)
		txLocs[i].TxLen = (fullLen - r.Len()) - txLocs[i].TxStart
	}

	return txLocs, nil
}

// DeserializeTxLoc Would be delete
func (msg *MsgBlockAbe) DeserializeTxLoc(r *bytes.Buffer) ([]TxAbeLoc, error) {
	fullLen := r.Len()

	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of existing wire protocol functions.
	err := readBlockHeader(r, 0, &msg.Header)
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
	txLocs := make([]TxAbeLoc, txCount)
	for i := uint64(0); i < txCount; i++ {
		txLocs[i].TxStart = fullLen - r.Len()
		tx := MsgTxAbe{}
		err := tx.DeserializeNoWitness(r)
		if err != nil {
			return nil, err
		}
		msg.Transactions = append(msg.Transactions, &tx)
		txLocs[i].TxLen = (fullLen - r.Len()) - txLocs[i].TxStart
	}

	return txLocs, nil
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding blocks to be stored to disk, such as in a
// database, as opposed to encoding blocks for the wire.
func (msg *MsgBlock) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
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
}

// Serialize encodes the block to w using a format that suitable for long-term
// storage such as a database while respecting the Version field in the block.
// This function differs from BtcEncode in that BtcEncode encodes the block to
// the bitcoin wire protocol in order to be sent across the network.  The wire
// encoding can technically differ depending on the protocol version and doesn't
// even really need to match the format of a stored block at all.  As of the
// time this comment was written, the encoded block is the same in both
// instances, but there is a distinct difference and separating the two allows
// the API to be flexible enough to deal with changes.
func (msg *MsgBlock) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcEncode.
	//
	// Passing WitnessEncoding as the encoding type here indicates that
	// each of the transactions should be serialized using the witness
	// serialization structure defined in BIP0141.
	return msg.BtcEncode(w, 0, WitnessEncoding)
}

// todo(ABE): for ABEBlocks, the encode of tx should not encode the txo details and witness details
func (msg *MsgBlockAbe) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := writeBlockHeader(w, pver, &msg.Header)
	if err != nil {
		return err
	}

	err = WriteVarInt(w, pver, uint64(len(msg.Transactions)))
	if err != nil {
		return err
	}

	for _, tx := range msg.Transactions {
		err = tx.BtcEncode(w, pver, BaseEncoding)
		if err != nil {
			return err
		}
	}

	for _, witHash := range msg.WitnessHashs {
		_, err = w.Write(witHash[:])
		if err != nil {
			return err
		}
	}

	if enc == WitnessEncoding && msg.HasWitness() {
		_, err = w.Write([]byte{1})
		if err != nil {
			return err
		}
		for _, tx := range msg.Transactions {
			err = WriteVarBytes(w, pver, tx.TxWitness)
			if err != nil {
				return err
			}
		}
	} else {
		_, err = w.Write([]byte{0})
		if err != nil {
			return err
		}
	}
	return nil
}

func (msg *MsgSimplifiedBlock) Serialize(w io.Writer) error {
	return msg.AbeEncode(w, 0, WitnessEncoding)
}

func (msg *MsgSimplifiedBlock) AbeEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	err := writeBlockHeader(w, pver, &msg.Header)
	if err != nil {
		return err
	}

	if msg.Coinbase == nil {
		err = WriteVarInt(w, pver, 0)
		if err != nil {
			return err
		}
	} else {
		err = WriteVarInt(w, pver, 1)
		if err != nil {
			return err
		}
		err = msg.Coinbase.BtcEncode(w, pver, enc)
		if err != nil {
			return err
		}
	}

	err = WriteVarInt(w, pver, uint64(len(msg.Transactions)))
	if err != nil {
		return err
	}

	for _, txHash := range msg.Transactions {
		_, err = w.Write(txHash[:])
		if err != nil {
			return err
		}
	}

	return nil
}
func (msg *MsgBlockAbe) SerializeNoWitness(w io.Writer) error {
	return msg.BtcEncode(w, 0, BaseEncoding)
}

// SerializeNoWitness encodes a block to w using an identical format to
// Serialize, with all (if any) witness data stripped from all transactions.
// This method is provided in additon to the regular Serialize, in order to
// allow one to selectively encode transaction witness data to non-upgraded
// peers which are unaware of the new encoding.
func (msg *MsgBlock) SerializeNoWitness(w io.Writer) error {
	return msg.BtcEncode(w, 0, BaseEncoding)
}

// SerializeSize returns the number of bytes it would take to serialize the
// block, factoring in any witness data within transaction.
func (msg *MsgBlock) SerializeSize() int {
	// Block header bytes + Serialized varint size for the number of
	// transactions.
	// todo: (EthashPow)
	// n := blockHeaderLen + VarIntSerializeSize(uint64(len(msg.Transactions)))
	n := blockHeaderLen
	// todo(MLP):
	if msg.Header.Version >= int32(BlockVersionEthashPow) {
		n = blockHeaderLenEthash
	}
	n += VarIntSerializeSize(uint64(len(msg.Transactions)))

	for _, tx := range msg.Transactions {
		n += tx.SerializeSize()
	}

	return n
}

// SerializeSizeStripped returns the number of bytes it would take to serialize
// the block, excluding any witness data (if any).
func (msg *MsgBlock) SerializeSizeStripped() int {
	// Block header bytes + Serialized varint size for the number of
	// transactions.
	//	todo: (EthashPoW)
	//n := blockHeaderLen + VarIntSerializeSize(uint64(len(msg.Transactions)))
	n := blockHeaderLen
	// todo(MLP):
	if msg.Header.Version >= int32(BlockVersionEthashPow) {
		n = blockHeaderLenEthash
	}
	n += VarIntSerializeSize(uint64(len(msg.Transactions)))

	for _, tx := range msg.Transactions {
		n += tx.SerializeSizeStripped()
	}

	return n
}
func (msg *MsgBlockAbe) SerializeSizeStripped() int {
	// Block header bytes + Serialized varint size for the number of
	// transactions.
	// todo: (EthashPoW)
	//n := blockHeaderLen + VarIntSerializeSize(uint64(len(msg.Transactions)))
	n := blockHeaderLen
	// todo(MLP):
	if msg.Header.Version >= int32(BlockVersionEthashPow) {
		n = blockHeaderLenEthash
	}
	n += VarIntSerializeSize(uint64(len(msg.Transactions)))

	for _, tx := range msg.Transactions {
		n += tx.SerializeSize()
	}

	return n
}

func (msg *MsgBlockAbe) Serialize(w io.Writer) error {
	return msg.BtcEncode(w, 0, WitnessEncoding)
	//err := msg.Header.Serialize(w)
	//if err != nil {
	//	return err
	//}
	//
	//err = WriteVarInt(w, 0, uint64(len(msg.Transactions)))
	//if err != nil {
	//	return err
	//}
	//// TODO(abe): when transfer the block to others, whether transfer the witnesses?
	////   In one hand, the transaction may have be transferred before being packaged into block, so does the witness
	////   In other hand, the transaction should not be transfer more than one time.
	////   But the question is, how can we know whether the peer have transactions or witnesses?
	//
	//// TODO(abe): at this moment, we transfer the transaction with witnesses all time.
	//for _, tx := range msg.Transactions {
	//	//err = tx.Serialize(w)
	//	err = tx.SerializeFull(w)
	//	if err != nil {
	//		return err
	//	}
	//}
	//
	//return nil
}

// SerializeSize returns the number of bytes it would take to serialize the
// block, factoring in any witness data within transaction.
func (msg *MsgBlockAbe) SerializeSize() int {
	// Block header bytes + Serialized varint size for the number of
	// transactions.
	// todo: (EthashPoW)
	// n := blockHeaderLen + VarIntSerializeSize(uint64(len(msg.Transactions)))
	n := blockHeaderLen
	// todo(MLP):
	if msg.Header.Version >= int32(BlockVersionEthashPow) {
		n = blockHeaderLenEthash
	}
	n += VarIntSerializeSize(uint64(len(msg.Transactions)))

	for _, tx := range msg.Transactions {
		n += tx.SerializeSizeFull() // to do, may remove the serializeType
	}

	return n
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *MsgBlock) Command() string {
	return CmdBlock
}

func (msg *MsgBlockAbe) Command() string {
	return CmdBlock
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *MsgBlock) MaxPayloadLength(pver uint32) uint32 {
	// Block header at 80 bytes + transaction count + max transactions
	// which can vary up to the MaxBlockPayload (including the block header
	// and transaction count).
	return MaxBlockPayload
}

func (msg *MsgBlockAbe) MaxPayloadLength(pver uint32) uint32 {
	// Block header at 80 bytes + transaction count + max transactions
	// which can vary up to the MaxBlockPayload (including the block header
	// and transaction count).
	return MaxBlockPayloadAbe
}

// BlockHash computes the block identifier hash for this block.
func (msg *MsgBlock) BlockHash() chainhash.Hash {
	return msg.Header.BlockHash()
}

func (msg *MsgBlockAbe) BlockHash() chainhash.Hash {
	return msg.Header.BlockHash()
}

func (msg *MsgBlockAbe) HasWitness() bool {
	witness := msg.Transactions[0].TxWitness
	if witness != nil && len(witness) != 0 {
		return true
	}
	return false
}

// TxHashes returns a slice of hashes of all of transactions in this block.
func (msg *MsgBlock) TxHashes() ([]chainhash.Hash, error) {
	hashList := make([]chainhash.Hash, 0, len(msg.Transactions))
	for _, tx := range msg.Transactions {
		hashList = append(hashList, tx.TxHash())
	}
	return hashList, nil
}

// NewMsgBlock returns a new bitcoin block message that conforms to the
// Message interface.  See MsgBlock for details.
func NewMsgBlock(blockHeader *BlockHeader) *MsgBlock {
	return &MsgBlock{
		Header:       *blockHeader,
		Transactions: make([]*MsgTx, 0, defaultTransactionAlloc),
	}
}

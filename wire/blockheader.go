package wire

import (
	"bytes"
	"io"
	"time"

	"github.com/abesuite/abec/chainhash"
)

// MaxBlockHeaderPayload is the maximum number of bytes a block header can be.
// Version 4 bytes + Timestamp 4 bytes + Bits 4 bytes + Nonce 4 bytes +
// PrevBlock and MerkleRoot hashes.
// todo: (EthashPoW) set this value to be a variable. Note that this value is used for mining (i.e., frequently called).
const MaxBlockHeaderPayload = 16 + (chainhash.HashSize * 2)

//	todo: (EthashPoW)
//
// Version 4 bytes + Timestamp 4 bytes + Bits 4 bytes + NonceExt 8 bytes + Height 4 bytes
// PrevBlock, MerkleRoot, and MixDigest hashes
const MaxBlockHeaderPayloadEthash = 24 + (chainhash.HashSize * 3)

// BlockHeader defines information about a block and is used in the bitcoin
// block (MsgBlock) and headers (MsgHeaders) messages.
type BlockHeader struct {
	// Version of the block.  This is not the same as the protocol version.
	Version int32

	// Hash of the previous block header in the block chain.
	PrevBlock chainhash.Hash

	// Merkle tree reference to hash of all transactions for the block.
	MerkleRoot chainhash.Hash

	// Time the block was created.  This is, unfortunately, encoded as a
	// uint32 on the wire and therefore is limited to 2106.
	Timestamp time.Time

	// Difficulty target for the block.
	Bits uint32

	//  todo: (EthashPoW)
	//	For EthashPoW, block height is an important and frequently accessed parameter, then is added as a field.
	Height int32

	// Nonce used to generate the block.
	Nonce uint32

	//	todo: (EthashPoW)
	//	For EthashPoW, Nonce is not used anymore, instead, we use NonceExt.
	NonceExt uint64 `json:"nonceExt"`

	//	MixDigest is a part of the EthashPoW. It is decided by previous fields, that is why we put it at the last position.
	MixDigest chainhash.Hash `json:"mixHash"`
}

// blockHeaderLen is a constant that represents the number of bytes for a block
// header.
const blockHeaderLen = 80

// todo: (EthashPoW)
const blockHeaderLenEthash = 120 // 4 + 2*32 + 4 + 4 + 4 + 8 + 32

const blockHeaderContentLen = 80 // 4 + 2*32 + 4 + 4 + 4

// BlockHash computes the block identifier hash for the given block header.
func (h *BlockHeader) BlockHash() chainhash.Hash {
	// Encode the header and double sha256 everything prior to the number of
	// transactions.  Ignore the error returns since there is no way the
	// encode could fail except being out of memory which would cause a
	// run-time panic.

	// todo: (EthashPoW) BlockHash() is called by many places, such as validate, it is necessary to have an if-else here,
	// to avoid modifying everywhere to call BlockHashETHash().
	//	Here it is necessary to use version rather than height, since the blocks before the update do not have a meaningful height.
	// todo(MLP):
	if h.Version >= int32(BlockVersionEthashPow) {
		return h.BlockHashEthash()
	}

	buf := bytes.NewBuffer(make([]byte, 0, blockHeaderLen))
	_ = writeBlockHeader(buf, 0, h)

	return chainhash.DoubleHashH(buf.Bytes())
}

// todo: (EthashPoW)
//
//	We separate this as a standalone funciton, since when mining, this funciton will be called very frequently.
//	In mining, this funciton, rather than the original BlockHash() is called.
//	Actually, this method is not called in mining. Just keeping here for completeness.
func (h *BlockHeader) BlockHashEthash() chainhash.Hash {
	// Encode the header and double sha256 everything prior to the number of
	// transactions.  Ignore the error returns since there is no way the
	// encode could fail except being out of memory which would cause a
	// run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, blockHeaderLenEthash))
	_ = writeBlockHeaderEthash(buf, 0, h)

	return chainhash.ChainHash(buf.Bytes())
}

// todo: (EthashPoW)
// ContentHash returns the hash of a block prior to it being sealed.
// Ignore the error returns since there is no way the
// encode could fail except being out of memory which would cause a
// run-time panic.
func (h *BlockHeader) ContentHash() chainhash.Hash {

	buf := bytes.NewBuffer(make([]byte, 0, blockHeaderContentLen))

	sec := uint32(h.Timestamp.Unix())
	_ = writeElements(buf, h.Version, &h.PrevBlock, &h.MerkleRoot,
		sec, h.Bits, h.Height)

	return chainhash.ChainHash(buf.Bytes())
}

func (h *BlockHeader) ContentHashExcludeTime() chainhash.Hash {

	buf := bytes.NewBuffer(make([]byte, 0, blockHeaderContentLen))

	_ = writeElements(buf, h.Version, &h.PrevBlock, &h.MerkleRoot, h.Bits, h.Height)

	return chainhash.ChainHash(buf.Bytes())
}

// BtcDecode decodes r using the bitcoin protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See Deserialize for decoding block headers stored to disk, such as in a
// database, as opposed to decoding block headers from the wire.
func (h *BlockHeader) BtcDecode(r io.Reader, pver uint32, enc MessageEncoding) error {
	return readBlockHeader(r, pver, h)
}

// BtcEncode encodes the receiver to w using the bitcoin protocol encoding.
// This is part of the Message interface implementation.
// See Serialize for encoding block headers to be stored to disk, such as in a
// database, as opposed to encoding block headers for the wire.
func (h *BlockHeader) BtcEncode(w io.Writer, pver uint32, enc MessageEncoding) error {
	return writeBlockHeader(w, pver, h)
}

// Deserialize decodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *BlockHeader) Deserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of readBlockHeader.
	return readBlockHeader(r, 0, h)
}

// Serialize encodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field.
func (h *BlockHeader) Serialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of writeBlockHeader.
	return writeBlockHeader(w, 0, h)
}

// NewBlockHeader returns a new BlockHeader using the provided version, previous
// block hash, merkle root hash, difficulty bits, and nonce used to generate the
// block with defaults for the remaining fields.
func NewBlockHeader(version int32, prevHash, merkleRootHash *chainhash.Hash,
	bits uint32, nonce uint32) *BlockHeader {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	return &BlockHeader{
		Version:    version,
		PrevBlock:  *prevHash,
		MerkleRoot: *merkleRootHash,
		Timestamp:  time.Unix(time.Now().Unix(), 0),
		Bits:       bits,
		Nonce:      nonce,
	}
}

// todo: (EthashPoW)
func NewBlockHeaderEthash(version int32, prevHash, merkleRootHash *chainhash.Hash,
	bits uint32, height int32, nonceExt uint64, mixDigest *chainhash.Hash) *BlockHeader {

	// Limit the timestamp to one second precision since the protocol
	// doesn't support better.
	return &BlockHeader{
		Version:    version,
		PrevBlock:  *prevHash,
		MerkleRoot: *merkleRootHash,
		Timestamp:  time.Unix(time.Now().Unix(), 0),
		Bits:       bits,
		Height:     height,
		NonceExt:   nonceExt,
		MixDigest:  *mixDigest,
	}
}

// readBlockHeader reads a bitcoin block header from r.  See Deserialize for
// decoding block headers stored to disk, such as in a database, as opposed to
// decoding from the wire.
//
//	todo: (EthashPoW)
func readBlockHeader(r io.Reader, pver uint32, bh *BlockHeader) error {

	// first read the version
	err := readElement(r, &bh.Version)
	if err != nil {
		return err
	}

	//	read the remainder fields according to the version
	// todo(MLP):
	if bh.Version >= int32(BlockVersionEthashPow) {
		return readElements(r, &bh.PrevBlock, &bh.MerkleRoot,
			(*uint32Time)(&bh.Timestamp), &bh.Bits, &bh.Height, &bh.NonceExt, &bh.MixDigest)
	}

	return readElements(r, &bh.PrevBlock, &bh.MerkleRoot,
		(*uint32Time)(&bh.Timestamp), &bh.Bits, &bh.Nonce)

	//return readElements(r, &bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
	//	(*uint32Time)(&bh.Timestamp), &bh.Bits, &bh.Nonce)
}

// writeBlockHeader writes a bitcoin block header to w.  See Serialize for
// encoding block headers to be stored to disk, such as in a database, as
// opposed to encoding for the wire.
//
//	todo: (EthashPoW)
func writeBlockHeader(w io.Writer, pver uint32, bh *BlockHeader) error {
	sec := uint32(bh.Timestamp.Unix())

	// todo(MLP):
	if bh.Version >= int32(BlockVersionEthashPow) {
		return writeElements(w, bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
			sec, bh.Bits, bh.Height, bh.NonceExt, bh.MixDigest)
		//	The codes here should be the same as that in writeBlockHeaderEthash().
		//	We directly copy the codes, rather than call writeBlockHeaderEthash(), to reduce function calls.
		//return writeBlockHeaderEthash(w, pver, bh)
	}

	return writeElements(w, bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
		sec, bh.Bits, bh.Nonce)
}

// todo: (EthashPoW)
func writeBlockHeaderEthash(w io.Writer, pver uint32, bh *BlockHeader) error {
	sec := uint32(bh.Timestamp.Unix())
	return writeElements(w, bh.Version, &bh.PrevBlock, &bh.MerkleRoot,
		sec, bh.Bits, bh.Height, bh.NonceExt, bh.MixDigest)
}

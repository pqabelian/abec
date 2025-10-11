package wire

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/abesuite/abec/chainhash"
)

// ConsensusProtocol defines a type to denote the consensus options.
//
// Note that we must define ConsensusNakamotoPow as the first/default consensus.
// this is because we define BlockHeader.PowScaleSecond to denote that "1 Consensus-2's Pow = PowScaleSecond * Consensus-2's Pow",
// i.e., Consensus-1 should be the easiest one, and it will serve as the base unit.
type ConsensusProtocol byte

const (
	ConsensusNone        ConsensusProtocol = 0
	ConsensusNakamotoPow ConsensusProtocol = 1
	ConsensusEthashPow   ConsensusProtocol = 2
)

const (
	NonceDummy          uint32 = 0
	HeightDummy         int32  = -1
	NonceExtDummy       uint64 = 0
	BitsSecondDummy     uint32 = 0
	PowScaleSecondDummy uint32 = 0
)

var MixDigestDummy chainhash.Hash = chainhash.InvalidHash // different pointer, same content

// BlockHeader defines information about a block and is used in the bitcoin
// block (MsgBlock) and headers (MsgHeaders) messages.
type BlockHeader struct {
	// Version of the block.  This is not the same as the protocol version.
	Version int32

	// Hash of the previous block header in the block chain.
	PrevBlock chainhash.Hash

	// Merkle tree reference to hash of all transactions for the block.
	MerkleRoot chainhash.Hash

	// Time the block was created.
	// This is, unfortunately, encoded as uint32 on the wire and therefore is limited to 2106.
	// It is serialized to 64-bits for version >= BlockVersionAconcagua, and 32-bits otherwise.
	Timestamp time.Time

	// Height of the block.
	// For Ethash-PoW, block height is an important and frequently accessed parameter,
	// thus, since Ethash-PoW-fork, Height is added as a field of BlockHeader.
	Height int32

	// Difficulty target for the PoWConsensus-1.
	// In the initial version, this is for NakamotoPoWInit;
	// In the EthashPow-fork, this is for EthashPow;
	// In the Aconcagua-fork, this is for NakamotoPoWAconcagua.
	Bits uint32

	// Difficulty target for the PoWConsensus-2 in Aconcagua-fork, particularly, forEthashPow.
	BitsSecond uint32
	// PowScale of EthashPow to NakamotoPoWAconcagua.
	PowScaleSecond uint32

	// ConsensusApplied specifies the ConsensusProtocol that this block applies in Aconcagua-fork.
	ConsensusApplied ConsensusProtocol

	// Nonce used to generate the block.
	// This is used in the initial NakamotoPoW, and is deprecated since EthashPoW-fork.
	Nonce uint32

	// NonceExt is used to mine.
	// Since EthashPoW-fork, Nonce is not used anymore, instead, NonceExt is used.
	NonceExt uint64 `json:"nonceExt"`

	// MixDigest is a part of the EthashPoW.
	// It is decided by previous fields, that is why we put it at the last position.
	MixDigest chainhash.Hash `json:"mixHash"`
}

const blockHeaderContentLen = 80 // 4 + 2*32 + 4 + 4 + 4

const (
	// blockHeaderSizeInit is a constant that represents the number of bytes for a block header,
	// for Initial Nakamoto-PoW.
	// Version 4 bytes + PrevBlock + MerkleRoot + Timestamp 4 bytes + Bits 4 bytes + Nonce 4 bytes.
	// 4 + 2*32 + 3*4
	blockHeaderSizeInit = 80

	// blockHeaderSizeEthash is a constant that represents the number of bytes for a block header,
	// for Ethash-PoW.
	// Version 4 bytes + PrevBlock + MerkleRoot + Timestamp 4 bytes + Bits 4 bytes +
	// Height 4 bytes + NonceExt 8 bytes + MixDigest
	// 4 + 2*32 + 2*4 + 4 + 8 + 32
	blockHeaderSizeEthash = 120 // 4 + 2*32 + 4 + 4 + 4 + 8 + 32name =

	// blockHeaderSizeAconcagua is a constant that represents the number of bytes for a block header,
	// for Hybird-Pow from Aconcagua fork.
	// Version 4 bytes + PrevBlock + MerkleRoot + Timestamp 8 bytes + Height 4 bytes +
	// Bits 4 bytes + BitsSecond 4 bytes + PowScaleSecond 4 bytes + ConsensusApplied 1 byte +
	// NonceExt 8 bytes + MixDigest
	// 4 + 2*32 + 8 + 4 +
	// 3*4 + 1 +
	// 8 + 32
	blockHeaderSizeAconcagua = 133
)

// GetBlockHeaderSize returns the blockHeader size corresponding to the input block version.
func GetBlockHeaderSize(blockVersion int32) int {

	if blockVersion >= int32(BlockVersionAconcagua) {
		return blockHeaderSizeAconcagua
	}

	if blockVersion >= int32(BlockVersionEthashPow) {
		return blockHeaderSizeEthash
	}

	return blockHeaderSizeInit
}

// GetBlockHeaderSizeMax returns the maximum of blockHeader sizes for different version blockHeaders.
//
// In some cases, the block version is not available, and it is sufficient to get the maximum of blockHeader size.
func GetBlockHeaderSizeMax() int {
	//return blockHeaderSizeEthash
	return blockHeaderSizeAconcagua
}

// BlockHash computes the block identifier hash for the given block header,
// which is also used to form the chain of blocks.
//
// In abelian, for each block, beside the BlockHash, there is another concept, say SealHash. In particular,
//   - BlockHash denotes the identifier of a block, computed by hashing all the fields in blockHeader.
//   - SealHash shows that the PoW of a block achieves the target for validity, computed by corresponding PoW consensus.
//
// Particularly, for block with version < BlockVersionEthashPow, the BlockHash and SealHash of a block are the same.
func (bh *BlockHeader) BlockHash() chainhash.Hash {
	// Encode the header and hash everything prior to the number of transactions.
	// Ignore the error returns since there is no way the encode could fail
	// except being out of memory which would cause a run-time panic.

	// Here it is necessary to use version rather than height,
	// since the blocks before the EthashPoW-fork do not have a meaningful height.

	// Here we use three explicit sub-routines to generate the BlockHash for different forks.

	if bh.Version >= int32(BlockVersionAconcagua) {
		return bh.blockHashAconcagua()
	}

	if bh.Version >= int32(BlockVersionEthashPow) {
		return bh.blockHashEthash()
	}

	//	Initial version
	return bh.blockHashInit()
}

// blockHashAconcagua computes the block identifier hash for the given block header with version>=BlockVersionAconcagua,
// using ChainHash, which is actually SHA3-256.
//
// The caller needs to guarantee the BlockHeader.Version >= BlockVersionAconcagua,
// as this function does not perform checks and just compute and return the hash.
func (bh *BlockHeader) blockHashAconcagua() chainhash.Hash {
	// Encode the header and ChainHash everything prior to the number of transactions.
	// Ignore the error returns since there is no way the encode could fail
	// except being out of memory which would cause a run-time panic.

	buf := bytes.NewBuffer(make([]byte, 0, blockHeaderSizeAconcagua))
	_ = bh.WriteBlockHeader(buf, 0)

	// todo: handle the errors explicitly, for example, panic, rather than return uncontrolled hash

	return chainhash.ChainHash(buf.Bytes())
}

// blockHashEthash computes the block identifier hash for the given block header
// with BlockVersionEthashPow <= version < BlockVersionAconcagua,
// using ChainHash, which is actually SHA3-256.
//
// The caller needs to guarantee the BlockHeader.Version >= BlockVersionEthashPow,
// as this function does not perform checks and just compute and return the hash.
func (bh *BlockHeader) blockHashEthash() chainhash.Hash {
	// Encode the header and ChainHash everything prior to the number of transactions.
	// Ignore the error returns since there is no way the encode could fail
	// except being out of memory which would cause a run-time panic.
	buf := bytes.NewBuffer(make([]byte, 0, blockHeaderSizeEthash))
	_ = bh.WriteBlockHeader(buf, 0)

	// todo: handle the errors explicitly, for example, panic, rather than return uncontrolled hash

	return chainhash.ChainHash(buf.Bytes())
}

// blockHashInit computes the block identifier hash for the given block header with version < BlockVersionEthashPow,
// using DoubleHash, which is actually double-SHA256.
//
// The caller needs to guarantee the BlockHeader.Version < BlockVersionEthashPow,
// as this function does not perform checks and just compute and return the hash.
func (bh *BlockHeader) blockHashInit() chainhash.Hash {
	// Encode the header and double sha256 everything prior to the number of transactions.
	// Ignore the error returns since there is no way the encode could fail
	// except being out of memory which would cause a run-time panic.

	//	the initial computation of BlockHash
	buf := bytes.NewBuffer(make([]byte, 0, blockHeaderSizeInit))
	_ = bh.WriteBlockHeader(buf, 0)

	// todo: handle the errors explicitly, for example, panic, rather than return uncontrolled hash

	return chainhash.DoubleHashH(buf.Bytes())
}

// HeaderContent returns the block's HeaderContent,
// which means the "fixed" business data in BlockHeader, excluding the nonce fields.
//
// HeaderContent will server as the payload that the consensus to seal by melting nonce fields on it.
// In particular,
//   - for block with version >= BlockVersionEthashPow, HeaderContent means the blockHeader's fields excluding NonceExt and MixDigest.
//   - for block with version < BlockVersionEthashPow, HeaderContent means the blockHeader's fields excluding Nonce.
//
// The codes in this function must be identical to that of WriteBlockHeader, except that the nonce fields are excluded.
// Note that WriteBlockHeader is the unified underlying entrance for Serialize and BlockHash,
// as well as the Write, Encode, and Serialize functions for MsgBlock.
func (bh *BlockHeader) HeaderContent() ([]byte, error) {

	var err error = nil

	// here we use the BlockHeaderSize which is a little larger than HeaderContent's Size.
	// this inaccuracy is not a problem.
	w := bytes.NewBuffer(make([]byte, 0, GetBlockHeaderSize(bh.Version)))

	if bh.Version >= int32(BlockVersionAconcagua) {
		sec64 := bh.Timestamp.Unix()
		err = writeElements(w,
			bh.Version, &bh.PrevBlock, &bh.MerkleRoot, sec64, bh.Height,
			bh.Bits, bh.BitsSecond, bh.PowScaleSecond, bh.ConsensusApplied)

	} else if bh.Version >= int32(BlockVersionEthashPow) {
		sec32 := uint32(bh.Timestamp.Unix())
		err = writeElements(w,
			bh.Version, &bh.PrevBlock, &bh.MerkleRoot, sec32, bh.Bits, bh.Height)

	} else { // for bh.Version < int32(BlockVersionEthashPow)
		sec32 := uint32(bh.Timestamp.Unix())
		err = writeElements(w,
			bh.Version, &bh.PrevBlock, &bh.MerkleRoot, sec32, bh.Bits)
	}

	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// HeaderContentExcludeTimestamp returns the blockHeader's HeaderContent excluding the timestamp.
//
// The codes in this function must be identical to that of WriteBlockHeader,
// except that the nonce fields and timestamp are excluded.
// Note that WriteBlockHeader is the unified underlying entrance for Serialize and BlockHash,
// as well as the Write, Encode, and Serialize functions for MsgBlock.
//
// This is a helper function, for example, for mining modules.
func (bh *BlockHeader) HeaderContentExcludeTimestamp() ([]byte, error) {

	var err error = nil
	// here we use the BlockHeaderSize which is a little larger than HeaderContent's Size.
	// this inaccuracy is not a problem.
	w := bytes.NewBuffer(make([]byte, 0, GetBlockHeaderSize(bh.Version)))

	if bh.Version >= int32(BlockVersionAconcagua) {
		err = writeElements(w,
			bh.Version, &bh.PrevBlock, &bh.MerkleRoot, bh.Height,
			bh.Bits, bh.BitsSecond, bh.PowScaleSecond, bh.ConsensusApplied)

	} else if bh.Version >= int32(BlockVersionEthashPow) {
		err = writeElements(w,
			bh.Version, &bh.PrevBlock, &bh.MerkleRoot, bh.Bits, bh.Height)

	} else { // for bh.Version < int32(BlockVersionEthashPow)
		err = writeElements(w,
			bh.Version, &bh.PrevBlock, &bh.MerkleRoot, bh.Bits)
	}

	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// WriteBlockHeader writes an abelian blockHeader to w.
// Write function provides functions for Serialize functions, as well as
func (bh *BlockHeader) WriteBlockHeader(w io.Writer, pver uint32) error {

	var err error = nil

	if bh.Version >= int32(BlockVersionAconcagua) {
		sec64 := bh.Timestamp.Unix()
		err = writeElements(w,
			bh.Version, &bh.PrevBlock, &bh.MerkleRoot, sec64, bh.Height,
			bh.Bits, bh.BitsSecond, bh.PowScaleSecond, bh.ConsensusApplied,
			bh.NonceExt, &bh.MixDigest)

	} else if bh.Version >= int32(BlockVersionEthashPow) {
		sec32 := uint32(bh.Timestamp.Unix())
		err = writeElements(w,
			bh.Version, &bh.PrevBlock, &bh.MerkleRoot, sec32, bh.Bits, bh.Height,
			bh.NonceExt, &bh.MixDigest)

	} else { // for bh.Version < int32(BlockVersionEthashPow)
		sec32 := uint32(bh.Timestamp.Unix())
		err = writeElements(w,
			bh.Version, &bh.PrevBlock, &bh.MerkleRoot, sec32, bh.Bits,
			bh.Nonce)
	}

	return err

}

// ReadBlockHeader reads an abelian blockHeader from r.
// Write function provides functions for Decode and Deserialize functions.
func (bh *BlockHeader) ReadBlockHeader(r io.Reader, pver uint32) error {

	// first read the version
	err := readElement(r, &bh.Version)
	if err != nil {
		return err
	}

	//	read the remainder fields according to the version
	if bh.Version >= int32(BlockVersionAconcagua) {
		err = readElements(r,
			&bh.PrevBlock, &bh.MerkleRoot, (*int64Time)(&bh.Timestamp), &bh.Height,
			&bh.Bits, &bh.BitsSecond, &bh.PowScaleSecond, &bh.ConsensusApplied,
			&bh.NonceExt, &bh.MixDigest)

		bh.Nonce = NonceDummy // this value does not make sense for  Version >= int32(BlockVersionAconcagua)

	} else if bh.Version >= int32(BlockVersionEthashPow) {
		err = readElements(r,
			&bh.PrevBlock, &bh.MerkleRoot, (*uint32Time)(&bh.Timestamp), &bh.Bits, &bh.Height,
			&bh.NonceExt, &bh.MixDigest)

		bh.ConsensusApplied = ConsensusNone     // this value does not make sense for  Version < int32(BlockVersionAconcagua)
		bh.BitsSecond = BitsSecondDummy         // this value does not make sense for  Version < int32(BlockVersionAconcagua)
		bh.PowScaleSecond = PowScaleSecondDummy // this value does not make sense for  Version < int32(BlockVersionAconcagua)
		bh.Nonce = NonceDummy                   // this value does not make sense for  Version < int32(BlockVersionAconcagua)

	} else {
		err = readElements(r,
			&bh.PrevBlock, &bh.MerkleRoot, (*uint32Time)(&bh.Timestamp), &bh.Bits,
			&bh.Nonce)

		bh.BitsSecond = BitsSecondDummy         // this value does not make sense for  Version < int32(BlockVersionEthashPow)
		bh.PowScaleSecond = PowScaleSecondDummy // this value does not make sense for  Version < int32(BlockVersionEthashPow)
		bh.ConsensusApplied = ConsensusNone     // this value does not make sense for  Version < int32(BlockVersionEthashPow)
		bh.Height = HeightDummy                 // this value does not make sense for  Version < int32(BlockVersionEthashPow)
		bh.NonceExt = NonceExtDummy             // this value does not make sense for  Version < int32(BlockVersionEthashPow)
		bh.MixDigest = MixDigestDummy           // this value does not make sense for  Version < int32(BlockVersionEthashPow)
	}

	return err
}

// SerializeSize returns the serialize size of BlockHeader,
// corresponding to WriteBlockHeader/Serialize.
func (bh *BlockHeader) SerializeSize() int {
	return GetBlockHeaderSize(bh.Version)
}

// Serialize encodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting the Version field.
func (bh *BlockHeader) Serialize() ([]byte, error) {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.
	// As a result, make use of WriteBlockHeader.

	// return WriteBlockHeader(w, 0, h)

	w := bytes.NewBuffer(make([]byte, 0, bh.SerializeSize()))

	err := bh.WriteBlockHeader(w, 0)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// Deserialize decodes a block header from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting the Version field.
func (bh *BlockHeader) Deserialize(serializedBlockHeader []byte) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.
	// As a result, make use of ReadBlockHeader.

	// return ReadBlockHeader(r, 0, h)

	if len(serializedBlockHeader) == 0 {
		return fmt.Errorf("Deserialize: the input serializedTx is nil/empty")
	}

	r := bytes.NewReader(serializedBlockHeader)

	return bh.ReadBlockHeader(r, 0)

}

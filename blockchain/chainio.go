package blockchain

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/pqabelian/abec/abecryptox/abecryptoxparam"
	"github.com/pqabelian/abec/abeutil"
	"github.com/pqabelian/abec/aut"
	"github.com/pqabelian/abec/chainhash"
	"github.com/pqabelian/abec/database"
	"github.com/pqabelian/abec/wire"
	"io"
	"math"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// blockHdrSize is the size of a block header.  This is simply the
	// constant from wire and is only provided here for convenience since
	// wire.MaxBlockHeaderPayload is quite long.
	//	todo: (EthashPoW) all codes related to blockHdrSize need to be modified.
	blockHdrSize = wire.MaxBlockHeaderPayloadEthash

	// latestUtxoSetBucketVersion is the current version of the utxo set
	// bucket that is used to track all unspent outputs.
	latestUtxoSetBucketVersion = 2
	//	todo(ABE)
	latestUtxoRingSetBucketVersion = 1

	// latestSpendJournalBucketVersion is the current version of the spend
	// journal bucket that is used to track all spent transactions for use
	// in reorgs.
	latestSpendJournalBucketVersion = 1
)

var (
	// blockIndexBucketName is the name of the db bucket used to house to the
	// block headers and contextual information.
	blockIndexBucketName = []byte("blockheaderidx")

	// hashIndexBucketName is the name of the db bucket used to house to the
	// block hash -> block height index.
	hashIndexBucketName = []byte("hashidx")

	// heightIndexBucketName is the name of the db bucket used to house to
	// the block height -> block hash index.
	heightIndexBucketName = []byte("heightidx")

	// chainStateKeyName is the name of the db key used to store the best
	// chain state.
	chainStateKeyName = []byte("chainstate")

	// spendJournalVersionKeyName is the name of the db key used to store
	// the version of the spend journal currently in the database.
	spendJournalVersionKeyName = []byte("spendjournalversion")

	// spendJournalBucketName is the name of the db bucket used to house
	// transactions outputs that are spent in each block.
	spendJournalBucketName = []byte("spendjournal")

	// utxoSetVersionKeyName is the name of the db key used to store the
	// version of the utxo set currently in the database.
	utxoSetVersionKeyName = []byte("utxosetversion")

	// utxoSetBucketName is the name of the db bucket used to house the
	// unspent transaction output set.
	utxoSetBucketName = []byte("utxosetv2")

	// utxoSetVersionKeyName is the name of the db key used to store the
	// version of the utxo set currently in the database.
	utxoRingSetVersionKeyName = []byte("utxoringsetversion")

	// utxoRIngSetBucketName is the name of the db bucket used to house the
	// unspent transaction output ring set.
	//	todo(ABE):
	utxoRingSetBucketName = []byte("utxoringset")

	// deletedWitnessFileBucketName is the name of the db key used to store
	// the delete history of witness files.
	deletedWitnessFileBucketName = []byte("deletedwitnessfile")

	// fakePowHeightScopeBucketName is the bucket used internally to track fake pow for block
	// format: start_end:start_end:start_end
	fakePowHeightScopeBucketName = []byte("fakepowheightscopes")

	workedFakePowHeightScopeKeyName = []byte("workedfakepowheightscopes")
	readyFakePowHeightScopeKeyName  = []byte("readyfakepowheightscopes")

	// autCoinBucketName is the name of the db bucket used to house the
	// Abelian User Token (AUT) state
	autInfoBucketName         = []byte("autinfo")
	autRootCoinBucketName     = []byte("autrootcoinset")
	autCoinBucketName         = []byte("autcoin")
	autSpendJournalBucketName = []byte("autspendjournal")
	// byteOrder is the preferred byte order used for serializing numeric
	// fields for storage in the database.
	byteOrder = binary.LittleEndian
)

// errNotInMainChain signifies that a block hash or height that is not in the
// main chain was requested.
type errNotInMainChain string

// Error implements the error interface.
func (e errNotInMainChain) Error() string {
	return string(e)
}

// isNotInMainChainErr returns whether or not the passed error is an
// errNotInMainChain error.
func isNotInMainChainErr(err error) bool {
	_, ok := err.(errNotInMainChain)
	return ok
}

// errDeserialize signifies that a problem was encountered when deserializing
// data.
type errDeserialize string

// Error implements the error interface.
func (e errDeserialize) Error() string {
	return string(e)
}

// isDeserializeErr returns whether or not the passed error is an errDeserialize
// error.
func isDeserializeErr(err error) bool {
	_, ok := err.(errDeserialize)
	return ok
}

// isDbBucketNotFoundErr returns whether or not the passed error is a
// database.Error with an error code of database.ErrBucketNotFound.
func isDbBucketNotFoundErr(err error) bool {
	dbErr, ok := err.(database.Error)
	return ok && dbErr.ErrorCode == database.ErrBucketNotFound
}

// dbFetchVersion fetches an individual version with the given key from the
// metadata bucket.  It is primarily used to track versions on entities such as
// buckets.  It returns zero if the provided key does not exist.
func dbFetchVersion(dbTx database.Tx, key []byte) uint32 {
	serialized := dbTx.Metadata().Get(key)
	if serialized == nil {
		return 0
	}

	return byteOrder.Uint32(serialized[:])
}

// dbPutVersion uses an existing database transaction to update the provided
// key in the metadata bucket to the given version.  It is primarily used to
// track versions on entities such as buckets.
func dbPutVersion(dbTx database.Tx, key []byte, version uint32) error {
	var serialized [4]byte
	byteOrder.PutUint32(serialized[:], version)
	return dbTx.Metadata().Put(key, serialized[:])
}

// dbFetchOrCreateVersion uses an existing database transaction to attempt to
// fetch the provided key from the metadata bucket as a version and in the case
// it doesn't exist, it adds the entry with the provided default version and
// returns that.  This is useful during upgrades to automatically handle loading
// and adding version keys as necessary.
func dbFetchOrCreateVersion(dbTx database.Tx, key []byte, defaultVersion uint32) (uint32, error) {
	version := dbFetchVersion(dbTx, key)
	if version == 0 {
		version = defaultVersion
		err := dbPutVersion(dbTx, key, version)
		if err != nil {
			return 0, err
		}
	}

	return version, nil
}

// -----------------------------------------------------------------------------
// The transaction spend journal consists of an entry for each block connected
// to the main chain which contains the transaction outputs the block spends
// serialized such that the order is the reverse of the order they were spent.
//
// This is required because reorganizing the chain necessarily entails
// disconnecting blocks to get back to the point of the fork which implies
// unspending all of the transaction outputs that each block previously spent.
// Since the utxo set, by definition, only contains unspent transaction outputs,
// the spent transaction outputs must be resurrected from somewhere.  There is
// more than one way this could be done, however this is the most straight
// forward method that does not require having a transaction index and unpruned
// blockchain.
//
// NOTE: This format is NOT self describing.  The additional details such as
// the number of entries (transaction inputs) are expected to come from the
// block itself and the utxo set (for legacy entries).  The rationale in doing
// this is to save space.  This is also the reason the spent outputs are
// serialized in the reverse order they are spent because later transactions are
// allowed to spend outputs from earlier ones in the same block.
//
// The reserved field below used to keep track of the version of the containing
// transaction when the height in the header code was non-zero, however the
// height is always non-zero now, but keeping the extra reserved field allows
// backwards compatibility.
//
// The serialized format is:
//
//   [<header code><reserved><compressed txout>],...
//
//   Field                Type     Size
//   header code          VLQ      variable
//   reserved             byte     1
//   compressed txout
//     compressed amount  VLQ      variable
//     compressed script  []byte   variable
//
// The serialized header code format is:
//   bit 0 - containing transaction is a coinbase
//   bits 1-x - height of the block that contains the spent txout
//
// Example 1:
// From block 170 in main blockchain.
//
//    1300320511db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c
//    <><><------------------------------------------------------------------>
//     | |                                  |
//     | reserved                  compressed txout
//    header code
//
//  - header code: 0x13 (coinbase, height 9)
//  - reserved: 0x00
//  - compressed txout 0:
//    - 0x32: VLQ-encoded compressed amount for 5000000000 (50 BTC)
//    - 0x05: special script type pay-to-pubkey
//    - 0x11...5c: x-coordinate of the pubkey
//
// Example 2:
// Adapted from block 100025 in main blockchain.
//
//    8b99700091f20f006edbc6c4d31bae9f1ccc38538a114bf42de65e868b99700086c64700b2fb57eadf61e106a100a7445a8c3f67898841ec
//    <----><><----------------------------------------------><----><><---------------------------------------------->
//     |    |                         |                        |    |                         |
//     |    reserved         compressed txout                  |    reserved         compressed txout
//    header code                                          header code
//
//  - Last spent output:
//    - header code: 0x8b9970 (not coinbase, height 100024)
//    - reserved: 0x00
//    - compressed txout:
//      - 0x91f20f: VLQ-encoded compressed amount for 34405000000 (344.05 BTC)
//      - 0x00: special script type pay-to-pubkey-hash
//      - 0x6e...86: pubkey hash
//  - Second to last spent output:
//    - header code: 0x8b9970 (not coinbase, height 100024)
//    - reserved: 0x00
//    - compressed txout:
//      - 0x86c647: VLQ-encoded compressed amount for 13761000000 (137.61 BTC)
//      - 0x00: special script type pay-to-pubkey-hash
//      - 0xb2...ec: pubkey hash
// -----------------------------------------------------------------------------

// SpentTxOut contains a spent transaction output and potentially additional
// contextual information such as whether or not it was contained in a coinbase
// transaction, the version of the transaction it was contained in, and which
// block height the containing transaction was included in.  As described in
// the comments above, the additional contextual information will only be valid
// when this spent txout is spending the last unspent output of the containing
// transaction.
type SpentTxOut struct {
	// Amount is the amount of the output.
	Amount int64

	// PkScipt is the the public key script for the output.
	PkScript []byte

	// Height is the height of the the block containing the creating tx.
	Height int32

	// Denotes if the creating tx is a coinbase.
	IsCoinBase bool
}

type SpentTxOutAbe struct {
	//	the serialNumber of spentTxo
	SerialNumber []byte

	//	the utoRing which contains the spentTxo
	//	also containing all information of the utxoRing, e.g., the serialNumber of the txos previously consumed
	UtxoRing *UtxoRingEntry
}

func (spentTxo *SpentTxOutAbe) SerializeSize() int {
	return wire.VarIntSerializeSize(uint64(len(spentTxo.SerialNumber))) + len(spentTxo.SerialNumber) + spentTxo.UtxoRing.SerializeSize()
}

// Serialize
// todo_DONE(MLP): reviewed on 2024.01.04
func (spentTxo *SpentTxOutAbe) Serialize(w io.Writer) error {

	//	the serialNumber of spentTxo
	err := wire.WriteVarBytes(w, 0, spentTxo.SerialNumber)
	//_, err := w.Write(spentTxo.SerialNumber[:])
	if err != nil {
		return err
	}

	err = spentTxo.UtxoRing.Serialize(w)
	if err != nil {
		return err
	}

	return nil
}

// Deserialize
// todo_DONE(MLP): reviewed on 2024.01.04
func (spentTxo *SpentTxOutAbe) Deserialize(r io.Reader) error {
	var err error
	spentTxo.SerialNumber, err = wire.ReadVarBytes(r, 0, abecryptoxparam.MaxAllowedSerialNumberSize, "SpentTxOutAbe.SerialNumber")
	if err != nil {
		return err
	}

	err = spentTxo.UtxoRing.Deserialize(r)
	if err != nil {
		return err
	}

	return nil
}

type SpentAUTType int

const ConsumeToken SpentAUTType = 0
const UpdateInfo SpentAUTType = 1

type SpentAUT interface {
	Type() SpentAUTType
}

type UpdateAUTInfo struct {
	Before *aut.MetaInfo
	After  *aut.MetaInfo

	// Height is the height of the the block containing the creating tx.
	Height int32

	// Denotes if the creating tx is a coinbase.
	IsReRegistration bool
}

func (s *UpdateAUTInfo) Type() SpentAUTType {
	return UpdateInfo
}

type SpentAUTTokens []SpentAUTToken

func (s *SpentAUTTokens) Type() SpentAUTType {
	return ConsumeToken
}

type SpentAUTToken struct {
	// Amount is the amount of the output.
	Amount uint64

	// Height is the height of the the block containing the creating tx.
	Height int32

	// Denotes if the creating tx is a coinbase.
	IsRootCoin bool
}

// FetchSpendJournal attempts to retrieve the spend journal, or the set of
// outputs spent for the target block. This provides a view of all the outputs
// that will be consumed once the target block is connected to the end of the
// main chain.
//
// This function is safe for concurrent access.
func (b *BlockChain) FetchSpendJournal(targetBlock *abeutil.Block) ([]SpentTxOut, error) {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	var spendEntries []SpentTxOut
	err := b.db.View(func(dbTx database.Tx) error {
		var err error

		spendEntries, err = dbFetchSpendJournalEntry(dbTx, targetBlock)
		return err
	})
	if err != nil {
		return nil, err
	}

	return spendEntries, nil
}

func (b *BlockChain) FetchSpendJournalAbe(targetBlock *abeutil.BlockAbe) ([]*SpentTxOutAbe, error) {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	var spendEntries []*SpentTxOutAbe
	err := b.db.View(func(dbTx database.Tx) error {
		var err error

		spendEntries, err = dbFetchSpendJournalEntryAbe(dbTx, targetBlock)
		return err
	})
	if err != nil {
		return nil, err
	}

	return spendEntries, nil
}

func (b *BlockChain) FetchSpendJournalAUT(targetBlock *abeutil.BlockAbe) ([]SpentAUT, error) {
	b.chainLock.RLock()
	defer b.chainLock.RUnlock()

	var spendEntries []SpentAUT
	err := b.db.View(func(dbTx database.Tx) error {
		var err error

		spendEntries, err = dbFetchSpendJournalEntryAUT(dbTx, targetBlock)
		return err
	})
	if err != nil {
		return nil, err
	}

	return spendEntries, nil
}

// spentTxOutHeaderCode returns the calculated header code to be used when
// serializing the provided stxo entry.
func spentTxOutHeaderCode(stxo *SpentTxOut) uint64 {
	// As described in the serialization format comments, the header code
	// encodes the height shifted over one bit and the coinbase flag in the
	// lowest bit.
	headerCode := uint64(stxo.Height) << 1
	if stxo.IsCoinBase {
		headerCode |= 0x01
	}

	return headerCode
}
func spentAUTHeaderCode(stxo *SpentAUTToken) uint64 {
	// As described in the serialization format comments, the header code
	// encodes the height shifted over one bit and the coinbase flag in the
	// lowest bit.
	headerCode := uint64(stxo.Height) << 1
	if stxo.IsRootCoin {
		headerCode |= 0x01
	}

	return headerCode
}
func spentAUTUpdateHeaderCode(updated *UpdateAUTInfo) uint64 {
	// As described in the serialization format comments, the header code
	// encodes the height shifted over one bit and the coinbase flag in the
	// lowest bit.
	headerCode := uint64(updated.Height) << 1
	if updated.IsReRegistration {
		headerCode |= 0x01
	}

	return headerCode
}

// spentTxOutSerializeSize returns the number of bytes it would take to
// serialize the passed stxo according to the format described above.
func spentTxOutSerializeSize(stxo *SpentTxOut) int {
	size := serializeSizeVLQ(spentTxOutHeaderCode(stxo))
	if stxo.Height > 0 {
		// The legacy v1 spend journal format conditionally tracked the
		// containing transaction version when the height was non-zero,
		// so this is required for backwards compat.
		size += serializeSizeVLQ(0)
	}
	return size + compressedTxOutSize(uint64(stxo.Amount), stxo.PkScript)
}
func spentAUTSerializeSize(stxo SpentAUT) int {
	size := 1 // 1 for type
	switch updated := stxo.(type) {
	case *SpentAUTTokens:
		size += serializeSizeVLQ(uint64(len(*updated)))
		for _, token := range *updated {
			size += serializeSizeVLQ(spentAUTHeaderCode(&token))
			size += compressedAUTSize(token.Amount)
		}
	case *UpdateAUTInfo:
		size += serializeSizeVLQ(spentAUTUpdateHeaderCode(updated))
		if updated.Height > 0 {

		}
		// +1 to represent nil
		sizeBefore := serializeAUTInfoSize(updated.Before)
		size += 1
		if sizeBefore != 0 {
			size += serializeSizeVLQ(uint64(sizeBefore)) + sizeBefore
			size += serializeSizeVLQ(uint64(len(updated.Before.RootCoinSet)))
			size += len(updated.Before.RootCoinSet) * (chainhash.HashSize + 1)
		}

		// +1 to represent nil
		sizeAfter := serializeAUTInfoSize(updated.After)
		size += 1
		if sizeAfter != 0 {
			size += serializeSizeVLQ(uint64(sizeAfter)) + sizeAfter
			size += serializeSizeVLQ(uint64(len(updated.After.RootCoinSet)))
			size += len(updated.After.RootCoinSet) * (chainhash.HashSize + 1)
		}
	}
	return size
}

// putSpentTxOut serializes the passed stxo according to the format described
// above directly into the passed target byte slice.  The target byte slice must
// be at least large enough to handle the number of bytes returned by the
// SpentTxOutSerializeSize function or it will panic.
func putSpentTxOut(target []byte, stxo *SpentTxOut) int {
	headerCode := spentTxOutHeaderCode(stxo)
	offset := putVLQ(target, headerCode)
	if stxo.Height > 0 {
		// The legacy v1 spend journal format conditionally tracked the
		// containing transaction version when the height was non-zero,
		// so this is required for backwards compat.
		offset += putVLQ(target[offset:], 0)
	}
	return offset + putCompressedTxOut(target[offset:], uint64(stxo.Amount),
		stxo.PkScript)
}

func putSpentAUT(target []byte, stxo SpentAUT) int {
	offset := 0
	switch updated := stxo.(type) {
	case *SpentAUTTokens:
		offset += putVLQ(target[offset:], 0)
		offset += putVLQ(target[offset:], uint64(len(*updated)))
		for i := 0; i < len(*updated); i++ {
			token := (*updated)[i]
			headerCode := spentAUTHeaderCode(&token)
			offset += putVLQ(target[offset:], headerCode)
			offset += putCompressedAUT(target[offset:], token.Amount)
		}
	case *UpdateAUTInfo:
		offset += putVLQ(target[offset:], 1)
		headerCode := spentAUTUpdateHeaderCode(updated)
		offset += putVLQ(target[offset:], headerCode)

		// +1 to represent nil
		sizeBefore := serializeAUTInfoSize(updated.Before)
		if sizeBefore == 0 {
			target[offset] = 0
			offset += 1
		} else {
			target[offset] = 1
			offset += 1

			serializedBefore, err := serializeAUTInfo(updated.Before)
			if err != nil {
				panic(err)
			}
			vlqSizeLen := putVLQ(target[offset:], uint64(len(serializedBefore)))
			offset += vlqSizeLen

			copy(target[offset:], serializedBefore)
			offset += len(serializedBefore)

			vlqSizeLen = putVLQ(target[offset:], uint64(len(updated.Before.RootCoinSet)))
			offset += vlqSizeLen

			for point := range updated.Before.RootCoinSet {
				copy(target[offset:], point.TxHash[:])
				offset += chainhash.HashSize
				target[offset] = point.Index
				offset += 1
			}
		}

		sizeAfter := serializeAUTInfoSize(updated.After)
		if sizeAfter == 0 {
			target[offset] = 0
			offset += 1
		} else {
			target[offset] = 1
			offset += 1

			serializedAfter, err := serializeAUTInfo(updated.After)
			if err != nil {
				panic(err)
			}
			vlqSizeLen := putVLQ(target[offset:], uint64(len(serializedAfter)))
			offset += vlqSizeLen

			copy(target[offset:], serializedAfter)
			offset += len(serializedAfter)

			vlqSizeLen = putVLQ(target[offset:], uint64(len(updated.After.RootCoinSet)))
			offset += vlqSizeLen

			for point := range updated.After.RootCoinSet {
				copy(target[offset:], point.TxHash[:])
				offset += chainhash.HashSize
				target[offset] = point.Index
				offset += 1
			}
		}
	}
	return offset
}

// decodeSpentTxOut decodes the passed serialized stxo entry, possibly followed
// by other data, into the passed stxo struct.  It returns the number of bytes
// read.
func decodeSpentTxOut(serialized []byte, stxo *SpentTxOut) (int, error) {
	// Ensure there are bytes to decode.
	if len(serialized) == 0 {
		return 0, errDeserialize("no serialized bytes")
	}

	// Deserialize the header code.
	code, offset := deserializeVLQ(serialized)
	if offset >= len(serialized) {
		return offset, errDeserialize("unexpected end of data after " +
			"header code")
	}

	// Decode the header code.
	//
	// Bit 0 indicates containing transaction is a coinbase.
	// Bits 1-x encode height of containing transaction.
	stxo.IsCoinBase = code&0x01 != 0
	stxo.Height = int32(code >> 1)
	if stxo.Height > 0 {
		// The legacy v1 spend journal format conditionally tracked the
		// containing transaction version when the height was non-zero,
		// so this is required for backwards compat.
		_, bytesRead := deserializeVLQ(serialized[offset:])
		offset += bytesRead
		if offset >= len(serialized) {
			return offset, errDeserialize("unexpected end of data " +
				"after reserved")
		}
	}

	// Decode the compressed txout.
	amount, pkScript, bytesRead, err := decodeCompressedTxOut(
		serialized[offset:])
	offset += bytesRead
	if err != nil {
		return offset, errDeserialize(fmt.Sprintf("unable to decode "+
			"txout: %v", err))
	}
	stxo.Amount = int64(amount)
	stxo.PkScript = pkScript
	return offset, nil
}

func decodeSpentAUT(serialized []byte) (SpentAUT, int, error) {
	// Ensure there are bytes to decode.
	if len(serialized) == 0 {
		return nil, 0, errDeserialize("no serialized bytes")
	}
	stxoType, offset := deserializeVLQ(serialized)
	switch stxoType {
	case 0:
		numSpendAUTToken, n := deserializeVLQ(serialized[offset:])
		offset += n
		if offset >= len(serialized) {
			return nil, offset, errDeserialize("unexpected end of data after " +
				"header code")
		}

		res := (SpentAUTTokens)(make([]SpentAUTToken, numSpendAUTToken))
		for i := uint64(0); i < numSpendAUTToken; i++ {
			// Decode the header code.
			//
			// Bit 0 indicates containing transaction is a coinbase.
			// Bits 1-x encode height of containing transaction.
			var code uint64
			code, n = deserializeVLQ(serialized[offset:])
			offset += n
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data after " +
					"header code")
			}
			res[i].IsRootCoin = code&0x01 != 0
			res[i].Height = int32(code >> 1)

			// Decode the compressed txout.
			compressedAmount, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			res[i].Amount = decompressTxOutAmount(compressedAmount)
		}
		return &res, offset, nil
	case 1:
		res := UpdateAUTInfo{}
		code, n := deserializeVLQ(serialized[offset:])
		offset += n
		if offset >= len(serialized) {
			return nil, offset, errDeserialize("unexpected end of data after " +
				"header code")
		}
		res.IsReRegistration = code&0x01 != 0
		res.Height = int32(code >> 1)

		var err error
		if serialized[offset] == 0 {
			offset += 1
		} else {
			offset += 1
			res.Before = &aut.MetaInfo{}
			sizeOfInfo, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}

			res.Before, err = deserializeAUTInfo(serialized[offset : offset+int(sizeOfInfo)])
			if err != nil {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}
			offset += int(sizeOfInfo)

			numRootCoin, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}
			res.Before.RootCoinSet = make(map[aut.OutPoint]struct{}, numRootCoin)
			for i := 0; i < int(numRootCoin); i++ {
				point := aut.OutPoint{}
				copy(point.TxHash[:], serialized[offset:])
				offset += chainhash.HashSize
				point.Index = serialized[offset]
				offset += 1
				res.Before.RootCoinSet[point] = struct{}{}
			}
		}

		if serialized[offset] == 0 {
			offset += 1
		} else {
			offset += 1
			res.After = &aut.MetaInfo{}
			sizeOfInfo, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}
			res.After, err = deserializeAUTInfo(serialized[offset : offset+int(sizeOfInfo)])
			if err != nil {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}
			offset += int(sizeOfInfo)

			numRootCoin, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}
			res.After.RootCoinSet = make(map[aut.OutPoint]struct{}, numRootCoin)
			for i := 0; i < int(numRootCoin); i++ {
				point := aut.OutPoint{}
				copy(point.TxHash[:], serialized[offset:])
				offset += chainhash.HashSize
				point.Index = serialized[offset]
				offset += 1
				res.After.RootCoinSet[point] = struct{}{}
			}
		}
		return &res, offset, nil

	default:
		panic("unreachable")
	}
}

// deserializeSpendJournalEntry decodes the passed serialized byte slice into a
// slice of spent txouts according to the format described in detail above.
//
// Since the serialization format is not self describing, as noted in the
// format comments, this function also requires the transactions that spend the
// txouts.
func deserializeSpendJournalEntry(serialized []byte, txns []*wire.MsgTx) ([]SpentTxOut, error) {
	// Calculate the total number of stxos.
	var numStxos int
	for _, tx := range txns {
		numStxos += len(tx.TxIn)
	}

	// When a block has no spent txouts there is nothing to serialize.
	if len(serialized) == 0 {
		// Ensure the block actually has no stxos.  This should never
		// happen unless there is database corruption or an empty entry
		// erroneously made its way into the database.
		if numStxos != 0 {
			return nil, AssertError(fmt.Sprintf("mismatched spend "+
				"journal serialization - no serialization for "+
				"expected %d stxos", numStxos))
		}

		return nil, nil
	}

	// Loop backwards through all transactions so everything is read in
	// reverse order to match the serialization order.
	stxoIdx := numStxos - 1
	offset := 0
	stxos := make([]SpentTxOut, numStxos)
	for txIdx := len(txns) - 1; txIdx > -1; txIdx-- {
		tx := txns[txIdx]

		// Loop backwards through all of the transaction inputs and read
		// the associated stxo.
		for txInIdx := len(tx.TxIn) - 1; txInIdx > -1; txInIdx-- {
			txIn := tx.TxIn[txInIdx]
			stxo := &stxos[stxoIdx]
			stxoIdx--

			n, err := decodeSpentTxOut(serialized[offset:], stxo)
			offset += n
			if err != nil {
				return nil, errDeserialize(fmt.Sprintf("unable "+
					"to decode stxo for %v: %v",
					txIn.PreviousOutPoint, err))
			}
		}
	}

	return stxos, nil
}

// Abe to do
func deserializeSpendJournalEntryAbe(serialized []byte, txns []*wire.MsgTxAbe) ([]*SpentTxOutAbe, error) {
	// Calculate the total number of stxos.
	var numStxos int
	for _, tx := range txns {
		numStxos += len(tx.TxIns)
	}

	// When a block has no spent txouts there is nothing to serialize.
	if len(serialized) == 0 {
		// Ensure the block actually has no stxos.  This should never
		// happen unless there is database corruption or an empty entry
		// erroneously made its way into the database.
		if numStxos != 0 {
			return nil, AssertError(fmt.Sprintf("mismatched spend "+
				"journal serialization - no serialization for "+
				"expected %d stxos", numStxos))
		}

		return nil, nil
	}

	br := bytes.NewReader(serialized)

	// Loop backwards through all transactions so everything is read in
	// reverse order to match the serialization order.
	stxoIdx := numStxos - 1
	stxos := make([]*SpentTxOutAbe, numStxos)
	for txIdx := len(txns) - 1; txIdx > -1; txIdx-- {
		tx := txns[txIdx]

		// Loop backwards through all of the transaction inputs and read
		// the associated stxo.
		for txInIdx := len(tx.TxIns) - 1; txInIdx > -1; txInIdx-- {
			txIn := tx.TxIns[txInIdx]
			stxo := &SpentTxOutAbe{
				SerialNumber: nil,
				UtxoRing:     new(UtxoRingEntry),
			}

			err := stxo.Deserialize(br)
			if err != nil {
				return nil, errDeserialize(fmt.Sprintf("unable "+
					"to decode stxo for %v: %v",
					txIn.PreviousOutPointRing, err))
			}
			stxos[stxoIdx] = stxo
			stxoIdx--
		}
	}

	return stxos, nil
}
func deserializeSpendJournalEntryAUT(serialized []byte, txns []aut.Transaction) ([]SpentAUT, error) {
	// Calculate the total number of stxos.
	numStxos := len(txns)

	// When a block has no spent txouts there is nothing to serialize.
	if len(serialized) == 0 {
		// Ensure the block actually has no stxos.  This should never
		// happen unless there is database corruption or an empty entry
		// erroneously made its way into the database.
		if numStxos != 0 {
			return nil, AssertError(fmt.Sprintf("mismatched spend aut"+
				"journal serialization - no serialization for "+
				"expected %d stxos", numStxos))
		}

		return nil, nil
	}

	// Loop backwards through all transactions so everything is read in
	// reverse order to match the serialization order.
	stxoIdx := numStxos - 1
	offset := 0
	stxos := make([]SpentAUT, numStxos)
	for txIdx := len(txns) - 1; txIdx > -1; txIdx-- {
		stxo, n, err := decodeSpentAUT(serialized[offset:])
		offset += n
		stxos[txIdx] = stxo
		if err != nil {
			return nil, errDeserialize(fmt.Sprintf("unable "+
				"to decode saut for %v", err))
		}
		stxoIdx -= 1
	}

	return stxos, nil
}

// serializeSpendJournalEntry serializes all of the passed spent txouts into a
// single byte slice according to the format described in detail above.
func serializeSpendJournalEntry(stxos []SpentTxOut) []byte {
	if len(stxos) == 0 {
		return nil
	}

	// Calculate the size needed to serialize the entire journal entry.
	var size int
	for i := range stxos {
		size += spentTxOutSerializeSize(&stxos[i])
	}
	serialized := make([]byte, size)

	// Serialize each individual stxo directly into the slice in reverse
	// order one after the other.
	var offset int
	for i := len(stxos) - 1; i > -1; i-- {
		offset += putSpentTxOut(serialized[offset:], &stxos[i])
	}

	return serialized
}

// Abe to do
// serializeSpendJournalEntryAbe
// todo_DONE(MLP): reviewed on 2024.01.04
func serializeSpendJournalEntryAbe(stxos []*SpentTxOutAbe) ([]byte, error) {
	if len(stxos) == 0 {
		return nil, nil
	}

	// Calculate the size needed to serialize the entire journal entry.
	var size int
	for _, stxo := range stxos {
		size += stxo.SerializeSize()
	}

	buf := bytes.NewBuffer(make([]byte, 0, size))
	// Serialize each individual stxo directly into the slice in reverse
	// order one after the other.
	for i := len(stxos) - 1; i >= 0; i-- {
		err := stxos[i].Serialize(buf)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func serializeSpendJournalEntryAUT(stxos []SpentAUT) []byte {
	if len(stxos) == 0 {
		return nil
	}

	// Calculate the size needed to serialize the entire journal entry.
	var size int
	for i := range stxos {
		size += spentAUTSerializeSize(stxos[i])
	}
	serialized := make([]byte, size)

	// Serialize each individual stxo directly into the slice in reverse
	// order one after the other.
	var offset int
	for i := len(stxos) - 1; i > -1; i-- {
		offset += putSpentAUT(serialized[offset:], stxos[i])
	}

	return serialized
}

// dbFetchSpendJournalEntry fetches the spend journal entry for the passed block
// and deserializes it into a slice of spent txout entries.
//
// NOTE: Legacy entries will not have the coinbase flag or height set unless it
// was the final output spend in the containing transaction.  It is up to the
// caller to handle this properly by looking the information up in the utxo set.
func dbFetchSpendJournalEntry(dbTx database.Tx, block *abeutil.Block) ([]SpentTxOut, error) {
	// Exclude the coinbase transaction since it can't spend anything.
	spendBucket := dbTx.Metadata().Bucket(spendJournalBucketName)
	serialized := spendBucket.Get(block.Hash()[:])
	blockTxns := block.MsgBlock().Transactions[1:]
	stxos, err := deserializeSpendJournalEntry(serialized, blockTxns)
	if err != nil {
		// Ensure any deserialization errors are returned as database
		// corruption errors.
		if isDeserializeErr(err) {
			return nil, database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt spend "+
					"information for %v: %v", block.Hash(),
					err),
			}
		}

		return nil, err
	}

	return stxos, nil
}

// Abe to do
func dbFetchSpendJournalEntryAbe(dbTx database.Tx, block *abeutil.BlockAbe) ([]*SpentTxOutAbe, error) {
	// Exclude the coinbase transaction since it can't spend anything.
	spendBucket := dbTx.Metadata().Bucket(spendJournalBucketName)
	serialized := spendBucket.Get(block.Hash()[:])
	blockTxns := block.MsgBlock().Transactions[1:]
	stxos, err := deserializeSpendJournalEntryAbe(serialized, blockTxns)
	if err != nil {
		// Ensure any deserialization errors are returned as database
		// corruption errors.
		if isDeserializeErr(err) {
			return nil, database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt spend "+
					"information for %v: %v", block.Hash(),
					err),
			}
		}

		return nil, err
	}

	return stxos, nil
}

func dbFetchSpendJournalEntryAUT(dbTx database.Tx, block *abeutil.BlockAbe) ([]SpentAUT, error) {
	// Exclude the coinbase transaction since it can't spend anything.
	spendBucket := dbTx.Metadata().Bucket(autSpendJournalBucketName)
	serialized := spendBucket.Get(block.Hash()[:])
	stxos, err := deserializeSpendJournalEntryAUT(serialized, block.AUTTransactions())
	if err != nil {
		// Ensure any deserialization errors are returned as database
		// corruption errors.
		if isDeserializeErr(err) {
			return nil, database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt spend "+
					"information for %v: %v", block.Hash(),
					err),
			}
		}

		return nil, err
	}

	return stxos, nil
}

// dbPutSpendJournalEntry uses an existing database transaction to update the
// spend journal entry for the given block hash using the provided slice of
// spent txouts.   The spent txouts slice must contain an entry for every txout
// the transactions in the block spend in the order they are spent.
func dbPutSpendJournalEntry(dbTx database.Tx, blockHash *chainhash.Hash, stxos []SpentTxOut) error {
	spendBucket := dbTx.Metadata().Bucket(spendJournalBucketName)
	serialized := serializeSpendJournalEntry(stxos)
	return spendBucket.Put(blockHash[:], serialized)
}

// todo_DONE(MLP): reviewed on 2024.01.04
func dbPutSpendJournalEntryAbe(dbTx database.Tx, blockHash *chainhash.Hash, stxos []*SpentTxOutAbe) error {
	spendBucket := dbTx.Metadata().Bucket(spendJournalBucketName)
	serialized, err := serializeSpendJournalEntryAbe(stxos)
	if err != nil {
		return err
	}
	if len(serialized) == 0 {
		return nil
	}

	return spendBucket.Put(blockHash[:], serialized)
}

func dbPutSpendJournalEntryAUT(dbTx database.Tx, blockHash *chainhash.Hash, sauts []SpentAUT) error {
	autSpendBucket := dbTx.Metadata().Bucket(autSpendJournalBucketName)
	serialized := serializeSpendJournalEntryAUT(sauts)
	if len(serialized) == 0 {
		return nil
	}

	return autSpendBucket.Put(blockHash[:], serialized)
}

// dbRemoveSpendJournalEntry uses an existing database transaction to remove the
// spend journal entry for the passed block hash.
func dbRemoveSpendJournalEntry(dbTx database.Tx, blockHash *chainhash.Hash) error {
	spendBucket := dbTx.Metadata().Bucket(spendJournalBucketName)
	return spendBucket.Delete(blockHash[:])
}
func dbRemoveSpendJournalEntryAUT(dbTx database.Tx, blockHash *chainhash.Hash) error {
	autSpendBucket := dbTx.Metadata().Bucket(autSpendJournalBucketName)
	return autSpendBucket.Delete(blockHash[:])
}

func serializeDeletedHistory(filesize int64, deletedTime int64) []byte {
	res := make([]byte, 16)
	byteOrder.PutUint64(res[0:8], uint64(filesize))
	byteOrder.PutUint64(res[8:16], uint64(deletedTime))
	return res[:]
}

// serializeUint32 serialize the uint32 value.
func serializeUint32(num uint32) []byte {
	var serializedRow [4]byte
	byteOrder.PutUint32(serializedRow[0:4], num)
	return serializedRow[:]
}

// dbPutDeletedHistory put the history of deleted witness file into database.
func dbPutDeletedHistory(dbTx database.Tx, num uint32, filesize int64, deletedTime int64) error {
	deletedWitnessFileBucket := dbTx.Metadata().Bucket(deletedWitnessFileBucketName)
	serialized := serializeDeletedHistory(filesize, deletedTime)
	return deletedWitnessFileBucket.Put(serializeUint32(num), serialized)
}

// -----------------------------------------------------------------------------
// The unspent transaction output (utxo) set consists of an entry for each
// unspent output using a format that is optimized to reduce space using domain
// specific compression algorithms.  This format is a slightly modified version
// of the format used in Bitcoin Core.
//
// Each entry is keyed by an outpoint as specified below.  It is important to
// note that the key encoding uses a VLQ, which employs an MSB encoding so
// iteration of utxos when doing byte-wise comparisons will produce them in
// order.
//
// The serialized key format is:
//   <hash><output index>
//
//   Field                Type             Size
//   hash                 chainhash.Hash   chainhash.HashSize
//   output index         VLQ              variable
//
// The serialized value format is:
//
//   <header code><compressed txout>
//
//   Field                Type     Size
//   header code          VLQ      variable
//   compressed txout
//     compressed amount  VLQ      variable
//     compressed script  []byte   variable
//
// The serialized header code format is:
//   bit 0 - containing transaction is a coinbase
//   bits 1-x - height of the block that contains the unspent txout
//
// Example 1:
// From tx in main blockchain:
// Blk 1, 0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098:0
//
//    03320496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52
//    <><------------------------------------------------------------------>
//     |                                          |
//   header code                         compressed txout
//
//  - header code: 0x03 (coinbase, height 1)
//  - compressed txout:
//    - 0x32: VLQ-encoded compressed amount for 5000000000 (50 BTC)
//    - 0x04: special script type pay-to-pubkey
//    - 0x96...52: x-coordinate of the pubkey
//
// Example 2:
// From tx in main blockchain:
// Blk 113931, 4a16969aa4764dd7507fc1de7f0baa4850a246de90c45e59a3207f9a26b5036f:2
//
//    8cf316800900b8025be1b3efc63b0ad48e7f9f10e87544528d58
//    <----><------------------------------------------>
//      |                             |
//   header code             compressed txout
//
//  - header code: 0x8cf316 (not coinbase, height 113931)
//  - compressed txout:
//    - 0x8009: VLQ-encoded compressed amount for 15000000 (0.15 BTC)
//    - 0x00: special script type pay-to-pubkey-hash
//    - 0xb8...58: pubkey hash
//
// Example 3:
// From tx in main blockchain:
// Blk 338156, 1b02d1c8cfef60a189017b9a420c682cf4a0028175f2f563209e4ff61c8c3620:22
//
//    a8a2588ba5b9e763011dd46a006572d820e448e12d2bbb38640bc718e6
//    <----><-------------------------------------------------->
//      |                             |
//   header code             compressed txout
//
//  - header code: 0xa8a258 (not coinbase, height 338156)
//  - compressed txout:
//    - 0x8ba5b9e763: VLQ-encoded compressed amount for 366875659 (3.66875659 BTC)
//    - 0x01: special script type pay-to-script-hash
//    - 0x1d...e6: script hash
// -----------------------------------------------------------------------------

// maxUint32VLQSerializeSize is the maximum number of bytes a max uint32 takes
// to serialize as a VLQ.
var maxUint32VLQSerializeSize = serializeSizeVLQ(1<<32 - 1)

// outpointKeyPool defines a concurrent safe free list of byte slices used to
// provide temporary buffers for outpoint database keys.
var outpointKeyPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, chainhash.HashSize+maxUint32VLQSerializeSize)
		return &b // Pointer to slice to avoid boxing alloc.
	},
}

var outPointRingKeyPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, chainhash.HashSize)
		return &b // Pointer to slice to avoid boxing alloc.
	},
}

var autOutpointKeyPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, chainhash.HashSize+maxUint32VLQSerializeSize)
		return &b // Pointer to slice to avoid boxing alloc.
	},
}

// outpointKey returns a key suitable for use as a database key in the utxo set
// while making use of a free list.  A new buffer is allocated if there are not
// already any available on the free list.  The returned byte slice should be
// returned to the free list by using the recycleOutpointKey function when the
// caller is done with it _unless_ the slice will need to live for longer than
// the caller can calculate such as when used to write to the database.
func outpointKey(outpoint wire.OutPoint) *[]byte {
	// A VLQ employs an MSB encoding, so they are useful not only to reduce
	// the amount of storage space, but also so iteration of utxos when
	// doing byte-wise comparisons will produce them in order.
	key := outpointKeyPool.Get().(*[]byte)
	idx := uint64(outpoint.Index)
	*key = (*key)[:chainhash.HashSize+serializeSizeVLQ(idx)]
	copy(*key, outpoint.Hash[:])
	putVLQ((*key)[chainhash.HashSize:], idx)
	return key
}

func autOutpointKey(outpoint aut.OutPoint) *[]byte {
	// A VLQ employs an MSB encoding, so they are useful not only to reduce
	// the amount of storage space, but also so iteration of utxos when
	// doing byte-wise comparisons will produce them in order.
	key := outpointKeyPool.Get().(*[]byte)
	idx := uint64(outpoint.Index)
	*key = (*key)[:chainhash.HashSize+serializeSizeVLQ(idx)]
	copy(*key, outpoint.TxHash[:])
	putVLQ((*key)[chainhash.HashSize:], idx)
	return key
}

func outPointRingKey(outPointRingHash chainhash.Hash) *[]byte {
	key := outpointKeyPool.Get().(*[]byte)
	copy(*key, outPointRingHash[:])
	return key
}

// recycleOutpointKey puts the provided byte slice, which should have been
// obtained via the outpointKey function, back on the free list.
func recycleOutpointKey(key *[]byte) {
	outpointKeyPool.Put(key)
}

// recycleOutPointRingKey puts the provided byte slice, which should have been
// obtained via the outpointKey function, back on the free list.
func recycleOutPointRingKey(key *[]byte) {
	outPointRingKeyPool.Put(key)
}
func recycleAUTOutpointKey(key *[]byte) {
	autOutpointKeyPool.Put(key)
}

// utxoEntryHeaderCode returns the calculated header code to be used when
// serializing the provided utxo entry.
func utxoEntryHeaderCode(entry *UtxoEntry) (uint64, error) {
	if entry.IsSpent() {
		return 0, AssertError("attempt to serialize spent utxo header")
	}

	// As described in the serialization format comments, the header code
	// encodes the height shifted over one bit and the coinbase flag in the
	// lowest bit.
	headerCode := uint64(entry.BlockHeight()) << 1
	if entry.IsCoinBase() {
		headerCode |= 0x01
	}

	return headerCode, nil
}

func autEntryHeaderCode(entry *AUTCoin) (uint64, error) {
	if entry.IsSpent() {
		return 0, AssertError("attempt to serialize spent utxo header")
	}

	// like utxo serialization, the lowest bit is for root coin
	headerCode := uint64(entry.BlockHeight()) << 1
	if entry.IsRootCoin() {
		headerCode |= 0x01
	}

	return headerCode, nil
}

// serializeUtxoEntry returns the entry serialized to a format that is suitable
// for long-term storage.  The format is described in detail above.
func serializeUtxoEntry(entry *UtxoEntry) ([]byte, error) {
	// Spent outputs have no serialization.
	if entry.IsSpent() {
		return nil, nil
	}

	// Encode the header code.
	headerCode, err := utxoEntryHeaderCode(entry)
	if err != nil {
		return nil, err
	}

	// Calculate the size needed to serialize the entry.
	size := serializeSizeVLQ(headerCode) +
		compressedTxOutSize(uint64(entry.Amount()), entry.PkScript())

	// Serialize the header code followed by the compressed unspent
	// transaction output.
	serialized := make([]byte, size)
	offset := putVLQ(serialized, headerCode)
	offset += putCompressedTxOut(serialized[offset:], uint64(entry.Amount()),
		entry.PkScript())

	return serialized, nil
}

func serializeAUTCoin(entry *AUTCoin) ([]byte, error) {
	// Spent outputs have no serialization.
	if entry.IsSpent() {
		return nil, nil
	}

	// Encode the header code.
	headerCode, err := autEntryHeaderCode(entry)
	if err != nil {
		return nil, err
	}

	// Calculate the size needed to serialize the entry.
	size := serializeSizeVLQ(headerCode) +
		serializeSizeVLQ(compressTxOutAmount(entry.Amount())) +
		serializeSizeVLQ(uint64(len(entry.identifier))) +
		len(entry.identifier)

	// Serialize the header code followed by the compressed unspent
	// transaction output.
	serialized := make([]byte, size)
	offset := putVLQ(serialized, headerCode)
	offset += putCompressedAUT(serialized[offset:], entry.Amount())
	offset += putVLQ(serialized[offset:], uint64(len(entry.identifier)))
	copy(serialized[offset:], entry.identifier[:])
	offset += len(entry.identifier)

	return serialized, nil
}
func serializeAUTInfoSize(info *aut.MetaInfo) int {
	if info == nil {
		return 0
	}
	n := wire.VarIntSerializeSize(uint64(len(info.AutIdentifier))) + len(info.AutIdentifier) +
		wire.VarIntSerializeSize(uint64(len(info.AutSymbol))) + len(info.AutSymbol) +
		wire.VarIntSerializeSize(uint64(len(info.AutMemo))) + len(info.AutMemo) +
		1 +
		1 +
		wire.VarIntSerializeSize(info.PlannedTotalAmount) +
		wire.VarIntSerializeSize(uint64(info.ExpireHeight)) +
		wire.VarIntSerializeSize(uint64(len(info.IssuerTokens)))
	for i := 0; i < len(info.IssuerTokens); i++ {
		n += wire.VarIntSerializeSize(uint64(len(info.IssuerTokens[i]))) + len(info.IssuerTokens[i])
	}
	n += wire.VarIntSerializeSize(uint64(len(info.UnitName))) + len(info.UnitName) +
		wire.VarIntSerializeSize(uint64(len(info.MinUnitName))) + len(info.MinUnitName) +
		wire.VarIntSerializeSize(info.UnitScale) +
		wire.VarIntSerializeSize(info.MintedAmount)
	return n
}
func serializeAUTInfo(info *aut.MetaInfo) ([]byte, error) {
	if info == nil {
		return nil, errors.New("nil pointer to aut.Instance for serialize")
	}
	// Calculate the size needed to serialize AUT info.
	size := serializeAUTInfoSize(info)

	// Serialize the header code followed by the compressed unspent
	// transaction output.
	buff := bytes.NewBuffer(make([]byte, 0, size))
	err := wire.WriteVarBytes(buff, 0, info.AutIdentifier)
	if err != nil {
		return nil, err
	}
	err = wire.WriteVarBytes(buff, 0, info.AutSymbol)
	if err != nil {
		return nil, err
	}
	err = wire.WriteVarBytes(buff, 0, info.AutMemo)
	if err != nil {
		return nil, err
	}

	err = buff.WriteByte(info.IssuerUpdateThreshold)
	if err != nil {
		return nil, err
	}
	err = buff.WriteByte(info.IssueTokensThreshold)
	if err != nil {
		return nil, err
	}
	err = wire.WriteVarInt(buff, 0, info.PlannedTotalAmount)
	if err != nil {
		return nil, err
	}
	err = wire.WriteVarInt(buff, 0, uint64(info.ExpireHeight))
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(buff, 0, uint64(len(info.IssuerTokens)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(info.IssuerTokens); i++ {
		err = wire.WriteVarBytes(buff, 0, info.IssuerTokens[i])
		if err != nil {
			return nil, errors.New("error to write issuer token")
		}
	}
	err = wire.WriteVarBytes(buff, 0, info.UnitName)
	if err != nil {
		return nil, err
	}
	err = wire.WriteVarBytes(buff, 0, info.MinUnitName)
	if err != nil {
		return nil, err
	}
	err = wire.WriteVarInt(buff, 0, info.UnitScale)
	if err != nil {
		return nil, err
	}
	err = wire.WriteVarInt(buff, 0, info.MintedAmount)
	if err != nil {
		return nil, err
	}

	return buff.Bytes(), nil
}
func serializeAUTRootCoinSet(coins []*aut.OutPoint) ([]byte, error) {
	res := make([]byte, serializeSizeVLQ(uint64(len(coins)))+(chainhash.HashSize+maxUint32VLQSerializeSize)*len(coins))
	offset := putVLQ(res, uint64(len(coins)))
	for i := 0; i < len(coins); i++ {
		copy(res[offset:], coins[i].TxHash[:])
		offset += chainhash.HashSize
		offset += putVLQ(res[offset:], uint64(coins[i].Index))
	}

	return res[:offset], nil
}

// Abe to do
func serializeUtxoRingEntry(entry *UtxoRingEntry) ([]byte, error) {

	buf := bytes.NewBuffer(make([]byte, 0, entry.SerializeSize()))
	err := entry.Serialize(buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// deserializeUtxoEntry decodes a utxo entry from the passed serialized byte
// slice into a new UtxoEntry using a format that is suitable for long-term
// storage.  The format is described in detail above.
func deserializeUtxoEntry(serialized []byte) (*UtxoEntry, error) {
	// Deserialize the header code.
	code, offset := deserializeVLQ(serialized)
	if offset >= len(serialized) {
		return nil, errDeserialize("unexpected end of data after header")
	}

	// Decode the header code.
	//
	// Bit 0 indicates whether the containing transaction is a coinbase.
	// Bits 1-x encode height of containing transaction.
	isCoinBase := code&0x01 != 0
	blockHeight := int32(code >> 1)

	// Decode the compressed unspent transaction output.
	amount, pkScript, _, err := decodeCompressedTxOut(serialized[offset:])
	if err != nil {
		return nil, errDeserialize(fmt.Sprintf("unable to decode "+
			"utxo: %v", err))
	}

	entry := &UtxoEntry{
		amount:      int64(amount),
		pkScript:    pkScript,
		blockHeight: blockHeight,
		packedFlags: 0,
	}
	if isCoinBase {
		entry.packedFlags |= tfCoinBase
	}

	return entry, nil
}

// deserializeUtxoRingEntry
// reviewed on 2024.01.04
func deserializeUtxoRingEntry(serialized []byte) (*UtxoRingEntry, error) {

	entry := UtxoRingEntry{}

	br := bytes.NewReader(serialized)

	err := entry.Deserialize(br)
	if err != nil {
		return nil, err
	}

	return &entry, nil

}

func deserializeAUTCoin(serialized []byte) (*AUTCoin, error) {
	// Deserialize the header code.
	code, offset := deserializeVLQ(serialized)
	if offset >= len(serialized) {
		return nil, errDeserialize("unexpected end of data after header")
	}

	// Decode the header code.
	//
	// Bit 0 indicates whether the token is a root coin.
	// Bits 1-x encode height of containing transaction.
	isRootCoin := code&0x01 != 0
	blockHeight := int32(code >> 1)

	// Decode the compressed unspent transaction output.
	amount, readSize, err := decodeCompressedAUT(serialized[offset:])
	if err != nil {
		return nil, errDeserialize(fmt.Sprintf("unable to decode "+
			"aut coin: %v", err))
	}
	offset += readSize
	identifierSize, n := deserializeVLQ(serialized[offset:])
	offset += n
	if offset+int(identifierSize) > len(serialized) {
		return nil, errDeserialize("unexpected end of data after header for aut coin")
	}
	identifier := serialized[offset : offset+int(identifierSize)]
	offset += int(identifierSize)
	entry := &AUTCoin{
		identifier:  identifier,
		amount:      amount,
		blockHeight: blockHeight,
		packedFlags: 0,
	}
	if isRootCoin {
		entry.packedFlags |= atfRootCoin
	}

	return entry, nil
}

func deserializeAUTInfo(serialized []byte) (*aut.MetaInfo, error) {
	// Serialize the header code followed by the compressed unspent
	// transaction output.
	info := &aut.MetaInfo{}
	var err error
	buff := bytes.NewReader(serialized)
	info.AutIdentifier, err = wire.ReadVarBytes(buff, 0, aut.IdentifierLength, "identifier")
	if err != nil {
		return nil, err
	}
	info.AutSymbol, err = wire.ReadVarBytes(buff, 0, aut.MaxSymbolLength, "symbol")
	if err != nil {
		return nil, err
	}
	info.AutMemo, err = wire.ReadVarBytes(buff, 0, aut.MaxAUTMemoLength, "memo")
	if err != nil {
		return nil, err
	}

	info.IssuerUpdateThreshold, err = buff.ReadByte()
	if err != nil {
		return nil, err
	}
	info.IssueTokensThreshold, err = buff.ReadByte()
	if err != nil {
		return nil, err
	}

	info.PlannedTotalAmount, err = wire.ReadVarInt(buff, 0)
	if err != nil {
		return nil, err
	}
	expiredHeight, err := wire.ReadVarInt(buff, 0)
	if err != nil {
		return nil, err
	}
	info.ExpireHeight = int32(expiredHeight)

	issuerNum, err := wire.ReadVarInt(buff, 0)
	if err != nil {
		return nil, err
	}

	info.IssuerTokens = make([][]byte, issuerNum)
	for i := uint64(0); i < issuerNum; i++ {
		info.IssuerTokens[i], err = wire.ReadVarBytes(buff, 0, aut.IssuerTokenLength, "issuerToken")
		if err != nil {
			return nil, errors.New("error to write issuer token")
		}
	}
	info.UnitName, err = wire.ReadVarBytes(buff, 0, aut.MaxUnitLength, "memo")
	if err != nil {
		return nil, err
	}
	info.MinUnitName, err = wire.ReadVarBytes(buff, 0, aut.MaxMinUnitLength, "memo")
	if err != nil {
		return nil, err
	}
	info.UnitScale, err = wire.ReadVarInt(buff, 0)
	if err != nil {
		return nil, err
	}
	info.MintedAmount, err = wire.ReadVarInt(buff, 0)
	if err != nil {
		return nil, err
	}
	return info, nil
}
func deserializeAUTRootCoinSet(serialized []byte) ([]*aut.OutPoint, error) {
	coinNum, offset := deserializeVLQ(serialized)
	outpoints := make([]*aut.OutPoint, coinNum)
	for i := uint64(0); i < coinNum; i++ {
		outpoint := &aut.OutPoint{}
		copy(outpoint.TxHash[:], serialized[offset:])
		offset += chainhash.HashSize
		idx, n := deserializeVLQ(serialized[offset:])
		offset += n
		if idx > math.MaxUint8 {
			return nil, errDeserialize("idx exceed the max allowed")
		}
		outpoint.Index = uint8(idx)
		outpoints[i] = outpoint
	}

	return outpoints, nil
}

// dbFetchUtxoEntryByHash attempts to find and fetch a utxo for the given hash.
// It uses a cursor and seek to try and do this as efficiently as possible.
//
// When there are no entries for the provided hash, nil will be returned for the
// both the entry and the error.
func dbFetchUtxoEntryByHash(dbTx database.Tx, hash *chainhash.Hash) (*UtxoEntry, error) {
	// Attempt to find an entry by seeking for the hash along with a zero
	// index.  Due to the fact the keys are serialized as <hash><index>,
	// where the index uses an MSB encoding, if there are any entries for
	// the hash at all, one will be found.
	cursor := dbTx.Metadata().Bucket(utxoSetBucketName).Cursor()
	key := outpointKey(wire.OutPoint{Hash: *hash, Index: 0})
	ok := cursor.Seek(*key)
	recycleOutpointKey(key)
	if !ok {
		return nil, nil
	}

	// An entry was found, but it could just be an entry with the next
	// highest hash after the requested one, so make sure the hashes
	// actually match.
	cursorKey := cursor.Key()
	if len(cursorKey) < chainhash.HashSize {
		return nil, nil
	}
	if !bytes.Equal(hash[:], cursorKey[:chainhash.HashSize]) {
		return nil, nil
	}

	return deserializeUtxoEntry(cursor.Value())
}

// dbFetchUtxoEntry uses an existing database transaction to fetch the specified
// transaction output from the utxo set.
//
// When there is no entry for the provided output, nil will be returned for both
// the entry and the error.
func dbFetchUtxoEntry(dbTx database.Tx, outpoint wire.OutPoint) (*UtxoEntry, error) {
	// Fetch the unspent transaction output information for the passed
	// transaction output.  Return now when there is no entry.
	key := outpointKey(outpoint)
	utxoBucket := dbTx.Metadata().Bucket(utxoSetBucketName)
	serializedUtxo := utxoBucket.Get(*key)
	recycleOutpointKey(key)
	if serializedUtxo == nil {
		return nil, nil
	}

	// A non-nil zero-length entry means there is an entry in the database
	// for a spent transaction output which should never be the case.
	if len(serializedUtxo) == 0 {
		return nil, AssertError(fmt.Sprintf("database contains entry "+
			"for spent tx output %v", outpoint))
	}

	// Deserialize the utxo entry and return it.
	entry, err := deserializeUtxoEntry(serializedUtxo)
	if err != nil {
		// Ensure any deserialization errors are returned as database
		// corruption errors.
		if isDeserializeErr(err) {
			return nil, database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt utxo entry "+
					"for %v: %v", outpoint, err),
			}
		}

		return nil, err
	}

	return entry, nil
}

// dbFetchUtxoRingEntry
// reviewed on 2024.01.04
func dbFetchUtxoRingEntry(dbTx database.Tx, outPointRingHash chainhash.Hash) (*UtxoRingEntry, error) {
	// Fetch the unspent transaction output information for the passed
	// transaction output.  Return nil when there is no entry.
	key := outPointRingKey(outPointRingHash)
	utxoRingBucket := dbTx.Metadata().Bucket(utxoRingSetBucketName)
	serializedUtxoRing := utxoRingBucket.Get(*key)
	recycleOutPointRingKey(key)
	if serializedUtxoRing == nil {
		return nil, nil
	}

	// A non-nil zero-length entry means there is an entry in the database
	// for a spent transaction output which should never be the case.
	if len(serializedUtxoRing) == 0 {
		return nil, AssertError(fmt.Sprintf("database contains empty entry "+
			"for spent tx output %v", outPointRingHash))
	}

	// Deserialize the utxoRing entry and return it.
	entry, err := deserializeUtxoRingEntry(serializedUtxoRing)
	if err != nil {
		// Ensure any deserialization errors are returned as database
		// corruption errors.
		if isUtxoRingDeserializeErr(err) {
			return nil, database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt utxoRing entry "+
					"for %v: %v", outPointRingHash, err),
			}
		}

		return nil, err
	}

	return entry, nil
}

func dbFetchAUTEntry(dbTx database.Tx, outpoint aut.OutPoint) (*AUTCoin, error) {
	// Fetch the unspent transaction output information for the passed
	// transaction output.  Return now when there is no entry.
	key := autOutpointKey(outpoint)
	autCoinBucket := dbTx.Metadata().Bucket(autCoinBucketName)
	if autCoinBucket == nil {
		return nil, nil
	}
	serializedUtxo := autCoinBucket.Get(*key)
	recycleAUTOutpointKey(key)
	if serializedUtxo == nil {
		return nil, nil
	}

	// A non-nil zero-length entry means there is an entry in the database
	// for a spent transaction output which should never be the case.
	if len(serializedUtxo) == 0 {
		return nil, AssertError(fmt.Sprintf("database contains entry "+
			"for spent tx output %v", outpoint))
	}

	// Deserialize the utxo entry and return it.
	entry, err := deserializeAUTCoin(serializedUtxo)
	if err != nil {
		// Ensure any deserialization errors are returned as database
		// corruption errors.
		if isDeserializeErr(err) {
			return nil, database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt utxo entry "+
					"for %v: %v", outpoint, err),
			}
		}

		return nil, err
	}

	return entry, nil
}

func dbFetchAUTMetaInfo(dbTx database.Tx, key []byte) (*aut.MetaInfo, error) {
	// Fetch the unspent transaction output information for the passed
	// transaction output.  Return now when there is no entry.
	autInfoBucket := dbTx.Metadata().Bucket(autInfoBucketName)
	serializedAUTInfo := autInfoBucket.Get(key)
	if serializedAUTInfo == nil {
		return nil, nil
	}

	// Deserialize the utxo entry and return it.
	info, err := deserializeAUTInfo(serializedAUTInfo)
	if err != nil {
		// Ensure any deserialization errors are returned as database
		// corruption errors.
		if isDeserializeErr(err) {
			return nil, database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt information "+
					"for AUT %v: %v", key, err),
			}
		}

		return nil, err
	}
	autRootCoinBucket := dbTx.Metadata().Bucket(autRootCoinBucketName)
	serializedAUTRootCoins := autRootCoinBucket.Get(key)
	rootCoinSet, err := deserializeAUTRootCoinSet(serializedAUTRootCoins)
	if err != nil {
		if isDeserializeErr(err) {
			return nil, database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt information "+
					"for AUT %v: %v", key, err),
			}
		}
		return nil, err
	}

	if info.RootCoinSet == nil {
		info.RootCoinSet = make(map[aut.OutPoint]struct{}, len(rootCoinSet))
	}
	for i := 0; i < len(rootCoinSet); i++ {
		info.RootCoinSet[*rootCoinSet[i]] = struct{}{}
	}

	return info, nil
}

// dbPutUtxoView uses an existing database transaction to update the utxo set
// in the database based on the provided utxo view contents and state.  In
// particular, only the entries that have been marked as modified are written
// to the database.
func dbPutUtxoView(dbTx database.Tx, view *UtxoViewpoint) error {
	utxoBucket := dbTx.Metadata().Bucket(utxoSetBucketName)
	for outpoint, entry := range view.entries {
		// No need to update the database if the entry was not modified.
		if entry == nil || !entry.isModified() {
			continue
		}

		// Remove the utxo entry if it is spent.
		if entry.IsSpent() {
			key := outpointKey(outpoint)
			err := utxoBucket.Delete(*key)
			recycleOutpointKey(key)
			if err != nil {
				return err
			}

			continue
		}

		// Serialize and store the utxo entry.
		serialized, err := serializeUtxoEntry(entry)
		if err != nil {
			return err
		}
		key := outpointKey(outpoint)
		err = utxoBucket.Put(*key, serialized)
		// NOTE: The key is intentionally not recycled here since the
		// database interface contract prohibits modifications.  It will
		// be garbage collected normally when the database is done with
		// it.
		if err != nil {
			return err
		}
	}

	return nil
}

func dbPutAUTView(dbTx database.Tx, view *AUTViewpoint, blockHeight int32, blockHash chainhash.Hash) error {
	autCoinBucket := dbTx.Metadata().Bucket(autCoinBucketName)
	autInfoBucket := dbTx.Metadata().Bucket(autInfoBucketName)
	autRootCoinBucket := dbTx.Metadata().Bucket(autRootCoinBucketName)
	for autNameKey, entry := range view.entries {
		log.Debugf(`AUT identified by %s with following configuration would be stored at height %d (block hash %s):
	Symbol: %s, IssuerUpdateThreshold: %v, IssueTokensThreshold: %v,
	PlannedTotalAmount: %v, ExpireHeight: %v, UnitName: %v, MinUnitName: %v, UnitScale: %v,
	Memo: %v, MintedAmount: %v`,
			string(entry.metadata.AutIdentifier), blockHeight, blockHash,
			string(entry.metadata.AutSymbol),
			entry.metadata.IssuerUpdateThreshold, entry.metadata.IssueTokensThreshold,
			entry.metadata.PlannedTotalAmount, entry.metadata.ExpireHeight,
			entry.metadata.UnitName, entry.metadata.MinUnitName, entry.metadata.UnitScale,
			entry.metadata.AutMemo, entry.metadata.MintedAmount)
		log.Debugf("IssuerTokens: len = %d", len(entry.metadata.IssuerTokens))
		for i := 0; i < len(entry.metadata.IssuerTokens); i++ {
			log.Debugf("[%d] %s", i, hex.EncodeToString(entry.metadata.IssuerTokens[i]))
		}
		// Serialize and store the utxo entry.
		serializedAUTInfo, err := serializeAUTInfo(entry.metadata)
		if err != nil {
			return err
		}
		autName, _ := hex.DecodeString(autNameKey)
		err = autInfoBucket.Put(autName, serializedAUTInfo)
		// NOTE: The key is intentionally not recycled here since the
		// database interface contract prohibits modifications.  It will
		// be garbage collected normally when the database is done with
		// it.
		if err != nil {
			return err
		}

		log.Debugf("RootCoinSet: len = %d", len(entry.metadata.RootCoinSet))
		rootCoinSet := make([]*aut.OutPoint, 0, len(entry.metadata.RootCoinSet))
		for rootCoin := range entry.metadata.RootCoinSet {
			autpoint := &aut.OutPoint{
				TxHash: rootCoin.TxHash,
				Index:  rootCoin.Index,
			}
			rootCoinSet = append(rootCoinSet, autpoint)
			log.Debugf("\t%s", autpoint)
		}
		serializedRootCoinSet, err := serializeAUTRootCoinSet(rootCoinSet)
		if err != nil {
			return err
		}
		err = autRootCoinBucket.Put(autName, serializedRootCoinSet)
		if err != nil {
			return err
		}

		for outpoint, coin := range entry.coins {
			// No need to update the database if the entry was not modified.
			if coin == nil || !coin.isModified() {
				continue
			}
			// Remove the utxo entry if it is spent.
			if coin.IsSpent() {
				key := autOutpointKey(outpoint)
				err := autCoinBucket.Delete(*key)
				recycleOutpointKey(key)
				if err != nil {
					return err
				}
				log.Debugf(`the token (%s,%d) with %d amount in AUT identified by %s is spent at height %d (block hash %s):`,
					outpoint.TxHash.String(), outpoint.Index,
					coin.amount,
					string(entry.metadata.AutIdentifier),
					blockHeight, blockHash)

				continue
			}

			// Serialize and store the coin.
			serialized, err := serializeAUTCoin(coin)
			if err != nil {
				return err
			}
			key := autOutpointKey(outpoint)
			err = autCoinBucket.Put(*key, serialized)
			// NOTE: The key is intentionally not recycled here since the
			// database interface contract prohibits modifications.  It will
			// be garbage collected normally when the database is done with
			// it.
			if err != nil {
				return err
			}
			log.Debugf(`the token (%s,%d) with %d amount in AUT identified by %s is stored at height %d (block hash %s):`,
				outpoint.TxHash.String(), outpoint.Index,
				coin.amount, string(entry.metadata.AutIdentifier),
				blockHeight, blockHash)
		}

	}

	return nil
}

// dbPutUtxoRingView uses an existing database transaction to update the utxo ring set
// in the database based on the provided utxo ring view contents and state.  In
// particular, only the entries that have been marked as modified are written
// to the database.
// todo_DONE(MLP): reviewed on 2024.01.04
func dbPutUtxoRingView(dbTx database.Tx, view *UtxoRingViewpoint) error {
	utxoRingBucket := dbTx.Metadata().Bucket(utxoRingSetBucketName)

	for outPointRingHash, entry := range view.entries {
		// No need to update the database if the entry was not modified.
		if entry == nil || !entry.isModified() {
			continue
		}

		// Remove the utxo entry if it is spent.
		if entry.IsAllSpent() {
			key := outPointRingKey(outPointRingHash)
			err := utxoRingBucket.Delete(*key)
			recycleOutPointRingKey(key)
			if err != nil {
				return err
			}
			log.Debugf("delete output point ring with key %s", outPointRingHash.String())
			continue
		}

		// Serialize and store the utxo entry.
		serialized, err := serializeUtxoRingEntry(entry)
		if err != nil {
			return err
		}
		key := outPointRingKey(outPointRingHash)
		err = utxoRingBucket.Put(*key, serialized)
		// NOTE: The key is intentionally not recycled here since the
		// database interface contract prohibits modifications.  It will
		// be garbage collected normally when the database is done with
		// it.
		if err != nil {
			return err
		}
		log.Debugf("store output point ring %d bytes with key %s", len(serialized), outPointRingHash.String())
	}

	return nil
}

// Abe add
func dbRemoveUtxoRingView(dbTx database.Tx, view *UtxoRingViewpoint) error {
	utxoRingBucket := dbTx.Metadata().Bucket(utxoRingSetBucketName)

	if view == nil || len(view.entries) == 0 {
		return nil
	}

	for outPointRingHash, _ := range view.entries {
		key := outPointRingKey(outPointRingHash)
		err := utxoRingBucket.Delete(*key)
		recycleOutPointRingKey(key)
		if err != nil {
			return err
		}
		log.Debugf("delete output point ring with key %s", outPointRingHash.String())
	}

	return nil
}

func dbRemoveAUTInfo(dbTx database.Tx, infoToDel map[string]struct{}, blockHeight int32, blockHash chainhash.Hash) error {
	autInfoBucket := dbTx.Metadata().Bucket(autInfoBucketName)
	autRootCoinBucket := dbTx.Metadata().Bucket(autRootCoinBucketName)
	autCoinBucket := dbTx.Metadata().Bucket(autCoinBucketName)

	for autIdentifierKey, _ := range infoToDel {
		autIdentifier, _ := hex.DecodeString(autIdentifierKey)
		err := autInfoBucket.Delete(autIdentifier)
		if err != nil {
			return err
		}

		err = autRootCoinBucket.Delete(autIdentifier)
		if err != nil {
			return err
		}

		err = autCoinBucket.Delete(autIdentifier)
		if err != nil {
			return err
		}
		log.Debugf(`AUT identified by %s would be deleted at height %d (block hash %s)`,
			string(autIdentifier), blockHeight, blockHash.String())
	}

	return nil
}

// -----------------------------------------------------------------------------
// The block index consists of two buckets with an entry for every block in the
// main chain.  One bucket is for the hash to height mapping and the other is
// for the height to hash mapping.
//
// The serialized format for values in the hash to height bucket is:
//   <height>
//
//   Field      Type     Size
//   height     uint32   4 bytes
//
// The serialized format for values in the height to hash bucket is:
//   <hash>
//
//   Field      Type             Size
//   hash       chainhash.Hash   chainhash.HashSize
// -----------------------------------------------------------------------------

// dbPutBlockIndex uses an existing database transaction to update or add the
// block index entries for the hash to height and height to hash mappings for
// the provided values.
func dbPutBlockIndex(dbTx database.Tx, hash *chainhash.Hash, height int32) error {
	// Serialize the height for use in the index entries.
	var serializedHeight [4]byte
	byteOrder.PutUint32(serializedHeight[:], uint32(height))

	// Add the block hash to height mapping to the index.
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(hashIndexBucketName)
	if err := hashIndex.Put(hash[:], serializedHeight[:]); err != nil {
		return err
	}

	// Add the block height to hash mapping to the index.
	heightIndex := meta.Bucket(heightIndexBucketName)
	return heightIndex.Put(serializedHeight[:], hash[:])
}

// dbRemoveBlockIndex uses an existing database transaction remove block index
// entries from the hash to height and height to hash mappings for the provided
// values.
func dbRemoveBlockIndex(dbTx database.Tx, hash *chainhash.Hash, height int32) error {
	// Remove the block hash to height mapping.
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(hashIndexBucketName)
	if err := hashIndex.Delete(hash[:]); err != nil {
		return err
	}

	// Remove the block height to hash mapping.
	var serializedHeight [4]byte
	byteOrder.PutUint32(serializedHeight[:], uint32(height))
	heightIndex := meta.Bucket(heightIndexBucketName)
	return heightIndex.Delete(serializedHeight[:])
}

// dbFetchHeightByHash uses an existing database transaction to retrieve the
// height for the provided hash from the index.
func dbFetchHeightByHash(dbTx database.Tx, hash *chainhash.Hash) (int32, error) {
	meta := dbTx.Metadata()
	hashIndex := meta.Bucket(hashIndexBucketName)
	serializedHeight := hashIndex.Get(hash[:])
	if serializedHeight == nil {
		str := fmt.Sprintf("block %s is not in the main chain", hash)
		return 0, errNotInMainChain(str)
	}

	return int32(byteOrder.Uint32(serializedHeight)), nil
}

// dbFetchHashByHeight uses an existing database transaction to retrieve the
// hash for the provided height from the index.
func dbFetchHashByHeight(dbTx database.Tx, height int32) (*chainhash.Hash, error) {
	var serializedHeight [4]byte
	byteOrder.PutUint32(serializedHeight[:], uint32(height))

	meta := dbTx.Metadata()
	heightIndex := meta.Bucket(heightIndexBucketName)
	hashBytes := heightIndex.Get(serializedHeight[:])
	if hashBytes == nil {
		str := fmt.Sprintf("no block at height %d exists", height)
		return nil, errNotInMainChain(str)
	}

	var hash chainhash.Hash
	copy(hash[:], hashBytes)
	return &hash, nil
}

// -----------------------------------------------------------------------------
// The best chain state consists of the best block hash and height, the total
// number of transactions up to and including those in the best block, and the
// accumulated work sum up to and including the best block.
//
// The serialized format is:
//
//   <block hash><block height><total txns><work sum length><work sum>
//
//   Field             Type             Size
//   block hash        chainhash.Hash   chainhash.HashSize
//   block height      uint32           4 bytes
//   total txns        uint64           8 bytes
//   work sum length   uint32           4 bytes
//   work sum          big.Int          work sum length
// -----------------------------------------------------------------------------

// bestChainState represents the data to be stored the database for the current
// best chain state.
type bestChainState struct {
	hash      chainhash.Hash
	height    uint32
	totalTxns uint64
	workSum   *big.Int
}

// serializeBestChainState returns the serialization of the passed block best
// chain state.  This is data to be stored in the chain state bucket.
func serializeBestChainState(state bestChainState) []byte {
	// Calculate the full size needed to serialize the chain state.
	workSumBytes := state.workSum.Bytes()
	workSumBytesLen := uint32(len(workSumBytes))
	serializedLen := chainhash.HashSize + 4 + 8 + 4 + workSumBytesLen

	// Serialize the chain state.
	serializedData := make([]byte, serializedLen)
	copy(serializedData[0:chainhash.HashSize], state.hash[:])
	offset := uint32(chainhash.HashSize)
	byteOrder.PutUint32(serializedData[offset:], state.height)
	offset += 4
	byteOrder.PutUint64(serializedData[offset:], state.totalTxns)
	offset += 8
	byteOrder.PutUint32(serializedData[offset:], workSumBytesLen)
	offset += 4
	copy(serializedData[offset:], workSumBytes)
	return serializedData[:]
}

// deserializeBestChainState deserializes the passed serialized best chain
// state.  This is data stored in the chain state bucket and is updated after
// every block is connected or disconnected form the main chain.
// block.
func deserializeBestChainState(serializedData []byte) (bestChainState, error) {
	// Ensure the serialized data has enough bytes to properly deserialize
	// the hash, height, total transactions, and work sum length.
	if len(serializedData) < chainhash.HashSize+16 {
		return bestChainState{}, database.Error{
			ErrorCode:   database.ErrCorruption,
			Description: "corrupt best chain state",
		}
	}

	state := bestChainState{}
	copy(state.hash[:], serializedData[0:chainhash.HashSize])
	offset := uint32(chainhash.HashSize)
	state.height = byteOrder.Uint32(serializedData[offset : offset+4])
	offset += 4
	state.totalTxns = byteOrder.Uint64(serializedData[offset : offset+8])
	offset += 8
	workSumBytesLen := byteOrder.Uint32(serializedData[offset : offset+4])
	offset += 4

	// Ensure the serialized data has enough bytes to deserialize the work
	// sum.
	if uint32(len(serializedData[offset:])) < workSumBytesLen {
		return bestChainState{}, database.Error{
			ErrorCode:   database.ErrCorruption,
			Description: "corrupt best chain state",
		}
	}
	workSumBytes := serializedData[offset : offset+workSumBytesLen]
	state.workSum = new(big.Int).SetBytes(workSumBytes)

	return state, nil
}

// dbPutBestState uses an existing database transaction to update the best chain
// state with the given parameters.
func dbPutBestState(dbTx database.Tx, snapshot *BestState, workSum *big.Int) error {
	// Serialize the current best chain state.
	serializedData := serializeBestChainState(bestChainState{
		hash:      snapshot.Hash,
		height:    uint32(snapshot.Height),
		totalTxns: snapshot.TotalTxns,
		workSum:   workSum,
	})

	// Store the current best chain state into the database.
	return dbTx.Metadata().Put(chainStateKeyName, serializedData)
}

// createChainState initializes both the database and the chain state to the
// genesis block.  This includes creating the necessary buckets and inserting
// the genesis block, so it must only be called on an uninitialized database.
func (b *BlockChain) createChainState() error {
	// Create a new node from the genesis block and set it as the best node.
	genesisBlock := abeutil.NewBlockAbe(b.chainParams.GenesisBlock)
	genesisBlock.SetHeight(0)
	header := &genesisBlock.MsgBlock().Header
	//	todo: (EthashPoW)
	node, err := b.newBlockNode(header, nil)
	if err != nil {
		return err
	}

	node.status = statusDataStored | statusValid
	b.bestChain.SetTip(node)

	// Add the new node to the index which is used for faster lookups.
	b.index.addNode(node)

	// Initialize the state related to the best block.  Since it is the
	// genesis block, use its timestamp for the median time.
	numTxns := uint64(len(genesisBlock.MsgBlock().Transactions))
	blockSize := uint64(genesisBlock.MsgBlock().SerializeSize())
	//	todo(ABE): ABE does not use weight, while use size only.
	//	blockWeight := uint64(GetBlockWeight(genesisBlock))
	blockWeight := blockSize
	b.stateSnapshot = newBestState(node, blockSize, blockWeight, numTxns,
		numTxns, time.Unix(node.timestamp, 0))

	var activeHeightScope []BlockHeightScope
	currentHeight := int32(0)
	if b.fakePoWHeightScopes != nil {
		activeHeightScope = make([]BlockHeightScope, 0, len(b.fakePoWHeightScopes))
		for _, scope := range b.fakePoWHeightScopes {
			if scope.StartHeight <= currentHeight && currentHeight < scope.EndHeight {
				activeHeightScope = append(activeHeightScope, BlockHeightScope{
					StartHeight: currentHeight + 1,
					EndHeight:   scope.EndHeight,
				})
			} else if currentHeight < scope.StartHeight {
				activeHeightScope = append(activeHeightScope, BlockHeightScope{
					StartHeight: scope.StartHeight,
					EndHeight:   scope.EndHeight,
				})
			}
		}
	}
	// TODO merge the active height scope
	b.fakePoWHeightScopes = activeHeightScope

	// Create the initial the database chain state including creating the
	// necessary index buckets and inserting the genesis block.
	err = b.db.Update(func(dbTx database.Tx) error {
		meta := dbTx.Metadata()

		// Create the bucket that houses the block index data.
		_, err := meta.CreateBucket(blockIndexBucketName)
		if err != nil {
			return err
		}

		// Create the bucket that houses the chain block hash to height
		// index.
		_, err = meta.CreateBucket(hashIndexBucketName)
		if err != nil {
			return err
		}

		// Create the bucket that houses the chain block height to hash
		// index.
		_, err = meta.CreateBucket(heightIndexBucketName)
		if err != nil {
			return err
		}

		//	todo(ABE): This is a bug for BTCD, utxo and spendjournal use wrong name.
		/*		// Create the bucket that houses the spend journal data and
				// store its version.
				_, err = meta.CreateBucket(spendJournalBucketName)
				if err != nil {
					return err
				}
				err = dbPutVersion(dbTx, utxoSetVersionKeyName,
					latestUtxoSetBucketVersion)
				if err != nil {
					return err
				}

				// Create the bucket that houses the utxo set and store its
				// version.  Note that the genesis block coinbase transaction is
				// intentionally not inserted here since it is not spendable by
				// consensus rules.
				_, err = meta.CreateBucket(utxoSetBucketName)
				if err != nil {
					return err
				}
				err = dbPutVersion(dbTx, spendJournalVersionKeyName,
					latestSpendJournalBucketVersion)
				if err != nil {
					return err
				}*/

		// Create the bucket that houses the spend journal data and
		// store its version.
		_, err = meta.CreateBucket(spendJournalBucketName)
		if err != nil {
			return err
		}
		err = dbPutVersion(dbTx, spendJournalVersionKeyName,
			latestSpendJournalBucketVersion)
		if err != nil {
			return err
		}

		// Create the bucket that houses the utxoring set and store its
		// version.  Note that the genesis block coinbase transaction is
		// intentionally not inserted here since it is not spendable by
		// consensus rules.
		//	todo(ABE): in ABE, the outputs of the coinbase transaction are spendable, but it does not matter, since the related utxoring will be generated when later blocks are generated.
		_, err = meta.CreateBucket(utxoRingSetBucketName)
		if err != nil {
			return err
		}
		err = dbPutVersion(dbTx, utxoRingSetVersionKeyName,
			latestUtxoRingSetBucketVersion)
		if err != nil {
			return err
		}

		// Create the bucket that houses the meta infos of deleted witness file,
		// including file size and deleted time.
		_, err = meta.CreateBucket(deletedWitnessFileBucketName)
		if err != nil {
			return err
		}

		_, err = meta.CreateBucket(fakePowHeightScopeBucketName)
		if err != nil {
			return err
		}

		err = dbStoreReadyFakePowBlockScope(dbTx, b.fakePoWHeightScopes)
		if err != nil {
			return err
		}

		_, err = meta.CreateBucket(autInfoBucketName)
		if err != nil {
			return err
		}

		_, err = meta.CreateBucket(autRootCoinBucketName)
		if err != nil {
			return err
		}

		_, err = meta.CreateBucket(autCoinBucketName)
		if err != nil {
			return err
		}

		_, err = meta.CreateBucket(autSpendJournalBucketName)
		if err != nil {
			return err
		}

		// Save the genesis block to the block index database.
		err = dbStoreBlockNode(dbTx, node)
		if err != nil {
			return err
		}

		// Add the genesis block hash to height and height to hash
		// mappings to the index.
		err = dbPutBlockIndex(dbTx, &node.hash, node.height)
		if err != nil {
			return err
		}

		// Store the current best chain state into the database.
		err = dbPutBestState(dbTx, b.stateSnapshot, node.workSum)
		if err != nil {
			return err
		}

		// Store the genesis block into the database.
		return dbStoreBlockAbe(dbTx, genesisBlock)
	})
	return err
}

// initChainState attempts to load and initialize the chain state from the
// database.  When the db does not yet contain any chain state, both it and the
// chain state are initialized to the genesis block.
func (b *BlockChain) initChainState() error {
	// Determine the state of the chain database. We may need to initialize
	// everything from scratch or upgrade certain buckets.
	var initialized, hasBlockIndex bool
	var hasDeletedWitnessFileBucket bool
	var hasAUTRelevantBucket bool
	var workedHeightScope, readyHeightScope []BlockHeightScope
	err := b.db.View(func(dbTx database.Tx) error {
		initialized = dbTx.Metadata().Get(chainStateKeyName) != nil
		hasBlockIndex = dbTx.Metadata().Bucket(blockIndexBucketName) != nil
		hasDeletedWitnessFileBucket = dbTx.Metadata().Bucket(deletedWitnessFileBucketName) != nil
		hasAUTRelevantBucket = dbTx.Metadata().Bucket(autInfoBucketName) != nil

		if b.chainParams.Net != wire.MainNet {
			workedHeightScope = dbFetchWorkedFakePowBlockScope(dbTx)
			readyHeightScope = dbFetchReadyFakePowBlockScope(dbTx)
		}

		return nil
	})
	if err != nil {
		return err
	}

	if !initialized {
		// At this point the database has not already been initialized, so
		// initialize both it and the chain state to the genesis block.
		return b.createChainState()
	}

	// todo: 202207 need refactor to remove
	if !hasBlockIndex {
		err := migrateBlockIndex(b.db)
		if err != nil {
			return nil
		}
	}

	if !hasDeletedWitnessFileBucket {
		// Create the bucket that houses the meta infos of deleted witness file,
		// including the file num, file size and deleted time.
		log.Infof("Adding new index for deleted witness file...")
		err = b.db.Update(func(dbTx database.Tx) error {
			meta := dbTx.Metadata()
			_, err = meta.CreateBucket(deletedWitnessFileBucketName)
			return err
		})
		if err != nil {
			return err
		}
	}

	if !hasAUTRelevantBucket {
		// Create the bucket that houses the meta infos of deleted witness file,
		// including the file num, file size and deleted time.
		log.Infof("Creating bucket for aut information...")
		err = b.db.Update(func(dbTx database.Tx) error {
			meta := dbTx.Metadata()
			_, err = meta.CreateBucket(autInfoBucketName)
			if err != nil {
				return err
			}

			_, err = meta.CreateBucket(autRootCoinBucketName)
			if err != nil {
				return err
			}

			_, err = meta.CreateBucket(autCoinBucketName)
			if err != nil {
				return err
			}

			_, err = meta.CreateBucket(autSpendJournalBucketName)
			if err != nil {
				return err
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	// Attempt to load the chain state from the database.
	err = b.db.View(func(dbTx database.Tx) error {
		// Fetch the stored chain state from the database metadata.
		// When it doesn't exist, it means the database hasn't been
		// initialized for use with chain yet, so break out now to allow
		// that to happen under a writable database transaction.
		serializedData := dbTx.Metadata().Get(chainStateKeyName)
		log.Tracef("Serialized chain state: %x", serializedData)
		state, err := deserializeBestChainState(serializedData)
		if err != nil {
			return err
		}

		// Load all of the headers from the data for the known best
		// chain and construct the block index accordingly.  Since the
		// number of nodes are already known, perform a single alloc
		// for them versus a whole bunch of little ones to reduce
		// pressure on the GC.
		log.Infof("Loading block index...")

		blockIndexBucket := dbTx.Metadata().Bucket(blockIndexBucketName)

		//// Determine how many blocks will be loaded into the index so we can
		//// allocate the right amount.
		//var blockCount int32
		//cursor := blockIndexBucket.Cursor()
		//for ok := cursor.First(); ok; ok = cursor.Next() {
		//	blockCount++
		//}
		//blockNodes := make([]blockNode, blockCount)

		var i int32
		var lastNode *blockNode
		cursor := blockIndexBucket.Cursor()
		for ok := cursor.First(); ok; ok = cursor.Next() {
			header, status, err := deserializeBlockRow(cursor.Value())
			if err != nil {
				return err
			}

			// Determine the parent block node. Since we iterate block headers
			// in order of height, if the blocks are mostly linear there is a
			// very good chance the previous header processed is the parent.
			var parent *blockNode
			if lastNode == nil {
				blockHash := header.BlockHash()
				if !blockHash.IsEqual(b.chainParams.GenesisHash) {
					return AssertError(fmt.Sprintf("initChainState: Expected "+
						"first entry in block index to be genesis block, "+
						"found %s", blockHash))
				}
			} else if header.PrevBlock == lastNode.hash {
				// Since we iterate block headers in order of height, if the
				// blocks are mostly linear there is a very good chance the
				// previous header processed is the parent.
				parent = lastNode
			} else {
				parent = b.index.LookupNode(&header.PrevBlock)
				if parent == nil {
					return AssertError(fmt.Sprintf("initChainState: Could "+
						"not find parent for block %s", header.BlockHash()))
				}
			}

			// Initialize the block node for the block, connect it,
			// and add it to the block index.
			node := new(blockNode)
			//	todo: (EthashPoW)
			err = b.initBlockNode(node, header, parent)
			if err != nil {
				return err
			}

			node.status = status
			b.index.addNode(node)

			lastNode = node
			i++
		}

		// Set the best chain view to the stored best state.
		tip := b.index.LookupNode(&state.hash)
		if tip == nil {
			return AssertError(fmt.Sprintf("initChainState: cannot find "+
				"chain tip %s in block index", state.hash))
		}
		b.bestChain.SetTip(tip)

		// Load the raw block bytes for the best block.
		blockBytes, _, err := dbTx.FetchBlockAbe(&state.hash)
		if err != nil {
			return err
		}
		var block wire.MsgBlockAbe
		err = block.DeserializeNoWitness(bytes.NewReader(blockBytes)) // if wrongly closed, the data will damaged.
		if err != nil {
			return err
		}

		// As a final consistency check, we'll run through all the
		// nodes which are ancestors of the current chain tip, and mark
		// them as valid if they aren't already marked as such.  This
		// is a safe assumption as all the block before the current tip
		// are valid by definition.
		for iterNode := tip; iterNode != nil; iterNode = iterNode.parent {
			// If this isn't already marked as valid in the index, then
			// we'll mark it as valid now to ensure consistency once
			// we're up and running.
			if !iterNode.status.KnownValid() {
				log.Infof("Block %v (height=%v) ancestor of "+
					"chain tip not marked as valid, "+
					"upgrading to valid for consistency",
					iterNode.hash, iterNode.height)

				b.index.SetStatusFlags(iterNode, statusValid)
			}
		}

		// Initialize the state related to the best block.
		blockSize := uint64(len(blockBytes))
		//	todo(ABE): ABE does not use weight, while use size only.
		//		blockWeight := uint64(GetBlockWeight(abeutil.NewBlock(&block)))
		blockWeight := blockSize
		numTxns := uint64(len(block.Transactions))
		b.stateSnapshot = newBestState(tip, blockSize, blockWeight,
			numTxns, state.totalTxns, tip.CalcPastMedianTime())

		return nil
	})
	if err != nil {
		return err
	}

	// As we might have updated the index after it was loaded, we'll
	// attempt to flush the index to the DB. This will only result in a
	// write if the elements are dirty, so it'll usually be a noop.
	err = b.index.flushToDB()
	if err != nil {
		return err
	}

	if b.chainParams.Net == wire.MainNet {
		return nil
	}

	activeHeightScope := make([]BlockHeightScope, 0, len(readyHeightScope))
	currentHeight := b.bestChain.Height()
	for _, scope := range readyHeightScope {
		if scope.StartHeight <= currentHeight && currentHeight < scope.EndHeight {
			workedHeightScope = append(workedHeightScope, BlockHeightScope{
				StartHeight: scope.StartHeight,
				EndHeight:   currentHeight,
			})
			activeHeightScope = append(activeHeightScope, BlockHeightScope{
				StartHeight: currentHeight + 1,
				EndHeight:   scope.EndHeight,
			})
		} else if scope.EndHeight <= currentHeight {
			workedHeightScope = append(workedHeightScope, BlockHeightScope{
				StartHeight: scope.StartHeight,
				EndHeight:   scope.EndHeight,
			})
		} else {
			activeHeightScope = append(activeHeightScope, BlockHeightScope{
				StartHeight: scope.StartHeight,
				EndHeight:   scope.EndHeight,
			})
		}
	}

	// replace with caller-defined scopes
	if b.fakePoWHeightScopes != nil {
		activeHeightScope = make([]BlockHeightScope, 0, len(b.fakePoWHeightScopes))
		for _, scope := range b.fakePoWHeightScopes {
			if scope.StartHeight <= currentHeight && currentHeight < scope.EndHeight {
				activeHeightScope = append(activeHeightScope, BlockHeightScope{
					StartHeight: currentHeight + 1,
					EndHeight:   scope.EndHeight,
				})
			} else if currentHeight < scope.StartHeight {
				activeHeightScope = append(activeHeightScope, BlockHeightScope{
					StartHeight: scope.StartHeight,
					EndHeight:   scope.EndHeight,
				})
			}
		}
	}

	// TODO merge the worked/active height scope

	b.workedHeightScope = workedHeightScope
	b.fakePoWHeightScopes = activeHeightScope

	// flush workedHeightScope and activeHeightScope into database
	err = b.db.Update(func(tx database.Tx) error {
		dbErr := dbStoreWorkedFakePowBlockScope(tx, workedHeightScope)
		if dbErr != nil {
			return dbErr
		}
		return dbStoreReadyFakePowBlockScope(tx, activeHeightScope)
	})
	if err != nil {
		return err
	}

	return nil
}

// deserializeBlockRow parses a value in the block index bucket into a block
// header and block status bitfield.
func deserializeBlockRow(blockRow []byte) (*wire.BlockHeader, blockStatus, error) {
	buffer := bytes.NewReader(blockRow)

	var header wire.BlockHeader
	err := header.Deserialize(buffer)
	if err != nil {
		return nil, statusNone, err
	}

	statusByte, err := buffer.ReadByte()
	if err != nil {
		return nil, statusNone, err
	}

	return &header, blockStatus(statusByte), nil
}

// dbFetchHeaderByHash uses an existing database transaction to retrieve the
// block header for the provided hash.
func dbFetchHeaderByHash(dbTx database.Tx, hash *chainhash.Hash) (*wire.BlockHeader, error) {
	headerBytes, err := dbTx.FetchBlockHeader(hash)
	if err != nil {
		return nil, err
	}

	var header wire.BlockHeader
	err = header.Deserialize(bytes.NewReader(headerBytes))
	if err != nil {
		return nil, err
	}

	return &header, nil
}

// dbFetchHeaderByHeight uses an existing database transaction to retrieve the
// block header for the provided height.
func dbFetchHeaderByHeight(dbTx database.Tx, height int32) (*wire.BlockHeader, error) {
	hash, err := dbFetchHashByHeight(dbTx, height)
	if err != nil {
		return nil, err
	}

	return dbFetchHeaderByHash(dbTx, hash)
}

// dbFetchBlockByNode uses an existing database transaction to retrieve the
// raw block for the provided node, deserialize it, and return a btcutil.Block
// with the height set.
func dbFetchBlockByNode(dbTx database.Tx, node *blockNode) (*abeutil.Block, error) {
	// Load the raw block bytes from the database.
	blockBytes, err := dbTx.FetchBlock(&node.hash)
	if err != nil {
		return nil, err
	}

	// Create the encapsulated block and set the height appropriately.
	block, err := abeutil.NewBlockFromBytes(blockBytes)
	if err != nil {
		return nil, err
	}
	block.SetHeight(node.height)

	return block, nil
}

func dbFetchBlockByNodeAbe(dbTx database.Tx, node *blockNode) (*abeutil.BlockAbe, error) {
	// Load the raw block bytes from the database.
	blockBytes, witnesses, err := dbTx.FetchBlockAbe(&node.hash)
	if err != nil {
		return nil, err
	}

	// Create the encapsulated block and set the height appropriately.
	block, err := abeutil.NewBlockFromBytesAbe(blockBytes)
	if err != nil {
		return nil, err
	}

	// Witness
	if witnesses != nil {
		txs := block.Transactions()
		for i := 0; i < len(txs); i++ {
			txs[i].MsgTx().TxWitness = witnesses[i][chainhash.HashSize:]
		}
	}
	block.SetHeight(node.height)

	return block, nil
}

// dbStoreBlockNode stores the block header and validation status to the block
// index bucket. This overwrites the current entry if there exists one.
func dbStoreBlockNode(dbTx database.Tx, node *blockNode) error {
	// Serialize block data to be stored.
	//	todo: (EthashPoW) use MaxBlockHeaderPayload rather than blockHdrSize, to avoid misunderstanding
	// w := bytes.NewBuffer(make([]byte, 0, blockHdrSize+1))
	w := bytes.NewBuffer(make([]byte, 0, wire.MaxBlockHeaderPayloadEthash+1))
	header := node.Header()
	err := header.Serialize(w)
	if err != nil {
		return err
	}
	err = w.WriteByte(byte(node.status))
	if err != nil {
		return err
	}
	value := w.Bytes()

	// Write block header data to block index bucket.
	blockIndexBucket := dbTx.Metadata().Bucket(blockIndexBucketName)
	key := blockIndexKey(&node.hash, uint32(node.height))
	return blockIndexBucket.Put(key, value)
}

// dbStoreBlock stores the provided block in the database if it is not already
// there. The full block data is written to ffldb.
func dbStoreBlock(dbTx database.Tx, block *abeutil.Block) error {
	hasBlock, err := dbTx.HasBlock(block.Hash())
	if err != nil {
		return err
	}
	if hasBlock {
		return nil
	}
	return dbTx.StoreBlock(block)
}

// Abe to do
func dbStoreBlockAbe(dbTx database.Tx, block *abeutil.BlockAbe) error {
	hasBlock, err := dbTx.HasBlock(block.Hash())
	if err != nil {
		return err
	}
	if hasBlock {
		return nil
	}
	return dbTx.StoreBlockAbe(block)
}

// blockIndexKey generates the binary key for an entry in the block index
// bucket. The key is composed of the block height encoded as a big-endian
// 32-bit unsigned int followed by the 32 byte block hash.
func blockIndexKey(blockHash *chainhash.Hash, blockHeight uint32) []byte {
	indexKey := make([]byte, chainhash.HashSize+4)
	binary.BigEndian.PutUint32(indexKey[0:4], blockHeight)
	copy(indexKey[4:chainhash.HashSize+4], blockHash[:])
	return indexKey
}

// BlockByHeight returns the block at the given height in the main chain.
//
// This function is safe for concurrent access.
//
//	todo(ABE):
func (b *BlockChain) BlockByHeightBTCD(blockHeight int32) (*abeutil.Block, error) {
	// Lookup the block height in the best chain.
	node := b.bestChain.NodeByHeight(blockHeight)
	if node == nil {
		str := fmt.Sprintf("no block at height %d exists", blockHeight)
		return nil, errNotInMainChain(str)
	}

	// Load the block from the database and return it.
	var block *abeutil.Block
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		block, err = dbFetchBlockByNode(dbTx, node)
		return err
	})
	return block, err
}

func (b *BlockChain) BlockByHeight(blockHeight int32) (*abeutil.BlockAbe, error) {
	// Lookup the block height in the best chain.
	node := b.bestChain.NodeByHeight(blockHeight)
	if node == nil {
		str := fmt.Sprintf("no block at height %d exists", blockHeight)
		return nil, errNotInMainChain(str)
	}

	// Load the block from the database and return it.
	var block *abeutil.BlockAbe
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		block, err = dbFetchBlockByNodeAbe(dbTx, node)
		return err
	})
	return block, err
}

// BlockByHash returns the block from the main chain with the given hash with
// the appropriate chain height set.
//
// This function is safe for concurrent access.
func (b *BlockChain) BlockByHash(hash *chainhash.Hash) (*abeutil.Block, error) {
	// Lookup the block hash in block index and ensure it is in the best
	// chain.
	node := b.index.LookupNode(hash)
	if node == nil || !b.bestChain.Contains(node) {
		str := fmt.Sprintf("block %s is not in the main chain", hash)
		return nil, errNotInMainChain(str)
	}

	// Load the block from the database and return it.
	var block *abeutil.Block
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		block, err = dbFetchBlockByNode(dbTx, node)
		return err
	})
	return block, err
}

func (b *BlockChain) BlockByHashAbe(hash *chainhash.Hash) (*abeutil.BlockAbe, error) {
	// Lookup the block hash in block index and ensure it is in the best
	// chain.
	node := b.index.LookupNode(hash)
	if node == nil || !b.bestChain.Contains(node) {
		str := fmt.Sprintf("block %s is not in the main chain", hash)
		return nil, errNotInMainChain(str)
	}

	// Load the block from the database and return it.
	var block *abeutil.BlockAbe
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		block, err = dbFetchBlockByNodeAbe(dbTx, node)
		return err
	})
	return block, err
}

// dbFetchWitnessFileNumByHashes fetch the file num that stores the block witness.
func dbFetchWitnessFileNumByHashes(dbTx database.Tx, hashes []*chainhash.Hash) ([]uint32, error) {
	return dbTx.FetchWitnessFileNum(hashes)
}

// dbPruneWitnessFile prune the specified witness files.
func dbPruneWitnessFile(dbTx database.Tx, fileNumPruned []uint32) ([]string, error) {
	return dbTx.DeleteWitnessFiles(fileNumPruned)
}

// dbFetchWitnessFileInfo fetch the concrete info of witness files.
func dbFetchWitnessFileInfo(dbTx database.Tx, fileNumPruned []uint32) (map[uint32]os.FileInfo, error) {
	return dbTx.FetchWitnessFileInfo(fileNumPruned)
}

// FileNumBetweenHeight fetch the corresponding file num that stores the block witness between
// startHeight and endHeight. The result has been deduplicated and sorted (positive order).
func (b *BlockChain) FileNumBetweenHeight(startHeight uint32, endHeight uint32) ([]uint32, error) {
	hashes := make([]*chainhash.Hash, 0)
	for i := startHeight; i <= endHeight; i++ {
		blkHash := b.bestChain.nodeByHeight(int32(i))
		hashes = append(hashes, &blkHash.hash)
	}

	// Fetch witness file number of each block by hashes.
	var fileNum []uint32
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		fileNum, err = dbFetchWitnessFileNumByHashes(dbTx, hashes)
		return err
	})
	if err != nil {
		return nil, err
	}

	// Deduplicate file number.
	fileNumMap := make(map[uint32]struct{})
	res := make([]uint32, 0)
	for _, num := range fileNum {
		if _, ok := fileNumMap[num]; !ok {
			res = append(res, num)
			fileNumMap[num] = struct{}{}
		}
	}

	//  Sort the file number.
	sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })
	return res, nil
}

// PruneWitnessFile prune the witness files specified as well as update minWitnessFileNum.
func (b *BlockChain) PruneWitnessFile(fileNumPruned []uint32) ([]string, error) {
	if len(fileNumPruned) == 0 {
		return nil, nil
	}

	var deleted []string
	err := b.db.Update(func(dbTx database.Tx) error {
		var err error
		deleted, err = dbPruneWitnessFile(dbTx, fileNumPruned)
		return err
	})
	return deleted, err
}

// UpdateMinConsecutiveWitnessFileNum update the minConsecutiveWitnessFileNum if needed.
func (b *BlockChain) UpdateMinConsecutiveWitnessFileNum(num uint32) error {
	var currentNum uint32
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		currentNum, err = dbTx.FetchMinConsecutiveWitnessFileNum()
		return err
	})
	if err != nil {
		return err
	}

	if num > currentNum {
		log.Debugf("Update min consecutive witness file num from %v to %v", currentNum, num)
		err := b.db.Update(func(dbTx database.Tx) error {
			var err error
			err = dbTx.StoreMinConsecutiveWitnessFileNum(num)
			return err
		})
		if err != nil {
			return err
		}
	} else {
		log.Debugf("Remain min consecutive witness file num %v (new num: %v)", currentNum, num)
	}
	return nil
}

// FetchMinExistingWitnessFileNum fetch the existing witness file num.
func (b *BlockChain) FetchMinExistingWitnessFileNum() (uint32, error) {
	var currentNum uint32
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		currentNum, err = dbTx.FetchMinExistingWitnessFileNum()
		return err
	})
	return currentNum, err
}

// StoreMinExistingWitnessFileNum store the minExistingWitnessFileNum.
func (b *BlockChain) StoreMinExistingWitnessFileNum(num uint32) error {
	err := b.db.Update(func(dbTx database.Tx) error {
		var err error
		err = dbTx.StoreMinExistingWitnessFileNum(num)
		return err
	})
	return err
}

// FetchWitnessFileInfo fetch the concrete info of witness files.
func (b *BlockChain) FetchWitnessFileInfo(fileNumPruned []uint32) (map[uint32]os.FileInfo, error) {
	if len(fileNumPruned) == 0 {
		return nil, nil
	}

	var fileInfos map[uint32]os.FileInfo
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		fileInfos, err = dbFetchWitnessFileInfo(dbTx, fileNumPruned)
		return err
	})
	return fileInfos, err
}

// StoreDeleteHistory store the information of witness file that will be deleted.
func (b *BlockChain) StoreDeleteHistory(fileInfos map[uint32]os.FileInfo) error {
	err := b.db.Update(func(dbTx database.Tx) error {
		var err error
		for num, fileInfo := range fileInfos {
			err = dbPutDeletedHistory(dbTx, num, fileInfo.Size(), time.Now().Unix())
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

// UpdateMinExistingWitnessFileNum update min existing witness file num automatically.
func (b *BlockChain) UpdateMinExistingWitnessFileNum() error {
	err := b.db.Update(func(dbTx database.Tx) error {
		return dbTx.UpdateMinExistingWitnessFileNum()
	})
	return err
}

// StoreWitnessServiceHeight update witness service height in db.
func (b *BlockChain) StoreWitnessServiceHeight(height uint32) error {
	err := b.db.Update(func(dbTx database.Tx) error {
		return dbTx.StoreWitnessServiceHeight(height)
	})
	return err
}

// FetchWitnessServiceHeight fetch witness service height in db.
func (b *BlockChain) FetchWitnessServiceHeight() (uint32, error) {
	var witnessServiceHeight uint32
	err := b.db.View(func(dbTx database.Tx) error {
		var err error
		witnessServiceHeight, err = dbTx.FetchWitnessServiceHeight()
		return err
	})
	return witnessServiceHeight, err
}

// dbStoreWorkedFakePowBlockScope store the worked block height with fake pow
func dbStoreWorkedFakePowBlockScope(dbTx database.Tx, scopes []BlockHeightScope) error {
	bucket, err := dbTx.Metadata().CreateBucketIfNotExists(fakePowHeightScopeBucketName)
	if err != nil {
		return err
	}
	serializedScopes := make([]string, len(scopes))
	for i, scope := range scopes {
		serializedScopes[i] = fmt.Sprintf("%d_%d", scope.StartHeight, scope.EndHeight)
	}
	return bucket.Put(workedFakePowHeightScopeKeyName, []byte(strings.Join(serializedScopes, ":")))
}
func dbFetchWorkedFakePowBlockScope(dbTx database.Tx) []BlockHeightScope {
	bucket := dbTx.Metadata().Bucket(fakePowHeightScopeBucketName)
	if bucket == nil {
		return nil
	}

	serializedBlockHeightScopes := bucket.Get(workedFakePowHeightScopeKeyName)
	if len(serializedBlockHeightScopes) == 0 {
		return nil
	}

	scopes := strings.Split(string(serializedBlockHeightScopes), ":")
	res := make([]BlockHeightScope, len(scopes))
	for i, scope := range scopes {
		heights := strings.Split(scope, "_")
		startHeight, _ := strconv.Atoi(heights[0])
		endHeight, _ := strconv.Atoi(heights[1])
		res[i].StartHeight = int32(startHeight)
		res[i].EndHeight = int32(endHeight)
	}

	return res
}

// dbStoreReadyFakePowBlockScope store the ready block height with fake pow
func dbStoreReadyFakePowBlockScope(dbTx database.Tx, scopes []BlockHeightScope) error {
	bucket, err := dbTx.Metadata().CreateBucketIfNotExists(fakePowHeightScopeBucketName)
	if err != nil {
		return err
	}
	serializedScopes := make([]string, len(scopes))
	for i, scope := range scopes {
		serializedScopes[i] = fmt.Sprintf("%d_%d", scope.StartHeight, scope.EndHeight)
	}
	return bucket.Put(readyFakePowHeightScopeKeyName, []byte(strings.Join(serializedScopes, ":")))
}
func dbFetchReadyFakePowBlockScope(dbTx database.Tx) []BlockHeightScope {
	bucket := dbTx.Metadata().Bucket(fakePowHeightScopeBucketName)
	if bucket == nil {
		return nil
	}

	serializedBlockHeightScopes := bucket.Get(readyFakePowHeightScopeKeyName)
	if len(serializedBlockHeightScopes) == 0 {
		return nil
	}

	scopes := strings.Split(string(serializedBlockHeightScopes), ":")
	res := make([]BlockHeightScope, len(scopes))
	for i, scope := range scopes {
		heights := strings.Split(scope, "_")
		startHeight, _ := strconv.Atoi(heights[0])
		endHeight, _ := strconv.Atoi(heights[1])
		res[i].StartHeight = int32(startHeight)
		res[i].EndHeight = int32(endHeight)
	}

	return res
}

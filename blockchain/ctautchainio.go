package blockchain

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	//"reflect"
	"sync"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/ctaut"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/wire"
)

var (
	// Confidential Transaction AUTScript - Abelian User Token (CTAUT) state
	ctAutInstanceBucketName     = []byte("ctautinstance")
	ctAutTokenBucketName        = []byte("ctauttoken")
	ctAutSpendJournalBucketName = []byte("ctautspendjournal")
)

func createBucketForCTAUT(meta database.Bucket) error {
	_, err := meta.CreateBucket(ctAutInstanceBucketName)
	if err != nil {
		return err
	}

	_, err = meta.CreateBucket(ctAutTokenBucketName)
	if err != nil {
		return err
	}

	_, err = meta.CreateBucket(ctAutSpendJournalBucketName)
	if err != nil {
		return err
	}
	return nil
}

var ctautOutpointKeyPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, chainhash.HashSize+maxUint32VLQSerializeSize)
		return &b // Pointer to slice to avoid boxing alloc.
	},
}

func ctautOutpointKey(outpoint ctaut.HostOutPoint) *[]byte {
	// A VLQ employs an MSB encoding, so they are useful not only to reduce
	// the amount of storage space, but also so iteration of utxos when
	// doing byte-wise comparisons will produce them in order.
	key := ctautOutpointKeyPool.Get().(*[]byte)
	idx := uint64(outpoint.Index)
	*key = (*key)[:chainhash.HashSize+serializeSizeVLQ(idx)]
	copy(*key, outpoint.TxHash[:])
	putVLQ((*key)[chainhash.HashSize:], idx)
	return key
}

func recycleCTAUTOutpointKey(key *[]byte) {
	ctautOutpointKeyPool.Put(key)
}

type SpentCTAUTType int

const ConsumeCTAUTToken SpentCTAUTType = 0
const UpdateCTAUTInfo SpentCTAUTType = 1

type SpentCTAUT interface {
	Type() SpentCTAUTType
}
type UpdatedCTAUTInfo struct {
	Before *ctaut.AutMetadata
	After  *ctaut.AutMetadata

	// Height is the height of the the block containing the creating tx.
	Height int32

	// Denotes if the creating tx is a registration or re-registration.
	IsReRegistration bool
}

func (s *UpdatedCTAUTInfo) Type() SpentCTAUTType {
	return UpdateCTAUTInfo
}

type SpentCTAUTTokens []SpentCTAUTToken

func (s *SpentCTAUTTokens) Type() SpentCTAUTType {
	return ConsumeCTAUTToken
}

type SpentCTAUTToken struct {
	// Amount is the amount of the output.
	Script []byte

	// Height is the height of the the block containing the creating tx.
	Height int32
}

func spentCTAUTSerializeSize(stxo SpentCTAUT) (int, error) {
	size := 1 // 1 for type
	switch updated := stxo.(type) {
	case *SpentCTAUTTokens:
		tokens := *updated
		size += serializeSizeVLQ(uint64(len(tokens)))
		for _, token := range tokens {
			headerCode := uint64(token.Height)
			size += serializeSizeVLQ(headerCode)

			size += serializeSizeVLQ(uint64(len(token.Script)))
			size += len(token.Script)
		}

	case *UpdatedCTAUTInfo:
		headerCode := uint64(updated.Height)
		size += serializeSizeVLQ(headerCode)

		size += 1
		// +1 to represent nil for before
		size += 1
		serializedBefore, err := updated.Before.Serialize()
		if err != nil {
			return 0, err
		}
		if len(serializedBefore) != 0 {
			size += serializeSizeVLQ(uint64(len(serializedBefore)))
			size += len(serializedBefore)
		}

		// +1 to represent nil for after
		size += 1
		sizeAfter, err := updated.After.Serialize()
		if err != nil {
			return 0, err
		}
		if len(sizeAfter) != 0 {
			size += serializeSizeVLQ(uint64(len(sizeAfter)))
			size += len(sizeAfter)
		}

	default:
		return 0, errors.New("unknown type for SpendCTAUT")
	}
	return size, nil
}
func putSpentCTAUT(target []byte, stxo SpentCTAUT) (int, error) {
	offset := 0
	switch updated := stxo.(type) {
	case *SpentCTAUTTokens:
		offset += putVLQ(target[offset:], 0) // type

		tokens := *updated
		offset += putVLQ(target[offset:], uint64(len(tokens)))
		for i := 0; i < len(tokens); i++ {
			token := tokens[i]

			headerCode := uint64(token.Height)
			offset += putVLQ(target[offset:], headerCode)

			vlqSizeLen := putVLQ(target[offset:], uint64(len(token.Script)))
			offset += vlqSizeLen
			copy(target[offset:], token.Script)
			offset += len(token.Script)
		}

	case *UpdatedCTAUTInfo:
		offset += putVLQ(target[offset:], 1)

		headerCode := uint64(updated.Height)
		offset += putVLQ(target[offset:], headerCode)

		target[offset] = 0x00
		if updated.IsReRegistration {
			target[offset] = 0x01
		}
		offset += 1

		// +1 to represent nil
		serializedBefore, err := updated.Before.Serialize()
		if err != nil {
			return 0, err
		}
		if len(serializedBefore) == 0 {
			target[offset] = 0
			offset += 1
		} else {
			target[offset] = 1
			offset += 1

			vlqSizeLen := putVLQ(target[offset:], uint64(len(serializedBefore)))
			offset += vlqSizeLen
			copy(target[offset:], serializedBefore)
			offset += len(serializedBefore)
		}

		serializedAfter, err := updated.After.Serialize()
		if err != nil {
			return 0, err
		}
		if len(serializedAfter) == 0 {
			target[offset] = 0
			offset += 1
		} else {
			target[offset] = 1
			offset += 1

			vlqSizeLen := putVLQ(target[offset:], uint64(len(serializedAfter)))
			offset += vlqSizeLen
			copy(target[offset:], serializedAfter)
			offset += len(serializedAfter)
		}
	}
	// TODO(CTAUT) assert length
	length, _ := spentCTAUTSerializeSize(stxo)
	if offset != length {
		panic("spentCTAUTSerializeSize() should never fail")
	}
	return offset, nil
}
func decodeSpentCTAUT(serialized []byte) (SpentCTAUT, int, error) {
	// Ensure there are bytes to decode.
	if len(serialized) == 0 {
		return nil, 0, errDeserialize("no serialized bytes")
	}

	stxoType, offset := deserializeVLQ(serialized)
	switch stxoType {
	case 0:
		numSpendCTAUTToken, n := deserializeVLQ(serialized[offset:])
		offset += n
		if offset >= len(serialized) {
			return nil, offset, errDeserialize("unexpected end of data after " +
				"header code")
		}

		res := (SpentCTAUTTokens)(make([]SpentCTAUTToken, numSpendCTAUTToken))
		for i := uint64(0); i < numSpendCTAUTToken; i++ {
			headerCode, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data after " +
					"header code")
			}
			res[i].Height = int32(headerCode)

			scriptSize, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset+int(scriptSize) > len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data for reading script")
			}
			res[i].Script = make([]byte, scriptSize)
			copy(res[i].Script, serialized[offset:offset+int(scriptSize)])
			offset += int(scriptSize)
		}
		return &res, offset, nil

	case 1:
		res := UpdatedCTAUTInfo{}

		headerCode, bytesRead := deserializeVLQ(serialized[offset:])
		offset += bytesRead
		if offset >= len(serialized) {
			return nil, offset, errDeserialize("unexpected end of data after " +
				"header code")
		}
		res.Height = int32(headerCode)

		flag := serialized[offset]
		offset += 1
		if flag == 0x01 {
			res.IsReRegistration = true
		}

		var err error
		if serialized[offset] == 0 {
			offset += 1
		} else {
			offset += 1
			res.Before = &ctaut.AutMetadata{}
			sizeOfInfo, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}

			err = res.Before.Deserialize(bytes.NewReader(serialized[offset : offset+int(sizeOfInfo)]))
			if err != nil {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}
			offset += int(sizeOfInfo)
		}

		if serialized[offset] == 0 {
			offset += 1
		} else {
			offset += 1
			res.After = &ctaut.AutMetadata{}
			sizeOfInfo, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}
			err = res.After.Deserialize(bytes.NewReader(serialized[offset : offset+int(sizeOfInfo)]))
			if err != nil {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}
			offset += int(sizeOfInfo)
		}
		return &res, offset, nil

	default:
		return nil, 0, errors.New("unknown spent type for CTAUT")
	}
}

func serializeSpendJournalEntryCTAUT(stxos []SpentCTAUT) ([]byte, error) {
	if len(stxos) == 0 {
		return nil, nil
	}

	var size int
	for i := range stxos {
		tmpSize, err := spentCTAUTSerializeSize(stxos[i])
		if err != nil {
			return nil, err
		}
		size += tmpSize

	}
	serialized := make([]byte, size)

	// Serialize each individual stxo directly into the slice in reverse
	// order one after the other.
	var offset int
	for i := len(stxos) - 1; i > -1; i-- {
		tmpOffset, err := putSpentCTAUT(serialized[offset:], stxos[i])
		if err != nil {
			return nil, err
		}
		offset += tmpOffset
	}

	return serialized, nil

}
func deserializeSpendJournalEntryCTAUT(serialized []byte, scripts []*abeutil.CTAUTScript) ([]SpentCTAUT, error) {
	// Calculate the total number of stxos.
	numStxos := len(scripts)

	// When a block has no spent txouts there is nothing to serialize.
	if len(serialized) == 0 && numStxos == 0 {
		return nil, nil
	}
	if len(serialized) == 0 && numStxos != 0 {
		// Ensure the block actually has no stxos.  This should never
		// happen unless there is database corruption or an empty entry
		// erroneously made its way into the database.
		return nil, AssertError(fmt.Sprintf("mismatched spend aut"+
			"journal serialization - no serialization for "+
			"expected %d stxos", numStxos))
	}

	// Loop backwards through all transactions so everything is read in
	// reverse order to match the serialization order.
	stxoIdx := numStxos - 1
	offset := 0
	stxos := make([]SpentCTAUT, numStxos)
	for txIdx := len(scripts) - 1; txIdx >= 0; txIdx-- {
		stxo, n, err := decodeSpentCTAUT(serialized[offset:])
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

func dbPutSpendJournalEntryCTAUT(dbTx database.Tx, blockHash *chainhash.Hash, sauts []SpentCTAUT) error {
	spendJournalBucket := dbTx.Metadata().Bucket(ctAutSpendJournalBucketName)
	serialized, err := serializeSpendJournalEntryCTAUT(sauts)
	if err != nil {
		return err
	}
	if len(serialized) == 0 {
		return nil
	}

	return spendJournalBucket.Put(blockHash[:], serialized)
}
func dbFetchSpendJournalEntryCTAUT(dbTx database.Tx, block *abeutil.BlockAbe) ([]SpentCTAUT, error) {
	// Exclude the coinbase transaction since it can't spend anything.
	spendJournalBucket := dbTx.Metadata().Bucket(ctAutSpendJournalBucketName)
	serialized := spendJournalBucket.Get(block.Hash()[:])

	scripts := block.CTAUTScripts()
	stxos, err := deserializeSpendJournalEntryCTAUT(serialized, scripts)
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
func dbRemoveSpendJournalEntryCTAUT(dbTx database.Tx, blockHash *chainhash.Hash) error {
	spendJournalBucket := dbTx.Metadata().Bucket(ctAutSpendJournalBucketName)
	return spendJournalBucket.Delete(blockHash[:])
}

func serializeCTAUTCoin(coin *CTAUTCoin) ([]byte, error) {
	// Spent outputs have no serialization.
	if coin.IsSpent() {
		return nil, nil
	}

	size := /* header code : [reserved] [height]*/ 8 +
		wire.VarIntSerializeSize(uint64(len(coin.identifier))) + len(coin.identifier) +
		wire.VarIntSerializeSize(uint64(len(coin.script))) + len(coin.script)

	buff := bytes.NewBuffer(make([]byte, 0, size))

	headerCode := uint64(coin.blockHeight)
	tmp := make([]byte, 8)
	binary.LittleEndian.PutUint64(tmp, headerCode)
	_, err := buff.Write(tmp)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(buff, 0, coin.identifier)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(buff, 0, coin.script)
	if err != nil {
		return nil, err
	}
	serializedCTAUTCoin := buff.Bytes()

	//deserializedCoin, err := deserializeCTAUTCoin(serializedCTAUTCoin)
	//if err != nil {
	//	return nil, err
	//}
	//if !reflect.DeepEqual(coin, deserializedCoin) {
	//	return nil, fmt.Errorf("unmatched CTAUTCoin serialized/deserialized")
	//}
	return serializedCTAUTCoin, nil
}
func deserializeCTAUTCoin(serialized []byte) (*CTAUTCoin, error) {
	if len(serialized) < 8 {
		return nil, errDeserialize("unexpected end of data after header")
	}
	// Deserialize the header code.
	headerCode := binary.LittleEndian.Uint64(serialized)
	blockHeight := int32(headerCode)

	reader := bytes.NewReader(serialized[8:])

	identifier, err := wire.ReadVarBytes(reader, 0, ctaut.CTAUTIdentifierLength, "identifier")
	if err != nil {
		return nil, err
	}
	if len(identifier) != ctaut.CTAUTIdentifierLength {
		return nil, errors.New("invalid identifier")
	}

	script, err := wire.ReadVarBytes(reader, 0, ctaut.MaxAUTValueScriptLength, "script")
	if err != nil {
		return nil, err
	}

	return NewCTAUTCoin(identifier, script, blockHeight), nil
}

func dbFetchCTAUTCoin(dbTx database.Tx, outpoint ctaut.HostOutPoint) (*CTAUTCoin, error) {
	// Fetch the unspent transaction output information for the passed
	// transaction output.  Return now when there is no entry.
	key := ctautOutpointKey(outpoint)
	ctAutTokenBucket := dbTx.Metadata().Bucket(ctAutTokenBucketName)
	if ctAutTokenBucket == nil {
		return nil, errors.New("bucket for ctaut coin is not exist")
	}
	serializedCoin := ctAutTokenBucket.Get(*key)
	recycleCTAUTOutpointKey(key)
	if serializedCoin == nil {
		return nil, nil
	}

	// A non-nil zero-length entry means there is an entry in the database
	// for a spent transaction output which should never be the case.
	if len(serializedCoin) == 0 {
		return nil, AssertError(fmt.Sprintf("database contains entry "+
			"for spent tx output %v", outpoint))
	}

	// Deserialize the utxo entry and return it.
	coin, err := deserializeCTAUTCoin(serializedCoin)
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

	return coin, nil
}

func dbFetchCTAUTMetadata(dbTx database.Tx, key []byte) (*ctaut.AutMetadata, error) {
	// Fetch the unspent transaction output information for the passed
	// transaction output.  Return now when there is no entry.
	autInfoBucket := dbTx.Metadata().Bucket(ctAutInstanceBucketName)
	serializedAUTInfo := autInfoBucket.Get(key)
	if serializedAUTInfo == nil {
		return nil, nil
	}

	// Deserialize the utxo entry and return it.
	var metadata ctaut.AutMetadata
	err := metadata.Deserialize(bytes.NewReader(serializedAUTInfo))
	if err != nil {
		// Ensure any deserialization errors are returned as database
		// corruption errors.
		if isDeserializeErr(err) {
			return nil, database.Error{
				ErrorCode: database.ErrCorruption,
				Description: fmt.Sprintf("corrupt information "+
					"for AUT metadata %v: %v", key, err),
			}
		}

		return nil, err
	}

	return &metadata, nil
}
func dbRemoveCTAUTInstance(dbTx database.Tx, instanceToDel map[string]struct{}, blockHeight int32, blockHash chainhash.Hash) error {
	ctautInstanceBucket := dbTx.Metadata().Bucket(ctAutInstanceBucketName)
	ctAutTokenBucket := dbTx.Metadata().Bucket(ctAutTokenBucketName)

	for autIdentifierKey, _ := range instanceToDel {
		autIdentifier, _ := hex.DecodeString(autIdentifierKey)
		err := ctautInstanceBucket.Delete(autIdentifier)
		if err != nil {
			return err
		}

		err = ctAutTokenBucket.Delete(autIdentifier)
		if err != nil {
			return err
		}
		log.Debugf(`AUT identified by %s would be deleted at height %d (block hash %s)`,
			string(autIdentifier), blockHeight, blockHash.String())
	}

	return nil
}

func dbPutCTAUTView(dbTx database.Tx, view *CTAUTViewpoint, blockHeight int32, blockHash chainhash.Hash) error {
	ctAutInfoBucket := dbTx.Metadata().Bucket(ctAutInstanceBucketName)
	ctAutTokenBucket := dbTx.Metadata().Bucket(ctAutTokenBucketName)
	for identifierKey, instance := range view.instances {
		identifier := instance.metadata.CTAutIdentifier

		// Serialize and store the utxo entry.
		serializedCTAUTInfo, err := instance.metadata.Serialize()
		if err != nil {
			return err
		}
		err = ctAutInfoBucket.Put(identifier[:], serializedCTAUTInfo)
		if err != nil {
			return err
		}

		for outpoint, coin := range instance.coins {
			// No need to update the database if the entry was not modified.
			if coin == nil || !coin.isModified() {
				continue
			}
			// Remove the utxo entry if it is spent.
			if coin.IsSpent() {
				key := ctautOutpointKey(outpoint)
				err = ctAutTokenBucket.Delete(*key) // if rollback, would restore by spend journal
				recycleOutpointKey(key)
				if err != nil {
					return err
				}
				log.Debugf(`the token (%s,%d) for CTAUT identified by %s is spent at height %d (block hash %s):`,
					outpoint.TxHash.String(), outpoint.Index, identifierKey, blockHeight, blockHash)

				continue
			}

			// Serialize and store the coin.
			serializedCoin, err := serializeCTAUTCoin(coin)
			if err != nil {
				return err
			}
			key := ctautOutpointKey(outpoint)
			err = ctAutTokenBucket.Put(*key, serializedCoin)
			// NOTE: The key is intentionally not recycled here since the
			// database interface contract prohibits modifications.  It will
			// be garbage collected normally when the database is done with
			// it.
			if err != nil {
				return err
			}
			log.Debugf(`the token (%s,%d) for CTAUT identified by %s is stored at height %d (block hash %s):`,
				outpoint.TxHash.String(), outpoint.Index, identifierKey, blockHeight, blockHash)
		}

	}

	return nil
}

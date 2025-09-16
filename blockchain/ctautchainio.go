package blockchain

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/aut"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/ctaut"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/wire"
)

var (
	// Confidential Transaction - Abelian User Token (CTAUT) state
	ctautInstanceBucketName     = []byte("ctautinstance")
	ctautCoinBucketName         = []byte("ctautcoin")
	ctautSpendJournalBucketName = []byte("ctautspendjournal")
)

func createBucketForCTAUT(meta database.Bucket) error {
	_, err := meta.CreateBucket(ctautInstanceBucketName)
	if err != nil {
		return err
	}

	_, err = meta.CreateBucket(ctautCoinBucketName)
	if err != nil {
		return err
	}

	_, err = meta.CreateBucket(ctautSpendJournalBucketName)
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

func ctautOutpointKey(outpoint ctaut.OutPoint) *[]byte {
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
func serializeCTAUTInstanceSize(info *ctaut.Metadata) int {
	if info == nil {
		return 0
	}
	n :=
		/*identifier, actually fixed length */ wire.VarIntSerializeSize(uint64(len(info.CTAutIdentifier))) + len(info.CTAutIdentifier) +
			/* symbol, variable length */ wire.VarIntSerializeSize(uint64(len(info.CTAutSymbol))) + len(info.CTAutSymbol) +
			/* memo, variable length */ wire.VarIntSerializeSize(uint64(len(info.AutMemo))) + len(info.AutMemo) +
			/* update threshold */ 1 +
			/* issue threshold */ 1 +
			/* planned amount */ wire.VarIntSerializeSize(info.PlannedTotalAmount) +
			/* expire height */ wire.VarIntSerializeSize(uint64(info.ExpireHeight))

	n += /* number of issuer tokens */ wire.VarIntSerializeSize(uint64(len(info.IssuerTokens)))
	for i := 0; i < len(info.IssuerTokens); i++ {
		/* actually fixed length */
		n += wire.VarIntSerializeSize(uint64(len(info.IssuerTokens[i]))) + len(info.IssuerTokens[i])
	}

	n += /* unit, variable length */ wire.VarIntSerializeSize(uint64(len(info.UnitName))) + len(info.UnitName) +
		/* minimum unit, variable length */ wire.VarIntSerializeSize(uint64(len(info.MinUnitName))) + len(info.MinUnitName) +
		/* scale, variable length */ wire.VarIntSerializeSize(info.UnitScale) +
		/* minted amount,variable length */ wire.VarIntSerializeSize(info.MintedAmount)

	n += /* number of issuer tokens */ wire.VarIntSerializeSize(uint64(len(info.RootCoinSet)))
	for point := range info.RootCoinSet {
		n += wire.VarIntSerializeSize(uint64(len(point.TxHash))) + len(point.TxHash)
		n += 1
	}
	for i := 0; i < len(info.RootCoinSet); i++ {
		/* actually fixed length */
		n += wire.VarIntSerializeSize(uint64(len(info.IssuerTokens[i]))) + len(info.IssuerTokens[i])
		n += 1
	}

	return n
}
func serializeCTAUTMetadata(info *ctaut.Metadata) ([]byte, error) {
	if info == nil {
		return nil, errors.New("nil pointer to aut.Metadata for serialize")
	}
	// Calculate the size needed to serialize AUT info.
	size := serializeCTAUTInstanceSize(info)
	// Serialize the header code followed by the compressed unspent
	// transaction output.
	buff := bytes.NewBuffer(make([]byte, 0, size))
	err := wire.WriteVarBytes(buff, 0, info.CTAutIdentifier)
	if err != nil {
		return nil, err
	}
	err = wire.WriteVarBytes(buff, 0, info.CTAutSymbol)
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

	err = wire.WriteVarInt(buff, 0, uint64(len(info.RootCoinSet)))
	if err != nil {
		return nil, err
	}
	for point := range info.RootCoinSet {
		err = wire.WriteVarBytes(buff, 0, point.TxHash[:])
		if err != nil {
			return nil, errors.New("error to write point")
		}
		err = buff.WriteByte(point.Index)
		if err != nil {
			return nil, errors.New("error to write point index")
		}
	}

	return buff.Bytes(), nil
}
func deserializeCTAUTMetadata(serialized []byte) (*ctaut.Metadata, error) {
	// Serialize the header code followed by the compressed unspent
	// transaction output.
	info := &ctaut.Metadata{}
	var err error
	buff := bytes.NewReader(serialized)
	info.CTAutIdentifier, err = wire.ReadVarBytes(buff, 0, aut.IdentifierLength, "identifier")
	if err != nil {
		return nil, err
	}
	info.CTAutSymbol, err = wire.ReadVarBytes(buff, 0, aut.MaxSymbolLength, "symbol")
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

	info.UnitName, err = wire.ReadVarBytes(buff, 0, aut.MaxUnitLength, "unit")
	if err != nil {
		return nil, err
	}
	info.MinUnitName, err = wire.ReadVarBytes(buff, 0, aut.MaxMinUnitLength, "minunit")
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

	rootCoinNum, err := wire.ReadVarInt(buff, 0)
	if err != nil {
		return nil, err
	}
	info.RootCoinSet = make(map[ctaut.OutPoint]struct{}, rootCoinNum)
	for i := uint64(0); i < issuerNum; i++ {
		txHashBytes, err := wire.ReadVarBytes(buff, 0, chainhash.HashSize, "hash")
		if err != nil {
			return nil, errors.New("error to write issuer token")
		}
		txHash, err := chainhash.NewHash(txHashBytes)
		if err != nil {
			return nil, errors.New("invalid hash for ctaut point")
		}

		index, err := buff.ReadByte()
		if err != nil {
			return nil, err
		}
		point := ctaut.OutPoint{
			TxHash: *txHash,
			Index:  index,
		}
		info.RootCoinSet[point] = struct{}{}
	}

	return info, nil
}

type SpentCTAUTType int

const ConsumeCTAUTToken SpentCTAUTType = 0
const UpdateCTAUTInfo SpentCTAUTType = 1

type SpentCTAUT interface {
	Type() SpentCTAUTType
}
type UpdatedCTAUTInfo struct {
	Before *ctaut.Metadata
	After  *ctaut.Metadata

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

		// +1 to represent nil for before
		size += 1
		serializedBefore, err := serializeCTAUTMetadata(updated.Before)
		if err != nil {
			return 0, err
		}
		if len(serializedBefore) != 0 {
			size += serializeSizeVLQ(uint64(len(serializedBefore)))
			size += len(serializedBefore)
		}

		// +1 to represent nil for after
		size += 1
		sizeAfter, err := serializeCTAUTMetadata(updated.After)
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

		// +1 to represent nil
		serializedBefore, err := serializeCTAUTMetadata(updated.Before)
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

		serializedAfter, err := serializeCTAUTMetadata(updated.After)
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
			if offset+int(scriptSize) >= len(serialized) {
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

		var err error
		if serialized[offset] == 0 {
			offset += 1
		} else {
			offset += 1
			res.Before = &ctaut.Metadata{}
			sizeOfInfo, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}

			res.Before, err = deserializeCTAUTMetadata(serialized[offset : offset+int(sizeOfInfo)])
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
			res.After = &ctaut.Metadata{}
			sizeOfInfo, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}
			res.After, err = deserializeCTAUTMetadata(serialized[offset : offset+int(sizeOfInfo)])
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
func deserializeSpendJournalEntryCTAUT(serialized []byte, txns []ctaut.Transaction) ([]SpentCTAUT, error) {
	// Calculate the total number of stxos.
	numStxos := len(txns)

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
	for txIdx := len(txns) - 1; txIdx >= 0; txIdx-- {
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
	spendJournalBucket := dbTx.Metadata().Bucket(ctautSpendJournalBucketName)
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
	spendJournalBucket := dbTx.Metadata().Bucket(ctautSpendJournalBucketName)
	serialized := spendJournalBucket.Get(block.Hash()[:])

	ctAUTTransactions := block.CTAUTTransactions()
	stxos, err := deserializeSpendJournalEntryCTAUT(serialized, ctAUTTransactions)
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
	spendJournalBucket := dbTx.Metadata().Bucket(ctautSpendJournalBucketName)
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

	return buff.Bytes(), nil
}
func deserializeCTAUTCoin(serialized []byte) (*CTAUTCoin, error) {
	if len(serialized) < 8 {
		return nil, errDeserialize("unexpected end of data after header")
	}
	// Deserialize the header code.
	headerCode := binary.LittleEndian.Uint64(serialized)
	blockHeight := int32(headerCode)

	reader := bytes.NewReader(serialized[8:])

	identifier, err := wire.ReadVarBytes(reader, 0, ctaut.IdentifierLength, "identifier")
	if err != nil {
		return nil, err
	}
	if len(identifier) != ctaut.IdentifierLength {
		return nil, errors.New("invalid identifier")
	}

	script, err := wire.ReadVarBytes(reader, 0, ctaut.MaxAUTTxoScriptLength, "script")
	if err != nil {
		return nil, err
	}

	return NewCTAUTCoin(identifier, script, blockHeight), nil
}

func dbFetchCTAUTCoin(dbTx database.Tx, outpoint ctaut.OutPoint) (*CTAUTCoin, error) {
	// Fetch the unspent transaction output information for the passed
	// transaction output.  Return now when there is no entry.
	key := ctautOutpointKey(outpoint)
	ctautCoinBucket := dbTx.Metadata().Bucket(ctautCoinBucketName)
	if ctautCoinBucket == nil {
		return nil, errors.New("bucket for ctaut coin is not exist")
	}
	serializedCoin := ctautCoinBucket.Get(*key)
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

func dbFetchCTAUTMetadata(dbTx database.Tx, key []byte) (*ctaut.Metadata, error) {
	// Fetch the unspent transaction output information for the passed
	// transaction output.  Return now when there is no entry.
	autInfoBucket := dbTx.Metadata().Bucket(ctautInstanceBucketName)
	serializedAUTInfo := autInfoBucket.Get(key)
	if serializedAUTInfo == nil {
		return nil, nil
	}

	// Deserialize the utxo entry and return it.
	metadata, err := deserializeCTAUTMetadata(serializedAUTInfo)
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

	return metadata, nil
}
func dbRemoveCTAUTInstance(dbTx database.Tx, instanceToDel map[string]struct{}, blockHeight int32, blockHash chainhash.Hash) error {
	ctautInstanceBucket := dbTx.Metadata().Bucket(ctautInstanceBucketName)
	ctautCoinBucket := dbTx.Metadata().Bucket(ctautCoinBucketName)

	for autIdentifierKey, _ := range instanceToDel {
		autIdentifier, _ := hex.DecodeString(autIdentifierKey)
		err := ctautInstanceBucket.Delete(autIdentifier)
		if err != nil {
			return err
		}

		err = ctautCoinBucket.Delete(autIdentifier)
		if err != nil {
			return err
		}
		log.Debugf(`AUT identified by %s would be deleted at height %d (block hash %s)`,
			string(autIdentifier), blockHeight, blockHash.String())
	}

	return nil
}

func dbPutCTAUTView(dbTx database.Tx, view *CTAUTViewpoint, blockHeight int32, blockHash chainhash.Hash) error {
	ctautInfoBucket := dbTx.Metadata().Bucket(ctautInstanceBucketName)
	ctautCoinBucket := dbTx.Metadata().Bucket(ctautCoinBucketName)
	for identifierKey, instance := range view.instances {
		identifier := instance.metadata.CTAutIdentifier

		// Serialize and store the utxo entry.
		serializedCTAUTInfo, err := serializeCTAUTMetadata(instance.metadata)
		if err != nil {
			return err
		}
		err = ctautInfoBucket.Put(identifier, serializedCTAUTInfo)
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
				err := ctautCoinBucket.Delete(*key)
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
			err = ctautCoinBucket.Put(*key, serializedCoin)
			// NOTE: The key is intentionally not recycled here since the
			// database interface contract prohibits modifications.  It will
			// be garbage collected normally when the database is done with
			// it.
			if err != nil {
				return err
			}
			log.Debugf(`the token (%s,%d) in AUT identified by %s is stored at height %d (block hash %s):`,
				outpoint.TxHash.String(), outpoint.Index, identifierKey, blockHeight, blockHash)
		}

	}

	return nil
}

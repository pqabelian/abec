package blockchain

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	ctautapi "github.com/abesuite/abec/ctaut/api"

	//"reflect"
	"sync"

	"github.com/abesuite/abec/abeutil"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/database"
	"github.com/abesuite/abec/wire"
)

var (
	// Confidential Transaction AUTScript - Abelian User Token (CTAUT) state
	// todo: could remove "ct"
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

// ctautOutpointKey
// review done 2025.12.11
// aut review done 2025.12.16
func ctautOutpointKey(outpoint ctautapi.HostOutPoint) *[]byte {
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

// SpentAutType
// aut review done 2025.12.17
type SpentAutType uint8

const SpentAutTypeAutInstance SpentAutType = 0
const SpentAutTypeAutTokenList SpentAutType = 1

type SpentAut interface {
	SpentType() SpentAutType
	SpendingScriptType() ctautapi.AutScriptType
	SerializeSize() (int, error)
	write(io.Writer) error
	read(io.Reader) error
	Serialize() ([]byte, error)
	Deserialize([]byte) error
}

// SpentAutInstance defines
type SpentAutInstance struct {
	spentType SpentAutType

	// SpentHeight is the height of the block containing the spending tx,
	// say the tx on which the ReRegistrationScript updates the AutInstance to After.
	SpentHeight int32

	// GeneratedHeight is the height of the block containing the generating tx,
	// say the tx on which the Before was created/updated.
	GeneratedHeight int32

	//	SpendingScriptType implies scriptType which generates this SpentJournalItem.
	spendingScriptType ctautapi.AutScriptType

	Before *ctautapi.AutMetadata
	After  *ctautapi.AutMetadata
}

// SpentAutTokenList implements the interface SpentAut.
type SpentAutTokenList struct {
	spentType SpentAutType

	// SpentHeight is the height of the block containing the spending tx,
	// say the tx on which the SpentAutTokenList is generated.
	SpentHeight int32

	//	SpendingScriptType implies scriptType which generates this SpentJournalItem.
	spendingScriptType ctautapi.AutScriptType

	SpentAutTokens []*SpentAutToken
}

// SpentAutToken does not implement the interface SpentCTAUT.
// aut review done 2025.12.17
type SpentAutToken struct {
	// GeneratedHeight is the height of the block containing the generating tx,
	// say the tx on which the AutToken was generated.
	GeneratedHeight int32

	Version uint32

	HostOutPoint ctautapi.HostOutPoint

	//	IsRootToken implies whether the spentToken is RootToken (or normalToken)
	IsRootToken bool

	// Amount is the amount of the output.
	ValueScript []byte
}

func NewSpentAutInstance(spentHeight int32, generatedHeight int32, spendingScriptType ctautapi.AutScriptType,
	before *ctautapi.AutMetadata, after *ctautapi.AutMetadata) *SpentAutInstance {
	return &SpentAutInstance{
		spentType:          SpentAutTypeAutInstance,
		SpentHeight:        spentHeight,
		GeneratedHeight:    generatedHeight,
		spendingScriptType: spendingScriptType,
		Before:             before,
		After:              after,
	}
}

func NewSpentAutTokenList(spentHeight int32, spendingScriptType ctautapi.AutScriptType,
	spentAutTokens []*SpentAutToken) *SpentAutTokenList {
	return &SpentAutTokenList{
		spentType:          SpentAutTypeAutTokenList,
		SpentHeight:        spentHeight,
		spendingScriptType: spendingScriptType,
		SpentAutTokens:     spentAutTokens,
	}
}

func NewSpentAutToken(generatedHeight int32, version uint32, hostOutPoint ctautapi.HostOutPoint, isRootToken bool, valueScript []byte) *SpentAutToken {
	return &SpentAutToken{
		GeneratedHeight: generatedHeight,
		Version:         version,
		HostOutPoint:    hostOutPoint,
		IsRootToken:     isRootToken,
		ValueScript:     valueScript,
	}
}

func (spentAutInstance *SpentAutInstance) SpentType() SpentAutType {
	return spentAutInstance.spentType
}

func (spentAutInstance *SpentAutInstance) SpendingScriptType() ctautapi.AutScriptType {
	return spentAutInstance.spendingScriptType
}

func (spentAutTokenList *SpentAutTokenList) SpentType() SpentAutType {
	return spentAutTokenList.spentType
}

func (spentAutTokenList *SpentAutTokenList) SpendingScriptType() ctautapi.AutScriptType {
	return spentAutTokenList.spendingScriptType
}

func (spentAutToken *SpentAutToken) serializeSize() int {

	size := wire.VarIntSerializeSize(uint64(spentAutToken.GeneratedHeight))                                   // GeneratedHeight int32
	size += wire.VarIntSerializeSize(uint64(spentAutToken.Version))                                           // Version uint32
	size += spentAutToken.HostOutPoint.SerializeSize()                                                        // HostOutPoint ctautapi.HostOutPoint
	size += 1                                                                                                 // IsRootToken     bool
	size += wire.VarIntSerializeSize(uint64(len(spentAutToken.ValueScript))) + len(spentAutToken.ValueScript) // ValueScript []byte

	return size
}

func (spentAutToken *SpentAutToken) write(w io.Writer) error {
	var err error

	// GeneratedHeight int32
	if err = wire.WriteVarInt(w, 0, uint64(spentAutToken.GeneratedHeight)); err != nil {
		return err
	}

	// Version uint32
	if err = wire.WriteVarInt(w, 0, uint64(spentAutToken.Version)); err != nil {
		return err
	}

	// HostOutPoint ctautapi.HostOutPoint
	if err = wire.WriteOutPointAbe(w, 0, 0, &spentAutToken.HostOutPoint); err != nil {
		return err
	}

	if spentAutToken.IsRootToken {
		if _, err = w.Write([]byte{0x01}); err != nil {
			return err
		}

		if len(spentAutToken.ValueScript) != 0 {
			return fmt.Errorf("spentAutToken.IsRootToken == TRUE, but the ValueScript is not nil/empty")
		}

	} else {
		if _, err = w.Write([]byte{0x00}); err != nil {
			return err
		}

		if len(spentAutToken.ValueScript) == 0 {
			return fmt.Errorf("spentAutToken.IsRootToken == FALSE, but the ValueScript is nil/empty")
		}
	}

	// ValueScript []byte
	if err = wire.WriteVarBytes(w, 0, spentAutToken.ValueScript); err != nil {
		return err
	}

	return nil
}

func (spentAutToken *SpentAutToken) read(r io.Reader) error {

	// GeneratedHeight int32
	heightRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	heightTemp := int64(heightRead)
	if heightTemp > math.MaxInt32 || heightTemp < 0 {
		return fmt.Errorf("read height (%d) is not in the scope [0, %d]", heightTemp, math.MaxInt32)
	}
	spentAutToken.GeneratedHeight = int32(heightTemp)

	// Version uint32
	versionRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if versionRead > math.MaxUint32 {
		return fmt.Errorf("read version (%d) is too big", versionRead)
	}
	spentAutToken.Version = uint32(versionRead)

	// HostOutPoint ctautapi.HostOutPoint
	if err = wire.ReadOutPointAbe(r, 0, 0, &spentAutToken.HostOutPoint); err != nil {
		return err
	}

	// IsRootToken     bool
	byteTemp := make([]byte, 1)
	_, err = io.ReadFull(r, byteTemp)
	if err != nil {
		return err
	}
	if byteTemp[0] == 0x01 {
		spentAutToken.IsRootToken = true
	} else if byteTemp[0] == 0x00 {
		spentAutToken.IsRootToken = false
	} else {
		return fmt.Errorf("read IsRootToken (%d) is NOT 0 or 1", byteTemp[0])
	}

	// ValueScript []byte
	if spentAutToken.ValueScript, err = wire.ReadVarBytes(r, 0, ctautapi.MaxAutValueScriptLength, "SpentAutToken.ValueScript"); err != nil {
		return err
	}

	if spentAutToken.IsRootToken {
		if len(spentAutToken.ValueScript) != 0 {
			return fmt.Errorf("spentAutToken.IsRootToken == TRUE, but the ValueScript is not nil/empty")
		}
	} else {
		if len(spentAutToken.ValueScript) == 0 {
			return fmt.Errorf("spentAutToken.IsRootToken == FALSE, but the ValueScript is nil/empty")
		}
	}

	return nil
}

func (spentAutInstance *SpentAutInstance) SerializeSize() (int, error) {
	size := 1                                                                  // spentType        SpentAutType
	size += wire.VarIntSerializeSize(uint64(spentAutInstance.SpentHeight))     // SpentHeight int32
	size += wire.VarIntSerializeSize(uint64(spentAutInstance.GeneratedHeight)) // GeneratedHeight int32
	size += 1                                                                  // SpendingScriptType api.AutScriptType

	switch spentAutInstance.spendingScriptType {
	case ctautapi.AutScriptTypeRegistration:
		if spentAutInstance.Before != nil {
			return 0, fmt.Errorf("spentAutInstance.spendingScriptType is AutScriptTypeRegistration, while spentAutInstance.Before is not nil")
		}

	case ctautapi.AutScriptTypeReRegistration:
		if spentAutInstance.Before == nil {
			return 0, fmt.Errorf("spentAutInstance.spendingScriptType is AutScriptTypeReRegistration, while spentAutInstance.Before is nil")
		}

		beforeSize, err := spentAutInstance.Before.SerializeSize() // Before *ctautapi.AutMetadata
		if err != nil {
			return 0, err
		}
		size += beforeSize

	default:
		return 0, fmt.Errorf("spentAutInstance.SpendingScriptType is %s, out of design", spentAutInstance.spendingScriptType.String())

	}

	if spentAutInstance.After == nil {
		return 0, fmt.Errorf("spentAutInstance.After is nil")
	}
	afterSize, err := spentAutInstance.After.SerializeSize() // After  *ctautapi.AutMetadata
	if err != nil {
		return 0, err
	}
	size += afterSize

	return size, nil
}

func (spentAutInstance *SpentAutInstance) write(w io.Writer) error {

	var err error

	// spentType SpentAutType
	_, err = w.Write([]byte{uint8(spentAutInstance.spentType)})
	if err != nil {
		return err
	}

	// SpentHeight int32
	if err = wire.WriteVarInt(w, 0, uint64(spentAutInstance.SpentHeight)); err != nil {
		return err
	}

	// GeneratedHeight int32
	if err = wire.WriteVarInt(w, 0, uint64(spentAutInstance.GeneratedHeight)); err != nil {
		return err
	}

	// SpendingScriptType api.AutScriptType
	_, err = w.Write([]byte{uint8(spentAutInstance.spendingScriptType)})
	if err != nil {
		return err
	}

	// Before * ctautapi.AutMetadata
	switch spentAutInstance.spendingScriptType {
	case ctautapi.AutScriptTypeRegistration:
		if spentAutInstance.Before != nil {
			return fmt.Errorf("spentAutInstance.spendingScriptType is AutScriptTypeRegistration, while spentAutInstance.Before is not nil")
		}
		if spentAutInstance.SpentHeight != spentAutInstance.GeneratedHeight {
			return fmt.Errorf("spentAutInstance.spendingScriptType is AutScriptTypeRegistration, but SpentHeight (%d) != GeneratedHeight (%d), out of design",
				spentAutInstance.SpentHeight, spentAutInstance.GeneratedHeight)
		}

	case ctautapi.AutScriptTypeReRegistration:
		if spentAutInstance.Before == nil {
			return fmt.Errorf("spentAutInstance.spendingScriptType is AutScriptTypeReRegistration, while spentAutInstance.Before is nil")
		}
		if spentAutInstance.SpentHeight <= spentAutInstance.GeneratedHeight {
			return fmt.Errorf("spentAutInstance.spendingScriptType is AutScriptTypeReRegistration, but SpentHeight (%d) <= GeneratedHeight (%d), out of design",
				spentAutInstance.SpentHeight, spentAutInstance.GeneratedHeight)
		}

		err = spentAutInstance.Before.Write(w)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("spentAutInstance.spendingScriptType is %s, out of design", spentAutInstance.spendingScriptType.String())
	}

	// After  *ctautapi.AutMetadata
	if spentAutInstance.After == nil {
		return fmt.Errorf("spentAutInstance.After is nil")
	}
	err = spentAutInstance.After.Write(w)
	if err != nil {
		return err
	}

	return nil
}

func (spentAutInstance *SpentAutInstance) read(r io.Reader) error {

	// spentType SpentAutType
	tmpByte := make([]byte, 1)
	_, err := io.ReadFull(r, tmpByte)
	if err != nil {
		return err
	}
	spentAutInstance.spentType = SpentAutType(tmpByte[0])
	if spentAutInstance.spentType != SpentAutTypeAutInstance {
		return fmt.Errorf("the read spentType (%d) is not SpentAutTypeAutInstance", spentAutInstance.spentType)
	}

	// SpentHeight int32
	spentHeightRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	spentHeightTemp := int64(spentHeightRead)
	if spentHeightTemp > math.MaxInt32 || spentHeightTemp < 0 {
		return fmt.Errorf("the read spentHeight (%d) is not in the scope [0, %d]", spentHeightTemp, math.MaxInt32)
	}
	spentAutInstance.SpentHeight = int32(spentHeightTemp)

	// GeneratedHeight int32
	generatedHeightRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	generatedHeightTemp := int64(generatedHeightRead)
	if generatedHeightTemp > math.MaxInt32 || generatedHeightTemp < 0 {
		return fmt.Errorf("the read generatedHeight (%d) is not in the scope [0, %d]", generatedHeightTemp, math.MaxInt32)
	}
	spentAutInstance.GeneratedHeight = int32(generatedHeightTemp)

	// SpendingScriptType api.AutScriptType
	tmpByte = make([]byte, 1)
	_, err = io.ReadFull(r, tmpByte)
	if err != nil {
		return err
	}
	spentAutInstance.spendingScriptType = ctautapi.AutScriptType(tmpByte[0])

	// Before * ctautapi.AutMetadata
	switch spentAutInstance.spendingScriptType {
	case ctautapi.AutScriptTypeRegistration:
		spentAutInstance.Before = nil

		if spentAutInstance.SpentHeight != spentAutInstance.GeneratedHeight {
			return fmt.Errorf("spentAutInstance.spendingScriptType is AutScriptTypeRegistration, but SpentHeight (%d) != GeneratedHeight (%d), out of design",
				spentAutInstance.SpentHeight, spentAutInstance.GeneratedHeight)
		}

	case ctautapi.AutScriptTypeReRegistration:
		spentAutInstance.Before = &ctautapi.AutMetadata{}
		err = spentAutInstance.Before.Read(r)
		if err != nil {
			return err
		}

		if spentAutInstance.Before == nil {
			return fmt.Errorf("spentAutInstance.spendingScriptType is AutScriptTypeReRegistration, while the read spentAutInstance.Before is nil")
		}
		if spentAutInstance.SpentHeight <= spentAutInstance.GeneratedHeight {
			return fmt.Errorf("spentAutInstance.spendingScriptType is AutScriptTypeReRegistration, but SpentHeight (%d) <= GeneratedHeight (%d), out of design",
				spentAutInstance.SpentHeight, spentAutInstance.GeneratedHeight)
		}

	default:
		return fmt.Errorf("spentAutInstance.spendingScriptType is %s, out of design", spentAutInstance.spendingScriptType.String())
	}

	// After  *ctautapi.AutMetadata
	spentAutInstance.After = &ctautapi.AutMetadata{}
	err = spentAutInstance.After.Read(r)
	if err != nil {
		return err
	}
	if spentAutInstance.After == nil {
		return fmt.Errorf("the read spentAutInstance.After is nil")
	}

	return nil
}

func (spentAutInstance *SpentAutInstance) Serialize() ([]byte, error) {
	size, err := spentAutInstance.SerializeSize()
	if err != nil {
		return nil, err
	}
	w := bytes.NewBuffer(make([]byte, 0, size))

	err = spentAutInstance.write(w)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (spentAutInstance *SpentAutInstance) Deserialize(serialized []byte) error {

	r := bytes.NewReader(serialized)

	err := spentAutInstance.read(r)
	if err != nil {
		return err
	}

	return nil
}

func (spentAutTokenList *SpentAutTokenList) SerializeSize() (int, error) {
	size := 1                                                               // spentType        SpentAutType
	size += wire.VarIntSerializeSize(uint64(spentAutTokenList.SpentHeight)) // SpentHeight int32
	size += 1                                                               // SpendingScriptType api.AutScriptType

	size += wire.VarIntSerializeSize(uint64(len(spentAutTokenList.SpentAutTokens))) // SpentAutTokens []SpentAutToken
	for _, spentAutToken := range spentAutTokenList.SpentAutTokens {
		size += spentAutToken.serializeSize()
	}

	return size, nil
}

func (spentAutTokenList *SpentAutTokenList) write(w io.Writer) error {

	// spentType SpentAutType
	_, err := w.Write([]byte{uint8(spentAutTokenList.spentType)})
	if err != nil {
		return err
	}

	// SpentHeight int32
	if err = wire.WriteVarInt(w, 0, uint64(spentAutTokenList.SpentHeight)); err != nil {
		return err
	}

	// SpendingScriptType api.AutScriptType
	_, err = w.Write([]byte{uint8(spentAutTokenList.spendingScriptType)})
	if err != nil {
		return err
	}

	// SpentAutTokens []SpentAutToken
	if err = wire.WriteVarInt(w, 0, uint64(len(spentAutTokenList.SpentAutTokens))); err != nil {
		return err
	}
	for i, spentAutToken := range spentAutTokenList.SpentAutTokens {
		if spentAutTokenList.SpentHeight <= spentAutToken.GeneratedHeight {
			return fmt.Errorf("th %d -th spentAutToken has GeneratedHeight = %d, while spentAutTokenList.SpentHeight is %d, whic is out of design",
				i, spentAutToken.GeneratedHeight, spentAutToken.GeneratedHeight)
		}

		if spentAutToken.IsRootToken {
			if spentAutTokenList.spendingScriptType != ctautapi.AutScriptTypeMint {
				return fmt.Errorf("th %d -th spentAutToken is RootToken, but the spentAutTokenList.spendingScriptType(%s) is not AutScriptTypeMint",
					i, spentAutTokenList.spendingScriptType.String())
			}
		} else {
			if spentAutTokenList.spendingScriptType != ctautapi.AutScriptTypeTransfer && spentAutTokenList.spendingScriptType != ctautapi.AutScriptTypeMint {
				return fmt.Errorf("th %d -th spentAutToken is NOT RootToken, "+
					"but the spentAutTokenList.SpendingScriptType(%s) is not AutScriptTypeTransfer or AutScriptTypeMint",
					i, spentAutTokenList.spendingScriptType.String())
			}
		}

		if err = spentAutToken.write(w); err != nil {
			return err
		}
	}

	return nil
}

func (spentAutTokenList *SpentAutTokenList) read(r io.Reader) error {

	// spentType SpentAutType
	tmpByte := make([]byte, 1)
	_, err := io.ReadFull(r, tmpByte)
	if err != nil {
		return err
	}
	spentAutTokenList.spentType = SpentAutType(tmpByte[0])
	if spentAutTokenList.spentType != SpentAutTypeAutTokenList {
		return fmt.Errorf("the read spentType (%d) is not SpentAutTypeAutTokenList", spentAutTokenList.spentType)
	}

	// SpentHeight int32
	spentHeightRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	spentHeightTemp := int64(spentHeightRead)
	if spentHeightTemp > math.MaxInt32 || spentHeightTemp < 0 {
		return fmt.Errorf("the read spentHeight (%d) is not in the scope [0, %d]", spentHeightTemp, math.MaxInt32)
	}
	spentAutTokenList.SpentHeight = int32(spentHeightTemp)

	// spentType SpentAutType
	tmpByte = make([]byte, 1)
	_, err = io.ReadFull(r, tmpByte)
	if err != nil {
		return err
	}
	spentAutTokenList.spendingScriptType = ctautapi.AutScriptType(tmpByte[0])

	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	spentAutTokenList.SpentAutTokens = make([]*SpentAutToken, count)
	for i := uint64(0); i < count; i++ {
		spentAutToken := &SpentAutToken{}
		if err = spentAutToken.read(r); err != nil {
			return err
		}

		if spentAutTokenList.SpentHeight <= spentAutToken.GeneratedHeight {
			return fmt.Errorf("th %d -th spentAutToken has GeneratedHeight = %d, while spentAutTokenList.SpentHeight is %d, which is out of design",
				i, spentAutToken.GeneratedHeight, spentAutToken.GeneratedHeight)
		}

		if spentAutToken.IsRootToken {
			if spentAutTokenList.spendingScriptType != ctautapi.AutScriptTypeMint {
				return fmt.Errorf("th %d -th spentAutToken is RootToken, but the spentAutTokenList.spendingScriptType(%s) is not AutScriptTypeMint",
					i, spentAutTokenList.spendingScriptType.String())
			}
		} else {
			if spentAutTokenList.spendingScriptType != ctautapi.AutScriptTypeTransfer && spentAutTokenList.spendingScriptType != ctautapi.AutScriptTypeMint {
				return fmt.Errorf("th %d -th spentAutToken is NOT RootToken, "+
					"but the spentAutTokenList.SpendingScriptType(%s) is not AutScriptTypeTransfer or AutScriptTypeMint",
					i, spentAutTokenList.spendingScriptType.String())
			}
		}

		spentAutTokenList.SpentAutTokens[i] = spentAutToken
	}

	return nil
}

func (spentAutTokenList *SpentAutTokenList) Serialize() ([]byte, error) {
	size, err := spentAutTokenList.SerializeSize()
	if err != nil {
		return nil, err
	}
	w := bytes.NewBuffer(make([]byte, 0, size))

	err = spentAutTokenList.write(w)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (spentAutTokenList *SpentAutTokenList) Deserialize(serialized []byte) error {
	r := bytes.NewReader(serialized)

	err := spentAutTokenList.read(r)
	if err != nil {
		return err
	}

	return nil
}

func deserializeSpentAut(serialized []byte) (SpentAut, error) {
	r := bytes.NewReader(serialized)
	// spentType SpentAutType
	spentTypeRead, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	spentType := SpentAutType(spentTypeRead)

	switch spentType {
	case SpentAutTypeAutInstance:
		spentAutInstance := &SpentAutInstance{}
		err = spentAutInstance.Deserialize(serialized)
		if err != nil {
			return nil, err
		}
		return spentAutInstance, nil

	case SpentAutTypeAutTokenList:
		spentAutTokenList := &SpentAutTokenList{}
		err = spentAutTokenList.Deserialize(serialized)
		if err != nil {
			return nil, err
		}
		return spentAutTokenList, nil

	default:
		return nil, fmt.Errorf("the read spentType (%d) is not SpentAutTypeAutInstance or SpentAutTypeAutTokenList", spentType)
	}
}

// aut review done 2025.12.17
type SpentCTAUTType uint8

const UpdateCTAUTInfo SpentCTAUTType = 1
const ConsumeCTAUTToken SpentCTAUTType = 0

type SpentCTAUT interface {
	Type() SpentCTAUTType
}
type UpdatedCTAUTInfo struct {
	Before *ctautapi.AutMetadata
	After  *ctautapi.AutMetadata

	// Height is the height of the the block containing the creating tx.
	Height int32

	// Denotes if the creating tx is a registration or re-registration.
	IsReRegistration bool
}

func (s *UpdatedCTAUTInfo) Type() SpentCTAUTType {
	return UpdateCTAUTInfo
}

// SpentCTAUTTokens implements the interface SpentCTAUT.
type SpentCTAUTTokens []SpentCTAUTToken

func (s *SpentCTAUTTokens) Type() SpentCTAUTType {
	return ConsumeCTAUTToken
}

// SpentCTAUTToken does not implement the interface SpentCTAUT.
// aut review done 2025.12.17
type SpentCTAUTToken struct {
	Version uint32

	HostOutPoint ctautapi.HostOutPoint

	// Amount is the amount of the output.
	ValueScript []byte

	// Height is the height of the the block containing the creating tx.
	Height int32
}

// aut review done 2025.12.17 todo
func spentCTAUTSerializeSize(stxo SpentCTAUT) (int, error) {
	size := 1 // 1 for type
	switch updated := stxo.(type) {
	case *SpentCTAUTTokens:
		tokens := *updated
		size += serializeSizeVLQ(uint64(len(tokens)))
		for _, token := range tokens {

			// height
			headerCode := uint64(token.Height)
			size += serializeSizeVLQ(headerCode)

			// version
			size += serializeSizeVLQ(uint64(token.Version))

			// hostOutPoint
			size += chainhash.HashSize
			size += 1

			// ValueScript
			size += serializeSizeVLQ(uint64(len(token.ValueScript)))
			size += len(token.ValueScript)
		}

	case *UpdatedCTAUTInfo:
		headerCode := uint64(updated.Height)
		// todo: encode headerCode by appending IsReRegistration ? if use 1 byte to flag IsReRegistration,
		// here could use varintsize? or directly use uint32?
		size += serializeSizeVLQ(headerCode)

		size += 1 // type

		// +1 to represent nil for before
		size += 1 // isReregistration
		if updated.Before != nil {
			serializedBefore, err := updated.Before.Serialize()
			if err != nil {
				return 0, err
			}
			if len(serializedBefore) != 0 {
				size += serializeSizeVLQ(uint64(len(serializedBefore)))
				size += len(serializedBefore)
			}
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

// todo: aut review done 2025.12.17; how about use serialize/deserialize or reader/writer
func putSpentCTAUT(target []byte, stxo SpentCTAUT) (int, error) {
	var err error
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

			offset += putVLQ(target[offset:], uint64(token.Version))

			copy(target[offset:], token.HostOutPoint.TxHash[:])
			offset += chainhash.HashSize
			target[offset] = token.HostOutPoint.Index
			offset += 1

			vlqSizeLen := putVLQ(target[offset:], uint64(len(token.ValueScript)))
			offset += vlqSizeLen
			copy(target[offset:], token.ValueScript)
			offset += len(token.ValueScript)
		}

	case *UpdatedCTAUTInfo:
		// todo: use a number to denote the type? how about define a type? 2025.12.17
		offset += putVLQ(target[offset:], 1)

		headerCode := uint64(updated.Height)
		offset += putVLQ(target[offset:], headerCode)

		// todo: use 0/1? 2025.12.17
		target[offset] = 0x00
		if updated.IsReRegistration {
			target[offset] = 0x01
		}
		offset += 1

		// +1 to represent nil
		// todo: double check the consistence between before and IsReRegistration
		var serializedBefore []byte
		if updated.Before != nil {
			serializedBefore, err = updated.Before.Serialize()
			if err != nil {
				return 0, err
			}
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

// todo: how about use serialize/deserialize or write/read? 2025.12.17
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

			version, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data after " +
					"header code")
			}
			res[i].Version = uint32(version)

			copy(res[i].HostOutPoint.TxHash[:], serialized[offset:offset+chainhash.HashSize])
			offset += chainhash.HashSize
			res[i].HostOutPoint.Index = serialized[offset]
			offset += 1

			scriptSize, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset+int(scriptSize) > len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data for reading script")
			}
			res[i].ValueScript = make([]byte, scriptSize)
			copy(res[i].ValueScript, serialized[offset:offset+int(scriptSize)])
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
			res.Before = &ctautapi.AutMetadata{}
			sizeOfInfo, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}

			err = res.Before.Deserialize(serialized[offset : offset+int(sizeOfInfo)])
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
			res.After = &ctautapi.AutMetadata{}
			sizeOfInfo, bytesRead := deserializeVLQ(serialized[offset:])
			offset += bytesRead
			if offset >= len(serialized) {
				return nil, offset, errDeserialize("unexpected end of data " +
					"after reserved")
			}
			err = res.After.Deserialize(serialized[offset : offset+int(sizeOfInfo)])
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

// aut review done 2025.12.16 todo
func serializeSpendJournalEntryCTAUT(stxos []SpentCTAUT) ([]byte, error) {
	if len(stxos) == 0 {
		return nil, nil
	}

	size := 0
	for i := range stxos {
		tmpSize, err := spentCTAUTSerializeSize(stxos[i])
		if err != nil {
			return nil, err
		}
		size += tmpSize

	}
	serialized := make([]byte, size) // todo: this requires that the size must be very ACCURATE.
	// todo: how about define serialize and deserialize for SpentCTAUT

	// Serialize each individual stxo directly into the slice in reverse
	// order one after the other.
	// todo: it is unnecessary to use a reverse order.
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

// todo: why scripts is used only by len()
func deserializeSpendJournalEntryCTAUT(serialized []byte, scripts []*ctautapi.ExtAutScript) ([]SpentCTAUT, error) {
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

// serializeSpendJournalEntryAut
//
// The parameter block implies that the []spendAut for a block is serialized to a []byte.
func serializeSpendJournalEntryAut(sauts []SpentAut, block *abeutil.BlockAbe) ([]byte, error) {

	numSauts := len(sauts)
	extAutScripts := block.ExtAutScripts()

	if len(extAutScripts) != numSauts {
		return nil, AssertError(fmt.Sprintf("the block (%s) carries %d ExtAutScripts, but the passed SpentAut has size %d",
			block.Hash(), len(block.ExtAutScripts()), numSauts))
	}

	if numSauts == 0 {
		return nil, nil
	}

	size := wire.VarIntSerializeSize(uint64(numSauts))
	for i, saut := range sauts {
		if saut == nil {
			return nil, AssertError(fmt.Sprintf("missing saut at position %d", i))
		}
		extAutScript := extAutScripts[i]
		if extAutScript == nil {
			return nil, AssertError(fmt.Sprintf("missing extAutScript at position %d", i))
		}

		if saut.SpendingScriptType() != extAutScripts[i].Type() {
			return nil, AssertError(fmt.Sprintf("mismatched spending script type of spentAut and ExtAutScript at position %d: %s vs %s ",
				i, saut.SpendingScriptType().String(), extAutScripts[i].Type().String()))
		}

		tmpSize, err := saut.SerializeSize()
		if err != nil {
			return nil, err
		}
		size += tmpSize
	}

	w := bytes.NewBuffer(make([]byte, 0, size))

	err := wire.WriteVarInt(w, 0, uint64(numSauts))
	if err != nil {
		return nil, err
	}

	for _, saut := range sauts {
		err = saut.write(w)
		if err != nil {
			return nil, err
		}
	}

	return w.Bytes(), nil
}

// aut review done 2025.12.18
func deserializeSpendJournalEntryAut(serializedSpentAuts []byte, block *abeutil.BlockAbe) ([]SpentAut, error) {

	extAutScripts := block.ExtAutScripts()

	// When a block has no spent txouts there is nothing to serialize.
	if len(extAutScripts) == 0 {
		return nil, nil
	}

	r := bytes.NewBuffer(serializedSpentAuts)
	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}
	if uint64(len(extAutScripts)) != count {
		return nil, AssertError(fmt.Sprintf("the block (%s) expects %d spentAut, but the read count from the serialziedSpentAuts is %d",
			block.Hash().String(), len(extAutScripts), count))
	}

	rstSpentAuts := make([]SpentAut, count)
	for i, extAutScript := range extAutScripts {
		if extAutScript == nil {
			return nil, AssertError(fmt.Sprintf("the %d-th ExtAutScript of block (%s) is nil", i, block.Hash().String()))
		}
		scriptType := extAutScript.Type()
		switch scriptType {
		case ctautapi.AutScriptTypeRegistration, ctautapi.AutScriptTypeReRegistration:
			spentAutInstance := &SpentAutInstance{}
			err = spentAutInstance.read(r)
			if err != nil {
				return nil, err
			}
			if spentAutInstance.spendingScriptType != scriptType {
				return nil, fmt.Errorf("the %d-th ExtAutScript of block (%s) expects AutScriptType %s, "+
					"but the read spentAutInstance.SpendingScriptType is %s",
					i, block.Hash().String(), scriptType.String(), spentAutInstance.spendingScriptType.String())

			}

			rstSpentAuts[i] = spentAutInstance

		case ctautapi.AutScriptTypeMint, ctautapi.AutScriptTypeTransfer, ctautapi.AutScriptTypeBurn:
			spentAutTokenList := &SpentAutTokenList{}
			err = spentAutTokenList.read(r)
			if err != nil {
				return nil, err
			}
			if spentAutTokenList.spendingScriptType != scriptType {
				return nil, fmt.Errorf("the %d-th ExtAutScript of block (%s) expects AutScriptType %s, "+
					"but the read spentAutInstance.SpendingScriptType is %s",
					i, block.Hash().String(), scriptType.String(), spentAutTokenList.spendingScriptType.String())
			}

			rstSpentAuts[i] = spentAutTokenList

		default:
			return nil, AssertError(fmt.Sprintf("the %d-th ExtAutScript of block (%s) has unknown ScriptType %s",
				i, block.Hash().String(), extAutScript.Type().String()))

		}

	}

	return rstSpentAuts, nil
}

// aut review done 2025.12.16 todo
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

// aut review done 2025.12.18
func dbPutSpendJournalEntryAut(dbTx database.Tx, block *abeutil.BlockAbe, sauts []SpentAut) error {
	spendJournalBucket := dbTx.Metadata().Bucket(ctAutSpendJournalBucketName)

	serialized, err := serializeSpendJournalEntryAut(sauts, block)
	if err != nil {
		return err
	}
	if len(serialized) == 0 {
		return nil
	}

	blockHash := block.Hash()
	return spendJournalBucket.Put(blockHash[:], serialized)
}

func dbFetchSpendJournalEntryCTAUT(dbTx database.Tx, block *abeutil.BlockAbe) ([]SpentCTAUT, error) {
	// Exclude the coinbase transaction since it can't spend anything.
	spendJournalBucket := dbTx.Metadata().Bucket(ctAutSpendJournalBucketName)
	serialized := spendJournalBucket.Get(block.Hash()[:])

	scripts := block.ExtAutScripts()
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

// aut review done 2025.12.18
func dbFetchSpendJournalEntryAut(dbTx database.Tx, block *abeutil.BlockAbe) ([]SpentAut, error) {
	// Exclude the coinbase transaction since it can't spend anything.
	spendJournalBucket := dbTx.Metadata().Bucket(ctAutSpendJournalBucketName)
	serialized := spendJournalBucket.Get(block.Hash()[:])

	sauts, err := deserializeSpendJournalEntryAut(serialized, block)
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

	return sauts, nil
}

func dbRemoveSpendJournalEntryCTAUT(dbTx database.Tx, blockHash *chainhash.Hash) error {
	spendJournalBucket := dbTx.Metadata().Bucket(ctAutSpendJournalBucketName)
	return spendJournalBucket.Delete(blockHash[:])
}

// deserializeCTAUTCoin
// review done 2025.12.11
// aut review done
// todo: 2025.12.16 confirm that this function should not be call when coin.IsSpent() is TRUE. confirm done
// todo: 2025.12.17 add hostOutPoint field in CTAUTCoin.
func serializeUnspentAutCoin(coin *CTAUTCoin) ([]byte, error) {
	// Spent outputs have no serialization.
	if coin.IsSpent() {
		return nil, nil
	}

	size := 4 + // version
		4 + // height
		len(coin.identifier) +
		wire.VarIntSerializeSize(uint64(len(coin.valueScript))) + len(coin.valueScript)

	w := bytes.NewBuffer(make([]byte, 0, size))

	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, coin.version)
	_, err := w.Write(tmp)
	if err != nil {
		return nil, err
	}

	tmp = make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, uint32(coin.blockHeight))
	_, err = w.Write(tmp)
	if err != nil {
		return nil, err
	}

	_, err = w.Write(coin.identifier[:])
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(w, 0, coin.valueScript)
	if err != nil {
		return nil, err
	}
	serializedUnspentAutCoin := w.Bytes()

	//deserializedCoin, err := deserializeCTAUTCoin(serializedCTAUTCoin)
	//if err != nil {
	//	return nil, err
	//}
	//if !reflect.DeepEqual(coin, deserializedCoin) {
	//	return nil, fmt.Errorf("unmatched CTAUTCoin serialized/deserialized")
	//}
	return serializedUnspentAutCoin, nil
}

// deserializeCTAUTCoin
// review done 2025.12.11
// aut review done 2025.12.16
func deserializeUnspentAutCoin(serialized []byte) (*CTAUTCoin, error) {

	r := bytes.NewReader(serialized)

	tmp := make([]byte, 4)
	_, err := io.ReadFull(r, tmp)
	if err != nil {
		return nil, err
	}
	version := binary.LittleEndian.Uint32(tmp)

	tmp = make([]byte, 4)
	_, err = io.ReadFull(r, tmp)
	if err != nil {
		return nil, err
	}
	heightRead := binary.LittleEndian.Uint32(tmp)
	if int64(heightRead) > math.MaxInt32 {
		return nil, AssertError(fmt.Sprintf("read height (%d) is invalid", heightRead))
	}
	blockHeight := int32(heightRead)

	var identifier ctautapi.AutId
	_, err = io.ReadFull(r, identifier[:])
	if err != nil {
		return nil, err
	}

	valueScript, err := wire.ReadVarBytes(r, 0, ctautapi.MaxAutValueScriptLength, "valueScript")
	if err != nil {
		return nil, err
	}

	// todo: confirm that each time a coin is read from database, it will be regarded as "modified", confirmed; research in the future
	// and as a result, if it is not spent, it will be "written" back to database, even if it is actually not modified.
	return NewCTAUTCoin(version, identifier, valueScript, blockHeight), nil
}

// dbFetchCTAUTCoin
// review done 2025.12.12
func dbFetchCTAUTCoin(dbTx database.Tx, outpoint ctautapi.HostOutPoint) (*CTAUTCoin, error) {
	// Fetch the unspent transaction output information for the passed
	// transaction output.  Return now when there is no entry.
	key := ctautOutpointKey(outpoint)
	ctAutTokenBucket := dbTx.Metadata().Bucket(ctAutTokenBucketName)
	if ctAutTokenBucket == nil {
		return nil, fmt.Errorf("bucket for aut coin does not exist")
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
	coin, err := deserializeUnspentAutCoin(serializedCoin)
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

// dbFetchCTAUTMetadata
// review done 2025.12.11
func dbFetchCTAUTMetadata(dbTx database.Tx, key ctautapi.AutId) (*ctautapi.AutMetadata, error) {
	// Fetch the unspent transaction output information for the passed
	// transaction output.  Return now when there is no entry.
	// todo: 2025.12.12 why not use the database-key mechanism?
	autInfoBucket := dbTx.Metadata().Bucket(ctAutInstanceBucketName)
	if autInfoBucket == nil {
		return nil, fmt.Errorf("bucket for aut instance does not exist")
	}
	serializedAUTInfo := autInfoBucket.Get(key[:])
	if serializedAUTInfo == nil {
		return nil, nil
	}

	// Deserialize the utxo entry and return it.
	var metadata ctautapi.AutMetadata
	err := metadata.Deserialize(serializedAUTInfo)
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
		autIdentifier, err := chainhash.NewHashFromStr(autIdentifierKey)
		if err != nil {
			return fmt.Errorf("invalid identifier key")
		}

		err = ctautInstanceBucket.Delete(autIdentifier[:])
		if err != nil {
			return err
		}

		err = ctAutTokenBucket.Delete(autIdentifier[:])
		if err != nil {
			return err
		}
		log.Debugf(`AUT identified by %s would be deleted at height %d (block hash %s)`,
			autIdentifierKey, blockHeight, blockHash.String())
	}

	return nil
}

// aut review done 2025.12.16
func dbPutCTAUTView(dbTx database.Tx, view *CTAUTViewpoint, blockHeight int32, blockHash chainhash.Hash) error {
	ctAutInfoBucket := dbTx.Metadata().Bucket(ctAutInstanceBucketName)
	ctAutTokenBucket := dbTx.Metadata().Bucket(ctAutTokenBucketName)
	for identifierKey, instance := range view.instances {
		if instance == nil {
			log.Warnf("dbPutCTAUTView: the AutInstance for identifier %s is nil", identifierKey)
			continue
		}
		if instance.metadata == nil {
			log.Warnf("dbPutCTAUTView: the AutInstance.metadata for identifier %s is nil", identifierKey)
			continue
		}

		identifier := instance.metadata.AutIdentifier

		// Serialize and store the utxo entry.
		serializedCTAUTInfo, err := instance.metadata.Serialize()
		if err != nil {
			return err
		}
		err = ctAutInfoBucket.Put(identifier[:], serializedCTAUTInfo)
		if err != nil {
			return err
		}

		log.Debugf("the metadata for CTAUT instance identified by %s is stored at height %d (block hash %s) with following configuration:",
			identifierKey, blockHeight, blockHash)
		metadata := instance.metadata
		log.Debugf("\t Version: %d", metadata.Version)
		log.Debugf("\t Memo: %v", metadata.AutMemo)
		log.Debugf("\t PlannedTotalSupply: %v", metadata.PlannedTotalSupply)
		log.Debugf("\t ReregistrationExpireHeight: %v", metadata.ReregistrationExpireHeight)
		log.Debugf("\t ReregistrationThreshold: %v", metadata.ReregistrationThreshold)
		log.Debugf("\t MintThreshold: %v", metadata.MintThreshold)
		log.Debugf("\t UnitScale: %v", metadata.UnitScale)
		log.Debugf("\t PrivacyType: %v", metadata.PrivacyType)
		log.Debugf("\t Current Issuers: len = %d", len(metadata.Issuers))
		for i := 0; i < len(metadata.Issuers); i++ {
			log.Debugf("\t\t [%d] %s", i, metadata.Issuers[i].String())
		}
		log.Debugf("\t Active RootCoin: len = %d", len(metadata.ActiveRootTokenSet))
		for point := range metadata.ActiveRootTokenSet {
			log.Debugf("%s", point)
		}
		log.Debugf("\t Updated Version: len = %d", len(metadata.UpdateScriptVersions))
		for i := 0; i < len(metadata.UpdateScriptVersions); i++ {
			log.Debugf("\t\t %d", metadata.UpdateScriptVersions[i])
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
			serializedCoin, err := serializeUnspentAutCoin(coin)
			if err != nil {
				return err
			}
			// todo: check whether serializedCoin is nil? 2025.12.17 refactor in the future
			key := ctautOutpointKey(outpoint)
			err = ctAutTokenBucket.Put(*key, serializedCoin)
			// todo: why above spent recycle the key, research in the future.
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

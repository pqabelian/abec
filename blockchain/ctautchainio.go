package blockchain

import (
	"bytes"
	"encoding/binary"
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

	// identifier -> serialized aut metadata
	ctAutInstanceBucketName = []byte("ctautinstance")
	// identifier -> [ outpoint -> serialized aut coin ]
	ctAutTokenBucketName = []byte("ctauttoken")
	// blockHash -> serialized spent aut
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
	SpentAutIdentifier() ctautapi.AutId
	SpendingScriptType() ctautapi.AutScriptType
	SerializeSize() (int, error)
	write(io.Writer) error
	read(io.Reader) error
	Serialize() ([]byte, error)
	Deserialize([]byte) error
	SanityCheck() error
	ScriptMatchCheck(*ctautapi.ExtAutScript) error
}

// SpentAutInstance defines
type SpentAutInstance struct {
	spentType SpentAutType

	spentAutIdentifier ctautapi.AutId

	// SpentHeight is the height of the block containing the spending tx,
	// say the tx on which the ReRegistrationScript updates the AutInstance to After.
	SpentHeight int32

	// GeneratedHeight is the height of the block containing the generating tx,
	// say the tx on which the Before was created/updated.
	GeneratedHeight int32

	//	SpendingScriptType implies scriptType which generates this SpentJournalItem.
	spendingScriptType ctautapi.AutScriptType

	After  *ctautapi.AutMetadata
	Before *ctautapi.AutMetadata
}

// SpentAutTokenList implements the interface SpentAut.
type SpentAutTokenList struct {
	spentType SpentAutType

	spentAutIdentifier ctautapi.AutId

	// SpentHeight is the height of the block containing the spending tx,
	// say the tx on which the SpentAutTokenList is generated.
	SpentHeight int32

	//	SpendingScriptType implies scriptType which generates this SpentJournalItem.
	spendingScriptType ctautapi.AutScriptType

	SpentAutTokens []*SpentAutToken
}

// SpentAutToken is used to store the spentToken Info.
// aut review done 2025.12.17
type SpentAutToken struct {
	// GeneratedHeight is the height of the block containing the generating tx,
	// say the tx on which the AutToken was generated.
	GeneratedHeight int32

	autIdentifier ctautapi.AutId

	Version uint32

	HostOutPoint ctautapi.HostOutPoint

	// Amount is the amount of the output.
	ValueScript []byte
}

func NewSpentAutInstance(spentAutIdentifier ctautapi.AutId, spentHeight int32, generatedHeight int32, spendingScriptType ctautapi.AutScriptType,
	after *ctautapi.AutMetadata, before *ctautapi.AutMetadata) *SpentAutInstance {
	return &SpentAutInstance{
		spentType:          SpentAutTypeAutInstance,
		spentAutIdentifier: spentAutIdentifier,
		SpentHeight:        spentHeight,
		GeneratedHeight:    generatedHeight,
		spendingScriptType: spendingScriptType,
		After:              after,
		Before:             before,
	}
}

func NewSpentAutTokenList(spentAutIdentifier ctautapi.AutId, spentHeight int32, spendingScriptType ctautapi.AutScriptType,
	spentAutTokens []*SpentAutToken) *SpentAutTokenList {
	return &SpentAutTokenList{
		spentType:          SpentAutTypeAutTokenList,
		spentAutIdentifier: spentAutIdentifier,
		SpentHeight:        spentHeight,
		spendingScriptType: spendingScriptType,
		SpentAutTokens:     spentAutTokens,
	}
}

func NewSpentAutToken(generatedHeight int32, autIdentifier ctautapi.AutId, version uint32,
	hostOutPoint ctautapi.HostOutPoint, valueScript []byte) *SpentAutToken {
	return &SpentAutToken{
		GeneratedHeight: generatedHeight,
		autIdentifier:   autIdentifier,
		Version:         version,
		HostOutPoint:    hostOutPoint,
		ValueScript:     valueScript,
	}
}

func (spentAutInstance *SpentAutInstance) SpentType() SpentAutType {
	return spentAutInstance.spentType
}

func (spentAutInstance *SpentAutInstance) SpentAutIdentifier() ctautapi.AutId {
	return spentAutInstance.spentAutIdentifier
}

func (spentAutInstance *SpentAutInstance) SpendingScriptType() ctautapi.AutScriptType {
	return spentAutInstance.spendingScriptType
}

func (spentAutTokenList *SpentAutTokenList) SpentType() SpentAutType {
	return spentAutTokenList.spentType
}

func (spentAutTokenList *SpentAutTokenList) SpentAutIdentifier() ctautapi.AutId {
	return spentAutTokenList.spentAutIdentifier
}

func (spentAutTokenList *SpentAutTokenList) SpendingScriptType() ctautapi.AutScriptType {
	return spentAutTokenList.spendingScriptType
}

func (spentAutToken *SpentAutToken) serializeSize() (int, error) {

	err := spentAutToken.sanityCheck()
	if err != nil {
		return 0, err
	}

	size := wire.VarIntSerializeSize(uint64(spentAutToken.GeneratedHeight))                                   // GeneratedHeight int32
	size += chainhash.HashSize                                                                                // autIdentifier   api.AutId
	size += wire.VarIntSerializeSize(uint64(spentAutToken.Version))                                           // Version uint32
	size += spentAutToken.HostOutPoint.SerializeSize()                                                        // HostOutPoint ctautapi.HostOutPoint
	size += wire.VarIntSerializeSize(uint64(len(spentAutToken.ValueScript))) + len(spentAutToken.ValueScript) // ValueScript []byte

	return size, nil
}

func (spentAutToken *SpentAutToken) write(w io.Writer) error {
	err := spentAutToken.sanityCheck()
	if err != nil {
		return err
	}

	// GeneratedHeight int32
	if err = wire.WriteVarInt(w, 0, uint64(spentAutToken.GeneratedHeight)); err != nil {
		return err
	}

	// autIdentifier   api.AutId
	if _, err = w.Write(spentAutToken.autIdentifier[:]); err != nil {
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

	// ValueScript []byte
	if err = wire.WriteVarBytes(w, 0, spentAutToken.ValueScript); err != nil {
		return err
	}

	return nil
}

func (spentAutToken *SpentAutToken) read(r io.Reader) error {

	if spentAutToken == nil {
		return fmt.Errorf("receiver spentAutToken is nil")
	}

	// GeneratedHeight int32
	heightRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	heightTemp := int64(heightRead)
	if heightTemp > math.MaxInt32 || heightTemp < 0 {
		return fmt.Errorf("read GeneratedHeight (%d) is not in the scope [0, %d]", heightTemp, math.MaxInt32)
	}
	spentAutToken.GeneratedHeight = int32(heightTemp)

	// autIdentifier   api.AutId
	_, err = io.ReadFull(r, spentAutToken.autIdentifier[:])
	if err != nil {
		return err
	}

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

	// ValueScript []byte
	if spentAutToken.ValueScript, err = wire.ReadVarBytes(r, 0, ctautapi.MaxAutValueScriptLength, "SpentAutToken.ValueScript"); err != nil {
		return err
	}

	err = spentAutToken.sanityCheck()
	if err != nil {
		return err
	}

	return nil
}

func (spentAutToken *SpentAutToken) sanityCheck() error {

	if spentAutToken == nil {
		return fmt.Errorf("receiver spentAutToken is nil")
	}

	// GeneratedHeight int32
	if spentAutToken.GeneratedHeight < 0 {
		return fmt.Errorf("spentAutToken.GeneratedHeight (%d) is < 0", spentAutToken.GeneratedHeight)
	}

	// autIdentifier   api.AutId

	// Version uint32
	// version check is deferred to the time when it is used.

	// HostOutPoint ctautapi.HostOutPoint

	// ValueScript []byte
	if len(spentAutToken.ValueScript) == 0 {
		return fmt.Errorf("spentAutToken.ValueScript is nil/empty")
	}

	return nil
}

func (spentAutInstance *SpentAutInstance) SerializeSize() (int, error) {
	err := spentAutInstance.SanityCheck()
	if err != nil {
		return 0, fmt.Errorf("spentAutInstance.SanityCheck fail: %v", err)
	}

	size := 1                                                                  // spentType        SpentAutType
	size += chainhash.HashSize                                                 // spentAutIdentifier api.AutId
	size += wire.VarIntSerializeSize(uint64(spentAutInstance.SpentHeight))     // SpentHeight int32
	size += wire.VarIntSerializeSize(uint64(spentAutInstance.GeneratedHeight)) // GeneratedHeight int32
	size += 1                                                                  // SpendingScriptType api.AutScriptType

	// Not the SanityCheck() has been called at the start.
	// After  *ctautapi.AutMetadata
	afterSize, err := spentAutInstance.After.SerializeSize()
	if err != nil {
		return 0, err
	}
	size += afterSize

	switch spentAutInstance.spendingScriptType {
	case ctautapi.AutScriptTypeRegistration:
		// Not the SanityCheck() has been called at the start.
		// Before *ctautapi.AutMetadata

	case ctautapi.AutScriptTypeReRegistration, ctautapi.AutScriptTypeMint:
		// Not the SanityCheck() has been called at the start.
		// Before *ctautapi.AutMetadata
		beforeSize, err := spentAutInstance.Before.SerializeSize()
		if err != nil {
			return 0, err
		}
		size += beforeSize

	default:
		return 0, fmt.Errorf("spentAutInstance.SpendingScriptType is %s, out of design",
			spentAutInstance.spendingScriptType.String())

	}

	return size, nil
}

func (spentAutInstance *SpentAutInstance) write(w io.Writer) error {

	err := spentAutInstance.SanityCheck()
	if err != nil {
		return err
	}

	// spentType SpentAutType
	_, err = w.Write([]byte{uint8(spentAutInstance.spentType)})
	if err != nil {
		return err
	}

	// spentAutIdentifier api.AutId
	_, err = w.Write(spentAutInstance.spentAutIdentifier[:])
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

	// After  *ctautapi.AutMetadata
	// Not the SanityCheck() has been called at the start.
	err = spentAutInstance.After.Write(w)
	if err != nil {
		return err
	}

	// Before * ctautapi.AutMetadata
	switch spentAutInstance.spendingScriptType {
	case ctautapi.AutScriptTypeRegistration:
		// Not the SanityCheck() has been called at the start.
		// Before  *ctautapi.AutMetadata

	case ctautapi.AutScriptTypeReRegistration, ctautapi.AutScriptTypeMint:
		// Not the SanityCheck() has been called at the start.
		// Before  *ctautapi.AutMetadata
		err = spentAutInstance.Before.Write(w)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("spentAutInstance.spendingScriptType is %s, out of design",
			spentAutInstance.spendingScriptType.String())
	}

	return nil
}

func (spentAutInstance *SpentAutInstance) read(r io.Reader) error {
	if spentAutInstance == nil {
		return fmt.Errorf("receiver spentAutInstance is nil")
	}

	// spentType SpentAutType
	tmpByte := make([]byte, 1)
	_, err := io.ReadFull(r, tmpByte)
	if err != nil {
		return err
	}
	spentAutInstance.spentType = SpentAutType(tmpByte[0])

	// spentAutIdentifier api.AutId
	_, err = io.ReadFull(r, spentAutInstance.spentAutIdentifier[:])
	if err != nil {
		return err
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

	// After  *ctautapi.AutMetadata
	spentAutInstance.After = &ctautapi.AutMetadata{}
	err = spentAutInstance.After.Read(r)
	if err != nil {
		return err
	}

	// Before * ctautapi.AutMetadata
	switch spentAutInstance.spendingScriptType {
	case ctautapi.AutScriptTypeRegistration:
		spentAutInstance.Before = nil

	case ctautapi.AutScriptTypeReRegistration, ctautapi.AutScriptTypeMint:
		spentAutInstance.Before = &ctautapi.AutMetadata{}
		err = spentAutInstance.Before.Read(r)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("spentAutInstance.spendingScriptType is %s, out of design",
			spentAutInstance.spendingScriptType.String())
	}

	err = spentAutInstance.SanityCheck()
	if err != nil {
		return err
	}

	return nil
}

func (spentAutInstance *SpentAutInstance) SanityCheck() error {
	if spentAutInstance == nil {
		return fmt.Errorf("receiver spentAutInstance is nil")
	}

	// spentType SpentAutType
	if spentAutInstance.spentType != SpentAutTypeAutInstance {
		return fmt.Errorf("the spentType (%d) is not SpentAutTypeAutInstance", spentAutInstance.spentType)
	}

	// spentAutIdentifier api.AutId

	// SpentHeight int32
	if spentAutInstance.SpentHeight < 0 {
		return fmt.Errorf("the SpentHeight (%d) is < 0", spentAutInstance.SpentHeight)
	}

	// GeneratedHeight int32
	if spentAutInstance.GeneratedHeight < 0 {
		return fmt.Errorf("the GeneratedHeight (%d) is < 0", spentAutInstance.GeneratedHeight)
	}

	// After  *ctautapi.AutMetadata
	if spentAutInstance.After == nil {
		return fmt.Errorf("spentAutInstance.After is nil")
	}
	err := spentAutInstance.After.SanityCheck()
	if err != nil {
		return err
	}

	// spentAutInstance and spentAutInstance.After
	if !bytes.Equal(spentAutInstance.spentAutIdentifier[:], spentAutInstance.After.AutIdentifier[:]) {
		return fmt.Errorf("spentAutInstance.spentAutIdentifier is %s, but spentAutInstance.Before.AutIdentifier is %s",
			spentAutInstance.spentAutIdentifier.String(), spentAutInstance.After.AutIdentifier.String())
	}

	// SpendingScriptType api.AutScriptType
	// Before * ctautapi.AutMetadata
	switch spentAutInstance.spendingScriptType {
	case ctautapi.AutScriptTypeRegistration:
		if spentAutInstance.Before != nil {
			return fmt.Errorf("AutScriptTypeRegistration: AutInstance %s, spentAutInstance.Before is NOT nil",
				spentAutInstance.spentAutIdentifier.String())
		}

		// Before==Nil spentAutInstance.GeneratedHeight == spentAutInstance.SpentHeight == spentAutInstance.After.UpdatedHeight
		if spentAutInstance.GeneratedHeight != spentAutInstance.After.UpdatedHeight {
			return fmt.Errorf("AutScriptTypeRegistration: AutInstance %s, spentAutInstance.GeneratedHeight (%d) != spentAutInstance.SpentHeight (%d)",
				spentAutInstance.spentAutIdentifier.String(), spentAutInstance.GeneratedHeight, spentAutInstance.SpentHeight)
		}
		if spentAutInstance.SpentHeight != spentAutInstance.After.UpdatedHeight {
			return fmt.Errorf("AutScriptTypeRegistration: AutInstance %s, spentAutInstance.SpentHeight (%d) != spentAutInstance.After.UpdatedHeight (%d), out of design",
				spentAutInstance.spentAutIdentifier.String(), spentAutInstance.SpentHeight, spentAutInstance.After.UpdatedHeight)
		}

		// After needs to satisfy

		// Version
		if spentAutInstance.After.Version != ctautapi.AutMetadataVersionInitValue {
			return fmt.Errorf("AutScriptTypeRegistration: AutInstance %s, spentAutInstance.After.Version (%d) != ctautapi.AutMetadataVersionInitValue (%d)",
				spentAutInstance.spentAutIdentifier.String(), spentAutInstance.After.Version, ctautapi.AutMetadataVersionInitValue)
		}

		// AutIdentifier
		// checked outside above

		// UpdatedHeight
		// checked outside above

		// MintedAmount
		if spentAutInstance.After.MintedAmount != 0 {
			return fmt.Errorf("AutScriptTypeRegistration: AutInstance %s, spentAutInstance.After.MintedAmount (%d) is not 0",
				spentAutInstance.spentAutIdentifier.String(), spentAutInstance.After.MintedAmount)
		}

		// BurnedAmount
		if spentAutInstance.After.BurnedAmount != 0 {
			return fmt.Errorf("AutScriptTypeRegistration: AutInstance %s, spentAutInstance.After.BurnedAmount (%d) is not 0",
				spentAutInstance.spentAutIdentifier.String(), spentAutInstance.After.BurnedAmount)
		}

		// ActiveRootTokenSet
		if len(spentAutInstance.After.ActiveRootTokenSet) == 0 {
			return fmt.Errorf("AutScriptTypeRegistration: AutInstance %s, spentAutInstance.After.ActiveRootTokenSet is empty",
				spentAutInstance.spentAutIdentifier.String())
		}

		// UpdateScriptVersions
		// checked in SanityCheck

		// UpdateHistoryHeights
		// checked in SanityCheck

	case ctautapi.AutScriptTypeReRegistration:
		if spentAutInstance.Before == nil {
			return fmt.Errorf("AutScriptTypeReRegistration: AutInsatnce %s, spentAutInstance.Before is nil",
				spentAutInstance.spentAutIdentifier.String())
		}

		err = spentAutInstance.Before.SanityCheck()
		if err != nil {
			return err
		}

		// spentAutInstance and spentAutInstance.Before
		if !bytes.Equal(spentAutInstance.spentAutIdentifier[:], spentAutInstance.Before.AutIdentifier[:]) {
			return fmt.Errorf("AutScriptTypeReRegistration: spentAutInstance.spentAutIdentifier is %s, but spentAutInstance.Before.AutIdentifier is %s",
				spentAutInstance.spentAutIdentifier.String(), spentAutInstance.Before.AutIdentifier.String())
		}

		// need: spentAutInstance.GeneratedHeight == spentAutInstance.Before.UpdatedHeight
		if spentAutInstance.GeneratedHeight != spentAutInstance.Before.UpdatedHeight {
			return fmt.Errorf("AutScriptTypeReRegistration: AutInsatnce %s, spentAutInstance.GeneratedHeight (%d) != spentAutInstance.Before.UpdatedHeight (%d)",
				spentAutInstance.spendingScriptType.String(), spentAutInstance.GeneratedHeight, spentAutInstance.Before.UpdatedHeight)
		}
		// need: spentAutInstance.SpentHeight == spentAutInstance.After.UpdatedHeight
		if spentAutInstance.SpentHeight != spentAutInstance.After.UpdatedHeight {
			return fmt.Errorf("AutScriptTypeReRegistration: AutInsatnce %s, spentAutInstance.SpentHeight (%d) != spentAutInstance.After.UpdatedHeight (%d)",
				spentAutInstance.SpentHeight, spentAutInstance.After.UpdatedHeight)
		}

		// spentAutInstance.After and spentAutInstance.Before
		// Version
		if spentAutInstance.After.Version != spentAutInstance.Before.Version+1 {
			return fmt.Errorf("AutScriptTypeReRegistration: AutInsatnce %s, spentAutInstance.After.Version (%d) != spentAutInstance.Before.Version (%d) +1",
				spentAutInstance.spendingScriptType.String(), spentAutInstance.After.Version, spentAutInstance.Before.Version)
		}

		// AutIdentifier
		// checked above: "=="

		// UpdatedHeight
		if spentAutInstance.After.UpdatedHeight <= spentAutInstance.Before.UpdatedHeight {
			return fmt.Errorf("AutScriptTypeReRegistration: AutInsatnce %s, spentAutInstance.After.UpdatedHeight (%d) <= spentAutInstance.Before.UpdatedHeight (%d)",
				spentAutInstance.spendingScriptType.String(), spentAutInstance.After.UpdatedHeight, spentAutInstance.Before.UpdatedHeight)
		}
		// Note now it holds that
		// spentAutInstance.Before.UpdatedHeight = spentAutInstance.GeneratedHeight < spentAutInstance.SpentHeight = spentAutInstance.After.UpdatedHeight

		// PlannedTotalSupply
		// MintedAmount
		if spentAutInstance.After.PlannedTotalSupply < spentAutInstance.Before.MintedAmount {
			return fmt.Errorf("AutScriptTypeReRegistration: AutInsatnce %s, spentAutInstance.After.PlannedTotalSupply (%d) < spentAutInstance.Before.MintedAmount (%d)",
				spentAutInstance.spendingScriptType.String(), spentAutInstance.After.PlannedTotalSupply, spentAutInstance.Before.MintedAmount)
		}

		// ActiveRootTokenSet
		if len(spentAutInstance.After.ActiveRootTokenSet) == 0 {
			// should produce new, this is consistent on the requirements on the AutScript.
			// if since the issuers want to freeze the AutInstance Reregistration/Mint, they could use out the ActiveRootTokenSet by some way.
			return fmt.Errorf("AutScriptTypeReRegistration: AutInsatnce %s, spentAutInstance.After.ActiveRootTokenSet is empty",
				spentAutInstance.spendingScriptType.String())
		}

		if len(spentAutInstance.Before.ActiveRootTokenSet) == 0 {
			// should have some to be consumed to generate the after
			return fmt.Errorf("AutScriptTypeReRegistration: AutInsatnce %s, spentAutInstance.Before.ActiveRootTokenSet is empty",
				spentAutInstance.spendingScriptType.String())
		}

		// spentAutInstance.After.ActiveRootTokenSet and spentAutInstance.Before.ActiveRootTokenSet have no common
		for _, rootTokenOp := range spentAutInstance.After.ActiveRootTokenSet {
			if _, ok := spentAutInstance.Before.ActiveRootTokenSet[rootTokenOp.String()]; ok {
				return fmt.Errorf("AutScriptTypeReRegistration: AutInsatnce %s, spentAutInstance.Before.ActiveRootTokenSet and spentAutInstance.Before.ActiveRootTokenSet has commond %s",
					spentAutInstance.spendingScriptType.String(), rootTokenOp.String())
			}
		}
		for _, rootTokenOp := range spentAutInstance.Before.ActiveRootTokenSet {
			if _, ok := spentAutInstance.After.ActiveRootTokenSet[rootTokenOp.String()]; ok {
				return fmt.Errorf("AutScriptTypeReRegistration: AutInsatnce %s, spentAutInstance.Before.ActiveRootTokenSet and spentAutInstance.After.ActiveRootTokenSet has commond %s",
					spentAutInstance.spendingScriptType.String(), rootTokenOp.String())
			}
		}

		// UpdateScriptVersions
		// UpdateHistoryHeights
		// Note that spentAutInstance.After.Version = spentAutInstance.Before.Version + 1
		for i := uint32(0); i < spentAutInstance.Before.Version; i++ {
			if spentAutInstance.After.UpdateScriptVersions[i] != spentAutInstance.Before.UpdateScriptVersions[i] {
				return fmt.Errorf("AutScriptTypeReRegistration: AutInsatnce %s, spentAutInstance.After.UpdateScriptVersions[%d] (%d) != spentAutInstance.Before.UpdateScriptVersions[%d] (%d)",
					spentAutInstance.spendingScriptType.String(), i, spentAutInstance.After.UpdateScriptVersions[i], i, spentAutInstance.Before.UpdateScriptVersions[i])
			}
			if spentAutInstance.After.UpdateHistoryHeights[i] != spentAutInstance.Before.UpdateHistoryHeights[i] {
				return fmt.Errorf("AutScriptTypeReRegistration: AutInsatnce %s, spentAutInstance.After.UpdateHistoryHeights[%d] (%d) != spentAutInstance.Before.UpdateHistoryHeights[%d] (%d)",
					spentAutInstance.spendingScriptType.String(), i, spentAutInstance.After.UpdateHistoryHeights[i], i, spentAutInstance.Before.UpdateHistoryHeights[i])
			}
		}

	case ctautapi.AutScriptTypeMint:
		if spentAutInstance.Before == nil {
			return fmt.Errorf("AutScriptTypeMint: AutInsatnce %s, spentAutInstance.Before is nil",
				spentAutInstance.spentAutIdentifier.String())
		}

		err = spentAutInstance.Before.SanityCheck()
		if err != nil {
			return err
		}

		// spentAutInstance and spentAutInstance.Before
		if !bytes.Equal(spentAutInstance.spentAutIdentifier[:], spentAutInstance.Before.AutIdentifier[:]) {
			return fmt.Errorf("AutScriptTypeMint: spentAutInstance.spentAutIdentifier is %s, but spentAutInstance.Before.AutIdentifier is %s",
				spentAutInstance.spentAutIdentifier.String(), spentAutInstance.Before.AutIdentifier.String())
		}

		// need: spentAutInstance.GeneratedHeight == spentAutInstance.Before.UpdatedHeight
		if spentAutInstance.GeneratedHeight != spentAutInstance.Before.UpdatedHeight {
			return fmt.Errorf("AutScriptTypeMint: AutInsatnce %s, spentAutInstance.GeneratedHeight (%d) != spentAutInstance.Before.UpdatedHeight (%d)",
				spentAutInstance.spendingScriptType.String(), spentAutInstance.GeneratedHeight, spentAutInstance.Before.UpdatedHeight)
		}
		// need: spentAutInstance.SpentHeight > spentAutInstance.Before.UpdatedHeight
		if spentAutInstance.SpentHeight <= spentAutInstance.Before.UpdatedHeight {
			return fmt.Errorf("AutScriptTypeMint: AutInsatnce %s, spentAutInstance.GeneratedHeight (%d) <= spentAutInstance.Before.UpdatedHeight (%d)",
				spentAutInstance.spendingScriptType.String(), spentAutInstance.GeneratedHeight, spentAutInstance.Before.UpdatedHeight)
		}

		// spentAutInstance.After and spentAutInstance.Before should be same, except the MintedAmount and ActiveRootTokenSet
		if !spentAutInstance.After.IsEqualExMint(spentAutInstance.Before) {
			return fmt.Errorf("AutScriptTypeMint: AutInsatnce %s, spentAutInstance.After is different from spentAutInstance.Before on some fields except MintedAmount and ActiveRootTokenSet",
				spentAutInstance.spendingScriptType.String())
		}

		// MintedAmount
		if spentAutInstance.After.MintedAmount <= spentAutInstance.Before.MintedAmount {
			return fmt.Errorf("AutScriptTypeMint: AutInsatnce %s, spentAutInstance.After.MintedAmount (%d) <= spentAutInstance.Before.MintedAmount (%d)",
				spentAutInstance.spendingScriptType.String(), spentAutInstance.After.MintedAmount, spentAutInstance.Before.MintedAmount)
		}

		// ActiveRootTokenSet
		// spentAutInstance.After.ActiveRootTokenSet could be any case.
		// spentAutInstance.Before.ActiveRootTokenSet could not empty.
		if len(spentAutInstance.Before.ActiveRootTokenSet) == 0 {
			// should have some to be consumed to generate the after
			return fmt.Errorf("AutScriptTypeMint: AutInsatnce %s, spentAutInstance.Before.ActiveRootTokenSet is empty",
				spentAutInstance.spendingScriptType.String())
		}
		// spentAutInstance.After.ActiveRootTokenSet should be a subset of spentAutInstance.Before.ActiveRootTokenSet
		for _, rootTokenOp := range spentAutInstance.After.ActiveRootTokenSet {
			if _, ok := spentAutInstance.Before.ActiveRootTokenSet[rootTokenOp.String()]; !ok {
				return fmt.Errorf("AutScriptTypeMint: AutInsatnce %s, rootToken %s is in spentAutInstance.After.ActiveRootTokenSet but not in spentAutInstance.Before.ActiveRootTokenSet has commond %s",
					spentAutInstance.spendingScriptType.String(), rootTokenOp.String())
			}
		}

	default:
		return fmt.Errorf("spentAutInstance.spendingScriptType is %s, out of design", spentAutInstance.spendingScriptType.String())
	}

	return nil
}

func (spentAutInstance *SpentAutInstance) Serialize() ([]byte, error) {
	// Note that SanityCheck() has been called in spentAutInstance.SerializeSize() and spentAutInstance.write().
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

	// Note that SanityCheck() has been called in spentAutInstance.read().

	return nil
}

func (spentAutInstance *SpentAutInstance) ScriptMatchCheck(extAutScript *ctautapi.ExtAutScript) error {
	if spentAutInstance == nil {
		return fmt.Errorf("receiver spentAutInstance is nil")
	}

	if extAutScript == nil {
		return fmt.Errorf("the input parameter extAutScript is nil")
	}

	err := spentAutInstance.SanityCheck()
	if err != nil {
		return err
	}

	err = extAutScript.SanityCheck()
	if err != nil {
		return err
	}

	// AutIdentifier
	scriptAutIdentifier := extAutScript.AutIdentifier()
	if !bytes.Equal(spentAutInstance.spentAutIdentifier[:], scriptAutIdentifier[:]) {
		return fmt.Errorf("spentAutInstance.spentAutIdentifier is %s, while extAutScript.AutIdentifier is %s ",
			spentAutInstance.spentAutIdentifier.String(), scriptAutIdentifier.String())
	}

	// spentAutInstance.After.ActiveRootTokenSet should be consistent with extAutScript.GeneratedTokens()
	if len(extAutScript.GeneratedTokens()) == 0 {
		return fmt.Errorf("extAutScript.GeneratedTokens is nil/empty")
	}
	if len(spentAutInstance.After.ActiveRootTokenSet) != len(extAutScript.GeneratedTokens()) {
		return fmt.Errorf("len(spentAutInstance.After.ActiveRootTokenSet) %d != len(extAutScript.GeneratedTokens()) %d",
			len(spentAutInstance.After.ActiveRootTokenSet), len(extAutScript.GeneratedTokens()))
	}
	tempAfter := spentAutInstance.After.Clone() // make sure spentAutInstance.After is not modified
	for i, scriptOutputToken := range extAutScript.GeneratedTokens() {
		if scriptOutputToken == nil {
			return fmt.Errorf("extAutScript.GeneratedTokens[%d] is nil", i)
		}
		outputTokenOP := scriptOutputToken.HostOutPoint
		outputTokenOPStr := outputTokenOP.String()
		rootTokenOP, ok := tempAfter.ActiveRootTokenSet[outputTokenOPStr]
		if !ok {
			return fmt.Errorf("extAutScript.GeneratedTokens[%d] (%s) does not map to any item in spentAutInstance.After.ActiveRootTokenSet",
				i, outputTokenOPStr)
		}
		if rootTokenOP == nil {
			return fmt.Errorf("extAutScript.GeneratedTokens[%d] (%s) maps to nil in spentAutInstance.After.ActiveRootTokenSet",
				i, outputTokenOPStr)
		}
		if !outputTokenOP.IsEqual(rootTokenOP) {
			return fmt.Errorf("extAutScript.GeneratedTokens[%d] (%s) maps to different item (%s) spentAutInstance.After.ActiveRootTokenSet",
				i, outputTokenOPStr, rootTokenOP.String())
		}
		delete(tempAfter.ActiveRootTokenSet, outputTokenOPStr)
	}

	// spendingScriptType api.AutScriptType
	// Before             *api.AutMetadata
	switch autScriptInst := extAutScript.AutScript.(type) {
	case *ctautapi.RegistrationScript:
		if spentAutInstance.spendingScriptType != ctautapi.AutScriptTypeRegistration {
			return fmt.Errorf("the AutScript is RegistrationScript, but the spentAutInstance.spendingScriptType is %s",
				spentAutInstance.spendingScriptType.String())
		}

		// spentAutInstance.Before
		// is nil, no checks

	case *ctautapi.ReRegistrationScript:
		if spentAutInstance.spendingScriptType != ctautapi.AutScriptTypeReRegistration {
			return fmt.Errorf("the AutScript is AutScriptTypeReRegistration, but the spentAutInstance.spendingScriptType is %s",
				spentAutInstance.spendingScriptType.String())
		}

		// spentAutInstance.Before
		// Note that previous spentAutInstance.SanityCheck() has guaranteed that spentAutInstance.Before is not nil
		// extAutScript.ConsumedHostOutpoints() should be in spentAutInstance.Before.ActiveRootTokenSet
		tempBefore := spentAutInstance.Before.Clone() // make sure spentAutInstance.After is not modified
		for i, scriptInputOutPoint := range extAutScript.ConsumedHostOutpoints() {
			scriptInputOutPointStr := scriptInputOutPoint.String()
			rootTokenOP, ok := tempBefore.ActiveRootTokenSet[scriptInputOutPointStr]
			if !ok {
				return fmt.Errorf("extAutScript.ConsumedHostOutpoints[%d] (%s) does not map to any item in spentAutInstance.Before.ActiveRootTokenSet",
					i, scriptInputOutPointStr)
			}
			if rootTokenOP == nil {
				return fmt.Errorf("extAutScript.ConsumedHostOutpoints[%d] (%s) map to nil in spentAutInstance.Before.ActiveRootTokenSet",
					i, scriptInputOutPointStr)
			}
			if !scriptInputOutPoint.IsEqual(rootTokenOP) {
				return fmt.Errorf("extAutScript.ConsumedHostOutpoints[%d] (%s) map to a different item (%s) in spentAutInstance.Before.ActiveRootTokenSet",
					i, scriptInputOutPointStr, rootTokenOP.String())
			}
		}

	case *ctautapi.MintScript:
		if spentAutInstance.spendingScriptType != ctautapi.AutScriptTypeMint {
			return fmt.Errorf("the AutScript is AutScriptTypeMint, but the spentAutInstance.spendingScriptType is %s",
				spentAutInstance.spendingScriptType.String())
		}

		// spentAutInstance.Before
		// Note that previous spentAutInstance.SanityCheck() has guaranteed that spentAutInstance.Before is not nil
		// extAutScript.ConsumedHostOutpoints() should be in spentAutInstance.Before.ActiveRootTokenSet
		tempBefore := spentAutInstance.Before.Clone() // make sure spentAutInstance.After is not modified
		for i, scriptInputOutPoint := range extAutScript.ConsumedHostOutpoints() {
			scriptInputOutPointStr := scriptInputOutPoint.String()
			rootTokenOP, ok := tempBefore.ActiveRootTokenSet[scriptInputOutPointStr]
			if !ok {
				return fmt.Errorf("extAutScript.ConsumedHostOutpoints[%d] (%s) does not map to any item in spentAutInstance.Before.ActiveRootTokenSet",
					i, scriptInputOutPointStr)
			}
			if rootTokenOP == nil {
				return fmt.Errorf("extAutScript.ConsumedHostOutpoints[%d] (%s) map to nil in spentAutInstance.Before.ActiveRootTokenSet",
					i, scriptInputOutPointStr)
			}
			if !scriptInputOutPoint.IsEqual(rootTokenOP) {
				return fmt.Errorf("extAutScript.ConsumedHostOutpoints[%d] (%s) map to a different item (%s) in spentAutInstance.Before.ActiveRootTokenSet",
					i, scriptInputOutPointStr, rootTokenOP.String())
			}
		}

		// mintAmount
		// Note that the three value has been guaranteed in the legal scope, so that adding them will not overflow.
		if spentAutInstance.Before.MintedAmount+autScriptInst.Vin() != spentAutInstance.After.MintedAmount {
			return fmt.Errorf("spentAutInstance.Before.MintedAmount (%d) + autScriptInst.Vin() (%d) != spentAutInstance.After.MintedAmount (%d)",
				spentAutInstance.Before.MintedAmount, autScriptInst.Vin(), spentAutInstance.After.MintedAmount)
		}

	default:
		return fmt.Errorf("the input parameter extAutScript is not RegistrationScript or ReRegistrationScript")
	}

	return nil
}

func (spentAutTokenList *SpentAutTokenList) SerializeSize() (int, error) {
	err := spentAutTokenList.SanityCheck()
	if err != nil {
		return 0, err
	}

	size := 1                                                               // spentType        SpentAutType
	size += chainhash.HashSize                                              // spentAutIdentifier api.AutId
	size += wire.VarIntSerializeSize(uint64(spentAutTokenList.SpentHeight)) // SpentHeight int32
	size += 1                                                               // SpendingScriptType api.AutScriptType

	size += wire.VarIntSerializeSize(uint64(len(spentAutTokenList.SpentAutTokens))) // SpentAutTokens []SpentAutToken
	for _, spentAutToken := range spentAutTokenList.SpentAutTokens {
		tempSize, err := spentAutToken.serializeSize()
		if err != nil {
			return 0, err
		}
		size += tempSize
	}

	return size, nil
}

func (spentAutTokenList *SpentAutTokenList) write(w io.Writer) error {

	err := spentAutTokenList.SanityCheck()
	if err != nil {
		return err
	}

	// spentType SpentAutType
	_, err = w.Write([]byte{uint8(spentAutTokenList.spentType)})
	if err != nil {
		return err
	}

	// spentAutIdentifier api.AutId
	_, err = w.Write(spentAutTokenList.spentAutIdentifier[:])
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
		if spentAutToken == nil {
			return fmt.Errorf("spentAutTokenList.SpentAutTokens[%d] is nil", i)
		}

		// Note that spentAutToken.sanityCheck() is called in spentAutToken.write(w)
		if err = spentAutToken.write(w); err != nil {
			return err
		}
	}

	return nil
}

func (spentAutTokenList *SpentAutTokenList) read(r io.Reader) error {
	if spentAutTokenList == nil {
		return fmt.Errorf("receiver SpentAutTokenList is nil")
	}

	// spentType SpentAutType
	tmpByte := make([]byte, 1)
	_, err := io.ReadFull(r, tmpByte)
	if err != nil {
		return err
	}
	spentAutTokenList.spentType = SpentAutType(tmpByte[0])

	// spentAutIdentifier api.AutId
	_, err = io.ReadFull(r, spentAutTokenList.spentAutIdentifier[:])
	if err != nil {
		return err
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

	// spendingScriptType api.AutScriptType
	tmpByte = make([]byte, 1)
	_, err = io.ReadFull(r, tmpByte)
	if err != nil {
		return err
	}
	spentAutTokenList.spendingScriptType = ctautapi.AutScriptType(tmpByte[0])

	// SpentAutTokens     []*SpentAutTokens
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
		spentAutTokenList.SpentAutTokens[i] = spentAutToken
	}

	err = spentAutTokenList.SanityCheck()
	if err != nil {
		return err
	}

	return nil
}

func (spentAutTokenList *SpentAutTokenList) SanityCheck() error {
	if spentAutTokenList == nil {
		return fmt.Errorf("receiver spentAutTokenList is nil")
	}

	// spentType SpentAutType
	if spentAutTokenList.spentType != SpentAutTypeAutTokenList {
		return fmt.Errorf("the spentType (%d) is not SpentAutTypeAutTokenList", spentAutTokenList.spentType)
	}

	// spentAutIdentifier api.AutId

	// SpentHeight int32
	if spentAutTokenList.SpentHeight < 0 {
		return fmt.Errorf("the spentHeight (%d) is < 0", spentAutTokenList.SpentHeight)
	}

	// spendingScriptType api.AutScriptType
	if spentAutTokenList.spendingScriptType != ctautapi.AutScriptTypeTransfer &&
		spentAutTokenList.spendingScriptType != ctautapi.AutScriptTypeBurn {
		return fmt.Errorf("the spendingScriptType (%s) is not AutScriptTypeTransfer or AutScriptTypeBurn",
			spentAutTokenList.spendingScriptType.String())
	}

	// SpentAutTokens     []*SpentAutTokens
	if len(spentAutTokenList.SpentAutTokens) == 0 {
		return fmt.Errorf("the spentAutTokenList.SpentAutTokens is empty/nil")
	}
	for i, spentAutToken := range spentAutTokenList.SpentAutTokens {
		err := spentAutToken.sanityCheck()
		if err != nil {
			return err
		}

		if !bytes.Equal(spentAutToken.autIdentifier[:], spentAutTokenList.spentAutIdentifier[:]) {
			return fmt.Errorf("th %d -th spentAutToken (%s) has autIdentifier = %s, while spentAutTokenList.spentAutIdentifier is %s",
				i, spentAutToken.HostOutPoint.String(), spentAutToken.autIdentifier.String(), spentAutTokenList.spentAutIdentifier.String())
		}

		if spentAutToken.GeneratedHeight >= spentAutTokenList.SpentHeight {
			return fmt.Errorf("th %d -th spentAutToken (%s) has GeneratedHeight = %d, while spentAutTokenList.SpentHeight is %d, which is out of design",
				i, spentAutToken.HostOutPoint.String(), spentAutToken.GeneratedHeight, spentAutToken.GeneratedHeight)
		}

	}

	return nil
}

func (spentAutTokenList *SpentAutTokenList) Serialize() ([]byte, error) {

	// Note that spentAutTokenList.SanityCheck() is called in spentAutTokenList.SerializeSize() and spentAutTokenList.write().
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

	// Note that spentAutTokenList.SanityCheck() is called in spentAutTokenList.read().
	err := spentAutTokenList.read(r)
	if err != nil {
		return err
	}

	return nil
}

func (spentAutTokenList *SpentAutTokenList) ScriptMatchCheck(extAutScript *ctautapi.ExtAutScript) error {
	if spentAutTokenList == nil {
		return fmt.Errorf("receiver spentAutTokenList is nil")
	}

	if extAutScript == nil {
		return fmt.Errorf("the input parameter extAutScript is nil")
	}

	err := spentAutTokenList.SanityCheck()
	if err != nil {
		return err
	}

	err = extAutScript.SanityCheck()
	if err != nil {
		return err
	}

	// AutIdentifier
	scriptAutIdentifier := extAutScript.AutIdentifier()
	if !bytes.Equal(spentAutTokenList.spentAutIdentifier[:], scriptAutIdentifier[:]) {
		return fmt.Errorf("spentAutInstance.spentAutIdentifier is %s, while extAutScript.AutIdentifier is %s ",
			spentAutTokenList.spentAutIdentifier.String(), scriptAutIdentifier.String())
	}

	// SpentHeight        int32
	// no checks here

	// spendingScriptType api.AutScriptType
	// SpentAutTokens     []*SpentAutToken
	switch extAutScript.AutScript.(type) {
	case *ctautapi.TransferScript:
		// spendingScriptType api.AutScriptType
		if spentAutTokenList.spendingScriptType != ctautapi.AutScriptTypeTransfer {
			return fmt.Errorf("the AutScript is TransferScript, but the spentAutInstance.spendingScriptType is %s",
				spentAutTokenList.spendingScriptType.String())
		}

	case *ctautapi.BurnScript:
		// spendingScriptType api.AutScriptType
		if spentAutTokenList.spendingScriptType != ctautapi.AutScriptTypeBurn {
			return fmt.Errorf("the AutScript is TransferScript, but the spentAutInstance.spendingScriptType is %s",
				spentAutTokenList.spendingScriptType.String())
		}

	default:
		return fmt.Errorf("the input parameter extAutScript is not MintScript, TransferScript, or BurnScript ")
	}

	// SpentAutTokens     []*SpentAutToken
	// should exactly match the extAutScript.ConsumedHostOutpoints()
	spentAutTokens := spentAutTokenList.SpentAutTokens
	if len(spentAutTokens) == 0 {
		return fmt.Errorf("the spentAutTokenList.SpentAutTokens is empty")
	}
	if len(extAutScript.ConsumedHostOutpoints()) != len(spentAutTokens) {
		return fmt.Errorf("len(extAutScript.ConsumedHostOutpoints()) (%d) != len(spentAutTokenList.SpentAutTokens) (%d)",
			len(extAutScript.ConsumedHostOutpoints()), len(spentAutTokens))
	}

	for i, scriptInputOutPoint := range extAutScript.ConsumedHostOutpoints() {
		if !spentAutTokens[i].HostOutPoint.IsEqual(scriptInputOutPoint) {
			return fmt.Errorf("the HostOutPoint (%s) of spentAutTokenList.SpentAutTokens[%d] is differnet from extAutScript.ConsumedHostOutpoints[%d]",
				spentAutTokens[i].HostOutPoint.String(), i, scriptInputOutPoint.String())
		}
	}

	return nil
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

		err := saut.ScriptMatchCheck(extAutScript)
		if err != nil {
			return nil, err
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

		// Note that saut.ScriptMatchCheck(extAutScript) has been called above.

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
		if len(serializedSpentAuts) != 0 {
			return nil, fmt.Errorf("deserializeSpendJournalEntryAut: the input serializedSpentAuts is nil/empty")
		}

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
		case ctautapi.AutScriptTypeRegistration, ctautapi.AutScriptTypeReRegistration, ctautapi.AutScriptTypeMint:
			rstSpentAuts[i] = &SpentAutInstance{}

		case ctautapi.AutScriptTypeTransfer, ctautapi.AutScriptTypeBurn:
			rstSpentAuts[i] = &SpentAutTokenList{}

		default:
			return nil, AssertError(fmt.Sprintf("the %d-th ExtAutScript of block (%s) has unknown ScriptType %s",
				i, block.Hash().String(), extAutScript.Type().String()))

		}

		err = rstSpentAuts[i].read(r)
		if err != nil {
			return nil, err
		}

		err = rstSpentAuts[i].ScriptMatchCheck(extAutScript)
		if err != nil {
			return nil, err
		}
	}

	return rstSpentAuts, nil
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

// aut add and reivew done 2025.12.19
func dbRemoveSpendJournalEntryAut(dbTx database.Tx, blockHash *chainhash.Hash) error {
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
func dbFetchCTAUTCoin(dbTx database.Tx, outpoint ctautapi.HostOutPoint, identifier ctautapi.AutId) (*CTAUTCoin, error) {
	// Fetch the unspent transaction output information for the passed
	// transaction output.  Return now when there is no entry.
	autTokenBucket := dbTx.Metadata().Bucket(ctAutTokenBucketName)
	if autTokenBucket == nil {
		return nil, fmt.Errorf("bucket for aut coin does not exist")
	}
	subBuckets := autTokenBucket.Bucket(identifier[:])
	if subBuckets == nil {
		return nil, nil
	}

	key := ctautOutpointKey(outpoint)
	serializedCoin := subBuckets.Get(*key)
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

	//	2025.12.19 coin read from database is set to be cafModified; future: set to be an NONE status
	coin.packedFlags = cafModified
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

// aut review done 2025.12.18 todo
func dbRemoveCTAUTInstance(dbTx database.Tx, autIdKeysToDel map[string]struct{}, blockHeight int32, blockHash chainhash.Hash) error {
	autInstanceBucket := dbTx.Metadata().Bucket(ctAutInstanceBucketName)
	autTokenBucket := dbTx.Metadata().Bucket(ctAutTokenBucketName)

	for autIdentifierKey, _ := range autIdKeysToDel {
		// todo: 2025.12.18 confirm This is based on that autIdentifierKey = autIdentifier.String(), where autIdentifier is a Hash.
		// todo: 2025.12.18 future: provide a more form "paired" functions.
		autIdentifier, err := chainhash.NewHashFromStr(autIdentifierKey)
		if err != nil {
			return fmt.Errorf("invalid identifier key")
		}

		err = autInstanceBucket.Delete(autIdentifier[:])
		if err != nil {
			return err
		}

		// assert no coins reside
		if subBucket := autTokenBucket.Bucket(autIdentifier[:]); subBucket != nil {
			count := 0
			err = subBucket.ForEach(func(k, v []byte) error {
				count++
				return nil
			})
			if err != nil {
				return err
			}
			if count != 0 {
				return fmt.Errorf("fail to remove instance %s because it has %d aut tokens ", autIdentifierKey, count)
			}
		}

		err = autTokenBucket.DeleteBucket(autIdentifier[:])
		if err != nil {
			return err
		}
		log.Debugf(`AUT identified by %s is removed at height %d (block hash %s)`,
			autIdentifierKey, blockHeight, blockHash.String())
	}

	return nil
}

// aut review done 2025.12.16
func dbPutCTAUTView(dbTx database.Tx, view *CTAUTViewpoint, blockHeight int32, blockHash chainhash.Hash) error {
	autInstanceBucket := dbTx.Metadata().Bucket(ctAutInstanceBucketName)

	autTokenBucket := dbTx.Metadata().Bucket(ctAutTokenBucketName)
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
		err = autInstanceBucket.Put(identifier[:], serializedCTAUTInfo)
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
		log.Debugf("\t MintedAmount: %v", metadata.MintedAmount)
		log.Debugf("\t BurnedAmount: %v", metadata.BurnedAmount)
		log.Debugf("\t Active RootCoin: len = %d", len(metadata.ActiveRootTokenSet))
		for point := range metadata.ActiveRootTokenSet {
			log.Debugf("%s", point)
		}
		log.Debugf("\t Updated Version: len = %d", len(metadata.UpdateScriptVersions))
		for i := 0; i < len(metadata.UpdateScriptVersions); i++ {
			log.Debugf("\t\t %d", metadata.UpdateScriptVersions[i])
		}

		subBucket := autTokenBucket.Bucket(identifier[:])
		if subBucket == nil {
			subBucket, err = autTokenBucket.CreateBucket(identifier[:])
			if err != nil {
				return err
			}
		}

		for outpoint, coin := range instance.coins {
			// No need to update the database if the entry was not modified.
			if coin == nil || !coin.isModified() {
				continue
			}
			// Remove the utxo entry if it is spent.
			if coin.IsSpent() {
				key := ctautOutpointKey(outpoint)
				err = subBucket.Delete(*key) // if rollback, would restore by spend journal
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
			err = subBucket.Put(*key, serializedCoin)
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

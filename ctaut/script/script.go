package script

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/abesuite/abec/ctaut/dao"

	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/chainhash"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/wire"
)

type HostOutPoint = dao.HostOutPoint
type AutId = dao.AutId
type AutIssuer = dao.AutIssuer

// AutMetadata maintains the metadata information of Abelian User Token (AUT) instance on Abelian
// 1. Each AutInstance has a unique identifier, which is actually a hash of the Abelian-Tx
// through which the AutInstance is registered.
// 2. Each instance has its own name, symbol, and unit names (including BaseUnitName and SubUnitName).
// 3. Each instance has its planned total supply amount.
// 4. Each instance has issuers, each minting and updating is required to meet the preset threshold.
//
// In details:
// RegistrationScript would register a new AutInstance with unique AutIdentifier, and generate some special
// tokens, named 'AutRootToken', that would be consumed by MintScript or ReRegistrationScript
//
// ReRegistrationScript would update the AutMetadata information of an AutInstance,
// including fields PlannedTotalSupply / Issuers / MintThreshold / ReregistrationThreshold / ReregistrationExpireHeight.
//
// MintScript would consume some AutRootToken of an AutInstance and generate normal tokens for that AutInstance,
// and also update the MintedAmount of that AutInstance.
//
// TransferScript would transfer tokens between users, it would not affect any of the fields in AutMetadata.
//
// BurnScript would burn some tokens, and update the BurnedAmount of that AutInstance's AutMetadata.
type AutMetadata struct {
	// Version rule is referred to the ctaut.wire.
	Version uint32

	// AutIdentifier is the unique identifier for an AutInstance.
	// TxHash of the host transaction (i.e. txId) where the registration script is located
	// is used as the AutInstance identifier.
	AutIdentifier AutId

	// AutName, the name of the AutInstance, gives
	// the full, descriptive and human-readable name of the token ,e.g. "Post-Quantum USD".
	// It could be used to improve usability, but MUST NOT be assumed that the value must be present.
	AutName []byte

	// AutSymbol, the symbol of the AutInstance, gives
	// a short, human-readable string that acts as a ticker for the token, e.g. "PQUSD".
	// could be used to improve usability, but MUST NOT be assumed that the value must be present.
	AutSymbol []byte

	// BaseUnitName is the name he commonly used units of tokens, e.g. "USD".
	// It could be used to user representation, but MUST NOT be assumed that the value must be present.
	BaseUnitName []byte

	// SubUnitName is the name of the token used for counting, e.g. "Cent".
	// It MUST NOT be assumed that the value must be present.
	SubUnitName []byte

	// UnitScale is used to store the scale between BaseUnit and SubUnit, e.g. 100.
	UnitScale uint64

	// AutMemo stores the memo of the AutInstance.
	AutMemo []byte

	// PlannedTotalSupply stores the total amount of token of the AutInstance would be issued,
	// which implies the total limit for all MintScript.
	// Note that the amount would be counted in terms of subUnit.
	PlannedTotalSupply uint64

	// Issuers contain DISTINCT AutIssuers for corresponding AutInstance.
	// the ReregistrationThreshold and MintThreshold specify the number of required issuers for Reregistration and Mint respectively.
	Issuers []*AutIssuer

	// ReregistrationExpireHeight specifies a height, after which the ReRegistrationScript could not be applied anymore.
	// Using int32 is to allow -1 to be used as the infinite height.
	ReregistrationExpireHeight int32

	// ReregistrationThreshold specifies the size of authorized issuer set for ReRegistrationScript.
	ReregistrationThreshold uint8

	// MintThreshold specifies the size of authorized issuer set for MintScript.
	MintThreshold uint8

	// PrivacyType specifies the privacy type of the AutInstance.
	PrivacyType AutPrivacyType

	// MintedAmount records the total minted amount of this AutInstance.
	MintedAmount uint64

	// BurnedAmount records the total burned amount of this AutInstance.
	BurnedAmount uint64

	// ActiveRootTokenSet stores the currently available AutRootTokens.
	// When a RegistrationScript or ReRegistrationScript is executed, some AutRootTokens are created and host on HostOutPoints,
	// and they are recorded as ActiveRootTokens.
	// Each AutRootToken is actually an Abelian-Txo owned by an issuer in []issuers.
	//
	// When a ReRegistrationScript or MintScript is executed, it must consume/spend some ActiveRootTokens.
	// When a ReRegistrationScript is executed, some ActiveRootTokens are consumed, and the remaining ActiveRootTokens are set to inactive,
	// and the new generated AutRootTokens are set to be the ActiveRootTokens.
	// When a MintScript is executed, some ActiveRootTokens are consumed, and the remaining ActiveRootTokens keep active,
	// that is, each time a MintScript is executed, some RootTokens are removed from ActiveRootTokenSet
	ActiveRootTokenSet map[string]*HostOutPoint

	// UpdateScriptVersions records all versions of the scripts that creates/updates the AutMetadata,
	// say RegistrationScript and ReRegistrationScript.
	// More specifically, when RegistrationScript creates the AutMetadata,
	// RegistrationScript's version is put into UpdateScriptVersions as the first one;
	// Each time ReRegistrationScript updates the AutMetadata, the ReRegistrationScript's version is appended to UpdateScriptVersions.
	// The versions in UpdateScriptVersions are sequenced from small to large.
	// The size of UpdateScriptVersions "equal" Metadata.Version.
	// Currently, there is no rules
	// Future, this field could be used to as conditions for upgrading script.
	UpdateScriptVersions []uint32
}

func (autMetadata *AutMetadata) serializeSize() (int, error) {
	n := wire.VarIntSerializeSize(uint64(autMetadata.Version)) + //version
		chainhash.HashSize + // identifier, fixed length
		wire.VarIntSerializeSize(uint64(len(autMetadata.AutName))) + len(autMetadata.AutName) + // name, variable length
		wire.VarIntSerializeSize(uint64(len(autMetadata.AutSymbol))) + len(autMetadata.AutSymbol) + // symbol, variable length
		wire.VarIntSerializeSize(uint64(len(autMetadata.BaseUnitName))) + len(autMetadata.BaseUnitName) + // base unit, variable length
		wire.VarIntSerializeSize(uint64(len(autMetadata.SubUnitName))) + len(autMetadata.SubUnitName) + // sub unit, variable length
		wire.VarIntSerializeSize(autMetadata.UnitScale) + // scale, variable length
		wire.VarIntSerializeSize(uint64(len(autMetadata.AutMemo))) + len(autMetadata.AutMemo) // autMemo, variable length

	n += wire.VarIntSerializeSize(autMetadata.PlannedTotalSupply) // planned amount

	n += wire.VarIntSerializeSize(uint64(len(autMetadata.Issuers))) // number of issuers
	for i := 0; i < len(autMetadata.Issuers); i++ {
		if autMetadata.Issuers[i] == nil {
			return 0, fmt.Errorf("autMetadata.Issuers[%d] is nil", i)
		}
		n += autMetadata.Issuers[i].SerializeSize()
	}

	n += wire.VarIntSerializeSize(uint64(autMetadata.ReregistrationExpireHeight)) // ReregistrationExpireHeight

	n += 1 // reregister threshold
	n += 1 // mint threshold
	n += 1 // privacy type

	n += wire.VarIntSerializeSize(autMetadata.MintedAmount) + // minted amount,variable length
		wire.VarIntSerializeSize(autMetadata.BurnedAmount) // burned amount,variable length

	n += wire.VarIntSerializeSize(uint64(len(autMetadata.ActiveRootTokenSet))) // number of issuer tokens
	for opStr, hostOutPoint := range autMetadata.ActiveRootTokenSet {
		if hostOutPoint == nil {
			return 0, fmt.Errorf("autMetadata.ActiveRootTokenSet[%s] is nil", opStr)
		}
		n += hostOutPoint.SerializeSize()
	}

	n += wire.VarIntSerializeSize(uint64(len(autMetadata.UpdateScriptVersions)))
	for i := 0; i < len(autMetadata.UpdateScriptVersions); i++ {
		n += wire.VarIntSerializeSize(uint64(autMetadata.UpdateScriptVersions[i]))
	}

	return n, nil
}

// Serialize serializes AutMetadata to []byte.
func (autMetadata *AutMetadata) Serialize() ([]byte, error) {
	if autMetadata == nil {
		return nil, fmt.Errorf("autMetadata is nil")
	}

	// Calculate the size needed to serialize AUT autMetadata.
	size, err := autMetadata.serializeSize()
	if err != nil {
		return nil, err
	}
	// Serialize the header code followed by the compressed unspent
	// transaction output.
	w := bytes.NewBuffer(make([]byte, 0, size))

	// Version                    uint32
	if err = wire.WriteVarInt(w, 0, uint64(autMetadata.Version)); err != nil {
		return nil, err
	}

	// AutIdentifier              AutId
	if _, err = w.Write(autMetadata.AutIdentifier[:]); err != nil {
		return nil, err
	}

	// AutName                    []byte
	if err = wire.WriteVarBytes(w, 0, autMetadata.AutName); err != nil {
		return nil, err
	}

	// AutSymbol                  []byte
	if err = wire.WriteVarBytes(w, 0, autMetadata.AutSymbol); err != nil {
		return nil, err
	}

	// BaseUnitName               []byte
	if err = wire.WriteVarBytes(w, 0, autMetadata.BaseUnitName); err != nil {
		return nil, err
	}

	// SubUnitName                []byte
	if err = wire.WriteVarBytes(w, 0, autMetadata.SubUnitName); err != nil {
		return nil, err
	}

	// UnitScale                  uint64
	if err = wire.WriteVarInt(w, 0, autMetadata.UnitScale); err != nil {
		return nil, err
	}

	// AutMemo                    []byte
	if err = wire.WriteVarBytes(w, 0, autMetadata.AutMemo); err != nil {
		return nil, err
	}

	// PlannedTotalSupply         uint64
	if err = wire.WriteVarInt(w, 0, autMetadata.PlannedTotalSupply); err != nil {
		return nil, err
	}

	// Issuers               []*AutIssuer
	if err = wire.WriteVarInt(w, 0, uint64(len(autMetadata.Issuers))); err != nil {
		return nil, err
	}
	for i := 0; i < len(autMetadata.Issuers); i++ {
		if autMetadata.Issuers[i] == nil {
			return nil, fmt.Errorf("autMetadata.Issuers[%d] is nil", i)
		}
		if err = autMetadata.Issuers[i].Write(w); err != nil {
			return nil, fmt.Errorf("error happens when writing issuer: %v", err)
		}
	}

	// ReregistrationExpireHeight int32
	if err = wire.WriteVarInt(w, 0, uint64(autMetadata.ReregistrationExpireHeight)); err != nil {
		return nil, err
	}

	// ReregistrationThreshold    uint8
	if err = w.WriteByte(autMetadata.ReregistrationThreshold); err != nil {
		return nil, err
	}

	// MintThreshold              uint8
	if err = w.WriteByte(autMetadata.MintThreshold); err != nil {
		return nil, err
	}

	// PrivacyType                AutPrivacyType
	if err = w.WriteByte(uint8(autMetadata.PrivacyType)); err != nil {
		return nil, err
	}

	// MintedAmount               uint64
	if err = wire.WriteVarInt(w, 0, autMetadata.MintedAmount); err != nil {
		return nil, err
	}

	// BurnedAmount               uint64
	if err = wire.WriteVarInt(w, 0, autMetadata.BurnedAmount); err != nil {
		return nil, err
	}

	// ActiveRootTokenSet         map[string]*HostOutPoint
	if err = wire.WriteVarInt(w, 0, uint64(len(autMetadata.ActiveRootTokenSet))); err != nil {
		return nil, err
	}
	for opStr, hostOutPoint := range autMetadata.ActiveRootTokenSet {
		if hostOutPoint == nil {
			return nil, fmt.Errorf("autMetadata.ActiveRootTokenSet[%s] is nil", opStr)
		}
		if err = wire.WriteOutPointAbe(w, 0, 0, hostOutPoint); err != nil {
			return nil, fmt.Errorf("error happens when writing active root token: %v", err)
		}
	}

	// UpdateScriptVersions            []uint32
	if err = wire.WriteVarInt(w, 0, uint64(len(autMetadata.UpdateScriptVersions))); err != nil {
		return nil, err
	}
	for i := 0; i < len(autMetadata.UpdateScriptVersions); i++ {
		if err = wire.WriteVarInt(w, 0, uint64(autMetadata.UpdateScriptVersions[i])); err != nil {
			return nil, err
		}
	}

	serializedMetadata := w.Bytes()

	//// todo: the following codes are necessary or only for test?
	//tmpMetadata := &AutMetadata{}
	//err = tmpMetadata.Deserialize(serializedMetadata)
	//if err != nil {
	//	return nil, err
	//}
	//if !reflect.DeepEqual(autMetadata, tmpMetadata) {
	//	return nil, errors.New("metadata not match after serialization")
	//}

	return serializedMetadata, nil
}

// Deserialize deserializes serializedMetadata to an AutMetadata.
func (autMetadata *AutMetadata) Deserialize(serializedMetadata []byte) error {
	if autMetadata == nil {
		return fmt.Errorf("autMetadata is nil")
	}

	r := bytes.NewReader(serializedMetadata)

	// Version                    uint32
	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if version > math.MaxUint32 {
		return fmt.Errorf("read version (%d) is too large", version)
	}
	autMetadata.Version = uint32(version)

	// AutIdentifier              AutId
	if _, err = io.ReadFull(r, autMetadata.AutIdentifier[:]); err != nil {
		return err
	}

	// AutName                    []byte
	if autMetadata.AutName, err = wire.ReadVarBytes(r, 0, MaxAutNameLength, "autName"); err != nil {
		return err
	}

	// AutSymbol                  []byte
	if autMetadata.AutSymbol, err = wire.ReadVarBytes(r, 0, MaxAutSymbolLength, "autSymbol"); err != nil {
		return err
	}

	// BaseUnitName               []byte
	if autMetadata.BaseUnitName, err = wire.ReadVarBytes(r, 0, MaxBaseUnitLength, "baseUnitName"); err != nil {
		return err
	}

	// SubUnitName                []byte
	if autMetadata.SubUnitName, err = wire.ReadVarBytes(r, 0, MaxSubUnitLength, "subUnitName"); err != nil {
		return err
	}

	// UnitScale                  uint64
	if autMetadata.UnitScale, err = wire.ReadVarInt(r, 0); err != nil {
		return err
	}

	// AutMemo                    []byte
	if autMetadata.AutMemo, err = wire.ReadVarBytes(r, 0, MaxAutMemoLength, "AutMemo"); err != nil {
		return err
	}

	// PlannedTotalSupply         uint64
	if autMetadata.PlannedTotalSupply, err = wire.ReadVarInt(r, 0); err != nil {
		return err
	}

	// IssuerTokens               [][]byte
	issuerNum, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if issuerNum > MaxIssuerNum {
		//	This is necessary here to prevent possible attack.
		return fmt.Errorf("read issuerNum (%d) is too large", issuerNum)
	}
	autMetadata.Issuers = make([]*AutIssuer, issuerNum)
	for i := uint64(0); i < issuerNum; i++ {
		issuer := &AutIssuer{}
		if err = issuer.Read(r); err != nil {
			return fmt.Errorf("error happens when reading issuer: %v", err)
		}

		autMetadata.Issuers[i] = issuer
	}

	// ReregistrationExpireHeight int32
	expiredHeightRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	temp := int64(expiredHeightRead)
	if temp > math.MaxInt32 || temp < -1 {
		return fmt.Errorf("the read ReregistrationExpireHeight (%d) is not in the scope [-1, %d]", temp, math.MaxInt32)
	}
	autMetadata.ReregistrationExpireHeight = int32(temp)

	// ReregistrationThreshold    uint8
	if autMetadata.ReregistrationThreshold, err = r.ReadByte(); err != nil {
		return err
	}

	// MintThreshold              uint8
	if autMetadata.MintThreshold, err = r.ReadByte(); err != nil {
		return err
	}

	// PrivacyType                AutPrivacyType
	privacyTypeRead, err := r.ReadByte()
	if err != nil {
		return err
	}
	autMetadata.PrivacyType = AutPrivacyType(privacyTypeRead)

	// MintedAmount               uint64
	if autMetadata.MintedAmount, err = wire.ReadVarInt(r, 0); err != nil {
		return err
	}

	// BurnedAmount               uint64
	if autMetadata.BurnedAmount, err = wire.ReadVarInt(r, 0); err != nil {
		return err
	}

	// ActiveRootTokenSet         map[string]*HostOutPoint
	rootCoinNum, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if rootCoinNum > MaxNumToken {
		return fmt.Errorf("read rootCoinNum (%d) is too large", rootCoinNum)
	}
	autMetadata.ActiveRootTokenSet = make(map[string]*HostOutPoint, rootCoinNum)
	for i := uint64(0); i < rootCoinNum; i++ {
		hostOutPoint := &HostOutPoint{}
		if err = wire.ReadOutPointAbe(r, 0, 0, hostOutPoint); err != nil {
			return fmt.Errorf("error happens when reading active root token: %v", err)
		}

		opStr := hostOutPoint.String()
		if _, ok := autMetadata.ActiveRootTokenSet[opStr]; ok {
			return fmt.Errorf("duplicate active root token for %s", opStr)
		}
		autMetadata.ActiveRootTokenSet[opStr] = hostOutPoint
	}

	updateScriptVersionNum, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if updateScriptVersionNum != uint64(autMetadata.Version) {
		// this is a designed rule.
		return fmt.Errorf("updateScriptVersionNum (%d) is not equla the value of autMetadata.Version (%d)",
			updateScriptVersionNum, autMetadata.Version)
	}
	autMetadata.UpdateScriptVersions = make([]uint32, updateScriptVersionNum)
	for i := 0; i < len(autMetadata.UpdateScriptVersions); i++ {
		version, err = wire.ReadVarInt(r, 0)
		if err != nil {
			return err
		}
		if version > math.MaxUint32 {
			return fmt.Errorf("read update script version (%d) is too large", version)
		}
		autMetadata.UpdateScriptVersions[i] = uint32(version)
	}

	return autMetadata.SanityCheck()
}

// SanityCheck checks whether the AutMetadata is well-formed, and return a non-nil error if it is not well-formed.
func (autMetadata *AutMetadata) SanityCheck() error {
	if autMetadata == nil {
		return fmt.Errorf("AutMetadata is nil")
	}

	if autMetadata.Version < ctautwire.AutMetadataVersionInitValue {
		return fmt.Errorf("invalid autMetadata.Version (%d)", autMetadata.Version)
	}

	if len(autMetadata.AutName) > MaxAutNameLength {
		return fmt.Errorf("invalid length (%d) for aut name", len(autMetadata.AutName))
	}

	if len(autMetadata.AutSymbol) > MaxAutSymbolLength {
		return fmt.Errorf("invalid length (%d) for aut symbol", len(autMetadata.AutSymbol))
	}

	if len(autMetadata.BaseUnitName) > MaxBaseUnitLength {
		return fmt.Errorf("invalid length (%d) for base unit name", len(autMetadata.BaseUnitName))
	}

	if len(autMetadata.SubUnitName) > MaxSubUnitLength {
		return fmt.Errorf("invalid length (%d) for sub unit name", len(autMetadata.SubUnitName))
	}

	if autMetadata.UnitScale > MaxAmount {
		return fmt.Errorf("invalid UnitScale (%d)", autMetadata.UnitScale)
	}

	if len(autMetadata.AutMemo) > MaxAutMemoLength {
		return fmt.Errorf("invalid length (%d) for aut memo", len(autMetadata.AutMemo))
	}

	if autMetadata.PlannedTotalSupply > MaxAmount {
		return fmt.Errorf("invalid planned total supply (%d)", autMetadata.PlannedTotalSupply)
	}

	if len(autMetadata.Issuers) > MaxIssuerNum {
		return fmt.Errorf("the number of issuers (%d) exceeds the allowed maximum (%d)",
			len(autMetadata.Issuers), MaxIssuerNum)
	}
	issuersMap := make(map[string]int, len(autMetadata.Issuers))
	for i, issuer := range autMetadata.Issuers {
		if issuer == nil {
			return fmt.Errorf("autMetadata.Issuers[%d] is nil", i)
		}
		issuerStr := issuer.String()
		if index, ok := issuersMap[issuerStr]; ok {
			return fmt.Errorf("duplicate issuers[%d] and issuers[%d]: %s", i, index, issuerStr)
		}
		issuersMap[issuerStr] = i
	}

	if autMetadata.ReregistrationExpireHeight < InfiniteExpireHeight {
		return fmt.Errorf("invalid reregistration expire height (%d)", autMetadata.ReregistrationExpireHeight)
	}

	if autMetadata.ReregistrationThreshold == 0 || int(autMetadata.ReregistrationThreshold) > len(autMetadata.Issuers) {
		return fmt.Errorf("invalid reregistration threshold (%d) for %d issuers",
			autMetadata.ReregistrationThreshold, len(autMetadata.Issuers))
	}
	if autMetadata.MintThreshold == 0 || int(autMetadata.MintThreshold) > len(autMetadata.Issuers) {
		return fmt.Errorf("invalid mint threshold (%d) for %d issuers", autMetadata.MintThreshold, len(autMetadata.Issuers))
	}

	if autMetadata.PrivacyType != AutPrivacyTypeUnlimited &&
		autMetadata.PrivacyType != AutPrivacyTypeLimitedPublic &&
		autMetadata.PrivacyType != AutPrivacyTypeLimitedHidden {
		return fmt.Errorf("invalid privacy type (%d)", autMetadata.PrivacyType)
	}

	if autMetadata.MintedAmount > autMetadata.PlannedTotalSupply {
		return fmt.Errorf("invalid minted amount (%d) for planned total supply (%d)", autMetadata.MintedAmount, autMetadata.PlannedTotalSupply)
	}
	if autMetadata.BurnedAmount > autMetadata.MintedAmount {
		return fmt.Errorf("invalid burned amount (%d) for minted amount (%d)", autMetadata.BurnedAmount, autMetadata.MintedAmount)
	}

	if len(autMetadata.ActiveRootTokenSet) > MaxNumToken {
		return fmt.Errorf("active root token number (%d) is too large", len(autMetadata.ActiveRootTokenSet))
	}
	for opStr, hostOutPoint := range autMetadata.ActiveRootTokenSet {
		if hostOutPoint == nil {
			return fmt.Errorf("autMetadata.ActiveRootTokenSet[%s] is nil", opStr)
		}
		valueKey := hostOutPoint.String()
		if strings.Compare(opStr, valueKey) != 0 {
			return fmt.Errorf("invalid active root token for %s, having key from value %s", opStr, valueKey)
		}
	}

	if uint64(len(autMetadata.UpdateScriptVersions)) != uint64(autMetadata.Version) {
		return fmt.Errorf("len(autMetadata.UpdateScriptVersions) (%d) != autMetadata.Version (%d)",
			len(autMetadata.UpdateScriptVersions), autMetadata.Version)
	}
	// now len(autMetadata.UpdateScriptVersions) >= 1
	if _, ok := ctautwire.AutScriptVersionSet[autMetadata.UpdateScriptVersions[0]]; !ok {
		return fmt.Errorf("invalid UpdateScriptVersion (%d) at position %d: not in the AutScriptVersionSet",
			autMetadata.UpdateScriptVersions[0], 0)
	}

	for i := 1; i < len(autMetadata.UpdateScriptVersions); i++ {
		if _, ok := ctautwire.AutScriptVersionSet[autMetadata.UpdateScriptVersions[i]]; !ok {
			return fmt.Errorf("invalid UpdateScriptVersion (%d) at position %d: not in the AutScriptVersionSet",
				autMetadata.UpdateScriptVersions[i], i)
		}

		if autMetadata.UpdateScriptVersions[i] < autMetadata.UpdateScriptVersions[i-1] {
			return fmt.Errorf("invalid UpdateScriptVersion version (%d) at position %d : "+
				"smaller than the UpdateScriptVersion (%d) at position %d",
				autMetadata.UpdateScriptVersions[i], i, autMetadata.UpdateScriptVersions[i-1], i-1)
		}
	}

	return nil
}

// Clone returns a deep copy of the AutMetadata entry.
func (autMetadata *AutMetadata) Clone() *AutMetadata {
	if autMetadata == nil {
		return nil
	}

	cloned := &AutMetadata{
		Version:       autMetadata.Version,
		AutIdentifier: AutId{},

		AutName:            make([]byte, len(autMetadata.AutName)),
		AutSymbol:          make([]byte, len(autMetadata.AutSymbol)),
		BaseUnitName:       make([]byte, len(autMetadata.BaseUnitName)),
		SubUnitName:        make([]byte, len(autMetadata.SubUnitName)),
		UnitScale:          autMetadata.UnitScale,
		AutMemo:            make([]byte, len(autMetadata.AutMemo)),
		PlannedTotalSupply: autMetadata.PlannedTotalSupply,

		Issuers: make([]*AutIssuer, len(autMetadata.Issuers)),

		ReregistrationExpireHeight: autMetadata.ReregistrationExpireHeight,
		ReregistrationThreshold:    autMetadata.ReregistrationThreshold,
		MintThreshold:              autMetadata.MintThreshold,
		PrivacyType:                autMetadata.PrivacyType,

		MintedAmount:         autMetadata.MintedAmount,
		BurnedAmount:         autMetadata.BurnedAmount,
		ActiveRootTokenSet:   make(map[string]*HostOutPoint, len(autMetadata.ActiveRootTokenSet)),
		UpdateScriptVersions: make([]uint32, len(autMetadata.UpdateScriptVersions)),
	}

	copy(cloned.AutIdentifier[:], autMetadata.AutIdentifier[:])

	copy(cloned.AutSymbol, autMetadata.AutSymbol)
	copy(cloned.AutName, autMetadata.AutName)
	copy(cloned.BaseUnitName, autMetadata.BaseUnitName)
	copy(cloned.SubUnitName, autMetadata.SubUnitName)
	copy(cloned.AutMemo, autMetadata.AutMemo)

	for i := 0; i < len(autMetadata.Issuers); i++ {
		if autMetadata.Issuers[i] == nil {
			cloned.Issuers[i] = nil
		} else {
			cloned.Issuers[i] = autMetadata.Issuers[i].Clone()
		}
	}

	for opStr, hostOutpoint := range autMetadata.ActiveRootTokenSet {
		if hostOutpoint == nil {
			cloned.ActiveRootTokenSet[opStr] = nil
		} else {
			cloned.ActiveRootTokenSet[opStr] = hostOutpoint.Clone()
		}
	}

	for i := 0; i < len(autMetadata.UpdateScriptVersions); i++ {
		cloned.UpdateScriptVersions[i] = autMetadata.UpdateScriptVersions[i]
	}

	return cloned
}

// AutScript defines the interface for Aut Scripts.
type AutScript interface {

	// Version returns the AutScriptVersion.
	Version() uint32

	// Type returns the AutScriptType, which could be {Registration, Reregistration, Mint, Transfer, Burn}.
	Type() AutScriptType

	// AutIdentifier returns the autIdentifier of the AutInstance that this AutScript is operating.
	AutIdentifier() AutId

	// InStartIndex returns the start index of the input AutTokens.
	InStartIndex() uint8

	// OutStartIndex returns the start index of the output AutTokens.
	OutStartIndex() uint8

	// WitnessHash returns the WitnessHash in the script.
	WitnessHash() chainhash.Hash

	// NumConsumedTokens returns the number of AutRootTokens/AutTokens that this AutScript consumes.
	NumConsumedTokens() int

	// NumGeneratedTokens returns the number of AutRootTokens/AutTokens that this AutScript generates.
	NumGeneratedTokens() int

	// Serialize serializes AutScript to []byte.
	Serialize() ([]byte, error)

	// Deserialize deserializes []byte to AutScript.
	Deserialize([]byte) error

	// SanityCheck perform sanity-checks on AutScript.
	SanityCheck() error
}

// RegistrationScript would be the structured script parsed from TxMemo in the host Abelian-Transaction,
// 1. the AutMetadata for the AutInstance will be extracted from the script with RegistrationScript.Metadata()
// 2. consumedTokens would be populated with the help of host-transaction and corresponding wire.TxoRing
// 3. generatedTokens would be populated with the function populateGeneratedCTAUTTokens with the help of host-transaction.
//
// RegistrationScript contains
// <Version>
// <ScriptType>
// <autIdentifier> ZeroHash, this is because the underlying Abelian-Tx has not been created,
// and the TxHash actually need RegistrationScript as a part of the preimage.
// <autName> a byte array with max length, would not be changed anymore
// <autSymbol> a byte array with max length, would not be changed anymore
// <baseUnitName> a byte array with max length, would not be changed anymore
// <subUnitName> a byte array with max length, would not be changed anymore
// <unitScale> the scale between unit and minUnit, would not be changed anymore
// <autMemo> a byte array with max length
//
// <Planed Total Amount> an integer range in [1, 1<<51 -1]
// <Issuers> an array with length N AutIssuer
// <ExpiryHeight> a height after which ReregistrationScript cannot be executed, and -1 implies no such limit
// <ReregistrationThreshold> An integer update_t in [1, N]
// <MintThreshold> An integer mint_t in [1, N]
//
// <Number of generated RootTokens> A number n, explicitly mark the 0~(n-1)-th pseudonym Abelian-Txo of the host-tx as RootToken
// <ScriptMemo> a byte array with max length, for this script
type RegistrationScript struct {
	// version denotes the AutScriptVersion
	version uint32

	// scriptType denotes the AutScriptType, should be "AutScriptTypeRegistration"
	scriptType AutScriptType

	// autIdentifier stores the AutIdentifier that this AutScript operates.
	// For RegistrationScript, the autIdentifier is ZeroHash, and the corresponding AutMetadata will have
	// autIdentifier to be the TxId of the host-Abelian-Tx.
	autIdentifier AutId

	autName      []byte
	autSymbol    []byte
	baseUnitName []byte
	subUnitName  []byte
	unitScale    uint64
	autMemo      []byte

	plannedTotalSupply         uint64
	issuers                    []*AutIssuer
	reregistrationExpireHeight int32
	reregisterThreshold        uint8
	mintThreshold              uint8
	privacyType                AutPrivacyType

	// the number of output AutRootTokens
	outStartIndex      uint8
	outAutRootTokenNum uint8 // value is set in deserialize, so, do not provide set function, but provide get function.

	scriptMemo []byte
}

// NewRegistrationScript creates a new RegistrationScript.
//
// Note that RegistrationScript's autIdentifier is zeroHash, and does not need a corresponding input.
func NewRegistrationScript(version uint32,
	autName []byte, autSymbol []byte, baseUnitName []byte, subUnitName []byte, unitScale uint64,
	autMemo []byte, plannedTotalSupply uint64,
	issuers []*AutIssuer, reregistrationExpireHeight int32, reregisterThreshold uint8, mintThreshold uint8,
	privacyType AutPrivacyType,
	outStarIndex uint8, outAutRootTokenNum uint8,
	scriptMemo []byte) *RegistrationScript {

	return &RegistrationScript{
		version:                    version,
		scriptType:                 AutScriptTypeRegistration,
		autIdentifier:              ZeroHash,
		autName:                    autName,
		autSymbol:                  autSymbol,
		baseUnitName:               baseUnitName,
		subUnitName:                subUnitName,
		unitScale:                  unitScale,
		autMemo:                    autMemo,
		plannedTotalSupply:         plannedTotalSupply,
		issuers:                    issuers,
		reregistrationExpireHeight: reregistrationExpireHeight,
		reregisterThreshold:        reregisterThreshold,
		mintThreshold:              mintThreshold,
		privacyType:                privacyType,
		outStartIndex:              outStarIndex,
		outAutRootTokenNum:         outAutRootTokenNum,
		scriptMemo:                 scriptMemo,
	}
}

func (autScript *RegistrationScript) Version() uint32 {
	return autScript.version
}
func (autScript *RegistrationScript) Type() AutScriptType {
	return autScript.scriptType
}
func (autScript *RegistrationScript) AutIdentifier() AutId {
	return autScript.autIdentifier
}

func (autScript *RegistrationScript) AutName() []byte {
	return autScript.autName
}

func (autScript *RegistrationScript) AutSymbol() []byte {
	return autScript.autSymbol
}

func (autScript *RegistrationScript) BaseUnitName() []byte {
	return autScript.baseUnitName
}

func (autScript *RegistrationScript) SubUnitName() []byte {
	return autScript.subUnitName
}

func (autScript *RegistrationScript) UnitScale() uint64 {
	return autScript.unitScale
}

func (autScript *RegistrationScript) AutMemo() []byte {
	return autScript.autMemo
}

func (autScript *RegistrationScript) PlannedTotalSupply() uint64 {
	return autScript.plannedTotalSupply
}

func (autScript *RegistrationScript) Issuers() []*AutIssuer {
	return autScript.issuers
}

func (autScript *RegistrationScript) ReregistrationExpireHeight() int32 {
	return autScript.reregistrationExpireHeight
}

func (autScript *RegistrationScript) ReregisterThreshold() uint8 {
	return autScript.reregisterThreshold
}

func (autScript *RegistrationScript) MintThreshold() uint8 {
	return autScript.mintThreshold
}

func (autScript *RegistrationScript) PrivacyType() AutPrivacyType {
	return autScript.privacyType
}

func (autScript *RegistrationScript) OutStartIndex() uint8 {
	return autScript.outStartIndex
}

func (autScript *RegistrationScript) OutAutRootTokenNum() uint8 {
	return autScript.outAutRootTokenNum
}

func (autScript *RegistrationScript) ScriptMemo() []byte {
	return autScript.scriptMemo
}

func (autScript *RegistrationScript) InStartIndex() uint8 {
	return 0
}

func (autScript *RegistrationScript) WitnessHash() chainhash.Hash {
	return ZeroHash // nonsense
}

func (autScript *RegistrationScript) NumConsumedTokens() int {
	return 0
}

func (autScript *RegistrationScript) NumGeneratedTokens() int {
	return int(autScript.outAutRootTokenNum)
}

func (autScript *RegistrationScript) serializeSize() (int, error) {
	if autScript == nil {
		return 0, fmt.Errorf("autScript is nil")
	}

	n := wire.VarIntSerializeSize(uint64(autScript.version))                                         // version                    uint32
	n += 1                                                                                           // scriptType                 AutScriptType
	n += chainhash.HashSize                                                                          // autIdentifier              AutId
	n += wire.VarIntSerializeSize(uint64(len(autScript.autName))) + len(autScript.autName)           // autName                    []byte
	n += wire.VarIntSerializeSize(uint64(len(autScript.autSymbol))) + len(autScript.autSymbol)       // autSymbol                  []byte
	n += wire.VarIntSerializeSize(uint64(len(autScript.baseUnitName))) + len(autScript.baseUnitName) // baseUnitName               []byte
	n += wire.VarIntSerializeSize(uint64(len(autScript.subUnitName))) + len(autScript.subUnitName)   // subUnitName                []byte
	n += wire.VarIntSerializeSize(autScript.unitScale)                                               // unitScale                  uint64
	n += wire.VarIntSerializeSize(uint64(len(autScript.autMemo))) + len(autScript.autMemo)           // autMemo                    []byte
	n += wire.VarIntSerializeSize(autScript.plannedTotalSupply)                                      // plannedTotalSupply         uint64

	n += wire.VarIntSerializeSize(uint64(len(autScript.issuers))) // issuers                    []*AutIssuer
	for i, issuer := range autScript.issuers {
		if issuer == nil {
			return 0, fmt.Errorf("autScript.issuers[%d] is nil", i)
		}
		n += issuer.SerializeSize()
	}

	n += wire.VarIntSerializeSize(uint64(autScript.reregistrationExpireHeight)) // reregistrationExpireHeight int32

	n += 1 // reregisterThreshold        uint8
	n += 1 // mintThreshold              uint8
	n += 1 // privacyType                AutPrivacyType

	n += 1 // outStartIndex				uint8
	n += 1 // outAutRootTokenNum		uint8

	n += wire.VarIntSerializeSize(uint64(len(autScript.scriptMemo))) + len(autScript.scriptMemo) // scriptMemo                 []byte

	return n, nil
}

func (autScript *RegistrationScript) Serialize() ([]byte, error) {
	if autScript == nil {
		return nil, fmt.Errorf("autScript is nil")
	}

	size, err := autScript.serializeSize()
	if err != nil {
		return nil, err
	}

	w := bytes.NewBuffer(make([]byte, 0, size))

	// version                    uint32
	if err = wire.WriteVarInt(w, 0, uint64(autScript.version)); err != nil {
		return nil, err
	}

	// scriptType                 AutScriptType
	if err = w.WriteByte(uint8(autScript.Type())); err != nil {
		return nil, err
	}

	// autIdentifier              AutId
	if _, err = w.Write(autScript.autIdentifier[:]); err != nil {
		return nil, err
	}

	// autName                    []byte
	if err = wire.WriteVarBytes(w, 0, autScript.autName); err != nil {
		return nil, err
	}

	// autSymbol                  []byte
	if err = wire.WriteVarBytes(w, 0, autScript.autSymbol); err != nil {
		return nil, err
	}

	// baseUnitName               []byte
	if err = wire.WriteVarBytes(w, 0, autScript.baseUnitName); err != nil {
		return nil, err
	}

	// subUnitName                []byte
	if err = wire.WriteVarBytes(w, 0, autScript.subUnitName); err != nil {
		return nil, err
	}

	// unitScale                  uint64
	if err = wire.WriteVarInt(w, 0, autScript.unitScale); err != nil {
		return nil, err
	}

	// autMemo                    []byte
	if err = wire.WriteVarBytes(w, 0, autScript.autMemo); err != nil {
		return nil, err
	}

	// plannedTotalSupply         uint64
	if err = wire.WriteVarInt(w, 0, autScript.plannedTotalSupply); err != nil {
		return nil, err
	}

	// issuers                    []*AutIssuer
	if err = wire.WriteVarInt(w, 0, uint64(len(autScript.issuers))); err != nil {
		return nil, err
	}
	for i, issuer := range autScript.issuers {
		if issuer == nil {
			return nil, fmt.Errorf("autScript.issuers[%d] is nil", i)
		}
		if err = issuer.Write(w); err != nil {
			return nil, err
		}
	}

	// reregistrationExpireHeight int32
	if err = wire.WriteVarInt(w, 0, uint64(autScript.reregistrationExpireHeight)); err != nil {
		return nil, err
	}

	// reregisterThreshold        uint8
	if err = w.WriteByte(autScript.reregisterThreshold); err != nil {
		return nil, err
	}

	// mintThreshold              uint8
	if err = w.WriteByte(autScript.mintThreshold); err != nil {
		return nil, err
	}

	// privacyType                AutPrivacyType
	if err = w.WriteByte(uint8(autScript.privacyType)); err != nil {
		return nil, err
	}

	// outStartIndex         uint8
	if err = w.WriteByte(autScript.outStartIndex); err != nil {
		return nil, err
	}

	// outAutRootTokenNum         uint8
	if err = w.WriteByte(autScript.outAutRootTokenNum); err != nil {
		return nil, err
	}

	// scriptMemo                 []byte
	if err = wire.WriteVarBytes(w, 0, autScript.scriptMemo); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (autScript *RegistrationScript) Deserialize(serializedScript []byte) error {
	if autScript == nil {
		return fmt.Errorf("autScript is nil")
	}

	r := bytes.NewReader(serializedScript)

	// version                    uint32
	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if version > math.MaxUint32 {
		return fmt.Errorf("readed version %d is too large", version)
	}
	autScript.version = uint32(version)

	// scriptType                 AutScriptType
	scriptTypeRead, err := r.ReadByte()
	if err != nil {
		return err
	}
	autScript.scriptType = AutScriptType(scriptTypeRead)

	// autIdentifier              AutId
	if _, err = io.ReadFull(r, autScript.autIdentifier[:]); err != nil {
		return err
	}

	// autName                    []byte
	if autScript.autName, err = wire.ReadVarBytes(r, 0, MaxAutNameLength, "autName"); err != nil {
		return err
	}

	// autSymbol                  []byte
	if autScript.autSymbol, err = wire.ReadVarBytes(r, 0, MaxAutSymbolLength, "autSymbol"); err != nil {
		return err
	}

	// baseUnitName               []byte
	if autScript.baseUnitName, err = wire.ReadVarBytes(r, 0, MaxBaseUnitLength, "baseUnitName"); err != nil {
		return err
	}

	// subUnitName                []byte
	if autScript.subUnitName, err = wire.ReadVarBytes(r, 0, MaxSubUnitLength, "subUnitName"); err != nil {
		return err
	}

	// unitScale                  uint64
	if autScript.unitScale, err = wire.ReadVarInt(r, 0); err != nil {
		return err
	}

	// autMemo                    []byte
	if autScript.autMemo, err = wire.ReadVarBytes(r, 0, MaxAutMemoLength, "autMemo"); err != nil {
		return err
	}

	// plannedTotalSupply         uint64
	if autScript.plannedTotalSupply, err = wire.ReadVarInt(r, 0); err != nil {
		return err
	}

	// issuers                    []*AutIssuer
	issuerNum, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if issuerNum > MaxIssuerNum {
		return fmt.Errorf("read issuer num %d is too large", issuerNum)
	}
	autScript.issuers = make([]*AutIssuer, issuerNum)
	for i := uint64(0); i < issuerNum; i++ {
		issuer := &AutIssuer{}
		if err = issuer.Read(r); err != nil {
			return err
		}
		autScript.issuers[i] = issuer
	}

	// reregistrationExpireHeight int32
	expireHeightRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	tmp := int64(expireHeightRead)
	if tmp < -1 || tmp > math.MaxInt32 {
		return fmt.Errorf("readed expire height %d is not in [-1, %d]", tmp, math.MaxInt32)
	}
	autScript.reregistrationExpireHeight = int32(expireHeightRead)

	// reregisterThreshold        uint8
	if autScript.reregisterThreshold, err = r.ReadByte(); err != nil {
		return err
	}

	// mintThreshold              uint8
	if autScript.mintThreshold, err = r.ReadByte(); err != nil {
		return err
	}

	// privacyType                AutPrivacyType
	privacyTypeRead, err := r.ReadByte()
	if err != nil {
		return err
	}
	autScript.privacyType = AutPrivacyType(privacyTypeRead)

	// outStartIndex         uint8
	if autScript.outStartIndex, err = r.ReadByte(); err != nil {
		return err
	}

	// outAutRootTokenNum         uint8
	if autScript.outAutRootTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// scriptMemo                 []byte
	autScript.scriptMemo, err = wire.ReadVarBytes(r, 0, MaxScriptMemoLength, "scriptMemo")
	if err != nil {
		return err
	}

	return autScript.SanityCheck()
}

func (autScript *RegistrationScript) SanityCheck() error {
	if autScript == nil {
		return fmt.Errorf("autScript is nil")
	}

	// version                    uint32
	if _, ok := ctautwire.AutScriptVersionSet[autScript.version]; !ok {
		return fmt.Errorf("invalid version: %d", autScript.version)
	}

	// scriptType                 AutScriptType
	if autScript.scriptType != AutScriptTypeRegistration {
		return fmt.Errorf("autScript.scriptType (%d) is not AutScriptTypeRegistration", autScript.scriptType)
	}

	// autIdentifier              AutId
	if !bytes.Equal(autScript.autIdentifier[:], ZeroHash[:]) {
		return fmt.Errorf("invalid autIdentifier (%x) for RegistrationScript", autScript.autIdentifier[:])
	}

	// autName                    []byte
	if len(autScript.autName) == 0 {
		return fmt.Errorf("autScript.autName is empty/nil")
	}
	if len(autScript.autName) > MaxAutNameLength {
		return fmt.Errorf("autScript.autName is too long (%d)", len(autScript.autName))
	}

	// autSymbol                  []byte
	if len(autScript.autSymbol) == 0 {
		return fmt.Errorf("autScript.autSymbol is empty/nil")
	}
	if len(autScript.autSymbol) > MaxAutSymbolLength {
		return fmt.Errorf("autScript.autSymbol is too long (%d)", len(autScript.autSymbol))
	}

	// baseUnitName               []byte
	if len(autScript.baseUnitName) == 0 {
		return fmt.Errorf("autScript.baseUnitName is empty/nil")
	}
	if len(autScript.baseUnitName) > MaxBaseUnitLength {
		return fmt.Errorf("autScript.baseUnitName is too long (%d)", len(autScript.baseUnitName))
	}

	// subUnitName                []byte
	if len(autScript.subUnitName) == 0 {
		return fmt.Errorf("autScript.subUnitName is empty/nil")
	}
	if len(autScript.subUnitName) > MaxSubUnitLength {
		return fmt.Errorf("autScript.subUnitName is too long (%d)", len(autScript.subUnitName))
	}

	// unitScale                  uint64
	if autScript.unitScale == 0 || autScript.unitScale > MaxAmount {
		return fmt.Errorf("autScript.unitScale (%d) is not in [1, %d]", autScript.unitScale, MaxAmount)
	}
	if autScript.unitScale > autScript.plannedTotalSupply {
		return fmt.Errorf("autScript.unitScale (%d) exceeds autScript.plannedTotalSupply (%d)",
			autScript.unitScale, autScript.plannedTotalSupply)
	}

	// autMemo                    []byte
	if len(autScript.autMemo) > MaxAutMemoLength {
		return fmt.Errorf("autScript.autMemo length (%d) exceeds MaxAutMemoLength (%d)", len(autScript.autMemo), MaxAutMemoLength)
	}

	// plannedTotalSupply         uint64
	if autScript.plannedTotalSupply == 0 || autScript.plannedTotalSupply > MaxAmount {
		return fmt.Errorf("autScript.plannedTotalSupply (%d) is not in [1, %d]", autScript.plannedTotalSupply, MaxAmount)
	}

	// issuers                    []*AutIssuer
	if len(autScript.issuers) == 0 || len(autScript.issuers) > MaxIssuerNum {
		return fmt.Errorf("the number of issuers (%d) is not in [1, %d]", len(autScript.issuers), MaxIssuerNum)
	}
	issuersMap := make(map[string]int, len(autScript.issuers))
	for i, issuer := range autScript.issuers {
		if issuer == nil {
			return fmt.Errorf("autScript.issuers[%d] is nil", i)
		}
		issuerStr := issuer.String()
		if index, ok := issuersMap[issuerStr]; ok {
			return fmt.Errorf("issuers[%d] and issuers[%d] are repeated : %s", i, index, issuerStr)
		}
		issuersMap[issuerStr] = i
	}

	// reregistrationExpireHeight int32
	if autScript.reregistrationExpireHeight < InfiniteExpireHeight || autScript.reregistrationExpireHeight > math.MaxInt32 {
		return fmt.Errorf("autScript.reregistrationExpireHeight (%d) is not in [-1, %d]",
			autScript.reregistrationExpireHeight, math.MaxInt32)
	}

	// reregisterThreshold        uint8
	if int(autScript.reregisterThreshold) == 0 {
		return fmt.Errorf("autScript.reregisterThreshold (%d) is invalid",
			autScript.reregisterThreshold)
	}
	if int(autScript.reregisterThreshold) > len(autScript.issuers) {
		return fmt.Errorf("autScript.reregisterThreshold (%d) exceeds the number of issuers (%d)",
			autScript.reregisterThreshold, len(autScript.issuers))
	}

	// mintThreshold              uint8
	if int(autScript.mintThreshold) == 0 {
		return fmt.Errorf("autScript.mintThreshold (%d) is invalid",
			autScript.mintThreshold)
	}
	if int(autScript.mintThreshold) > len(autScript.issuers) {
		return fmt.Errorf("autScript.mintThreshold (%d) exceeds the number of issuers (%d)",
			autScript.mintThreshold, len(autScript.issuers))
	}

	// privacyType                AutPrivacyType
	if autScript.privacyType != AutPrivacyTypeUnlimited &&
		autScript.privacyType != AutPrivacyTypeLimitedPublic &&
		autScript.privacyType != AutPrivacyTypeLimitedHidden {
		return fmt.Errorf("autScript.privacyType (%d) is not supported",
			autScript.privacyType)
	}

	// outStartIndex         uint8
	// no checks can conduct here

	// outAutRootTokenNum         uint8
	if int(autScript.outAutRootTokenNum) == 0 {
		return fmt.Errorf("autScript.outAutRootTokenNum (%d) is invalid",
			autScript.outAutRootTokenNum)
	}
	if int(autScript.outAutRootTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.outAutRootTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.outAutRootTokenNum, MaxNumToken)
	}
	if int(autScript.outStartIndex)+int(autScript.outAutRootTokenNum) > math.MaxUint8 {
		// The Index in (TxHash, Index) is designed to be uint8.
		return fmt.Errorf("autScript.outStartIndex (%d) + autScript.outAutRootTokenNum (%d) exceeds %d",
			autScript.outStartIndex, autScript.outAutRootTokenNum, math.MaxUint8)
	}

	// autScriptMemo                 []byte
	if len(autScript.scriptMemo) > MaxScriptMemoLength {
		return fmt.Errorf("len(autScript.scriptMemo) (%d) is too large", len(autScript.scriptMemo))
	}

	return nil
}

var _ AutScript = &RegistrationScript{}

// ReRegistrationScript would be the structured script parsed from memo in host transaction,
// 1. The field values used to update the metadata will be extracted from the scripts with ReRegistrationScript.UpdateAutMetadata()
// 2. consumedTokens would be populated with the help of host transaction and corresponding wire.TxoRing
// 3. generatedTokens would be populated with the function populateGeneratedCTAUTTokens with the help of host transaction
//
// ReRegistrationScript contains
// <Version>
// <ScriptType>
// <autIdentifier>
//
// <autMemo> a byte array with max length, to update that of the AutInstance with <autIdentifier>
// <plannedTotalSupply> an integer range in [1, 1<<51 -1], to update that of the AutInstance with <autIdentifier>
// <issuers> an array with length N AutIssuer, to update that of the AutInstance with <autIdentifier>
// <reregistrationExpireHeight> to update that of the AutInstance with <autIdentifier>
// <reregisterThreshold> An integer update_t in [1, N], to update that of the AutInstance with <autIdentifier>
// <mintThreshold> An integer mint_t in [1, N], to update that of the AutInstance with <autIdentifier>
//
// <inAutRootTokenNum> A number m, explicitly specify the 0~(m-1)-th pseudonym TXO of inputs in host transaction as RootToken
// <outAutRootTokenNum> A number n, Explicitly specify the 0~(n-1)-th pseudonym TXO of outputs in host transaction as RootToken
//
// <ScriptMemo> a byte array with max length
type ReRegistrationScript struct {

	// version denotes the AutScriptVersion
	version uint32

	// scriptType denotes the AutScriptType, should be "AutScriptTypeReRegistration"
	scriptType AutScriptType

	// autIdentifier stores the AutIdentifier that this AutScript operates.
	// For ReRegistrationScript, the autIdentifier points to an existing AutMetadata.
	autIdentifier AutId

	// these fields of an AutInstance (stored in AutMetadata) cannot be change.
	//autName      []byte
	//autSymbol    []byte
	//baseUnitName []byte
	//subUnitName  []byte
	//unitScale    uint64

	autMemo []byte

	plannedTotalSupply         uint64
	issuers                    []*AutIssuer
	reregistrationExpireHeight int32
	reregisterThreshold        uint8
	mintThreshold              uint8
	privacyType                AutPrivacyType

	// inAutRootTokenNum is an additional field that ReRegistrationScript has while RegistrationScript doesn't.
	inStartIndex      uint8
	inAutRootTokenNum uint8

	// the number of output AutRootTokens
	outStartIndex      uint8
	outAutRootTokenNum uint8 // value is set in deserialize, so, do not provide set function, but provide get function.

	scriptMemo []byte
}

func NewReRegistrationScript(version uint32,
	autIdentifier AutId,
	autMemo []byte, plannedTotalSupply uint64,
	issuers []*AutIssuer, reregistrationExpireHeight int32, reregisterThreshold uint8, mintThreshold uint8,
	privacyType AutPrivacyType,
	inStartIndex uint8, inAutRootTokenNum uint8,
	outStartIndex uint8, outAutRootTokenNum uint8,
	scriptMemo []byte) *ReRegistrationScript {

	return &ReRegistrationScript{
		version:                    version,
		scriptType:                 AutScriptTypeReRegistration,
		autIdentifier:              autIdentifier,
		autMemo:                    autMemo,
		plannedTotalSupply:         plannedTotalSupply,
		issuers:                    issuers,
		reregistrationExpireHeight: reregistrationExpireHeight,
		reregisterThreshold:        reregisterThreshold,
		mintThreshold:              mintThreshold,
		privacyType:                privacyType,
		inStartIndex:               inStartIndex,
		inAutRootTokenNum:          inAutRootTokenNum,
		outStartIndex:              outStartIndex,
		outAutRootTokenNum:         outAutRootTokenNum,
		scriptMemo:                 scriptMemo,
	}
}

func (autScript *ReRegistrationScript) Version() uint32 {
	return autScript.version
}
func (autScript *ReRegistrationScript) Type() AutScriptType {
	return autScript.scriptType
}
func (autScript *ReRegistrationScript) AutIdentifier() AutId {
	return autScript.autIdentifier
}

func (autScript *ReRegistrationScript) AutMemo() []byte {
	return autScript.autMemo
}

func (autScript *ReRegistrationScript) PlannedTotalSupply() uint64 {
	return autScript.plannedTotalSupply
}

func (autScript *ReRegistrationScript) Issuers() []*AutIssuer {
	return autScript.issuers
}

func (autScript *ReRegistrationScript) ReregistrationExpireHeight() int32 {
	return autScript.reregistrationExpireHeight
}

func (autScript *ReRegistrationScript) ReregisterThreshold() uint8 {
	return autScript.reregisterThreshold
}

func (autScript *ReRegistrationScript) MintThreshold() uint8 {
	return autScript.mintThreshold
}

func (autScript *ReRegistrationScript) PrivacyType() AutPrivacyType {
	return autScript.privacyType
}

func (autScript *ReRegistrationScript) InStartIndex() uint8 {
	return autScript.inStartIndex
}

func (autScript *ReRegistrationScript) InAutRootTokenNum() uint8 {
	return autScript.inAutRootTokenNum
}

func (autScript *ReRegistrationScript) OutStartIndex() uint8 {
	return autScript.outStartIndex
}

func (autScript *ReRegistrationScript) OutAutRootTokenNum() uint8 {
	return autScript.outAutRootTokenNum
}

func (autScript *ReRegistrationScript) ScriptMemo() []byte {
	return autScript.scriptMemo
}

func (autScript *ReRegistrationScript) WitnessHash() chainhash.Hash {
	return ZeroHash // non sense
}

func (autScript *ReRegistrationScript) NumConsumedTokens() int {
	return int(autScript.inAutRootTokenNum)
}

func (autScript *ReRegistrationScript) NumGeneratedTokens() int {
	return int(autScript.outAutRootTokenNum)
}

func (autScript *ReRegistrationScript) serializeSize() (int, error) {
	if autScript == nil {
		return 0, fmt.Errorf("autScript is nil")
	}

	n := wire.VarIntSerializeSize(uint64(autScript.version))                               // version                    uint32
	n += 1                                                                                 // scriptType                 AutScriptType
	n += chainhash.HashSize                                                                // autIdentifier              AutId
	n += wire.VarIntSerializeSize(uint64(len(autScript.autMemo))) + len(autScript.autMemo) // autMemo                    []byte
	n += wire.VarIntSerializeSize(autScript.plannedTotalSupply)                            // plannedTotalSupply         uint64

	n += wire.VarIntSerializeSize(uint64(len(autScript.issuers))) // issuers                    []*AutIssuer
	for i, issuer := range autScript.issuers {
		if issuer == nil {
			return 0, fmt.Errorf("autScript.issuers[%d] is nil", i)
		}
		n += issuer.SerializeSize()
	}

	n += wire.VarIntSerializeSize(uint64(autScript.reregistrationExpireHeight)) // reregistrationExpireHeight int32

	n += 1 // reregisterThreshold        uint8
	n += 1 // mintThreshold              uint8
	n += 1 // privacyType                AutPrivacyType

	n += 1 // inStartIndex               uint8
	n += 1 // inAutRootTokenNum          uint8

	n += 1 // outStartIndex              uint8
	n += 1 // outAutRootTokenNum         uint8

	n += wire.VarIntSerializeSize(uint64(len(autScript.scriptMemo))) + len(autScript.scriptMemo) // scriptMemo                 []byte

	return n, nil
}

func (autScript *ReRegistrationScript) Serialize() ([]byte, error) {
	if autScript == nil {
		return nil, fmt.Errorf("autScript is nil")
	}

	size, err := autScript.serializeSize()
	w := bytes.NewBuffer(make([]byte, 0, size))

	// version                    uint32
	if err = wire.WriteVarInt(w, 0, uint64(autScript.version)); err != nil {
		return nil, err
	}

	// scriptType                 AutScriptType
	if err = w.WriteByte(uint8(autScript.Type())); err != nil {
		return nil, err
	}

	// autIdentifier              AutId
	if _, err = w.Write(autScript.autIdentifier[:]); err != nil {
		return nil, err
	}

	// autMemo                    []byte
	if err = wire.WriteVarBytes(w, 0, autScript.autMemo); err != nil {
		return nil, err
	}

	// plannedTotalSupply         uint64
	if err = wire.WriteVarInt(w, 0, autScript.plannedTotalSupply); err != nil {
		return nil, err
	}

	// issuers                    []*AutIssuer
	if err = wire.WriteVarInt(w, 0, uint64(len(autScript.issuers))); err != nil {
		return nil, err
	}
	for i, issuer := range autScript.issuers {
		if issuer == nil {
			return nil, fmt.Errorf("autScript.issuers[%d] is nil", i)
		}
		if err = issuer.Write(w); err != nil {
			return nil, err
		}
	}

	// reregistrationExpireHeight int32
	if err = wire.WriteVarInt(w, 0, uint64(autScript.reregistrationExpireHeight)); err != nil {
		return nil, err
	}

	// reregisterThreshold        uint8
	if err = w.WriteByte(autScript.reregisterThreshold); err != nil {
		return nil, err
	}

	// mintThreshold              uint8
	if err = w.WriteByte(autScript.mintThreshold); err != nil {
		return nil, err
	}

	// privacyType                AutPrivacyType
	if err = w.WriteByte(uint8(autScript.privacyType)); err != nil {
		return nil, err
	}

	// inStartIndex         uint8
	if err = w.WriteByte(autScript.inStartIndex); err != nil {
		return nil, err
	}

	// inAutRootTokenNum         uint8
	if err = w.WriteByte(autScript.inAutRootTokenNum); err != nil {
		return nil, err
	}

	// outStartIndex         uint8
	if err = w.WriteByte(autScript.outStartIndex); err != nil {
		return nil, err
	}

	// outAutRootTokenNum         uint8
	if err = w.WriteByte(autScript.outAutRootTokenNum); err != nil {
		return nil, err
	}

	// scriptMemo                 []byte
	if err = wire.WriteVarBytes(w, 0, autScript.scriptMemo); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (autScript *ReRegistrationScript) Deserialize(serializedScript []byte) error {

	if autScript == nil {
		return fmt.Errorf("autScript is nil")
	}

	r := bytes.NewReader(serializedScript)

	// version                    uint32
	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if version > math.MaxUint32 {
		return fmt.Errorf("readed version %d is too large", version)
	}
	autScript.version = uint32(version)

	// scriptType                 AutScriptType
	scriptTypeRead, err := r.ReadByte()
	if err != nil {
		return err
	}
	autScript.scriptType = AutScriptType(scriptTypeRead)

	// autIdentifier              AutId
	if _, err = io.ReadFull(r, autScript.autIdentifier[:]); err != nil {
		return err
	}

	// autMemo                    []byte
	if autScript.autMemo, err = wire.ReadVarBytes(r, 0, MaxAutMemoLength, "autMemo"); err != nil {
		return err
	}

	// plannedTotalSupply         uint64
	if autScript.plannedTotalSupply, err = wire.ReadVarInt(r, 0); err != nil {
		return err
	}

	// issuers                    []*AutIssuer
	issuerNum, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if issuerNum > MaxIssuerNum {
		return fmt.Errorf("read issuer num %d is too large", issuerNum)
	}
	autScript.issuers = make([]*AutIssuer, issuerNum)
	for i := uint64(0); i < issuerNum; i++ {
		issuer := &AutIssuer{}
		if err = issuer.Read(r); err != nil {
			return err
		}
		autScript.issuers[i] = issuer
	}

	// reregistrationExpireHeight int32
	expireHeightRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	tmp := int64(expireHeightRead)
	if tmp < -1 || tmp > math.MaxInt32 {
		return fmt.Errorf("read expire height %d is not in [-1, %d]", tmp, math.MaxInt32)
	}
	autScript.reregistrationExpireHeight = int32(expireHeightRead)

	// reregisterThreshold        uint8
	if autScript.reregisterThreshold, err = r.ReadByte(); err != nil {
		return err
	}

	// mintThreshold              uint8
	if autScript.mintThreshold, err = r.ReadByte(); err != nil {
		return err
	}

	// privacyType                AutPrivacyType
	privacyTypeRead, err := r.ReadByte()
	if err != nil {
		return err
	}
	autScript.privacyType = AutPrivacyType(privacyTypeRead)

	// inStartIndex               uint8
	if autScript.inStartIndex, err = r.ReadByte(); err != nil {
		return err
	}

	// inAutRootTokenNum         uint8
	if autScript.inAutRootTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// outStartIndex         uint8
	if autScript.outStartIndex, err = r.ReadByte(); err != nil {
		return err
	}

	// outAutRootTokenNum         uint8
	if autScript.outAutRootTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// scriptMemo                 []byte
	if autScript.scriptMemo, err = wire.ReadVarBytes(r, 0, MaxScriptMemoLength, "scriptMemo"); err != nil {
		return err
	}

	return autScript.SanityCheck()
}

func (autScript *ReRegistrationScript) SanityCheck() error {
	if autScript == nil {
		return fmt.Errorf("autScript is nil")
	}

	// version                    uint32
	if _, ok := ctautwire.AutScriptVersionSet[autScript.version]; !ok {
		return fmt.Errorf("invalid version: %d", autScript.version)
	}

	// scriptType                 AutScriptType
	if autScript.scriptType != AutScriptTypeReRegistration {
		return fmt.Errorf("autScript.scriptType (%d) is not AutScriptTypeReRegistration", autScript.scriptType)
	}

	// autIdentifier              AutId

	// autMemo                    []byte
	if len(autScript.autMemo) > MaxAutMemoLength {
		return fmt.Errorf("autScript.autMemo length (%d) exceeds MaxAutMemoLength (%d)", len(autScript.autMemo), MaxAutMemoLength)
	}

	// plannedTotalSupply         uint64
	if autScript.plannedTotalSupply == 0 || autScript.plannedTotalSupply > MaxAmount {
		return fmt.Errorf("script.plannedTotalSupply (%d) is not in [1, %d]", autScript.plannedTotalSupply, MaxAmount)
	}

	// issuers                    []*AutIssuer
	if len(autScript.issuers) == 0 || len(autScript.issuers) > MaxIssuerNum {
		return fmt.Errorf("the number of issuers (%d) is not in [1, %d]", len(autScript.issuers), MaxIssuerNum)
	}
	issuersMap := make(map[string]int, len(autScript.issuers))
	for i, issuer := range autScript.issuers {
		if issuer == nil {
			return fmt.Errorf("autScript.issuers[%d] is nil", i)
		}

		issuerStr := issuer.String()
		if index, ok := issuersMap[issuerStr]; ok {
			return fmt.Errorf("issuers[%d] and issuers[%d] are repeated : %s", i, index, issuerStr)
		}
		issuersMap[issuerStr] = i
	}

	// reregistrationExpireHeight int32
	if autScript.reregistrationExpireHeight < InfiniteExpireHeight || autScript.reregistrationExpireHeight > math.MaxInt32 {
		return fmt.Errorf("autScript.reregistrationExpireHeight (%d) is not in [-1, %d]",
			autScript.reregistrationExpireHeight, math.MaxInt32)
	}

	// reregisterThreshold        uint8
	if int(autScript.reregisterThreshold) == 0 {
		return fmt.Errorf("autScript.reregisterThreshold (%d) is invalid",
			autScript.reregisterThreshold)
	}
	if int(autScript.reregisterThreshold) > len(autScript.issuers) {
		return fmt.Errorf("autScript.reregisterThreshold (%d) exceeds the number of issuers (%d)",
			autScript.reregisterThreshold, len(autScript.issuers))
	}

	// mintThreshold              uint8
	if int(autScript.mintThreshold) == 0 {
		return fmt.Errorf("autScript.mintThreshold (%d) is invalid",
			autScript.mintThreshold)
	}
	if int(autScript.mintThreshold) > len(autScript.issuers) {
		return fmt.Errorf("autScript.mintThreshold (%d) exceeds the number of issuers (%d)",
			autScript.mintThreshold, len(autScript.issuers))
	}

	// privacyType                AutPrivacyType
	if autScript.privacyType != AutPrivacyTypeUnlimited &&
		autScript.privacyType != AutPrivacyTypeLimitedPublic &&
		autScript.privacyType != AutPrivacyTypeLimitedHidden {
		return fmt.Errorf("autScript.privacyType (%d) is not supported",
			autScript.privacyType)
	}

	// inStartIndex         uint8

	// inAutRootTokenNum         uint8
	if int(autScript.inAutRootTokenNum) == 0 {
		return fmt.Errorf("autScript.inAutRootTokenNum (%d) is invalid",
			autScript.inAutRootTokenNum)
	}
	if int(autScript.inAutRootTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.inAutRootTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.inAutRootTokenNum, MaxNumToken)
	}
	if int(autScript.inStartIndex)+int(autScript.inAutRootTokenNum) > math.MaxUint8 {
		// The number of TxIns is designed to be at most uint8.
		return fmt.Errorf("autScript.inStartIndex (%d) + autScript.inAutRootTokenNum (%d) exceeds %d",
			autScript.inStartIndex, autScript.inAutRootTokenNum, math.MaxUint8)
	}

	// outStartIndex         uint8

	// outAutRootTokenNum         uint8
	if int(autScript.outAutRootTokenNum) == 0 {
		return fmt.Errorf("autScript.outAutRootTokenNum (%d) is invalid",
			autScript.outAutRootTokenNum)
	}
	if int(autScript.outAutRootTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.outAutRootTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.outAutRootTokenNum, MaxNumToken)
	}
	if int(autScript.outStartIndex)+int(autScript.outAutRootTokenNum) > math.MaxUint8 {
		// The Index in (TxHash, Index) is designed to be uint8.
		return fmt.Errorf("autScript.outStartIndex (%d) + autScript.outAutRootTokenNum (%d) exceeds %d",
			autScript.outStartIndex, autScript.outAutRootTokenNum, math.MaxUint8)
	}

	// scriptMemo                 []byte
	if len(autScript.scriptMemo) > MaxScriptMemoLength {
		return fmt.Errorf("len(script.scriptMemo) (%d) is too large", len(autScript.scriptMemo))
	}

	return nil
}

var _ AutScript = &ReRegistrationScript{}

// MintScript would be the structured script parsed from memo in host transaction,
// 1. the minted amount with such a script MUST be explicit specified
// 2. the number of generated Hidden-Token and Plain-Token MUST be explicitly specified, as well as corresponding serializedAutTxos
// 3. the number of consumed RootTokens MUST be explicitly specified,
// 4. the witnessHash MUST be given, which is computed from AutWitness at host-transaction layer,
// 5. the generatedTokens would be populated with the function populateGeneratedCTAUTTokens with the help of host transaction
// 6. the consumedTokens would be populated with the help of host transaction and corresponding wire.TxoRing.
//
// MintScript consists of
// <version>
// <scriptType>
// <autIdentifier>
// <vin> an integer, representing the amount of tokens to be minted, must less than plannedTotalSupply
// <inAutRootTokenNum> A number n, explicitly specify the 0~(n-1)-th pseudonym TxIn of host-transaction as consumed RootToken
// <outHiddenAutTokenNum> A number i, Explicitly specify the 0~(i-1)-th pseudonym Txo of host-transaction as the host-points of Hidden-Tokens
// <outPublicAutTokenNum> A number j, Explicitly specify the i~(i+j-1)-th pseudonym Txo of in host-transaction as host-points of Public-Tokens
// <serializedAutTxos> an array of i+j byte array, corresponding to the outAutTokens
// <witnessHash> a Hash of the witness for balance proof between vin and outAutTokens
// <scriptMemo> a byte array with max length, for this script
type MintScript struct {
	// version denotes the AutScriptVersion
	version uint32

	// scriptType denotes the AutScriptType, should be "AutScriptTypeMint"
	scriptType AutScriptType

	// autIdentifier stores the AutIdentifier that this AutScript operates.
	// For MintScript, the autIdentifier points to an existing AutMetadata.
	autIdentifier AutId

	// vin specifies the value to mint.
	vin uint64

	// inAutRootTokenNum specifies the number of consumed AutRootTokens by the host-Tx.
	// It is used to locate the start and end TxIn of the host-Tx, which should be parsed as AutRootToken.
	// The RULE is the FIRST inAutRootTokenNum pseudonym TxIn of the host-Tx should be AutRootToken.
	// When generating the script, inAutRootTokenNum must be set correctly.
	inStartIndex      uint8
	inAutRootTokenNum uint8

	// outHiddenAutTokenNum and outPublicAutTokenNum together specify the number of generated AutTokens by the host-Tx.
	// They are used to locate the start and end Txo of the host-Tx, which should be parsed as AutTokens.
	// The RULE is (a) the FIRST outHiddenAutTokenNum pseudonym Txo of the host-Tx should be HiddenAutTxo,
	// and then (b) the following outPublicAutTokenNum pseudonym Txo of the host-Tx should be publicAutTxo.
	outStartIndex        uint8
	outHiddenAutTokenNum uint8
	outPublicAutTokenNum uint8
	serializedAutTxos    [][]byte // length = outHiddenAutTokenNum + outPublicAutTokenNum

	witnessHash chainhash.Hash

	scriptMemo []byte
}

func NewMintScript(version uint32,
	autIdentifier AutId,
	vin uint64,
	inStartIndex uint8, inAutRootTokenNum uint8,
	outStartIndex uint8, outHiddenAutTokenNum uint8, outPublicAutTokenNum uint8,
	serializedAutTxos [][]byte,
	scriptMemo []byte,
	witnessHash chainhash.Hash) *MintScript {

	return &MintScript{
		version:              version,
		scriptType:           AutScriptTypeMint,
		autIdentifier:        autIdentifier,
		vin:                  vin,
		inStartIndex:         inStartIndex,
		inAutRootTokenNum:    inAutRootTokenNum,
		outStartIndex:        outStartIndex,
		outHiddenAutTokenNum: outHiddenAutTokenNum,
		outPublicAutTokenNum: outPublicAutTokenNum,
		serializedAutTxos:    serializedAutTxos,
		scriptMemo:           scriptMemo,
		witnessHash:          witnessHash,
	}
}

func (autScript *MintScript) Version() uint32 {
	return autScript.version
}

func (autScript *MintScript) Type() AutScriptType {
	return autScript.scriptType
}

func (autScript *MintScript) AutIdentifier() AutId {
	return autScript.autIdentifier
}

func (autScript *MintScript) Vin() uint64 {
	return autScript.vin
}

func (autScript *MintScript) InStartIndex() uint8 {
	return autScript.inStartIndex
}

func (autScript *MintScript) InAutRootTokenNum() uint8 {
	return autScript.inAutRootTokenNum
}

func (autScript *MintScript) OutStartIndex() uint8 {
	return autScript.outStartIndex
}

func (autScript *MintScript) OutHiddenAutTokenNum() uint8 {
	return autScript.outHiddenAutTokenNum
}

func (autScript *MintScript) OutPublicAutTokenNum() uint8 {
	return autScript.outPublicAutTokenNum
}

func (autScript *MintScript) SerializedAutTxos() [][]byte {
	return autScript.serializedAutTxos
}

func (autScript *MintScript) ScriptMemo() []byte {
	return autScript.scriptMemo
}

func (autScript *MintScript) WitnessHash() chainhash.Hash {
	return autScript.witnessHash
}

func (autScript *MintScript) NumConsumedTokens() int {
	return int(autScript.inAutRootTokenNum)
}

func (autScript *MintScript) NumGeneratedTokens() int {
	return int(autScript.outHiddenAutTokenNum) + int(autScript.outPublicAutTokenNum)
}

func (autScript *MintScript) serializeSize() int {
	n := wire.VarIntSerializeSize(uint64(autScript.version)) // version                    uint32
	n += 1                                                   // scriptType                 AutScriptType
	n += chainhash.HashSize                                  // autIdentifier              AutId

	n += wire.VarIntSerializeSize(autScript.vin) // vin                  uint64
	n += 1                                       // inStartIndex    uint8
	n += 1                                       // inAutRootTokenNum    uint8
	n += 1                                       // outStartIndex uint8
	n += 1                                       // outHiddenAutTokenNum uint8
	n += 1                                       // outPublicAutTokenNum uint8

	n += wire.VarIntSerializeSize(uint64(len(autScript.serializedAutTxos))) // serializedAutTxos    [][]byte
	for _, serializedAutTxo := range autScript.serializedAutTxos {
		n += wire.VarIntSerializeSize(uint64(len(serializedAutTxo))) + len(serializedAutTxo)
	}

	n += wire.VarIntSerializeSize(uint64(len(autScript.scriptMemo))) + len(autScript.scriptMemo) // scriptMemo                 []byte

	n += chainhash.HashSize // witnessHash          chainhash.Hash

	return n
}

func (autScript *MintScript) Serialize() ([]byte, error) {
	if autScript == nil {
		return nil, fmt.Errorf("autScript is nil")
	}

	var err error

	w := bytes.NewBuffer(make([]byte, 0, autScript.serializeSize()))

	// version                    uint32
	if err = wire.WriteVarInt(w, 0, uint64(autScript.version)); err != nil {
		return nil, err
	}

	// scriptType                 AutScriptType
	if err = w.WriteByte(uint8(autScript.Type())); err != nil {
		return nil, err
	}

	// autIdentifier              AutId
	if _, err = w.Write(autScript.autIdentifier[:]); err != nil {
		return nil, err
	}

	// vin                  uint64
	if err = wire.WriteVarInt(w, 0, autScript.vin); err != nil {
		return nil, err
	}

	// inStartIndex    uint8
	if err = w.WriteByte(autScript.inStartIndex); err != nil {
		return nil, err
	}

	// inAutRootTokenNum    uint8
	if err = w.WriteByte(autScript.inAutRootTokenNum); err != nil {
		return nil, err
	}

	// outStartIndex    uint8
	if err = w.WriteByte(autScript.outStartIndex); err != nil {
		return nil, err
	}

	// outHiddenAutTokenNum uint8
	if err = w.WriteByte(autScript.outHiddenAutTokenNum); err != nil {
		return nil, err
	}

	// outPublicAutTokenNum uint8
	if err = w.WriteByte(autScript.outPublicAutTokenNum); err != nil {
		return nil, err
	}

	// serializedAutTxos    [][]byte
	if err = wire.WriteVarInt(w, 0, uint64(len(autScript.serializedAutTxos))); err != nil {
		return nil, err
	}
	for _, serializedAutTxo := range autScript.serializedAutTxos {
		if err = wire.WriteVarBytes(w, 0, serializedAutTxo); err != nil {
			return nil, err
		}
	}

	// scriptMemo                 []byte
	if err = wire.WriteVarBytes(w, 0, autScript.scriptMemo); err != nil {
		return nil, err
	}

	// witnessHash          chainhash.Hash
	if _, err = w.Write(autScript.witnessHash[:]); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (autScript *MintScript) Deserialize(serializedScript []byte) error {
	if autScript == nil {
		return fmt.Errorf("autScript is nil")
	}

	var err error

	r := bytes.NewReader(serializedScript)

	// version                    uint32
	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if version > math.MaxUint32 {
		return fmt.Errorf("read version %d is too large", version)
	}
	autScript.version = uint32(version)

	// scriptType                 AutScriptType
	scriptTypeRead, err := r.ReadByte()
	if err != nil {
		return err
	}
	autScript.scriptType = AutScriptType(scriptTypeRead)

	// autIdentifier              AutId
	if _, err = io.ReadFull(r, autScript.autIdentifier[:]); err != nil {
		return err
	}

	// vin                  uint64
	if autScript.vin, err = wire.ReadVarInt(r, 0); err != nil {
		return err
	}

	// inStartIndex    uint8
	if autScript.inStartIndex, err = r.ReadByte(); err != nil {
		return err
	}

	// inAutRootTokenNum    uint8
	if autScript.inAutRootTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// outStartIndex    uint8
	if autScript.outStartIndex, err = r.ReadByte(); err != nil {
		return err
	}

	// outHiddenAutTokenNum    uint8
	if autScript.outHiddenAutTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// outPublicAutTokenNum    uint8
	if autScript.outPublicAutTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// serializedAutTxos    [][]byte
	autTxoNum, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if autTxoNum > MaxNumToken {
		return fmt.Errorf("read AutTxo num %d is too large", autTxoNum)
	}
	autScript.serializedAutTxos = make([][]byte, autTxoNum)
	for i := uint64(0); i < autTxoNum; i++ {
		if autScript.serializedAutTxos[i], err = wire.ReadVarBytes(r, 0, MaxAutTxoLength, "SerializedAutTxo"); err != nil {
			return err
		}
	}

	// scriptMemo                 []byte
	if autScript.scriptMemo, err = wire.ReadVarBytes(r, 0, MaxScriptMemoLength, "scriptMemo"); err != nil {
		return err
	}

	// witnessHash          chainhash.Hash
	if _, err = io.ReadFull(r, autScript.witnessHash[:]); err != nil {
		return err
	}

	return autScript.SanityCheck()
}

func (autScript *MintScript) SanityCheck() error {
	if autScript == nil {
		return fmt.Errorf("autScript is nil")
	}

	// version                    uint32
	if _, ok := ctautwire.AutScriptVersionSet[autScript.version]; !ok {
		return fmt.Errorf("invalid version: %d", autScript.version)
	}

	// scriptType                 AutScriptType
	if autScript.scriptType != AutScriptTypeMint {
		return fmt.Errorf("autScript.scriptType (%d) is not AutScriptTypeMint", autScript.scriptType)
	}

	// autIdentifier              AutId

	// vin                  uint64
	if autScript.vin == 0 || autScript.vin > MaxAmount {
		return fmt.Errorf("autScript.vin (%d) is not in [1, %d]", autScript.vin, MaxAmount)
	}

	// inStartIndex    uint8

	// inAutRootTokenNum    uint8
	if int(autScript.inAutRootTokenNum) == 0 {
		return fmt.Errorf("autScript.inAutRootTokenNum (%d) is invalid",
			autScript.inAutRootTokenNum)
	}
	if int(autScript.inAutRootTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.inAutRootTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.inAutRootTokenNum, MaxNumToken)
	}
	if int(autScript.inStartIndex)+int(autScript.inAutRootTokenNum) > math.MaxUint8 {
		// The number of TxIns is designed to be at most uint8.
		return fmt.Errorf("autScript.inStartIndex (%d) + autScript.inAutRootTokenNum (%d) exceeds %d",
			autScript.inStartIndex, autScript.inAutRootTokenNum, math.MaxUint8)
	}
	// outStartIndex    uint8

	// outHiddenAutTokenNum uint8
	if int(autScript.outHiddenAutTokenNum) > MaxNumHiddenToken {
		return fmt.Errorf("autScript.outHiddenAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.outHiddenAutTokenNum, MaxNumHiddenToken)
	}

	// outPublicAutTokenNum uint8
	if int(autScript.outPublicAutTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.outPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.outPublicAutTokenNum, MaxNumToken)
	}

	if int(autScript.outHiddenAutTokenNum)+int(autScript.outPublicAutTokenNum) == 0 {
		return fmt.Errorf("autScript.outHiddenAutTokenNum (%d) + autScript.outPublicAutTokenNum (%d) is 0",
			autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum)
	}

	if int(autScript.outHiddenAutTokenNum)+int(autScript.outPublicAutTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.outHiddenAutTokenNum (%d) + autScript.outPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum, MaxNumToken)
	}
	if int(autScript.outStartIndex)+int(autScript.outHiddenAutTokenNum)+int(autScript.outPublicAutTokenNum) > math.MaxUint8 {
		// The Index in (TxHash, Index) is designed to be uint8.
		return fmt.Errorf("autScript.outStartIndex (%d) + autScript.outHiddenAutTokenNum (%d) + autScript.outPublicAutTokenNum (%d) exceeds %d",
			autScript.outStartIndex, autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum, math.MaxUint8)
	}

	// serializedAutTxos    [][]byte
	if len(autScript.serializedAutTxos) != int(autScript.outHiddenAutTokenNum)+int(autScript.outPublicAutTokenNum) {
		return fmt.Errorf("the number of serializedAutTxos (%d) does equal script.outHiddenAutTokenNum (%d) + script.outPublicAutTokenNum (%d)",
			len(autScript.serializedAutTxos), autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum)
	}
	for i := 0; i < len(autScript.serializedAutTxos); i++ {
		autTxo := &ctautwire.AutTxo{}
		err := autTxo.Deserialize(autScript.serializedAutTxos[i])
		if err != nil {
			return err
		}
		if autTxo.Version != autScript.version {
			return fmt.Errorf("version mismatch (autTxo.Version %d != autScript.version %d)", autTxo.Version, autScript.version)
		}

		autTxoType, err := abecryptox.GetAutTxoType(autTxo)
		if err != nil {
			return err
		}
		if i < int(autScript.outHiddenAutTokenNum) {
			if autTxoType != abecryptox.AutTxoTypeHidden {
				return fmt.Errorf("autScript.outHiddenAutTokenNum = %d, but %d -th AutTxo has type %d (not AutTxoTypeHidden)",
					autScript.outHiddenAutTokenNum, autTxoType, abecryptox.AutTxoTypeHidden)
			}
		} else {
			if autTxoType != abecryptox.AutTxoTypePublic {
				return fmt.Errorf("autScript.outHiddenAutTokenNum = %d, autScript.outPublicAutTokenNum =%d, but %d -th AutTxo has type %d (not AutTxoTypePublic)",
					autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum, autTxoType, abecryptox.AutTxoTypePublic)
			}

			autTxoValue, err := abecryptox.ExtractAutTxoValue(autTxo, nil, nil)
			if err != nil {
				return err
			}
			if autTxoValue == 0 {
				return fmt.Errorf("autScript.outHiddenAutTokenNum = %d, autScript.outPublicAutTokenNum =%d, but %d -th AutTxo has value 0",
					autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum, i)
			}
		}
	}

	// scriptMemo                 []byte
	if len(autScript.scriptMemo) > MaxScriptMemoLength {
		return fmt.Errorf("len(autScript.scriptMemo) (%d) is too large", len(autScript.scriptMemo))
	}

	// witnessHash          chainhash.Hash

	return nil
}

var _ AutScript = &MintScript{}

// TransferScript would be the structured script parsed from memo in host transaction,
// 1. the number of generated Hidden-Tokens and Public-Tokens MUST be explicitly specified, as well as corresponding serializedAutTxos
// 3. the number of consumed Hidden-Tokens and Public-Tokens MUST be explicitly specified,
// 4. the witnessHash MUST be given, which is computed from AutWitness at host-transaction layer,
// 5. the generatedTokens would be populated with the function populateGeneratedCTAUTTokens with the help of host transaction
// 6. the consumedTokens would be populated with the help of host transaction and corresponding wire.TxoRing.
//
// TransferScript consists of
// <version>
// <scriptType>
// <autIdentifier>
// <inHiddenAutTokenNum> A number n, explicitly specify the 0~(n-1)-th pseudonym TxIn of host-transaction as consumed Hidden-Tokens
// <inPublicAutTokenNum> A number m, explicitly specify the m~(n+m-1)-th pseudonym TxIn of host-transaction as consumed Public-Tokens
// <outHiddenAutTokenNum> A number i, Explicitly specify the 0~(i-1)-th pseudonym Txo of host-transaction as the host-points of Hidden-Tokens
// <outPublicAutTokenNum> A number j, Explicitly specify the i~(i+j-1)-th pseudonym Txo of in host-transaction as host-points of Public-Tokens
// <serializedAutTxos> an array of i+j byte array, corresponding to the outAutTokens
// <witnessHash> a Hash of the witness for balance proof between inAutTokens and outAutTokens
// <scriptMemo> a byte array with max length, for this script
type TransferScript struct {
	version       uint32
	scriptType    AutScriptType
	autIdentifier AutId

	inStartIndex        uint8
	inHiddenAutTokenNum uint8
	inPublicAutTokenNum uint8

	outStartIndex        uint8
	outHiddenAutTokenNum uint8
	outPublicAutTokenNum uint8
	serializedAutTxos    [][]byte

	scriptMemo []byte

	witnessHash chainhash.Hash
}

func NewTransferScript(version uint32,
	autIdentifier AutId,
	inStartIndex uint8, inHiddenAutTokenNum uint8, inPublicAutTokenNum uint8,
	outStartIndex uint8, outHiddenAutTokenNum uint8, outPlainAutTokenNum uint8,
	serializedAutTxos [][]byte,
	scriptMemo []byte,
	witnessHash chainhash.Hash) *TransferScript {

	return &TransferScript{
		version:              version,
		scriptType:           AutScriptTypeTransfer,
		autIdentifier:        autIdentifier,
		inStartIndex:         inStartIndex,
		inHiddenAutTokenNum:  inHiddenAutTokenNum,
		inPublicAutTokenNum:  inPublicAutTokenNum,
		outStartIndex:        outStartIndex,
		outHiddenAutTokenNum: outHiddenAutTokenNum,
		outPublicAutTokenNum: outPlainAutTokenNum,
		serializedAutTxos:    serializedAutTxos,
		scriptMemo:           scriptMemo,
		witnessHash:          witnessHash,
	}
}

func (autScript *TransferScript) Version() uint32 {
	return autScript.version
}

func (autScript *TransferScript) Type() AutScriptType {
	return autScript.scriptType
}

func (autScript *TransferScript) AutIdentifier() AutId {
	return autScript.autIdentifier
}

func (autScript *TransferScript) InStartIndex() uint8 {
	return autScript.inStartIndex
}

func (autScript *TransferScript) InHiddenAutTokenNum() uint8 {
	return autScript.inHiddenAutTokenNum
}

func (autScript *TransferScript) InPublicAutTokenNum() uint8 {
	return autScript.inPublicAutTokenNum
}

func (autScript *TransferScript) OutStartIndex() uint8 {
	return autScript.outStartIndex
}

func (autScript *TransferScript) OutHiddenAutTokenNum() uint8 {
	return autScript.outHiddenAutTokenNum
}

func (autScript *TransferScript) OutPublicAutTokenNum() uint8 {
	return autScript.outPublicAutTokenNum
}

func (autScript *TransferScript) SerializedAutTxos() [][]byte {
	return autScript.serializedAutTxos
}

func (autScript *TransferScript) ScriptMemo() []byte {
	return autScript.scriptMemo
}

func (autScript *TransferScript) WitnessHash() chainhash.Hash {
	return autScript.witnessHash
}

func (autScript *TransferScript) NumConsumedTokens() int {
	return int(autScript.inHiddenAutTokenNum) + int(autScript.inPublicAutTokenNum)
}

func (autScript *TransferScript) NumGeneratedTokens() int {
	return int(autScript.outHiddenAutTokenNum) + int(autScript.outPublicAutTokenNum)
}

func (autScript *TransferScript) serializeSize() int {
	n := wire.VarIntSerializeSize(uint64(autScript.version)) // version                    uint32
	n += 1                                                   // scriptType                 AutScriptType
	n += chainhash.HashSize                                  // autIdentifier              AutId

	n += 1 // inStartIndex  uint8
	n += 1 // inHiddenAutTokenNum  uint8
	n += 1 // inPublicAutTokenNum  uint8
	n += 1 // outStartIndex uint8
	n += 1 // outHiddenAutTokenNum uint8
	n += 1 // outPublicAutTokenNum uint8

	n += wire.VarIntSerializeSize(uint64(len(autScript.serializedAutTxos))) // serializedAutTxos    [][]byte
	for _, serializedAutTxo := range autScript.serializedAutTxos {
		n += wire.VarIntSerializeSize(uint64(len(serializedAutTxo))) + len(serializedAutTxo)
	}

	n += wire.VarIntSerializeSize(uint64(len(autScript.scriptMemo))) + len(autScript.scriptMemo) // scriptMemo                 []byte

	n += chainhash.HashSize // witnessHash          chainhash.Hash

	return n
}

func (autScript *TransferScript) Serialize() ([]byte, error) {
	if autScript == nil {
		return nil, fmt.Errorf("autScript is nil")
	}

	var err error

	w := bytes.NewBuffer(make([]byte, 0, autScript.serializeSize()))

	// version                    uint32
	if err = wire.WriteVarInt(w, 0, uint64(autScript.version)); err != nil {
		return nil, err
	}

	// scriptType                 AutScriptType
	if err = w.WriteByte(uint8(autScript.Type())); err != nil {
		return nil, err
	}

	// autIdentifier              AutId
	if _, err = w.Write(autScript.autIdentifier[:]); err != nil {
		return nil, err
	}

	// inStartIndex    uint8
	if err = w.WriteByte(autScript.inStartIndex); err != nil {
		return nil, err
	}

	// inHiddenAutTokenNum    uint8
	if err = w.WriteByte(autScript.inHiddenAutTokenNum); err != nil {
		return nil, err
	}

	// inPublicAutTokenNum    uint8
	if err = w.WriteByte(autScript.inPublicAutTokenNum); err != nil {
		return nil, err
	}

	// outStartIndex    uint8
	if err = w.WriteByte(autScript.outStartIndex); err != nil {
		return nil, err
	}

	// outHiddenAutTokenNum uint8
	if err = w.WriteByte(autScript.outHiddenAutTokenNum); err != nil {
		return nil, err
	}

	// outPublicAutTokenNum uint8
	if err = w.WriteByte(autScript.outPublicAutTokenNum); err != nil {
		return nil, err
	}

	// serializedAutTxos    [][]byte
	if err = wire.WriteVarInt(w, 0, uint64(len(autScript.serializedAutTxos))); err != nil {
		return nil, err
	}
	for _, serializedAutTxo := range autScript.serializedAutTxos {
		if err = wire.WriteVarBytes(w, 0, serializedAutTxo); err != nil {
			return nil, err
		}
	}

	// scriptMemo                 []byte
	if err = wire.WriteVarBytes(w, 0, autScript.scriptMemo); err != nil {
		return nil, err
	}

	// witnessHash          chainhash.Hash
	if _, err = w.Write(autScript.witnessHash[:]); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (autScript *TransferScript) Deserialize(serializedScript []byte) error {
	if autScript == nil {
		return fmt.Errorf("autScript is nil")
	}

	var err error

	r := bytes.NewReader(serializedScript)

	// version                    uint32
	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if version > math.MaxUint32 {
		return fmt.Errorf("read version %d is too large", version)
	}
	autScript.version = uint32(version)

	// scriptType                 AutScriptType
	scriptTypeRead, err := r.ReadByte()
	if err != nil {
		return err
	}
	autScript.scriptType = AutScriptType(scriptTypeRead)

	// autIdentifier              AutId
	if _, err = io.ReadFull(r, autScript.autIdentifier[:]); err != nil {
		return err
	}

	// inStartIndex    uint8
	if autScript.inStartIndex, err = r.ReadByte(); err != nil {
		return err
	}

	// inHiddenAutTokenNum    uint8
	if autScript.inHiddenAutTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// inPublicAutTokenNum    uint8
	if autScript.inPublicAutTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// outStartIndex    uint8
	if autScript.outStartIndex, err = r.ReadByte(); err != nil {
		return err
	}

	// outHiddenAutTokenNum    uint8
	if autScript.outHiddenAutTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// inAutRootTokenNum    uint8
	if autScript.outPublicAutTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// serializedAutTxos    [][]byte
	autTxoNum, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if autTxoNum > MaxNumToken {
		return fmt.Errorf("read AutTxo num %d is too large", autTxoNum)
	}
	autScript.serializedAutTxos = make([][]byte, autTxoNum)
	for i := uint64(0); i < autTxoNum; i++ {
		if autScript.serializedAutTxos[i], err = wire.ReadVarBytes(r, 0, MaxAutTxoLength, "SerializedAutTxo"); err != nil {
			return err
		}
	}

	// scriptMemo                 []byte
	autScript.scriptMemo, err = wire.ReadVarBytes(r, 0, MaxScriptMemoLength, "scriptMemo")
	if err != nil {
		return err
	}

	// witnessHash          chainhash.Hash
	if _, err = io.ReadFull(r, autScript.witnessHash[:]); err != nil {
		return err
	}

	return autScript.SanityCheck()
}

func (autScript *TransferScript) SanityCheck() error {

	if autScript == nil {
		return fmt.Errorf("autScript is nil")
	}

	// version                    uint32
	if _, ok := ctautwire.AutScriptVersionSet[autScript.version]; !ok {
		return fmt.Errorf("invalid version: %d", autScript.version)
	}

	// scriptType                 AutScriptType
	if autScript.scriptType != AutScriptTypeTransfer {
		return fmt.Errorf("autScript.scriptType (%d) is not AutScriptTypeTransfer", autScript.scriptType)
	}

	// autIdentifier              AutId

	// inStartIndex    uint8

	// inHiddenAutTokenNum    uint8
	if int(autScript.inHiddenAutTokenNum) > MaxNumHiddenToken {
		return fmt.Errorf("autScript.inHiddenAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.inHiddenAutTokenNum, MaxNumHiddenToken)
	}

	// inPublicAutTokenNum    uint8
	if int(autScript.inPublicAutTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.inPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.inPublicAutTokenNum, MaxNumToken)
	}

	if int(autScript.inHiddenAutTokenNum)+int(autScript.inPublicAutTokenNum) == 0 {
		return fmt.Errorf("autScript.inHiddenAutTokenNum (%d) + script.inPublicAutTokenNum (%d) is 0",
			autScript.inHiddenAutTokenNum, autScript.inPublicAutTokenNum)
	}

	if int(autScript.inHiddenAutTokenNum)+int(autScript.inPublicAutTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.inHiddenAutTokenNum (%d) + script.inPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.inHiddenAutTokenNum, autScript.inPublicAutTokenNum, MaxNumToken)
	}

	if int(autScript.inStartIndex)+int(autScript.inHiddenAutTokenNum)+int(autScript.inPublicAutTokenNum) > math.MaxUint8 {
		// The number of TxIns is designed to be at most uint8.
		return fmt.Errorf("autScript.inStartIndex (%d) + autScript.inHiddenAutTokenNum (%d) + script.inPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.inStartIndex, autScript.inHiddenAutTokenNum, autScript.inPublicAutTokenNum, math.MaxUint8)
	}

	// outStartIndex uint8

	// outHiddenAutTokenNum uint8
	if int(autScript.outHiddenAutTokenNum) > MaxNumHiddenToken {
		return fmt.Errorf("autScript.outHiddenAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.outHiddenAutTokenNum, MaxNumHiddenToken)
	}

	// outPublicAutTokenNum uint8
	if int(autScript.outPublicAutTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.outPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.outPublicAutTokenNum, MaxNumToken)
	}

	if int(autScript.outHiddenAutTokenNum)+int(autScript.outPublicAutTokenNum) == 0 {
		return fmt.Errorf("autScript.outHiddenAutTokenNum (%d) + script.outPublicAutTokenNum (%d) is 0",
			autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum)
	}

	if int(autScript.outHiddenAutTokenNum)+int(autScript.outPublicAutTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.outHiddenAutTokenNum (%d) + autScript.outPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum, MaxNumToken)
	}

	if int(autScript.outStartIndex)+int(autScript.outHiddenAutTokenNum)+int(autScript.outPublicAutTokenNum) > math.MaxUint8 {
		// The Index in (TxHash, Index) is designed to be uint8.
		return fmt.Errorf("autScript.outStartIndex (%d) + autScript.outHiddenAutTokenNum (%d) + autScript.outPublicAutTokenNum (%d) exceeds %d",
			autScript.outStartIndex, autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum, math.MaxUint8)
	}

	// serializedAutTxos    [][]byte
	if len(autScript.serializedAutTxos) != int(autScript.outHiddenAutTokenNum)+int(autScript.outPublicAutTokenNum) {
		return fmt.Errorf("the number of serializedAutTxos (%d) does equal autScript.outHiddenAutTokenNum (%d) + autScript.outPublicAutTokenNum (%d)",
			len(autScript.serializedAutTxos), autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum)
	}
	for i := 0; i < len(autScript.serializedAutTxos); i++ {
		autTxo := &ctautwire.AutTxo{}
		err := autTxo.Deserialize(autScript.serializedAutTxos[i])
		if err != nil {
			return err
		}
		if autTxo.Version != autScript.version {
			return fmt.Errorf("version mismatch (autTxo.Version %d != autScript.version %d)", autTxo.Version, autScript.version)
		}

		autTxoType, err := abecryptox.GetAutTxoType(autTxo)
		if err != nil {
			return err
		}
		if i < int(autScript.outHiddenAutTokenNum) {
			if autTxoType != abecryptox.AutTxoTypeHidden {
				return fmt.Errorf("autScript.outHiddenAutTokenNum = %d, but %d -th AutTxo has type %d (not AutTxoTypeHidden)",
					autScript.outHiddenAutTokenNum, autTxoType, abecryptox.AutTxoTypeHidden)
			}
		} else {
			if autTxoType != abecryptox.AutTxoTypePublic {
				return fmt.Errorf("autScript.outHiddenAutTokenNum = %d, script.outPublicAutTokenNum =%d, but %d -th AutTxo has type %d (not AutTxoTypePublic)",
					autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum, autTxoType, abecryptox.AutTxoTypePublic)
			}

			autTxoValue, err := abecryptox.ExtractAutTxoValue(autTxo, nil, nil)
			if err != nil {
				return err
			}
			if autTxoValue == 0 {
				return fmt.Errorf("autScript.outHiddenAutTokenNum = %d, autScript.outPublicAutTokenNum =%d, but %d -th AutTxo has value 0",
					autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum, i)
			}
		}
	}

	// scriptMemo                 []byte
	if len(autScript.scriptMemo) > MaxScriptMemoLength {
		return fmt.Errorf("len(autScript.scriptMemo) (%d) is too large", len(autScript.scriptMemo))
	}

	// witnessHash          chainhash.Hash

	return nil
}

var _ AutScript = &TransferScript{}

// BurnScript would be the structured script parsed from memo in host transaction,
// 1. the number of generated Hidden-Tokens and Public-Tokens MUST be explicitly specified, as well as corresponding serializedAutTxos
// 3. the number of consumed Hidden-Tokens and Public-Tokens MUST be explicitly specified,
// 4. the witnessHash MUST be given, which is computed from AutWitness at host-transaction layer,
// 5. the generatedTokens would be populated with the function populateGeneratedCTAUTTokens with the help of host transaction
// 6. the consumedTokens would be populated with the help of host transaction and corresponding wire.TxoRing,
// 7. (RULE) the number of generated Public-Tokens MUST be at least 1, since (RULE) the LAST Public-Token would be marked burned.
//
// BurnScript consists of
// <version>
// <scriptType>
// <autIdentifier>
// <inHiddenAutTokenNum> A number n, explicitly specify the 0~(n-1)-th pseudonym TxIn of host-transaction as consumed Hidden-Tokens
// <inPublicAutTokenNum> A number m, explicitly specify the m~(n+m-1)-th pseudonym TxIn of host-transaction as consumed Public-Tokens
// <outHiddenAutTokenNum> A number i, Explicitly specify the 0~(i-1)-th pseudonym Txo of host-transaction as the host-points of Hidden-Tokens
// <outPublicAutTokenNum> A number j, Explicitly specify the i~(i+j-1)-th pseudonym Txo of in host-transaction as host-points of Public-Tokens
// <serializedAutTxos> an array of i+j byte array, corresponding to the outAutTokens
// <witnessHash> a Hash of the witness for balance proof between inAutTokens and outAutTokens
// <scriptMemo> a byte array with max length, for this script
type BurnScript struct {
	version       uint32
	scriptType    AutScriptType
	autIdentifier AutId

	inStartIndex        uint8
	inHiddenAutTokenNum uint8
	inPublicAutTokenNum uint8

	outStartIndex        uint8
	outHiddenAutTokenNum uint8
	outPublicAutTokenNum uint8
	serializedAutTxos    [][]byte

	scriptMemo []byte

	witnessHash chainhash.Hash
}

func NewBurnScript(version uint32,
	autIdentifier AutId,
	inStartIndex uint8, inHiddenAutTokenNum uint8, inPublicAutTokenNum uint8,
	outStartIndex uint8, outHiddenAutTokenNum uint8, outPublicAutTokenNum uint8,
	serializedAutTxos [][]byte,
	scriptMemo []byte,
	witnessHash chainhash.Hash) *BurnScript {

	return &BurnScript{
		version:              version,
		scriptType:           AutScriptTypeBurn,
		autIdentifier:        autIdentifier,
		inStartIndex:         inStartIndex,
		inHiddenAutTokenNum:  inHiddenAutTokenNum,
		inPublicAutTokenNum:  inPublicAutTokenNum,
		outStartIndex:        outStartIndex,
		outHiddenAutTokenNum: outHiddenAutTokenNum,
		outPublicAutTokenNum: outPublicAutTokenNum,
		serializedAutTxos:    serializedAutTxos,
		scriptMemo:           scriptMemo,
		witnessHash:          witnessHash,
	}
}

func (autScript *BurnScript) Version() uint32 {
	return autScript.version
}

func (autScript *BurnScript) Type() AutScriptType {
	return autScript.scriptType
}

func (autScript *BurnScript) AutIdentifier() AutId {
	return autScript.autIdentifier
}

func (autScript *BurnScript) InStartIndex() uint8 {
	return autScript.inStartIndex
}

func (autScript *BurnScript) InHiddenAutTokenNum() uint8 {
	return autScript.inHiddenAutTokenNum
}

func (autScript *BurnScript) InPublicAutTokenNum() uint8 {
	return autScript.inPublicAutTokenNum
}

func (autScript *BurnScript) OutStartIndex() uint8 {
	return autScript.outStartIndex
}

func (autScript *BurnScript) OutHiddenAutTokenNum() uint8 {
	return autScript.outHiddenAutTokenNum
}

func (autScript *BurnScript) OutPublicAutTokenNum() uint8 {
	return autScript.outPublicAutTokenNum
}

func (autScript *BurnScript) SerializedAutTxos() [][]byte {
	return autScript.serializedAutTxos
}

func (autScript *BurnScript) ScriptMemo() []byte {
	return autScript.scriptMemo
}

func (autScript *BurnScript) WitnessHash() chainhash.Hash {
	return autScript.witnessHash
}

func (autScript *BurnScript) NumConsumedTokens() int {
	return int(autScript.inHiddenAutTokenNum) + int(autScript.inPublicAutTokenNum)
}

func (autScript *BurnScript) NumGeneratedTokens() int {
	return int(autScript.outHiddenAutTokenNum) + int(autScript.outPublicAutTokenNum)
}

func (autScript *BurnScript) serializeSize() int {
	n := wire.VarIntSerializeSize(uint64(autScript.version)) // version                    uint32
	n += 1                                                   // scriptType                 AutScriptType
	n += chainhash.HashSize                                  // autIdentifier              AutId

	n += 1 // inStartIndex  uint8
	n += 1 // inHiddenAutTokenNum  uint8
	n += 1 // inPublicAutTokenNum  uint8
	n += 1 // outStartIndex uint8
	n += 1 // outHiddenAutTokenNum uint8
	n += 1 // outPublicAutTokenNum uint8

	n += wire.VarIntSerializeSize(uint64(len(autScript.serializedAutTxos))) // serializedAutTxos    [][]byte
	for _, serializedAutTxo := range autScript.serializedAutTxos {
		n += wire.VarIntSerializeSize(uint64(len(serializedAutTxo))) + len(serializedAutTxo)
	}

	n += wire.VarIntSerializeSize(uint64(len(autScript.scriptMemo))) + len(autScript.scriptMemo) // scriptMemo                 []byte

	n += chainhash.HashSize // witnessHash          chainhash.Hash

	return n
}

func (autScript *BurnScript) Serialize() ([]byte, error) {
	if autScript == nil {
		return nil, fmt.Errorf("autScript is nil")
	}

	var err error

	w := bytes.NewBuffer(make([]byte, 0, autScript.serializeSize()))

	// version                    uint32
	if err = wire.WriteVarInt(w, 0, uint64(autScript.version)); err != nil {
		return nil, err
	}

	// scriptType                 AutScriptType
	if err = w.WriteByte(uint8(autScript.Type())); err != nil {
		return nil, err
	}

	// autIdentifier              AutId
	if _, err = w.Write(autScript.autIdentifier[:]); err != nil {
		return nil, err
	}

	// inStartIndex    uint8
	if err = w.WriteByte(autScript.inStartIndex); err != nil {
		return nil, err
	}

	// inHiddenAutTokenNum    uint8
	if err = w.WriteByte(autScript.inHiddenAutTokenNum); err != nil {
		return nil, err
	}

	// inPublicAutTokenNum    uint8
	if err = w.WriteByte(autScript.inPublicAutTokenNum); err != nil {
		return nil, err
	}

	// outStartIndex uint8
	if err = w.WriteByte(autScript.outStartIndex); err != nil {
		return nil, err
	}

	// outHiddenAutTokenNum uint8
	if err = w.WriteByte(autScript.outHiddenAutTokenNum); err != nil {
		return nil, err
	}

	// outPublicAutTokenNum uint8
	if err = w.WriteByte(autScript.outPublicAutTokenNum); err != nil {
		return nil, err
	}

	// serializedAutTxos    [][]byte
	if err = wire.WriteVarInt(w, 0, uint64(len(autScript.serializedAutTxos))); err != nil {
		return nil, err
	}
	for _, serializedAutTxo := range autScript.serializedAutTxos {
		if err = wire.WriteVarBytes(w, 0, serializedAutTxo); err != nil {
			return nil, err
		}
	}

	// scriptMemo                 []byte
	if err = wire.WriteVarBytes(w, 0, autScript.scriptMemo); err != nil {
		return nil, err
	}

	// witnessHash          chainhash.Hash
	if _, err = w.Write(autScript.witnessHash[:]); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (autScript *BurnScript) Deserialize(serializedScript []byte) error {
	if autScript == nil {
		return fmt.Errorf("autScript is nil")
	}

	var err error

	r := bytes.NewReader(serializedScript)

	// version                    uint32
	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if version > math.MaxUint32 {
		return fmt.Errorf("read version %d is too large", version)
	}
	autScript.version = uint32(version)

	// scriptType                 AutScriptType
	scriptTypeRead, err := r.ReadByte()
	if err != nil {
		return err
	}
	autScript.scriptType = AutScriptType(scriptTypeRead)

	// autIdentifier              AutId
	if _, err = io.ReadFull(r, autScript.autIdentifier[:]); err != nil {
		return err
	}

	// inStartIndex    uint8
	if autScript.inStartIndex, err = r.ReadByte(); err != nil {
		return err
	}

	// inHiddenAutTokenNum    uint8
	if autScript.inHiddenAutTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// inPublicAutTokenNum    uint8
	if autScript.inPublicAutTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// outStartIndex    uint8
	if autScript.outStartIndex, err = r.ReadByte(); err != nil {
		return err
	}

	// outHiddenAutTokenNum    uint8
	if autScript.outHiddenAutTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// outPublicAutTokenNum    uint8
	if autScript.outPublicAutTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// serializedAutTxos    [][]byte
	autTxoNum, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if autTxoNum > MaxNumToken {
		return fmt.Errorf("read AutTxo num %d is too large", autTxoNum)
	}
	autScript.serializedAutTxos = make([][]byte, autTxoNum)
	for i := uint64(0); i < autTxoNum; i++ {
		if autScript.serializedAutTxos[i], err = wire.ReadVarBytes(r, 0, MaxAutTxoLength, "SerializedAutTxo"); err != nil {
			return err
		}
	}

	// scriptMemo                 []byte
	autScript.scriptMemo, err = wire.ReadVarBytes(r, 0, MaxScriptMemoLength, "scriptMemo")
	if err != nil {
		return err
	}

	// witnessHash          chainhash.Hash
	if _, err = io.ReadFull(r, autScript.witnessHash[:]); err != nil {
		return err
	}

	return autScript.SanityCheck()
}

func (autScript *BurnScript) SanityCheck() error {
	if autScript == nil {
		return fmt.Errorf("autScript is nil")
	}

	// version                    uint32
	if _, ok := ctautwire.AutScriptVersionSet[autScript.version]; !ok {
		return fmt.Errorf("invalid version: %d", autScript.version)
	}

	// scriptType                 AutScriptType
	if autScript.scriptType != AutScriptTypeBurn {
		return fmt.Errorf("autScript.scriptType (%d) is not AutScriptTypeTransfer", autScript.scriptType)
	}

	// autIdentifier              AutId

	// inStartIndex    uint8

	// inHiddenAutTokenNum    uint8
	if int(autScript.inHiddenAutTokenNum) > MaxNumHiddenToken {
		return fmt.Errorf("autScript.inHiddenAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.inHiddenAutTokenNum, MaxNumHiddenToken)
	}

	// inPublicAutTokenNum    uint8
	if int(autScript.inPublicAutTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.inPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.inPublicAutTokenNum, MaxNumToken)
	}

	if int(autScript.inHiddenAutTokenNum)+int(autScript.inPublicAutTokenNum) == 0 {
		return fmt.Errorf("autScript.inHiddenAutTokenNum (%d) + autScript.inPublicAutTokenNum (%d) is 0",
			autScript.inHiddenAutTokenNum, autScript.inPublicAutTokenNum)
	}

	if int(autScript.inHiddenAutTokenNum)+int(autScript.inPublicAutTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.inHiddenAutTokenNum (%d) + autScript.inPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.inHiddenAutTokenNum, autScript.inPublicAutTokenNum, MaxNumToken)
	}

	if int(autScript.inStartIndex)+int(autScript.inHiddenAutTokenNum)+int(autScript.inPublicAutTokenNum) > math.MaxUint8 {
		// The number of TxIns is designed to be at most uint8.
		return fmt.Errorf("autScript.inStartIndex (%d) + autScript.inHiddenAutTokenNum (%d) + script.inPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.inStartIndex, autScript.inHiddenAutTokenNum, autScript.inPublicAutTokenNum, math.MaxUint8)
	}

	// outStartIndex uint8

	// outHiddenAutTokenNum uint8
	if int(autScript.outHiddenAutTokenNum) > MaxNumHiddenToken {
		return fmt.Errorf("autScript.outHiddenAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.outHiddenAutTokenNum, MaxNumHiddenToken)
	}

	// outPublicAutTokenNum uint8
	if int(autScript.outPublicAutTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.outPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.outPublicAutTokenNum, MaxNumToken)
	}
	if int(autScript.outPublicAutTokenNum) < 1 {
		return fmt.Errorf("autScript.outPublicAutTokenNum (%d) is smaller than 1: invalid for BurnScript",
			autScript.outPublicAutTokenNum)
	}

	// This check can be removed. Keep here for alignment.
	if int(autScript.outHiddenAutTokenNum)+int(autScript.outPublicAutTokenNum) == 0 {
		return fmt.Errorf("autScript.outHiddenAutTokenNum (%d) + autScript.outPublicAutTokenNum (%d) is 0",
			autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum)
	}

	if int(autScript.outHiddenAutTokenNum)+int(autScript.outPublicAutTokenNum) > MaxNumToken {
		return fmt.Errorf("autScript.outHiddenAutTokenNum (%d) + autScript.outPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum, MaxNumToken)
	}

	if int(autScript.outStartIndex)+int(autScript.outHiddenAutTokenNum)+int(autScript.outPublicAutTokenNum) > math.MaxUint8 {
		// The Index in (TxHash, Index) is designed to be uint8.
		return fmt.Errorf("autScript.outStartIndex (%d) + autScript.outHiddenAutTokenNum (%d) + autScript.outPublicAutTokenNum (%d) exceeds %d",
			autScript.outStartIndex, autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum, math.MaxUint8)
	}

	// serializedAutTxos    [][]byte
	if len(autScript.serializedAutTxos) != int(autScript.outHiddenAutTokenNum)+int(autScript.outPublicAutTokenNum) {
		return fmt.Errorf("the number of serializedAutTxos (%d) does equal autScript.outHiddenAutTokenNum (%d) + autScript.outPublicAutTokenNum (%d)",
			len(autScript.serializedAutTxos), autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum)
	}
	for i := 0; i < len(autScript.serializedAutTxos); i++ {
		autTxo := &ctautwire.AutTxo{}
		err := autTxo.Deserialize(autScript.serializedAutTxos[i])
		if err != nil {
			return err
		}
		if autTxo.Version != autScript.version {
			return fmt.Errorf("version mismatch (autTxo.Version %d != autScript.version %d)", autTxo.Version, autScript.version)
		}

		autTxoType, err := abecryptox.GetAutTxoType(autTxo)
		if err != nil {
			return err
		}
		if i < int(autScript.outHiddenAutTokenNum) {
			if autTxoType != abecryptox.AutTxoTypeHidden {
				return fmt.Errorf("autScript.outHiddenAutTokenNum = %d, but %d -th AutTxo has type %d (not AutTxoTypeHidden)",
					autScript.outHiddenAutTokenNum, autTxoType, abecryptox.AutTxoTypeHidden)
			}
		} else {
			if autTxoType != abecryptox.AutTxoTypePublic {
				return fmt.Errorf("autScript.outHiddenAutTokenNum = %d, script.outPublicAutTokenNum =%d, but %d -th AutTxo has type %d (not AutTxoTypePublic)",
					autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum, autTxoType, abecryptox.AutTxoTypePublic)
			}

			autTxoValue, err := abecryptox.ExtractAutTxoValue(autTxo, nil, nil)
			if err != nil {
				return err
			}
			if autTxoValue == 0 {
				return fmt.Errorf("autScript.outHiddenAutTokenNum = %d, autScript.outPublicAutTokenNum =%d, but %d -th AutTxo has value 0",
					autScript.outHiddenAutTokenNum, autScript.outPublicAutTokenNum, i)
			}
		}
	}

	// scriptMemo                 []byte
	if len(autScript.scriptMemo) > MaxScriptMemoLength {
		return fmt.Errorf("len(autScript.scriptMemo) (%d) is too large", len(autScript.scriptMemo))
	}

	// witnessHash          chainhash.Hash

	return nil
}

var _ AutScript = &BurnScript{}

// DeserializeAutScriptV1 deserializes the serializedAutScript to an AutScript, where
// serializedAutScript is assumed to be the result of Serialize of AutScript with Version=AutScriptVersion_1.
// If the input serializedAutScript does not satisfy this requirement, an error will be returned.
func DeserializeAutScriptV1(serializedAutScript []byte) (AutScript, error) {
	r := bytes.NewReader(serializedAutScript)

	versionRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}
	if versionRead > math.MaxUint32 {
		return nil, fmt.Errorf("read script version (%d) is too large", versionRead)
	}
	scriptVersion := uint32(versionRead)
	if _, ok := ctautwire.AutScriptVersionSet[scriptVersion]; !ok {
		return nil, fmt.Errorf("unknown au script version %d", scriptVersion)
	}

	// make sure the function is correctly called
	if scriptVersion != ctautwire.AutScriptVersion_1 {
		return nil, fmt.Errorf("the read version %d is not AutScriptVersion_1", scriptVersion)
	}

	scriptTypeRead, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	scriptType := AutScriptType(scriptTypeRead)

	var autScript AutScript
	switch scriptType {
	case AutScriptTypeRegistration:
		autScript = &RegistrationScript{}
	case AutScriptTypeReRegistration:
		autScript = &ReRegistrationScript{}
	case AutScriptTypeMint:
		autScript = &MintScript{}
	case AutScriptTypeTransfer:
		autScript = &TransferScript{}
	case AutScriptTypeBurn:
		autScript = &BurnScript{}
	default:
		return nil, fmt.Errorf("unknown aut script type %d", scriptType)
	}

	err = autScript.Deserialize(serializedAutScript)
	if err != nil {
		return nil, err
	}

	return autScript, nil
}

// end of codes

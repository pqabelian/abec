package ctaut

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/chainhash"
	ctautwire "github.com/abesuite/abec/ctaut/wire"
	"github.com/abesuite/abec/wire"
)

// HostOutPoint defines the host of aut token, it could be used to track previous tokens.
type HostOutPoint = wire.OutPointAbe

type AutId = chainhash.Hash

// AutIssuer defines Aut Issuer by IssuerAddress, where IssuerAddress is a wrapper of coinAddress.
// Each AutIssuer corresponds to a coinAddress,
// where coinAddress means the address on chain that a coin belongs to,
// say, each coin on chain has a format (coinAddress, valueScript).
// Do not limit the coinAddress here to the concept in CryptoAddress in abecryptox package.
// Note that, as Abelian-Txo belongs to coinAddress, AutToken also belongs to coinAddress.
// Note that it must keep that each AutIssuer can be identified by its underlying coinAddress.
// Note that it must keep that each AutIssuer can be identified by its IssuerAddress.
type AutIssuer struct {
	IssuerAddress []byte
}

// NewAutIssuer returns a new AutIssuer for the input issuerAddress.
func NewAutIssuer(issuerAddress []byte) *AutIssuer {
	return &AutIssuer{
		IssuerAddress: issuerAddress,
	}
}

// CoinAddress returns the coinAddress contained in autIssuer.IssuerAddress.
func (autIssuer *AutIssuer) CoinAddress() []byte {
	// At present, IssuerAddress is exactly the coinAddress.
	return autIssuer.IssuerAddress
}

func (autIssuer *AutIssuer) serializeSize() int {
	return wire.VarIntSerializeSize(uint64(len(autIssuer.IssuerAddress))) + len(autIssuer.IssuerAddress)
}

func (autIssuer *AutIssuer) write(w io.Writer) error {
	return wire.WriteVarBytes(w, 0, autIssuer.IssuerAddress)
}

func (autIssuer *AutIssuer) read(r io.Reader) error {
	issuerAddress, err := wire.ReadVarBytes(r, 0, MaxIssuerAddressLength, "AutIssuer.IssuerAddress")
	if err != nil {
		return err
	}

	autIssuer.IssuerAddress = issuerAddress
	return nil
}

func (autIssuer *AutIssuer) String() string {
	return hex.EncodeToString(autIssuer.IssuerAddress)
}

// Equal reports whether autIssuer and issuer have the same IssuerAddress.
// Equal returns TURE only if
// autIssuer and issuer are not nil,
// autIssuer.IssuerAddress and issuer.IssuerAddress are not nil/empty, and
// autIssuer.IssuerAddress and issuer.IssuerAddress have the same length and contain the same bytes.
func (autIssuer *AutIssuer) Equal(issuer *AutIssuer) bool {
	if autIssuer == nil || issuer == nil {
		return false
	}

	if len(autIssuer.IssuerAddress) == 0 || len(issuer.IssuerAddress) == 0 {
		return false
	}

	return bytes.Equal(autIssuer.IssuerAddress, issuer.IssuerAddress)
}

func (autIssuer *AutIssuer) Clone() *AutIssuer {
	rst := &AutIssuer{}
	rst.IssuerAddress = make([]byte, len(autIssuer.IssuerAddress))
	copy(rst.IssuerAddress, autIssuer.IssuerAddress)
	return rst
}

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

	// ReregistrationExpireHeight specifies a height, after which the ReRegistrationScript could not be applied any more.
	// Using int32 is to allow -1 to be used as the infinite height.
	ReregistrationExpireHeight int32

	// ReregistrationThreshold specifies the size of authorized issuer set for ReRegistrationScript.
	ReregistrationThreshold uint8

	// MintThreshold specifies the size of authorized issuer set for MintScript.
	MintThreshold uint8

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

func (autMetadata *AutMetadata) serializeSize() int {
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
		n += autMetadata.Issuers[i].serializeSize()
	}

	n += wire.VarIntSerializeSize(uint64(autMetadata.ReregistrationExpireHeight)) // ReregistrationExpireHeight

	n += 1 + // reregister threshold
		1 // mint threshold

	n += wire.VarIntSerializeSize(autMetadata.MintedAmount) + // minted amount,variable length
		wire.VarIntSerializeSize(autMetadata.BurnedAmount) // burned amount,variable length

	n += wire.VarIntSerializeSize(uint64(len(autMetadata.ActiveRootTokenSet))) // number of issuer tokens
	for _, hostOutPoint := range autMetadata.ActiveRootTokenSet {
		n += hostOutPoint.SerializeSize()
	}

	n += wire.VarIntSerializeSize(uint64(len(autMetadata.UpdateScriptVersions)))
	for _, version := range autMetadata.UpdateScriptVersions {
		n += wire.VarIntSerializeSize(uint64(version))
	}

	return n
}

// Serialize serializes AutMetadata to []byte.
func (autMetadata *AutMetadata) Serialize() ([]byte, error) {
	if autMetadata == nil {
		return nil, nil
	}

	// Calculate the size needed to serialize AUT autMetadata.
	var err error
	size := autMetadata.serializeSize()
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
	err = wire.WriteVarInt(w, 0, uint64(len(autMetadata.Issuers)))
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(autMetadata.Issuers); i++ {
		err = autMetadata.Issuers[i].write(w)
		if err != nil {
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

	// MintedAmount               uint64
	err = wire.WriteVarInt(w, 0, autMetadata.MintedAmount)
	if err != nil {
		return nil, err
	}

	// BurnedAmount               uint64
	err = wire.WriteVarInt(w, 0, autMetadata.BurnedAmount)
	if err != nil {
		return nil, err
	}

	// ActiveRootTokenSet         map[string]*HostOutPoint
	err = wire.WriteVarInt(w, 0, uint64(len(autMetadata.ActiveRootTokenSet)))
	if err != nil {
		return nil, err
	}
	for _, hostOutPoint := range autMetadata.ActiveRootTokenSet {
		err = wire.WriteOutPointAbe(w, 0, 0, hostOutPoint)
		if err != nil {
			return nil, fmt.Errorf("error happens when writing active root token: %v", err)
		}
	}

	// UpdateScriptVersions            []uint32
	err = wire.WriteVarInt(w, 0, uint64(len(autMetadata.UpdateScriptVersions)))
	for _, version := range autMetadata.UpdateScriptVersions {
		err = wire.WriteVarInt(w, 0, uint64(version))
		if err != nil {
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
	r := bytes.NewReader(serializedMetadata)

	var err error

	// Version                    uint32
	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if version > math.MaxUint32 {
		return fmt.Errorf("readed version (%d) is too large", version)
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
		return fmt.Errorf("issuerNum (%d) is too large", issuerNum)
	}
	autMetadata.Issuers = make([]*AutIssuer, issuerNum)
	for i := uint64(0); i < issuerNum; i++ {
		issuer := &AutIssuer{}
		err = issuer.read(r)
		if err != nil {
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
		return fmt.Errorf("the readed ReregistrationExpireHeight (%d) is not in the scope [-1, %d]", temp, math.MaxInt32)
	}
	autMetadata.ReregistrationExpireHeight = int32(temp)

	// ReregistrationThreshold    uint8
	if autMetadata.ReregistrationThreshold, err = ReadByte(r); err != nil {
		return err
	}

	// MintThreshold              uint8
	if autMetadata.MintThreshold, err = ReadByte(r); err != nil {
		return err
	}

	// MintedAmount               uint64
	autMetadata.MintedAmount, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	// BurnedAmount               uint64
	autMetadata.BurnedAmount, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	// ActiveRootTokenSet         map[string]*HostOutPoint
	rootCoinNum, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if rootCoinNum > MaxNumToken {
		return fmt.Errorf("rootCoinNum (%d) is too large", rootCoinNum)
	}
	autMetadata.ActiveRootTokenSet = make(map[string]*HostOutPoint, rootCoinNum)
	for i := uint64(0); i < rootCoinNum; i++ {
		hostOutPoint := &HostOutPoint{}
		err = wire.ReadOutPointAbe(r, 0, 0, hostOutPoint)
		if err != nil {
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
			return fmt.Errorf("readed update script version (%d) is too large", version)
		}
		autMetadata.UpdateScriptVersions[i] = uint32(version)
	}

	return autMetadata.SanityCheck()
}

// SanityCheck checks whether the AutMetadata is well-formed, and return a non-nil error if it is not well-formed.
func (autMetadata *AutMetadata) SanityCheck() error {

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

// Clone returns a shallow copy of the AutMetadata entry.
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
		cloned.Issuers[i] = autMetadata.Issuers[i].Clone()
	}

	for _, hostOutpoint := range autMetadata.ActiveRootTokenSet {
		newHosOutpoint := &HostOutPoint{}
		copy(newHosOutpoint.TxHash[:], hostOutpoint.TxHash[:])
		newHosOutpoint.Index = hostOutpoint.Index

		cloned.ActiveRootTokenSet[newHosOutpoint.String()] = newHosOutpoint
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

	// Serialize serializes AutScript to []byte.
	Serialize() ([]byte, error)

	// Deserialize deserializes []byte to AutScript.
	Deserialize([]byte) error

	// NumConsumedTokens returns the number of AutRootTokens/AutTokens that this AutScript consumes.
	NumConsumedTokens() int

	// NumGeneratedTokens returns the number of AutRootTokens/AutTokens that this AutScript generates.
	NumGeneratedTokens() int
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

	// the number of output AutRootTokens
	outAutRootTokenNum uint8 // value is set in deserialize, so, do not provide set function, but provide get function.

	scriptMemo []byte
}

func (script *RegistrationScript) AutName() []byte {
	return script.autName
}

func (script *RegistrationScript) AutSymbol() []byte {
	return script.autSymbol
}

func (script *RegistrationScript) BaseUnitName() []byte {
	return script.baseUnitName
}

func (script *RegistrationScript) SubUnitName() []byte {
	return script.subUnitName
}

func (script *RegistrationScript) UnitScale() uint64 {
	return script.unitScale
}

func (script *RegistrationScript) AutMemo() []byte {
	return script.autMemo
}

func (script *RegistrationScript) PlannedTotalSupply() uint64 {
	return script.plannedTotalSupply
}

func (script *RegistrationScript) Issuers() []*AutIssuer {
	return script.issuers
}

func (script *RegistrationScript) ReregistrationExpireHeight() int32 {
	return script.reregistrationExpireHeight
}

func (script *RegistrationScript) MintThreshold() uint8 {
	return script.mintThreshold
}

func (script *RegistrationScript) ReregisterThreshold() uint8 {
	return script.reregisterThreshold
}

func (script *RegistrationScript) OutAutRootTokenNum() uint8 {
	return script.outAutRootTokenNum
}

func (script *RegistrationScript) ScriptMemo() []byte {
	return script.scriptMemo
}

// NewRegistrationScript creates a new RegistrationScript.
//
// Note that RegistrationScript's autIdentifier is zeroHash, and does not need a corresponding input.
func NewRegistrationScript(version uint32,
	autName []byte, autSymbol []byte, baseUnitName []byte, subUnitName []byte, unitScale uint64,
	autMemo []byte, plannedTotalSupply uint64,
	issuers []*AutIssuer, reregistrationExpireHeight int32, reregisterThreshold uint8, mintThreshold uint8,
	outAutRootTokenNum uint8,
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
		outAutRootTokenNum:         outAutRootTokenNum,
		scriptMemo:                 scriptMemo,
	}
}

func (script *RegistrationScript) Version() uint32 {
	return script.version
}
func (script *RegistrationScript) Type() AutScriptType {
	return script.scriptType
}
func (script *RegistrationScript) AutIdentifier() AutId {
	return script.autIdentifier
}

func (script *RegistrationScript) serializeSize() int {
	n := wire.VarIntSerializeSize(uint64(script.version))                                      // version                    uint32
	n += 1                                                                                     // scriptType                 AutScriptType
	n += chainhash.HashSize                                                                    // autIdentifier              AutId
	n += wire.VarIntSerializeSize(uint64(len(script.autName))) + len(script.autName)           // autName                    []byte
	n += wire.VarIntSerializeSize(uint64(len(script.autSymbol))) + len(script.autSymbol)       // autSymbol                  []byte
	n += wire.VarIntSerializeSize(uint64(len(script.baseUnitName))) + len(script.baseUnitName) // baseUnitName               []byte
	n += wire.VarIntSerializeSize(uint64(len(script.subUnitName))) + len(script.subUnitName)   // subUnitName                []byte
	n += wire.VarIntSerializeSize(script.unitScale)                                            // unitScale                  uint64
	n += wire.VarIntSerializeSize(uint64(len(script.autMemo))) + len(script.autMemo)           // autMemo                    []byte
	n += wire.VarIntSerializeSize(script.plannedTotalSupply)                                   // plannedTotalSupply         uint64
	n += wire.VarIntSerializeSize(uint64(len(script.issuers)))                                 // issuers                    []*AutIssuer
	for _, issuer := range script.issuers {
		n += issuer.serializeSize()
	}
	n += wire.VarIntSerializeSize(uint64(script.reregistrationExpireHeight)) // reregistrationExpireHeight int32

	n += 1 // reregisterThreshold        uint8
	n += 1 // mintThreshold              uint8
	n += 1 // outAutRootTokenNum         uint8

	n += wire.VarIntSerializeSize(uint64(len(script.scriptMemo))) + len(script.scriptMemo) // scriptMemo                 []byte

	return n
}

func (script *RegistrationScript) Serialize() ([]byte, error) {
	var err error

	w := bytes.NewBuffer(make([]byte, 0, script.serializeSize()))

	// version                    uint32
	if err = wire.WriteVarInt(w, 0, uint64(script.version)); err != nil {
		return nil, err
	}

	// scriptType                 AutScriptType
	if err = w.WriteByte(script.Type()); err != nil {
		return nil, err
	}

	// autIdentifier              AutId
	if _, err = w.Write(script.autIdentifier[:]); err != nil {
		return nil, err
	}

	// autName                    []byte
	if err = wire.WriteVarBytes(w, 0, script.autName); err != nil {
		return nil, err
	}

	// autSymbol                  []byte
	if err = wire.WriteVarBytes(w, 0, script.autSymbol); err != nil {
		return nil, err
	}

	// baseUnitName               []byte
	if err = wire.WriteVarBytes(w, 0, script.baseUnitName); err != nil {
		return nil, err
	}

	// subUnitName                []byte
	if err = wire.WriteVarBytes(w, 0, script.subUnitName); err != nil {
		return nil, err
	}

	// unitScale                  uint64
	if err = wire.WriteVarInt(w, 0, script.unitScale); err != nil {
		return nil, err
	}

	// autMemo                    []byte
	if err = wire.WriteVarBytes(w, 0, script.autMemo); err != nil {
		return nil, err
	}

	// plannedTotalSupply         uint64
	if err = wire.WriteVarInt(w, 0, script.plannedTotalSupply); err != nil {
		return nil, err
	}

	// issuers                    []*AutIssuer
	if err = wire.WriteVarInt(w, 0, uint64(len(script.issuers))); err != nil {
		return nil, err
	}
	for _, issuer := range script.issuers {
		if err = issuer.write(w); err != nil {
			return nil, err
		}
	}

	// reregistrationExpireHeight int32
	if err = wire.WriteVarInt(w, 0, uint64(script.reregistrationExpireHeight)); err != nil {
		return nil, err
	}

	// reregisterThreshold        uint8
	if err = w.WriteByte(script.reregisterThreshold); err != nil {
		return nil, err
	}

	// mintThreshold              uint8
	if err = w.WriteByte(script.mintThreshold); err != nil {
		return nil, err
	}

	// outAutRootTokenNum         uint8
	if err = w.WriteByte(script.outAutRootTokenNum); err != nil {
		return nil, err
	}

	// scriptMemo                 []byte
	if err = wire.WriteVarBytes(w, 0, script.scriptMemo); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (script *RegistrationScript) Deserialize(serializedScript []byte) error {
	var err error

	r := bytes.NewReader(serializedScript)

	// version                    uint32
	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if version > math.MaxUint32 {
		return fmt.Errorf("readed version %d is too large", version)
	}
	script.version = uint32(version)

	// scriptType                 AutScriptType
	// todo: discuss, io.ReadFull (not r.Read()), while here r.ReadByte()
	script.scriptType, err = r.ReadByte()
	if err != nil {
		return err
	}

	// autIdentifier              AutId
	if _, err = io.ReadFull(r, script.autIdentifier[:]); err != nil {
		return err
	}

	// autName                    []byte
	if script.autName, err = wire.ReadVarBytes(r, 0, MaxAutNameLength, "autName"); err != nil {
		return err
	}

	// autSymbol                  []byte
	if script.autSymbol, err = wire.ReadVarBytes(r, 0, MaxAutSymbolLength, "autSymbol"); err != nil {
		return err
	}

	// baseUnitName               []byte
	if script.baseUnitName, err = wire.ReadVarBytes(r, 0, MaxBaseUnitLength, "baseUnitName"); err != nil {
		return err
	}

	// subUnitName                []byte
	if script.subUnitName, err = wire.ReadVarBytes(r, 0, MaxSubUnitLength, "subUnitName"); err != nil {
		return err
	}

	// unitScale                  uint64
	if script.unitScale, err = wire.ReadVarInt(r, 0); err != nil {
		return err
	}

	// autMemo                    []byte
	if script.autMemo, err = wire.ReadVarBytes(r, 0, MaxAutMemoLength, "autMemo"); err != nil {
		return err
	}

	// plannedTotalSupply         uint64
	if script.plannedTotalSupply, err = wire.ReadVarInt(r, 0); err != nil {
		return err
	}

	// issuers                    []*AutIssuer
	issuerNum, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if issuerNum > MaxIssuerNum {
		return fmt.Errorf("readed issuer num %d is too large", issuerNum)
	}
	script.issuers = make([]*AutIssuer, issuerNum)
	for i := uint64(0); i < issuerNum; i++ {
		issuer := &AutIssuer{}
		if err = issuer.read(r); err != nil {
			return err
		}
		script.issuers[i] = issuer
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
	script.reregistrationExpireHeight = int32(expireHeightRead)

	// reregisterThreshold        uint8
	script.reregisterThreshold, err = r.ReadByte()
	if err != nil {
		return err
	}

	// mintThreshold              uint8
	if script.mintThreshold, err = r.ReadByte(); err != nil {
		return err
	}

	// outAutRootTokenNum         uint8
	if script.outAutRootTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// scriptMemo                 []byte
	script.scriptMemo, err = wire.ReadVarBytes(r, 0, MaxScriptMemoLength, "scriptMemo")
	if err != nil {
		return err
	}

	return script.SanityCheck()
}

func (script *RegistrationScript) SanityCheck() error {

	// version                    uint32
	if _, ok := ctautwire.AutScriptVersionSet[script.version]; !ok {
		return fmt.Errorf("invalid version: %d", script.version)
	}

	// scriptType                 AutScriptType
	if script.scriptType != AutScriptTypeRegistration {
		return fmt.Errorf("script.scriptType (%d) is not AutScriptTypeRegistration", script.scriptType)
	}

	// autIdentifier              AutId
	if !bytes.Equal(script.autIdentifier[:], ZeroHash[:]) {
		return fmt.Errorf("invalid autIdentifier (%x) for RegistrationScript", script.autIdentifier[:])
	}

	// autName                    []byte
	if len(script.autName) == 0 {
		return fmt.Errorf("script.autName is empty/nil")
	}
	if len(script.autName) > MaxAutNameLength {
		return fmt.Errorf("script.autName is too long (%d)", len(script.autName))
	}

	// autSymbol                  []byte
	if len(script.autSymbol) == 0 {
		return fmt.Errorf("script.autSymbol is empty/nil")
	}
	if len(script.autSymbol) > MaxAutSymbolLength {
		return fmt.Errorf("script.autSymbol is too long (%d)", len(script.autSymbol))
	}

	// baseUnitName               []byte
	if len(script.baseUnitName) == 0 {
		return fmt.Errorf("script.baseUnitName is empty/nil")
	}
	if len(script.baseUnitName) > MaxBaseUnitLength {
		return fmt.Errorf("script.baseUnitName is too long (%d)", len(script.baseUnitName))
	}

	// subUnitName                []byte
	if len(script.subUnitName) == 0 {
		return fmt.Errorf("script.subUnitName is empty/nil")
	}
	if len(script.subUnitName) > MaxSubUnitLength {
		return fmt.Errorf("script.subUnitName is too long (%d)", len(script.subUnitName))
	}

	// unitScale                  uint64
	if script.unitScale == 0 || script.unitScale > MaxAmount {
		return fmt.Errorf("script.unitScale (%d) is not in [1, %d]", script.unitScale, MaxAmount)
	}
	if script.unitScale > script.plannedTotalSupply {
		return fmt.Errorf("script.unitScale (%d) exceeds script.plannedTotalSupply (%d)",
			script.unitScale, script.plannedTotalSupply)
	}

	// autMemo                    []byte
	if len(script.autMemo) > MaxAutMemoLength {
		return fmt.Errorf("script.autMemo length (%d) exceeds MaxAutMemoLength (%d)", len(script.autMemo), MaxAutMemoLength)
	}

	// plannedTotalSupply         uint64
	if script.plannedTotalSupply == 0 || script.plannedTotalSupply > MaxAmount {
		return fmt.Errorf("script.plannedTotalSupply (%d) is not in [1, %d]", script.plannedTotalSupply, MaxAmount)
	}

	// issuers                    []*AutIssuer
	if len(script.issuers) == 0 || len(script.issuers) > MaxIssuerNum {
		return fmt.Errorf("the number of issuers (%d) is not in [1, %d]", len(script.issuers), MaxIssuerNum)
	}
	issuersMap := make(map[string]int, len(script.issuers))
	for i, issuer := range script.issuers {
		issuerStr := issuer.String()
		if index, ok := issuersMap[issuerStr]; ok {
			return fmt.Errorf("issuers[%d] and issuers[%d] are repeated : %s", i, index, issuerStr)
		}
		issuersMap[issuerStr] = i
	}

	// reregistrationExpireHeight int32
	if script.reregistrationExpireHeight < InfiniteExpireHeight || script.reregistrationExpireHeight > math.MaxInt32 {
		return fmt.Errorf("script.reregistrationExpireHeight (%d) is not in [-1, %d]",
			script.reregistrationExpireHeight, math.MaxInt32)
	}

	// reregisterThreshold        uint8
	if int(script.reregisterThreshold) == 0 {
		return fmt.Errorf("script.reregisterThreshold (%d) is invalid",
			script.reregisterThreshold)
	}
	if int(script.reregisterThreshold) > len(script.issuers) {
		return fmt.Errorf("script.reregisterThreshold (%d) exceeds the number of issuers (%d)",
			script.reregisterThreshold, len(script.issuers))
	}

	// mintThreshold              uint8
	if int(script.mintThreshold) == 0 {
		return fmt.Errorf("script.mintThreshold (%d) is invalid",
			script.mintThreshold)
	}
	if int(script.mintThreshold) > len(script.issuers) {
		return fmt.Errorf("script.mintThreshold (%d) exceeds the number of issuers (%d)",
			script.mintThreshold, len(script.issuers))
	}

	// outAutRootTokenNum         uint8
	if int(script.outAutRootTokenNum) == 0 {
		return fmt.Errorf("script.outAutRootTokenNum (%d) is invalid",
			script.outAutRootTokenNum)
	}
	if int(script.outAutRootTokenNum) > MaxNumToken {
		return fmt.Errorf("script.outAutRootTokenNum (%d) exceeds the allowed max number (%d)",
			script.outAutRootTokenNum, MaxNumToken)
	}

	// scriptMemo                 []byte
	if len(script.scriptMemo) > MaxScriptMemoLength {
		return fmt.Errorf("len(script.scriptMemo) (%d) is too large", len(script.scriptMemo))
	}

	return nil
}

func (script *RegistrationScript) NumConsumedTokens() int {
	return 0
}

func (script *RegistrationScript) NumGeneratedTokens() int {
	return int(script.outAutRootTokenNum)
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

	// inAutRootTokenNum is an additional field that ReRegistrationScript has while RegistrationScript doesn't.
	inAutRootTokenNum uint8

	// the number of output AutRootTokens
	outAutRootTokenNum uint8 // value is set in deserialize, so, do not provide set function, but provide get function.

	scriptMemo []byte
}

func (script *ReRegistrationScript) AutMemo() []byte {
	return script.autMemo
}

func (script *ReRegistrationScript) PlannedTotalSupply() uint64 {
	return script.plannedTotalSupply
}

func (script *ReRegistrationScript) Issuers() []*AutIssuer {
	return script.issuers
}

func (script *ReRegistrationScript) ReregistrationExpireHeight() int32 {
	return script.reregistrationExpireHeight
}

func (script *ReRegistrationScript) MintThreshold() uint8 {
	return script.mintThreshold
}

func (script *ReRegistrationScript) ReregisterThreshold() uint8 {
	return script.reregisterThreshold
}

func (script *ReRegistrationScript) InAutRootTokenNum() uint8 {
	return script.inAutRootTokenNum
}

func (script *ReRegistrationScript) OutAutRootTokenNum() uint8 {
	return script.outAutRootTokenNum
}

func (script *ReRegistrationScript) ScriptMemo() []byte {
	return script.scriptMemo
}

func NewReRegistrationScript(version uint32,
	autIdentifier AutId,
	autMemo []byte, plannedTotalSupply uint64,
	issuers []*AutIssuer, reregistrationExpireHeight int32, reregisterThreshold uint8, mintThreshold uint8,
	inAutRootTokenNum uint8, outAutRootTokenNum uint8,
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
		inAutRootTokenNum:          inAutRootTokenNum,
		outAutRootTokenNum:         outAutRootTokenNum,
		scriptMemo:                 scriptMemo,
	}
}

func (script *ReRegistrationScript) Version() uint32 {
	return script.version
}
func (script *ReRegistrationScript) Type() AutScriptType {
	return script.scriptType
}
func (script *ReRegistrationScript) AutIdentifier() AutId {
	return script.autIdentifier
}

func (script *ReRegistrationScript) serializeSize() int {
	n := wire.VarIntSerializeSize(uint64(script.version))                            // version                    uint32
	n += 1                                                                           // scriptType                 AutScriptType
	n += chainhash.HashSize                                                          // autIdentifier              AutId
	n += wire.VarIntSerializeSize(uint64(len(script.autMemo))) + len(script.autMemo) // autMemo                    []byte
	n += wire.VarIntSerializeSize(script.plannedTotalSupply)                         // plannedTotalSupply         uint64
	n += wire.VarIntSerializeSize(uint64(len(script.issuers)))                       // issuers                    []*AutIssuer
	for _, issuer := range script.issuers {
		n += issuer.serializeSize()
	}
	n += wire.VarIntSerializeSize(uint64(script.reregistrationExpireHeight)) // reregistrationExpireHeight int32

	n += 1 // reregisterThreshold        uint8
	n += 1 // mintThreshold              uint8
	n += 1 // inAutRootTokenNum          uint8
	n += 1 // outAutRootTokenNum         uint8

	n += wire.VarIntSerializeSize(uint64(len(script.scriptMemo))) + len(script.scriptMemo) // scriptMemo                 []byte

	return n
}

func (script *ReRegistrationScript) Serialize() ([]byte, error) {
	var err error

	w := bytes.NewBuffer(make([]byte, 0, script.serializeSize()))

	// version                    uint32
	if err = wire.WriteVarInt(w, 0, uint64(script.version)); err != nil {
		return nil, err
	}

	// scriptType                 AutScriptType
	if err = w.WriteByte(script.Type()); err != nil {
		return nil, err
	}

	// autIdentifier              AutId
	if _, err = w.Write(script.autIdentifier[:]); err != nil {
		return nil, err
	}

	// autMemo                    []byte
	if err = wire.WriteVarBytes(w, 0, script.autMemo); err != nil {
		return nil, err
	}

	// plannedTotalSupply         uint64
	if err = wire.WriteVarInt(w, 0, script.plannedTotalSupply); err != nil {
		return nil, err
	}

	// issuers                    []*AutIssuer
	if err = wire.WriteVarInt(w, 0, uint64(len(script.issuers))); err != nil {
		return nil, err
	}
	for _, issuer := range script.issuers {
		if err = issuer.write(w); err != nil {
			return nil, err
		}
	}

	// reregistrationExpireHeight int32
	if err = wire.WriteVarInt(w, 0, uint64(script.reregistrationExpireHeight)); err != nil {
		return nil, err
	}

	// reregisterThreshold        uint8
	if err = w.WriteByte(script.reregisterThreshold); err != nil {
		return nil, err
	}

	// mintThreshold              uint8
	if err = w.WriteByte(script.mintThreshold); err != nil {
		return nil, err
	}

	// inAutRootTokenNum         uint8
	if err = w.WriteByte(script.inAutRootTokenNum); err != nil {
		return nil, err
	}

	// outAutRootTokenNum         uint8
	if err = w.WriteByte(script.outAutRootTokenNum); err != nil {
		return nil, err
	}

	// scriptMemo                 []byte
	if err = wire.WriteVarBytes(w, 0, script.scriptMemo); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (script *ReRegistrationScript) Deserialize(serializedScript []byte) error {
	var err error

	r := bytes.NewReader(serializedScript)

	// version                    uint32
	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if version > math.MaxUint32 {
		return fmt.Errorf("readed version %d is too large", version)
	}
	script.version = uint32(version)

	// scriptType                 AutScriptType
	script.scriptType, err = r.ReadByte()
	if err != nil {
		return err
	}

	// autIdentifier              AutId
	if _, err = io.ReadFull(r, script.autIdentifier[:]); err != nil {
		return err
	}

	// autMemo                    []byte
	if script.autMemo, err = wire.ReadVarBytes(r, 0, MaxAutMemoLength, "autMemo"); err != nil {
		return err
	}

	// plannedTotalSupply         uint64
	if script.plannedTotalSupply, err = wire.ReadVarInt(r, 0); err != nil {
		return err
	}

	// issuers                    []*AutIssuer
	issuerNum, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if issuerNum > MaxIssuerNum {
		return fmt.Errorf("readed issuer num %d is too large", issuerNum)
	}
	script.issuers = make([]*AutIssuer, issuerNum)
	for i := uint64(0); i < issuerNum; i++ {
		issuer := &AutIssuer{}
		if err = issuer.read(r); err != nil {
			return err
		}
		script.issuers[i] = issuer
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
	script.reregistrationExpireHeight = int32(expireHeightRead)

	// reregisterThreshold        uint8
	script.reregisterThreshold, err = r.ReadByte()
	if err != nil {
		return err
	}

	// mintThreshold              uint8
	if script.mintThreshold, err = r.ReadByte(); err != nil {
		return err
	}

	// inAutRootTokenNum         uint8
	if script.inAutRootTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// outAutRootTokenNum         uint8
	if script.outAutRootTokenNum, err = r.ReadByte(); err != nil {
		return err
	}

	// scriptMemo                 []byte
	script.scriptMemo, err = wire.ReadVarBytes(r, 0, MaxScriptMemoLength, "scriptMemo")
	if err != nil {
		return err
	}

	return script.SanityCheck()
}

func (script *ReRegistrationScript) SanityCheck() error {

	// version                    uint32
	if _, ok := ctautwire.AutScriptVersionSet[script.version]; !ok {
		return fmt.Errorf("invalid version: %d", script.version)
	}

	// scriptType                 AutScriptType
	if script.scriptType != AutScriptTypeReRegistration {
		return fmt.Errorf("script.scriptType (%d) is not AutScriptTypeReRegistration", script.scriptType)
	}

	// autIdentifier              AutId

	// autMemo                    []byte
	if len(script.autMemo) > MaxAutMemoLength {
		return fmt.Errorf("script.autMemo length (%d) exceeds MaxAutMemoLength (%d)", len(script.autMemo), MaxAutMemoLength)
	}

	// plannedTotalSupply         uint64
	if script.plannedTotalSupply == 0 || script.plannedTotalSupply > MaxAmount {
		return fmt.Errorf("script.plannedTotalSupply (%d) is not in [1, %d]", script.plannedTotalSupply, MaxAmount)
	}

	// issuers                    []*AutIssuer
	if len(script.issuers) == 0 || len(script.issuers) > MaxIssuerNum {
		return fmt.Errorf("the number of issuers (%d) is not in [1, %d]", len(script.issuers), MaxIssuerNum)
	}
	issuersMap := make(map[string]int, len(script.issuers))
	for i, issuer := range script.issuers {
		issuerStr := issuer.String()
		if index, ok := issuersMap[issuerStr]; ok {
			return fmt.Errorf("issuers[%d] and issuers[%d] are repeated : %s", i, index, issuerStr)
		}
		issuersMap[issuerStr] = i
	}

	// reregistrationExpireHeight int32
	if script.reregistrationExpireHeight < InfiniteExpireHeight || script.reregistrationExpireHeight > math.MaxInt32 {
		return fmt.Errorf("script.reregistrationExpireHeight (%d) is not in [-1, %d]",
			script.reregistrationExpireHeight, math.MaxInt32)
	}

	// reregisterThreshold        uint8
	if int(script.reregisterThreshold) == 0 {
		return fmt.Errorf("script.reregisterThreshold (%d) is invalid",
			script.reregisterThreshold)
	}
	if int(script.reregisterThreshold) > len(script.issuers) {
		return fmt.Errorf("script.reregisterThreshold (%d) exceeds the number of issuers (%d)",
			script.reregisterThreshold, len(script.issuers))
	}

	// mintThreshold              uint8
	if int(script.mintThreshold) == 0 {
		return fmt.Errorf("script.mintThreshold (%d) is invalid",
			script.mintThreshold)
	}
	if int(script.mintThreshold) > len(script.issuers) {
		return fmt.Errorf("script.mintThreshold (%d) exceeds the number of issuers (%d)",
			script.mintThreshold, len(script.issuers))
	}

	// inAutRootTokenNum         uint8
	if int(script.inAutRootTokenNum) == 0 {
		return fmt.Errorf("script.inAutRootTokenNum (%d) is invalid",
			script.inAutRootTokenNum)
	}
	if int(script.inAutRootTokenNum) > MaxNumToken {
		return fmt.Errorf("script.inAutRootTokenNum (%d) exceeds the allowed max number (%d)",
			script.inAutRootTokenNum, MaxNumToken)
	}

	// outAutRootTokenNum         uint8
	if int(script.outAutRootTokenNum) == 0 {
		return fmt.Errorf("script.outAutRootTokenNum (%d) is invalid",
			script.outAutRootTokenNum)
	}
	if int(script.outAutRootTokenNum) > MaxNumToken {
		return fmt.Errorf("script.outAutRootTokenNum (%d) exceeds the allowed max number (%d)",
			script.outAutRootTokenNum, MaxNumToken)
	}

	// scriptMemo                 []byte
	if len(script.scriptMemo) > MaxScriptMemoLength {
		return fmt.Errorf("len(script.scriptMemo) (%d) is too large", len(script.scriptMemo))
	}

	return nil
}

func (script *ReRegistrationScript) NumConsumedTokens() int {
	return int(script.inAutRootTokenNum)
}
func (script *ReRegistrationScript) NumGeneratedTokens() int {
	return int(script.outAutRootTokenNum)
}

var _ AutScript = &ReRegistrationScript{}

// MintScript would be the structured script parsed from memo in host transaction,
// 1. the minted amount with such a script MUST be explicit specified
// 2. the number of generated Hidden-Token and Plain-Token MUST be explicitly specified, and corresponding value scripts
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
	inAutRootTokenNum uint8

	// outHiddenAutTokenNum and outPublicAutTokenNum together specify the number of generated AutTokens by the host-Tx.
	// They are used to locate the start and end Txo of the host-Tx, which should be parsed as AutTokens.
	// The RULE is (a) the FIRST outHiddenAutTokenNum pseudonym Txo of the host-Tx should be HiddenAutTxo,
	// and then (b) the following outPublicAutTokenNum pseudonym Txo of the host-Tx should be publicAutTxo.
	outHiddenAutTokenNum uint8
	outPublicAutTokenNum uint8
	serializedAutTxos    [][]byte // length = outHiddenAutTokenNum + outPublicAutTokenNum
	witnessHash          chainhash.Hash

	scriptMemo []byte
}

func (script *MintScript) Vin() uint64 {
	return script.vin
}

func (script *MintScript) InAutRootTokenNum() uint8 {
	return script.inAutRootTokenNum
}

func (script *MintScript) OutHiddenAutTokenNum() uint8 {
	return script.outHiddenAutTokenNum
}

func (script *MintScript) OutPublicAutTokenNum() uint8 {
	return script.outPublicAutTokenNum
}

func (script *MintScript) SerializedAutTxos() [][]byte {
	return script.serializedAutTxos
}

func (script *MintScript) WitnessHash() chainhash.Hash {
	return script.witnessHash
}

func (script *MintScript) ScriptMemo() []byte {
	return script.scriptMemo
}

func NewMintScript(version uint32,
	autIdentifier AutId,
	vin uint64, inAutRootTokenNum uint8,
	outCTAutTokenNum uint8, outPlainAutTokenNum uint8, serializedAutTxos [][]byte,
	witnessHash chainhash.Hash,
	scriptMemo []byte) *MintScript {

	return &MintScript{
		version:              version,
		scriptType:           AutScriptTypeMint,
		autIdentifier:        autIdentifier,
		vin:                  vin,
		inAutRootTokenNum:    inAutRootTokenNum,
		outHiddenAutTokenNum: outCTAutTokenNum,
		outPublicAutTokenNum: outPlainAutTokenNum,
		serializedAutTxos:    serializedAutTxos,
		witnessHash:          witnessHash,
		scriptMemo:           scriptMemo,
	}
}

func (script *MintScript) Version() uint32 {
	return script.version
}

func (script *MintScript) Type() AutScriptType {
	return script.scriptType
}
func (script *MintScript) AutIdentifier() AutId {
	return script.autIdentifier
}

func (script *MintScript) serializeSize() int {
	n := wire.VarIntSerializeSize(uint64(script.version)) // version                    uint32
	n += 1                                                // scriptType                 AutScriptType
	n += chainhash.HashSize                               // autIdentifier              AutId

	n += wire.VarIntSerializeSize(script.vin) // vin                  uint64
	n += 1                                    // inAutRootTokenNum    uint8
	n += 1                                    // outHiddenAutTokenNum uint8
	n += 1                                    // outPublicAutTokenNum uint8

	n += wire.VarIntSerializeSize(uint64(len(script.serializedAutTxos))) // serializedAutTxos    [][]byte
	for _, serializedAutTxo := range script.serializedAutTxos {
		n += wire.VarIntSerializeSize(uint64(len(serializedAutTxo))) + len(serializedAutTxo)
	}

	n += chainhash.HashSize                                                                // witnessHash          chainhash.Hash
	n += wire.VarIntSerializeSize(uint64(len(script.scriptMemo))) + len(script.scriptMemo) // scriptMemo                 []byte

	return n
}

func (script *MintScript) Serialize() ([]byte, error) {
	var err error

	w := bytes.NewBuffer(make([]byte, 0, script.serializeSize()))

	// version                    uint32
	if err = wire.WriteVarInt(w, 0, uint64(script.version)); err != nil {
		return nil, err
	}

	// scriptType                 AutScriptType
	if err = w.WriteByte(script.Type()); err != nil {
		return nil, err
	}

	// autIdentifier              AutId
	if _, err = w.Write(script.autIdentifier[:]); err != nil {
		return nil, err
	}

	// vin                  uint64
	if err = wire.WriteVarInt(w, 0, script.vin); err != nil {
		return nil, err
	}

	// inAutRootTokenNum    uint8
	if err = w.WriteByte(script.inAutRootTokenNum); err != nil {
		return nil, err
	}

	// outHiddenAutTokenNum uint8
	if err = w.WriteByte(script.outHiddenAutTokenNum); err != nil {
		return nil, err
	}

	// outPublicAutTokenNum uint8
	if err = w.WriteByte(script.outPublicAutTokenNum); err != nil {
		return nil, err
	}

	// serializedAutTxos    [][]byte
	if err = wire.WriteVarInt(w, 0, uint64(len(script.serializedAutTxos))); err != nil {
		return nil, err
	}
	for _, serializedAutTxo := range script.serializedAutTxos {
		if err = wire.WriteVarBytes(w, 0, serializedAutTxo); err != nil {
			return nil, err
		}
	}

	// witnessHash          chainhash.Hash
	if _, err = w.Write(script.witnessHash[:]); err != nil {
		return nil, err
	}

	// scriptMemo                 []byte
	if err = wire.WriteVarBytes(w, 0, script.scriptMemo); err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

func (script *MintScript) Deserialize(serializedScript []byte) error {
	var err error

	r := bytes.NewReader(serializedScript)

	// version                    uint32
	version, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if version > math.MaxUint32 {
		return fmt.Errorf("readed version %d is too large", version)
	}
	script.version = uint32(version)

	// scriptType                 AutScriptType
	script.scriptType, err = r.ReadByte()
	if err != nil {
		return err
	}

	// autIdentifier              AutId
	if _, err = io.ReadFull(r, script.autIdentifier[:]); err != nil {
		return err
	}

	// vin                  uint64
	if script.vin, err = wire.ReadVarInt(r, 0); err != nil {
		return err
	}

	// inAutRootTokenNum    uint8
	script.inAutRootTokenNum, err = r.ReadByte()
	if err != nil {
		return err
	}

	// outHiddenAutTokenNum    uint8
	script.outHiddenAutTokenNum, err = r.ReadByte()
	if err != nil {
		return err
	}

	// inAutRootTokenNum    uint8
	script.outPublicAutTokenNum, err = r.ReadByte()
	if err != nil {
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
	script.serializedAutTxos = make([][]byte, autTxoNum)
	for i := uint64(0); i < autTxoNum; i++ {
		if script.serializedAutTxos[i], err = wire.ReadVarBytes(r, 0, MaxAutTxoLength, "SerializedAutTxo"); err != nil {
			return err
		}
	}

	// witnessHash          chainhash.Hash
	if _, err = io.ReadFull(r, script.witnessHash[:]); err != nil {
		return err
	}

	// scriptMemo                 []byte
	script.scriptMemo, err = wire.ReadVarBytes(r, 0, MaxScriptMemoLength, "scriptMemo")
	if err != nil {
		return err
	}

	return script.SanityCheck()
}

func (script *MintScript) SanityCheck() error {

	// version                    uint32
	if _, ok := ctautwire.AutScriptVersionSet[script.version]; !ok {
		return fmt.Errorf("invalid version: %d", script.version)
	}

	// scriptType                 AutScriptType
	if script.scriptType != AutScriptTypeMint {
		return fmt.Errorf("script.scriptType (%d) is not AutScriptTypeMint", script.scriptType)
	}

	// autIdentifier              AutId

	// vin                  uint64
	if script.vin == 0 || script.vin > MaxAmount {
		return fmt.Errorf("script.vin (%d) is not in [1, %d]", script.vin, MaxAmount)
	}

	// inAutRootTokenNum    uint8
	if int(script.inAutRootTokenNum) == 0 {
		return fmt.Errorf("script.inAutRootTokenNum (%d) is invalid",
			script.inAutRootTokenNum)
	}
	if int(script.inAutRootTokenNum) > MaxNumToken {
		return fmt.Errorf("script.inAutRootTokenNum (%d) exceeds the allowed max number (%d)",
			script.inAutRootTokenNum, MaxNumToken)
	}

	// outHiddenAutTokenNum uint8
	if int(script.outHiddenAutTokenNum) > MaxNumHiddenToken {
		return fmt.Errorf("script.outHiddenAutTokenNum (%d) exceeds the allowed max number (%d)",
			script.outHiddenAutTokenNum, MaxNumHiddenToken)
	}

	// outPublicAutTokenNum uint8
	if int(script.outPublicAutTokenNum) > MaxNumToken {
		return fmt.Errorf("script.outPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			script.outPublicAutTokenNum, MaxNumToken)
	}

	if script.outHiddenAutTokenNum+script.outPublicAutTokenNum == 0 {
		return fmt.Errorf("script.outHiddenAutTokenNum (%d) + script.outPublicAutTokenNum (%d) is 0",
			script.outHiddenAutTokenNum, script.outPublicAutTokenNum)
	}

	if script.outHiddenAutTokenNum+script.outPublicAutTokenNum > MaxNumToken {
		return fmt.Errorf("script.outHiddenAutTokenNum (%d) + script.outPublicAutTokenNum (%d) exceeds the allowed max number (%d)",
			script.outHiddenAutTokenNum, script.outPublicAutTokenNum, MaxNumToken)
	}

	// serializedAutTxos    [][]byte
	if len(script.serializedAutTxos) != int(script.outHiddenAutTokenNum+script.outPublicAutTokenNum) {
		return fmt.Errorf("the number of serializedAutTxos (%d) does equal script.outHiddenAutTokenNum (%d) + script.outPublicAutTokenNum (%d)",
			len(script.serializedAutTxos), script.outHiddenAutTokenNum, script.outPublicAutTokenNum)
	}
	for i := 0; i < len(script.serializedAutTxos); i++ {
		autTxo := &ctautwire.AutTxo{}
		err := autTxo.Deserialize(script.serializedAutTxos[i])
		if err != nil {
			return err
		}
		if autTxo.Version != script.version {
			return fmt.Errorf("version mismatch (autTxo.Version %d != script.version %d)", autTxo.Version, script.version)
		}

		// todo: cyclic import?
		autTxoType, err := abecryptox.GetAutTxoType(autTxo)
		if err != nil {
			return err
		}
		if i < int(script.outHiddenAutTokenNum) {
			if autTxoType != abecryptox.AutTxoTypeHidden {
				return fmt.Errorf("script.outHiddenAutTokenNum = %d, but %d -th AutTxo has type %d (not AutTxoTypeHidden)",
					script.outHiddenAutTokenNum, autTxoType, abecryptox.AutTxoTypeHidden)
			}
		} else {
			if autTxoType != abecryptox.AutTxoTypePublic {
				return fmt.Errorf("script.outHiddenAutTokenNum = %d, script.outPublicAutTokenNum =%d, but %d -th AutTxo has type %d (not AutTxoTypePublic)",
					script.outHiddenAutTokenNum, script.outPublicAutTokenNum, autTxoType, abecryptox.AutTxoTypePublic)
			}
		}
	}

	// witnessHash          chainhash.Hash

	// scriptMemo                 []byte
	if len(script.scriptMemo) > MaxScriptMemoLength {
		return fmt.Errorf("len(script.scriptMemo) (%d) is too large", len(script.scriptMemo))
	}

	return nil
}

func (script *MintScript) NumConsumedTokens() int {
	return int(script.inAutRootTokenNum)
}
func (script *MintScript) NumGeneratedTokens() int {
	return int(script.outHiddenAutTokenNum + script.outPublicAutTokenNum)
}

var _ AutScript = &MintScript{}

// TransferScript would be the structured script parsed from memo in host transaction,
// 1. the number of consumed CT-Token and Plain-Token MUST be explicit specified
// 2. the number of generated CT-Token and Plain-Token MUST be explicit specified, and corresponding value scripts
// 3. the witness hash would be computed from AutWitness in host transaction
// 3. consumedTokens would be populated with the help of host transaction and corresponding wire.TxoRing
// 4. generatedTokens would be populated with the function populateGeneratedCTAUTTokens with the help of host transaction
//
// TransferScript would be serialized with following format
// <Common Prefix> "CTAUTSCRIPT" "3"
// <Identifier> a byte array with fixed length
// <Number of CTAUTTokens> A number n, Explicitly specify the 0~(m-1)-th pseudonym TXO of outputs in host transaction as CT-Token
// <Number of PlainTokens> A number m, Explicitly specify the n~(n+m-1)-th pseudonym TXO of outputs in host transaction as Plain-Token
// <Number of CTAUTTokens> A number i, Explicitly specify the 0~(i-1)-th pseudonym TXO of outputs in host transaction as CT-Token
// <Number of PlainTokens> A number j, Explicitly specify the i~(i+j-1)-th pseudonym TXO of outputs in host transaction as Plain-Token
// <ValueScript> an array of n byte array, represent the amount for an AUTToken
// <WitnessHash> a byte array with fixed length
// <Memo> a byte array with max length, for this transaction
type TransferScript struct {
	version       uint32
	scriptType    AutScriptType
	autIdentifier AutId

	inHiddenAutTokenNum uint8
	inPublicAutTokenNum uint8

	outHiddenAutTokenNum uint8
	outPublicAutTokenNum uint8
	valueScripts         [][]byte // todo: defined as serializedAutTxos? why not autTxos

	witnessHash chainhash.Hash
	scriptMemo  []byte // todo: scriptMemo
}

func (script *TransferScript) WitnessHash() chainhash.Hash {
	return script.witnessHash
}

func (script *TransferScript) Version() uint32 {
	return script.version
}

func NewTransferScript(
	version uint32,
	autIdentifier AutId,
	inHiddenAutTokenNum uint8,
	inPublicAutTokenNum uint8,
	outHiddenAutTokenNum uint8,
	outPlainAutTokenNum uint8,
	autTxoScripts [][]byte,
	witnessHash chainhash.Hash,
	scriptMemo []byte,
) *TransferScript {
	return &TransferScript{
		version:              version,
		scriptType:           AutScriptTypeTransfer,
		autIdentifier:        autIdentifier,
		inHiddenAutTokenNum:  inHiddenAutTokenNum,
		inPublicAutTokenNum:  inPublicAutTokenNum,
		outHiddenAutTokenNum: outHiddenAutTokenNum,
		outPublicAutTokenNum: outPlainAutTokenNum,
		valueScripts:         autTxoScripts,
		witnessHash:          witnessHash,
		scriptMemo:           scriptMemo,
	}
}

func (script *TransferScript) Type() AutScriptType {
	return script.scriptType
}

func (script *TransferScript) AutIdentifier() AutId {
	return script.autIdentifier
}

func (script *TransferScript) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var err error

	// todo: necessary to use a function?
	if err = writePrefix(&b, script.version, script.scriptType, script.autIdentifier); err != nil {
		return nil, err
	}

	if err = b.WriteByte(script.inHiddenAutTokenNum); err != nil {
		return nil, err
	}
	if err = b.WriteByte(script.inPublicAutTokenNum); err != nil {
		return nil, err
	}

	if err = b.WriteByte(script.outHiddenAutTokenNum); err != nil {
		return nil, err
	}
	if err = b.WriteByte(script.outPublicAutTokenNum); err != nil {
		return nil, err
	}

	// todo: necessary to use a function?
	if err = writeCTAUTTxoScripts(&b, script.valueScripts); err != nil {
		return nil, err
	}

	// todo: necessary to use a function?
	if err = writeWitnessHash(&b, script.witnessHash); err != nil {
		return nil, err
	}

	// todo: necessary to use a function?
	if err = writeMemo(&b, script.scriptMemo); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
func (script *TransferScript) Deserialize(serializedScript []byte) error {
	var err error

	r := bytes.NewReader(serializedScript)

	// todo: necessary to use a function?
	if script.version, script.autIdentifier, script.scriptType, err = readPrefix(r, AutScriptTypeTransfer); err != nil {
		return err
	}

	if script.inHiddenAutTokenNum, err = ReadByte(r); err != nil {
		return err
	}
	if script.inPublicAutTokenNum, err = ReadByte(r); err != nil {
		return err
	}

	if script.outHiddenAutTokenNum, err = ReadByte(r); err != nil {
		return err
	}
	if script.outPublicAutTokenNum, err = ReadByte(r); err != nil {
		return err
	}

	// todo: necessary to use a function?
	if script.valueScripts, err = readCTAUTTxoScript(r, int(script.outHiddenAutTokenNum), int(script.outPublicAutTokenNum)); err != nil {
		return err
	}

	// todo: necessary to use a function?
	if script.witnessHash, err = readWitnessHash(r); err != nil {
		return err
	}

	// todo: necessary to use a function?
	if script.scriptMemo, err = readMemo(r); err != nil {
		return err
	}

	// todo: sanity check here, so that the above checks could be optimized.
	if err = script.SanityCheck(); err != nil {
		return err
	}
	return nil
}

func (script *TransferScript) SanityCheck() error {
	// todo(ctaut): check version

	if script.scriptType != AutScriptTypeTransfer {
		return errors.New("unexpected type for transfer script")
	}

	if script.inHiddenAutTokenNum+script.inPublicAutTokenNum == 0 {
		return ErrInValidAUTTx
	}
	if script.outHiddenAutTokenNum+script.outPublicAutTokenNum == 0 {
		return ErrInValidAUTTx
	}

	if int(script.outHiddenAutTokenNum) > MaxNumHiddenToken {
		return ErrInValidAUTTx
	}
	if len(script.valueScripts) != int(script.outHiddenAutTokenNum)+int(script.outPublicAutTokenNum) {
		return ErrInValidAUTTx
	}

	for i := 0; i < len(script.valueScripts); i++ {
		autTxo := &ctautwire.AutTxo{}
		err := autTxo.Deserialize(script.valueScripts[i])
		if err != nil {
			return err
		}

		autTxoType, err := abecryptox.GetAutTxoType(autTxo)
		if err != nil {
			return ErrInValidAUTTx
		}
		if i < int(script.outHiddenAutTokenNum) {
			if autTxoType != abecryptox.AutTxoTypeHidden {
				return ErrInValidAUTTx
			}
		} else {
			if autTxoType != abecryptox.AutTxoTypePublic {
				return ErrInValidAUTTx
			}
		}
	}

	if len(script.scriptMemo) > MaxScriptMemoLength {
		return ErrInValidAUTTx
	}

	return nil
}

func (script *TransferScript) NumConsumedTokens() int {
	return int(script.inHiddenAutTokenNum + script.inPublicAutTokenNum)
}
func (script *TransferScript) NumGeneratedTokens() int {
	return int(script.outHiddenAutTokenNum + script.outPublicAutTokenNum)
}

var _ AutScript = &TransferScript{}

// BurnScript would be the structured script parsed from memo in host transaction,
// 1. the number of consumed CT-Token and Plain-Token MUST be explicit specified
// 2. the number of generated CT-Token and Plain-Token MUST be explicit specified, and corresponding value scripts,
// and NOTE THAT the first Plain-Token would be marked burned -> TODO add check logic
// 3. the witness hash would be computed from AutWitness in host transaction
// 3. consumedTokens would be populated with the help of host transaction and corresponding wire.TxoRing
// 4. generatedTokens would be populated with the function populateGeneratedCTAUTTokens with the help of host transaction
//
// BurnScript would be serialized with following format
// <Common Prefix> "CTAUTSCRIPT" "4"
// <Identifier> a byte array with fixed length
// <Number of CTAUTTokens> A number n, Explicitly specify the 0~(m-1)-th pseudonym TXO of outputs in host transaction as CT-Token
// <Number of PlainTokens> A number m, Explicitly specify the n~(n+m-1)-th pseudonym TXO of outputs in host transaction as Plain-Token
// <Number of CTAUTTokens> A number i, Explicitly specify the 0~(i-1)-th pseudonym TXO of outputs in host transaction as CT-Token
// <Number of PlainTokens> A number j, Explicitly specify the i~(i+j-1)-th pseudonym TXO of outputs in host transaction as Plain-Token
// <ValueScript> an array of n byte array, represent the amount for an AUTToken
// <WitnessHash> a byte array with fixed length
// <Memo> a byte array with max length, for this transaction
type BurnScript struct {
	version       uint32
	scriptType    AutScriptType
	autIdentifier AutId

	inCTAutTokenNum     uint8
	inPlainAutTokenNum  uint8
	outCTAutTokenNum    uint8
	outPlainAutTokenNum uint8
	valueScripts        [][]byte // todo: defined as serializedAutTxos? why not autTxos

	witnessHash chainhash.Hash
	scriptMemo  []byte // todo: scriptMemo
}

func (script *BurnScript) WitnessHash() chainhash.Hash {
	return script.witnessHash
}

func (script *BurnScript) Version() uint32 {
	return script.version
}

func NewBurnScript(
	version uint32,
	autIdentifier AutId,
	inCTAutTokenNum uint8,
	inPlainAutTokenNum uint8,
	outCTAutTokenNum uint8,
	outPlainAutTokenNum uint8,
	valueScripts [][]byte,
	witnessHash chainhash.Hash,
	scriptMemo []byte,
) *BurnScript {
	return &BurnScript{
		version:             version,
		scriptType:          AutScriptTypeBurn,
		autIdentifier:       autIdentifier,
		inCTAutTokenNum:     inCTAutTokenNum,
		inPlainAutTokenNum:  inPlainAutTokenNum,
		outCTAutTokenNum:    outCTAutTokenNum,
		outPlainAutTokenNum: outPlainAutTokenNum,
		valueScripts:        valueScripts,
		witnessHash:         witnessHash,
		scriptMemo:          scriptMemo,
	}
}

func (script *BurnScript) Type() AutScriptType {
	return script.scriptType
}

func (script *BurnScript) AutIdentifier() AutId {
	return script.autIdentifier
}

func (script *BurnScript) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var err error

	// todo: necessary to use a function?
	if err = writePrefix(&b, script.version, script.scriptType, script.autIdentifier); err != nil {
		return nil, err
	}

	if err = b.WriteByte(script.inCTAutTokenNum); err != nil {
		return nil, err
	}
	if err = b.WriteByte(script.inPlainAutTokenNum); err != nil {
		return nil, err
	}

	if err = b.WriteByte(script.outCTAutTokenNum); err != nil {
		return nil, err
	}
	if err = b.WriteByte(script.outPlainAutTokenNum); err != nil {
		return nil, err
	}

	// todo: necessary to use a function?
	if err = writeCTAUTTxoScripts(&b, script.valueScripts); err != nil {
		return nil, err
	}

	// todo: necessary to use a function?
	if err = writeWitnessHash(&b, script.witnessHash); err != nil {
		return nil, err
	}

	// todo: necessary to use a function?
	if err = writeMemo(&b, script.scriptMemo); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// todo(ctaut): add a standalone sanity-check function, and call it at the end of deserialize
func (script *BurnScript) Deserialize(serializedScript []byte) error {
	var err error

	r := bytes.NewReader(serializedScript)

	// todo: necessary to use a function?
	if script.version, script.autIdentifier, script.scriptType, err = readPrefix(r, AutScriptTypeBurn); err != nil {
		return err
	}

	if script.inCTAutTokenNum, err = ReadByte(r); err != nil {
		return err
	}
	if script.inPlainAutTokenNum, err = ReadByte(r); err != nil {
		return err
	}

	if script.outCTAutTokenNum, err = ReadByte(r); err != nil {
		return err
	}
	if script.outPlainAutTokenNum, err = ReadByte(r); err != nil {
		return err
	}

	// todo: necessary to use a function?
	if script.valueScripts, err = readCTAUTTxoScript(r, int(script.outCTAutTokenNum), int(script.outPlainAutTokenNum)); err != nil {
		return err
	}

	// todo: necessary to use a function?
	if script.witnessHash, err = readWitnessHash(r); err != nil {
		return err
	}

	// todo: necessary to use a function?
	if script.scriptMemo, err = readMemo(r); err != nil {
		return err
	}

	//	todo: sanity check can optimize the above checks
	if err = script.SanityCheck(); err != nil {
		return err
	}

	return nil
}
func (script *BurnScript) SanityCheck() error {
	// todo(ctaut): check version

	if script.scriptType != AutScriptTypeBurn {
		return errors.New("unexpected type for burn script")
	}

	if script.inCTAutTokenNum+script.inPlainAutTokenNum == 0 {
		return ErrInValidAUTTx
	}
	if script.outCTAutTokenNum+script.outPlainAutTokenNum == 0 {
		return ErrInValidAUTTx
	}

	if int(script.outCTAutTokenNum) > MaxNumHiddenToken {
		return ErrInValidAUTTx
	}
	if len(script.valueScripts) != int(script.outCTAutTokenNum)+int(script.outPlainAutTokenNum) {
		return ErrInValidAUTTx
	}

	for i := 0; i < len(script.valueScripts); i++ {
		autTxo := &ctautwire.AutTxo{}
		err := autTxo.Deserialize(script.valueScripts[i])
		if err != nil {
			return err
		}
		autTxoType, err := abecryptox.GetAutTxoType(autTxo)
		if err != nil {
			return ErrInValidAUTTx
		}
		if i < int(script.outCTAutTokenNum) {
			if autTxoType != abecryptox.AutTxoTypeHidden {
				return ErrInValidAUTTx
			}
		} else {
			if autTxoType != abecryptox.AutTxoTypePublic {
				return ErrInValidAUTTx
			}
		}
	}

	// todo: the burned one must be plainAut

	if len(script.scriptMemo) > MaxScriptMemoLength {
		return ErrInValidAUTTx
	}

	return nil
}
func (script *BurnScript) NumConsumedTokens() int {
	return int(script.inCTAutTokenNum + script.inPlainAutTokenNum)
}
func (script *BurnScript) NumGeneratedTokens() int {
	return int(script.outCTAutTokenNum + script.outPlainAutTokenNum)
}

var _ AutScript = &BurnScript{}

var ErrNonAutTx = errors.New("not a AUT transaction")
var ErrInValidAUTTx = errors.New("not a valid AUT transaction")

// PackageAutScript packages an AutScript to a packagedAutScript, where
// packagedAutScript = commonPrefix (="AUTSCRIPT") || version (in VarInt form) || serializedAutScript (in VarBytes form).
func PackageAutScript(script AutScript) (packagedAutScript []byte, err error) {

	serializedScript, err := script.Serialize()
	if err != nil {
		return nil, err
	}

	length := len([]byte(commonPrefix))
	length += wire.VarIntSerializeSize(uint64(script.Version()))

	length += wire.VarIntSerializeSize(uint64(len(serializedScript))) + len(serializedScript)

	w := bytes.NewBuffer(make([]byte, 0, length))

	_, err = w.Write([]byte(commonPrefix))
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(w, 0, uint64(script.Version()))
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(w, 0, serializedScript)
	if err != nil {
		return nil, err
	}

	return w.Bytes(), nil
}

// UnpackageAutScript unpackages a packagedAutScript to an AutScript, where packagedAutScript is assumed to start from
// commonPrefix (="AUTSCRIPT") || version (in VarInt form) || serializedAutScript (in VarBytes form).
// A packagedAutScript does not satisfy this form will result an error returned.
func UnpackageAutScript(packagedAutScript []byte) (AutScript, error) {
	commonPrefixLen := len([]byte(commonPrefix))
	if len(packagedAutScript) < commonPrefixLen {
		return nil, fmt.Errorf("packagedAutScript is not well-form as expected")
	}

	if !bytes.Equal(packagedAutScript[:commonPrefixLen], []byte(commonPrefix)) {
		return nil, fmt.Errorf("packagedAutScript is not well-form as expected: not start with %s", commonPrefix)
	}

	r := bytes.NewReader(packagedAutScript[commonPrefixLen:])
	versionRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}
	if versionRead > math.MaxUint32 {
		return nil, fmt.Errorf("readed script version (%d) is too large", versionRead)
	}
	scriptVersion := uint32(versionRead)
	if _, ok := ctautwire.AutScriptVersionSet[scriptVersion]; !ok {
		return nil, fmt.Errorf("unknown version %d", scriptVersion)
	}

	serializedScript, err := wire.ReadVarBytes(r, 0, MaxAutScriptLength, "AutScript")
	if err != nil {
		return nil, err
	}

	// todo: if multiple versions are supported, may need to code here to run different branch
	switch scriptVersion {
	case ctautwire.AutScriptVersion_1:
		return deserializeAutScriptV1(serializedScript)

	default:
		return nil, fmt.Errorf("unknown aut script version %d", scriptVersion)
	}
}

// deserializeAutScriptV1 deserializes the serializedAutScript to an AutScript, where
// serializedAutScript is assumed to be the result of Serialize of AutScript with Version=AutScriptVersion_1.
// If the input serializedAutScript does not satisfy this requirement, an error will be returned.
func deserializeAutScriptV1(serializedAutScript []byte) (AutScript, error) {
	r := bytes.NewReader(serializedAutScript)

	versionRead, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}
	if versionRead > math.MaxUint32 {
		return nil, fmt.Errorf("readed script version (%d) is too large", versionRead)
	}
	scriptVersion := uint32(versionRead)
	if _, ok := ctautwire.AutScriptVersionSet[scriptVersion]; !ok {
		return nil, fmt.Errorf("unknown au script version %d", scriptVersion)
	}
	if scriptVersion != ctautwire.AutScriptVersion_1 {
		return nil, fmt.Errorf("the readed version %d is not AutScriptVersion_1", scriptVersion)
	}

	scriptType, err := r.ReadByte()
	if err != nil {
		return nil, err
	}

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

// ParseAutScript try to deserialize CTAUT script from transaction memo
// todo: rename memo to TxMemo
// todo: why not use a MsgTxAbe as input?
func ParseAutScript(txVersion uint32, txHash chainhash.Hash, memo []byte) (AutScript, error) {
	if txVersion < wire.TxVersion_Height_464000_Aconcagua {
		return nil, nil
	}

	commonPrefixLen := len([]byte(commonPrefix))

	// could not be an AUT transaction
	if len(memo) < commonPrefixLen {
		return nil, nil
	}
	if !bytes.Equal(memo[:commonPrefixLen], []byte(commonPrefix)) {
		return nil, nil
	}

	// RULE: if commonPrefix appears, the commonPrefix and its following bytes must be a well-formed packagedAutScript,
	// namely, commonPrefix || Version(in VarInt form) || serializedAutScript (in VarBytes form).
	autScript, err := UnpackageAutScript(memo)
	if err != nil {
		return nil, err
	}

	// check the script version with the host version
	// todo: use the ScriptVersion and TxVersion rule.
	expectedTxVersion, err := GetTxVersionFromAutScriptVersion(autScript.Version())
	if expectedTxVersion != txVersion {
		return nil, fmt.Errorf("autScript.Version() (%d) corresponds to TxVersion (%d), does not match TxVersion %d",
			autScript.Version(), expectedTxVersion, txVersion)
	}

	// populate the identifier for registration script
	if autScript.Type() == AutScriptTypeRegistration {
		registrationScript, ok := autScript.(*RegistrationScript)
		if !ok {
			return nil, fmt.Errorf("autScript.Type() (%d) is not RegistrationScript", autScript.Type())
		}
		registrationScript.autIdentifier = txHash
	}

	return autScript, nil
}

// todo(ctaut): this is for database storage or only memeory? why has CoinAddress and ValueScript?
// todo(ctaut): define an interface? only a case needs coinAddress.
// CTAUTToken holds the main information of token in memory, it would be used to check all rules
type CTAUTToken struct {
	// inherit from script
	Version uint32
	// used to track the host location on blockchain
	HostOutPoint HostOutPoint
	// For root token, value script would be nil,
	// For normal token, value script could be interpreted to either a public value or a hidden value
	// with abecryptox.ExtractAutTxoValue()
	// todo: serializedAutTxo, or AutTxo?
	ValueScript []byte // todo(ctaut): used to denote AUT value.
	// For all token, coin address would be used to indicate the ownership of token
	// For root token, it would be used match the claimed issuers to recognize operational permission
	// CoinAddress means the address on chain that a coin belongs to,
	// say, each coin on chain has a format (coinAddress, valueScript).
	// Do not limit the CoinAddress here to the concept in CryptoAddress in abecryptox package.
	// As Abelian-Txo belongs to CoinAddress, AutToken also belongs to CoinAddress.
	CoinAddress []byte
}

// todo: what is this?
// todo: rename
type EnhancedAutScript struct {
	AutScript

	// Note that for following 2 fields:
	// - if the value is nil, it means that the tokens is not set
	// - if the value is empty slice, it means that the tokens is set but has no token
	consumedTokens  []*CTAUTToken
	generatedTokens []*CTAUTToken
}

func (script *EnhancedAutScript) ConsumedTokens() ([]*CTAUTToken, error) {
	if script.consumedTokens == nil {
		return nil, errors.New("consumed tokens not set")
	}

	return script.consumedTokens, nil
}
func (script *EnhancedAutScript) setConsumedTokens(consumedTokens []*CTAUTToken) error {
	if len(consumedTokens) != script.NumConsumedTokens() {
		return errors.New("mismatched number of consumed tokens")
	}

	script.consumedTokens = consumedTokens
	return nil
}

func (script *EnhancedAutScript) GeneratedTokens() ([]*CTAUTToken, error) {
	if script.generatedTokens == nil {
		return nil, errors.New("generated tokens not set")
	}

	return script.generatedTokens, nil
}
func (script *EnhancedAutScript) setGeneratedTokens(generatedTokens []*CTAUTToken) error {
	if len(generatedTokens) != script.NumGeneratedTokens() {
		return errors.New("mismatched number of consumed tokens")
	}

	script.generatedTokens = generatedTokens

	return nil
}

// todo: AutMetadata
func (script *EnhancedAutScript) Metadata() (*AutMetadata, error) {
	if script.Type() != AutScriptTypeRegistration {
		return nil, errors.New("metadata only available for registration script")
	}
	if script.generatedTokens == nil {
		return nil, errors.New("generated tokens not set")
	}

	registerScript, ok := script.AutScript.(*RegistrationScript)
	if !ok {
		return nil, errors.New("metadata only available for registration script")
	}

	//issuers := make([][]byte, 0, len(script.generatedTokens))
	//issuerMapping := map[string]struct{}{}
	//for i := 0; i < len(script.generatedTokens); i++ {
	//	key := hex.EncodeToString(script.generatedTokens[i].CoinAddress)
	//	if _, ok := issuerMapping[key]; ok {
	//		continue
	//	}
	//	issuerMapping[key] = struct{}{}
	//	issuers = append(issuers, script.generatedTokens[i].CoinAddress)
	//}
	//if len(issuers) == 0 || len(issuers) > MaxIssuerNum {
	//	return nil, ErrInValidAUTTx
	//}
	//if int(registerScript.mintThreshold) == 0 || int(registerScript.mintThreshold) > len(issuers) {
	//	return nil, ErrInValidAUTTx
	//}
	//if int(registerScript.reregisterThreshold) == 0 || int(registerScript.reregisterThreshold) > len(issuers) {
	//	return nil, ErrInValidAUTTx
	//}

	rootTokenSet := map[string]*HostOutPoint{}
	for i := 0; i < len(script.generatedTokens); i++ {
		rootTokenSet[script.generatedTokens[i].HostOutPoint.String()] = &script.generatedTokens[i].HostOutPoint
	}
	metadata := &AutMetadata{
		Version:                    ctautwire.AutMetadataVersionInitValue,
		AutIdentifier:              registerScript.autIdentifier,
		AutName:                    registerScript.autName,
		AutSymbol:                  registerScript.autSymbol,
		BaseUnitName:               registerScript.baseUnitName,
		SubUnitName:                registerScript.subUnitName,
		UnitScale:                  registerScript.unitScale,
		AutMemo:                    registerScript.autMemo,
		PlannedTotalSupply:         registerScript.plannedTotalSupply,
		Issuers:                    registerScript.issuers,
		ReregistrationExpireHeight: registerScript.reregistrationExpireHeight,

		ReregistrationThreshold: registerScript.reregisterThreshold,
		MintThreshold:           registerScript.mintThreshold,

		MintedAmount:         0,
		BurnedAmount:         0,
		ActiveRootTokenSet:   rootTokenSet,
		UpdateScriptVersions: []uint32{registerScript.version},
	}
	return metadata, nil
}

// todo: AutMetadata
func (script *EnhancedAutScript) UpdateAutMetadata(metadata *AutMetadata) error {
	// assert
	if script.Type() != AutScriptTypeReRegistration {
		return errors.New("update metadata only available for re-registration script")
	}
	identifier := script.AutIdentifier()
	if !bytes.Equal(identifier[:], metadata.AutIdentifier[:]) {
		return ErrInValidAUTTx
	}
	consumedTokens := script.consumedTokens
	for i := 0; i < len(consumedTokens); i++ {
		if _, ok := metadata.ActiveRootTokenSet[consumedTokens[i].HostOutPoint.String()]; !ok {
			return fmt.Errorf("an re-registration AUT transaction try to update AUT "+
				"with non-existing/spent root token (%s,%d) for AUT identified by %s",
				consumedTokens[i].HostOutPoint.TxHash, consumedTokens[i].HostOutPoint.Index,
				metadata.AutIdentifier)
		}
		delete(metadata.ActiveRootTokenSet, consumedTokens[i].HostOutPoint.String())
	}

	// follow defined rules in AutScriptVersion
	metadata.Version += 1

	reregisterScript, ok := script.AutScript.(*ReRegistrationScript)
	if !ok {
		return errors.New("update metadata only available for re-registration script")
	}
	metadata.AutMemo = reregisterScript.autMemo

	//issuers := make([][]byte, 0, len(script.generatedTokens))
	//issuerMapping := map[string]struct{}{}
	//for i := 0; i < len(script.generatedTokens); i++ {
	//	key := hex.EncodeToString(script.generatedTokens[i].CoinAddress)
	//	if _, ok := issuerMapping[key]; ok {
	//		continue
	//	}
	//	issuerMapping[key] = struct{}{}
	//	issuers = append(issuers, script.generatedTokens[i].CoinAddress)
	//}
	//if len(issuers) == 0 || len(issuers) > MaxIssuerNum {
	//	return ErrInValidAUTTx
	//}
	//if int(reregisterScript.mintThreshold) == 0 || int(reregisterScript.mintThreshold) > len(issuers) {
	//	return ErrInValidAUTTx
	//}
	//if int(reregisterScript.reregisterThreshold) == 0 || int(reregisterScript.reregisterThreshold) > len(issuers) {
	//	return ErrInValidAUTTx
	//}

	// assert here?
	if metadata.MintedAmount > reregisterScript.plannedTotalSupply {
		return errors.New("re-registration transaction try to make planned amount less than minted amount")
	}
	metadata.PlannedTotalSupply = reregisterScript.plannedTotalSupply

	metadata.Issuers = reregisterScript.issuers
	metadata.ReregistrationThreshold = reregisterScript.reregisterThreshold
	metadata.MintThreshold = reregisterScript.mintThreshold
	metadata.ReregistrationExpireHeight = reregisterScript.reregistrationExpireHeight

	// remove previous root tokens
	metadata.ActiveRootTokenSet = make(map[string]*HostOutPoint, len(script.generatedTokens))
	for i := 0; i < len(script.generatedTokens); i++ {
		metadata.ActiveRootTokenSet[script.generatedTokens[i].HostOutPoint.String()] = &script.generatedTokens[i].HostOutPoint
	}

	// check
	if reregisterScript.version < metadata.UpdateScriptVersions[len(metadata.UpdateScriptVersions)-1] {
		return fmt.Errorf("the version of re-register script %d should not less than the largest version (%d) in UpdateScriptVersions",
			reregisterScript.version,
			metadata.UpdateScriptVersions[len(metadata.UpdateScriptVersions)-1],
		)
	}
	metadata.UpdateScriptVersions = append(metadata.UpdateScriptVersions, reregisterScript.version)

	return nil
}

// ExtractAutScript try to deserialize CTAUT script from transaction memo
// if success, it would :
// - extract the well-formed script from memo with sanity check:
//   - no conflict configuration
//   - no token parasitized in invalid host output
//
// - populate the generated tokens by CTAUT script by populateGeneratedTokens
//
// Note that the legality of consumed tokens and the effect of script MUST be checked
// with the help of instance on blockchain.
// - legality of host transaction input
//   - no double/duplicate spending token
//
// - legality of witness
// - effect on the instance
//   - no overflow
//
// todo: CTAUT to Aut?
// todo: what is the relation with Parse
// todo: rename to Aut
func ExtractAutScript(tx *wire.MsgTxAbe) (enhancedScript *EnhancedAutScript, err error) {
	if tx.Version < wire.TxVersion_Height_464000_Aconcagua {
		return nil, nil
	}
	// parse script from memo and check well-formedness
	autScript, err := ParseAutScript(tx.Version, tx.TxHash(), tx.TxMemo)
	if err != nil {
		return nil, err
	}
	if autScript == nil {
		return nil, nil
	}

	// populate the generated tokens with host transaction outputs
	enhancedScript = &EnhancedAutScript{
		AutScript:       autScript,
		consumedTokens:  nil,
		generatedTokens: nil,
	}
	tokens, err := GetGeneratedAutTokens(autScript, tx.TxHash(), tx.TxOuts)
	if err != nil {
		return nil, err
	}
	err = enhancedScript.setGeneratedTokens(tokens)
	if err != nil {
		return nil, err
	}

	switch script := autScript.(type) {
	case *RegistrationScript:
		// for inputs, there is no rules

		// for outputs, the claimed issuer tokens must match the generated tokens exactly
		// - all issuer tokens must appear
		// - no unclaimed issuer token appear
		if err = matchIssuers(script.issuers, tokens); err != nil {
			return nil, err
		}
	case *ReRegistrationScript:
		// for inputs, note that here is no enough information to
		// 1. check the legality of token
		// 2. check the re-register threshold is meet
		// Above checks have to be delayed until the instance could be seen

		// for outputs, the claimed issuer tokens must match the outputs exactly
		if err = matchIssuers(script.issuers, tokens); err != nil {
			return nil, err
		}
	case *MintScript:
		// for inputs, note that here is no enough information to
		// 1. check the legality of token
		// 2. check the mint threshold is meet
		// 3. check the balance proof
		// 4. check whether minted amount conflict with planned total amount
		// Above checks have to be delayed until the instance could be seen

		//witnessHash := chainhash.HashH(tx.AutWitness)
		//if !witnessHash.IsEqual(&script.witnessHash) {
		//	return nil, fmt.Errorf("mismatch witness for script")
		//}

	case *TransferScript:
		// for inputs, note that here is no enough information to
		// 1. check the legality of token
		// 2. check the balance proof
		// Above checks have to be delayed until the instance could be seen

		//witnessHash := chainhash.HashH(tx.AutWitness)
		//if !witnessHash.IsEqual(&script.witnessHash) {
		//	return nil, fmt.Errorf("mismatch witness for script")
		//}

	case *BurnScript:
		// for inputs, note that here is no enough information to
		// 1. check the legality of token
		// 2. check the balance proof
		// Above checks have to be delayed until the instance could be seen

		// for outputs, check the legality of burned token (a.k.a last generated token)
		// Above ParseCTAUTScript() ensures the length of valueScripts is not less than 1
		autTxo := &ctautwire.AutTxo{}
		err = autTxo.Deserialize(script.valueScripts[len(script.valueScripts)-1])
		if err != nil {
			return nil, err
		}
		autTxoType, err := abecryptox.GetAutTxoType(autTxo)
		if err != nil {
			return nil, fmt.Errorf("fail to get last aut txo type from burn script: %v", err)
		}
		// assert the last aut txo must be public
		if autTxoType != abecryptox.AutTxoTypePublic {
			return nil, fmt.Errorf("last aut txo type must not public")
		}

		//witnessHash := chainhash.HashH(tx.AutWitness)
		//if !witnessHash.IsEqual(&script.witnessHash) {
		//	return nil, fmt.Errorf("mismatch witness for script")
		//}
	default:
		return nil, ErrInValidAUTTx
	}

	return enhancedScript, nil
}

// PresetHostOutpointForCTAUT would preset the host outpoint for consumed tokens with the help of
// host transaction and ring
// todo: use the correcy HostOutPoint
func PresetHostOutpointForCTAUT(script *EnhancedAutScript, msgTx *wire.MsgTxAbe,
	lookupHostOutput func(ringHash chainhash.Hash) (*wire.TxOutAbe, error),
) error {
	if script == nil || script.AutScript == nil {
		return nil
	}
	if script.Type() == AutScriptTypeRegistration {
		return script.setConsumedTokens([]*CTAUTToken{})
	}
	txHash := msgTx.TxHash()

	hostedTxIns := msgTx.TxIns
	startIndex := 0
	for ; startIndex < len(hostedTxIns); startIndex++ {
		ringHash := hostedTxIns[startIndex].PreviousOutPointRing.Hash()
		txOut, err := lookupHostOutput(ringHash)
		if err != nil {
			return err
		}

		privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
		if err != nil {
			return err
		}

		// skip fully-privacy area
		if privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre ||
			privacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
			continue
		}

		if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			return fmt.Errorf("expect privacy level %d but got %d",
				abecryptoxkey.PrivacyLevelPSEUDONYMCT, privacyLevel)
		}
		break
	}

	numInCoins := script.NumConsumedTokens()
	if startIndex+numInCoins > len(hostedTxIns) {
		return fmt.Errorf("claim %d (root) coins but only remain %d outputs",
			numInCoins, len(hostedTxIns)-startIndex)
	}

	consumedTokens := make([]*CTAUTToken, numInCoins)
	for i := 0; i < len(consumedTokens); i++ {
		hostIndex := startIndex + i

		// sanity-check
		ringHash := hostedTxIns[hostIndex].PreviousOutPointRing.Hash()
		txOut, err := lookupHostOutput(ringHash)
		if err != nil {
			return err
		}

		privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
		if err != nil {
			return err
		}
		if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
			return fmt.Errorf("expect privacy level %d but got %d",
				abecryptoxkey.PrivacyLevelPSEUDONYMCT, privacyLevel)
		}

		// fill out with the first item in ring
		ringIdx := 0
		outpoint := HostOutPoint{
			TxHash: hostedTxIns[hostIndex].PreviousOutPointRing.OutPoints[ringIdx].TxHash,
			Index:  hostedTxIns[hostIndex].PreviousOutPointRing.OutPoints[ringIdx].Index,
		}

		coinAddress, err := CheckHostTxoParasiticity(outpoint.TxHash, outpoint.Index, txOut)
		if err != nil {
			return fmt.Errorf("transaction %s try to consume UTXO at Ring %s is not a valid output", txHash,
				hostedTxIns[hostIndex].PreviousOutPointRing.Hash())
		}

		// TODO would be check with populated version
		//err = abecryptox.AutRuleCheckOnTxInputVersion(hostedTxIns[hostIndex].PreviousOutPointRing.Version, msgTx.Version)
		//if err != nil {
		//	return fmt.Errorf("transaction %s try to consume CT-AUT token %s with version %d, but tx version is %d",
		//		txHash, outpoint,
		//		hostedTxIns[hostIndex].PreviousOutPointRing.Version, msgTx.Version)
		//}

		consumedTokens[i] = &CTAUTToken{
			Version:      ctautwire.AutScriptVersion_Unknown,
			HostOutPoint: outpoint,    // will be populated later with CTAUTViewpoint
			ValueScript:  nil,         // will be populated later with CTAUTViewpoint
			CoinAddress:  coinAddress, // required by root coin while optional for coin
		}
	}
	return script.setConsumedTokens(consumedTokens)
}

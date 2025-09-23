package ctaut

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"

	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
)

// OutPoint defines an aut data type that is used to track previous
// transaction outputs.
// todo(AUT): Hash --> TxHash
// refer to Abel.OutPoint? or Aut.(TxHash, Index)?
// type OutPoint wire.OutPointAbe
// or refer to OutPointAbe in the Txs?
type OutPoint struct {
	TxHash chainhash.Hash
	Index  uint8
}

// aut Name + tx Hash + index -> aut value
// tx Hash + index -> aut Name + aut value
// String returns the OutPoint in the human-readable form "hash:index".
func (o OutPoint) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.

	buf := make([]byte, 2*chainhash.HashSize+1, 2*chainhash.HashSize+1+10)
	copy(buf[:], o.TxHash.String())
	buf[2*chainhash.HashSize] = ':'
	buf = strconv.AppendUint(buf, uint64(o.Index), 10)
	return string(buf)
}

// todo(ctaut): this is for database storage or only memeory? why has CoinAddress and ValueScript?
type CTAUTToken struct {
	Version     uint32
	OutPoint           // todo(ctaut): HostOutPoint OutPoint
	ValueScript []byte // optional from root coin
	CoinAddress []byte
}

type TransactionType = uint8

// todo(ctaut): shift the Mint and ReRegistration?
const (
	Registration   TransactionType = 0
	Mint           TransactionType = 1
	ReRegistration TransactionType = 2
	Transfer       TransactionType = 3
	Burn           TransactionType = 4
)

// todo(ctaut): defined as []byte?
const CommonPrefix = "CTAUTSCRIPT"

const CommonPrefixLength = 11
const IdentifierLength = 64 // identifier
const MaxSymbolLength = 64  // symbol

const MaxAUTMemoLength = 1024
const MaxUnitLength = 20
const MaxMinUnitLength = 20

// todo(ctaut): shall be uint64(1)<<51 - 1 ?
const MaxAmount = uint64(1<<51 - 1)

// IssuerTokenLength would be length of coin address for pseudonym address (193)
const IssuerTokenLength = 193 // todo(ctaut): is this right? pseudonymCT ?
const MaxIssuerNum = 10       // todo(ctaut): Is this right?

// todo(ctaut): MaxAUTTxoScriptLength is not correct, it may be larger than 1024.
const MaxAUTTxoScriptLength = 1024
const MaxAUTTxMemoLength = 1024

type Transaction interface {
	Type() TransactionType
	Serialize() ([]byte, error)
	Deserialize(io.Reader) error

	AUTIdentifier() []byte

	NumTxInputs() int
	SetTxInputs(autTxIns []*CTAUTToken) error
	TxInputs() []*CTAUTToken

	NumTxOutputs() int
	setTxOutputs(autTxouts []*CTAUTToken) error
	TxOutputs() []*CTAUTToken
}

//const HashSize = 64

// Metadata hosts metadata information for registered Abelian User Token
// Different AUTs are uniquely distinguished and identified by identifiers
// In details:
// RegistrationTx would create a new one with unique CTAutIdentifier
// MintTx would update fields MintedAmount and RootCoinSet
// ReRegistrationTx would update fields other than CTAutIdentifier/ UnitName / MinUnitName /MintedAmount
// TransferTx would update no fields
// BurnTx would update no fields
type Metadata struct {
	CTAutIdentifier []byte // unique identifier
	CTAutSymbol     []byte // symbol for public view
	UnitName        []byte // can not chang anymore
	MinUnitName     []byte // can not chang anymore
	UnitScale       uint64 // can not change anymore
	AutMemo         []byte

	PlannedTotalAmount uint64 // can change with re-register
	// todo(AUT): using SHA3-512, define a standalone hash in AUT. Hash(CoinAddress)?
	IssuerTokens          [][]byte //[] coin address
	IssueTokensThreshold  uint8    // it works for all mint tx before next re-register where can change this field
	IssuerUpdateThreshold uint8    // it works for next re-register, and can change this field with next re-register
	ExpireHeight          int32    // next re-register must be before this height

	MintedAmount uint64
	// only records active root coins
	RootCoinSet map[OutPoint]struct{} // it works for all mint tx and next re-register tx before next re-register where would change this field
}

// Clone returns a shallow copy of the utxo entry.
func (info *Metadata) Clone() *Metadata {
	if info == nil {
		return nil
	}

	// ToDo(Alice): by the same order as the definition?
	cloned := &Metadata{
		CTAutIdentifier: make([]byte, len(info.CTAutIdentifier)),
		CTAutSymbol:     make([]byte, len(info.CTAutSymbol)),
		UnitName:        make([]byte, len(info.UnitName)),
		MinUnitName:     make([]byte, len(info.MinUnitName)),
		UnitScale:       info.UnitScale,
		AutMemo:         make([]byte, len(info.AutMemo)),

		IssuerTokens:          make([][]byte, len(info.IssuerTokens)),
		IssuerUpdateThreshold: info.IssuerUpdateThreshold,
		IssueTokensThreshold:  info.IssueTokensThreshold,
		PlannedTotalAmount:    info.PlannedTotalAmount,
		ExpireHeight:          info.ExpireHeight,

		MintedAmount: info.MintedAmount,
		RootCoinSet:  make(map[OutPoint]struct{}, len(info.RootCoinSet)),
	}
	copy(cloned.CTAutIdentifier, info.CTAutIdentifier)
	copy(cloned.CTAutSymbol, info.CTAutSymbol)
	copy(cloned.UnitName, info.UnitName)
	copy(cloned.MinUnitName, info.MinUnitName)
	copy(cloned.AutMemo, info.AutMemo)

	for i := 0; i < len(info.IssuerTokens); i++ {
		cloned.IssuerTokens[i] = make([]byte, len(info.IssuerTokens[i]))
		copy(cloned.IssuerTokens[i][:], info.IssuerTokens[i][:])
	}

	for outpoint := range info.RootCoinSet {
		newOutpoint := OutPoint{}
		copy(newOutpoint.TxHash[:], outpoint.TxHash[:])
		newOutpoint.Index = outpoint.Index

		cloned.RootCoinSet[newOutpoint] = struct{}{}
	}

	return cloned
}

// Flag = "CTAUTRegistration"
// <Identifier> a byte array with fixed length, would not be changed anymore
// <AUTName> a byte array with max length, would not be changed anymore
// [UnitName] a byte array with max length, would not be changed anymore
// [MinUnitName] a byte array with max length, would not be changed anymore
// [UnitScale] the scale between unit and minUnit, would not be changed anymore
// [AutMemo] a byte array with max length
//
// [Planed Total Amount] an integer range in [1, 1<<51 -1)
// <IssuerTokens> an array with length N of hash, each one represents a public key (represented by a pseudonym coin address)
// <IssuerUpdateThreshold> An integer update_t <= N
// <IssueTokensThreshold> An integer mint_t <= N
// <Expiry of IssuerTokens> a height value
//
// <Number of AUTRootCoins> A number n, explicitly specify the 0~(n-1)-th TXO of this transaction as RootCoins, all other TXOs are regarded as normal AbelianCoins.
// <Memo> a byte array with max length, for this transaction

// todo: RegistrationTx has its TxMemo, where a user can specify.
// and each AUT instance has its Memo (simialr to a description of the AutInstance).
// Why this is dupliating the Info?
// todo(Alice): for the common fields, using the same order as the definition, the particular fields
type RegistrationTx struct {
	CTAutIdentifier []byte // identifier // todo(ctaut): how to guarantee that there is no repeated identifier? how about use Hash?
	// todo(ctaut): use Hash(symbol, registeredTime)

	CTAutSymbol []byte // symbol
	UnitName    []byte
	MinUnitName []byte
	UnitScale   uint64
	AutMemo     []byte

	PlannedTotalAmount    uint64
	IssuerTokens          [][]byte
	IssueTokensThreshold  uint8 // todo(ctaut): MintThreshold
	IssuerUpdateThreshold uint8 // todo(ctaut): UpdateThreshold
	ExpireHeight          int32

	OutAutRootCoinNum uint8
	Memo              []byte

	TxIns  []*CTAUTToken
	TxOuts []*CTAUTToken
}

func (tx *RegistrationTx) Type() TransactionType {
	return Registration
}
func (tx *RegistrationTx) AUTIdentifier() []byte {
	return tx.CTAutIdentifier
}

func (tx *RegistrationTx) Serialize() ([]byte, error) {
	// todo(ctaut): initialize a space first?
	// w := bytes.NewBuffer(make([]byte, tx.SerializeSize()))
	var b bytes.Buffer
	var err error

	if err = writePrefix(b, Registration, tx.CTAutIdentifier); err != nil {
		return nil, err
	}

	if err = WriteVarBytes(&b, tx.CTAutSymbol); err != nil {
		return nil, err
	}

	if err = WriteVarBytes(&b, tx.UnitName); err != nil {
		return nil, err
	}

	if err = WriteVarBytes(&b, tx.MinUnitName); err != nil {
		return nil, err
	}

	if err = WriteVarInt(&b, tx.UnitScale); err != nil {
		return nil, err
	}

	if err = writeAutMemo(b, tx.AutMemo); err != nil {
		return nil, err
	}

	if err = WriteVarInt(&b, tx.PlannedTotalAmount); err != nil {
		return nil, err
	}

	if err = writeIssuerTokens(b, tx.IssuerTokens); err != nil {
		return nil, err
	}

	if err = b.WriteByte(tx.IssueTokensThreshold); err != nil {
		return nil, err
	}
	if err = b.WriteByte(tx.IssuerUpdateThreshold); err != nil {
		return nil, err
	}
	if err = WriteVarInt(&b, uint64(tx.ExpireHeight)); err != nil {
		return nil, err
	}

	if err = b.WriteByte(tx.OutAutRootCoinNum); err != nil {
		return nil, err
	}
	if err = writeMemo(b, tx.Memo); err != nil {
		return nil, err
	}

	// todo(ctaut): does not wrire TxIns and TxOuts?
	return b.Bytes(), nil
}
func (tx *RegistrationTx) Deserialize(r io.Reader) error {
	var err error

	if tx.CTAutIdentifier, err = readPrefix(r, Registration); err != nil {
		return err
	}

	tx.CTAutSymbol, err = ReadVarBytes(r, MaxSymbolLength, "symbol")
	if err != nil {
		return err
	}
	// todo(ctaut): discuss on shall the ckecks are preformed here; the ckeck on len > MaxSymbolLength does not make sense here
	if len(tx.CTAutSymbol) == 0 || len(tx.CTAutSymbol) > MaxSymbolLength {
		return ErrInValidAUTTx
	}

	tx.UnitName, err = ReadVarBytes(r, MaxUnitLength, "unit")
	if err != nil {
		return err
	}
	// todo(ctaut): discuss on shall the ckecks are preformed here; the ckeck on len > MaxUnitLength does not make sense here
	if len(tx.UnitName) == 0 || len(tx.UnitName) > MaxUnitLength {
		return ErrInValidAUTTx
	}

	tx.MinUnitName, err = ReadVarBytes(r, MaxMinUnitLength, "minUnit")
	if err != nil {
		return err
	}
	// todo(ctaut): discuss on shall the ckecks are preformed here; the ckeck on len > MaxMinUnitLength does not make sense here
	if len(tx.MinUnitName) == 0 || len(tx.MinUnitName) > MaxMinUnitLength {
		return ErrInValidAUTTx
	}

	if tx.UnitScale, err = ReadVarInt(r); err != nil {
		return err
	}
	if tx.UnitScale == 0 || tx.UnitScale > MaxAmount {
		return ErrInValidAUTTx
	}

	if tx.AutMemo, err = readAutMemo(r); err != nil {
		return err
	}
	if tx.PlannedTotalAmount, err = ReadVarInt(r); err != nil {
		return err
	}
	// todo(ctaut): what is the unit for PlannedTotalAmount?
	if tx.PlannedTotalAmount == 0 || tx.PlannedTotalAmount > MaxAmount {
		return ErrInValidAUTTx
	}

	if tx.IssuerTokens, err = readIssuerTokens(r); err != nil {
		return err
	}

	if tx.IssueTokensThreshold, err = ReadByte(r); err != nil {
		return err
	}
	if int(tx.IssueTokensThreshold) > len(tx.IssuerTokens) {
		return ErrInValidAUTTx
	}

	if tx.IssuerUpdateThreshold, err = ReadByte(r); err != nil {
		return err
	}
	if int(tx.IssuerUpdateThreshold) > len(tx.IssuerTokens) {
		return ErrInValidAUTTx
	}

	var expireHeight uint64
	if expireHeight, err = ReadVarInt(r); err != nil {
		return err
	}
	if expireHeight > math.MaxInt32 {
		return ErrInValidAUTTx
	}
	tx.ExpireHeight = int32(expireHeight)

	if tx.OutAutRootCoinNum, err = ReadByte(r); err != nil {
		return err
	}

	if tx.Memo, err = readMemo(r); err != nil {
		return err
	}

	// TODO extra
	// todo(ctaut): define a sanity-check function?
	if tx.UnitScale > tx.PlannedTotalAmount {
		return errors.New("an AUT with invalid scale")
	}

	return nil
}

func (tx *RegistrationTx) NumTxInputs() int {
	return 0
}
func (tx *RegistrationTx) SetTxInputs(autTxIns []*CTAUTToken) error {
	if len(autTxIns) != 0 {
		return fmt.Errorf("invalid inputs")
	}
	tx.TxIns = autTxIns // todo(ctaut): directly nil?
	return nil
}

func (tx *RegistrationTx) NumTxOutputs() int {
	return int(tx.OutAutRootCoinNum) // todo(ctaut): the funtion output uint8?
}

// todo(ctaut): always output nil?
func (tx *RegistrationTx) TxInputs() []*CTAUTToken {
	return tx.TxIns
}

// todo(ctaut): shall have functions Get/SetOutAutRootCoinNum()?   NumTxOutputs() should use tx.TxOuts?
// todo(ctaut): redundant? double-check? or consistent?
func (tx *RegistrationTx) setTxOutputs(autTxouts []*CTAUTToken) error {
	if len(autTxouts) != int(tx.OutAutRootCoinNum) {
		return errors.New("invalid set inputs")
	}
	tx.TxOuts = autTxouts
	return nil
}

// todo(ctaut): consider it together with setTxOutputs
func (tx *RegistrationTx) TxOutputs() []*CTAUTToken {
	return tx.TxOuts
}

var _ Transaction = &RegistrationTx{}

// Flag = "CTAUTMint"
// <Identifier> a byte array with fixed length
// <Vin> an integer, representing the amount of AUTCoins to be minted, must less than plannedTotalAmount
// <Number of AUTRootCoins> A number n, explicitly specify the 0~(n-1)-th TXO of this transaction as AutRootCoins, all other TXOs are regarded as normal AbelianCoins.
// <Number of AUTCoins> A number n, Explicitly specify the 0~(n-1)-th TXO of  this transaction as AUTCoins All other TXOs are regarded as normal TXOs.
// <AUTTxoScripts> an array of n byte array each one for an AUTCoin
// <WitnessHash> a byte array with fixed length
// <Memo> a byte array with max length, for this transaction
// todo(ctaut): the comments need to be improved.

type MintTx struct {
	AutIdentifier []byte

	Vin              uint64
	InAutRootCoinNum uint8
	OutAutCoinNum    uint8 // todo(ctaut): explicitly specify the number of plain-aut and the number of ct-aut? not specified, will call underlying API to extract AutTxoType?
	AUTTxoScripts    [][]byte
	WitnessHash      chainhash.Hash // todo(ctaut): move to the last position
	Memo             []byte

	// todo(ctaut): these are the memory-cached content?
	TxIns  []*CTAUTToken
	TxOuts []*CTAUTToken
}

// todo(ctaut): the Type is serialized so that deserialization can obtain it at the first time.
// todo(ctaut): how about add a field in the structure?
func (tx *MintTx) Type() TransactionType {
	return Mint
}
func (tx *MintTx) AUTIdentifier() []byte {
	return tx.AutIdentifier
}

func (tx *MintTx) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var err error

	if err = writePrefix(b, Mint, tx.AutIdentifier); err != nil {
		return nil, err
	}

	if err = WriteVarInt(&b, tx.Vin); err != nil {
		return nil, err
	}

	if err = b.WriteByte(tx.InAutRootCoinNum); err != nil {
		return nil, err
	}

	if err = b.WriteByte(tx.OutAutCoinNum); err != nil {
		return nil, err
	}

	if err = writeCTAUTTxoScript(b, tx.AUTTxoScripts); err != nil {
		return nil, err
	}
	if err = writeWitnessHash(b, tx.WitnessHash); err != nil {
		return nil, err
	}
	if err = writeMemo(b, tx.Memo); err != nil {
		return nil, err
	}

	return b.Bytes(), nil

}
func (tx *MintTx) Deserialize(r io.Reader) error {
	var err error

	if tx.AutIdentifier, err = readPrefix(r, Mint); err != nil {
		return err
	}

	if tx.Vin, err = ReadVarInt(r); err != nil {
		return err
	}

	// todo(ctaut): shall perform the checks here? add a standalone sanity-check function?
	if tx.Vin == 0 || tx.Vin > MaxAmount {
		return ErrInValidAUTTx
	}

	if tx.InAutRootCoinNum, err = ReadByte(r); err != nil {
		return err
	}

	if tx.OutAutCoinNum, err = ReadByte(r); err != nil {
		return err
	}

	if tx.AUTTxoScripts, err = readCTAUTTxoScript(r, int(tx.OutAutCoinNum)); err != nil {
		return err
	}

	if tx.WitnessHash, err = readWitnessHash(r); err != nil {
		return err
	}

	if tx.Memo, err = readMemo(r); err != nil {
		return err
	}

	// extra
	// nothing

	return nil
}

// todo(ctaut): should have Set/GetInAutRootCoinNum()
// todo(ctaut): SetTxInputs(), TxInputs(), NumTxInputs() should be a suite, or NumTxInputs() is removed.
func (tx *MintTx) NumTxInputs() int {
	return int(tx.InAutRootCoinNum)
}

// todo(ctaut): add comment to explain that SetInAutRootCoinNum() should be call before SetTxInputs().
// todo(ctaut): add a sanity-check function to guarantee the consistence between InAutRootCoinNum and TxIns. or make a unique data source.
func (tx *MintTx) SetTxInputs(autTxIns []*CTAUTToken) error {
	if len(autTxIns) != int(tx.InAutRootCoinNum) {
		return fmt.Errorf("invalid inputs")
	}
	tx.TxIns = autTxIns
	return nil
}

func (tx *MintTx) TxInputs() []*CTAUTToken {
	return tx.TxIns
}

// todo(ctaut): should have Set/GetOutAutCoinNum()
// todo(ctaut): setTxOutputs(), TxOutputs(), NumTxOutputs() should be a suite, or NumTxOutputs() is removed.
func (tx *MintTx) NumTxOutputs() int {
	return int(tx.OutAutCoinNum)
}

func (tx *MintTx) setTxOutputs(autTxouts []*CTAUTToken) error {
	if len(autTxouts) != int(tx.OutAutCoinNum) {
		return errors.New("invalid set inputs")
	}
	tx.TxOuts = autTxouts
	return nil
}
func (tx *MintTx) TxOutputs() []*CTAUTToken {
	return tx.TxOuts
}

var _ Transaction = &MintTx{}

// Flag = "CTAUTReRegistration"
// <Identifier> a byte array with fixed length, would not be changed anymore
// <AUTMemo> a byte array with max length
// [Planed Total Amount] an integer range in [1<<51 -1)
// <IssuerTokens> an array with length N of hash, each one represents a public key (represented by a pseudonym coin address)
// <IssuerUpdateThreshold> An integer update_t <= N
// <IssueTokensThreshold> An integer mint_t <= N
// <Expiry of IssuerTokens> a height value
//
// <Number of AUTRootCoins> A number m, explicitly specify the 0~(m-1)-th TXO of inputs in this transaction as AutRootCoins, all other TXOs are regarded as normal AbelianCoins.
// <Number of AUTRootCoins> A number n, Explicitly specify the 0~(n-1)-th TXO of outputs in this transaction as AutRootCoins, all other TXOs are regarded as normal AbelianCoins.
// <Memo> a byte array with max length, for this transaction

type ReRegistrationTx struct {
	CTAutIdentifier []byte

	AutMemo []byte

	PlannedTotalAmount    uint64
	IssuerTokens          [][]byte
	IssueTokensThreshold  uint8 // todo(ctaut): MintThreshold
	IssuerUpdateThreshold uint8 // todo(ctaut): UpdateThreshold
	ExpireHeight          int32

	InAutRootCoinNum  uint8
	OutAutRootCoinNum uint8
	Memo              []byte

	TxIns  []*CTAUTToken
	TxOuts []*CTAUTToken
}

func (tx *ReRegistrationTx) Type() TransactionType {
	return ReRegistration
}

func (tx *ReRegistrationTx) AUTIdentifier() []byte {
	return tx.CTAutIdentifier
}

func (tx *ReRegistrationTx) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var err error

	if err = writePrefix(b, ReRegistration, tx.CTAutIdentifier); err != nil {
		return nil, err
	}

	if err = writeAutMemo(b, tx.AutMemo); err != nil {
		return nil, err
	}

	if err = WriteVarInt(&b, tx.PlannedTotalAmount); err != nil {
		return nil, err
	}

	if err = writeIssuerTokens(b, tx.IssuerTokens); err != nil {
		return nil, err
	}

	if err = b.WriteByte(tx.IssueTokensThreshold); err != nil {
		return nil, err
	}

	if err = b.WriteByte(tx.IssuerUpdateThreshold); err != nil {
		return nil, err
	}

	if err = WriteVarInt(&b, uint64(tx.ExpireHeight)); err != nil {
		return nil, err
	}

	if err = b.WriteByte(tx.InAutRootCoinNum); err != nil {
		return nil, err
	}

	if err = b.WriteByte(tx.OutAutRootCoinNum); err != nil {
		return nil, err
	}

	if err = writeMemo(b, tx.Memo); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
func (tx *ReRegistrationTx) Deserialize(r io.Reader) error {
	var err error

	if tx.CTAutIdentifier, err = readPrefix(r, ReRegistration); err != nil {
		return err
	}

	if tx.AutMemo, err = readAutMemo(r); err != nil {
		return err
	}

	if tx.PlannedTotalAmount, err = ReadVarInt(r); err != nil {
		return err
	}
	if tx.PlannedTotalAmount == 0 || tx.PlannedTotalAmount > MaxAmount {
		return ErrInValidAUTTx
	}

	if tx.IssuerTokens, err = readIssuerTokens(r); err != nil {
		return err
	}

	if tx.IssueTokensThreshold, err = ReadByte(r); err != nil {
		return err
	}
	if int(tx.IssueTokensThreshold) > len(tx.IssuerTokens) {
		return ErrInValidAUTTx
	}

	if tx.IssuerUpdateThreshold, err = ReadByte(r); err != nil {
		return err
	}
	if int(tx.IssuerUpdateThreshold) > len(tx.IssuerTokens) {
		return ErrInValidAUTTx
	}

	var expireHeight uint64
	if expireHeight, err = ReadVarInt(r); err != nil {
		return err
	}
	if expireHeight > math.MaxInt32 {
		return ErrInValidAUTTx
	}
	tx.ExpireHeight = int32(expireHeight)

	if tx.InAutRootCoinNum, err = ReadByte(r); err != nil {
		return err
	}
	if tx.InAutRootCoinNum == 0 {
		return ErrInValidAUTTx
	}

	if tx.OutAutRootCoinNum, err = ReadByte(r); err != nil {
		return err
	}
	if tx.OutAutRootCoinNum == 0 {
		return ErrInValidAUTTx
	}

	if tx.Memo, err = readMemo(r); err != nil {
		return err
	}

	// extra
	// nothing

	return nil
}

// todo(ctaut): add Set/Get functions for InAutRootCoinNum
// todo(ctaut): NumTxInputs(), SetTxInputs(), TxInputs() should use the same data source.
// todo(ctaut): the consistence between InAutRootCoinNum and TxIns.
// todo(ctaut): add standalone sanity-check functions.
func (tx *ReRegistrationTx) NumTxInputs() int {
	return int(tx.InAutRootCoinNum)
}

// todo(ctaut): add comment to clarify that SetTxInputs should be called after SetInAutRootCoinNum()
func (tx *ReRegistrationTx) SetTxInputs(autTxIns []*CTAUTToken) error {
	if len(autTxIns) != int(tx.InAutRootCoinNum) {
		return fmt.Errorf("invalid inputs")
	}
	tx.TxIns = autTxIns
	return nil
}
func (tx *ReRegistrationTx) TxInputs() []*CTAUTToken {
	return tx.TxIns
}

// todo(ctaut): add Set/Get functions for OutAutRootCoinNum
// todo(ctaut): NumTxOutputs(), setTxOutputs(), TxOutputs() should use the same data source.
// todo(ctaut): the consistence between OutAutRootCoinNum and TxOuts.
// todo(ctaut): add standalone sanity-check function.
func (tx *ReRegistrationTx) NumTxOutputs() int {
	return int(tx.OutAutRootCoinNum)
}

// todo(ctaut): add comment to clarify that setTxOutputs should be called after SetOutAutRootCoinNum()
func (tx *ReRegistrationTx) setTxOutputs(autTxouts []*CTAUTToken) error {
	if len(autTxouts) != int(tx.OutAutRootCoinNum) {
		return errors.New("invalid set inputs")
	}
	tx.TxOuts = autTxouts
	return nil
}
func (tx *ReRegistrationTx) TxOutputs() []*CTAUTToken {
	return tx.TxOuts
}

var _ Transaction = &ReRegistrationTx{}

// Flag = "CTAUTTransfer"
// <Identifier> a byte array with fixed length
// <Number of AUTCoins> A number m, explicitly specify the 0~(m-1)-th TXO of this transaction as AUTCoins All other TXOs are regarded as normal TXOs.
// <Number of AUTCoins> A number n, explicitly specify the 0~(n-1)-th TXO of this transaction as AUTCoins All other TXOs are regarded as normal TXOs.
// <AUTTxoScripts> a byte array with length n, each one for an AUTCoin
// <WitnessHash> a byte array with fixed length, for balance proof
// <Memo> a byte array with max length, for this transaction

type TransferTx struct {
	AutIdentifier []byte

	InAutCoinNum  uint8
	OutAutCoinNum uint8
	AUTTxoScripts [][]byte

	WitnessHash chainhash.Hash
	Memo        []byte

	TxIns  []*CTAUTToken
	TxOuts []*CTAUTToken
}

func (tx *TransferTx) Type() TransactionType {
	return Transfer
}

func (tx *TransferTx) AUTIdentifier() []byte {
	return tx.AutIdentifier
}

func (tx *TransferTx) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var err error

	if err = writePrefix(b, Transfer, tx.AutIdentifier); err != nil {
		return nil, err
	}

	if err = b.WriteByte(tx.InAutCoinNum); err != nil {
		return nil, err
	}

	if err = b.WriteByte(tx.OutAutCoinNum); err != nil {
		return nil, err
	}

	if err = writeCTAUTTxoScript(b, tx.AUTTxoScripts); err != nil {
		return nil, err
	}

	if err = writeWitnessHash(b, tx.WitnessHash); err != nil {
		return nil, err
	}

	if err = writeMemo(b, tx.Memo); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
func (tx *TransferTx) Deserialize(r io.Reader) error {
	var err error
	if tx.AutIdentifier, err = readPrefix(r, Transfer); err != nil {
		return err
	}

	if tx.InAutCoinNum, err = ReadByte(r); err != nil {
		return err
	}
	if tx.InAutCoinNum == 0 {
		return ErrInValidAUTTx
	}

	if tx.OutAutCoinNum, err = ReadByte(r); err != nil {
		return err
	}
	if tx.OutAutCoinNum == 0 {
		return ErrInValidAUTTx
	}

	if tx.AUTTxoScripts, err = readCTAUTTxoScript(r, int(tx.OutAutCoinNum)); err != nil {
		return err

	}

	if tx.WitnessHash, err = readWitnessHash(r); err != nil {
		return err
	}

	if tx.Memo, err = readMemo(r); err != nil {
		return err
	}

	// extra
	// nothing

	return nil
}

// todo(ctaut): NumTxInputs(), SetTxInputs(), TxInputs() should use the same data source.
// todo(ctaut): add Set/Get functions for InAutCoinNum?
// todo(ctaut): add a standalone sanity-chech function?
func (tx *TransferTx) NumTxInputs() int {
	return int(tx.InAutCoinNum)
}

// todo(ctaut): add comment that call this function after SetInAutCoinNum() is called.
func (tx *TransferTx) SetTxInputs(autTxIns []*CTAUTToken) error {
	if len(autTxIns) != int(tx.InAutCoinNum) {
		return fmt.Errorf("invalid inputs")
	}
	tx.TxIns = autTxIns
	return nil
}
func (tx *TransferTx) TxInputs() []*CTAUTToken {
	return tx.TxIns
}

// todo(ctaut): NumTxOutputs(), setTxOutputs(), TxOutputs() should use the same data source.
// todo(ctaut): add Set/Get functions for OutAutCoinNum?
// todo(ctaut): add a standalone sanity-chech function?
func (tx *TransferTx) NumTxOutputs() int {
	return int(tx.OutAutCoinNum)
}
func (tx *TransferTx) setTxOutputs(autTxouts []*CTAUTToken) error {
	if len(autTxouts) != int(tx.OutAutCoinNum) {
		return errors.New("invalid set inputs")
	}
	tx.TxOuts = autTxouts
	return nil
}
func (tx *TransferTx) TxOutputs() []*CTAUTToken {
	return tx.TxOuts

}

var _ Transaction = &TransferTx{}

// Flag = "CTAUTBurn"
// <Identifier> a byte array with fixed length
// <Number of AUTCoins> A number m, explicitly specify the 0~(m-1)-th TXO of this transaction as AUTCoins All other TXOs are regarded as normal TXOs.
// <Vout> an integer, representing the amount of AUTCoins to be burned
// <WitnessHash> a byte array with fixed length, for balance proof
// <Memo> a byte array with max length, for this transaction
// todo(ctaut): improve the comments
type BurnTx struct {
	AutIdentifier []byte

	InAutCoinNum  uint8
	OutAutCoinNum uint8
	AUTTxoScripts [][]byte

	WitnessHash chainhash.Hash
	Memo        []byte // 	// todo(Alice): how about TxMemo?

	TxIns  []*CTAUTToken
	TxOuts []*CTAUTToken
}

// todo(ctaut): why here, rather than the last position.
var _ Transaction = &BurnTx{}

func (tx *BurnTx) Type() TransactionType {
	return Burn
}

func (tx *BurnTx) AUTIdentifier() []byte {
	return tx.AutIdentifier
}

func (tx *BurnTx) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var err error

	if err = writePrefix(b, Burn, tx.AutIdentifier); err != nil {
		return nil, err
	}

	if err = b.WriteByte(tx.InAutCoinNum); err != nil {
		return nil, err
	}

	if err = b.WriteByte(tx.OutAutCoinNum); err != nil {
		return nil, err
	}

	if err = writeCTAUTTxoScript(b, tx.AUTTxoScripts); err != nil {
		return nil, err
	}

	if err = writeWitnessHash(b, tx.WitnessHash); err != nil {
		return nil, err
	}

	if err = writeMemo(b, tx.Memo); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// todo(ctaut): add a standalone sanity-check function, and call it at the end of deserialize
func (tx *BurnTx) Deserialize(r io.Reader) error {
	var err error
	if tx.AutIdentifier, err = readPrefix(r, Burn); err != nil {
		return err
	}

	if tx.InAutCoinNum, err = ReadByte(r); err != nil {
		return err
	}
	if tx.InAutCoinNum == 0 {
		return ErrInValidAUTTx
	}

	if tx.OutAutCoinNum, err = ReadByte(r); err != nil {
		return err
	}
	if tx.OutAutCoinNum == 0 {
		return ErrInValidAUTTx
	}

	if tx.AUTTxoScripts, err = readCTAUTTxoScript(r, int(tx.OutAutCoinNum)); err != nil {
		return err
	}

	if tx.WitnessHash, err = readWitnessHash(r); err != nil {
		return err
	}

	if tx.Memo, err = readMemo(r); err != nil {
		return err
	}

	// extra
	// nothing

	return nil
}

// todo(ctaut): NumTxInputs(), SetTxInputs(), TxInputs() should use the same data source.
// todo(ctaut): add Set/Get functions for InAutCoinNum?
// todo(ctaut): add a standalone sanity-chech function?
func (tx *BurnTx) NumTxInputs() int {
	return int(tx.InAutCoinNum)
}

// todo(ctaut): add a standalone sanity-check function
func (tx *BurnTx) SetTxInputs(autTxIns []*CTAUTToken) error {
	if len(autTxIns) != int(tx.InAutCoinNum) {
		return fmt.Errorf("invalid inputs")
	}
	tx.TxIns = autTxIns
	return nil
}
func (tx *BurnTx) TxInputs() []*CTAUTToken {
	return tx.TxIns
}

// todo(ctaut): NumTxOutputs(), setTxOutputs(), TxOutputs() should use the same data source.
// todo(ctaut): add Set/Get functions for OutAutCoinNum?
// todo(ctaut): add a standalone sanity-chech function?
func (tx *BurnTx) NumTxOutputs() int {
	return int(tx.OutAutCoinNum)
}

// todo(ctaut): add a standalone sanity-check function
func (tx *BurnTx) setTxOutputs(autTxouts []*CTAUTToken) error {
	if len(autTxouts) != int(tx.OutAutCoinNum) {
		return errors.New("invalid set inputs")
	}
	tx.TxOuts = autTxouts
	return nil
}

func (tx *BurnTx) TxOutputs() []*CTAUTToken {
	return nil
}

var ErrNonAutTx = errors.New("not a AUT transaction")
var ErrInValidAUTTx = errors.New("not a valid AUT transaction")
var ErrInValidIndex = errors.New("not a valid index")

// ExtractCTAutTransaction try to deserialize CTAUT script from transaction memo
// if success, it would :
// - populate CTAUT transaction outputs
//   - for root coin, version / outpoint / coin address
//   - for non-root coin, version / outpoint / coin address / value script
//
// - do sanity-check for AUT transaction, including
//   - no repeat issuer tokens for registration/re-registration
//   - no tokens parasitized on invalid type coin
//   - check configuration
//
// Note that the input part needs to be filled with the help of blockchain.
func ExtractCTAutTransaction(tx *wire.MsgTxAbe) (autTx Transaction, err error) {
	// could not be an AUT transaction
	if len(tx.TxMemo) <= CommonPrefixLength+1 {
		return nil, nil
	}
	if !bytes.Equal(tx.TxMemo[:CommonPrefixLength], []byte(CommonPrefix)) {
		return nil, nil
	}

	// todo(ctaut): why +1? "CTAUTSCRIPT" will result (nil, nil) or (nil, err)
	// todo(ctaut): only if ctaut-script's CommonPrefixLength is the the start position, it will be recognized as ctaut-script.
	// todo(ctaut): what "txMemo" should be shown at the front end?

	//	extract
	switch tx.TxMemo[CommonPrefixLength] {
	case Registration:
		autTx = &RegistrationTx{}
	case Mint:
		autTx = &MintTx{}
	case ReRegistration:
		autTx = &ReRegistrationTx{}
	case Transfer:
		autTx = &TransferTx{}
	case Burn:
		autTx = &BurnTx{}
	default:
		return nil, ErrInValidAUTTx
	}
	reader := bytes.NewBuffer(tx.TxMemo)
	err = autTx.Deserialize(reader)
	if err != nil {
		return nil, err
	}

	// we don't know whether the CTAUT instance is exist or not, it should be checked by blockchain
	// for input part, we can't determine which ones are input for CTAUT for the time being.
	// for output part
	err = populateCTAUTOutputs(autTx, tx)
	if err != nil {
		return nil, err
	}

	// Here, the built-in rules for CTAUT configuration can be verified, including:
	// - limit for some configuration item
	// - length for some configuration item

	switch autTransaction := autTx.(type) {
	case *RegistrationTx:
		// for inputs, there is no rules

		// for outputs, the claimed issuer tokens must match the outputs exactly
		if err = matchIssuerTokens(autTransaction.IssuerTokens, autTransaction.TxOuts); err != nil {
			return nil, err
		}

	case *MintTx:
		// for inputs, here is no enough information to check
		// 1. have no idea whether which inputs is for CTAUT
		// 2. have no idea whether the (issue) threshold is meet
		// It has to be delayed until the chain data can be seen before checking.

		// for outputs, fill out the script
		for i := 0; i < len(autTransaction.TxOuts); i++ {
			// todo(ctaut): why fill now? could not earlier or simpler? "ValueScript" is appropriate?
			autTransaction.TxOuts[i].ValueScript = autTransaction.AUTTxoScripts[i]
		}

	case *ReRegistrationTx:
		// for inputs, here is no enough information to check
		// 1. have no idea whether which inputs is for CTAUT
		// 2. have no idea whether the (update) threshold is meet
		// It has to be delayed until the chain data can be seen before checking.

		// for outputs, the claimed issuer tokens must match the outputs exactly
		if err = matchIssuerTokens(autTransaction.IssuerTokens, autTransaction.TxOuts); err != nil {
			return nil, err
		}

	case *TransferTx:
		// for inputs, here is no enough information to check
		// 1. have no idea whether which inputs is for CTAUT
		// 2. have no idea whether the (update) threshold is meet
		// It has to be delayed until the chain data can be seen before checking.

		// for outputs, fill out the script
		for i := 0; i < len(autTransaction.TxOuts); i++ {
			// todo(ctaut): why fill now? could not earlier or simpler? "ValueScript" is appropriate?
			autTransaction.TxOuts[i].ValueScript = autTransaction.AUTTxoScripts[i]
		}

	case *BurnTx:
		// for inputs, here is no enough information to check
		// 1. have no idea whether which inputs is for CTAUT
		// 2. have no idea whether the (update) threshold is meet
		// It has to be delayed until the chain data can be seen before checking.

		// for outputs, fill out the script
		for i := 0; i < len(autTransaction.TxOuts); i++ {
			// todo(ctaut): why fill now? could not earlier or simpler? "ValueScript" is appropriate?
			autTransaction.TxOuts[i].ValueScript = autTransaction.AUTTxoScripts[i]
		}

	default:
		return nil, ErrInValidAUTTx
	}

	return autTx, nil
}

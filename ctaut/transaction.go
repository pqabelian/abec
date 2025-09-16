package ctaut

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"

	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
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

type CTAUTToken struct {
	OutPoint
	ValueScript []byte // optional from root coin
	CoinAddress []byte // optional for coin
}

type TransactionType = uint8

// todo(AUT): hardcode rather than iota
const (
	Registration TransactionType = 0
	// todo(Alice): ecah needs to specify the type.
	Mint           TransactionType = 1
	ReRegistration TransactionType = 2
	Transfer       TransactionType = 3
	Burn           TransactionType = 4
)

const CommonPrefixLength = 11
const IdentifierLength = 64 // identifier
const MaxSymbolLength = 64  // symbol

// todo(Alice): MaxAutMemoLength, MaxTxMemoLength
const MaxAUTMemoLength = 1024
const MaxAUTTxMemoLength = 1024
const MaxAUTTxoScriptLength = 1024 // TODO size
const MaxUnitLength = 20
const MaxMinUnitLength = 20

// IssuerTokenLength would be length of coin address for pseudonym(4+1+193)
const IssuerTokenLength = 198

// MaxIssuerNum won't exceed number limit of pseudonym address in crypto scheme(current abecryptox)
// also, it won't exceed 256 math.MaxUint8
const MaxIssuerNum = 10

// todo: using constant?
const CommonPrefix = "CTAUTSCRIPT"

// todo(AUT): Ins --> TxIns(), Outs --> TxOuts (since Ins and Outs are too short to describe clearly).
// todo(AUT): NumIns() ? shall be removed?
// todo(AUT): Values() ?
type Transaction interface {
	Type() TransactionType
	Serialize() ([]byte, error)
	Deserialize(io.Reader) error
	AUTIdentifier() []byte
	// ToDo(Alice): TxIns, TxOuts
	//TxInputs() []*CTAUTToken
	NumTxInputs() int
	SetTxInputs(autTxIns []*CTAUTToken) error
	TxOutputs() []*CTAUTToken
}

//const HashSize = 64

// Instance hosts metadata information for registered Abelian User Token
// Different AUTs are uniquely distinguished and identified by identifiers
// In details:
// RegistrationTx would create a new one with unique CTAutIdentifier
// MintTx would update fields MintedAmount and RootCoinSet
// ReRegistrationTx would update fields other than CTAutIdentifier/ UnitName / MinUnitName /MintedAmount
// TransferTx would update no fields
// BurnTx would update no fields
type Instance struct {
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
func (info *Instance) Clone() *Instance {
	if info == nil {
		return nil
	}

	// ToDo(Alice): by the same order as the definition?
	cloned := &Instance{
		CTAutIdentifier:       make([]byte, len(info.CTAutIdentifier)),
		CTAutSymbol:           make([]byte, len(info.CTAutSymbol)),
		IssuerTokens:          make([][]byte, len(info.IssuerTokens)),
		IssuerUpdateThreshold: info.IssuerUpdateThreshold,
		IssueTokensThreshold:  info.IssueTokensThreshold,
		PlannedTotalAmount:    info.PlannedTotalAmount,
		ExpireHeight:          info.ExpireHeight,
		UnitName:              make([]byte, len(info.UnitName)),
		MinUnitName:           make([]byte, len(info.MinUnitName)),
		UnitScale:             info.UnitScale,
		AutMemo:               make([]byte, len(info.AutMemo)),
		MintedAmount:          info.MintedAmount,
		RootCoinSet:           make(map[OutPoint]struct{}, len(info.RootCoinSet)),
	}
	copy(cloned.CTAutIdentifier, info.CTAutIdentifier)
	copy(cloned.CTAutSymbol, info.CTAutSymbol)
	copy(cloned.AutMemo, info.AutMemo)

	for i := 0; i < len(info.IssuerTokens); i++ {
		cloned.IssuerTokens[i] = make([]byte, len(info.IssuerTokens[i]))
		copy(cloned.IssuerTokens[i][:], info.IssuerTokens[i][:])
	}

	copy(cloned.UnitName, info.UnitName)
	copy(cloned.MinUnitName, info.MinUnitName)

	for outpoint := range info.RootCoinSet {
		newOutpoint := OutPoint{}
		copy(newOutpoint.TxHash[:], outpoint.TxHash[:])
		newOutpoint.Index = outpoint.Index

		cloned.RootCoinSet[newOutpoint] = struct{}{}
	}

	return cloned
}

// Flag = ”CTAUTRegistration”
// <Identifier> a byte array with fixed length, would not be changed anymore
// <AUTName> a byte array with max length, would not be changed anymore
// [UnitName] a byte array with max length, would not be changed anymore
// [MinUnitName] a byte array with max length, would not be changed anymore
// [UnitScale] the scale between unit and minUnit, would not be changed anymore
// [AutMemo] a byte array with max length
//
// [Planed Total Amount] an integer range in [0, 1<<51 -1)
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
	CTAutIdentifier []byte // identifier
	CTAutSymbol     []byte // symbol
	UnitName        []byte
	MinUnitName     []byte
	UnitScale       uint64
	AutMemo         []byte

	PlannedTotalAmount    uint64
	IssuerTokens          [][]byte // todo(AUT): same as in Info
	IssueTokensThreshold  uint8
	IssuerUpdateThreshold uint8 // TODO confirm the range
	ExpireHeight          int32

	OutAutRootCoinNum uint8
	Memo              []byte
	// todo(Alice): besides AutMemo to initialize the AUT, should have TxMemo to memo this transaction.

	TxIns  []*CTAUTToken
	TxOuts []*CTAUTToken
}

func (tx *RegistrationTx) Type() TransactionType {
	return Registration
}

func (tx *RegistrationTx) Serialize() ([]byte, error) {
	// todo(Alice): initialize a space first
	// w := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	var b bytes.Buffer
	var err error

	_, err = b.WriteString(CommonPrefix)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(Registration)
	if err != nil {
		return nil, err
	}

	err = WriteVarBytes(&b, 0, tx.CTAutIdentifier)
	if err != nil {
		return nil, err
	}

	err = WriteVarBytes(&b, 0, tx.CTAutSymbol)
	if err != nil {
		return nil, err
	}

	err = WriteVarInt(&b, 0, uint64(len(tx.IssuerTokens)))
	if err != nil {
		return nil, err
	}
	for _, issuer := range tx.IssuerTokens {
		err = WriteVarBytes(&b, 0, issuer[:])
		if err != nil {
			return nil, err
		}
	}

	err = WriteVarInt(&b, 0, tx.PlannedTotalAmount)
	if err != nil {
		return nil, err
	}

	err = WriteVarBytes(&b, 0, tx.UnitName)
	if err != nil {
		return nil, err
	}
	err = WriteVarBytes(&b, 0, tx.MinUnitName)
	if err != nil {
		return nil, err
	}
	err = WriteVarInt(&b, 0, tx.UnitScale)
	if err != nil {
		return nil, err
	}
	err = WriteVarBytes(&b, 0, tx.AutMemo)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.IssueTokensThreshold)
	if err != nil {
		return nil, err
	}
	err = WriteVarInt(&b, 0, uint64(tx.ExpireHeight))
	if err != nil {
		return nil, err
	}
	err = b.WriteByte(tx.IssuerUpdateThreshold)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.OutAutRootCoinNum)
	if err != nil {
		return nil, err
	}
	err = WriteVarBytes(&b, 0, tx.Memo)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
func (tx *RegistrationTx) AUTIdentifier() []byte {
	return tx.CTAutIdentifier
}
func (tx *RegistrationTx) Deserialize(r io.Reader) error {
	// todo(Alice): use bytes.NewReader()?
	var err error

	commprefix := make([]byte, len(CommonPrefix))
	_, err = io.ReadFull(r, commprefix)
	if err != nil {
		return err
	}
	if !bytes.Equal(commprefix, []byte(CommonPrefix)) {
		return ErrNonAutTx
	}

	oneByte := make([]byte, 1)
	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	if oneByte[0] != Registration {
		return ErrInValidAUTTx
	}

	tx.CTAutIdentifier, err = ReadVarBytes(r, 0, IdentifierLength, "identifier")
	if err != nil {
		return err
	}
	if len(tx.CTAutIdentifier) == 0 {
		return ErrInValidAUTTx
	}

	tx.CTAutSymbol, err = ReadVarBytes(r, 0, MaxSymbolLength, "symbol")
	if err != nil {
		return err
	}
	if len(tx.CTAutSymbol) == 0 {
		return ErrInValidAUTTx
	}

	var numIssuer uint64
	numIssuer, err = ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	tx.IssuerTokens = make([][]byte, numIssuer)
	existIssuerTokens := map[string]struct{}{}
	for i := 0; i < len(tx.IssuerTokens); i++ {
		tx.IssuerTokens[i], err = ReadVarBytes(r, 0, IssuerTokenLength, "issuerToken")
		if err != nil {
			return err
		}
		// TODO check length
		if _, ok := existIssuerTokens[hex.EncodeToString(tx.IssuerTokens[i])]; ok {
			return ErrInValidAUTTx
		}
		existIssuerTokens[hex.EncodeToString(tx.IssuerTokens[i])] = struct{}{}
	}
	// TODO max limit?

	tx.PlannedTotalAmount, err = ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	// TODO check max ?

	tx.UnitName, err = ReadVarBytes(r, 0, MaxUnitLength, "unit")
	if err != nil {
		return err
	}
	if len(tx.UnitName) == 0 {
		return ErrInValidAUTTx
	}

	tx.MinUnitName, err = ReadVarBytes(r, 0, MaxMinUnitLength, "minUnit")
	if err != nil {
		return err
	}
	if len(tx.MinUnitName) == 0 {
		return ErrInValidAUTTx
	}

	tx.UnitScale, err = ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	// TODO assert range
	// TODO check max ?

	tx.AutMemo, err = ReadVarBytes(r, 0, MaxAUTMemoLength, "autmemo")
	if err != nil {
		return err
	}

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	tx.IssueTokensThreshold = oneByte[0]

	var expireHeight uint64
	expireHeight, err = ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if expireHeight > math.MaxInt32 {
		return ErrInValidAUTTx
	}
	tx.ExpireHeight = int32(expireHeight)

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	tx.IssuerUpdateThreshold = oneByte[0]

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	tx.OutAutRootCoinNum = oneByte[0]

	if len(tx.CTAutIdentifier) != IdentifierLength ||
		len(tx.CTAutSymbol) > MaxSymbolLength ||
		len(tx.AutMemo) > MaxAUTMemoLength ||
		len(tx.Memo) > MaxAUTTxMemoLength ||
		len(tx.UnitName) > MaxUnitLength ||
		len(tx.MinUnitName) > MaxMinUnitLength {
		return errors.New("an AUT with invalid length of name")
	}
	if len(tx.IssuerTokens) > MaxIssuerNum ||
		int(tx.IssueTokensThreshold) > len(tx.IssuerTokens) ||
		int(tx.IssuerUpdateThreshold) > len(tx.IssuerTokens) {
		return errors.New("an AUT with invalid threshold")
	}
	if tx.UnitScale > tx.PlannedTotalAmount {
		return errors.New("an AUT with invalid scale")
	}
	return nil
}
func (tx *RegistrationTx) TxInputs() []*CTAUTToken {
	return tx.TxIns
}
func (tx *RegistrationTx) NumTxInputs() int {
	return 0
}
func (tx *RegistrationTx) SetTxInputs(autTxIns []*CTAUTToken) error {
	if len(autTxIns) != 0 {
		return fmt.Errorf("invalid inputs")
	}
	tx.TxIns = autTxIns
	return nil
}

func (tx *RegistrationTx) TxOutputs() []*CTAUTToken {
	return tx.TxOuts
}

var _ Transaction = &RegistrationTx{}

// Flag = ”CTAUTMint”
// <Identifier> a byte array with fixed length
// <Vin> an integer, representing the amount of AUTCoins to be minted, must less than plannedTotalAmount
// <Number of AUTRootCoins> A number n, explicitly specify the 0~(n-1)-th TXO of this transaction as AutRootCoins, all other TXOs are regarded as normal AbelianCoins.
// <Number of AUTCoins> A number n, Explicitly specify the 0~(n-1)-th TXO of  this transaction as AUTCoins All other TXOs are regarded as normal TXOs.
// <AUTTxoScript> an array of n byte array each one for an AUTCoin
// <WitnessHash> a byte array with fixed length
// <Memo> a byte array with max length, for this transaction

type MintTx struct {
	AutIdentifier []byte

	Vin              uint64
	InAutRootCoinNum uint8
	OutAutCoinNum    uint8
	AUTTxoScript     [][]byte
	WitnessHash      chainhash.Hash
	Memo             []byte

	TxIns  []*CTAUTToken
	TxOuts []*CTAUTToken
}

func (tx *MintTx) Type() TransactionType {
	return Mint
}
func (tx *MintTx) Serialize() ([]byte, error) {
	// todo(Alice): initialize a space first
	// w := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))

	var b bytes.Buffer
	var err error

	_, err = b.WriteString(CommonPrefix)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(Mint)
	if err != nil {
		return nil, err
	}

	err = WriteVarBytes(&b, 0, tx.AutIdentifier)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.InAutRootCoinNum)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.OutAutCoinNum)
	if err != nil {
		return nil, err
	}

	// todo(Alice): add a simple santiy-check on the consistence bewteen OutAutCoinNum and len(TxoAUTValues)
	if len(tx.AUTTxoScript) != int(tx.OutAutCoinNum) {
		return nil, errors.New("mis-match number of output and declared")
	}
	err = WriteVarInt(&b, 0, uint64(len(tx.AUTTxoScript)))
	if err != nil {
		return nil, err
	}

	for _, txoScript := range tx.AUTTxoScript {
		err = WriteVarBytes(&b, 0, txoScript)
		if err != nil {
			return nil, err
		}
	}

	err = WriteVarBytes(&b, 0, tx.Memo)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil

}
func (tx *MintTx) Deserialize(r io.Reader) error {
	var err error
	// todo(Alice): use bytes.NewReader()?

	commprefix := make([]byte, len(CommonPrefix))
	_, err = io.ReadFull(r, commprefix)
	if err != nil {
		return err
	}
	if !bytes.Equal(commprefix, []byte(CommonPrefix)) {
		return ErrNonAutTx
	}

	oneByte := make([]byte, 1)
	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	if oneByte[0] != Mint {
		return ErrInValidAUTTx
	}

	tx.AutIdentifier, err = ReadVarBytes(r, 0, IdentifierLength, "identifier")
	if err != nil {
		return err
	}
	if len(tx.AutIdentifier) == 0 {
		return ErrInValidAUTTx
	}

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	tx.InAutRootCoinNum = oneByte[0]

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	tx.OutAutCoinNum = oneByte[0]

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	numOutAutCoins := oneByte[0]

	if tx.OutAutCoinNum != numOutAutCoins {
		return errors.New("mis-match output coin")
	}

	tx.AUTTxoScript = make([][]byte, numOutAutCoins)
	for i := 0; i < len(tx.AUTTxoScript); i++ {
		tx.AUTTxoScript[i], err = ReadVarBytes(r, 0, MaxAUTTxoScriptLength, "an AUT with invalid txo script")
		if err != nil {
			return err
		}
	}

	tx.Memo, err = ReadVarBytes(r, 0, MaxAUTTxMemoLength, "memo")
	if err != nil {
		return err
	}

	// todo(Alice): MaxAutTxMemo
	if len(tx.AutIdentifier) != IdentifierLength ||
		len(tx.Memo) > MaxAUTTxMemoLength {
		return errors.New("an AUT with invalid length of name")
	}

	return nil
}
func (tx *MintTx) AUTIdentifier() []byte {
	return tx.AutIdentifier
}

func (tx *MintTx) TxInputs() []*CTAUTToken {
	return tx.TxIns
}
func (tx *MintTx) NumTxInputs() int {
	return int(tx.InAutRootCoinNum)
}
func (tx *MintTx) SetTxInputs(autTxIns []*CTAUTToken) error {
	if len(autTxIns) != int(tx.InAutRootCoinNum) {
		return fmt.Errorf("invalid inputs")
	}
	tx.TxIns = autTxIns
	return nil
}
func (tx *MintTx) TxOutputs() []*CTAUTToken {
	return tx.TxOuts
}

var _ Transaction = &MintTx{}

// Flag = ”CTAUTReRegistration”
// <Identifier> a byte array with fixed length, would not be changed anymore
// <AUTMemo> a byte array with max length
// [Planed Total Amount] an integer range in [0, 1<<51 -1)
// <IssuerTokens> an array with length N of hash, each one represents a public key (represented by a pseudonym coin address)
// <IssuerUpdateThreshold> An integer update_t <= N
// <IssueTokensThreshold> An integer mint_t <= N
// <Expiry of IssuerTokens> a height value
//
// <Number of AUTRootCoins> A number m, explicitly specify the 0~(m-1)-th TXO of inputs in this transaction as AutRootCoins, all other TXOs are regarded as normal AbelianCoins.
// <Number of AUTRootCoins> A number n, Explicitly specify the 0~(n-1)-th TXO of outputs in this transaction as AutRootCoins, all other TXOs are regarded as normal AbelianCoins.
// <Memo> a byte array with max length, for this transaction

type ReRegistrationTx struct {
	// todo(Alice): for the common fields with RegistrationTx, use the same order; then particular fields
	// AutMemo, and AutTxMemo
	CTAutIdentifier []byte
	// TODO remove
	CTAutSymbol []byte
	UnitScale   uint64

	AutMemo               []byte
	PlannedTotalAmount    uint64
	IssuerTokens          [][]byte
	IssuerUpdateThreshold uint8 // TODO confirm the range
	IssueTokensThreshold  uint8
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
func (tx *ReRegistrationTx) Serialize() ([]byte, error) {
	// todo(Alice): initialize a space first
	// w := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))

	var b bytes.Buffer
	var err error

	_, err = b.WriteString(CommonPrefix)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(ReRegistration)
	if err != nil {
		return nil, err
	}

	err = WriteVarBytes(&b, 0, tx.CTAutIdentifier)
	if err != nil {
		return nil, err
	}
	err = WriteVarBytes(&b, 0, tx.CTAutSymbol)
	if err != nil {
		return nil, err
	}

	err = WriteVarInt(&b, 0, uint64(len(tx.IssuerTokens)))
	if err != nil {
		return nil, err
	}
	for _, issuer := range tx.IssuerTokens {
		err = WriteVarBytes(&b, 0, issuer)
		if err != nil {
			return nil, err
		}
	}

	err = WriteVarInt(&b, 0, tx.PlannedTotalAmount)
	if err != nil {
		return nil, err
	}

	err = WriteVarInt(&b, 0, tx.UnitScale)
	if err != nil {
		return nil, err
	}

	err = WriteVarBytes(&b, 0, tx.AutMemo)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.IssueTokensThreshold)
	if err != nil {
		return nil, err
	}
	err = WriteVarInt(&b, 0, uint64(tx.ExpireHeight))
	if err != nil {
		return nil, err
	}
	err = b.WriteByte(tx.IssuerUpdateThreshold)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.InAutRootCoinNum)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.OutAutRootCoinNum)
	if err != nil {
		return nil, err
	}

	err = WriteVarBytes(&b, 0, tx.Memo)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
func (tx *ReRegistrationTx) Deserialize(r io.Reader) error {
	var err error

	// todo(Alice): use bytes.NewReader()?

	commprefix := make([]byte, len(CommonPrefix))
	_, err = io.ReadFull(r, commprefix)
	if err != nil {
		return err
	}
	if !bytes.Equal(commprefix, []byte(CommonPrefix)) {
		return ErrNonAutTx
	}

	oneByte := make([]byte, 1)
	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	if oneByte[0] != ReRegistration {
		return ErrInValidAUTTx
	}

	tx.CTAutIdentifier, err = ReadVarBytes(r, 0, IdentifierLength, "identifier")
	if err != nil {
		return err
	}
	if len(tx.CTAutIdentifier) == 0 {
		return ErrInValidAUTTx
	}
	tx.CTAutSymbol, err = ReadVarBytes(r, 0, IdentifierLength, "symbol")
	if err != nil {
		return err
	}
	if len(tx.CTAutSymbol) == 0 {
		return ErrInValidAUTTx
	}

	var numIssuer uint64
	numIssuer, err = ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	tx.IssuerTokens = make([][]byte, numIssuer)
	existIssuerTokens := map[string]struct{}{}
	for i := 0; i < len(tx.IssuerTokens); i++ {
		tx.IssuerTokens[i], err = ReadVarBytes(r, 0, IssuerTokenLength, "issuerToken")
		if err != nil {
			return err
		}
		if _, ok := existIssuerTokens[hex.EncodeToString(tx.IssuerTokens[i])]; ok {
			return ErrInValidAUTTx
		}
		// todo(Alice): did not put into existIssuerTokens? as existIssuerTokens is used to detect repeated tokens
		existIssuerTokens[hex.EncodeToString(tx.IssuerTokens[i])] = struct{}{}
	}

	tx.PlannedTotalAmount, err = ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	tx.UnitScale, err = ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	tx.AutMemo, err = ReadVarBytes(r, 0, MaxAUTMemoLength, "autmemo")
	if err != nil {
		return err
	}

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	tx.IssueTokensThreshold = oneByte[0]

	var expireHeight uint64
	expireHeight, err = ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if tx.ExpireHeight > math.MaxInt32 {
		return ErrInValidAUTTx
	}
	tx.ExpireHeight = int32(expireHeight)

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	tx.IssuerUpdateThreshold = oneByte[0]

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	tx.InAutRootCoinNum = oneByte[0]

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	tx.OutAutRootCoinNum = oneByte[0]

	tx.Memo, err = ReadVarBytes(r, 0, MaxAUTTxMemoLength, "memo")
	if err != nil {
		return err
	}

	if len(tx.CTAutIdentifier) != IdentifierLength ||
		len(tx.CTAutSymbol) > MaxSymbolLength ||
		len(tx.AutMemo) > MaxAUTMemoLength ||
		len(tx.Memo) > MaxAUTTxMemoLength {
		return errors.New("an AUT with invalid length of name")
	}
	// todo(Alice): AutMemo, AutTxMemo

	if len(tx.IssuerTokens) > MaxIssuerNum ||
		int(tx.IssueTokensThreshold) > len(tx.IssuerTokens) ||
		int(tx.IssuerUpdateThreshold) > len(tx.IssuerTokens) {
		return errors.New("an AUT with invalid threshold")
	}

	// todo(Alice): is this check necessary?
	if tx.UnitScale > tx.PlannedTotalAmount {
		return errors.New("an AUT with invalid scale")
	}
	return nil
}
func (tx *ReRegistrationTx) AUTIdentifier() []byte {
	return tx.CTAutIdentifier
}

func (tx *ReRegistrationTx) TxInputs() []*CTAUTToken {
	return tx.TxIns
}
func (tx *ReRegistrationTx) NumTxInputs() int {
	return int(tx.InAutRootCoinNum)
}
func (tx *ReRegistrationTx) SetTxInputs(autTxIns []*CTAUTToken) error {
	if len(autTxIns) != int(tx.InAutRootCoinNum) {
		return fmt.Errorf("invalid inputs")
	}
	tx.TxIns = autTxIns
	return nil
}
func (tx *ReRegistrationTx) TxOutputs() []*CTAUTToken {
	return tx.TxOuts
}
func (tx *ReRegistrationTx) ValueAt(uint8) uint64 {
	return 0
}

var _ Transaction = &ReRegistrationTx{}

// Flag = ”CTAUTTransfer”
// <Identifier> a byte array with fixed length
// <Number of AUTCoins> A number m, explicitly specify the 0~(m-1)-th TXO of this transaction as AUTCoins All other TXOs are regarded as normal TXOs.
// <Number of AUTCoins> A number n, explicitly specify the 0~(n-1)-th TXO of this transaction as AUTCoins All other TXOs are regarded as normal TXOs.
// <AUTTxoScript> a byte array with length n, each one for an AUTCoin
// <WitnessHash> a byte array with fixed length, for balance proof
// <Memo> a byte array with max length, for this transaction

type TransferTx struct {
	AutIdentifier []byte
	InAutCoinNum  uint8
	OutAutCoinNum uint8
	AUTTxoScript  [][]byte
	WitnessHash   []byte
	Memo          []byte // todo(Alice): how about TxMemo?

	TxIns  []*CTAUTToken
	TxOuts []*CTAUTToken
}

func (tx *TransferTx) Type() TransactionType {
	return Transfer
}
func (tx *TransferTx) Serialize() ([]byte, error) {
	// todo(Alice): initialize a space first
	// w := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))

	var b bytes.Buffer
	var err error

	_, err = b.WriteString(CommonPrefix)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(Transfer)
	if err != nil {
		return nil, err
	}

	err = WriteVarBytes(&b, 0, tx.AutIdentifier)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.InAutCoinNum)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.OutAutCoinNum)
	if err != nil {
		return nil, err
	}

	if int(tx.OutAutCoinNum) != len(tx.AUTTxoScript) {
		return nil, ErrInValidAUTTx
	}

	err = WriteVarInt(&b, 0, uint64(len(tx.AUTTxoScript)))
	if err != nil {
		return nil, err
	}

	for _, script := range tx.AUTTxoScript {
		err = WriteVarBytes(&b, 0, script)
		if err != nil {
			return nil, err
		}
	}

	err = WriteVarBytes(&b, 0, tx.Memo)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
func (tx *TransferTx) Deserialize(r io.Reader) error {
	var err error

	// todo(Alice): use bytes.NewReader()? which supports ReadByte

	commprefix := make([]byte, len(CommonPrefix))
	_, err = io.ReadFull(r, commprefix)
	if err != nil {
		return err
	}
	if !bytes.Equal(commprefix, []byte(CommonPrefix)) {
		return ErrNonAutTx
	}

	oneByte := make([]byte, 1)
	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	if oneByte[0] != Transfer {
		return ErrInValidAUTTx
	}

	tx.AutIdentifier, err = ReadVarBytes(r, 0, IdentifierLength, "identifier")
	if err != nil {
		return err
	}
	if len(tx.AutIdentifier) == 0 {
		return ErrInValidAUTTx
	}

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	tx.InAutCoinNum = oneByte[0]

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	tx.OutAutCoinNum = oneByte[0]

	numOutAutCoins, err := ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	if numOutAutCoins != uint64(tx.OutAutCoinNum) {
		return errors.New("mis-match output coin")
	}

	tx.AUTTxoScript = make([][]byte, numOutAutCoins)
	for i := 0; i < len(tx.AUTTxoScript); i++ {
		tx.AUTTxoScript[i], err = ReadVarBytes(r, 0, MaxAUTTxoScriptLength, "an AUT with invalid txo script")
		if err != nil {
			return err
		}
	}

	tx.Memo, err = ReadVarBytes(r, 0, MaxAUTTxMemoLength, "memo")
	if err != nil {
		return err
	}

	if len(tx.AutIdentifier) != IdentifierLength ||
		len(tx.Memo) > MaxAUTTxMemoLength {
		return errors.New("an AUT with invalid length of name")
	}
	return nil
}
func (tx *TransferTx) AUTIdentifier() []byte {
	return tx.AutIdentifier
}
func (tx *TransferTx) NumIns() int {
	return len(tx.TxIns)
}

func (tx *TransferTx) TxInputs() []*CTAUTToken {
	return tx.TxIns
}
func (tx *TransferTx) NumTxInputs() int {
	return int(tx.InAutCoinNum)
}
func (tx *TransferTx) SetTxInputs(autTxIns []*CTAUTToken) error {
	if len(autTxIns) != int(tx.InAutCoinNum) {
		return fmt.Errorf("invalid inputs")
	}
	tx.TxIns = autTxIns
	return nil
}
func (tx *TransferTx) TxOutputs() []*CTAUTToken {
	return tx.TxOuts

}

var _ Transaction = &TransferTx{}

// Flag = ”CTAUTBurn”
// <Identifier> a byte array with fixed length
// <Number of AUTCoins> A number m, explicitly specify the 0~(m-1)-th TXO of this transaction as AUTCoins All other TXOs are regarded as normal TXOs.
// <Vout> an integer, representing the amount of AUTCoins to be burned
// <WitnessHash> a byte array with fixed length, for balance proof
// <Memo> a byte array with max length, for this transaction

type BurnTx struct {
	AutIdentifier []byte
	InAutCoinNum  uint8
	OutAutCoinNum uint8
	TxoAUTScripts [][]byte
	WitnessHash   []byte
	Memo          []byte // 	// todo(Alice): how about TxMemo?

	TxIns  []*CTAUTToken
	TxOuts []*CTAUTToken
}

var _ Transaction = &BurnTx{}

func (tx *BurnTx) Type() TransactionType {
	return Burn
}
func (tx *BurnTx) Serialize() ([]byte, error) {
	// todo(Alice): initialize a space first
	// w := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))

	var b bytes.Buffer
	var err error

	_, err = b.WriteString(CommonPrefix)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(Burn)
	if err != nil {
		return nil, err
	}

	// todo(Alice): why use wire
	err = WriteVarBytes(&b, 0, tx.AutIdentifier)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.InAutCoinNum)
	if err != nil {
		return nil, err
	}

	err = WriteVarBytes(&b, 0, tx.Memo)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
func (tx *BurnTx) Deserialize(r io.Reader) error {
	var err error
	// todo(Alice): use bytes.NewReader()? which supports ReadByte
	commprefix := make([]byte, len(CommonPrefix))
	_, err = io.ReadFull(r, commprefix)
	if err != nil {
		return err
	}
	if !bytes.Equal(commprefix, []byte(CommonPrefix)) {
		return ErrNonAutTx
	}

	oneByte := make([]byte, 1)
	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	if oneByte[0] != Burn {
		return ErrInValidAUTTx
	}

	tx.AutIdentifier, err = ReadVarBytes(r, 0, IdentifierLength, "identifier")
	if err != nil {
		return err
	}
	if len(tx.AutIdentifier) == 0 {
		return ErrInValidAUTTx
	}

	_, err = io.ReadFull(r, oneByte)
	if err != nil {
		return err
	}
	tx.InAutCoinNum = oneByte[0]

	tx.Memo, err = ReadVarBytes(r, 0, MaxAUTTxMemoLength, "memo")
	if err != nil {
		return err
	}

	if len(tx.AutIdentifier) != IdentifierLength ||
		len(tx.Memo) > MaxAUTTxMemoLength {
		return errors.New("an AUT with invalid length of name")
	}
	return nil
}
func (tx *BurnTx) AUTIdentifier() []byte {
	return tx.AutIdentifier
}

func (tx *BurnTx) TxInputs() []*CTAUTToken {
	return tx.TxIns
}
func (tx *BurnTx) NumTxInputs() int {
	return int(tx.InAutCoinNum)
}
func (tx *BurnTx) SetTxInputs(autTxIns []*CTAUTToken) error {
	if len(autTxIns) != int(tx.InAutCoinNum) {
		return fmt.Errorf("invalid inputs")
	}
	tx.TxIns = autTxIns
	return nil
}
func (tx *BurnTx) TxOutputs() []*CTAUTToken {
	return nil
}

var ErrNonAutTx = errors.New("not a AUT transaction")
var ErrInValidAUTTx = errors.New("not a valid AUT transaction")
var ErrInValidIndex = errors.New("not a valid index")

// ExtractCTAutTransaction try to deserialize AUT transaction from transaction memo
// if success, do some sanity for AUT transaction:
// - check amount of output of origin transaction for AUT
// - check configuration of AUT transaction
// todo(AUT): using []byte rather than MsgTxAbe as input?
// In aut package, add ExtractCTAutTransaction function
// for each valid TrTx, ExtractAutTRansaction is called
// if returned (autTx,  nil)
// further proceeding
// logic should be aut package, but database operation should be in blockchain.

func ExtractCTAutTransaction(tx *wire.MsgTxAbe) (autTx Transaction, err error) {
	// could not be an AUT transaction
	if len(tx.TxMemo) <= CommonPrefixLength+1 {
		return nil, nil
	}
	if !bytes.Equal(tx.TxMemo[:CommonPrefixLength], []byte(CommonPrefix)) {
		return nil, nil
	}

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

	// we don't know whether the AUT name is exist or not, it should be checked by blockchain
	// and even the output rules are specified by the chain, so they are not check here.
	// Here only need to verify built-in rules of the AUT configuration itself, such as:
	// - limit for some configuration item
	// - length for some configuration item

	txHash := tx.TxHash()
	switch autTransaction := autTx.(type) {
	case *RegistrationTx:
		// skip the fully-privacy outputs
		startIdx := 0
		for ; startIdx < len(tx.TxOuts); startIdx++ {
			privacyLevel, err := abecryptox.GetTxoPrivacyLevel(tx.TxOuts[startIdx])
			if err != nil {
				return nil, err
			}
			if privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre ||
				privacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
				continue
			}

			if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
				return nil, fmt.Errorf("expect privacy level %d but got %d",
					abecryptoxkey.PrivacyLevelPSEUDONYMCT, privacyLevel)
			}
			break
		}

		if startIdx+int(autTransaction.OutAutRootCoinNum) > len(tx.TxOuts) {
			return nil, fmt.Errorf("claim %d root coins but only remain %d outputs",
				autTransaction.OutAutRootCoinNum, len(tx.TxOuts)-startIdx)
		}

		claimedCoinAddresses := map[string]struct{}{}
		for i := 0; i < len(autTransaction.IssuerTokens); i++ {
			coinAddress := autTransaction.IssuerTokens[i]
			key := hex.EncodeToString(coinAddress)
			// ensure no duplicates one
			if _, ok := claimedCoinAddresses[key]; !ok {
				claimedCoinAddresses[key] = struct{}{}
			}
		}
		if len(claimedCoinAddresses) != len(autTransaction.IssuerTokens) {
			return nil, fmt.Errorf("claimed repeated issue token")
		}

		//	todo(Alice): should not have coinAddress at this layer, how to match the token and actual coin address
		autTransaction.TxOuts = make([]*CTAUTToken, 0, autTransaction.OutAutRootCoinNum)
		tokenCoinAddresses := map[string]struct{}{}
		for i := 0; i < int(autTransaction.OutAutRootCoinNum); i++ {
			index := startIdx + i
			txOut := tx.TxOuts[index]
			coinAddress, err := CheckTxoSanity(txHash, index, txOut)
			if err != nil {
				return nil, err
			}

			key := hex.EncodeToString(coinAddress)
			if _, ok := tokenCoinAddresses[key]; !ok {
				tokenCoinAddresses[key] = struct{}{}
			}

			autTransaction.TxOuts = append(autTransaction.TxOuts, &CTAUTToken{
				OutPoint: OutPoint{
					TxHash: txHash,
					Index:  uint8(index),
				},
				ValueScript: nil, // nil for root coin
			})
		}

		// compare with claimed issueTokens
		for coinAddress := range tokenCoinAddresses {
			if _, ok := claimedCoinAddresses[coinAddress]; !ok {
				return nil, fmt.Errorf("use unclaimed issuer token")
			}
			delete(claimedCoinAddresses, coinAddress)
		}
		if len(claimedCoinAddresses) != 0 {
			return nil, fmt.Errorf("claim unused issuer token")
		}

		// configuration conflict
		if len(tokenCoinAddresses) < int(autTransaction.IssueTokensThreshold) ||
			len(tokenCoinAddresses) < int(autTransaction.IssuerUpdateThreshold) {
			return nil, fmt.Errorf("the num of exist tokens less than configurated threshold from transaction %s", txHash)
		}

		// TODO(CTAUT) necessary?
		if autTransaction.UnitScale > autTransaction.PlannedTotalAmount {
			return nil, errors.New("an AUT with invalid unit scale")
		}

	case *MintTx:
		// TODO need to check the length of outpoint ring?
		// TODO check the num of issue token?

		// TODO(CTAUT) Note that here is no enough information to known whether the input is pseudo txo or not
		// It has to be delayed until the chain data can be seen before checking.
		//if int(autTransaction.InAutRootCoinNum) > len(tx.TxIns) {
		//	return nil, ErrInValidAUTTx
		//}
		autTransaction.TxIns = make([]*CTAUTToken, autTransaction.InAutRootCoinNum)
		//for i := 0; i < int(autTransaction.InAutRootCoinNum); i++ {
		//	autTransaction.TxIns = append(autTransaction.TxIns, &CTAUTToken{
		//		OutPoint: OutPoint{
		//			TxHash: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
		//			Index:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
		//		},
		//		ValueScript: nil,
		//	})
		//}

		startIdx := 0
		for ; startIdx < len(tx.TxOuts); startIdx++ {
			privacyLevel, err := abecryptox.GetTxoPrivacyLevel(tx.TxOuts[startIdx])
			if err != nil {
				return nil, err
			}
			if privacyLevel == abecryptoxkey.PrivacyLevelRINGCTPre ||
				privacyLevel == abecryptoxkey.PrivacyLevelRINGCT {
				continue
			}

			if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
				return nil, fmt.Errorf("expect privacy level %d but got %d",
					abecryptoxkey.PrivacyLevelPSEUDONYMCT, privacyLevel)
			}
			break
		}

		if startIdx+int(autTransaction.OutAutCoinNum) > len(tx.TxOuts) {
			return nil, fmt.Errorf("claim %d root coins but only remain %d outputs",
				autTransaction.OutAutCoinNum, len(tx.TxOuts)-startIdx)
		}

		autTransaction.TxOuts = make([]*CTAUTToken, 0, autTransaction.OutAutCoinNum)
		tokenCoinAddresses := map[string]struct{}{}
		for i := 0; i < int(autTransaction.OutAutCoinNum); i++ {
			index := startIdx + i
			txOut := tx.TxOuts[index]
			coinAddress, err := CheckTxoSanity(txHash, index, txOut)
			if err != nil {
				return nil, err
			}

			key := hex.EncodeToString(coinAddress)
			if _, ok := tokenCoinAddresses[key]; !ok {
				tokenCoinAddresses[key] = struct{}{}
			}

			autTransaction.TxOuts = append(autTransaction.TxOuts, &CTAUTToken{
				OutPoint: OutPoint{
					TxHash: txHash,
					Index:  uint8(index),
				},
				ValueScript: autTransaction.AUTTxoScript[i],
			})
		}

	case *ReRegistrationTx:
		// TODO(CTAUT) Note that here is no enough information to known whether the input is pseudo txo or not
		// It has to be delayed until the chain data can be seen before checking.
		if int(autTransaction.InAutRootCoinNum) > len(tx.TxIns) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxIns = make([]*CTAUTToken, 0, autTransaction.InAutRootCoinNum)
		for i := 0; i < int(autTransaction.InAutRootCoinNum); i++ {
			autTransaction.TxIns = append(autTransaction.TxIns, &CTAUTToken{
				OutPoint: OutPoint{
					TxHash: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
					Index:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
				},
				ValueScript: nil,
			})
		}

		claimedCoinAddresses := map[string]struct{}{}
		for i := 0; i < len(autTransaction.IssuerTokens); i++ {
			privacyLevel, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(autTransaction.IssuerTokens[i])
			if err != nil {
				return nil, fmt.Errorf("fail to parse %d-th issuer token for aut from transaction %s", i, txHash)
			}
			if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM {
				return nil, fmt.Errorf("specified %d-th issuer token is invalid for aut from transaction %s", i, txHash)
			}
			key := hex.EncodeToString(coinAddress)
			if _, ok := claimedCoinAddresses[key]; !ok {
				claimedCoinAddresses[key] = struct{}{}
			}
		}
		if len(claimedCoinAddresses) != len(autTransaction.IssuerTokens) {
			return nil, fmt.Errorf("claimed repeated issuer token")
		}

		// invalid configurations can exit early
		// TODO need to check the length of outpoint ring?
		// TODO check the num of issue token?
		if int(autTransaction.InAutRootCoinNum) > len(tx.TxIns) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxIns = make([]*CTAUTToken, 0, autTransaction.InAutRootCoinNum)
		for i := 0; i < int(autTransaction.InAutRootCoinNum); i++ {
			autTransaction.TxIns = append(autTransaction.TxIns, &CTAUTToken{
				OutPoint: OutPoint{
					TxHash: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
					Index:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
				},
				ValueScript: nil,
			})
		}

		// invalid configurations can exit early
		if int(autTransaction.OutAutRootCoinNum) > len(tx.TxOuts) {
			return nil, ErrInValidAUTTx
		}

		autTransaction.TxOuts = make([]*CTAUTToken, 0, autTransaction.OutAutRootCoinNum)
		tokenCoinAddresses := map[string]struct{}{}
		for i := 0; i < int(autTransaction.OutAutRootCoinNum); i++ {
			txOut := tx.TxOuts[i]
			coinAddress, err := CheckTxoSanity(txHash, i, txOut)
			if err != nil {
				return nil, err
			}

			if _, ok := tokenCoinAddresses[hex.EncodeToString(coinAddress)]; !ok {
				tokenCoinAddresses[hex.EncodeToString(coinAddress)] = struct{}{}
			}

			autTransaction.TxOuts = append(autTransaction.TxOuts, &CTAUTToken{
				OutPoint: OutPoint{
					TxHash: txHash,
					Index:  uint8(i),
				},
				ValueScript: nil,
			})
		}

		// configuration conflict
		if len(tokenCoinAddresses) < int(autTransaction.IssueTokensThreshold) ||
			len(tokenCoinAddresses) < int(autTransaction.IssuerUpdateThreshold) {
			return nil, fmt.Errorf("the num of exist tokens less than configurated threshold from transaction %s", txHash)
		}

		if len(tokenCoinAddresses) != len(autTransaction.IssuerTokens) {
			return nil, fmt.Errorf("unmatched issuer tokens and outputs for aut root coin")
		}
		// compare claimed issueTokens
		for coinAddress := range tokenCoinAddresses {
			if _, ok := claimedCoinAddresses[coinAddress]; !ok {
				return nil, fmt.Errorf("use unclaimed issuer token")
			}
			delete(claimedCoinAddresses, coinAddress)
		}
		if len(claimedCoinAddresses) != 0 {
			return nil, fmt.Errorf("claimed unused issuer token")
		}

		if autTransaction.UnitScale > autTransaction.PlannedTotalAmount {
			return nil, errors.New("an AUT with invalid unit scale")
		}

	case *TransferTx:
		// invalid configurations can exit early
		// TODO need to check the length of outpoint ring?
		if int(autTransaction.InAutCoinNum) > len(tx.TxIns) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxIns = make([]*CTAUTToken, 0, autTransaction.InAutCoinNum)
		for i := 0; i < int(autTransaction.InAutCoinNum); i++ {
			autTransaction.TxIns = append(autTransaction.TxIns, &CTAUTToken{
				OutPoint: OutPoint{
					TxHash: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
					Index:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
				},
				ValueScript: nil,
			})
		}

		// invalid configurations can exit early
		if int(autTransaction.OutAutCoinNum) > len(tx.TxOuts) {
			return nil, ErrInValidAUTTx
		}
		txHash := tx.TxHash()
		for i := 0; i < int(autTransaction.OutAutCoinNum); i++ {
			_, err = CheckTxoSanity(txHash, i, tx.TxOuts[i])
			if err != nil {
				return nil, err
			}
			autTransaction.TxOuts = append(autTransaction.TxOuts, &CTAUTToken{
				OutPoint: OutPoint{
					TxHash: txHash,
					Index:  uint8(i),
				},
				ValueScript: nil,
			})
		}

	case *BurnTx:
		// invalid configurations can exit early
		if int(autTransaction.InAutCoinNum) > len(tx.TxIns) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxIns = make([]*CTAUTToken, 0, autTransaction.InAutCoinNum)
		for i := 0; i < int(autTransaction.InAutCoinNum); i++ {
			autTransaction.TxIns = append(autTransaction.TxIns, &CTAUTToken{
				OutPoint: OutPoint{
					TxHash: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
					Index:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
				},
				ValueScript: nil,
			})
		}
		// invalid configurations can exit early
		if int(autTransaction.OutAutCoinNum) > len(tx.TxOuts) {
			return nil, ErrInValidAUTTx
		}
		txHash := tx.TxHash()
		for i := 0; i < int(autTransaction.OutAutCoinNum); i++ {
			_, err = CheckTxoSanity(txHash, i, tx.TxOuts[i])
			if err != nil {
				return nil, err
			}
			autTransaction.TxOuts = append(autTransaction.TxOuts, &CTAUTToken{
				OutPoint: OutPoint{
					TxHash: txHash,
					Index:  uint8(i),
				},
				ValueScript: nil,
			})
		}

	default:
		return nil, ErrInValidAUTTx
	}

	return autTx, nil
}

func CheckTxoSanity(txHash chainhash.Hash, outputIndex int, txOut *wire.TxOutAbe) ([]byte, error) {
	privacyLevel, err := abecryptox.GetTxoPrivacyLevel(txOut)
	if err != nil {
		return nil, fmt.Errorf("fail to extract the privacy level from transaction %s:%s", txHash, err.Error())
	}
	if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYMCT {
		return nil, fmt.Errorf("invalid privacy level to %d-th output from transaction %s", outputIndex, txHash)
	}

	coinAddress, coinValue, err := abecryptox.PseudonymTxoCoinParse(txOut)
	if err != nil {
		return nil, fmt.Errorf("fail to parse %d-th output as an pseudonym txo from transaction %s", outputIndex, txHash)
	}
	if coinValue != 1 {
		return nil, fmt.Errorf("invalid value from %d-th output from transaction %s as AUT coin", outputIndex, txHash)
	}
	return coinAddress, nil
}

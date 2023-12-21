package aut

import (
	"bytes"
	"errors"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"io"
	"math"
	"strconv"
)

const (
	// MaxPrevOutIndex is the maximum index the index field of a previous
	// outpoint can be.
	// TODO 20231126
	MaxPrevOutIndex uint32 = 0xffffffff

	// defaultTxInOutAlloc is the default size used for the backing array for
	// transaction inputs and outputs.  The array will dynamically grow as needed,
	// but this figure is intended to provide enough space for the number of
	// inputs and outputs in a typical transaction without needing to grow the
	// backing array multiple times.
	defaultTxInOutAlloc = 15

	// minTxInPayload is the minimum payload size for a transaction input.
	// PreviousOutPoint.Hash + PreviousOutPoint.Index 4 bytes + Value 8 byte
	minTxInPayload = 12 + chainhash.HashSize
)

// OutPoint defines a aut data type that is used to track previous
// transaction outputs.
type OutPoint struct {
	Hash  chainhash.Hash
	Index uint8
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
	copy(buf[:], o.Hash.String())
	buf[2*chainhash.HashSize] = ':'
	buf = strconv.AppendUint(buf, uint64(o.Index), 10)
	return string(buf)
}

type TransactionType = uint8

const (
	Registration TransactionType = iota
	Mint
	ReRegistration
	Transfer
	Burn
)

const CommonPrefixLength = 9
const MaxNameLength = 20
const MaxMemoLength = 20
const MaxUnitLength = 20
const MaxMinUnitLength = 20

const MaxIssuerNum = 10

// AUTSCRIPT 0 varSize ...
// AUTSCRIPT 1 varSize ...

var CommonPrefix = []byte("AUTSCRIPT")

type Transaction interface {
	Type() TransactionType
	Serialize() ([]byte, error)
	Deserialize(io.Reader) error
	AUTName() []byte
	NumIns() int
	Ins() []OutPoint
	Outs() []OutPoint
	Values(uint8) uint64
}

type Info struct {
	Name               []byte
	Memo               []byte
	UpdateThreshold    uint8
	IssueThreshold     uint8
	PlannedTotalAmount uint64
	ExpireHeight       int32
	Issuers            []*chainhash.Hash
	UnitName           []byte
	MinUnitName        []byte
	UnitScale          uint64

	MintedAmount uint64
	RootCoinSet  map[OutPoint]struct{}
}

// Clone returns a shallow copy of the utxo entry.
func (info *Info) Clone() *Info {
	if info == nil {
		return nil
	}

	cloned := &Info{
		Name:               make([]byte, len(info.Name)),
		Memo:               make([]byte, len(info.Memo)),
		UpdateThreshold:    info.UpdateThreshold,
		IssueThreshold:     info.IssueThreshold,
		PlannedTotalAmount: info.PlannedTotalAmount,
		ExpireHeight:       info.ExpireHeight,
		Issuers:            make([]*chainhash.Hash, len(info.Issuers)),
		UnitName:           make([]byte, len(info.UnitName)),
		MinUnitName:        make([]byte, len(info.MinUnitName)),
		UnitScale:          info.UnitScale,
		MintedAmount:       info.MintedAmount,
		RootCoinSet:        make(map[OutPoint]struct{}, len(info.RootCoinSet)),
	}
	copy(cloned.Name, info.Name)
	copy(cloned.Memo, info.Memo)

	for i := 0; i < len(info.Issuers); i++ {
		cloned.Issuers[i] = &chainhash.Hash{}
		copy(cloned.Issuers[i][:], info.Issuers[i][:])
	}

	copy(cloned.UnitName, info.UnitName)
	copy(cloned.MinUnitName, info.MinUnitName)

	for outpoint, rootCoin := range info.RootCoinSet {
		cloned.RootCoinSet[outpoint] = rootCoin
	}

	return cloned
}

// Flag = ”AUTRegistration”
// <AUTName>
// a string
// <Issuers>
// an array of hash value
// each one represents a public key
// N <= 10
// <Expiry of Issuers>
// a height value
// <IssuerUpdateThreshold>
// An integer update_t <= N
// <IssueTokensThreshold>
// An integer mint_t <= N
// <Number of AUTRootCoins>
// A number n
// Explicitly specify the 0~(n-1)-th TXO of this transaction as RootCoins
// All other TXOs are regarded as normal AbelianCoins.
// [AutMemo]
// [Planed Total Amount]
// [UnitName]
// [MinUnitName]

type RegistrationTx struct {
	Name                  []byte
	Issuers               []*chainhash.Hash
	ExpireHeight          int32
	IssuerUpdateThreshold uint8 // TODO confirm the range
	IssueTokensThreshold  uint8
	NumOutAutRootCoins    uint8
	Memo                  []byte
	PlannedTotalAmount    uint64
	UnitName              []byte
	MinUnitName           []byte
	UnitScale             uint64

	TxIns  []OutPoint
	TxOuts []OutPoint
}

func (tx *RegistrationTx) Type() TransactionType {
	return Registration
}

func (tx *RegistrationTx) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var err error

	_, err = b.Write(CommonPrefix)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(Registration)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(&b, 0, tx.Name)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(&b, 0, uint64(len(tx.Issuers)))
	if err != nil {
		return nil, err
	}
	for _, issuer := range tx.Issuers {
		_, err = b.Write(issuer[:])
		if err != nil {
			return nil, err
		}
	}

	err = wire.WriteVarInt(&b, 0, uint64(tx.ExpireHeight))
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.IssuerUpdateThreshold)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.IssueTokensThreshold)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.NumOutAutRootCoins)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(&b, 0, tx.Memo)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(&b, 0, tx.PlannedTotalAmount)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(&b, 0, tx.UnitName)
	if err != nil {
		return nil, err
	}
	err = wire.WriteVarBytes(&b, 0, tx.MinUnitName)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(&b, 0, tx.UnitScale)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
func (tx *RegistrationTx) AUTName() []byte {
	return tx.Name
}
func (tx *RegistrationTx) Deserialize(r io.Reader) error {
	var err error

	commprefix := make([]byte, len(CommonPrefix))
	_, err = r.Read(commprefix)
	if err != nil {
		return err
	}
	if !bytes.Equal(commprefix, CommonPrefix) {
		return ErrNonAutTx
	}

	oneByte := make([]byte, 1)
	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	if oneByte[0] != Registration {
		return ErrInValidAUTTx
	}

	tx.Name, err = wire.ReadVarBytes(r, 0, MaxNameLength, "name")
	if err != nil {
		return err
	}
	if len(tx.Name) == 0 {
		return ErrInValidAUTTx
	}

	var numIssuer uint64
	numIssuer, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	tx.Issuers = make([]*chainhash.Hash, numIssuer)
	for i := 0; i < len(tx.Issuers); i++ {
		tx.Issuers[i] = &chainhash.Hash{}
		_, err = r.Read(tx.Issuers[i][:])
		if err != nil {
			return err
		}
	}

	var expireHeight uint64
	expireHeight, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if expireHeight > math.MaxInt32 {
		return ErrInValidAUTTx
	}
	tx.ExpireHeight = int32(expireHeight)

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.IssuerUpdateThreshold = oneByte[0]

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.IssueTokensThreshold = oneByte[0]

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.NumOutAutRootCoins = oneByte[0]

	tx.Memo, err = wire.ReadVarBytes(r, 0, MaxMemoLength, "memo")
	if err != nil {
		return err
	}

	tx.PlannedTotalAmount, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	tx.UnitName, err = wire.ReadVarBytes(r, 0, MaxUnitLength, "unit")
	if err != nil {
		return err
	}
	if len(tx.UnitName) == 0 {
		return ErrInValidAUTTx
	}

	tx.MinUnitName, err = wire.ReadVarBytes(r, 0, MaxMinUnitLength, "minUnit")
	if err != nil {
		return err
	}
	if len(tx.MinUnitName) == 0 {
		return ErrInValidAUTTx
	}

	tx.UnitScale, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	if len(tx.Name) > MaxNameLength ||
		len(tx.Memo) > MaxMemoLength ||
		len(tx.UnitName) > MaxUnitLength ||
		len(tx.MinUnitName) > MaxMinUnitLength {
		return errors.New("an AUT with invalid length of name")
	}
	if len(tx.Issuers) > MaxIssuerNum ||
		int(tx.IssueTokensThreshold) > len(tx.Issuers) ||
		int(tx.IssuerUpdateThreshold) > len(tx.Issuers) {
		return errors.New("an AUT with invalid threshold")
	}
	if tx.UnitScale > tx.PlannedTotalAmount {
		return errors.New("an AUT with invalid scale")
	}
	return nil
}
func (tx *RegistrationTx) NumIns() int {
	return len(tx.TxIns)
}
func (tx *RegistrationTx) Ins() []OutPoint {
	return tx.TxIns
}

func (tx *RegistrationTx) Outs() []OutPoint {
	return tx.TxOuts
}
func (tx *RegistrationTx) Values(uint8) uint64 {
	return 0
}

var _ Transaction = &RegistrationTx{}

// Flag = ”AUTMint”
// <AUTName>  a string
// <Number of AUTCoins> A number n, Explicitly specify the 0~(n-1)-th TXO of  this transaction as AUTCoins All other TXOs are regarded as normal TXOs.
// <TxoAUTValues> an array of n integer value each one for a an AUTCoin
// [Memo]
type MintTx struct {
	Name              []byte
	NumInAutRootCoins uint8
	NumOutAutCoins    uint8
	TxoAUTValues      []uint64
	Memo              []byte

	TxIns  []OutPoint
	TxOuts []OutPoint
}

func (tx *MintTx) Type() TransactionType {
	return Mint
}
func (tx *MintTx) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var err error

	_, err = b.Write(CommonPrefix)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(Mint)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(&b, 0, tx.Name)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.NumInAutRootCoins)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.NumOutAutCoins)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(&b, 0, uint64(len(tx.TxoAUTValues)))
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}
	for _, value := range tx.TxoAUTValues {
		err = wire.WriteVarInt(&b, 0, value)
		if err != nil {
			return nil, err
		}
	}

	err = wire.WriteVarBytes(&b, 0, tx.Memo)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil

}
func (tx *MintTx) Deserialize(r io.Reader) error {
	var err error

	commprefix := make([]byte, len(CommonPrefix))
	_, err = r.Read(commprefix)
	if err != nil {
		return err
	}
	if !bytes.Equal(commprefix, CommonPrefix) {
		return ErrNonAutTx
	}

	oneByte := make([]byte, 1)
	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	if oneByte[0] != Mint {
		return ErrInValidAUTTx
	}

	tx.Name, err = wire.ReadVarBytes(r, 0, MaxNameLength, "name")
	if err != nil {
		return err
	}
	if len(tx.Name) == 0 {
		return ErrInValidAUTTx
	}

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.NumInAutRootCoins = oneByte[0]

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.NumOutAutCoins = oneByte[0]

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	numOutAutCoins := oneByte[0]

	if tx.NumOutAutCoins != numOutAutCoins {
		return errors.New("mis-match output coin")
	}

	tx.TxoAUTValues = make([]uint64, numOutAutCoins)
	for i := 0; i < len(tx.TxoAUTValues); i++ {
		tx.TxoAUTValues[i], err = wire.ReadVarInt(r, 0)
		if err != nil {
			return err
		}
	}

	tx.Memo, err = wire.ReadVarBytes(r, 0, MaxMemoLength, "memo")
	if err != nil {
		return err
	}

	if len(tx.Name) > MaxNameLength ||
		len(tx.Memo) > MaxMemoLength {
		return errors.New("an AUT with invalid length of name")
	}
	return nil
}
func (tx *MintTx) AUTName() []byte {

	return tx.Name
}
func (tx *MintTx) NumIns() int {
	return len(tx.TxIns)
}
func (tx *MintTx) Ins() []OutPoint {
	return tx.TxIns
}

func (tx *MintTx) Outs() []OutPoint {
	return tx.TxOuts
}
func (tx *MintTx) Values(idx uint8) uint64 {
	if int(idx) < len(tx.TxoAUTValues) {
		return tx.TxoAUTValues[idx]
	}
	return 0
}

var _ Transaction = &MintTx{}

// Flag = ”AUTReRegistration”
// <AUTName> a string
// <Issuers> an array of hash value  each one represents a public key  N <= 10
// <Expiry of Issuers>  a height value
// <IssuerUpdateThreshold>  An integer update_t <= N
// <IssueTokensThreshold>  An integer mint_t <= N
// <Number of AUTRootCoins>  A number n  Explicitly specify the 0~(n-1)-th TXO of this transaction as RootCoins  All other TXOs are regarded as normal AbelianCoins.
type ReRegistrationTx struct {
	Name                  []byte
	Issuers               []*chainhash.Hash
	ExpireHeight          int32
	IssuerUpdateThreshold uint8 // TODO confirm the range
	IssueTokensThreshold  uint8
	NumInAutRootCoins     uint8
	NumOutAutRootCoins    uint8
	Memo                  []byte
	PlannedTotalAmount    uint64
	UnitScale             uint64

	TxIns  []OutPoint
	TxOuts []OutPoint
}

func (tx *ReRegistrationTx) Type() TransactionType {
	return ReRegistration
}
func (tx *ReRegistrationTx) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var err error

	_, err = b.Write(CommonPrefix)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(ReRegistration)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(&b, 0, tx.Name)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(&b, 0, uint64(len(tx.Issuers)))
	if err != nil {
		return nil, err
	}
	for _, issuer := range tx.Issuers {
		_, err = b.Write(issuer[:])
		if err != nil {
			return nil, err
		}
	}

	err = wire.WriteVarInt(&b, 0, uint64(tx.ExpireHeight))
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.IssuerUpdateThreshold)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.IssueTokensThreshold)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.NumInAutRootCoins)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.NumOutAutRootCoins)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(&b, 0, tx.Memo)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(&b, 0, tx.PlannedTotalAmount)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(&b, 0, tx.UnitScale)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
func (tx *ReRegistrationTx) Deserialize(r io.Reader) error {
	var err error

	commprefix := make([]byte, len(CommonPrefix))
	_, err = r.Read(commprefix)
	if err != nil {
		return err
	}
	if !bytes.Equal(commprefix, CommonPrefix) {
		return ErrNonAutTx
	}

	oneByte := make([]byte, 1)
	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	if oneByte[0] != ReRegistration {
		return ErrInValidAUTTx
	}

	tx.Name, err = wire.ReadVarBytes(r, 0, MaxNameLength, "name")
	if err != nil {
		return err
	}
	if len(tx.Name) == 0 {
		return ErrInValidAUTTx
	}

	var numIssuer uint64
	numIssuer, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	tx.Issuers = make([]*chainhash.Hash, numIssuer)
	for i := 0; i < len(tx.Issuers); i++ {
		tx.Issuers[i] = &chainhash.Hash{}
		_, err = r.Read(tx.Issuers[i][:])
		if err != nil {
			return err
		}
	}

	var expireHeight uint64
	expireHeight, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if tx.ExpireHeight > math.MaxInt32 {
		return ErrInValidAUTTx
	}
	tx.ExpireHeight = int32(expireHeight)

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.IssuerUpdateThreshold = oneByte[0]

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.IssueTokensThreshold = oneByte[0]

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.NumOutAutRootCoins = oneByte[0]

	tx.Memo, err = wire.ReadVarBytes(r, 0, MaxMemoLength, "memo")
	if err != nil {
		return err
	}

	tx.PlannedTotalAmount, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	tx.UnitScale, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	if len(tx.Name) > MaxNameLength || len(tx.Memo) > MaxMemoLength {
		return errors.New("an AUT with invalid length of name")
	}
	if len(tx.Issuers) > MaxIssuerNum ||
		int(tx.IssueTokensThreshold) > len(tx.Issuers) ||
		int(tx.IssuerUpdateThreshold) > len(tx.Issuers) {
		return errors.New("an AUT with invalid threshold")
	}
	if tx.UnitScale > tx.PlannedTotalAmount {
		return errors.New("an AUT with invalid scale")
	}
	return nil
}
func (tx *ReRegistrationTx) AUTName() []byte {
	return tx.Name
}
func (tx *ReRegistrationTx) NumIns() int {
	return len(tx.TxIns)
}
func (tx *ReRegistrationTx) Ins() []OutPoint {
	return tx.TxIns
}

func (tx *ReRegistrationTx) Outs() []OutPoint {
	return tx.TxOuts
}
func (tx *ReRegistrationTx) Values(uint8) uint64 {
	return 0
}

var _ Transaction = &ReRegistrationTx{}

// Flag = ”AUTTransfer”
// <AUTName> a string
// <Number of AUTCoins>  A number n  Explicitly specify the 0~(n-1)-th TXO of  this transaction as AUTCoins  All other TXOs are regarded as normal TXOs.
// <TxoAUTValues> an array of n integer value, each one for a AUTCoin-TXO
// [Memo]
type TransferTx struct {
	Name           []byte
	NumInAutCoins  uint8
	NumOutAutCoins uint8
	TxoAUTValues   []uint64
	Memo           []byte

	TxIns  []OutPoint
	TxOuts []OutPoint
}

func (tx *TransferTx) Type() TransactionType {
	return Transfer
}
func (tx *TransferTx) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var err error

	_, err = b.Write(CommonPrefix)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(Transfer)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(&b, 0, tx.Name)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.NumInAutCoins)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.NumOutAutCoins)
	if err != nil {
		return nil, err
	}

	if int(tx.NumOutAutCoins) != len(tx.TxoAUTValues) {
		return nil, ErrInValidAUTTx
	}

	err = wire.WriteVarInt(&b, 0, uint64(len(tx.TxoAUTValues)))
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, err
	}
	for _, value := range tx.TxoAUTValues {
		err = wire.WriteVarInt(&b, 0, value)
		if err != nil {
			return nil, err
		}
	}

	err = wire.WriteVarBytes(&b, 0, tx.Memo)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
func (tx *TransferTx) Deserialize(r io.Reader) error {
	var err error

	commprefix := make([]byte, len(CommonPrefix))
	_, err = r.Read(commprefix)
	if err != nil {
		return err
	}
	if !bytes.Equal(commprefix, CommonPrefix) {
		return ErrNonAutTx
	}

	oneByte := make([]byte, 1)
	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	if oneByte[0] != Transfer {
		return ErrInValidAUTTx
	}

	tx.Name, err = wire.ReadVarBytes(r, 0, MaxNameLength, "name")
	if err != nil {
		return err
	}
	if len(tx.Name) == 0 {
		return ErrInValidAUTTx
	}

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.NumInAutCoins = oneByte[0]

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.NumOutAutCoins = oneByte[0]

	numOutAutCoins, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	if numOutAutCoins != uint64(tx.NumOutAutCoins) {
		return errors.New("mis-match output coin")
	}

	tx.TxoAUTValues = make([]uint64, numOutAutCoins)
	for i := 0; i < len(tx.TxoAUTValues); i++ {
		tx.TxoAUTValues[i], err = wire.ReadVarInt(r, 0)
		if err != nil {
			return err
		}
	}

	tx.Memo, err = wire.ReadVarBytes(r, 0, MaxMemoLength, "memo")
	if err != nil {
		return err
	}

	if len(tx.Memo) > MaxMemoLength {
		return errors.New("an AUT with invalid length of name")
	}
	return nil
}
func (tx *TransferTx) AUTName() []byte {
	return tx.Name
}
func (tx *TransferTx) NumIns() int {
	return len(tx.TxIns)
}

func (tx *TransferTx) Ins() []OutPoint {
	return tx.TxIns
}

func (tx *TransferTx) Outs() []OutPoint {
	return tx.TxOuts

}
func (tx *TransferTx) Values(idx uint8) uint64 {
	if int(idx) < len(tx.TxoAUTValues) {
		return tx.TxoAUTValues[idx]
	}
	return 0
}

var _ Transaction = &TransferTx{}

// Flag = ”AUTBurn”
// <Name>  a string
// [Memo]
type BurnTx struct {
	Name          []byte
	NumInAutCoins uint8
	Memo          []byte

	TxIns  []OutPoint
	TxOuts []OutPoint
}

var _ Transaction = &BurnTx{}

func (tx *BurnTx) Type() TransactionType {
	return Burn
}
func (tx *BurnTx) Serialize() ([]byte, error) {
	var b bytes.Buffer
	var err error

	_, err = b.Write(CommonPrefix)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(Burn)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(&b, 0, tx.Name)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.NumInAutCoins)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(&b, 0, tx.Memo)
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}
func (tx *BurnTx) Deserialize(r io.Reader) error {
	var err error

	commprefix := make([]byte, len(CommonPrefix))
	_, err = r.Read(commprefix)
	if err != nil {
		return err
	}
	if !bytes.Equal(commprefix, CommonPrefix) {
		return ErrNonAutTx
	}

	oneByte := make([]byte, 1)
	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	if oneByte[0] != Burn {
		return ErrInValidAUTTx
	}

	tx.Name, err = wire.ReadVarBytes(r, 0, MaxNameLength, "name")
	if err != nil {
		return err
	}
	if len(tx.Name) == 0 {
		return ErrInValidAUTTx
	}

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.NumInAutCoins = oneByte[0]

	tx.Memo, err = wire.ReadVarBytes(r, 0, MaxMemoLength, "memo")
	if err != nil {
		return err
	}

	if len(tx.Memo) > MaxMemoLength {
		return errors.New("an AUT with invalid length of name")
	}
	return nil
}
func (tx *BurnTx) AUTName() []byte {
	return tx.Name
}
func (tx *BurnTx) NumIns() int {
	return len(tx.TxIns)
}
func (tx *BurnTx) Ins() []OutPoint {
	return tx.TxIns
}

func (tx *BurnTx) Outs() []OutPoint {
	return nil
}
func (tx *BurnTx) Values(uint8) uint64 {
	return 0
}

var ErrNonAutTx = errors.New("not a AUT transaction")
var ErrInValidAUTTx = errors.New("not a valid AUT transaction")

// DeserializeFromTx try to deserialize AUT transaction from transaction memo
// if success, do some sanity for AUT transaction:
// - check amount of output of origin transaction for AUT
// - check configuration of AUT transaction
func DeserializeFromTx(tx *wire.MsgTxAbe) (autTx Transaction, err error) {
	if len(tx.TxMemo) <= CommonPrefixLength {
		return nil, ErrNonAutTx
	}
	if !bytes.Equal(tx.TxMemo[:CommonPrefixLength], CommonPrefix) {
		return nil, ErrNonAutTx
	}

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

	switch autTransaction := autTx.(type) {
	case *RegistrationTx:
		// invalid configurations can exit early
		if int(autTransaction.NumOutAutRootCoins) > len(tx.TxOuts) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxOuts = make([]OutPoint, 0, autTransaction.NumOutAutRootCoins)
		for i := 0; i < int(autTransaction.NumOutAutRootCoins); i++ {
			autTransaction.TxOuts = append(autTransaction.TxOuts, OutPoint{
				Hash:  tx.TxHash(),
				Index: uint8(i),
			})
		}

		// configuration conflict
		if autTransaction.NumOutAutRootCoins < autTransaction.IssueTokensThreshold ||
			autTransaction.NumOutAutRootCoins < autTransaction.IssuerUpdateThreshold {
			return nil, errors.New("an AUT with invalid threshold")
		}
		if autTransaction.UnitScale > autTransaction.PlannedTotalAmount {
			return nil, errors.New("an AUT with invalid unit scale")
		}

	case *MintTx:
		// invalid configurations can exit early
		if int(autTransaction.NumInAutRootCoins) > len(tx.TxIns) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxIns = make([]OutPoint, 0, autTransaction.NumInAutRootCoins)
		for i := 0; i < int(autTransaction.NumInAutRootCoins); i++ {
			autTransaction.TxIns = append(autTransaction.TxIns, OutPoint{
				Hash:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
				Index: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
			})
		}

		// invalid configurations can exit early
		if int(autTransaction.NumOutAutCoins) > len(tx.TxOuts) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxOuts = make([]OutPoint, 0, autTransaction.NumOutAutCoins)
		for i := 0; i < int(autTransaction.NumOutAutCoins); i++ {
			autTransaction.TxOuts = append(autTransaction.TxOuts, OutPoint{
				Hash:  tx.TxHash(),
				Index: uint8(i),
			})
		}

	case *ReRegistrationTx:
		// invalid configurations can exit early
		if int(autTransaction.NumInAutRootCoins) > len(tx.TxIns) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxIns = make([]OutPoint, 0, autTransaction.NumInAutRootCoins)
		for i := 0; i < int(autTransaction.NumInAutRootCoins); i++ {
			autTransaction.TxIns = append(autTransaction.TxIns, OutPoint{
				Hash:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
				Index: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
			})
		}

		// invalid configurations can exit early
		if int(autTransaction.NumOutAutRootCoins) > len(tx.TxOuts) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxOuts = make([]OutPoint, 0, autTransaction.NumOutAutRootCoins)
		for i := 0; i < int(autTransaction.NumOutAutRootCoins); i++ {
			autTransaction.TxOuts = append(autTransaction.TxOuts, OutPoint{
				Hash:  tx.TxHash(),
				Index: uint8(i),
			})
		}

		// configuration conflict
		if autTransaction.NumOutAutRootCoins < autTransaction.IssueTokensThreshold ||
			autTransaction.NumOutAutRootCoins < autTransaction.IssuerUpdateThreshold {
			return nil, errors.New("an AUT with invalid threshold")
		}
	case *TransferTx:
		// invalid configurations can exit early
		if int(autTransaction.NumInAutCoins) > len(tx.TxIns) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxIns = make([]OutPoint, 0, autTransaction.NumInAutCoins)
		for i := 0; i < int(autTransaction.NumInAutCoins); i++ {
			// TODO Check length
			autTransaction.TxIns = append(autTransaction.TxIns, OutPoint{
				Hash:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
				Index: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
			})
		}

		// invalid configurations can exit early
		if int(autTransaction.NumOutAutCoins) > len(tx.TxOuts) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxOuts = make([]OutPoint, 0, autTransaction.NumOutAutCoins)
		for i := 0; i < int(autTransaction.NumOutAutCoins); i++ {
			// TODO check the value is 1
			//ExtractValueFromScript(tx.TxOuts[i].TxoScript)
			autTransaction.TxOuts = append(autTransaction.TxOuts, OutPoint{
				Hash:  tx.TxHash(),
				Index: uint8(i),
			})
		}
	case *BurnTx:
		// invalid configurations can exit early
		if int(autTransaction.NumInAutCoins) > len(tx.TxIns) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxIns = make([]OutPoint, 0, autTransaction.NumInAutCoins)
		for i := 0; i < int(autTransaction.NumInAutCoins); i++ {
			autTransaction.TxIns = append(autTransaction.TxIns, OutPoint{
				Hash:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
				Index: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
			})
		}
	default:
		return nil, ErrInValidAUTTx
	}

	return autTx, nil
}

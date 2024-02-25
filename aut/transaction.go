package aut

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
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

type TransactionType = uint8

// todo(AUT): hardcode rather than iota
const (
	Registration   TransactionType = 0
	Mint                           = 1
	ReRegistration                 = 2
	Transfer                       = 3
	Burn                           = 4
)

const CommonPrefixLength = 9
const MaxNameLength = 20
const MaxMemoLength = 20
const MaxUnitLength = 20
const MaxMinUnitLength = 20
const MaxIssuerTokenLength = 198 // TODO
const MaxIssuerNum = 10

// AUTSCRIPT 0 varSize ...
// AUTSCRIPT 1 varSize ...

// todo: using constant?
var CommonPrefix = []byte("AUTSCRIPT")

// todo(AUT): Ins --> TxIns(), Outs --> TxOuts (since Ins and Outs are too short to describe clearly).
// todo(AUT): NumIns() ? shall be removed?
// todo(AUT): Values() ?
type Transaction interface {
	Type() TransactionType
	Serialize() ([]byte, error)
	Deserialize(io.Reader) error
	AUTName() []byte
	Ins() []OutPoint
	Outs() []OutPoint
	Value(uint8) uint64
}

//const HashSize = 64

// todo: Info --> AutInstance? AutDef? or AutDesc ?
// ReRegistration will update this info? If true, this means AutState or AutMeta?
// How to store the history AutState?
// Use a bucket store the history AutState, and AutEntry refers to the latest?
//type AUTHash [HashSize]byte

//func Hash(b []byte) AUTHash {
//	return AUTHash(sha3.Sum512(b))
//}

type Info struct {
	AutName            []byte
	IssuerTokens       [][]byte //[] crypto address // todo(AUT): using SHA3-512, define a standalone hash in AUT. Hash(CoinAddress)?
	UpdateThreshold    uint8
	IssueThreshold     uint8
	PlannedTotalAmount uint64
	ExpireHeight       int32
	UnitName           []byte
	MinUnitName        []byte
	UnitScale          uint64
	AutMemo            []byte

	MintedAmount uint64
	RootCoinSet  map[OutPoint]struct{} // todo(AUT): this is all or only the actives ones.
}

// Clone returns a shallow copy of the utxo entry.
func (info *Info) Clone() *Info {
	if info == nil {
		return nil
	}

	cloned := &Info{
		AutName:            make([]byte, len(info.AutName)),
		AutMemo:            make([]byte, len(info.AutMemo)),
		UpdateThreshold:    info.UpdateThreshold,
		IssueThreshold:     info.IssueThreshold,
		PlannedTotalAmount: info.PlannedTotalAmount,
		ExpireHeight:       info.ExpireHeight,
		IssuerTokens:       make([][]byte, len(info.IssuerTokens)),
		UnitName:           make([]byte, len(info.UnitName)),
		MinUnitName:        make([]byte, len(info.MinUnitName)),
		UnitScale:          info.UnitScale,
		MintedAmount:       info.MintedAmount,
		RootCoinSet:        make(map[OutPoint]struct{}, len(info.RootCoinSet)),
	}
	copy(cloned.AutName, info.AutName)
	copy(cloned.AutMemo, info.AutMemo)

	for i := 0; i < len(info.IssuerTokens); i++ {
		cloned.IssuerTokens[i] = make([]byte, len(info.IssuerTokens[i]))
		copy(cloned.IssuerTokens[i][:], info.IssuerTokens[i][:])
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
// <IssuerTokens>
// an array of hash value
// each one represents a public key
// N <= 10
// <Expiry of IssuerTokens>
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

// todo: RegistrationTx has its TxMemo, where a user can specify.
// and each AUT instance has its Memo (simialr to a description of the AutInstance).
// Why this is dupliating the Info?
type RegistrationTx struct {
	AutName               []byte   // todo(AUT): AutName ?
	IssuerTokens          [][]byte // todo(AUT): same as in Info
	ExpireHeight          int32
	IssueTokensThreshold  uint8
	IssuerUpdateThreshold uint8 // TODO confirm the range
	OutAutRootCoinNum     uint8
	AutMemo               []byte
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

	err = wire.WriteVarBytes(&b, 0, tx.AutName)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(&b, 0, uint64(len(tx.IssuerTokens)))
	if err != nil {
		return nil, err
	}
	for _, issuer := range tx.IssuerTokens {
		err = wire.WriteVarBytes(&b, 0, issuer[:])
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

	err = b.WriteByte(tx.OutAutRootCoinNum)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarBytes(&b, 0, tx.AutMemo)
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
	return tx.AutName
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

	tx.AutName, err = wire.ReadVarBytes(r, 0, MaxNameLength, "name")
	if err != nil {
		return err
	}
	if len(tx.AutName) == 0 {
		return ErrInValidAUTTx
	}

	var numIssuer uint64
	numIssuer, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	tx.IssuerTokens = make([][]byte, numIssuer)
	existIssuerTokens := map[string]struct{}{}
	for i := 0; i < len(tx.IssuerTokens); i++ {
		tx.IssuerTokens[i], err = wire.ReadVarBytes(r, 0, MaxIssuerTokenLength, "issuerToken")
		if err != nil {
			return err
		}
		if _, ok := existIssuerTokens[hex.EncodeToString(tx.IssuerTokens[i])]; ok {
			return ErrInValidAUTTx
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
	tx.OutAutRootCoinNum = oneByte[0]

	tx.AutMemo, err = wire.ReadVarBytes(r, 0, MaxMemoLength, "memo")
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

	if len(tx.AutName) > MaxNameLength ||
		len(tx.AutMemo) > MaxMemoLength ||
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
func (tx *RegistrationTx) NumIns() int {
	return len(tx.TxIns)
}
func (tx *RegistrationTx) Ins() []OutPoint {
	return tx.TxIns
}

func (tx *RegistrationTx) Outs() []OutPoint {
	return tx.TxOuts
}
func (tx *RegistrationTx) Value(uint8) uint64 {
	return 0
}

var _ Transaction = &RegistrationTx{}

// Flag = ”AUTMint”
// <AUTName>  a string
// <Number of AUTCoins> A number n, Explicitly specify the 0~(n-1)-th TXO of  this transaction as AUTCoins All other TXOs are regarded as normal TXOs.
// <TxoAUTValues> an array of n integer value each one for a an AUTCoin
// [Memo]
type MintTx struct {
	AutName          []byte
	InAutRootCoinNum uint8
	OutAutCoinNum    uint8
	TxoAUTValues     []uint64
	Memo             []byte

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

	err = wire.WriteVarBytes(&b, 0, tx.AutName)
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

	tx.AutName, err = wire.ReadVarBytes(r, 0, MaxNameLength, "name")
	if err != nil {
		return err
	}
	if len(tx.AutName) == 0 {
		return ErrInValidAUTTx
	}

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.InAutRootCoinNum = oneByte[0]

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.OutAutCoinNum = oneByte[0]

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	numOutAutCoins := oneByte[0]

	if tx.OutAutCoinNum != numOutAutCoins {
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

	if len(tx.AutName) > MaxNameLength ||
		len(tx.Memo) > MaxMemoLength {
		return errors.New("an AUT with invalid length of name")
	}
	return nil
}
func (tx *MintTx) AUTName() []byte {
	return tx.AutName
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
func (tx *MintTx) Value(idx uint8) uint64 {
	if int(idx) < len(tx.TxoAUTValues) {
		return tx.TxoAUTValues[idx]
	}
	return 0
}

var _ Transaction = &MintTx{}

// Flag = ”AUTReRegistration”
// <AUTName> a string
// <IssuerTokens> an array of hash value  each one represents a public key  N <= 10
// <Expiry of IssuerTokens>  a height value
// <IssuerUpdateThreshold>  An integer update_t <= N
// <IssueTokensThreshold>  An integer mint_t <= N
// <Number of AUTRootCoins>  A number n  Explicitly specify the 0~(n-1)-th TXO of this transaction as RootCoins  All other TXOs are regarded as normal AbelianCoins.
type ReRegistrationTx struct {
	AutName               []byte
	IssuerTokens          [][]byte
	ExpireHeight          int32
	IssuerUpdateThreshold uint8 // TODO confirm the range
	IssueTokensThreshold  uint8
	InAutRootCoinNum      uint8
	OutAutRootCoinNum     uint8
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

	err = wire.WriteVarBytes(&b, 0, tx.AutName)
	if err != nil {
		return nil, err
	}

	err = wire.WriteVarInt(&b, 0, uint64(len(tx.IssuerTokens)))
	if err != nil {
		return nil, err
	}
	for _, issuer := range tx.IssuerTokens {
		err = wire.WriteVarBytes(&b, 0, issuer)
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

	err = b.WriteByte(tx.InAutRootCoinNum)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.OutAutRootCoinNum)
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

	tx.AutName, err = wire.ReadVarBytes(r, 0, MaxNameLength, "name")
	if err != nil {
		return err
	}
	if len(tx.AutName) == 0 {
		return ErrInValidAUTTx
	}

	var numIssuer uint64
	numIssuer, err = wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	tx.IssuerTokens = make([][]byte, numIssuer)
	existIssuerTokens := map[string]struct{}{}
	for i := 0; i < len(tx.IssuerTokens); i++ {
		tx.IssuerTokens[i], err = wire.ReadVarBytes(r, 0, MaxIssuerTokenLength, "issuerToken")
		if err != nil {
			return err
		}
		if _, ok := existIssuerTokens[hex.EncodeToString(tx.IssuerTokens[i])]; ok {
			return ErrInValidAUTTx
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
	tx.InAutRootCoinNum = oneByte[0]

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.OutAutRootCoinNum = oneByte[0]

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

	if len(tx.AutName) > MaxNameLength || len(tx.Memo) > MaxMemoLength {
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
func (tx *ReRegistrationTx) AUTName() []byte {
	return tx.AutName
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
func (tx *ReRegistrationTx) Value(uint8) uint64 {
	return 0
}

var _ Transaction = &ReRegistrationTx{}

// Flag = ”AUTTransfer”
// <AUTName> a string
// <Number of AUTCoins>  A number n  Explicitly specify the 0~(n-1)-th TXO of  this transaction as AUTCoins  All other TXOs are regarded as normal TXOs.
// <TxoAUTValues> an array of n integer value, each one for a AUTCoin-TXO
// [Memo]
type TransferTx struct {
	AutName       []byte
	InAutCoinNum  uint8
	OutAutCoinNum uint8
	TxoAUTValues  []uint64
	Memo          []byte

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

	err = wire.WriteVarBytes(&b, 0, tx.AutName)
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

	if int(tx.OutAutCoinNum) != len(tx.TxoAUTValues) {
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

	tx.AutName, err = wire.ReadVarBytes(r, 0, MaxNameLength, "name")
	if err != nil {
		return err
	}
	if len(tx.AutName) == 0 {
		return ErrInValidAUTTx
	}

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.InAutCoinNum = oneByte[0]

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.OutAutCoinNum = oneByte[0]

	numOutAutCoins, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}

	if numOutAutCoins != uint64(tx.OutAutCoinNum) {
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
	return tx.AutName
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
func (tx *TransferTx) Value(idx uint8) uint64 {
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
	AutName      []byte
	InAutCoinNum uint8
	Memo         []byte

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

	err = wire.WriteVarBytes(&b, 0, tx.AutName)
	if err != nil {
		return nil, err
	}

	err = b.WriteByte(tx.InAutCoinNum)
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

	tx.AutName, err = wire.ReadVarBytes(r, 0, MaxNameLength, "name")
	if err != nil {
		return err
	}
	if len(tx.AutName) == 0 {
		return ErrInValidAUTTx
	}

	_, err = r.Read(oneByte)
	if err != nil {
		return err
	}
	tx.InAutCoinNum = oneByte[0]

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
	return tx.AutName
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
func (tx *BurnTx) Value(uint8) uint64 {
	return 0
}

var ErrNonAutTx = errors.New("not a AUT transaction")
var ErrInValidAUTTx = errors.New("not a valid AUT transaction")

// ExtractAutTransaction try to deserialize AUT transaction from transaction memo
// if success, do some sanity for AUT transaction:
// - check amount of output of origin transaction for AUT
// - check configuration of AUT transaction
// todo(AUT): using []byte rather than MsgTxAbe as input?
// In aut package, add ExtractAutTransaction function
// for each valid TrTx, ExtractAutTRansaction is called
// if returned (autTx,  nil)
// further proceeding
// logic should be aut package, but database operation should be in blockchain.

func ExtractAutTransaction(tx *wire.MsgTxAbe) (autTx Transaction, err error) {
	if len(tx.TxMemo) <= CommonPrefixLength {
		return nil, nil
	}
	if !bytes.Equal(tx.TxMemo[:CommonPrefixLength], CommonPrefix) {
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

	switch autTransaction := autTx.(type) {
	case *RegistrationTx:
		// invalid configurations can exit early
		if int(autTransaction.OutAutRootCoinNum) > len(tx.TxOuts) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxOuts = make([]OutPoint, 0, autTransaction.OutAutRootCoinNum)
		txHash := tx.TxHash()

		existCoinAddresses := map[string]struct{}{}
		for i := 0; i < int(autTransaction.OutAutRootCoinNum); i++ {
			txOut := tx.TxOuts[i]
			coinAddress, err := CheckTxoSanity(txHash, i, txOut)
			if err != nil {
				return nil, err
			}

			if _, ok := existCoinAddresses[hex.EncodeToString(coinAddress)]; !ok {
				existCoinAddresses[hex.EncodeToString(coinAddress)] = struct{}{}
			}

			autTransaction.TxOuts = append(autTransaction.TxOuts, OutPoint{
				TxHash: txHash,
				Index:  uint8(i),
			})
		}

		// configuration conflict
		if len(existCoinAddresses) < int(autTransaction.IssueTokensThreshold) ||
			len(existCoinAddresses) < int(autTransaction.IssuerUpdateThreshold) {
			return nil, fmt.Errorf("the num of exist tokens less than configurated threshold from transaction %s", txHash)
		}

		if len(existCoinAddresses) != len(autTransaction.IssuerTokens) {
			return nil, fmt.Errorf("unmatched issuer tokens and outputs for aut root coin")
		}
		// compare claimed issueTokens
		for i := 0; i < len(autTransaction.IssuerTokens); i++ {
			privacyLevel, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(autTransaction.IssuerTokens[i])
			if err != nil {
				return nil, fmt.Errorf("fail to parse %d-th issuer token for aut from transaction %s", i, txHash)
			}
			if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM {
				return nil, fmt.Errorf("specified %d-th issuer token is invalid for aut from transaction %s", i, txHash)
			}
			key := hex.EncodeToString(coinAddress)
			if _, ok := existCoinAddresses[key]; !ok {
				return nil, fmt.Errorf("the claimed issuer tokens claims duplicate issuer token or "+
					"claims non-exist issuer tken in root coin from transaction %s", txHash)
			}
			delete(existCoinAddresses, key)
		}
		if len(existCoinAddresses) != 0 {
			return nil, fmt.Errorf("unmatched issuer tokens and outputs for aut root coin")
		}

		if autTransaction.UnitScale > autTransaction.PlannedTotalAmount {
			return nil, errors.New("an AUT with invalid unit scale")
		}

	case *MintTx:
		// invalid configurations can exit early
		// TODO need to check the length of outpoint ring?
		// TODO check the num of issue token?
		if int(autTransaction.InAutRootCoinNum) > len(tx.TxIns) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxIns = make([]OutPoint, 0, autTransaction.InAutRootCoinNum)
		for i := 0; i < int(autTransaction.InAutRootCoinNum); i++ {
			autTransaction.TxIns = append(autTransaction.TxIns, OutPoint{
				TxHash: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
				Index:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
			})
		}

		// invalid configurations can exit early
		if int(autTransaction.OutAutCoinNum) > len(tx.TxOuts) {
			return nil, ErrInValidAUTTx
		}

		autTransaction.TxOuts = make([]OutPoint, 0, autTransaction.OutAutCoinNum)
		txHash := tx.TxHash()
		for i := 0; i < int(autTransaction.OutAutCoinNum); i++ {
			txOut := tx.TxOuts[i]
			_, err := CheckTxoSanity(txHash, i, txOut)
			if err != nil {
				return nil, err
			}

			autTransaction.TxOuts = append(autTransaction.TxOuts, OutPoint{
				TxHash: txHash,
				Index:  uint8(i),
			})
		}

	case *ReRegistrationTx:
		// invalid configurations can exit early
		// TODO need to check the length of outpoint ring?
		// TODO check the num of issue token?
		if int(autTransaction.InAutRootCoinNum) > len(tx.TxIns) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxIns = make([]OutPoint, 0, autTransaction.InAutRootCoinNum)
		for i := 0; i < int(autTransaction.InAutRootCoinNum); i++ {
			autTransaction.TxIns = append(autTransaction.TxIns, OutPoint{
				TxHash: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
				Index:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
			})
		}

		// invalid configurations can exit early
		if int(autTransaction.OutAutRootCoinNum) > len(tx.TxOuts) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxOuts = make([]OutPoint, 0, autTransaction.OutAutRootCoinNum)
		txHash := tx.TxHash()

		existCoinAddresses := map[string]struct{}{}
		for i := 0; i < int(autTransaction.OutAutRootCoinNum); i++ {
			txOut := tx.TxOuts[i]
			coinAddress, err := CheckTxoSanity(txHash, i, txOut)
			if err != nil {
				return nil, err
			}

			if _, ok := existCoinAddresses[hex.EncodeToString(coinAddress)]; !ok {
				existCoinAddresses[hex.EncodeToString(coinAddress)] = struct{}{}
			}

			autTransaction.TxOuts = append(autTransaction.TxOuts, OutPoint{
				TxHash: txHash,
				Index:  uint8(i),
			})
		}

		// configuration conflict
		if len(existCoinAddresses) < int(autTransaction.IssueTokensThreshold) ||
			len(existCoinAddresses) < int(autTransaction.IssuerUpdateThreshold) {
			return nil, fmt.Errorf("the num of exist tokens less than configurated threshold from transaction %s", txHash)
		}

		if len(existCoinAddresses) != len(autTransaction.IssuerTokens) {
			return nil, fmt.Errorf("unmatched issuer tokens and outputs for aut root coin")
		}
		// compare claimed issueTokens
		for i := 0; i < len(autTransaction.IssuerTokens); i++ {
			privacyLevel, coinAddress, _, err := abecryptoxkey.CryptoAddressParse(autTransaction.IssuerTokens[i])
			if err != nil {
				return nil, fmt.Errorf("fail to parse %d-th issuer token for aut from transaction %s", i, txHash)
			}
			if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM {
				return nil, fmt.Errorf("specified %d-th issuer token is invalid for aut from transaction %s", i, txHash)
			}
			key := hex.EncodeToString(coinAddress)
			if _, ok := existCoinAddresses[key]; !ok {
				return nil, fmt.Errorf("the claimed issuer tokens claims duplicate issuer token or "+
					"claims non-exist issuer tken in root coin from transaction %s", txHash)
			}
			delete(existCoinAddresses, key)
		}
		if len(existCoinAddresses) != 0 {
			return nil, fmt.Errorf("unmatched issuer tokens and outputs for aut root coin")
		}
	case *TransferTx:
		// invalid configurations can exit early
		// TODO need to check the length of outpoint ring?
		if int(autTransaction.InAutCoinNum) > len(tx.TxIns) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxIns = make([]OutPoint, 0, autTransaction.InAutCoinNum)
		for i := 0; i < int(autTransaction.InAutCoinNum); i++ {
			// TODO Check length
			autTransaction.TxIns = append(autTransaction.TxIns, OutPoint{
				TxHash: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
				Index:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
			})
		}

		// invalid configurations can exit early
		if int(autTransaction.OutAutCoinNum) > len(tx.TxOuts) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxOuts = make([]OutPoint, 0, autTransaction.OutAutCoinNum)

		txHash := tx.TxHash()
		for i := 0; i < int(autTransaction.OutAutCoinNum); i++ {
			_, err = CheckTxoSanity(txHash, i, tx.TxOuts[i])
			if err != nil {
				return nil, err
			}
			autTransaction.TxOuts = append(autTransaction.TxOuts, OutPoint{
				TxHash: txHash,
				Index:  uint8(i),
			})
		}

	case *BurnTx:
		// invalid configurations can exit early
		if int(autTransaction.InAutCoinNum) > len(tx.TxIns) {
			return nil, ErrInValidAUTTx
		}
		autTransaction.TxIns = make([]OutPoint, 0, autTransaction.InAutCoinNum)
		for i := 0; i < int(autTransaction.InAutCoinNum); i++ {
			autTransaction.TxIns = append(autTransaction.TxIns, OutPoint{
				TxHash: tx.TxIns[i].PreviousOutPointRing.OutPoints[0].TxHash,
				Index:  tx.TxIns[i].PreviousOutPointRing.OutPoints[0].Index,
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
	if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM {
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

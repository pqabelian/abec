package aut

import (
	"bytes"
	"errors"
	"github.com/abesuite/abec/chainhash"
	"github.com/abesuite/abec/wire"
	"io"
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
	NumOuts() int
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
	NumAutRootCoins       uint8
	Memo                  []byte
	PlannedTotalAmount    uint64
	UnitName              []byte
	MinUnitName           []byte
	UnitScale             uint64

	TxHash chainhash.Hash
	TxIns  []*OutPoint
	TxOuts []OutPoint
}

func (tx *RegistrationTx) Type() TransactionType {
	return Registration
}

func (tx *RegistrationTx) Serialize() ([]byte, error) {
	panic("implement me!")
}
func (tx *RegistrationTx) AUTName() []byte {
	panic("implement me!")
}
func (tx *RegistrationTx) Deserialize(r io.Reader) error {
	panic("implement me!")
}
func (tx *RegistrationTx) NumIns() int {
	panic("implement me!")
}
func (tx *RegistrationTx) NumOuts() int {
	panic("implement me!")
}
func (tx *RegistrationTx) Ins() []OutPoint {
	//TODO implement me
	panic("implement me")
}

func (tx *RegistrationTx) Outs() []OutPoint {
	//TODO implement me
	panic("implement me")
}
func (tx *RegistrationTx) Values(uint8) uint64 {
	//TODO implement me
	panic("implement me")
}

var _ Transaction = &RegistrationTx{}

// Flag = ”AUTMint”
// <AUTName>  a string
// <Number of AUTCoins> A number n, Explicitly specify the 0~(n-1)-th TXO of  this transaction as AUTCoins All other TXOs are regarded as normal TXOs.
// <TxoAUTValues> an array of n integer value each one for a an AUTCoin
// [Memo]
type MintTx struct {
	Name         []byte
	NumAutCoins  uint8
	TxoAUTValues []uint64
	Memo         []byte

	TxHash chainhash.Hash
	TxIns  []OutPoint
	TxOuts []OutPoint
}

func (tx *MintTx) Type() TransactionType {
	return Mint
}
func (tx *MintTx) Serialize() ([]byte, error) {
	panic("implement me!")
}
func (tx *MintTx) Deserialize(r io.Reader) error {
	panic("implement me!")
}
func (tx *MintTx) AUTName() []byte {
	panic("implement me!")
}
func (tx *MintTx) NumIns() int {
	panic("implement me!")
}
func (tx *MintTx) NumOuts() int {
	//TODO implement me
	panic("implement me")
}
func (tx *MintTx) Ins() []OutPoint {
	//TODO implement me
	panic("implement me")
}

func (tx *MintTx) Outs() []OutPoint {
	//TODO implement me
	panic("implement me")
}
func (tx *MintTx) Values(uint8) uint64 {
	//TODO implement me
	panic("implement me")
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
	NumAutRootCoins       uint8
	Memo                  []byte
	PlannedTotalAmount    uint64

	TxHash chainhash.Hash
	TxIns  []OutPoint
	TxOuts []OutPoint
}

func (tx *ReRegistrationTx) Type() TransactionType {
	return ReRegistration
}
func (tx *ReRegistrationTx) Serialize() ([]byte, error) {
	panic("implement me!")
}
func (tx *ReRegistrationTx) Deserialize(r io.Reader) error {
	panic("implement me!")
}
func (tx *ReRegistrationTx) AUTName() []byte {
	panic("implement me!")
}
func (tx *ReRegistrationTx) NumIns() int {
	panic("implement me!")
}
func (tx *ReRegistrationTx) NumOuts() int {
	//TODO implement me
	panic("implement me")
}
func (tx *ReRegistrationTx) Ins() []OutPoint {
	//TODO implement me
	panic("implement me")
}

func (tx *ReRegistrationTx) Outs() []OutPoint {
	//TODO implement me
	panic("implement me")
}
func (tx *ReRegistrationTx) Values(uint8) uint64 {
	//TODO implement me
	panic("implement me")
}

var _ Transaction = &ReRegistrationTx{}

// Flag = ”AUTTransfer”
// <AUTName> a string
// <Number of AUTCoins>  A number n  Explicitly specify the 0~(n-1)-th TXO of  this transaction as AUTCoins  All other TXOs are regarded as normal TXOs.
// <TxoAUTValues> an array of n integer value, each one for a AUTCoin-TXO
// [Memo]
type TransferTx struct {
	Name         []byte
	NumAutCoins  uint8
	TxoAUTValues []uint64
	Memo         []byte

	TxHash chainhash.Hash
	TxIns  []OutPoint
	TxOuts []OutPoint
}

func (tx *TransferTx) Type() TransactionType {
	return Transfer
}
func (tx *TransferTx) Serialize() ([]byte, error) {
	panic("implement me!")
}
func (tx *TransferTx) Deserialize(r io.Reader) error {
	panic("implement me!")
}
func (tx *TransferTx) AUTName() []byte {
	panic("implement me!")
}
func (tx *TransferTx) NumIns() int {
	panic("implement me!")
}

func (tx *TransferTx) NumOuts() int {
	//TODO implement me
	panic("implement me")
}
func (tx *TransferTx) Ins() []OutPoint {
	//TODO implement me
	panic("implement me")
}

func (tx *TransferTx) Outs() []OutPoint {
	//TODO implement me
	panic("implement me")
}
func (tx *TransferTx) Values(uint8) uint64 {
	//TODO implement me
	panic("implement me")
}

var _ Transaction = &TransferTx{}

// Flag = ”AUTBurn”
// <Name>  a string
// [Memo]
type BurnTx struct {
	Name []byte
	Memo []byte

	TxHash chainhash.Hash
	TxIns  []OutPoint
	TxOuts []OutPoint
}

var _ Transaction = &BurnTx{}

func (tx *BurnTx) Type() TransactionType {
	return Burn
}
func (tx *BurnTx) Serialize() ([]byte, error) {
	panic("implement me!")
}
func (tx *BurnTx) Deserialize(r io.Reader) error {
	panic("implement me!")
}
func (tx *BurnTx) AUTName() []byte {
	panic("implement me!")
}
func (tx *BurnTx) NumIns() int {
	panic("implement me!")
}
func (tx *BurnTx) NumOuts() int {
	return 0
}
func (tx *BurnTx) Ins() []OutPoint {
	//TODO implement me
	panic("implement me")
}

func (tx *BurnTx) Outs() []OutPoint {
	//TODO implement me
	panic("implement me")
}
func (tx *BurnTx) Values(uint8) uint64 {
	//TODO implement me
	panic("implement me")
}

var ErrNonAutTx = errors.New("not a AUT transaction")
var ErrInValidAUTTx = errors.New("not a valid AUT transaction")

func DeserializeFromTx(tx *wire.MsgTxAbe) (autTx Transaction, err error) {
	if len(tx.TxMemo) < CommonPrefixLength {
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
	reader := bytes.NewBuffer(tx.TxMemo[CommonPrefixLength+1:])
	err = autTx.Deserialize(reader)
	if err != nil {
		return nil, err
	}

	return autTx, nil
}

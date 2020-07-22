package abeutil

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abesalrs"
)

// MasterAddressSalrsMasterPubKey implements the interface MasterAddress for CryptoScheme SALRS
type MasterAddressSalrs struct {
	//	cryptoScheme seems to be redundant, at this moment, just work for double-check
	cryptoScheme abecrypto.CryptoScheme
	masterPubKey *abesalrs.MasterPubKey
}

// SerializeSize returns the number of bytes it would take to serialize the MasterAddressSalrs.
func (maddr *MasterAddressSalrs) SerializeSize() int {
	return 2 + abesalrs.MpkByteLen
}

func (maddr *MasterAddressSalrs) Serialize() []byte {

	b := make([]byte, 2+abesalrs.MpkByteLen)

	binary.BigEndian.PutUint16(b, uint16(maddr.cryptoScheme))

	copy(b[2:], maddr.masterPubKey.Serialize())

	return b
}

func (maddr *MasterAddressSalrs) Deserialize(serialized []byte) error {
	if len(serialized) != 2+abesalrs.MpkByteLen {
		return errors.New("the serialized does not match the rules for MasterAddressSalrs")
	}
	cryptoScheme := binary.BigEndian.Uint16(serialized[:2])
	if abecrypto.CryptoScheme(cryptoScheme) != abecrypto.CryptoSchemeSALRS {
		return errors.New("the serialized does not match the rules for MasterAddressSalrs")
	}

	mpk, err := abesalrs.DeseralizeMasterPubKey(serialized[2:])
	if err != nil {
		return err
	}

	maddr.cryptoScheme = abecrypto.CryptoScheme(cryptoScheme)
	maddr.masterPubKey = mpk

	return nil
}

func (maddr *MasterAddressSalrs) MasterAddressCryptoScheme() abecrypto.CryptoScheme {

	return maddr.cryptoScheme
}

func (maddr *MasterAddressSalrs) String() string {
	return hex.EncodeToString(maddr.Serialize())
}

//	ParseMasterAddressSalrs is the reverse function for String()
func ParseMasterAddressSalrsFromStr(serializedStr string) (*MasterAddressSalrs, error) {
	serialized, err := hex.DecodeString(serializedStr)
	if err != nil {
		return nil, err
	}

	maddrsalrs := &MasterAddressSalrs{}
	err = maddrsalrs.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return maddrsalrs, nil

}

func ParseMasterAddressSalrsFromSerialzedBytes(serialized []byte) (*MasterAddressSalrs, error) {
	maddrsalrs := &MasterAddressSalrs{}
	err := maddrsalrs.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return maddrsalrs, nil

}

func (maddr *MasterAddressSalrs) GenerateDerivedAddress() (DerivedAddress, error) {
	dpk, err := abesalrs.GenerateDerivedPubKey(maddr.masterPubKey)
	if err != nil {
		return nil, err
	}

	return &DerivedAddressSalrs{
		cryptoScheme:  maddr.cryptoScheme,
		derivedPubKey: dpk,
	}, nil

}

// DerivedAddressSalrsDerivedPubKey implements the interface DerivedAddress for CryptoScheme SALRS
type DerivedAddressSalrs struct {
	cryptoScheme  abecrypto.CryptoScheme
	derivedPubKey *abesalrs.DerivedPubKey
}

// SerializeSize returns the number of bytes it would take to serialize the DerivedAddressSalrs.
func (daddr *DerivedAddressSalrs) SerializeSize() int {
	return 2 + abesalrs.DpkByteLen
}

func (daddr *DerivedAddressSalrs) Serialize() []byte {

	b := make([]byte, 2+abesalrs.DpkByteLen)

	binary.BigEndian.PutUint16(b, uint16(daddr.cryptoScheme))

	copy(b[2:], daddr.derivedPubKey.Serialize())

	return b
}

func (daddr *DerivedAddressSalrs) Deserialize(serialized []byte) error {
	if len(serialized) != 2+abesalrs.DpkByteLen {
		return errors.New("the serialized does not match the rules for DerivedAddressSalrs")
	}
	cryptoScheme := binary.BigEndian.Uint16(serialized[:2])
	if abecrypto.CryptoScheme(cryptoScheme) != abecrypto.CryptoSchemeSALRS {
		return errors.New("the serialized does not match the rules for DerivedAddressSalrs")
	}

	dpk, err := abesalrs.DeseralizeDerivedPubKey(serialized[2:])
	if err != nil {
		return nil
	}

	daddr.cryptoScheme = abecrypto.CryptoScheme(cryptoScheme)
	daddr.derivedPubKey = dpk

	return nil
}

func (daddr *DerivedAddressSalrs) DerivedAddressCryptoScheme() abecrypto.CryptoScheme {

	return daddr.cryptoScheme
}

func (daddr *DerivedAddressSalrs) String() string {
	return hex.EncodeToString(daddr.Serialize())
}

//	ParseDerivedAddressSalrs is the reverse function for String()
func ParseDerivedAddressSalrsFromStr(serializedStr string) (*DerivedAddressSalrs, error) {
	serialized, err := hex.DecodeString(serializedStr)
	if err != nil {
		return nil, err
	}

	daddrsalrs := &DerivedAddressSalrs{}

	err = daddrsalrs.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return daddrsalrs, nil

}

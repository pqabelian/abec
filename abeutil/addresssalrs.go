package abeutil

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/salrs"
)

// MasterAddressSalrsMasterPubKey implements the interface MasterAddress for CryptoScheme SALRS
type MasterAddressSalrs struct {
	masterPubKey *salrs.MasterPubKey
}

// SerializeSize returns the number of bytes it would take to serialize the MasterAddressSalrs.
func (maddr *MasterAddressSalrs) SerializeSize() int {
	return 2 + salrs.MpkByteLen
}

func (maddr *MasterAddressSalrs) Serialize() []byte {

	b := make([]byte, 2+salrs.MpkByteLen)

	binary.BigEndian.PutUint16(b, uint16(abecrypto.CryptoSchemeSALRS))

	copy(b[2:], maddr.masterPubKey.Serialize())

	return b
}

func (maddr *MasterAddressSalrs) Deserialize(serialized []byte) error {
	if len(serialized) != 2+salrs.MpkByteLen {
		return errors.New("the serialized does not match the rules for MasterAddressSalrs")
	}
	cryptoScheme := binary.BigEndian.Uint16(serialized[:2])
	if abecrypto.CryptoScheme(cryptoScheme) != abecrypto.CryptoSchemeSALRS {
		return errors.New("the serialized does not match the rules for MasterAddressSalrs")
	}

	mpk, err := salrs.DeseralizeMasterPubKey(serialized[2:])
	if err != nil {
		return err
	}

	maddr.masterPubKey = mpk

	return nil
}

func (maddr *MasterAddressSalrs) String() string {
	return hex.EncodeToString(maddr.Serialize())
}

func (maddr *MasterAddressSalrs) MasterAddressCryptoScheme() abecrypto.CryptoScheme {
	return abecrypto.CryptoSchemeSALRS
}

func (maddr *MasterAddressSalrs) GenerateDerivedAddress() (DerivedAddress, error) {
	dpk, err := salrs.GenerateDerivedPubKey(maddr.masterPubKey)
	if err != nil {
		return nil, err
	}

	return &DerivedAddressSalrs{
		derivedPubKey: dpk,
	}, nil

}

// DerivedAddressSalrsDerivedPubKey implements the interface DerivedAddress for CryptoScheme SALRS
type DerivedAddressSalrs struct {
	derivedPubKey *salrs.DerivedPubKey
}

// SerializeSize returns the number of bytes it would take to serialize the DerivedAddressSalrs.
func (daddr *DerivedAddressSalrs) SerializeSize() int {
	return 2 + salrs.DpkByteLen
}

func (daddr *DerivedAddressSalrs) Serialize() []byte {

	b := make([]byte, 2+salrs.DpkByteLen)

	binary.BigEndian.PutUint16(b, uint16(abecrypto.CryptoSchemeSALRS))

	copy(b[2:], daddr.derivedPubKey.Serialize())

	return b
}

func (daddr *DerivedAddressSalrs) Deserialize(serialized []byte) error {
	if len(serialized) != 2+salrs.DpkByteLen {
		return errors.New("the serialized does not match the rules for DerivedAddressSalrs")
	}
	cryptoScheme := binary.BigEndian.Uint16(serialized[:2])
	if abecrypto.CryptoScheme(cryptoScheme) != abecrypto.CryptoSchemeSALRS {
		return errors.New("the serialized does not match the rules for DerivedAddressSalrs")
	}

	dpk, err := salrs.DeseralizeDerivedPubKey(serialized[2:])
	if err != nil {
		return nil
	}

	daddr.derivedPubKey = dpk

	return nil
}

func (daddr *DerivedAddressSalrs) String() string {
	return hex.EncodeToString(daddr.Serialize())
}

func (daddr *DerivedAddressSalrs) DerivedAddressCryptoScheme() abecrypto.CryptoScheme {
	return abecrypto.CryptoSchemeSALRS
}

func ParseMasterAddressSalrs(serialized []byte) (*MasterAddressSalrs, error) {
	maddrsalrs := &MasterAddressSalrs{}

	err := maddrsalrs.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return maddrsalrs, nil

}

func ParseDerivedAddressSalrs(serialized []byte) (*DerivedAddressSalrs, error) {
	daddrsalrs := &DerivedAddressSalrs{}

	err := daddrsalrs.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return daddrsalrs, nil

}

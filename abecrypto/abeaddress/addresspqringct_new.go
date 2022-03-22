package abeaddress

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/pqringctparam"
	"github.com/abesuite/abec/chaincfg"
	"github.com/cryptosuite/pqringct"
)

// MasterAddressPQringctMasterPubKey implements the interface MasterAddress for CryptoScheme SALRS
type AddressPQringct struct {
	//	cryptoScheme seems to be redundant, at this moment, just work for double-check
	// TODO: add the flag for network
	netID byte
	abecrypto.AbeCryptoParam
	pk *pqringct.AddressPublicKey
}

// SerializeSize returns the number of bytes it would take to serialize the MasterAddressPQringct.
func (maddr *AddressPQringct) SerializeSize() uint32 {
	return 5 + pqringctparam.GetMasterPublicKeyLen(uint32(maddr.Version))
}

func (maddr *AddressPQringct) Serialize() []byte {

	b := make([]byte, 5+pqringctparam.GetMasterPublicKeyLen(uint32(maddr.Version)))

	b[0] = maddr.netID

	binary.BigEndian.PutUint32(b[1:], uint32(maddr.Version))
	// TODO(20220322) there are something wrong but now do not handle
	serializeAddressPublicKey, err := maddr.RingCT.SerializeAddressPublicKey(maddr.pk)
	if err != nil {
		panic(err)
	}
	copy(b[5:], serializeAddressPublicKey)

	return b
}

func (maddr *AddressPQringct) Deserialize(serialized []byte) error {
	if len(serialized) != 5+int(pqringctparam.GetMasterPublicKeyLen(uint32(abecrypto.CryptoSchemePQRINGCT))) {
		return errors.New("the serialized does not match the rules for AddressPQringct")
	}
	netId := serialized[0]
	cryptoScheme := binary.BigEndian.Uint32(serialized[1:5])
	if abecrypto.CryptoScheme(cryptoScheme) != abecrypto.CryptoSchemePQRINGCT {
		return errors.New("the serialized does not match the rules for AddressPQringct")
	}
	mpk, err := maddr.RingCT.DeserializeAddressPublicKey(serialized[5:])
	if err != nil {
		return err
	}

	maddr.netID = netId
	maddr.pk = mpk

	return nil
}

func (maddr *AddressPQringct) MasterAddressCryptoScheme() abecrypto.CryptoScheme {
	return maddr.Version
}

func (maddr *AddressPQringct) EncodeAddress() string {
	//return hex.EncodeToString(append([]byte{maddr.netID}, maddr.Serialize()...))
	return hex.EncodeToString(maddr.Serialize())
}

func (maddr *AddressPQringct) String() string {
	return hex.EncodeToString(maddr.Serialize())
}

func (maddr *AddressPQringct) IsForNet(net *chaincfg.Params) bool {
	return maddr.netID == net.PQRingCTID
}

//	ParseAddressPQringct is the reverse function for String()
func ParseAddressPQringctFromStr(serializedStr string) (*AddressPQringct, error) {
	serialized, err := hex.DecodeString(serializedStr)
	if err != nil {
		return nil, err
	}

	maddrsalrs := &AddressPQringct{}
	err = maddrsalrs.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return maddrsalrs, nil

}

func ParseAddressPQringctFromSerialzedBytes(serialized []byte) (*AddressPQringct, error) {
	maddrpqringct := &AddressPQringct{}
	err := maddrpqringct.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return maddrpqringct, nil

}

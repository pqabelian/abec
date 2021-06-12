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
type MasterAddressPQringct struct {
	//	cryptoScheme seems to be redundant, at this moment, just work for double-check
	// TODO: add the flag for network
	netID        byte
	cryptoScheme abecrypto.CryptoScheme
	masterPubKey *pqringct.MasterPublicKey
}

// SerializeSize returns the number of bytes it would take to serialize the MasterAddressPQringct.
func (maddr *MasterAddressPQringct) SerializeSize() uint32 {
	return 5 + pqringctparam.GetMasterPublicKeyLen(uint32(maddr.cryptoScheme))
}

func (maddr *MasterAddressPQringct) Serialize() []byte {

	b := make([]byte, 5+pqringctparam.GetMasterPublicKeyLen(uint32(maddr.cryptoScheme)))

	b[0] = maddr.netID

	binary.BigEndian.PutUint32(b[1:], uint32(maddr.cryptoScheme))

	copy(b[5:], maddr.masterPubKey.Serialize()[:])

	return b
}

func (maddr *MasterAddressPQringct) Deserialize(serialized []byte) error {
	if len(serialized) != 5+int(pqringctparam.GetMasterPublicKeyLen(uint32(abecrypto.CryptoSchemePQRINGCT))) {
		return errors.New("the serialized does not match the rules for MasterAddressPQringct")
	}
	netId := serialized[0]
	cryptoScheme := binary.BigEndian.Uint32(serialized[1:4])
	if abecrypto.CryptoScheme(cryptoScheme) != abecrypto.CryptoSchemePQRINGCT {
		return errors.New("the serialized does not match the rules for MasterAddressPQringct")
	}
	mpk := &pqringct.MasterPublicKey{}
	err := mpk.Deserialize(serialized[5:])
	if err != nil {
		return err
	}

	maddr.netID = netId
	maddr.cryptoScheme = abecrypto.CryptoScheme(cryptoScheme)
	maddr.masterPubKey = mpk

	return nil
}

func (maddr *MasterAddressPQringct) MasterAddressCryptoScheme() abecrypto.CryptoScheme {
	return maddr.cryptoScheme
}

func (maddr *MasterAddressPQringct) EncodeAddress() string {
	//return hex.EncodeToString(append([]byte{maddr.netID}, maddr.Serialize()...))
	return hex.EncodeToString(maddr.Serialize())
}

func (maddr *MasterAddressPQringct) String() string {
	return hex.EncodeToString(maddr.Serialize())
}

func (maddr *MasterAddressPQringct) IsForNet(net *chaincfg.Params) bool {
	return maddr.netID == net.PQRingCTID
}

//	ParseMasterAddressPQringct is the reverse function for String()
func ParseMasterAddressPQringctFromStr(serializedStr string) (*MasterAddressPQringct, error) {
	serialized, err := hex.DecodeString(serializedStr)
	if err != nil {
		return nil, err
	}

	maddrsalrs := &MasterAddressPQringct{}
	err = maddrsalrs.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return maddrsalrs, nil

}

func ParseMasterAddressPQringctFromSerialzedBytes(serialized []byte) (*MasterAddressPQringct, error) {
	maddrpqringct := &MasterAddressPQringct{}
	err := maddrpqringct.Deserialize(serialized)
	if err != nil {
		return nil, err
	}

	return maddrpqringct, nil

}

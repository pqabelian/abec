package abeutil

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/pqabelian/abec/abecrypto"
	"github.com/pqabelian/abec/abecrypto/abecryptoparam"
	"github.com/pqabelian/abec/abecryptox/abecryptoxkey"
	"github.com/pqabelian/abec/abecryptox/abecryptoxparam"
	"github.com/pqabelian/abec/chaincfg"
	"github.com/pqabelian/abec/chainhash"
)

/*
// MasterAddressPQringctMasterPubKey implements the interface MasterAddress for CryptoScheme SALRS
type MasterAddressPQringct struct {
	//	cryptoScheme seems to be redundant, at this moment, just work for double-check
	// TODO: add the flag for network
	netID        byte
	cryptoScheme abecrypto.CryptoScheme
	masterPubKey pqringct.MasterPublicKey
}

func (maddr *MasterAddressPQringct) EncodeAddress() string {
	return hex.EncodeToString(append([]byte{maddr.netID}, maddr.Serialize()...))
}

// SerializeSize returns the number of bytes it would take to serialize the MasterAddressPQringct.
func (maddr *MasterAddressPQringct) SerializeSize() uint32 {
	return 2 + abecryptoparam.GetMasterPublicKeyLen(uint32(maddr.cryptoScheme))
}

func (maddr *MasterAddressPQringct) Serialize() []byte {

	b := make([]byte, 2+abecryptoparam.GetMasterPublicKeyLen(uint32(maddr.cryptoScheme)))

	binary.BigEndian.PutUint16(b, uint16(maddr.cryptoScheme))

	copy(b[2:], maddr.masterPubKey.Serialize()[:])

	return b
}

func (maddr *MasterAddressPQringct) Deserialize(serialized []byte) error {
	if len(serialized) !=2+ int(abecryptoparam.GetMasterPublicKeyLen(uint32(abecrypto.CryptoSchemePQRINGCT))) {
		return errors.New("the serialized does not match the rules for MasterAddressPQringct")
	}
	cryptoScheme := binary.BigEndian.Uint16(serialized[:2])
	if abecrypto.CryptoScheme(cryptoScheme) != abecrypto.CryptoSchemePQRINGCT {
		return errors.New("the serialized does not match the rules for MasterAddressPQringct")
	}
	var mpk  pqringct.MasterPublicKey
	err := mpk.Deserialize(serialized[2:])
	if err != nil {
		return err
	}

	maddr.cryptoScheme = abecrypto.CryptoScheme(cryptoScheme)
	maddr.masterPubKey = mpk

	return nil
}
func (maddr *MasterAddressPQringct) GenerateDerivedAddress() (DerivedAddress, error){
	return nil,errors.New("pqringct can not support to derive address from master address")
}
func (maddr *MasterAddressPQringct) MasterAddressCryptoScheme() abecrypto.CryptoScheme {
	return maddr.cryptoScheme
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
*/

//	PQRingCT 1.0

//	PQRINGCT1.0 adapts instance-address mechanism.
//	In particular, for a TXO, the coin-address is directly "extracted" from a given instance-address,
//	and it has the following two features:
//	1) the coin-address is a part of the instance-address, and
//	2) the extracting algorithm is deterministic, and the coin-address and instance-address is one-to-one map.

type InstanceAddress struct {
	netID         byte
	cryptoAddress []byte
	cryptoScheme  abecryptoxparam.CryptoScheme // This value is encoded in cryptoAddress. It is defined for cache.
}

func (instAddr *InstanceAddress) SerializeSize() uint32 {
	//return 1 + abecrypto.GetCryptoAddressSerializeSize(instAdd.cryptoScheme)
	return uint32(1 + len(instAddr.cryptoAddress))
}

func (instAddr *InstanceAddress) Serialize() []byte {
	b := make([]byte, instAddr.SerializeSize())

	b[0] = instAddr.netID
	copy(b[1:], instAddr.cryptoAddress[:])

	return b
}

func (instAddr *InstanceAddress) Deserialize(serializedInstAddr []byte) error {
	if len(serializedInstAddr) <= 5 {
		return errors.New("byte length of serializedInstAddr does not match the design")
	}

	netId := serializedInstAddr[0]

	privacyLevel, _, _, err := abecryptoxkey.CryptoAddressParse(serializedInstAddr[1:])
	if err != nil {
		return errors.New("A non-PQRingCT abelAddress is deserialized as an instanceAddress")
	}
	switch privacyLevel {
	case abecryptoxkey.PrivacyLevelRINGCTPre:
		if uint32(len(serializedInstAddr)) != abecrypto.GetCryptoAddressSerializeSize(abecryptoparam.CryptoSchemePQRingCT)+1 {
			return errors.New("the length of serializedInstAddr does not match the design")
		}

		instAddr.netID = netId
		instAddr.cryptoScheme = abecryptoxparam.CryptoSchemePQRingCT

		instAddr.cryptoAddress = make([]byte, len(serializedInstAddr)-1)
		copy(instAddr.cryptoAddress, serializedInstAddr[1:])
		return nil
	case abecryptoxkey.PrivacyLevelRINGCT:
		fallthrough
	case abecryptoxkey.PrivacyLevelPSEUDONYM:
		instAddr.netID = netId
		instAddr.cryptoScheme = abecryptoxparam.CryptoSchemePQRingCT

		instAddr.cryptoAddress = make([]byte, len(serializedInstAddr)-1)
		copy(instAddr.cryptoAddress, serializedInstAddr[1:])
		return nil
	default:
		return errors.New("A non-PQRingCT abelAddress is deserialized as an instanceAddress")
	}

	return nil
}

func (instAddr *InstanceAddress) Encode() string {
	serialized := instAddr.Serialize()
	checkSum := chainhash.DoubleHashH(serialized)

	encodeAddrStr := hex.EncodeToString(serialized)
	encodeAddrStr = encodeAddrStr + hex.EncodeToString(checkSum[:])
	return encodeAddrStr
}

func (instAddr *InstanceAddress) Decode(addrStr string) error {
	addrBytes, err := hex.DecodeString(addrStr)
	if err != nil {
		return err
	}
	if len(addrBytes) <= 5+chainhash.HashSize {
		errStr := fmt.Sprintf("abel-address %v has a wrong length", addrStr)
		return errors.New(errStr)
	}

	serializedInstantAddr := addrBytes[:len(addrBytes)-chainhash.HashSize]
	checkSum := addrBytes[len(addrBytes)-chainhash.HashSize:]
	checkSumComputed := chainhash.DoubleHashH(serializedInstantAddr)
	if bytes.Compare(checkSum, checkSumComputed[:]) != 0 {
		errStr := fmt.Sprintf("abel-address %v has a wrong check sum", addrStr)
		return errors.New(errStr)
	}

	err = instAddr.Deserialize(serializedInstantAddr)
	if err != nil {
		return err
	}

	return nil
}

func (instAddr *InstanceAddress) String() string {
	serialized := instAddr.Serialize()
	return hex.EncodeToString(serialized)
}

func (instAddr *InstanceAddress) CryptoAddress() []byte {
	return instAddr.cryptoAddress
}
func (instAddr *InstanceAddress) CryptoScheme() abecryptoxparam.CryptoScheme {
	return instAddr.cryptoScheme
}

func (instAddr *InstanceAddress) IsForNet(netParam *chaincfg.Params) bool {
	return instAddr.netID == netParam.AbelAddressNetId
}

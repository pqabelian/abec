package abeutil

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

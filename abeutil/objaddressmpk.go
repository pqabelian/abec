package abeutil

/*//	abec to do
// AddressPubKey is an Address for a pay-to-pubkey transaction.
type AddressSalrsMasterPubKey struct {
	masterPubKey *salrs.MasterPubKey
	pubKeyHashID byte
}

// EncodeAddress returns the string encoding of the public key as a
// pay-to-pubkey-hash.  Note that the public key format (uncompressed,
// compressed, etc) will change the resulting address.  This is expected since
// pay-to-pubkey-hash is a hash of the serialized public key which obviously
// differs with the format.  At the time of this writing, most Bitcoin addresses
// are pay-to-pubkey-hash constructed from the uncompressed public key.
//
// Part of the Address interface.
func (addrmpk *AddressSalrsMasterPubKey) EncodeAddress() string {

	serializedMpk := addrmpk.serialize()

	return encodeAddress(Hash160(addrmpk.serialize()), addrmpk.pubKeyHashID)
}

// ScriptAddress returns the bytes to be included in a txout script to pay
// to a public key.  Setting the public key format will affect the output of
// this function accordingly.  Part of the Address interface.
func (addrmpk *AddressSalrsMasterPubKey) ScriptAddress() []byte {
	return addrmpk.serialize()
}

// IsForNet returns whether or not the pay-to-pubkey address is associated
// with the passed bitcoin network.
func (addrmpk *AddressSalrsMasterPubKey) IsForNet(net *chaincfg.Params) bool {
	return addrmpk.pubKeyHashID == net.PubKeyHashAddrID
}

// String returns the hex-encoded human-readable string for the pay-to-pubkey
// address.  This is not the same as calling EncodeAddress.
func (addrmpk *AddressSalrsMasterPubKey) String() string {
	return hex.EncodeToString(addrmpk.serialize())
}

// serialize returns the serialization of the public key according to the
// format associated with the address.
func (addrmpk *AddressSalrsMasterPubKey) serialize() []byte {

	return addrmpk.masterPubKey.Serialize()

}*/

/*func (addrmpk *AddressSalrsMasterPubKey) GenerateAddressDerivedPubKey() (*AddressDerivedPubKey, error) {
	dpk, err := abecrypto.GenerateDerivedPubKey(addrmpk.masterPubKey)
	if err != nil {
		return nil, err
	}

	return &AddressDerivedPubKey{
		derivedPubKey: dpk,
		pubKeyHashID:  addrmpk.pubKeyHashID,
	}, nil
}*/

//	abec to do

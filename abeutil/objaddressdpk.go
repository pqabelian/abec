package abeutil

/*//	abec to do	begin
// AddressDerivedPublicKey is an Address for a pay-to-derivedpublickey transaction.
type AddressDerivedPubKey struct {
	derivedPubKey *abecrypto.DerivedPubKey
	pubKeyHashID  byte
}

// EncodeAddress returns the string encoding of the public key as a
// pay-to-pubkey-hash.  Note that the public key format (uncompressed,
// compressed, etc) will change the resulting address.  This is expected since
// pay-to-pubkey-hash is a hash of the serialized public key which obviously
// differs with the format.  At the time of this writing, most Bitcoin addresses
// are pay-to-pubkey-hash constructed from the uncompressed public key.
//
// Part of the Address interface.
func (addrdpk *AddressDerivedPubKey) EncodeAddress() string {
	return encodeAddress(Hash160(addrdpk.serialize()), addrdpk.pubKeyHashID)
}

// ScriptAddress returns the bytes to be included in a txout script to pay
// to a public key.  Setting the public key format will affect the output of
// this function accordingly.  Part of the Address interface.
func (addrdpk *AddressDerivedPubKey) ScriptAddress() []byte {
	return addrdpk.serialize()
}

// IsForNet returns whether or not the pay-to-pubkey address is associated
// with the passed bitcoin network.
func (addrdpk *AddressDerivedPubKey) IsForNet(net *chaincfg.Params) bool {
	return addrdpk.pubKeyHashID == net.PubKeyHashAddrID
}

// String returns the hex-encoded human-readable string for the pay-to-pubkey
// address.  This is not the same as calling EncodeAddress.
func (addrdpk *AddressDerivedPubKey) String() string {
	return hex.EncodeToString(addrdpk.serialize())
}

// serialize returns the serialization of the public key according to the
// format associated with the address.
func (addrdpk *AddressDerivedPubKey) serialize() []byte {

	return addrdpk.derivedPubKey.Serialize()

}

//	abec to do	end
*/

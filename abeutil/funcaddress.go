package abeutil

import (
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/chaincfg"
)

const Address_MPK_HRP = "abempk"

// NewAddressMasterPubKey returns a new AddressMasterPubKey which represents a master-pub-key address.
// The serializedMasterPubKey parameter must be a valid (serialized) MasterPubKey.
func NewAddressMasterPubKey(serializedMasterPubKey []byte, net *chaincfg.Params) (*AddressMasterPubKey, error) {
	masterPubKey, err := abecrypto.DeseralizeMasterPubKey(serializedMasterPubKey)
	if err != nil {
		return nil, err
	}

	return &AddressMasterPubKey{
		masterPubKey: masterPubKey,
		pubKeyHashID: net.PubKeyHashAddrID,
	}, nil
}

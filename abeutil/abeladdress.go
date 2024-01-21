package abeutil

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/chaincfg"
)

// AbelAddress is the address facing to the users.
// In particular, its EncodeString form is used by users to receive coins.
// AbelAddress vs. CryptoAddress:
// 1. CryptoAddress is generated and used by the underlying crypto scheme, such as PQRingCT1.0.
// 2. AbelAddress's string form is used by users to receives coins, such as mining-address or payment-address.
// As a result, AbelAddress instance shall contain (netId, cryptoAddress) and its encodeString form shall contain checksum.
type AbelAddress interface {
	SerializeSize() uint32

	// Serialize() returns the bytes for (netId, cryptoAddress)
	Serialize() []byte

	// Deserialize() parses the bytes for (netId, cryptoAddress) to AbelAddress object.
	Deserialize(serialized []byte) error

	//	Encode() returns hex-codes of (netId, cryptoAddress, checksum) where checksum is the hash of (netId, cryptoAddress)
	Encode() string

	//	Decode() parses the hex-codes of (netId, cryptoAddress, checksum) to AbelAddress object.
	Decode(addrStr string) error

	//	String() returns the hex-codes of (netId, cryptoAddress)
	String() string

	//	CryptoAddress() returns the cryptoAddress
	CryptoAddress() []byte

	// IsForNet returns whether or not the address is associated with the passed Abelian network.
	// Each abec net (such as mainnet, testnet) has a chaincfg.Params instance object,
	// where particular parameters (such as genesis block, block-reward etc.) are set.
	// One of these parameters is AbelAddressNetId, which is used to specify the address that the abec will recognize.
	// Actually, in abec, only the mining module needs to decode a (user side) address to a cryptoAddress.
	// If we remove or disable mining module in abec,
	// then	(1) the concept of AbelAddress should not appear in abec;
	//		(2) the AbelAddressNetId parameter is not needed either;
	//		(3) the outside modules, such as wallet, only need to package cryptoAddress to any user-side address as they need.
	IsForNet(*chaincfg.Params) bool
}

// DecodeAbelAddress() calls the concrete AbelAddress type's Decode() method, based on the cryptoScheme.
// All AbelAddress types shall obey the same rule on the first 5 bytes of its encode, naemly
// (1) [0] specifies the AbelAddressNetId, say 0x00 for mainnet, 0x01 for ...
// (2) [1]~[4] specifies the CryptoScheme of the corresponding CryptoAddress, which are encoded in abecrypto.CryptoAddressKeyGen()
func DecodeAbelAddress(addrStr string) (AbelAddress, error) {
	addrBytes, err := hex.DecodeString(addrStr)
	if err != nil {
		return nil, err
	}
	if len(addrBytes) < 5 {
		errStr := fmt.Sprintf("abel-address %v has a wrong length", addrStr)
		return nil, errors.New(errStr)
	}

	//	the bytes [1]~[4] must match the generation of cryptoAddress, namely in pqringctCryptoAddressGen()

	cryptoScheme, err := abecryptoxparam.DeserializeCryptoScheme(addrBytes[1:5])
	if err != nil {
		errStr := fmt.Sprintf("abel-address %v has a wrong length", addrStr)
		return nil, errors.New(errStr)
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		instAddr := &InstanceAddress{}
		err := instAddr.Decode(addrStr)
		if err != nil {
			return nil, err
		}

		return instAddr, nil
	case abecryptoxparam.CryptoSchemePQRingCTX:
		instAddr := &InstanceAddress{}
		err := instAddr.Decode(addrStr)
		if err != nil {
			return nil, err
		}

		return instAddr, nil
	default:
		return nil, errors.New("Unsupported cryptoScheme of AbelAddress")
	}

}

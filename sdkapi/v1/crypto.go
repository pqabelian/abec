package v1

import (
	"errors"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/wire"
)

type CryptoScheme abecryptoparam.CryptoScheme

func GetCryptoSchemeByTxVersion(txVersion uint32) (CryptoScheme, error) {
	cryptoScheme, err := abecryptoparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}
	return CryptoScheme(cryptoScheme), nil
}

/*
* CryptoAddressKeySeedGen generates a cryptoAddressKeySeed for current cryptoScheme, say PQRingCT.
 */
func CryptoAddressKeySeedGen() (cryptoAddressKeySeed []byte, err error) {
	cryptoScheme := abecryptoparam.CryptoSchemePQRingCT
	return abecrypto.CryptoAddressKeySeedGen(cryptoScheme)
}

func CryptoAddressKeyGen(cryptoAddressKeySeed []byte) (retCryptoAddress []byte, retCryptoSpsk []byte, retCryptoSnsk []byte, retCryptoVsk []byte, err error) {
	return abecrypto.CryptoAddressKeyGenFromSeed(cryptoAddressKeySeed)
}

// CryptoAddressCheck checks wthether the given cryptoAddress is valid (in format).
// When the result is false, the hints will give the reasons why it is invalid.
func CryptoAddressCheck(cryptoAddress []byte) (bl bool, hints string) {
	return abecrypto.CryptoAddressCheck(cryptoAddress)
}

/*
*
ToDo: At this moment (2023.03.03), serializedTxOut is actually txoScript (which user obtains by RPC API).
In later version, we need to modify the RPC API to provide serializedTxOut.
*/
func ExtractCoinAddressFromSerializedTxOut(serializedTxOut []byte) ([]byte, error) {
	cryptoSchem := abecryptoparam.CryptoSchemePQRingCT
	txoScript := serializedTxOut
	// todo: by deserialize
	return abecrypto.ExtractCoinAddressFromTxoScript(txoScript, cryptoSchem)
}

/*
*
ToDo: At this moment (2023.03.03), serializedTxOut is actually txoScript (which user obtains by RPC API).
In later version, we need to modify the RPC API to provide serializedTxOut.
*/
func ExtractCoinValueFromSerializedTxOut(serializedTxOut []byte, cryptoVsk []byte) (uint64, error) {
	// todo: by deserialize
	abeTxo := &wire.TxOutAbe{Version: wire.TxVersion, TxoScript: serializedTxOut}
	cryptoAddress, err := ExtractCoinAddressFromSerializedTxOut(serializedTxOut)
	if err != nil {
		return 0, err
	}
	cryptoAddress = append([]byte{0, 0, 0, byte(abecryptoparam.CryptoSchemePQRingCT)}, cryptoAddress...)
	bl, value, err := abecrypto.TxoCoinReceive(abeTxo, cryptoAddress, cryptoVsk)
	if err != nil {
		return 0, err
	}
	if bl == false {
		//	this should not happen, since the cryptoAddress is extracted from serializedTxOut
		return 0, errors.New("Unexpected error in ExtractCoinValueFromSerializedTxOut")
	}

	return value, nil

}

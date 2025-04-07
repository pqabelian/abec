package v1

import (
	"bytes"
	"errors"
	"github.com/pqabelian/abec/abecrypto"
	"github.com/pqabelian/abec/abecrypto/abecryptoparam"
	"github.com/pqabelian/abec/wire"
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
	cryptoScheme := abecryptoparam.GetCurrentCryptoScheme()
	return abecrypto.CryptoAddressKeySeedGen(cryptoScheme)
}

func CryptoAddressKeyGen(cryptoAddressKeySeed []byte) (retCryptoAddress []byte, retCryptoSpsk []byte, retCryptoSnsk []byte, retCryptoVsk []byte, err error) {
	return abecrypto.CryptoAddressKeyGenFromSeed(cryptoAddressKeySeed)
}

func CryptoAddressKeyVerify(cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte, cryptoVsk []byte) (bool, error) {
	valid, hints := abecrypto.VerifyCryptoAddressKey(cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk)
	if !valid {
		return false, errors.New(hints)
	}
	return valid, nil
}

func CryptoAddressValueKeyVerify(cryptoAddress []byte, cryptoVsk []byte) (bool, error) {
	valid, hints := abecrypto.VerifyCryptoAddressVsk(cryptoAddress, cryptoVsk)
	if !valid {
		return false, errors.New(hints)
	}
	return valid, nil
}

// CheckCryptoAddress checks whether the given cryptoAddress is valid (in format).
// When the result is false, the hints will give the reasons why it is invalid.
func CheckCryptoAddress(cryptoAddress []byte) (valid bool, hints string) {
	return abecrypto.CheckCryptoAddress(cryptoAddress)
}

/*
*
ToDo: At this moment (2023.03.03), serializedTxOut is actually txoScript (which user obtains by RPC API).
In later version, we need to modify the RPC API to provide serializedTxOut.
*/
func ExtractCoinAddressFromSerializedTxOut(serializedTxOut []byte) ([]byte, error) {
	abeTxo := &wire.TxOutAbe{}
	err := wire.ReadTxOutAbe(bytes.NewReader(serializedTxOut), 0, 1, abeTxo)
	if err != nil {
		return nil, err
	}
	cryptoSchema, err := abecryptoparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return nil, err
	}
	return abecrypto.ExtractCoinAddressFromTxoScript(abeTxo.TxoScript, cryptoSchema)
}

/*
*
ToDo: At this moment (2023.03.03), serializedTxOut is actually txoScript (which user obtains by RPC API).
In later version, we need to modify the RPC API to provide serializedTxOut.
*/
func ExtractCoinValueFromSerializedTxOut(serializedTxOut []byte, cryptoVsk []byte) (uint64, error) {
	abeTxo := &wire.TxOutAbe{}
	err := wire.ReadTxOutAbe(bytes.NewReader(serializedTxOut), 0, 1, abeTxo)
	if err != nil {
		return 0, err
	}
	cryptoSchema, err := abecryptoparam.GetCryptoSchemeByTxVersion(abeTxo.Version)
	if err != nil {
		return 0, err
	}
	cryptoAddress, err := abecrypto.ExtractCoinAddressFromTxoScript(abeTxo.TxoScript, cryptoSchema)
	if err != nil {
		return 0, err
	}
	cryptoAddress = append([]byte{0, 0, 0, byte(cryptoSchema)}, cryptoAddress...)
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

func ExtractCoinAddressFromCryptoAddress(cryptoAddress []byte) ([]byte, error) {
	return abecrypto.ExtractCoinAddressFromCryptoAddress(cryptoAddress)
}

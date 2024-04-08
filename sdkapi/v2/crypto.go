package v2

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/wire"
)

type CryptoScheme = abecryptoxparam.CryptoScheme
type PrivacyLevel = abecryptoxkey.PrivacyLevel

func GetCryptoSchemeByTxVersion(txVersion uint32) (CryptoScheme, error) {
	cryptoScheme, err := abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
	if err != nil {
		return 0, err
	}
	return CryptoScheme(cryptoScheme), nil
}

/*
* CryptoAddressKeySeedGen generates a cryptoAddressKeySeed for current cryptoScheme, say PQRingCTX.
 */
func CryptoAddressKeySeedGen(cryptoScheme CryptoScheme, privacyLevel PrivacyLevel) (coinSpendKeyRootSeed []byte,
	coinSerialNumberKeyRootSeed []byte, coinValueKeyRootSeed []byte, coinDetectorRootKey []byte, err error) {
	cryptoScheme = abecryptoxparam.GetCurrentCryptoScheme()
	coinSpendKeyRootSeed, coinSerialNumberKeyRootSeed,
		coinValueKeyRootSeed, coinDetectorRootKey, err = abecryptoxkey.CryptoAddressKeySeedGen(cryptoScheme, privacyLevel)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return coinSpendKeyRootSeed, coinSerialNumberKeyRootSeed, coinValueKeyRootSeed,
		coinDetectorRootKey, nil
}

func CryptoAddressKeyGenByRootSeeds(cryptoScheme CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRootSeed []byte, coinSerialNumberKeyRootSeed []byte, coinValueKeyRootSeed []byte,
	coinDetectorRootKey []byte) (cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte, cryptoVsk []byte, cryptoDetectorKey []byte, err error) {
	cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey, err = abecryptoxkey.CryptoAddressKeyGenByRootSeeds(cryptoScheme, privacyLevel,
		coinSpendKeyRootSeed, coinSerialNumberKeyRootSeed,
		coinValueKeyRootSeed, coinDetectorRootKey)
	return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey, err
}

func CryptoAddressKeyVerify(cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte, cryptoVsk []byte, cryptoDectectorKey []byte) (bool, error) {
	valid, err := abecryptoxkey.CryptoAddressKeysVerify(cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDectectorKey)
	if !valid {
		return false, fmt.Errorf("CryptoAddressKeyVerify: fail to verify %s", err)
	}
	return true, nil
}

// CheckCryptoAddress checks whether the given cryptoAddress is valid (in format).
// When the result is false, the hints will give the reasons why it is invalid.
func CheckCryptoAddress(cryptoAddress []byte) (valid bool, err error) {
	return abecryptoxkey.CheckCryptoAddress(cryptoAddress)
}

/*
*
ToDo: At this moment (2023.03.03), serializedTxOut is actually txoScript (which user obtains by RPC API).
In later version, we need to modify the RPC API to provide serializedTxOut.
*/
func ExtractCoinAddressFromSerializedTxOut(txVersion uint32, serializedTxOut []byte) ([]byte, error) {
	abeTxo := &wire.TxOutAbe{}
	err := wire.ReadTxOutAbe(bytes.NewReader(serializedTxOut), 0, txVersion, abeTxo)
	if err != nil {
		return nil, err
	}
	return abecryptox.ExtractCoinAddressFromTxo(abeTxo)
}

/*
*
ToDo: At this moment (2023.03.03), serializedTxOut is actually txoScript (which user obtains by RPC API).
In later version, we need to modify the RPC API to provide serializedTxOut.
*/
func ExtractCoinValueFromSerializedTxOutByKeys(txVersion uint32, serializedTxOut []byte, cryptoValueSecretKey []byte, coinDetectorKey []byte) (uint64, error) {
	abeTxo := &wire.TxOutAbe{}
	err := wire.ReadTxOutAbe(bytes.NewReader(serializedTxOut), 0, txVersion, abeTxo)
	if err != nil {
		return 0, err
	}

	bl, value, err := abecryptox.TxoCoinReceiveByKeys(abeTxo, cryptoValueSecretKey, coinDetectorKey)
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
	_, coinAddr, _, err := abecryptoxkey.CryptoAddressParse(cryptoAddress)
	return coinAddr, err
}

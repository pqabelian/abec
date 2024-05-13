package v2

import (
	"bytes"
	"errors"
	"github.com/abesuite/abec/abecryptox"
	"github.com/abesuite/abec/abecryptox/abecryptoxkey"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/abesuite/abec/wire"
)

type CryptoScheme = abecryptoxparam.CryptoScheme

const (
	CryptoSchemePQRingCT  = abecryptoxparam.CryptoSchemePQRingCT
	CryptoSchemePQRingCTX = abecryptoxparam.CryptoSchemePQRingCTX
)

func CryptoSchemeSerializeSize() int {
	return abecryptoxparam.CryptoSchemeSerializeSize()
}
func SerializeCryptoScheme(cryptoScheme CryptoScheme) []byte {
	return abecryptoxparam.SerializeCryptoScheme(cryptoScheme)
}
func DeserializeCryptoScheme(serializedCryptoScheme []byte) (CryptoScheme, error) {
	return abecryptoxparam.DeserializeCryptoScheme(serializedCryptoScheme)
}

func GetCryptoSchemeParamSeedBytesLen(cryptoScheme CryptoScheme) (int, error) {
	return abecryptoxparam.GetCryptoSchemeParamSeedBytesLen(cryptoScheme)
}

func GetParamKeyGenPublicRandBytesLen(cryptoScheme CryptoScheme) (int, error) {
	return abecryptoxparam.GetParamKeyGenPublicRandBytesLen(cryptoScheme)
}

type PrivacyLevel = abecryptoxkey.PrivacyLevel

const (
	PrivacyLevelRINGCTPre PrivacyLevel = abecryptoxkey.PrivacyLevelRINGCTPre //	hide the payer in ring, hide the amount by commitment, the default privacy-level in the initial version
	PrivacyLevelRINGCT    PrivacyLevel = abecryptoxkey.PrivacyLevelRINGCT    //	hide the payer in ring, hide the amount by commitment, same as the initial version, but explicitly specified
	PrivacyLevelPSEUDONYM PrivacyLevel = abecryptoxkey.PrivacyLevelPSEUDONYM //	pseudonym, i.e., hide the real identity
	// PrivacyLevelRINGCTSA  PrivacyLevel = 3 //	(not supported at this moment) hide the payer in ring, hide the amount by commitment, hide the payee by SA
)

func GetCryptoSchemeByTxVersion(txVersion uint32) (CryptoScheme, error) {
	return abecryptoxparam.GetCryptoSchemeByTxVersion(txVersion)
}

func CryptoAddressKeyGenByRootSeeds(cryptoScheme CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRootSeed []byte, coinSerialNumberKeyRootSeed []byte, coinValueKeyRootSeed []byte,
	coinDetectorRootKey []byte) (cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte, cryptoVsk []byte, cryptoDetectorKey []byte, err error) {
	return abecryptoxkey.CryptoAddressKeyGenByRootSeeds(cryptoScheme, privacyLevel,
		coinSpendKeyRootSeed, coinSerialNumberKeyRootSeed,
		coinValueKeyRootSeed, coinDetectorRootKey)
}

func CryptoAddressKeyVerify(cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte, cryptoVsk []byte, cryptoDetectorKey []byte) (bool, error) {
	return abecryptoxkey.CryptoAddressKeysVerify(cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey)
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

func ExtractCoinAddressFromCryptoAddress(cryptoAddress []byte) (PrivacyLevel, []byte, error) {
	privacyLevel, coinAddr, _, err := abecryptoxkey.CryptoAddressParse(cryptoAddress)
	return privacyLevel, coinAddr, err
}

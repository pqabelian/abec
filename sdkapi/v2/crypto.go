package v2

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/pqabelian/abec/abecryptox"
	"github.com/pqabelian/abec/abecryptox/abecryptoxkey"
	"github.com/pqabelian/abec/abecryptox/abecryptoxparam"
	"github.com/pqabelian/abec/wire"
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
	switch cryptoScheme {
	case CryptoSchemePQRingCTX:
		return abecryptoxkey.CryptoAddressKeyGenByRootSeeds(cryptoScheme, privacyLevel,
			coinSpendKeyRootSeed, coinSerialNumberKeyRootSeed,
			coinValueKeyRootSeed, coinDetectorRootKey)
	default:
		return nil, nil, nil, nil, nil, fmt.Errorf("unsupported crypto scheme %d", cryptoScheme)
	}
}

func ExtractPublicRandFromCryptoAddress(cryptoAddress []byte) (publicRand []byte, err error) {
	return abecryptoxkey.ExtractPublicRandFromCryptoAddress(cryptoAddress)
}

func CryptoAddressKeyReGenByRootSeedsFromPublicRand(cryptoScheme CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRootSeed []byte, coinSerialNumberKeyRootSeed []byte, coinValueKeyRootSeed []byte,
	coinDetectorRootKey []byte, publicRand []byte) (cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte,
	cryptoVsk []byte, cryptoDetectorKey []byte, err error) {
	return abecryptoxkey.CryptoAddressKeyReGenByRootSeedsFromPublicRand(cryptoScheme, privacyLevel,
		coinSpendKeyRootSeed, coinSerialNumberKeyRootSeed, coinValueKeyRootSeed,
		coinDetectorRootKey, publicRand)
}

func RandSeedsGenByRootSeedsFromPublicRand(cryptoScheme CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRootSeed []byte, coinSerialNumberKeyRootSeed []byte, coinValueKeyRootSeed []byte,
	coinDetectorRootKey []byte, publicRand []byte) (coinSpendKeyRandSeed []byte, coinSerialNumberKeyRandSeed []byte, coinValueKeyRandSeed []byte,
	coinDetectorKey []byte, err error) {
	return abecryptoxkey.RandSeedsGenByRootSeedsFromPublicRand(cryptoScheme, privacyLevel,
		coinSpendKeyRootSeed, coinSerialNumberKeyRootSeed, coinValueKeyRootSeed,
		coinDetectorRootKey, publicRand)
}

func CryptoAddressKeyGenByRandSeeds(cryptoScheme CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRandSeed []byte, coinSerialNumberKeyRandSeed []byte, coinValueKeyRandSeed []byte,
	coinDetectorKey []byte, publicRand []byte) (cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte, cryptoVsk []byte, cryptoDetectorKey []byte, err error) {
	return abecryptoxkey.CryptoAddressKeyGenByRandSeeds(cryptoScheme, privacyLevel,
		coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed, coinValueKeyRandSeed,
		coinDetectorKey, publicRand)
}

func CryptoAddressKeyVerify(cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte, cryptoVsk []byte, cryptoDetectorKey []byte) (bool, error) {
	return abecryptoxkey.CryptoAddressKeysVerify(cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey)
}

// CheckCryptoAddress checks whether the given cryptoAddress is valid (in format).
// When the result is false, the hints will give the reasons why it is invalid.
func CheckCryptoAddress(cryptoAddress []byte) (valid bool, err error) {
	return abecryptoxkey.CheckCryptoAddress(cryptoAddress)
}

func ExtractCoinAddressFromSerializedTxOut(txVersion uint32, serializedTxOut []byte) ([]byte, error) {
	abeTxo := &wire.TxOutAbe{}
	err := wire.ReadTxOutAbe(bytes.NewReader(serializedTxOut), 0, txVersion, abeTxo)
	if err != nil {
		return nil, err
	}
	return abecryptox.ExtractCoinAddressFromTxo(abeTxo)
}

func TxoCoinDetectByCoinDetectorRootKey(txVersion uint32, serializedTxOut []byte, coinDetectorRootKey []byte) (bool, error) {
	abeTxo := &wire.TxOutAbe{}
	err := wire.ReadTxOutAbe(bytes.NewReader(serializedTxOut), 0, txVersion, abeTxo)
	if err != nil {
		return false, err
	}
	return abecryptox.TxoCoinDetectByCoinDetectorRootKey(abeTxo, coinDetectorRootKey)
}
func TxoCoinReceiveByRootSeeds(txVersion uint32, serializedTxOut []byte, coinValueKeyRootSeed []byte, coinDetectorRootKey []byte) (bool, uint64, error) {
	abeTxo := &wire.TxOutAbe{}
	err := wire.ReadTxOutAbe(bytes.NewReader(serializedTxOut), 0, txVersion, abeTxo)
	if err != nil {
		return false, 0, err
	}
	return abecryptox.TxoCoinReceiveByRootSeeds(abeTxo, coinValueKeyRootSeed, coinDetectorRootKey)
}
func TxoCoinReceiveByKeys(txVersion uint32, serializedTxOut []byte, cryptoAddress []byte, cryptoValueSecretKey []byte) (bool, uint64, error) {
	abeTxo := &wire.TxOutAbe{}
	err := wire.ReadTxOutAbe(bytes.NewReader(serializedTxOut), 0, txVersion, abeTxo)
	if err != nil {
		return false, 0, err
	}
	return abecryptox.TxoCoinReceiveByKeys(abeTxo, cryptoAddress, cryptoValueSecretKey)
}

func GetTxoPrivacyLevel(txVersion uint32, serializedTxOut []byte) (PrivacyLevel, error) {
	abeTxo := &wire.TxOutAbe{}
	err := wire.ReadTxOutAbe(bytes.NewReader(serializedTxOut), 0, txVersion, abeTxo)
	if err != nil {
		return 0, err
	}
	return abecryptox.GetTxoPrivacyLevel(abeTxo)
}

func PrivacyLevelPseudonymTxoCoinParse(txVersion uint32, serializedTxOut []byte) (value uint64, err error) {
	abeTxo := &wire.TxOutAbe{}
	err = wire.ReadTxOutAbe(bytes.NewReader(serializedTxOut), 0, txVersion, abeTxo)
	if err != nil {
		return 0, err
	}
	privacyLevel, err := abecryptox.GetTxoPrivacyLevel(abeTxo)
	if err != nil {
		return 0, fmt.Errorf("fail to extract the privacy level from transaction output: %v", err)
	}
	if privacyLevel != abecryptoxkey.PrivacyLevelPSEUDONYM {
		return 0, fmt.Errorf("can not extract from non-pseudonym output")
	}
	_, coinValue, err := abecryptox.PseudonymTxoCoinParse(abeTxo)
	if err != nil {
		return 0, fmt.Errorf("fail to parse transacoutput output as an pseudonym txo: %v", err)
	}
	return coinValue, nil
}

/*
*
ToDo: At this moment (2023.03.03), serializedTxOut is actually txoScript (which user obtains by RPC API).
In later version, we need to modify the RPC API to provide serializedTxOut.
*/
func ExtractCoinValueFromSerializedTxOutByKeys(txVersion uint32, serializedTxOut []byte, cryptoAddress []byte, cryptoValueSecretKey []byte) (uint64, error) {
	abeTxo := &wire.TxOutAbe{}
	err := wire.ReadTxOutAbe(bytes.NewReader(serializedTxOut), 0, txVersion, abeTxo)
	if err != nil {
		return 0, err
	}

	bl, value, err := abecryptox.TxoCoinReceiveByKeys(abeTxo, cryptoAddress, cryptoValueSecretKey)
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

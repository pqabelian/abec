package abecryptoxkey

import (
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
)

// PrivacyLevel defines the type to denote PrivacyLevel.
// reviewed on 2023.12.07
type PrivacyLevel uint8

// reviewed on 2023.12.07
const (
	PrivacyLevelRINGCTPre PrivacyLevel = 0 //	hide the payer in ring, hide the amount by commitment, the default privacy-level in the initial version
	PrivacyLevelRINGCT    PrivacyLevel = 1 //	hide the payer in ring, hide the amount by commitment, same as the initial version, but explicitly specified
	PrivacyLevelPSEUDONYM PrivacyLevel = 2 //	pseudonym, i.e., hide the real identity
	// PrivacyLevelRINGCTSA  PrivacyLevel = 3 //	(not supported at this moment) hide the payer in ring, hide the amount by commitment, hide the payee by SA
)

// CryptoAddressKeyGen generates cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk from the param randSeed.
// The param randSeed is a randomness that will be used to in randomized algorithms to make the algorithms be deterministic to the caller.
// The caller should make sure that randSeed is random and have sufficient entropy.
// (1) For the case of privacyLevel == abecryptoxparam.PrivacyLevelRINGCT, randSeed should have size of TWO times of CryptoScheme's ParamSeedBytesLen (in bytes), one for address and one for value-privacy.
// (2) For the case of privacyLevel == abecryptoxparam.PrivacyLevelPSEUDONYM, randSeed should have size of CryptoScheme's ParamSeedBytesLen (in bytes), which is used to address.
// (Note that CryptoScheme's ParamSeedBytesLen could be obtained by GetCryptoSchemeParamSeedBytesLen().)
// Accordingly,
// for the case of privacyLevel == abecryptoxparam.PrivacyLevelPSEUDONYM, cryptoSnsk and cryptoVsk will be nil.
// reviewed on 2032.12.07
func CryptoAddressKeyGen(randSeed []byte, cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel PrivacyLevel) (retCryptoAddress []byte, retCryptoSpsk []byte, retCryptoSnsk []byte, retCryptoVsk []byte, err error) {
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		// This is to achieve back-compatibility with CryptoSchemePQRingCT.
		// The caller, e.g., the wallet created with CryptoSchemePQRingCT will still call this function with cryptoScheme=CryptoSchemePQRingCT.
		return abecrypto.CryptoAddressKeyGen(randSeed, abecryptoparam.CryptoSchemePQRingCT)

	case abecryptoxparam.CryptoSchemePQRingCTX:
		cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, err := pqringctxCryptoAddressKeyGen(abecryptoxparam.PQRingCTXPP, randSeed, cryptoScheme, privacyLevel)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil

	default:
		return nil, nil, nil, nil, errors.New("CryptoAddressKeyGen: unsupported crypto-scheme")
	}
	//return nil, nil, nil, nil, nil
}

//	APIs for AddressKey-Encode-Format	begin
//
// ExtractCryptoSchemeFromCryptoAddress extracts cryptoScheme from cryptoAddress.
// reviewed on 2023.12.07
// reviewed on 2023.12.12
func ExtractCryptoSchemeFromCryptoAddress(cryptoAddress []byte) (cryptoScheme abecryptoxparam.CryptoScheme, err error) {
	if len(cryptoAddress) < 4 {
		return 0, fmt.Errorf("ExtractCryptoSchemeFromCryptoAddress: incorrect length of cryptoAddress: %d", len(cryptoAddress))
	}

	//	Note that in both PQRingCT and PQRingCTX, the first 4 bytes of CryptoAddress is serialization of the crypto-scheme
	cryptoScheme, err = abecryptoxparam.DeserializeCryptoScheme(cryptoAddress[:4])
	if err != nil {
		return 0, err
	}

	return cryptoScheme, err
}

// ExtractCryptoSchemeFromCryptoSpendSecretKey extracts cryptoScheme from cryptoSpendSecretKey.
// reviewed on 2023.12.09
// reviewed on 2023.12.12
func ExtractCryptoSchemeFromCryptoSpendSecretKey(cryptoSpendSecretKey []byte) (cryptoScheme abecryptoxparam.CryptoScheme, err error) {
	if len(cryptoSpendSecretKey) < 4 {
		return 0, fmt.Errorf("ExtractCryptoSchemeFromCryptoSpendSecretKey: incorrect length of cryptoSpendSecretKey: %d", len(cryptoSpendSecretKey))
	}

	//	Note that in both PQRingCT and PQRingCTX, the first 4 bytes of CryptoSpendSecretKey is serialization of the crypto-scheme
	cryptoScheme, err = abecryptoxparam.DeserializeCryptoScheme(cryptoSpendSecretKey[:4])
	if err != nil {
		return 0, err
	}

	return cryptoScheme, err
}

// ExtractCryptoSchemeFromCryptoSerialNumberSecretKey extracts cryptoScheme from cryptoSerialNumberSecretKey.
// reviewed on 2023.12.09.
// reviewed on 2023.12.12
func ExtractCryptoSchemeFromCryptoSerialNumberSecretKey(cryptoSerialNumberSecretKey []byte) (cryptoScheme abecryptoxparam.CryptoScheme, err error) {
	if len(cryptoSerialNumberSecretKey) < 4 {
		return 0, fmt.Errorf("ExtractCryptoSchemeFromCryptoSerialNumberSecretKey: incorrect length of cryptoSpendSecretKey: %d", len(cryptoSerialNumberSecretKey))
	}

	//	Note that in both PQRingCT and PQRingCTX, the first 4 bytes of CryptoSerialNumberSecretKey is serialization of the crypto-scheme
	cryptoScheme, err = abecryptoxparam.DeserializeCryptoScheme(cryptoSerialNumberSecretKey[:4])
	if err != nil {
		return 0, err
	}

	return cryptoScheme, err
}

// ExtractCryptoSchemeFromCryptoValueSecretKey extracts CryptoScheme from the input cryptoValueSecretKey.
// reviewed on 2023.12.12
func ExtractCryptoSchemeFromCryptoValueSecretKey(cryptoValueSecretKey []byte) (cryptoScheme abecryptoxparam.CryptoScheme, err error) {
	if len(cryptoValueSecretKey) < 4 {
		return 0, fmt.Errorf("ExtractCryptoSchemeFromCryptoValueSecretKey: incorrect length of cryptoValueSecretKey: %d", len(cryptoValueSecretKey))
	}

	//	Note that in both PQRingCT and PQRingCTX, the first 4 bytes of cryptoValueSecretKey is serialization of the crypto-scheme
	cryptoScheme, err = abecryptoxparam.DeserializeCryptoScheme(cryptoValueSecretKey[:4])
	if err != nil {
		return 0, err
	}

	return cryptoScheme, err
}

//// ExtractPrivacyLevelFromCryptoAddress extracts privacyLevel from cryptoAddress
//// reviewed on 2023.12.07
//func ExtractPrivacyLevelFromCryptoAddress(cryptoScheme CryptoScheme, cryptoAddress []byte) (privacyLevel PrivacyLevel, err error) {
//	cryptoSchemeInAddress, err := ExtractCryptoSchemeFromCryptoAddress(cryptoAddress)
//	if err != nil {
//		return 0, err
//	}
//
//	if cryptoSchemeInAddress != cryptoScheme {
//		return 0, fmt.Errorf("ExtractPrivacyLevelFromCryptoAddress: extracted CryptoScheme %d does not match the input CryptoScheme %d", cryptoSchemeInAddress, cryptoScheme)
//	}
//
//	switch cryptoScheme {
//	case CryptoSchemePQRingCT:
//		//	this is to achieve back-compatibility with PQRingCT
//		_, _, err := abecryptoparam.CryptoAddressParse(cryptoAddress) // This call to make sure the input cryptoAddress is well-formed.
//		if err != nil {
//			return 0, err
//		}
//		privacyLevel = PrivacyLevelRINGCTPre
//
//	case CryptoSchemePQRingCTX:
//		privacyLevel, _, _, err = pqringctxCryptoAddressParse(PQRingCTXPP, cryptoScheme, cryptoAddress)
//		if err != nil {
//			return 0, err
//		}
//
//	default:
//		return 0, fmt.Errorf("ExtractPrivacyLevelFromCryptoAddress: unsupported crypto-scheme")
//	}
//
//	return privacyLevel, nil
//}
//
//func ExtractPrivacyLevelFromCryptoSpendSecretKey(cryptoScheme CryptoScheme, cryptoSpendSecretKey []byte) (privacyLevel PrivacyLevel, err error) {
//	cryptoSchemeInSpSk, err := ExtractCryptoSchemeFromCryptoSpendSecretKey(cryptoSpendSecretKey)
//	if err != nil {
//		return 0, err
//	}
//
//	if cryptoSchemeInSpSk != cryptoScheme {
//		return 0, fmt.Errorf("ExtractPrivacyLevelFromCryptoSpendSecretKey: extracted CryptoScheme %d does not match the input CryptoScheme %d", cryptoSchemeInSpSk, cryptoScheme)
//	}
//
//	switch cryptoScheme {
//	case CryptoSchemePQRingCT:
//		//	this is to achieve back-compatibility with PQRingCT
//		_, _, err := abecryptoparam.CryptoAddressParse(cryptoSpendSecretKey) // This call to make sure the input cryptoSpendSecretKey is well-formed.
//		if err != nil {
//			return 0, err
//		}
//		privacyLevel = PrivacyLevelRINGCTPre
//
//	case CryptoSchemePQRingCTX:
//		privacyLevel, _, _, err = pqringctxCryptoAddressParse(PQRingCTXPP, cryptoScheme, cryptoSpendSecretKey)
//		if err != nil {
//			return 0, err
//		}
//
//	default:
//		return 0, fmt.Errorf("ExtractPrivacyLevelFromCryptoAddress: unsupported crypto-scheme")
//	}
//
//	return privacyLevel, nil
//}

// CryptoAddressParse could be used to parse the CryptoAddress to the corresponding coinAddress, and valuePublicKey, as well as its privacyLevel.
// Note that the input CryptoAddress should be ones generated by CryptoAddressKeyGen (of different underlying crypto-schemes) and encoded by the unifrom rule,
// namely, the first 4 bytes is the encoded CryptoScheme, under which the cryptoAddress was generated.
// reviewed on 2023.12.07
// reviewed on 2023.12.12
func CryptoAddressParse(cryptoAddress []byte) (privacyLevel PrivacyLevel,
	coinAddress []byte,
	coinValuePublicKey []byte,
	err error) {

	cryptoScheme, err := ExtractCryptoSchemeFromCryptoAddress(cryptoAddress)
	if err != nil {
		return 0, nil, nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		//	this is to achieve back-compatibility with PQRingCT
		coinAddress, coinValuePublicKey, err = abecryptoparam.CryptoAddressParse(cryptoAddress)
		if err != nil {
			return 0, nil, nil, err
		}
		privacyLevel = PrivacyLevelRINGCTPre

	case abecryptoxparam.CryptoSchemePQRingCTX:
		privacyLevel, coinAddress, coinValuePublicKey, err = pqringctxCryptoAddressParse(abecryptoxparam.PQRingCTXPP, cryptoScheme, cryptoAddress)
		if err != nil {
			return 0, nil, nil, err
		}

	default:
		return 0, nil, nil, errors.New("CryptoAddressParse: unsupported crypto-scheme")
	}

	return privacyLevel, coinAddress, coinValuePublicKey, nil

}

// CryptoSpendSecretKeyParse parses cryptoSpendSecretKey, which was generated by CryptoAddressKeyGen,
// into privacyLevel and coinSpendSecretKey.
// reviewed on 2023.12.12
func CryptoSpendSecretKeyParse(cryptoSpSk []byte) (privacyLevel PrivacyLevel,
	coinSpendSecretKey []byte,
	err error) {

	cryptoScheme, err := ExtractCryptoSchemeFromCryptoSpendSecretKey(cryptoSpSk)
	if err != nil {
		return 0, nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		//	this is to achieve back-compatibility with PQRingCT
		coinSpendSecretKey, err = abecryptoparam.CryptoSpendSecretKeyParse(cryptoSpSk)
		if err != nil {
			return 0, nil, err
		}
		privacyLevel = PrivacyLevelRINGCTPre

	case abecryptoxparam.CryptoSchemePQRingCTX:
		privacyLevel, coinSpendSecretKey, err = pqringctxCryptoSpendSecretKeyParse(abecryptoxparam.PQRingCTXPP, cryptoScheme, cryptoSpSk)
		if err != nil {
			return 0, nil, err
		}

	default:
		return 0, nil, fmt.Errorf("CryptoSpendSecretKeyParse: unsupported crypto-scheme")
	}

	return privacyLevel, coinSpendSecretKey, nil

}

// CryptoSerialNumberSecretKeyParse parses cryptoSnSk, which was generated by CryptoAddressKeyGen (including those by PQRingCT),
// into privacyLevel and coinSerialNumberSecretKey.
// reviewed on 2023.12.12
func CryptoSerialNumberSecretKeyParse(cryptoSnSk []byte) (privacyLevel PrivacyLevel,
	coinSerialNumberSecretKey []byte,
	err error) {

	cryptoScheme, err := ExtractCryptoSchemeFromCryptoSerialNumberSecretKey(cryptoSnSk)
	if err != nil {
		return 0, nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		//	this is to achieve back-compatibility with PQRingCT
		coinSerialNumberSecretKey, err = abecryptoparam.CryptoSerialNumberSecretKeyParse(cryptoSnSk)
		if err != nil {
			return 0, nil, err
		}
		privacyLevel = PrivacyLevelRINGCTPre

	case abecryptoxparam.CryptoSchemePQRingCTX:
		privacyLevel, coinSerialNumberSecretKey, err = pqringctxCryptoSerialNumberSecretKeyParse(abecryptoxparam.PQRingCTXPP, cryptoScheme, cryptoSnSk)
		if err != nil {
			return 0, nil, err
		}

	default:
		return 0, nil, fmt.Errorf("CryptoSerialNumberSecretKeyParse: unsupported crypto-scheme")
	}

	return privacyLevel, coinSerialNumberSecretKey, nil
}

// CryptoValueSecretKeyParse parses the input CryptoValueSecretKey, which was generated by CryptoAddressKeyGen (including those by PQRingCT),
// into privacyLevel and coinValueSecretKey.
// todo: review pqringctxCryptoValueSecretKeyParse
func CryptoValueSecretKeyParse(cryptoVsk []byte) (privacyLevel PrivacyLevel,
	coinValueSecretKey []byte,
	err error) {

	cryptoScheme, err := ExtractCryptoSchemeFromCryptoValueSecretKey(cryptoVsk)
	if err != nil {
		return 0, nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		//	this is to achieve back-compatibility with PQRingCT
		coinValueSecretKey, err = abecryptoparam.CryptoValueSecretKeyParse(cryptoVsk)
		if err != nil {
			return 0, nil, err
		}
		privacyLevel = PrivacyLevelRINGCTPre

	case abecryptoxparam.CryptoSchemePQRingCTX:
		privacyLevel, coinValueSecretKey, err = pqringctxCryptoValueSecretKeyParse(abecryptoxparam.PQRingCTXPP, cryptoScheme, cryptoVsk)
		if err != nil {
			return 0, nil, err
		}

	default:
		return 0, nil, errors.New("CryptoValueSecretKeyParse: unsupported crypto-scheme")
	}

	return privacyLevel, coinValueSecretKey, nil

}

//	APIs for AddressKey-Encode-Format	end

package abecryptoxkey

import (
	"errors"
	"fmt"
	"github.com/abesuite/abec/abecrypto"
	"github.com/abesuite/abec/abecrypto/abecryptoparam"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/cryptosuite/pqringctx/pqringctxapi"
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
// todo: remove this function, since it is replaced by CryptoAddressKeyGenByRandSeed
func CryptoAddressKeyGen(randSeed []byte, cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel PrivacyLevel) (retCryptoAddress []byte, retCryptoSpsk []byte, retCryptoSnsk []byte, retCryptoVsk []byte, err error) {
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		// This is to achieve back-compatibility with CryptoSchemePQRingCT.
		// The caller, e.g., the wallet created with CryptoSchemePQRingCT will still call this function with cryptoScheme=CryptoSchemePQRingCT.
		return abecrypto.CryptoAddressKeyGen(randSeed, abecryptoparam.CryptoSchemePQRingCT)

	//case abecryptoxparam.CryptoSchemePQRingCTX:
	//	cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, err := pqringctxCryptoAddressKeyGen(abecryptoxparam.PQRingCTXPP, randSeed, cryptoScheme, privacyLevel)
	//	if err != nil {
	//		return nil, nil, nil, nil, err
	//	}
	//	return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil

	default:
		return nil, nil, nil, nil, errors.New("CryptoAddressKeyGen: unsupported crypto-scheme")
	}
	//return nil, nil, nil, nil, nil
}

// CryptoAddressKeyGenByRootSeeds generates a (cryptoAddress, cryptoKeys) for the input (Root Seeds, CoinDetectorRootKey).
// CryptoAddressKeyGenByRootSeeds is a randomized algorithm.
// reviewed on 2023.12.30
func CryptoAddressKeyGenByRootSeeds(cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRootSeed []byte, coinSerialNumberKeyRootSeed []byte, coinValueKeyRootSeed []byte,
	coinDetectorRootKey []byte) (cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte, cryptoVsk []byte, cryptoDetectorKey []byte, err error) {
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxCryptoAddressKeyGenByRootSeeds(abecryptoxparam.PQRingCTXPP, cryptoScheme, privacyLevel, coinSpendKeyRootSeed, coinSerialNumberKeyRootSeed, coinValueKeyRootSeed, coinDetectorRootKey)

	default:
		return nil, nil, nil, nil, nil, fmt.Errorf("CryptoAddressKeyGenByRootSeeds: cryptoScheme (%d) is not supported", cryptoScheme)
	}
	//return nil, nil, nil, nil, nil
}

// ExtractPublicRandFromCryptoAddress extracts the PublicRand from the input/given CryptoAddress.
// reviewed on 2023.12.30
func ExtractPublicRandFromCryptoAddress(cryptoAddress []byte) (publicRand []byte, err error) {
	cryptoScheme, err := ExtractCryptoSchemeFromCryptoAddress(cryptoAddress)

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxExtractPublicRandFromCryptoAddress(abecryptoxparam.PQRingCTXPP, cryptoScheme, cryptoAddress)
	default:
		return nil, fmt.Errorf("ExtractPublicRandFromCryptoAddress: cryptoScheme (%d) is not CryptoSchemePQRingCTX", cryptoScheme)
	}
}

// CryptoAddressKeyReGenByRootSeedsFromPublicRand is used to re-generates the (CryptoAddress, Crypto-Keys) for the given/input (Root Seeds, Root Key) and PublicRand.
// CryptoAddressKeyReGenByRootSeedsFromPublicRand is the same as CryptoAddressKeyGenByRootSeeds, except that an additional Public Rand is given as input.
// CryptoAddressKeyReGenByRootSeedsFromPublicRand is a deterministic algorithm.
// reviewed on 2023.12.31
func CryptoAddressKeyReGenByRootSeedsFromPublicRand(cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRootSeed []byte, coinSerialNumberKeyRootSeed []byte, coinValueKeyRootSeed []byte,
	coinDetectorRootKey []byte, publicRand []byte) (cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte, cryptoVsk []byte, cryptoDetectorKey []byte, err error) {

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxCryptoAddressKeyReGenByRootSeedsFromPublicRand(abecryptoxparam.PQRingCTXPP, cryptoScheme, privacyLevel, coinSpendKeyRootSeed, coinSerialNumberKeyRootSeed, coinValueKeyRootSeed, coinDetectorRootKey, publicRand)

	default:
		return nil, nil, nil, nil, nil, fmt.Errorf("CryptoAddressKeyReGenByRootSeedsFromPublicRand: cryptoScheme (%d) is not supported", cryptoScheme)
	}
	//return nil, nil, nil, nil, nil
}

// RandSeedsGenByRootSeedsFromPublicRand generates (Rand Seeds, coinDetectorKey) from the input/given (Root Seeds, coinDetectorKey) and PublicRand.
// RandSeedsGenByRootSeedsFromPublicRand has the same inputs as CryptoAddressKeyReGenByRootSeedsFromPublicRand, but outputs the internal (Rand Seeds, coinDetectorKey),
// rather than the final (CryptoAddress, Crypto-Keys).
// The output (Rand Seeds, coinDetectorKey) can be used to call CryptoAddressKeyGenByRandSeeds to generate the final (CryptoAddress, Crypto-Keys).
// reviewed on 2023.12.31
func RandSeedsGenByRootSeedsFromPublicRand(cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRootSeed []byte, coinSerialNumberKeyRootSeed []byte, coinValueKeyRootSeed []byte,
	coinDetectorRootKey []byte, publicRand []byte) (coinSpendKeyRandSeed []byte, coinSerialNumberKeyRandSeed []byte, coinValueKeyRandSeed []byte,
	coinDetectorKey []byte, err error) {

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxRandSeedsGenByRootSeedsFromPublicRand(abecryptoxparam.PQRingCTXPP, cryptoScheme, privacyLevel, coinSpendKeyRootSeed, coinSerialNumberKeyRootSeed, coinValueKeyRootSeed, coinDetectorRootKey, publicRand)

	default:
		return nil, nil, nil, nil, fmt.Errorf("RandSeedsGenByRootSeedsFromPublicRand: cryptoScheme (%d) is not supported", cryptoScheme)
	}

	return nil, nil, nil, nil, err
}

// CryptoAddressKeyGenByRandSeeds generates (cryptoAddress, cryptoKeys) from the input Rand Seeds, coinDetectorKey, and Public Rand.
// A caller may directly use a set of Rand Seeds, CoinDetectorKey, and Public Rand to generate a particular (CryptoAddress, Crypto-Keys) tuple.
// This is a deterministic algorithm, because the Public Rand is given.
// NOTE: coinDetectorKey is given in the input, implying that the caller have this key, and it will be the responsibility to put the returned (CryptoAddress)
// NOTE: CryptoAddressKeyGenByRandSeeds is back-compatible with CryptoSchemePQRingCT. In particular,
// the caller, e.g., the wallet created with CryptoSchemePQRingCT, shall still call this function with cryptoScheme=CryptoSchemePQRingCT, with the following specifications:
// (1) For CryptoSchemePQRingCT, the case is randSeed = AddressKeyRandSeed || ValueKeyRandSeed, and AddressKeyRandSeed will be used to generate coinSpendKey and coinSerialNumberKey.
// (2) To call this function, the caller should pass AddressKeyRandSeed as input coinSpendKeyRandSeed, and here it will set that randSeed := coinSpendKeyRandSeed || coinValueKeyRandSeed,
// and then call abecrypto.CryptoAddressKeyGen(randSeed, abecryptoparam.CryptoSchemePQRingCT).
// reviewed on 2023.12.31
func CryptoAddressKeyGenByRandSeeds(cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRandSeed []byte, coinSerialNumberKeyRandSeed []byte, coinValueKeyRandSeed []byte,
	coinDetectorKey []byte, publicRand []byte) (cryptoAddress []byte, cryptoSpsk []byte, cryptoSnsk []byte, cryptoVsk []byte, cryptoDetectorKey []byte, err error) {
	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCT:
		// This is to achieve back-compatibility with CryptoSchemePQRingCT.
		// The caller, e.g., the wallet created with CryptoSchemePQRingCT will still call this function with cryptoScheme=CryptoSchemePQRingCT.
		// For CryptoSchemePQRingCT, the case is randSeed = AddressKeyRandSeed || ValueKeyRandSeed,
		// and AddressKeyRandSeed will be used to generate coinSpendKey and coinSerialNumberKey.
		// Here, we set randSeed := coinSpendKeyRandSeed || coinValueKeyRandSeed, and the caller should pass AddressKeyRandSeed as input coinSpendKeyRandSeed.
		randSeed := make([]byte, len(coinSpendKeyRandSeed)+len(coinValueKeyRandSeed))
		copy(randSeed, coinSpendKeyRandSeed)
		copy(randSeed[len(coinSpendKeyRandSeed):], coinValueKeyRandSeed)

		cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, err = abecrypto.CryptoAddressKeyGen(randSeed, abecryptoparam.CryptoSchemePQRingCT)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil, err

	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxCryptoAddressKeyGenByRandSeeds(abecryptoxparam.PQRingCTXPP, cryptoScheme, privacyLevel, coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed, coinValueKeyRandSeed, coinDetectorKey, publicRand)
	default:
		return nil, nil, nil, nil, nil, fmt.Errorf("CryptoAddressKeyGenByRandSeeds: unsupported crypto-scheme")
	}
	//return nil, nil, nil, nil, nil
}

// GetPrivacyLevelFromCoinAddressType returns the PrivacyLevel corresponding to the input coinAddressType.
// todo: review
func GetPrivacyLevelFromCoinAddressType(coinAddressType pqringctxapi.CoinAddressType) (PrivacyLevel, error) {
	return pqringctxGetPrivacyLevelFromCoinAddressType(coinAddressType)
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

// ExtractCryptoSchemeFromCryptoDetectorKey extracts cryptoScheme from cryptoDetectorKey.
// reviewed on 2023.12.30
// todo: review
func ExtractCryptoSchemeFromCryptoDetectorKey(cryptoDetectorKey []byte) (cryptoScheme abecryptoxparam.CryptoScheme, err error) {
	if len(cryptoDetectorKey) < 4 {
		return 0, fmt.Errorf("ExtractCryptoSchemeFromCryptoDetectorKey: incorrect length of cryptoDetectorKey: %d", len(cryptoDetectorKey))
	}

	//	Note that in both PQRingCT and PQRingCTX, the first 4 bytes of CryptoSpendSecretKey is serialization of the crypto-scheme
	cryptoScheme, err = abecryptoxparam.DeserializeCryptoScheme(cryptoDetectorKey[:4])
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

// CryptoDetectorKeyParse parses cryptoDetectorKey, which was generated by CryptoDetectorKeyGenByRootKey,
// into privacyLevel and coinSpendSecretKey.
// reviewed on 2023.12.12
func CryptoDetectorKeyParse(cryptoDetectorKey []byte) (privacyLevel PrivacyLevel,
	coinDetectorKey []byte,
	err error) {

	cryptoScheme, err := ExtractCryptoSchemeFromCryptoDetectorKey(cryptoDetectorKey)
	if err != nil {
		return 0, nil, err
	}

	switch cryptoScheme {
	case abecryptoxparam.CryptoSchemePQRingCTX:
		privacyLevel, coinDetectorKey, err = pqringctxCryptoDetectorKeyParse(abecryptoxparam.PQRingCTXPP, cryptoScheme, cryptoDetectorKey)
		if err != nil {
			return 0, nil, err
		}

	default:
		return 0, nil, fmt.Errorf("CryptoSpendSecretKeyParse: unsupported crypto-scheme")
	}

	return privacyLevel, coinDetectorKey, nil

}

//	APIs for AddressKey-Encode-Format	end

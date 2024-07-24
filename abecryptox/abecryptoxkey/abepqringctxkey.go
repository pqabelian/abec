package abecryptoxkey

import (
	"fmt"
	"github.com/pqabelian/abec/abecryptox/abecryptoutils"
	"github.com/pqabelian/abec/abecryptox/abecryptoxparam"
	"github.com/pqabelian/pqringctx"
	"github.com/pqabelian/pqringctx/pqringctxapi"
)

// pqringctxCryptoAddressKeyGenByRootSeeds generates (CryptoAddress, CryptoKeys) for the input Root Seeds and the CoinDetectorRootKey.
// This is a randomized algorithm, in particular,
// (1) A Public Rand is chosen,
// (2) Rand Seeds are generated from (Root Seeds, Public Rand),
// (3) CoinDetectorKey is generated from (CoinDetectorRootKey, Public Rand)，
// (4) (Rand Seeds, CoinDetectorKey, Public Rand) are passed to pqringctxCryptoAddressKeyGenByRandSeed to generate a (CryptoAddress, Crypto-keys) tuple.
// (5) (cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey) is returned.
// NOTE: With this function, we separate the generation of Rand Seeds from the crypto-scheme layer, and form a standalone layer here.
// As a result,
// (a) crypto-scheme layer still only needs to guarantee the cryptographic security, where the only "change" is that it use rand seeds to make randomized algorithm deterministic.
// (b) the layer here takes the responsibility of generating the Rand Seeds for crypto-scheme layer.
// (c) such an architecture provides flexible functionalities to the application layer,
// namely, the application layer can use (Root Seeds, CoinDetectorRootKey) or (Rand Seeds, CoinDetectorKey) to call the functionalities.
// reviewed on 2023.12.30
func pqringctxCryptoAddressKeyGenByRootSeeds(pp *pqringctxapi.PublicParameter,
	cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRootSeed []byte, coinSerialNumberKeyRootSeed []byte, coinValueKeyRootSeed []byte,
	coinDetectorRootKey []byte) (
	cryptoAddress []byte,
	cryptoSpsk []byte,
	cryptoSnsk []byte,
	cryptoVsk []byte,
	cryptoDetectorKey []byte,
	err error) {

	if len(coinSpendKeyRootSeed) != abecryptoutils.PRFKeyBytesLen {
		return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyGenByRootSeed: invalid length of coinSpendKeyRootSeed (%d)", len(coinSpendKeyRootSeed))
	}

	if len(coinDetectorRootKey) != abecryptoutils.PRFKeyBytesLen {
		return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyGenByRootSeed: invalid length of coinDetectorRootKey (%d)", len(coinDetectorRootKey))
	}

	// choose PublicRand
	publicRand := abecryptoutils.RandomBytes(pp.GetParamKeyGenPublicRandBytesLen())

	//	coinSpendKeyRandSeed
	coinSpendKeyRandSeed, err := abecryptoutils.KDF(coinSpendKeyRootSeed, publicRand)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	//	coinDetectorKey
	// coinDetectorKey, err := abecryptoutils.KDF(coinDetectorRootKey, publicRand)
	coinDetectorKey, err := coinDetectorKeyGenByCoinDetectorRootKeyFromPublicRand(pp, coinDetectorRootKey, publicRand)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if privacyLevel == PrivacyLevelRINGCT {
		if len(coinSerialNumberKeyRootSeed) != abecryptoutils.PRFKeyBytesLen {
			return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyGenByRootSeed: invalid length of coinSerialNumberKeyRootSeed (%d)", len(coinSerialNumberKeyRootSeed))
		}
		if len(coinValueKeyRootSeed) != abecryptoutils.PRFKeyBytesLen {
			return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyGenByRootSeed: invalid length of coinValueKeyRootSeed (%d)", len(coinValueKeyRootSeed))
		}

		coinSerialNumberKeyRandSeed, err := abecryptoutils.KDF(coinSerialNumberKeyRootSeed, publicRand)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		coinValueKeyRandSeed, err := abecryptoutils.KDF(coinValueKeyRootSeed, publicRand)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey, err = pqringctxCryptoAddressKeyGenByRandSeeds(pp, cryptoScheme, privacyLevel, coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed, coinValueKeyRandSeed, coinDetectorKey, publicRand)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

	} else if privacyLevel == PrivacyLevelPSEUDONYM {
		cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey, err = pqringctxCryptoAddressKeyGenByRandSeeds(pp, cryptoScheme, privacyLevel, coinSpendKeyRandSeed, nil, nil, coinDetectorKey, publicRand)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

	} else {
		return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyGenByRootSeed: the input privacyLevel (%d) is not supported", privacyLevel)
	}

	return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey, nil
}

// pqringctxExtractPublicRandFromCryptoAddress extracts PublicRand from CryptoAddress.
// reviewed on 2023.12.30
func pqringctxExtractPublicRandFromCryptoAddress(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme,
	cryptoAddress []byte) (
	publicRand []byte, err error) {

	_, coinAddress, _, err := pqringctxCryptoAddressParse(pp, cryptoScheme, cryptoAddress)
	if err != nil {
		return nil, err
	}

	return pqringctxapi.ExtractPublicRandFromCoinAddress(pp, coinAddress)
}

// pqringctxCryptoAddressKeyReGenByRootSeedsFromPublicRand is the same as pqringctxCryptoAddressKeyGenByRootSeeds,
// except that it has an additional input PublicRand, and as a result, it is a deterministic algorithm.
// reviewed on 2023.12.31
func pqringctxCryptoAddressKeyReGenByRootSeedsFromPublicRand(pp *pqringctxapi.PublicParameter,
	cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRootSeed []byte, coinSerialNumberKeyRootSeed []byte, coinValueKeyRootSeed []byte,
	coinDetectorRootKey []byte, publicRand []byte) (
	cryptoAddress []byte,
	cryptoSpsk []byte,
	cryptoSnsk []byte,
	cryptoVsk []byte,
	cryptoDetectorKey []byte,
	err error) {

	if len(coinSpendKeyRootSeed) != abecryptoutils.PRFKeyBytesLen {
		return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyReGenByRootSeedsFromPublicRand: invalid length of coinSpendKeyRootSeed (%d)", len(coinSpendKeyRootSeed))
	}

	if len(coinDetectorRootKey) != abecryptoutils.PRFKeyBytesLen {
		return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyReGenByRootSeedsFromPublicRand: invalid length of coinDetectorRootKey (%d)", len(coinDetectorRootKey))
	}

	if len(publicRand) != pp.GetParamKeyGenPublicRandBytesLen() {
		return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyReGenByRootSeedsFromPublicRand: invalid length of publicRand (%d)", len(publicRand))
	}

	//// choose PublicRand
	//publicRand := abecryptoutils.RandomBytes(pp.GetParamKeyGenPublicRandBytesLen())

	//	coinSpendKeyRandSeed
	coinSpendKeyRandSeed, err := abecryptoutils.KDF(coinSpendKeyRootSeed, publicRand)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	//	coinDetectorKey
	// coinDetectorKey, err := abecryptoutils.KDF(coinDetectorRootKey, publicRand)
	coinDetectorKey, err := coinDetectorKeyGenByCoinDetectorRootKeyFromPublicRand(pp, coinDetectorRootKey, publicRand)
	if err != nil {
		return nil, nil, nil, nil, nil, err
	}

	if privacyLevel == PrivacyLevelRINGCT {
		if len(coinSerialNumberKeyRootSeed) != abecryptoutils.PRFKeyBytesLen {
			return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyReGenByRootSeedsFromPublicRand: invalid length of coinSerialNumberKeyRootSeed (%d)", len(coinSerialNumberKeyRootSeed))
		}
		if len(coinValueKeyRootSeed) != abecryptoutils.PRFKeyBytesLen {
			return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyReGenByRootSeedsFromPublicRand: invalid length of coinValueKeyRootSeed (%d)", len(coinValueKeyRootSeed))
		}

		coinSerialNumberKeyRandSeed, err := abecryptoutils.KDF(coinSerialNumberKeyRootSeed, publicRand)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		coinValueKeyRandSeed, err := abecryptoutils.KDF(coinValueKeyRootSeed, publicRand)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey, err = pqringctxCryptoAddressKeyGenByRandSeeds(pp, cryptoScheme, privacyLevel, coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed, coinValueKeyRandSeed, coinDetectorKey, publicRand)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

	} else if privacyLevel == PrivacyLevelPSEUDONYM {
		cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey, err = pqringctxCryptoAddressKeyGenByRandSeeds(pp, cryptoScheme, privacyLevel, coinSpendKeyRandSeed, nil, nil, coinDetectorKey, publicRand)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

	} else {
		return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyReGenByRootSeedsFromPublicRand: the input privacyLevel (%d) is not supported", privacyLevel)
	}

	return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey, nil
}

// pqringctxRandSeedsGenByRootSeedsFromPublicRand generates (Rand Seeds, coinDetectorKey) from the input/given (Root Seeds, coinDetectorRootKey) and PublicRand.
// pqringctxRandSeedsGenByRootSeedsFromPublicRand has the same inputs as pqringctxCryptoAddressKeyReGenByRootSeedsFromPublicRand, but outputs the internal (Rand Seeds, coinDetectorKey),
// rather than the final (CryptoAddress, Crypto-Keys).
// The output (Rand Seeds, coinDetectorKey) can be used to call pqringctxCryptoAddressKeyGenByRandSeeds to generate the final (CryptoAddress, Crypto-Keys).
// reviewed on 2023.12.31
func pqringctxRandSeedsGenByRootSeedsFromPublicRand(pp *pqringctxapi.PublicParameter,
	cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRootSeed []byte, coinSerialNumberKeyRootSeed []byte, coinValueKeyRootSeed []byte,
	coinDetectorRootKey []byte, publicRand []byte) (
	coinSpendKeyRandSeed []byte,
	coinSerialNumberKeyRandSeed []byte,
	coinValueKeyRandSeed []byte,
	coinDetectorKey []byte,
	err error) {

	if len(coinSpendKeyRootSeed) != abecryptoutils.PRFKeyBytesLen {
		return nil, nil, nil, nil, fmt.Errorf("pqringctxRandSeedsGenByRootSeedsFromPublicRand: invalid length of coinSpendKeyRootSeed (%d)", len(coinSpendKeyRootSeed))
	}

	if len(coinDetectorRootKey) != abecryptoutils.PRFKeyBytesLen {
		return nil, nil, nil, nil, fmt.Errorf("pqringctxRandSeedsGenByRootSeedsFromPublicRand: invalid length of coinDetectorRootKey (%d)", len(coinDetectorRootKey))
	}

	if len(publicRand) != pp.GetParamKeyGenPublicRandBytesLen() {
		return nil, nil, nil, nil, fmt.Errorf("pqringctxRandSeedsGenByRootSeedsFromPublicRand: invalid length of publicRand (%d)", len(publicRand))
	}

	//// choose PublicRand
	//publicRand := abecryptoutils.RandomBytes(pp.GetParamKeyGenPublicRandBytesLen())

	//	coinSpendKeyRandSeed
	coinSpendKeyRandSeed, err = abecryptoutils.KDF(coinSpendKeyRootSeed, publicRand)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	//	coinDetectorKey
	// coinDetectorKey, err = abecryptoutils.KDF(coinDetectorRootKey, publicRand)
	coinDetectorKey, err = coinDetectorKeyGenByCoinDetectorRootKeyFromPublicRand(pp, coinDetectorRootKey, publicRand)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if privacyLevel == PrivacyLevelRINGCT {
		if len(coinSerialNumberKeyRootSeed) != abecryptoutils.PRFKeyBytesLen {
			return nil, nil, nil, nil, fmt.Errorf("pqringctxRandSeedsGenByRootSeedsFromPublicRand: invalid length of coinSerialNumberKeyRootSeed (%d)", len(coinSerialNumberKeyRootSeed))
		}
		if len(coinValueKeyRootSeed) != abecryptoutils.PRFKeyBytesLen {
			return nil, nil, nil, nil, fmt.Errorf("pqringctxRandSeedsGenByRootSeedsFromPublicRand: invalid length of coinValueKeyRootSeed (%d)", len(coinValueKeyRootSeed))
		}

		coinSerialNumberKeyRandSeed, err = abecryptoutils.KDF(coinSerialNumberKeyRootSeed, publicRand)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		coinValueKeyRandSeed, err = abecryptoutils.KDF(coinValueKeyRootSeed, publicRand)
		if err != nil {
			return nil, nil, nil, nil, err
		}

	} else if privacyLevel == PrivacyLevelPSEUDONYM {
		//	nothing to do, since it needs only coinSpendKeyRandSeed and coinDetectorKey
		coinSerialNumberKeyRandSeed = nil
		coinValueKeyRandSeed = nil
	} else {
		return nil, nil, nil, nil, fmt.Errorf("pqringctxRandSeedsGenByRootSeedsFromPublicRand: the input privacyLevel (%d) is not supported", privacyLevel)
	}

	return coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed, coinValueKeyRandSeed, coinDetectorKey, nil
}

// pqringctxCryptoAddressKeyGenByRandSeeds() generates cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, and cryptoDetectorKey,
// by calling pqringctx's key-generation functions to obtain CoinAddress and Coin-keys, and packaging them to CryptoAddress ane Crypto-keys.
// NOTE: DetectorKey is a symmetric key for HMAC, it is generated at the abecrypto-layer.
// Note that based on privacyLevel, the returned cryptoSnsk and cryptoVsk could be nil.
// Note that the input Rand Seeds are used to make the underlying crypto-algorithms deterministic.
// reviewed on 2023.12.07
// reviewed on 2023.12.30
// reviewed on 2023.12.31
// reviewed on 2024.01.24
func pqringctxCryptoAddressKeyGenByRandSeeds(pp *pqringctxapi.PublicParameter,
	cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel PrivacyLevel,
	coinSpendKeyRandSeed []byte, coinSerialNumberKeyRandSeed []byte, coinValueKeyRandSeed []byte,
	coinDetectorKey []byte, publicRand []byte) (
	cryptoAddress []byte,
	cryptoSpsk []byte,
	cryptoSnsk []byte,
	cryptoVsk []byte,
	cryptoDetectorKey []byte,
	err error) {

	expectedSeedLen := pqringctxapi.GetParamSeedBytesLen(pp)

	if len(coinSpendKeyRandSeed) != expectedSeedLen {
		return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyGenByRandSeeds: invalid length of coinSpendKeyRandSeed (%d)", len(coinSpendKeyRandSeed))
	}

	if len(coinDetectorKey) != pqringctxapi.GetParamMACKeyBytesLen(pp) {
		return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyGenByRandSeeds: invalid length of coinDetectorKey (%d)", len(coinDetectorKey))
	}

	if len(publicRand) != pqringctxapi.GetParamKeyGenPublicRandBytesLen(pp) {
		return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyGenByRandSeeds: invalid length of publicRand (%d)", len(publicRand))
	}

	// package coinDetectorKey to cryptoDetectorKey
	serializedCryptoScheme := abecryptoxparam.SerializeCryptoScheme(cryptoScheme)
	cryptoDetectorKey = make([]byte, 5+len(coinDetectorKey))
	copy(cryptoDetectorKey[0:], serializedCryptoScheme)
	cryptoDetectorKey[4] = byte(privacyLevel)
	copy(cryptoDetectorKey[5:], coinDetectorKey)

	if privacyLevel == PrivacyLevelRINGCT {
		if len(coinSerialNumberKeyRandSeed) != expectedSeedLen {
			return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyGenByRandSeeds: invalid length of coinSerialNumberKeyRandSeed (%d)", len(coinSerialNumberKeyRandSeed))
		}
		if len(coinValueKeyRandSeed) != expectedSeedLen {
			return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyGenByRandSeeds: invalid length of coinValueKeyRandSeed (%d)", len(coinValueKeyRandSeed))
		}

		coinAddress, coinSpSk, coinSnSk, err := pqringctxapi.CoinAddressKeyForPKRingGen(pp, coinSpendKeyRandSeed, coinSerialNumberKeyRandSeed, coinDetectorKey, publicRand)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		coinValuePK, coinValueSk, err := pqringctxapi.CoinValueKeyGen(pp, coinValueKeyRandSeed)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		//serializedCryptoScheme := abecryptoxparam.SerializeCryptoScheme(cryptoScheme)

		cryptoAddress = make([]byte, 5+len(coinAddress)+len(coinValuePK))
		copy(cryptoAddress[0:], serializedCryptoScheme)
		cryptoAddress[4] = byte(PrivacyLevelRINGCT)
		copy(cryptoAddress[5:], coinAddress)
		copy(cryptoAddress[5+len(coinAddress):], coinValuePK)

		cryptoSpsk = make([]byte, 5+len(coinSpSk))
		copy(cryptoSpsk[0:], serializedCryptoScheme)
		cryptoSpsk[4] = byte(PrivacyLevelRINGCT)
		copy(cryptoSpsk[5:], coinSpSk)

		cryptoSnsk = make([]byte, 5+len(coinSnSk))
		copy(cryptoSnsk[0:], serializedCryptoScheme)
		cryptoSnsk[4] = byte(PrivacyLevelRINGCT)
		copy(cryptoSnsk[5:], coinSnSk)

		cryptoVsk = make([]byte, 5+len(coinValueSk))
		copy(cryptoVsk[0:], serializedCryptoScheme)
		cryptoVsk[4] = byte(PrivacyLevelRINGCT)
		copy(cryptoVsk[5:], coinValueSk)

		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey, nil

	} else if privacyLevel == PrivacyLevelPSEUDONYM {
		coinAddress, coinSpSk, err := pqringctxapi.CoinAddressKeyForPKHSingleGen(pp, coinSpendKeyRandSeed, coinDetectorKey, publicRand)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}

		//serializedCryptoScheme := abecryptoxparam.SerializeCryptoScheme(cryptoScheme)

		cryptoAddress = make([]byte, 5+len(coinAddress))
		copy(cryptoAddress[0:], serializedCryptoScheme)
		cryptoAddress[4] = byte(PrivacyLevelPSEUDONYM)
		copy(cryptoAddress[5:], coinAddress)

		cryptoSpsk = make([]byte, 5+len(coinSpSk))
		copy(cryptoSpsk[0:], serializedCryptoScheme)
		cryptoSpsk[4] = byte(PrivacyLevelPSEUDONYM)
		copy(cryptoSpsk[5:], coinSpSk)

		cryptoSnsk = nil

		cryptoVsk = nil

		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, cryptoDetectorKey, nil
	} else {
		return nil, nil, nil, nil, nil, fmt.Errorf("pqringctxCryptoAddressKeyGenByRandSeeds: the input privacyLevel is not supported")
	}
}

func pqringctxCoinAddressKeyForPKRingVerify(pp *pqringctxapi.PublicParameter, coinAddress []byte,
	coinSpendSecretKey []byte, coinSerialNumberSecretKey []byte, coinDetectorKey []byte) (bool, error) {
	return pqringctxapi.CoinAddressKeyForPKRingVerify(pp, coinAddress, coinSpendSecretKey, coinSerialNumberSecretKey, coinDetectorKey)
}
func pqringctxCoinAddressKeyForPKHSingleVerify(pp *pqringctxapi.PublicParameter, coinAddress []byte,
	coinSpendSecretKey []byte, coinDetectorKey []byte) (bool, error) {
	return pqringctxapi.CoinAddressKeyForPKHSingleVerify(pp, coinAddress, coinSpendSecretKey, coinDetectorKey)
}
func pqringctxCoinValueKeyVerify(pp *pqringctxapi.PublicParameter,
	coinValuePublicKey []byte, coinValueSecretKey []byte) (bool, error) {
	return pqringctxapi.CoinValueKeyVerify(pp, coinValuePublicKey, coinValueSecretKey)
}

// mapping between PrivacyLevel and CoinAddressType	begin

// pqringctxGetPrivacyLevelFromCoinAddressType returns the PrivacyLevel corresponding to the input CoinAddressType.
// Note that abepqringctxkey.go is the layer which knows the mapping between PrivacyLevel and CoinAddressType.
// reviewed on 2024.01.04
func pqringctxGetPrivacyLevelFromCoinAddressType(coinAddressType pqringctxapi.CoinAddressType) (PrivacyLevel, error) {
	switch coinAddressType {
	case pqringctxapi.CoinAddressTypePublicKeyForRingPre:
		return PrivacyLevelRINGCTPre, nil
	case pqringctxapi.CoinAddressTypePublicKeyForRing:
		return PrivacyLevelRINGCT, nil
	case pqringctxapi.CoinAddressTypePublicKeyHashForSingle:
		return PrivacyLevelPSEUDONYM, nil
	default:
		return 0, fmt.Errorf("pqringctxGetPrivacyLevelFromCoinAddressType: the input CoinAddressType is not supported")
	}
}

// mapping between PrivacyLevel and CoinAddressType	end

//	APIs for AddressKey-Encode-Format	begin

// pqringctxCryptoDetectorKeyParse parses the input cryptoDetectorKey, which was generated by pqringctxCryptoDetectorKeyGenByRootKey,
// to privacyLevel and coinDetectorKey.
// reviewed on 2023.12.30
// reviewed on 2024.01.24
func pqringctxCryptoDetectorKeyParse(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, cryptoDetectorKey []byte) (
	privacyLevel PrivacyLevel,
	coinDetectorKey []byte,
	err error) {

	cryptoSchemeInCryptoDetectorKey, err := ExtractCryptoSchemeFromCryptoDetectorKey(cryptoDetectorKey)
	if err != nil {
		return 0, nil, err
	}

	if cryptoSchemeInCryptoDetectorKey != cryptoScheme {
		return 0, nil, fmt.Errorf("pqringctxCryptoDetectorKeyParse: the input cryptoScheme does not match the cryptoScheme extracted from the input cryptoDetectorKey")
	}

	if len(cryptoDetectorKey) < 5 {
		return 0, nil, fmt.Errorf("pqringctxCryptoDetectorKeyParse: incorrect length of cryptoDetectorKey: %d", len(cryptoDetectorKey))
	}

	privacyLevel = PrivacyLevel(cryptoDetectorKey[4])
	if privacyLevel != PrivacyLevelRINGCT && privacyLevel != PrivacyLevelPSEUDONYM {
		return 0, nil, fmt.Errorf("pqringctxCryptoDetectorKeyParse: invalid PrivacyLevel of cryptoDetectorKey: %d", byte(privacyLevel))
	}

	if len(cryptoDetectorKey) != 5+pqringctxapi.GetParamMACKeyBytesLen(pp) {
		return 0, nil, fmt.Errorf("pqringctxCryptoDetectorKeyParse: incorrect length of cryptoDetectorKey: %d", len(cryptoDetectorKey))
	}

	coinDetectorKey = make([]byte, pqringctxapi.GetParamMACKeyBytesLen(pp))
	copy(coinDetectorKey, cryptoDetectorKey[5:])

	return privacyLevel, coinDetectorKey, nil
}

// pqringctxCryptoAddressParse parses the input cryptoAddress into (coinAddress, valuePublicKey), where valuePublicKey may be nil.
// Note that cryptoAddress was generated by pqringctxCryptoAddressKeyGen, where, depending on the privacyLevel,
// cryptoAddress = cryptoScheme (4 bytes) + privacyLevel (1 byte) + coinAddress or
// cryptoAddress = cryptoScheme (4 bytes) + privacyLevel (1 byte) + coinAddress + valuePublicKey
// Note that this function will parse only those cryptoAddresses generated by pqringctxCryptoAddressKeyGen.
// Note that this is the only function at the pqringctxABC level that takes cryptoAddress as input.
// The caller will call this function and (possible) other APIs (e.g., the ones in abecrypto for back-compatability) to parse cryptoAddress to coinAddress,
// and the call other functions with coinAddress as the input.
// pqringctxCryptoAddressParse parses the cryptoAddress, which was generated by pqringctxCryptoAddressKeyGen,
// into (privacyLevel, coinAddress, coinValuePublicKeys).
// reviewed on 2023.12.07
// reviewed on 2023.12.12
// reviewed on 2024.01.24
func pqringctxCryptoAddressParse(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, cryptoAddress []byte) (
	privacyLevel PrivacyLevel,
	coinAddress []byte,
	coinValuePublicKey []byte,
	err error) {

	cryptoSchemeInCryptoAddress, err := ExtractCryptoSchemeFromCryptoAddress(cryptoAddress)
	if err != nil {
		return 0, nil, nil, err
	}

	if cryptoSchemeInCryptoAddress != cryptoScheme {
		return 0, nil, nil, fmt.Errorf("pqringctxCryptoAddressParse: the input cryptoScheme does not match the cryptoScheme extracted from the input cryptoAddress")
	}

	if len(cryptoAddress) < 5 {
		return 0, nil, nil, fmt.Errorf("pqringctxCryptoAddressParse: incorrect length of cryptoAddress: %d", len(cryptoAddress))
	}

	privacyLevel = PrivacyLevel(cryptoAddress[4])

	if privacyLevel == PrivacyLevelRINGCT {
		coinAddressSize, err := pqringctxapi.CoinAddressSizeByCoinAddressKeyForPKRingGen(pp)
		if err != nil {
			return 0, nil, nil, err
		}
		coinValuePublicKeySize := pqringctxapi.GetCoinValuePublicKeySize(pp)

		if len(cryptoAddress) != 5+coinAddressSize+coinValuePublicKeySize {
			return 0, nil, nil, fmt.Errorf("pqringctxCryptoAddressParse: incorrect length of cryptoAddress: %d for privacyLevel = %d", len(cryptoAddress), privacyLevel)
		}

		coinAddress = make([]byte, coinAddressSize)
		copy(coinAddress, cryptoAddress[5:5+coinAddressSize])

		coinValuePublicKey = make([]byte, coinValuePublicKeySize)
		copy(coinValuePublicKey, cryptoAddress[5+coinAddressSize:])

		return privacyLevel, coinAddress, coinValuePublicKey, nil

	} else if privacyLevel == PrivacyLevelPSEUDONYM {
		coinAddressSize, err := pqringctxapi.CoinAddressSizeByCoinAddressKeyForPKHSingleGen(pp)
		if err != nil {
			return 0, nil, nil, err
		}

		if len(cryptoAddress) != 5+coinAddressSize {
			return 0, nil, nil, fmt.Errorf("pqringctxCryptoAddressParse: incorrect length of cryptoAddress: %d for privacyLevel = %d", len(cryptoAddress), privacyLevel)
		}

		coinAddress = make([]byte, coinAddressSize)
		copy(coinAddress, cryptoAddress[5:])

		coinValuePublicKey = nil

		return privacyLevel, coinAddress, coinValuePublicKey, nil

	} else {
		return 0, nil, nil, fmt.Errorf("pqringctxCryptoAddressParse: invalid PrivacyLevel of cryptoAddress: %d", byte(privacyLevel))
	}

	//return 0, nil, nil, nil
}

// pqringctxCryptoSpendSecretKeyParse parses the input cryptoSpendSecretKey, which was generated by CryptoAddressKeyGen,
// to privacyLevel and coinSpendSecretKey.
// reviewed on 2023.12.12.
// reviewed on 2024.01.24
func pqringctxCryptoSpendSecretKeyParse(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, cryptoSpendSecretKey []byte) (
	privacyLevel PrivacyLevel,
	coinSpendSecretKey []byte,
	err error) {

	cryptoSchemeInCryptoSpSk, err := ExtractCryptoSchemeFromCryptoSpendSecretKey(cryptoSpendSecretKey)
	if err != nil {
		return 0, nil, err
	}

	if cryptoSchemeInCryptoSpSk != cryptoScheme {
		return 0, nil, fmt.Errorf("pqringctxCryptoSpendSecretKeyParse: the input cryptoScheme does not match the cryptoScheme extracted from the input cryptoSpendSecretKey")
	}

	if len(cryptoSpendSecretKey) < 5 {
		return 0, nil, fmt.Errorf("pqringctxCryptoSpendSecretKeyParse: incorrect length of cryptoSpendSecretKey: %d", len(cryptoSpendSecretKey))
	}

	var coinSpendSecretKeySize = 0

	privacyLevel = PrivacyLevel(cryptoSpendSecretKey[4])
	if privacyLevel == PrivacyLevelRINGCT {
		//	cryptoSpendSecretKey was generated by pqringctxapi.CoinAddressKeyForPKRingGen
		coinSpendSecretKeySize, err = pqringctxapi.CoinSpendSecretKeySizeByCoinAddressKeyForPKRingGen(pp)
		if err != nil {
			return 0, nil, err
		}
	} else if privacyLevel == PrivacyLevelPSEUDONYM {
		//	cryptoSpendSecretKey was generated by pqringctxapi.CoinAddressKeyForPKHSingleGen
		coinSpendSecretKeySize, err = pqringctxapi.CoinSpendSecretKeySizeByCoinAddressKeyForPKHSingleGen(pp)
		if err != nil {
			return 0, nil, err
		}
	} else {
		return 0, nil, fmt.Errorf("pqringctxCryptoSpendSecretKeyParse: invalid PrivacyLevel of cryptoSpendSecretKey: %d", byte(privacyLevel))
	}

	if len(cryptoSpendSecretKey) != 5+coinSpendSecretKeySize {
		return 0, nil, fmt.Errorf("pqringctxCryptoSpendSecretKeyParse: incorrect length of cryptoSpendSecretKey: %d for privacyLevel = %d", len(cryptoSpendSecretKey), privacyLevel)
	}

	coinSpendSecretKey = make([]byte, coinSpendSecretKeySize)
	copy(coinSpendSecretKey, cryptoSpendSecretKey[5:5+coinSpendSecretKeySize])

	return privacyLevel, coinSpendSecretKey, nil
}

// pqringctxCryptoSerialNumberSecretKeyParse parses the input cryptoSerialNumberSecretKey, which was generated by CryptoAddressKeyGen,
// to privacyLevel and coinSerialNumberSecretKey.
// reviewed on 2023.12.12
// reviewed on 2024.01.24
func pqringctxCryptoSerialNumberSecretKeyParse(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, cryptoSerialNumberSecretKey []byte) (
	privacyLevel PrivacyLevel,
	coinSerialNumberSecretKey []byte,
	err error) {
	cryptoSchemeInCryptoSnSk, err := ExtractCryptoSchemeFromCryptoSerialNumberSecretKey(cryptoSerialNumberSecretKey)
	if err != nil {
		return 0, nil, err
	}

	if cryptoSchemeInCryptoSnSk != cryptoScheme {
		return 0, nil, fmt.Errorf("pqringctxCryptoSerialNumberSecretKeyParse: the input cryptoScheme does not match the cryptoScheme extracted from the input cryptoSerialNumberSecretKey")
	}

	if len(cryptoSerialNumberSecretKey) < 5 {
		return 0, nil, fmt.Errorf("pqringctxCryptoSerialNumberSecretKeyParse: incorrect length of cryptoSerialNumberSecretKey: %d", len(cryptoSerialNumberSecretKey))
	}

	var coinSerialNumberSecretKeySize = 0

	privacyLevel = PrivacyLevel(cryptoSerialNumberSecretKey[4])
	if privacyLevel == PrivacyLevelRINGCT {
		//	cryptoSerialNumberSecretKey was generated by pqringctxapi.CoinAddressKeyForPKRingGen
		coinSerialNumberSecretKeySize, err = pqringctxapi.CoinSerialNumberSecretKeySizeByCoinAddressKeyForPKRingGen(pp)
		if err != nil {
			return 0, nil, err
		}
	} else {
		//	other cases do not have coinSerialNumberSecretKey, the caller should not call this function.
		return 0, nil, fmt.Errorf("pqringctxCryptoSerialNumberSecretKeyParse: invalid PrivacyLevel of cryptoSerialNumberSecretKey: %d", byte(privacyLevel))
	}

	if len(cryptoSerialNumberSecretKey) != 5+coinSerialNumberSecretKeySize {
		return 0, nil, fmt.Errorf("pqringctxCryptoSerialNumberSecretKeyParse: incorrect length of cryptoSerialNumberSecretKey: %d for privacyLevel = %d", len(cryptoSerialNumberSecretKey), privacyLevel)
	}

	coinSerialNumberSecretKey = make([]byte, coinSerialNumberSecretKeySize)
	copy(coinSerialNumberSecretKey, cryptoSerialNumberSecretKey[5:5+coinSerialNumberSecretKeySize])

	return privacyLevel, coinSerialNumberSecretKey, nil
}

// pqringctxCryptoValueSecretKeyParse parses the input cryptoValueSecretKey, which was generated by CryptoAddressKeyGen,
// to privacyLevel and coinValueSecretKey.
// todo: review pqringctxapi.GetCoinValueSecretKeySize(pp)
func pqringctxCryptoValueSecretKeyParse(pp *pqringctxapi.PublicParameter, cryptoScheme abecryptoxparam.CryptoScheme, cryptoValueSecretKey []byte) (
	privacyLevel PrivacyLevel,
	coinValueSecretKey []byte,
	err error) {
	cryptoSchemeInCryptoVsk, err := ExtractCryptoSchemeFromCryptoValueSecretKey(cryptoValueSecretKey)
	if err != nil {
		return 0, nil, err
	}

	if cryptoSchemeInCryptoVsk != cryptoScheme {
		return 0, nil, fmt.Errorf("pqringctxCryptoValueSecretKeyParse: the input cryptoScheme does not match the cryptoScheme extracted from the input cryptoValueSecretKey")
	}

	if len(cryptoValueSecretKey) < 5 {
		return 0, nil, fmt.Errorf("pqringctxCryptoValueSecretKeyParse: incorrect length of cryptoValueSecretKey: %d", len(cryptoValueSecretKey))
	}

	var coinValueSecretKeySize = 0

	privacyLevel = PrivacyLevel(cryptoValueSecretKey[4])
	if privacyLevel == PrivacyLevelRINGCT {
		//	cryptoValueSecretKey was generated by pqringctxapi.CoinAddressKeyForPKRingGen
		coinValueSecretKeySize = pqringctxapi.GetCoinValueSecretKeySize(pp)
	} else {
		//	other cases do not have coinValueSecretKey, the caller should not call this function.
		return 0, nil, fmt.Errorf("pqringctxCryptoValueSecretKeyParse: invalid PrivacyLevel of cryptoValueSecretKey: %d", byte(privacyLevel))
	}

	if len(cryptoValueSecretKey) != 5+coinValueSecretKeySize {
		return 0, nil, fmt.Errorf("pqringctxCryptoValueSecretKeyParse: incorrect length of cryptoValueSecretKey: %d for privacyLevel = %d", len(cryptoValueSecretKey), privacyLevel)
	}

	coinValueSecretKey = make([]byte, coinValueSecretKeySize)
	copy(coinValueSecretKey, cryptoValueSecretKey[5:5+coinValueSecretKeySize])

	return privacyLevel, coinValueSecretKey, nil
}

// APIs for AddressKey-Encode-Format	end

// APIs for key size start
// pqringctxGetCoinAddressSize returns the CoinAddressSize for the input PrivacyLevel.
// todo: review
func pqringctxGetCoinAddressSize(pp *pqringctxapi.PublicParameter, privacyLevel PrivacyLevel) (int, error) {
	switch privacyLevel {
	case PrivacyLevelRINGCTPre:
		return pqringctxapi.GetCoinAddressSize(pp, pqringctx.CoinAddressTypePublicKeyForRingPre)
	case PrivacyLevelRINGCT:
		return pqringctxapi.GetCoinAddressSize(pp, pqringctx.CoinAddressTypePublicKeyForRing)
	case PrivacyLevelPSEUDONYM:
		return pqringctxapi.GetCoinAddressSize(pp, pqringctx.CoinAddressTypePublicKeyHashForSingle)
	default:
		return 0, fmt.Errorf("pqringctxGetCoinAddressSize: the input PrivacyLevel is not supported")
	}
}

func pqringctxGetCoinValuePublicKeySize(pp *pqringctxapi.PublicParameter, privacyLevel PrivacyLevel) (int, error) {
	switch privacyLevel {
	case PrivacyLevelRINGCTPre:
		return pqringctxapi.GetCoinValuePublicKeySize(pp), nil
	case PrivacyLevelRINGCT:
		return pqringctxapi.GetCoinValuePublicKeySize(pp), nil
	default:
		return 0, fmt.Errorf("pqringctxGetCoinValuePublicKeySize: the input PrivacyLevel is not supported")
	}
}

// APIs for key size end

//	helper functions	begin
//
// coinDetectorKeyGenByCoinDetectorRootKeyFromPublicRand generates CoinDetectorKey from the input coinDetectorRootKey and PublicRand.
// NOTE: this should be consistent with
// todo: review
func coinDetectorKeyGenByCoinDetectorRootKeyFromPublicRand(pp *pqringctxapi.PublicParameter, coinDetectorRootKey []byte, publicRand []byte) (coinDetectorKey []byte, err error) {

	//// choose PublicRand
	//publicRand := abecryptoutils.RandomBytes(pp.GetParamKeyGenPublicRandBytesLen())

	if len(publicRand) != pqringctxapi.GetParamKeyGenPublicRandBytesLen(pp) {
		return nil, fmt.Errorf("pqringctxCoinDetectorKeyGenByCoinDetectorRootKeyFromPublicRand: the input publicRand has an invalid length (%d)", len(publicRand))
	}

	//	coinDetectorKey
	coinDetectorKey, err = abecryptoutils.KDF(coinDetectorRootKey, publicRand)
	if err != nil {
		return nil, err
	}

	return coinDetectorKey, nil
}

//	helper functions	end

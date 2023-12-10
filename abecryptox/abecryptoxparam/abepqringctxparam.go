package abecryptoxparam

import (
	"fmt"
	"github.com/cryptosuite/pqringctx/pqringctxapi"
)

//	APIs for AddressKey-Encode-Format	begin

// pqringctxCryptoAddressParse parses the input cryptoAddress into (coinAddress, valuePublicKey), where valuePublicKey may be nil.
// Note that cryptoAddress was generated by pqringctxCryptoAddressKeyGen, where, depending on the privacyLevel,
// cryptoAddress = cryptoScheme (4 bytes) + privacyLevel (1 byte) + coinAddress or
// cryptoAddress = cryptoScheme (4 bytes) + privacyLevel (1 byte) + coinAddress + valuePublicKey
// Note that this function will parse only those cryptoAddresses generated by pqringctxCryptoAddressKeyGen.
// Note that this is the only function at the pqringctxABC level that takes cryptoAddress as input.
// The caller will call this function and (possible) other APIs (e.g., the ones in abecrypto for back-compatability) to parse cryptoAddress to coinAddress,
// and the call other functions with coinAddress as the input.
// pqringctxCryptoAddressParse parse the cryptoAddress generated by pqringctxCryptoAddressKeyGen.
// reviewed on 2023.12.07
func pqringctxCryptoAddressParse(pp *pqringctxapi.PublicParameter, cryptoScheme CryptoScheme, cryptoAddress []byte) (
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
		coinAddressSize, err := pqringctxapi.GetCoinAddressSizeByCoinAddressKeyForPKRingGen(pp)
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
		coinAddressSize, err := pqringctxapi.GetCoinAddressSizeByCoinAddressKeyForPKHSingleGen(pp)
		if err != nil {
			return 0, nil, nil, err
		}

		if len(cryptoAddress) != 5+coinAddressSize {
			return 0, nil, nil, fmt.Errorf("pqringctxCryptoAddressParse: incorrect length of cryptoAddress: %d for privacyLevel = %d", len(cryptoAddress), privacyLevel)
		}

		coinAddress = make([]byte, coinAddressSize)
		copy(coinAddress, cryptoAddress[5:])

		coinVluePublicKey = nil

		return privacyLevel, coinAddress, coinVluePublicKey, nil

	} else {
		return 0, nil, nil, fmt.Errorf("pqringctxCryptoAddressParse: invalid PrivacyLevel of cryptoAddress: %d", byte(privacyLevel))
	}

	return 0, nil, nil, nil
}

// todo: review
func pqringctxCryptoSpendSecretKeyParse(pp *pqringctxapi.PublicParameter, cryptoScheme CryptoScheme, cryptoSpendSecretKey []byte) (
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
		coinSpendSecretKeySize, err = pqringctxapi.GetCoinSpendSecretKeySizeByCoinAddressKeyForPKRingGen(pp)
		if err != nil {
			return 0, nil, err
		}
	} else if privacyLevel == PrivacyLevelPSEUDONYM {
		//	cryptoSpendSecretKey was generated by pqringctxapi.CoinAddressKeyForPKHSingleGen
		coinSpendSecretKeySize, err = pqringctxapi.GetCoinSpendSecretKeySizeByCoinAddressKeyForPKHSingleGen(pp)
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

func pqringctxCryptoSerialNumberSecretKeyParse(pp *pqringctxapi.PublicParameter, cryptoScheme CryptoScheme, cryptoSerialNumberSecretKey []byte) (
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
		coinSerialNumberSecretKeySize, err = pqringctxapi.GetCoinSerialNumberSecretKeySizeByCoinAddressKeyForPKRingGen(pp)
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

func pqringctxCryptoValueSecretKeyParse(pp *pqringctxapi.PublicParameter, cryptoScheme CryptoScheme, cryptoValueSecretKey []byte) (
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
		return 0, nil, fmt.Errorf("pqringctxCryptoValueSecretKeyParse: incorrect length of cryptoSerialNumberSecretKey: %d", len(cryptoValueSecretKey))
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

// API for Sizes	begin
// reviewed on 2023.12.07
func pqringctxGetCryptoSchemeParamSeedBytesLen(pp *pqringctxapi.PublicParameter) int {
	return pqringctxapi.GetParamSeedBytesLen(pp)
}

// pqringctxGetTxoSerializeSize returns the TxoSerializeSize for the input coinAddress.
// reviewed on 2023.12.07
func pqringctxGetTxoSerializeSize(pp *pqringctxapi.PublicParameter, coinAddress []byte) (int, error) {
	return pqringctxapi.GetTxoSerializeSize(pp, coinAddress)
}

func pqringctxGetCbTxWitnessSerializeSize(pp *pqringctxapi.PublicParameter, coinAddressListPayTo [][]byte) (int, error) {
	return pqringctxapi.GetCbTxWitnessSerializeSizeByDesc(pp, coinAddressListPayTo)
}

//	API for Sizes	end

// GetNullSerialNumber() return the null serial number.
// reviewed on 2023.12.07
func pqringctxGetNullSerialNumber(pp *pqringctxapi.PublicParameter) []byte {
	return pqringctxapi.GetNullSerialNumber(pp)
}

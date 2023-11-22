package abecryptox

import (
	"errors"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
)

// CryptoAddressKeyGen generates cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk from the param randSeed.
// The param randSeed is a randomness that will be used to in randomized algorithms to make the algorithms be deterministic to the caller.
// The caller should make sure that randSeed is random and have sufficient entropy.
// (1) For the case of privacyLevel == abecryptoxparam.PrivacyLevelRINGCT, randSeed should have size of TWO times of CryptoScheme's ParamSeedBytesLen (in bytes), one for address and one for value-privacy.
// (2) For the case of privacyLevel == abecryptoxparam.PrivacyLevelPSEUDONYM, randSeed should have size of CryptoScheme's ParamSeedBytesLen (in bytes), which is used to address.
// (Note that CryptoScheme's ParamSeedBytesLen could be obtained by GetCryptoSchemeParamSeedBytesLen().)
// Accordingly,
// for the case of privacyLevel == abecryptoxparam.PrivacyLevelPSEUDONYM, cryptoSnsk and cryptoVsk will be nil.
func CryptoAddressKeyGen(randSeed []byte, cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel abecryptoxparam.PrivacyLevel) (retCryptoAddress []byte, retCryptoSpsk []byte, retCryptoSnsk []byte, retCryptoVsk []byte, err error) {
	switch cryptoScheme {
	// case abecryptoxparam.CryptoSchemePQRingCT:
	// As the package abecryptoxparam is provided only after Fork-MLP,
	// case abecryptoxparam.CryptoSchemePQRingCT should not be considered.
	case abecryptoxparam.CryptoSchemePQRingCTX:
		cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, err := pqringctxCryptoAddressGen(abecryptoxparam.PQRingCTXPP, randSeed, cryptoScheme, privacyLevel)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil

	default:
		return nil, nil, nil, nil, errors.New("CryptoAddressKeyGen: unsupported crypto-scheme")
	}
	//return nil, nil, nil, nil, nil
}

// API for Sizes	begin

// GetCryptoSchemeParamSeedBytesLen returns the ParamSeedBytesLen for the input param cryptoScheme.
// The caller may call this API to obtain the ParamSeedBytesLen for the input param cryptoScheme,
// then prepare randSeed for CryptoAddressKeyGen().
func GetCryptoSchemeParamSeedBytesLen(cryptoScheme abecryptoxparam.CryptoScheme) (int, error) {
	switch cryptoScheme {
	// case abecryptoxparam.CryptoSchemePQRingCT:
	// As the package abecryptoxparam is provided only after Fork-MLP,
	// case abecryptoxparam.CryptoSchemePQRingCT should not be considered.
	case abecryptoxparam.CryptoSchemePQRingCTX:
		return pqringctxGetCryptoSchemeParamSeedBytesLen(abecryptoxparam.PQRingCTXPP), nil

	default:
		return 0, errors.New("CryptoAddressKeyGen: unsupported crypto-scheme")
	}

	return 0, nil
}

// API for Sizes	end

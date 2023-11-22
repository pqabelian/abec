package abecryptox

import (
	"errors"
	"github.com/abesuite/abec/abecryptox/abecryptoxparam"
	"github.com/cryptosuite/pqringctx/pqringctxapi"
	"github.com/cryptosuite/pqringctx/pqringctxapidao"
)

// // abecryptox -> abepqringctx -> pqringctx
// pqringctxCryptoAddressGen() generates cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, by calling pqringctx's key-generation functions and encapsed the keys.
// cryptoScheme is set as a parameter, since the map between CryptoScheme and the real crypto-scheme (here is pqringct) is coded by abecryptoxparam.
// Note that based on privacyLevel, the returned cryptoSnsk and cryptoVsk could be nil.
func pqringctxCryptoAddressGen(pp *pqringctxapidao.PublicParameter, randSeed []byte,
	cryptoScheme abecryptoxparam.CryptoScheme, privacyLevel abecryptoxparam.PrivacyLevel) (
	cryptoAddress []byte,
	cryptoSpsk []byte,
	cryptoSnsk []byte,
	cryptoVsk []byte,
	err error) {

	expectedSeedLen := pqringctxapi.GetParamSeedBytesLen(pp)

	if privacyLevel == abecryptoxparam.PrivacyLevelRINGCT {
		if 2*expectedSeedLen != len(randSeed) {
			return nil, nil, nil, nil, errors.New("invalid length of seed in pqringctxCryptoAddressGen")
		}

		coinAddress, coinSpendKey, coinSnKey, err := pqringctxapi.AddressKeyForRingGen(pp, randSeed[:expectedSeedLen])
		if err != nil {
			return nil, nil, nil, nil, err
		}

		serializedVPk, serializedVSk, err := pqringctxapi.ValueKeyGen(pp, randSeed[expectedSeedLen:])
		if err != nil {
			return nil, nil, nil, nil, err
		}

		serializedCryptoScheme := cryptoScheme.Serialize()

		cryptoAddress = make([]byte, 4+len(coinAddress)+len(serializedVPk))
		copy(cryptoAddress[0:], serializedCryptoScheme)
		copy(cryptoAddress[4:], coinAddress)
		copy(cryptoAddress[4+len(coinAddress):], serializedVPk)

		cryptoSpsk = make([]byte, 4+len(coinSpendKey))
		copy(cryptoSpsk[0:], serializedCryptoScheme)
		copy(cryptoSpsk[4:], coinSpendKey)

		cryptoSnsk = make([]byte, 0, 4+len(coinSnKey))
		copy(cryptoSnsk[0:], serializedCryptoScheme)
		copy(cryptoSnsk[4:], coinSnKey)

		cryptoVsk = make([]byte, 4+len(serializedVSk))
		copy(cryptoVsk[0:], serializedCryptoScheme)
		copy(cryptoVsk[4:], serializedVSk)

		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil

	} else if privacyLevel == abecryptoxparam.PrivacyLevelPSEUDONYM {
		if expectedSeedLen != len(randSeed) {
			return nil, nil, nil, nil, errors.New("invalid length of seed in pqringctxCryptoAddressGen")
		}

		coinAddress, coinSpendKey, err := pqringctxapi.AddressKeyForSingleGen(pp, randSeed)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		serializedCryptoScheme := cryptoScheme.Serialize()

		cryptoAddress = make([]byte, 4+len(coinAddress))
		copy(cryptoAddress[0:], serializedCryptoScheme)
		copy(cryptoAddress[4:], coinAddress)

		cryptoSpsk = make([]byte, 4+len(coinSpendKey))
		copy(cryptoSpsk[0:], serializedCryptoScheme)
		copy(cryptoSpsk[4:], coinSpendKey)

		cryptoSnsk = nil

		cryptoVsk = nil

		return cryptoAddress, cryptoSpsk, cryptoSnsk, cryptoVsk, nil
	} else {
		return nil, nil, nil, nil, errors.New("unsupported privacyLevel in pqringctxCryptoAddressGen")
	}
}

// API for Sizes	begin
func pqringctxGetCryptoSchemeParamSeedBytesLen(pp *pqringctxapidao.PublicParameter) int {
	return pp.GetParamSeedBytesLen()
}

//	API for Sizes	end

package abecryptoparam

import (
	"fmt"
	"github.com/cryptosuite/pqringct"
)

// This file is added when refactoring due to the implementation of pqringctx.

// pqringctCryptoAddressParse parse the input cryptoAddress into (serializedAPK, serializedVPK).
// reviewed on 2023.12.07.
func pqringctCryptoAddressParse(pp *pqringct.PublicParameter, cryptoScheme CryptoScheme, cryptoAddress []byte) (serializedAPK []byte, serializedVPK []byte, err error) {
	if len(cryptoAddress) < 4 {
		return nil, nil, fmt.Errorf("pqringctParseCryptoAddress: invalid length of cryptoAddress: %d", len(cryptoAddress))
	}

	cryptoSchemeInAddress, err := ExtractCryptoSchemeFromCryptoAddress(cryptoAddress)
	if err != nil {
		return nil, nil, err
	}
	if cryptoSchemeInAddress != cryptoScheme {
		return nil, nil, fmt.Errorf("pqringctParseCryptoAddress: the CryptoScheme of the input cryptoAddress %d does match the input CryptoScheme %d", cryptoSchemeInAddress, cryptoScheme)
	}

	// parse the cryptoAddress to serializedApk and serializedVpk
	apkLen := pqringct.GetAddressPublicKeySerializeSize(pp)
	vpkLen := pqringct.GetValuePublicKeySerializeSize(pp)
	if len(cryptoAddress) != 4+apkLen+vpkLen {
		return nil, nil, fmt.Errorf("pqringctParseCryptoAddress: the input cryptoAddress has invalid length %d", len(cryptoAddress))
	}

	//vpkLen := pp.GetValuePublicKeySerializeSize()
	serializedAPK = cryptoAddress[4 : 4+apkLen]
	serializedVPK = cryptoAddress[4+apkLen:]

	return serializedAPK, serializedVPK, nil
}

func pqringctGetParamSeedBytesLen(pp *pqringct.PublicParameter) int {
	return pqringct.GetParamSeedBytesLen(pp)
}

package abecryptoparam

import (
	"errors"
	"fmt"
	"github.com/cryptosuite/pqringct"
)

func pqringctCryptoAddressParse(pp *pqringct.PublicParameter, cryptoScheme CryptoScheme, cryptoAddress []byte) (serializedAPK []byte, serializedVPK []byte, err error) {
	if len(cryptoAddress) < 4 {
		errMsg := fmt.Sprintf("pqringctParseCryptoAddress: invalid length of cryptoAddress: %d", len(cryptoAddress))
		return nil, nil, errors.New(errMsg)
	}

	cryptoSchemeInAddress, err := ExtractCryptoSchemeFromCryptoAddress(cryptoAddress)
	if err != nil || cryptoSchemeInAddress != cryptoScheme {
		errMsg := fmt.Sprintf("pqringctParseCryptoAddress: the CryptoScheme of the input cryptoAddress %d does match the input CryptoScheme %d", cryptoSchemeInAddress, cryptoScheme)
		return nil, nil, errors.New(errMsg)
	}

	// parse the cryptoAddress to serializedApk and serializedVpk
	apkLen := pqringct.GetAddressPublicKeySerializeSize(pp)
	vpkLen := pqringct.GetValuePublicKeySerializeSize(pp)
	if len(cryptoAddress) != 4+apkLen+vpkLen {
		errMsg := fmt.Sprintf("pqringctParseCryptoAddress: the input cryptoAddress has invalid length %d", len(cryptoAddress))
		return nil, nil, errors.New(errMsg)
	}

	//vpkLen := pp.GetValuePublicKeySerializeSize()
	serializedAPK = cryptoAddress[4 : 4+apkLen]
	serializedVPK = cryptoAddress[4+apkLen:]

	return serializedAPK, serializedVPK, nil
}

func pqringctGetParamSeedBytesLen(pp *pqringct.PublicParameter) int {
	return pqringct.GetParamSeedBytesLen(pp)
}

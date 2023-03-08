package v1

import "github.com/abesuite/abec/abecrypto"

// CryptoAddressCheck checks wthether the given cryptoAddress is valid (in format).
// When the result is false, the hints will give the reasons why it is invalid.
func CryptoAddressCheck(cryptoAddress []byte) (bl bool, hints string) {
	return abecrypto.CryptoAddressCheck(cryptoAddress)
}

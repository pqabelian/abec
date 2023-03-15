package v1

import (
	"fmt"
	"testing"
)

func TestAddress(t *testing.T) {
	seed, err := CryptoAddressKeySeedGen()
	if err != nil {
		fmt.Sprint(err)
		return
	}
	fmt.Println("AddressKeySeed:", seed)

	cryptoAddress, _, _, _, err := CryptoAddressKeyGen(seed)
	if err != nil {
		fmt.Sprint(err)
		return
	}
	fmt.Println("CryptoAddress:", cryptoAddress)
	fmt.Println("CryptoAddresslen:", len(cryptoAddress))

	coinAddress, err := ExtractCoinAddressFromCryptoAddress(cryptoAddress)
	if err != nil {
		fmt.Sprint(err)
		return
	}
	fmt.Println("coinAddress:", coinAddress)
	fmt.Println("coinAddresslen:", len(coinAddress))
}
